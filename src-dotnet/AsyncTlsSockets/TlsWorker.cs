using Serilog;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Channels;

namespace AsyncTlsSockets;

public unsafe class TlsWorker
{
    private readonly int _id;

    private readonly int _port;
    private readonly string _certPath;
    private readonly string _keyPath;

    private readonly ChannelWriter<ConnectionContext> _acceptQueue;

    private IntPtr _sslCtx;
    private int _epollFd;
    private int _listenFd;

    public TlsWorker(int id, int port, string cert, string key, ChannelWriter<ConnectionContext> acceptQueue)
    {
        _id = id;
        _acceptQueue = acceptQueue;

        _port = port;
        _certPath = cert;
        _keyPath = key;
    }

    public void Start()
    {
        var thread = new Thread(RunLoop) { IsBackground = true };
        thread.Start();
    }

    private unsafe void RunLoop()
    {
        // 0. Pin this worker thread to a specific CPU core
        int numCpus = Libc.get_nprocs();
        int targetCpu = _id % numCpus;
        ulong cpuMask = 1UL << targetCpu;
        Libc.sched_setaffinity(0, (nuint)sizeof(ulong), &cpuMask);  // 0 = current thread
        Log.Information("[TlsWorker {_id}] Pinned to CPU {Cpu}/{Total}", _id, targetCpu, numCpus);

        // 1. Initialize OpenSSL Context for this thread
        InitOpenSsl();

        // 2. Create the listening socket with SO_REUSEPORT
        _listenFd = SetupListenSocket();

        // 3. Setup Epoll
        _epollFd = Libc.EpollCreate1(0);
        var ev = new EpollEvent
        {
            events = (uint)EpollEvents.EPOLLIN,
            data = new EpollData { fd = _listenFd }
        };
        Libc.EpollCtl(_epollFd, (int)EpollOp.ADD, _listenFd, ref ev);

        var eventsArray = new EpollEvent[64];
        while (true)
        {
            int n = Libc.EpollWait(_epollFd, eventsArray, 64, -1);
            for (int i = 0; i < n; i++)
            {
                var currentEv = eventsArray[i];

                if (currentEv.data.fd == _listenFd)
                {
                    HandleAccept();
                }
                else
                {
                    HandleData(currentEv);
                }
            }
        }
    }

    private void HandleData(EpollEvent ev)
    {
        // 1. Get the pointer from the event
        var connectionContextId = ev.data.u64;
        var connectionContext = ConnectionRegistry.Get((long)connectionContextId);
        if (connectionContext is null)
        {
            Log.Debug("[TlsWorker {_id}] Received event for unknown connection context ID {ContextId}", _id, connectionContextId);
            return;
        }

        // 3.1 & 3.2 Process READ and WRITE
        // We check both because a single event can have both flags
        if ((ev.events & (uint)(EpollEvents.EPOLLIN | EpollEvents.EPOLLOUT)) != 0)
        {
            // The worker tells the context: "Something changed on the socket, try to progress"
            connectionContext.OnSocketReady(); 
        }
        // 3.3 PROCESS DISCONNECT
        else if ((ev.events & (uint)EpollEvents.EPOLLRDHUP) != 0)
        {
            Log.Debug("[TlsWorker {_id}] Peer closed connection on FD {Fd}", _id, connectionContext._fd);
            connectionContext.Dispose();
        }
    }

    private unsafe void HandleAccept()
    {
        // Multi-accept: accept all pending connections in one go (like nginx multi_accept)
        while (true)
        {
            int clientFd = Libc.accept4(_listenFd, IntPtr.Zero, IntPtr.Zero, 0x800); // SOCK_NONBLOCK
            if (clientFd < 0) break; // No more pending connections

            // TCP_NODELAY: Disable Nagle's algorithm - send small handshake messages immediately
            int optval = 1;
            Libc.setsockopt(clientFd, Libc.IPPROTO_TCP, Libc.TCP_NODELAY, &optval, sizeof(int));

            // TCP_QUICKACK: Disable delayed ACKs for faster handshake
            Libc.setsockopt(clientFd, Libc.IPPROTO_TCP, Libc.TCP_QUICKACK, &optval, sizeof(int));

            IntPtr ssl = NativeOpenSsl.SSL_new(_sslCtx);
            NativeOpenSsl.SSL_set_fd(ssl, clientFd);
            NativeOpenSsl.SSL_set_accept_state(ssl);

            // Set write BIO buffer size to 16KB (matches nginx).
            IntPtr wbio = NativeOpenSsl.SSL_get_wbio(ssl);
            if (wbio != IntPtr.Zero)
                NativeOpenSsl.BIO_set_write_buffer_size(wbio, 16384);

            // Create the context and tell it who its 'parent' queue is
            var context = new ConnectionContext(_epollFd, clientFd, ssl, _acceptQueue);
            var connectionContextId = ConnectionRegistry.Register(context);

            // Register in Worker's local Epoll
            RegisterInEpoll(clientFd, connectionContextId);

            Log.Debug("[TlsWorker {_id}] Accepted new connection on FD {Fd}", _id, clientFd);

            // Kick off the handshake
            context.DoHandshake();
        }
    }

    private void RegisterInEpoll(int clientFd, long connectionContextId)
    {
        // We watch for:
        // EPOLLIN: Data available to read
        // EPOLLRDHUP: Peer closed connection (useful for clean shutdown)
        // EPOLLET: Edge-Triggered mode (Performance)
        var ev = new EpollEvent
        {
            events = (uint)(EpollEvents.EPOLLIN | EpollEvents.EPOLLET | EpollEvents.EPOLLRDHUP),
            data = new EpollData { u64 = (ulong)connectionContextId }
        };

        if (Libc.EpollCtl(_epollFd, (int)EpollOp.ADD, clientFd, ref ev) < 0)
        {
            int error = Marshal.GetLastWin32Error();
            // Log error and close connection if registration fails
            Libc.close(clientFd);
            throw new Exception($"Failed to add client FD {clientFd} to epoll. Error: {error}");
        }
    }

    private unsafe void InitOpenSsl()
    {
        // 1. Initialize the library (Only needed once, but safe to call multiple times in newer versions)
        NativeOpenSsl.OPENSSL_init_ssl(0, IntPtr.Zero);

        // 2. Create a new Context using the TLS Server Method
        _sslCtx = NativeOpenSsl.SSL_CTX_new(NativeOpenSsl.TLS_server_method());
        if (_sslCtx == IntPtr.Zero) throw new Exception("Failed to create SSL Context");

        // 3. Load the Certificate Chain (.crt)
        // We use 'chain_file' to ensure intermediate certificates are sent to the client
        if (NativeOpenSsl.SSL_CTX_use_certificate_chain_file(_sslCtx, _certPath) <= 0)
            throw new Exception("Failed to load certificate file");

        // 4. Load the Private Key (.key)
        if (NativeOpenSsl.SSL_CTX_use_PrivateKey_file(_sslCtx, _keyPath, 1) <= 0) // 1 = SSL_FILETYPE_PEM
            throw new Exception("Failed to load private key file");

        // 5. Verify the key matches the certificate
        if (NativeOpenSsl.SSL_CTX_check_private_key(_sslCtx) <= 0)
            throw new Exception("Private key does not match the certificate public key");

        // 6. Performance & Security options
        NativeOpenSsl.SSL_CTX_set_mode(_sslCtx, NativeOpenSsl.SSL_MODE_RELEASE_BUFFERS);  // ~34KB saved per idle connection
        NativeOpenSsl.SSL_CTX_set_read_ahead(_sslCtx, 1);  // Buffer multiple TLS records for better throughput

        NativeOpenSsl.SSL_CTX_set_options(_sslCtx,
            NativeOpenSsl.SSL_OP_NO_COMPRESSION |           // ~522KB saved per connection, also mitigates CRIME attack
            NativeOpenSsl.SSL_OP_SINGLE_ECDH_USE |          // Fresh ECDH key per handshake (security)
            NativeOpenSsl.SSL_OP_NO_CLIENT_RENEGOTIATION |  // Block client-initiated renegotiation (DoS protection)
            NativeOpenSsl.SSL_OP_IGNORE_UNEXPECTED_EOF);    // OpenSSL 3.0+: cleaner EOF handling

        Console.WriteLine("OpenSSL Context initialized successfully.");
    }

    private unsafe int SetupListenSocket()
    {
        // 1. Create a TCP Socket
        int fd = Libc.socket(Libc.AF_INET, Libc.SOCK_STREAM, 0);
        if (fd < 0) throw new Exception("Could not create socket");

        // 2. Set SO_REUSEPORT (Constant is usually 15 on Linux)
        int optval = 1;
        if (Libc.setsockopt(fd, Libc.SOL_SOCKET, Libc.SO_REUSEPORT, &optval, sizeof(int)) < 0)
            throw new Exception("Setsockopt SO_REUSEPORT failed");

        // 3. TCP_DEFER_ACCEPT: Don't wake on accept until client sends data (ClientHello)
        // Value is timeout in seconds - kernel will wait up to this long for data
        int deferTimeout = 3;
        Libc.setsockopt(fd, Libc.IPPROTO_TCP, Libc.TCP_DEFER_ACCEPT, &deferTimeout, sizeof(int));

        // 3. Set Non-Blocking (Required for Epoll)
        int flags = Libc.fcntl(fd, Libc.F_GETFL, 0);
        Libc.fcntl(fd, Libc.F_SETFL, flags | Libc.SOCK_NONBLOCK);

        // 4. Bind to the port (0.0.0.0:PORT)
        SockAddrIn addr = new SockAddrIn();
        addr.sin_family = (short)Libc.AF_INET;
        addr.sin_port = (ushort)IPAddress.HostToNetworkOrder((short)_port);
        addr.sin_addr = 0; // INADDR_ANY (0.0.0.0)

        if (Libc.bind(fd, ref addr, sizeof(SockAddrIn)) < 0)
            throw new Exception($"Bind failed on port {_port}");

        // 5. Start Listening
        if (Libc.listen(fd, 1024) < 0) // 1024 is the backlog size
            throw new Exception("Listen failed");

        return fd;
    }
}