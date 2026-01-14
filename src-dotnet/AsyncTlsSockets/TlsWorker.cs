using Serilog;
using System.Net;
using System.Runtime.InteropServices;

namespace AsyncTlsSockets;

public unsafe class TlsWorker
{
    private readonly int _id;

    private readonly int _port;
    private readonly string _certPath;
    private readonly string _keyPath;

    private IntPtr _sslCtx;
    private int _epollFd;
    private int _listenFd;

    public TlsWorker(int id, int port, string cert, string key)
    {
        _id = id;

        _port = port;
        _certPath = cert;
        _keyPath = key;
    }

    public void Start()
    {
        var thread = new Thread(RunLoop) { IsBackground = true };
        thread.Start();
    }

    private void RunLoop()
    {
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
                    Log.Debug("[TlsWorker {_id}] New connection ready to accept", _id);

                    // 1. Accept the connection with Non-Blocking flag (0x800 is SOCK_NONBLOCK on Linux)
                    // We pass null for addr/addrlen for maximum speed if you don't need the Client IP immediately
                    int clientFd = Libc.accept4(_listenFd, IntPtr.Zero, IntPtr.Zero, 0x800);

                    if (clientFd < 0)
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err != (int)Libc.Errno.EAGAIN && err != (int)Libc.Errno.EWOULDBLOCK)
                        {
                            Log.Error("Accept failed with errno: {0}", err);
                        }
                        return;
                    }

                    // 2. Create the SSL object from our Worker's Context
                    IntPtr ssl = NativeOpenSsl.SSL_new(_sslCtx);
                    if (ssl == IntPtr.Zero)
                    {
                        Libc.close(clientFd);
                        return;
                    }

                    // Link the Socket FD to the SSL object
                    NativeOpenSsl.SSL_set_fd(ssl, clientFd);
                    // Tell OpenSSL we are acting as the Server in the upcoming handshake
                    NativeOpenSsl.SSL_set_accept_state(ssl);

                    // 3. Create the ConnectionContext
                    var context = new ConnectionContext(clientFd, ssl);

                    // 4. Pin the object so the GC doesn't move it while its address is in Epoll
                    GCHandle handle = GCHandle.Alloc(context);
                    IntPtr contextPtr = GCHandle.ToIntPtr(handle);

                    // 5. Register with Epoll
                    // We watch for READ, Peer Shutdown (RDHUP), and use Edge-Triggered (ET) mode
                    EpollEvent ev = new EpollEvent
                    {
                        events = (uint)(EpollEvents.EPOLLIN | EpollEvents.EPOLLET | EpollEvents.EPOLLRDHUP),
                        data = new EpollData { ptr = contextPtr }
                    };

                    if (Libc.EpollCtl(_epollFd, (int)EpollOp.ADD, clientFd, ref ev) < 0)
                    {
                        Log.Error("Failed to add client to epoll");
                        NativeOpenSsl.SSL_free(ssl);
                        Libc.close(clientFd);
                        handle.Free();
                        return;
                    }

                    // 6. Start the Handshake
                    // This will likely return WANT_READ immediately, 
                    // but it kicks off the state machine.
                    context.DoHandshake();
                }
                else
                {
                    Log.Debug("[TlsWorker {_id}] new work on connection fd='{connectionFd}'", _id, currentEv.data.fd);

                    // This is where you retrieve your ConnectionContext from data.ptr
                    // and perform SSL_read / SSL_write
                }
            }
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

        // 3. Set Non-Blocking (Required for Epoll)
        int flags = Libc.fcntl(fd, Libc.F_GETFL, 0);
        Libc.fcntl(fd, Libc.F_SETFL, flags | Libc.O_NONBLOCK);

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