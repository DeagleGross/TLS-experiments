using DemoSemiUnmanagedSocket.Interop;
using DemoSemiUnmanagedSocket.Ssl.Requests;
using System;
using System.Collections.Generic;
using System.Text;

namespace DemoSemiUnmanagedSocket.Ssl;

/// <summary>
/// A single SSL worker thread (nginx-style).
/// 
/// Runs a synchronous loop:
/// 1. Call epoll_wait to get ready fds (listen socket or client sockets)
/// 2. If listen socket ready: accept connections in a loop
/// 3. If client socket ready: call ssl_do_handshake
/// 4. Complete finished handshakes
/// 
/// Key difference from queue-based approach:
/// - Listen socket is added to each worker's epoll with EPOLLEXCLUSIVE
/// - Workers accept connections directly, no cross-thread handoff
/// </summary>
internal sealed class SslWorker
{
    private const int MaxBatchEvents = 64;
    private const int EpollTimeoutMs = 100; // Timeout when idle
    
    private readonly int _workerId;
    private readonly SslContext _sslContext;
    private readonly int _epollFd;
    private readonly Thread _thread;
    private readonly Dictionary<int, ActiveConnection> _activeConnections = new(); // fd -> connection (local to this worker)
    private int _listenFd = -1;
    private volatile bool _running;

    // Stats
    private long _completed;
    private long _failed;
    private long _accepted;

    /// <summary>
    /// Lightweight struct to track active SSL connections (avoids TaskCompletionSource overhead).
    /// </summary>
    private struct ActiveConnection
    {
        public IntPtr Ssl;
        public int ClientFd;
    }

    public SslWorker(int workerId, SslContext sslContext)
    {
        _workerId = workerId;
        _sslContext = sslContext;

        // Create epoll instance for this worker
        _epollFd = NativeSsl.create_epoll();
        if (_epollFd < 0)
        {
            throw new InvalidOperationException($"Failed to create epoll for worker {workerId}");
        }

        _thread = new Thread(WorkerLoop)
        {
            Name = $"SslWorker-{_workerId}",
            IsBackground = true
        };
    }

    /// <summary>
    /// Start the worker with a listen socket fd.
    /// The listen fd is added to this worker's epoll with EPOLLEXCLUSIVE.
    /// </summary>
    public void Start(int listenFd)
    {
        _listenFd = listenFd;
        
        // Add listen socket to our epoll with EPOLLEXCLUSIVE
        // This prevents thundering herd - only one worker wakes per connection
        int result = NativeSsl.epoll_add_listen_fd(_epollFd, listenFd);
        if (result < 0)
        {
            throw new InvalidOperationException($"Failed to add listen_fd to epoll for worker {_workerId}");
        }
        
        _running = true;
        _thread.Start();
    }

    public void Stop()
    {
        _running = false;
        _thread.Join(timeout: TimeSpan.FromSeconds(2));
        NativeSsl.close_epoll(_epollFd);
    }

    public (long completed, long failed, long pending) GetStats()
    {
        return (
            Interlocked.Read(ref _completed),
            Interlocked.Read(ref _failed),
            _activeConnections.Count
        );
    }

    /// <summary>
    /// Main worker loop - runs synchronously on dedicated thread.
    /// Uses batch epoll_wait for better throughput.
    /// </summary>
    private unsafe void WorkerLoop()
    {
        Console.WriteLine($"[Worker {_workerId}] Started, epoll_fd={_epollFd}, listen_fd={_listenFd}");

        // Stack-allocate buffer for batch epoll results
        int* readyFds = stackalloc int[MaxBatchEvents];

        while (_running)
        {
            // Determine timeout based on active connections
            int timeout = _activeConnections.Count == 0 ? EpollTimeoutMs : 10;

            // Wait for socket events (batch mode - get multiple events per syscall)
            int numReady = NativeSsl.epoll_wait_batch(_epollFd, timeout, readyFds, MaxBatchEvents);
            
            // Process all ready sockets
            for (int i = 0; i < numReady; i++)
            {
                int fd = readyFds[i];
                
                if (fd == _listenFd)
                {
                    // Listen socket ready - accept new connections
                    AcceptConnections();
                }
                else
                {
                    // Client socket ready - process handshake
                    ProcessReadySocket(fd);
                }
            }
        }

        // Cleanup remaining connections
        foreach (var kvp in _activeConnections)
        {
            var conn = kvp.Value;
            if (conn.Ssl != IntPtr.Zero)
            {
                NativeSsl.ssl_connection_destroy(conn.Ssl);
            }
            // Close the client socket (we own it since we accepted it)
            Close(conn.ClientFd);
        }
        _activeConnections.Clear();

        Console.WriteLine($"[Worker {_workerId}] Stopped. Accepted: {_accepted}, Completed: {_completed}, Failed: {_failed}");
    }

    /// <summary>
    /// Accept new connections from the listen socket (nginx pattern).
    /// Loops until EAGAIN (no more pending connections).
    /// </summary>
    private void AcceptConnections()
    {
        while (true)
        {
            int clientFd = NativeSsl.accept_nonblocking(_listenFd);
            
            if (clientFd == -1)
            {
                // EAGAIN - no more pending connections
                break;
            }
            
            if (clientFd == -2)
            {
                // Error - continue trying
                continue;
            }
            
            Interlocked.Increment(ref _accepted);
            
            // Create SSL connection and register with our epoll
            IntPtr ssl = NativeSsl.ssl_connection_create(
                _sslContext.Handle,
                clientFd,
                _epollFd);

            if (ssl == IntPtr.Zero)
            {
                Interlocked.Increment(ref _failed);
                Close(clientFd);
                continue;
            }

            _activeConnections[clientFd] = new ActiveConnection
            {
                Ssl = ssl,
                ClientFd = clientFd
            };

            // Try handshake immediately (might complete in one call for resumed sessions)
            TryAdvanceHandshake(clientFd, ssl);
        }
    }

    /// <summary>
    /// Process a socket that epoll reported as ready.
    /// </summary>
    private void ProcessReadySocket(int fd)
    {
        if (!_activeConnections.TryGetValue(fd, out var conn))
        {
            // Unknown fd - shouldn't happen, but ignore
            return;
        }

        TryAdvanceHandshake(fd, conn.Ssl);
    }

    /// <summary>
    /// Try to advance the TLS handshake for a connection.
    /// </summary>
    private unsafe void TryAdvanceHandshake(int clientFd, IntPtr ssl)
    {
        int status = NativeSsl.ssl_try_handshake(ssl, clientFd, _epollFd);

        switch (status)
        {
            case NativeSsl.HANDSHAKE_COMPLETE:
                // Success! Send HTTP response immediately on this worker thread
                SendHttpResponse(ssl);

                // Cleanup SSL and remove from active
                _activeConnections.Remove(clientFd);
                NativeSsl.ssl_connection_destroy(ssl);
                Close(clientFd);  // We own the socket

                Interlocked.Increment(ref _completed);
                break;

            case NativeSsl.HANDSHAKE_WANT_READ:
            case NativeSsl.HANDSHAKE_WANT_WRITE:
                // Need more I/O - epoll is already updated by ssl_try_handshake
                // Just wait for next epoll_wait to return this fd
                break;

            case NativeSsl.HANDSHAKE_ERROR:
            default:
                // Failed - cleanup
                _activeConnections.Remove(clientFd);
                NativeSsl.ssl_connection_destroy(ssl);
                Close(clientFd);  // We own the socket
                Interlocked.Increment(ref _failed);
                break;
        }
    }

    /// <summary>
    /// Send HTTP response through SSL connection.
    /// </summary>
    private static unsafe void SendHttpResponse(IntPtr ssl)
    {
        ReadOnlySpan<byte> response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"u8;
        fixed (byte* ptr = response)
        {
            int written = NativeSsl.ssl_write(ssl, ptr, response.Length);
            // Note: In production, should handle partial writes and errors
        }
    }

    /// <summary>
    /// Close a file descriptor using native close().
    /// </summary>
    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    private static void Close(int fd)
    {
        if (fd >= 0)
        {
            close(fd);
        }
    }
}
