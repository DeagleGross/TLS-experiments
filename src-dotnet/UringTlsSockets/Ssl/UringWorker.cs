using UringTlsSockets.Interop;

namespace UringTlsSockets.Ssl;

/// <summary>
/// A single SSL worker thread using io_uring (replaces epoll-based SslWorker).
///
/// Main loop:
///   1. uring_wait_batch — flush pending SQEs, reap CQEs
///   2. ACCEPT CQE → create SSL, try handshake (next accept auto-resubmitted)
///   3. POLL CQE   → retry handshake for that fd
///   4. On handshake WANT_READ/WRITE → uring_prep_poll (batched)
///   5. On handshake complete → SSL_write HTTP response, close
///
/// Key differences from epoll worker:
///   • Single-shot accept via SQE (auto-resubmitted in native layer)
///   • poll_add SQE instead of epoll_ctl for readiness
///   • All SQE submissions batched in uring_wait_batch's io_uring_submit()
///   • No epoll_ctl ADD/MOD/DEL overhead per connection
/// </summary>
internal sealed class UringWorker
{
    private const int MaxBatchEvents = 64;
    private const int UringQueueDepth = 256;
    private const int TimeoutIdleMs = 100;
    private const int TimeoutActiveMs = 10;

    private readonly int _workerId;
    private readonly SslContext _sslContext;
    private readonly IntPtr _uringCtx;
    private readonly Thread _thread;
    private readonly Dictionary<int, ActiveConnection> _activeConnections = new();
    private volatile bool _running;

    private long _completed;
    private long _failed;
    private long _accepted;

    private struct ActiveConnection
    {
        public IntPtr Ssl;
        public int ClientFd;
    }

    public UringWorker(int workerId, SslContext sslContext)
    {
        _workerId = workerId;
        _sslContext = sslContext;

        _uringCtx = UringNative.uring_create(UringQueueDepth);
        if (_uringCtx == IntPtr.Zero)
            throw new InvalidOperationException($"Failed to create io_uring for worker {workerId}");

        _thread = new Thread(WorkerLoop)
        {
            Name = $"UringWorker-{_workerId}",
            IsBackground = true
        };
    }

    public void Start(int listenFd)
    {
        int result = UringNative.uring_set_listen_fd(_uringCtx, listenFd);
        if (result < 0)
            throw new InvalidOperationException(
                $"Failed to set listen_fd for worker {_workerId}");

        _running = true;
        _thread.Start();
    }

    public void Stop()
    {
        _running = false;
        _thread.Join(timeout: TimeSpan.FromSeconds(2));
        UringNative.uring_destroy(_uringCtx);
    }

    public (long completed, long failed, long pending) GetStats()
    {
        return (
            Interlocked.Read(ref _completed),
            Interlocked.Read(ref _failed),
            _activeConnections.Count
        );
    }

    private unsafe void WorkerLoop()
    {
        Console.WriteLine($"[Worker {_workerId}] Started with io_uring (queue_depth={UringQueueDepth})");

        int* types   = stackalloc int[MaxBatchEvents];
        int* fds     = stackalloc int[MaxBatchEvents];
        int* results = stackalloc int[MaxBatchEvents];

        while (_running)
        {
            int timeout = _activeConnections.Count == 0 ? TimeoutIdleMs : TimeoutActiveMs;

            int numComplete = UringNative.uring_wait_batch(
                _uringCtx, types, fds, results, MaxBatchEvents, timeout);

            if (numComplete < 0)
                continue;

            for (int i = 0; i < numComplete; i++)
            {
                switch (types[i])
                {
                    case UringNative.CQE_TYPE_ACCEPT:
                        HandleAccept(results[i]);
                        break;

                    case UringNative.CQE_TYPE_POLL:
                        HandlePollReady(fds[i]);
                        break;
                }
            }
        }

        // Cleanup remaining connections
        foreach (var kvp in _activeConnections)
        {
            var conn = kvp.Value;
            if (conn.Ssl != IntPtr.Zero)
                UringNative.ssl_connection_destroy(conn.Ssl);
            Close(conn.ClientFd);
        }
        _activeConnections.Clear();

        Console.WriteLine(
            $"[Worker {_workerId}] Stopped. Accepted: {_accepted}, " +
            $"Completed: {_completed}, Failed: {_failed}");
    }

    /// <summary>
    /// Handle a completed accept CQE. result is the new client fd.
    /// </summary>
    private void HandleAccept(int clientFd)
    {
        if (clientFd < 0) return; // accept error (e.g., -EAGAIN)

        Interlocked.Increment(ref _accepted);

        IntPtr ssl = UringNative.ssl_connection_create(
            _sslContext.Handle, clientFd);

        if (ssl == IntPtr.Zero)
        {
            Interlocked.Increment(ref _failed);
            Close(clientFd);
            return;
        }

        _activeConnections[clientFd] = new ActiveConnection
        {
            Ssl = ssl,
            ClientFd = clientFd
        };

        TryAdvanceHandshake(clientFd, ssl);
    }

    /// <summary>
    /// Handle a poll CQE — the socket is ready, retry the handshake.
    /// </summary>
    private void HandlePollReady(int fd)
    {
        if (!_activeConnections.TryGetValue(fd, out var conn))
            return;

        TryAdvanceHandshake(fd, conn.Ssl);
    }

    /// <summary>
    /// Drive the TLS handshake forward. On WANT_READ/WRITE, submit
    /// a poll SQE (batched — flushed on next uring_wait_batch).
    /// </summary>
    private unsafe void TryAdvanceHandshake(int clientFd, IntPtr ssl)
    {
        int status = UringNative.ssl_try_handshake(ssl);

        switch (status)
        {
            case UringNative.HANDSHAKE_COMPLETE:
                SendHttpResponse(ssl);
                _activeConnections.Remove(clientFd);
                UringNative.ssl_connection_destroy(ssl);
                Close(clientFd);
                Interlocked.Increment(ref _completed);
                break;

            case UringNative.HANDSHAKE_WANT_READ:
                // Prepare poll for POLLIN — flushed on next wait_batch
                UringNative.uring_prep_poll(_uringCtx, clientFd, 0);
                break;

            case UringNative.HANDSHAKE_WANT_WRITE:
                // Prepare poll for POLLOUT — flushed on next wait_batch
                UringNative.uring_prep_poll(_uringCtx, clientFd, 1);
                break;

            case UringNative.HANDSHAKE_ERROR:
            default:
                _activeConnections.Remove(clientFd);
                UringNative.ssl_connection_destroy(ssl);
                Close(clientFd);
                Interlocked.Increment(ref _failed);
                break;
        }
    }

    private static unsafe void SendHttpResponse(IntPtr ssl)
    {
        ReadOnlySpan<byte> response =
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"u8;
        fixed (byte* ptr = response)
        {
            UringNative.ssl_write_data(ssl, ptr, response.Length);
        }
    }

    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    private static void Close(int fd)
    {
        if (fd >= 0)
            close(fd);
    }
}
