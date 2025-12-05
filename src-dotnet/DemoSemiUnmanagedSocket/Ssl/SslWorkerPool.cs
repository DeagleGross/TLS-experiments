using DemoSemiUnmanagedSocket.Interop;
using System.Collections.Concurrent;
using System.Net.Sockets;

namespace DemoSemiUnmanagedSocket.Ssl;

/// <summary>
/// Result of a handshake operation.
/// </summary>
public enum HandshakeResult
{
    Success,
    Failed,
    Timeout
}

/// <summary>
/// Represents a pending handshake request.
/// </summary>
internal sealed class HandshakeRequest
{
    public Socket ClientSocket { get; }
    public IntPtr Ssl { get; set; }
    public int ClientFd { get; }
    public TaskCompletionSource<HandshakeResult> Completion { get; }
    public int WorkerId { get; set; } = -1;

    public HandshakeRequest(Socket clientSocket)
    {
        ClientSocket = clientSocket;
        ClientFd = (int)clientSocket.Handle;
        Completion = new TaskCompletionSource<HandshakeResult>(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}

/// <summary>
/// Pool of dedicated SSL worker threads.
/// 
/// Architecture (similar to nginx):
/// - Fixed number of worker threads (default 4)
/// - Each worker has its own epoll instance
/// - Single shared queue - workers pick up work when free
/// - Workers run a synchronous loop: epoll_wait → ssl_do_handshake
/// - App threads submit handshake requests and await completion
/// 
/// This avoids async overhead and keeps TLS work on dedicated threads.
/// </summary>
internal sealed class SslWorkerPool : IDisposable
{
    private static SslWorkerPool? _instance;
    private static readonly object _instanceLock = new();

    private readonly SslWorker[] _workers;
    private readonly int _workerCount;
    private readonly SslContext _sslContext;
    private readonly ConcurrentQueue<HandshakeRequest> _sharedQueue = new(); // Shared across all workers
    private bool _disposed;

    /// <summary>
    /// Get or create the singleton instance.
    /// </summary>
    public static SslWorkerPool GetInstance(SslContext sslContext, int workerCount = 4)
    {
        if (_instance == null)
        {
            lock (_instanceLock)
            {
                _instance ??= new SslWorkerPool(sslContext, workerCount);
            }
        }
        return _instance;
    }

    private SslWorkerPool(SslContext sslContext, int workerCount)
    {
        _sslContext = sslContext;
        _workerCount = workerCount;
        _workers = new SslWorker[workerCount];

        // Create and start worker threads - all share the same queue
        for (int i = 0; i < workerCount; i++)
        {
            _workers[i] = new SslWorker(i, sslContext, _sharedQueue);
            _workers[i].Start();
        }

        Console.WriteLine($"[SslWorkerPool] Started {workerCount} workers with shared queue");
    }

    /// <summary>
    /// Submit a socket for TLS handshake.
    /// Returns a task that completes when handshake is done.
    /// Any free worker will pick it up.
    /// </summary>
    public Task<HandshakeResult> SubmitHandshakeAsync(Socket clientSocket)
    {
        var request = new HandshakeRequest(clientSocket);
        
        // Just enqueue - any worker will pick it up when free
        _sharedQueue.Enqueue(request);
        
        return request.Completion.Task;
    }

    /// <summary>
    /// Get statistics from all workers.
    /// </summary>
    public (long completed, long failed, long pending) GetStats()
    {
        long completed = 0, failed = 0, pending = 0;
        foreach (var worker in _workers)
        {
            var stats = worker.GetStats();
            completed += stats.completed;
            failed += stats.failed;
            pending += stats.pending;
        }
        // Add queue size to pending
        pending += _sharedQueue.Count;
        return (completed, failed, pending);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            foreach (var worker in _workers)
            {
                worker.Stop();
            }
            _disposed = true;
        }
    }
}

/// <summary>
/// A single SSL worker thread.
/// 
/// Runs a synchronous loop:
/// 1. Check for new connection requests from shared queue
/// 2. Call epoll_wait to get ready sockets
/// 3. Call ssl_do_handshake on ready sockets
/// 4. Complete finished handshakes
/// </summary>
internal sealed class SslWorker
{
    private readonly int _workerId;
    private readonly SslContext _sslContext;
    private readonly int _epollFd;
    private readonly Thread _thread;
    private readonly ConcurrentQueue<HandshakeRequest> _sharedQueue; // Shared with other workers
    private readonly Dictionary<int, HandshakeRequest> _activeConnections = new(); // fd -> request (local to this worker)
    private volatile bool _running;

    // Stats
    private long _completed;
    private long _failed;

    public SslWorker(int workerId, SslContext sslContext, ConcurrentQueue<HandshakeRequest> sharedQueue)
    {
        _workerId = workerId;
        _sslContext = sslContext;
        _sharedQueue = sharedQueue;
        
        // Create epoll instance for this worker
        _epollFd = NativeSsl.create_epoll();
        if (_epollFd < 0)
        {
            throw new InvalidOperationException($"Failed to create epoll for worker {workerId}");
        }

        _thread = new Thread(WorkerLoop)
        {
            Name = $"SslWorker-{workerId}",
            IsBackground = true
        };
    }

    public void Start()
    {
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
    /// </summary>
    private void WorkerLoop()
    {
        Console.WriteLine($"[Worker {_workerId}] Started, epoll_fd={_epollFd}");

        while (_running)
        {
            // 1. Try to pick up new requests from shared queue
            ProcessNewRequests();

            // 2. If no active connections, just wait a bit and check again
            if (_activeConnections.Count == 0)
            {
                Thread.Sleep(1); // Avoid busy spin
                continue;
            }

            // 3. Wait for socket events (short timeout to check for new requests)
            int readyFd = NativeSsl.epoll_wait_one(_epollFd, 10);

            if (readyFd > 0)
            {
                // 4. Handle the ready socket
                ProcessReadySocket(readyFd);
            }
        }

        // Cleanup remaining connections
        foreach (var kvp in _activeConnections)
        {
            var request = kvp.Value;
            if (request.Ssl != IntPtr.Zero)
            {
                NativeSsl.ssl_connection_destroy(request.Ssl);
            }
            request.Completion.TrySetResult(HandshakeResult.Failed);
        }
        _activeConnections.Clear();

        Console.WriteLine($"[Worker {_workerId}] Stopped");
    }

    /// <summary>
    /// Process new handshake requests from the shared queue.
    /// Each worker competes to dequeue - natural load balancing.
    /// </summary>
    private void ProcessNewRequests()
    {
        // Try to grab one or more requests from shared queue
        while (_sharedQueue.TryDequeue(out var request))
        {
            // Create SSL connection and register with our epoll
            IntPtr ssl = NativeSsl.ssl_connection_create(
                _sslContext.Handle, 
                request.ClientFd, 
                _epollFd);

            if (ssl == IntPtr.Zero)
            {
                Interlocked.Increment(ref _failed);
                request.Completion.TrySetResult(HandshakeResult.Failed);
                continue;
            }

            request.Ssl = ssl;
            request.WorkerId = _workerId; // Track which worker owns this
            _activeConnections[request.ClientFd] = request;

            // Try handshake immediately (might complete in one call for resumed sessions)
            TryAdvanceHandshake(request);
        }
    }

    /// <summary>
    /// Process a socket that epoll reported as ready.
    /// </summary>
    private void ProcessReadySocket(int fd)
    {
        if (!_activeConnections.TryGetValue(fd, out var request))
        {
            // Unknown fd - shouldn't happen, but remove from epoll
            NativeSsl.epoll_wait_one(_epollFd, 0); // Clear it
            return;
        }

        TryAdvanceHandshake(request);
    }

    /// <summary>
    /// Try to advance the TLS handshake for a connection.
    /// </summary>
    private unsafe void TryAdvanceHandshake(HandshakeRequest request)
    {
        int status = NativeSsl.ssl_try_handshake(request.Ssl, request.ClientFd, _epollFd);

        switch (status)
        {
            case NativeSsl.HANDSHAKE_COMPLETE:
                // Success! Send HTTP response immediately on this worker thread
                SendHttpResponse(request.Ssl);
                
                // Cleanup SSL and remove from active
                _activeConnections.Remove(request.ClientFd);
                NativeSsl.ssl_connection_destroy(request.Ssl);
                request.Ssl = IntPtr.Zero;
                
                Interlocked.Increment(ref _completed);
                request.Completion.TrySetResult(HandshakeResult.Success);
                break;

            case NativeSsl.HANDSHAKE_WANT_READ:
            case NativeSsl.HANDSHAKE_WANT_WRITE:
                // Need more I/O - epoll is already updated by ssl_try_handshake
                // Just wait for next epoll_wait to return this fd
                break;

            case NativeSsl.HANDSHAKE_ERROR:
            default:
                // Failed - cleanup and complete with error
                _activeConnections.Remove(request.ClientFd);
                NativeSsl.ssl_connection_destroy(request.Ssl);
                request.Ssl = IntPtr.Zero;
                Interlocked.Increment(ref _failed);
                request.Completion.TrySetResult(HandshakeResult.Failed);
                break;
        }
    }

    /// <summary>
    /// Send HTTP response through SSL connection.
    /// </summary>
    private static unsafe void SendHttpResponse(IntPtr ssl)
    {
        // Simple HTTP response
        ReadOnlySpan<byte> response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8;
        fixed (byte* ptr = response)
        {
            NativeSsl.ssl_write(ssl, ptr, response.Length);
        }
    }
}
