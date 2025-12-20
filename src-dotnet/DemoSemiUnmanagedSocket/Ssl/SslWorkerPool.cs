using DemoSemiUnmanagedSocket.Interop;
using DemoSemiUnmanagedSocket.Ssl.Requests;
using System.Collections.Concurrent;
using System.Net.Sockets;

namespace DemoSemiUnmanagedSocket.Ssl;



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
