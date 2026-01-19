using DemoSemiUnmanagedSocket.Interop;
using System.Net.Sockets;

namespace DemoSemiUnmanagedSocket.Ssl;



/// <summary>
/// Pool of dedicated SSL worker threads.
/// 
/// Architecture (similar to nginx):
/// - Fixed number of worker threads (default 4)
/// - Each worker has its own epoll instance
/// - Listen socket added to each worker's epoll with EPOLLEXCLUSIVE
/// - Workers accept connections directly in their epoll loop
/// - Workers run a synchronous loop: epoll_wait → accept/ssl_do_handshake
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

        // Create worker threads (don't start yet - need listen fd first)
        for (int i = 0; i < workerCount; i++)
        {
            _workers[i] = new SslWorker(i, sslContext);
        }

        Console.WriteLine($"[SslWorkerPool] Created {workerCount} workers");
    }

    /// <summary>
    /// Set the listen socket and start workers.
    /// Workers will add the listen fd to their epoll with EPOLLEXCLUSIVE.
    /// </summary>
    public void SetListenSocketAndStart(Socket listenSocket)
    {
        // Get the raw file descriptor from the managed Socket
        int listenFd = GetSocketFd(listenSocket);
        Console.WriteLine($"[SslWorkerPool] Listen fd: {listenFd}");

        // Start workers with the listen fd
        for (int i = 0; i < _workerCount; i++)
        {
            _workers[i].Start(listenFd);
        }

        Console.WriteLine($"[SslWorkerPool] Started {_workerCount} workers with listen fd in epoll");
    }

    /// <summary>
    /// Get the native file descriptor from a managed Socket.
    /// </summary>
    private static int GetSocketFd(Socket socket)
    {
        // Socket.Handle returns nint (the raw fd) in modern .NET
        return (int)socket.Handle;
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
