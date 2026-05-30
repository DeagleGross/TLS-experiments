using BioEpollWorkers.Interop;
using System.Net.Sockets;

namespace BioEpollWorkers.Ssl;

/// <summary>
/// Pool of dedicated SSL worker threads (nginx-style).
/// Identical to experiment 04's pool.
/// </summary>
internal sealed class SslWorkerPool : IDisposable
{
    private static SslWorkerPool? _instance;
    private static readonly object _instanceLock = new();

    private readonly SslWorker[] _workers;
    private readonly int _workerCount;
    private readonly SslContext _sslContext;
    private bool _disposed;

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

        for (int i = 0; i < workerCount; i++)
        {
            _workers[i] = new SslWorker(i, sslContext);
        }

        Console.WriteLine($"[SslWorkerPool] Created {workerCount} workers");
    }

    public void SetListenSocketAndStart(Socket listenSocket)
    {
        int listenFd = (int)listenSocket.Handle;
        Console.WriteLine($"[SslWorkerPool] Listen fd: {listenFd}");

        for (int i = 0; i < _workerCount; i++)
        {
            _workers[i].Start(listenFd);
        }

        Console.WriteLine($"[SslWorkerPool] Started {_workerCount} workers with listen fd in epoll");
    }

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
