using System.Net.Sockets;

namespace UringTlsSockets.Ssl;

/// <summary>
/// Pool of dedicated io_uring SSL worker threads (nginx-style).
/// Each worker owns its own io_uring ring and processes connections independently.
/// </summary>
internal sealed class UringWorkerPool : IDisposable
{
    private static UringWorkerPool? _instance;
    private static readonly object _instanceLock = new();

    private readonly UringWorker[] _workers;
    private readonly int _workerCount;
    private bool _disposed;

    public static UringWorkerPool GetInstance(SslContext sslContext, int workerCount = 4)
    {
        if (_instance == null)
        {
            lock (_instanceLock)
            {
                _instance ??= new UringWorkerPool(sslContext, workerCount);
            }
        }
        return _instance;
    }

    private UringWorkerPool(SslContext sslContext, int workerCount)
    {
        _workerCount = workerCount;
        _workers = new UringWorker[workerCount];

        for (int i = 0; i < workerCount; i++)
            _workers[i] = new UringWorker(i, sslContext);

        Console.WriteLine($"[UringWorkerPool] Created {workerCount} workers");
    }

    /// <summary>
    /// Pass the shared listen socket fd to all workers and start them.
    /// Each worker submits a single-shot accept SQE on this fd via its own io_uring ring.
    /// </summary>
    public void SetListenSocketAndStart(Socket listenSocket)
    {
        int listenFd = (int)listenSocket.Handle;
        Console.WriteLine($"[UringWorkerPool] Listen fd: {listenFd}");

        for (int i = 0; i < _workerCount; i++)
            _workers[i].Start(listenFd);

        Console.WriteLine(
            $"[UringWorkerPool] Started {_workerCount} workers with " +
            $"io_uring accept on listen fd");
    }

    public (long completed, long failed, long pending) GetStats()
    {
        long completed = 0, failed = 0, pending = 0;
        foreach (var worker in _workers)
        {
            var stats = worker.GetStats();
            completed += stats.completed;
            failed    += stats.failed;
            pending   += stats.pending;
        }
        return (completed, failed, pending);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            foreach (var worker in _workers)
                worker.Stop();
            _disposed = true;
        }
    }
}
