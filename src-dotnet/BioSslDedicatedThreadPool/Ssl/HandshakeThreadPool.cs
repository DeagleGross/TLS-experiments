using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Sockets;

namespace BioSslDedicatedThreadPool.Ssl;

/// <summary>
/// Dedicated THREAD pool for SSL handshake operations.
/// Worker THREADS (not tasks!) ONLY do OpenSSL P/Invoke operations.
/// Socket I/O happens on separate ThreadPool threads.
/// This ensures OpenSSL operations stay on dedicated threads.
/// </summary>
internal sealed class HandshakeThreadPool : IDisposable
{
    private readonly int _threadCount;
    private readonly Thread[] _workerThreads;
    private readonly BlockingCollection<HandshakeWorkItem> _workQueue;
    private readonly CancellationTokenSource _cts;
    private bool _disposed;

    // Statistics
    private long _totalHandshakes;
    private long _successfulHandshakes;
    private long _failedHandshakes;
    private long _totalHandshakeAttempts;
    private long _queuedItems;
    private long _currentQueueSize; // Track current items in queue

    public long CurrentQueueSize => Interlocked.Read(ref _currentQueueSize);

    public HandshakeThreadPool(int threadCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(threadCount);

        _threadCount = threadCount;
        _workerThreads = new Thread[threadCount];
        _workQueue = new BlockingCollection<HandshakeWorkItem>(new ConcurrentQueue<HandshakeWorkItem>());
        _cts = new CancellationTokenSource();

        // Start DEDICATED worker THREADS (not tasks!)
        for (int i = 0; i < threadCount; i++)
        {
            int workerId = i;
            _workerThreads[i] = new Thread(() => WorkerThreadLoop(workerId))
            {
                Name = $"SSL-Worker-{i}",
                IsBackground = true,
                Priority = ThreadPriority.AboveNormal // OpenSSL operations are latency-sensitive
            };
            _workerThreads[i].Start();
        }

        Console.WriteLine($"[HandshakeThreadPool] Started {threadCount} DEDICATED worker THREADS (OpenSSL only)");
    }

    /// <summary>
    /// Queue a handshake operation. Returns immediately.
    /// The handshake will be processed by one of the dedicated worker THREADS.
    /// </summary>
    public Task<bool> QueueHandshakeAsync(BioSslConnection connection, Socket socket)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var workItem = new HandshakeWorkItem(connection, socket);
        
        Interlocked.Increment(ref _queuedItems);
        Interlocked.Increment(ref _currentQueueSize);
        
        // Queue for worker THREAD (not async!)
        _workQueue.Add(workItem, _cts.Token);

        return workItem.CompletionSource.Task;
    }

    /// <summary>
    /// Worker THREAD loop - processes handshake work items.
    /// This thread ONLY does OpenSSL P/Invoke operations (no socket I/O!).
    /// Socket I/O happens on separate threads via callbacks.
    /// </summary>
    private void WorkerThreadLoop(int workerId)
    {
        Console.WriteLine($"[Worker {workerId}] Started - THREAD dedicated to OpenSSL operations only");

        try
        {
            foreach (var workItem in _workQueue.GetConsumingEnumerable(_cts.Token))
            {
                Interlocked.Decrement(ref _currentQueueSize);
                Interlocked.Increment(ref _totalHandshakes);

                try
                {
                    // Process ONE iteration of handshake (OpenSSL only!)
                    // This thread ONLY does:
                    // 1. SSL_do_handshake()
                    // 2. BIO_ctrl_pending()
                    // 3. BIO_read()
                    // 4. BIO_write()
                    HandshakeState state = workItem.Connection.DoHandshakeStepSync(out byte[]? dataToSend, out bool needsReceive);

                    switch (state)
                    {
                        case HandshakeState.NeedsMoreData:
                            // Need socket I/O - delegate to ThreadPool
                            if (dataToSend != null && dataToSend.Length > 0)
                            {
                                // Send data on ThreadPool thread
                                _ = Task.Run(async () =>
                                {
                                    try
                                    {
                                        await workItem.Socket.SendAsync(new Memory<byte>(dataToSend), SocketFlags.None);
                                        
                                        // After send, might need to receive
                                        if (needsReceive)
                                        {
                                            byte[] buffer = new byte[4096];
                                            int received = await workItem.Socket.ReceiveAsync(new Memory<byte>(buffer), SocketFlags.None);
                                            
                                            if (received > 0)
                                            {
                                                // Write received data to BIO (on THIS thread, not worker)
                                                workItem.Connection.WriteReceivedDataToBio(buffer, received);
                                            }
                                        }
                                        
                                        // Re-queue for worker thread to process
                                        Interlocked.Increment(ref _currentQueueSize);
                                        _workQueue.Add(workItem, _cts.Token);
                                    }
                                    catch (Exception ex)
                                    {
                                        workItem.CompletionSource.SetException(ex);
                                    }
                                });
                            }
                            else if (needsReceive)
                            {
                                // Just receive on ThreadPool thread
                                _ = Task.Run(async () =>
                                {
                                    try
                                    {
                                        byte[] buffer = new byte[16384];
                                        int received = await workItem.Socket.ReceiveAsync(new Memory<byte>(buffer), SocketFlags.None);
                                        
                                        if (received > 0)
                                        {
                                            workItem.Connection.WriteReceivedDataToBio(buffer, received);
                                        }
                                        
                                        Interlocked.Increment(ref _currentQueueSize);
                                        _workQueue.Add(workItem, _cts.Token);
                                    }
                                    catch (Exception ex)
                                    {
                                        workItem.CompletionSource.SetException(ex);
                                    }
                                });
                            }
                            else
                            {
                                // Re-queue immediately (no socket I/O needed)
                                Interlocked.Increment(ref _currentQueueSize);
                                _workQueue.Add(workItem, _cts.Token);
                            }
                            break;

                        case HandshakeState.Complete:
                            // Send final data if needed
                            if (dataToSend != null && dataToSend.Length > 0)
                            {
                                _ = Task.Run(async () =>
                                {
                                    try
                                    {
                                        await workItem.Socket.SendAsync(new Memory<byte>(dataToSend), SocketFlags.None);
                                        
                                        Interlocked.Increment(ref _successfulHandshakes);
                                        Interlocked.Add(ref _totalHandshakeAttempts, workItem.Connection.HandshakeAttempts);
                                        workItem.CompletionSource.SetResult(true);
                                    }
                                    catch (Exception ex)
                                    {
                                        workItem.CompletionSource.SetException(ex);
                                    }
                                });
                            }
                            else
                            {
                                Interlocked.Increment(ref _successfulHandshakes);
                                Interlocked.Add(ref _totalHandshakeAttempts, workItem.Connection.HandshakeAttempts);
                                workItem.CompletionSource.SetResult(true);
                            }
                            break;

                        case HandshakeState.Failed:
                            Interlocked.Increment(ref _failedHandshakes);
                            workItem.CompletionSource.SetResult(false);
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref _failedHandshakes);
                    workItem.CompletionSource.SetException(ex);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown
        }

        Console.WriteLine($"[Worker {workerId}] Stopped");
    }

    public (long Total, long Success, long Failed, double AvgAttempts, long Queued, long QueueSize) GetStatistics()
    {
        long total = Interlocked.Read(ref _totalHandshakes);
        long success = Interlocked.Read(ref _successfulHandshakes);
        long failed = Interlocked.Read(ref _failedHandshakes);
        long attempts = Interlocked.Read(ref _totalHandshakeAttempts);
        long queued = Interlocked.Read(ref _queuedItems);
        long queueSize = Interlocked.Read(ref _currentQueueSize);

        double avgAttempts = success > 0 ? (double)attempts / success : 0;

        return (total, success, failed, avgAttempts, queued, queueSize);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _cts.Cancel();
            _workQueue.CompleteAdding();

            // Wait for worker threads to finish
            foreach (var thread in _workerThreads)
            {
                thread?.Join(TimeSpan.FromSeconds(5));
            }

            _workQueue.Dispose();
            _cts.Dispose();
            _disposed = true;

            Console.WriteLine("[HandshakeThreadPool] Stopped");
        }
    }
}

/// <summary>
/// Represents a single handshake work item in the queue.
/// </summary>
internal sealed class HandshakeWorkItem
{
    public BioSslConnection Connection { get; }
    public Socket Socket { get; }
    public TaskCompletionSource<bool> CompletionSource { get; }

    public HandshakeWorkItem(BioSslConnection connection, Socket socket)
    {
        Connection = connection ?? throw new ArgumentNullException(nameof(connection));
        Socket = socket ?? throw new ArgumentNullException(nameof(socket));
        CompletionSource = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
