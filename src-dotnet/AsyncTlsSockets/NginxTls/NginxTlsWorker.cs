using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;

namespace NginxTls;

/// <summary>
/// Nginx-style worker thread that ONLY does epoll + OpenSSL interops.
/// This thread never blocks and processes events in a tight loop.
/// Business logic runs on other threads and communicates via async/await.
/// </summary>
public sealed class NginxTlsWorker : IDisposable
{
    private readonly IntPtr _epollCtx;
    private readonly IntPtr _sslCtx;
    private readonly Thread _workerThread;
    private readonly CancellationTokenSource _cts;
    private readonly int _maxEvents;

    // Nginx-style posted events queue (operations queued from business threads)
    private readonly ConcurrentQueue<(NginxTlsConnection, OperationType)> _postedEvents;

    // Active connections managed by this worker
    private readonly ConcurrentDictionary<IntPtr, NginxTlsConnection> _connections;

    // Connections pending removal (deferred to avoid epoll race conditions)
    private readonly ConcurrentQueue<NginxTlsConnection> _pendingRemovals;

    private bool _disposed;

    public NginxTlsWorker(IntPtr sslCtx, int maxEvents = 1024)
    {
        _sslCtx = sslCtx;
        _maxEvents = maxEvents;
        _epollCtx = NativeMethods.ngx_epoll_create(maxEvents);

        if (_epollCtx == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to create epoll context");
        }

        _postedEvents = new ConcurrentQueue<(NginxTlsConnection, OperationType)>();
        _connections = new ConcurrentDictionary<IntPtr, NginxTlsConnection>();
        _pendingRemovals = new ConcurrentQueue<NginxTlsConnection>();
        _cts = new CancellationTokenSource();

        // Start dedicated worker thread (nginx-style)
        _workerThread = new Thread(WorkerLoop)
        {
            IsBackground = false,
            Name = $"NginxTlsWorker-{Environment.CurrentManagedThreadId}",
            Priority = ThreadPriority.AboveNormal // Higher priority for I/O worker
        };
        _workerThread.Start();
    }

    /// <summary>
    /// Accepts a new connection and adds it to this worker's epoll.
    /// This should be called from accept thread or can be distributed across workers.
    /// </summary>
    public NginxTlsConnection AcceptConnection(int clientFd)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(NginxTlsWorker));

        // Create native connection
        IntPtr connHandle = NativeMethods.ngx_connection_create(_epollCtx, _sslCtx, clientFd);
        if (connHandle == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to create connection");
        }

        // Add to epoll (edge-triggered)
        int result = NativeMethods.ngx_epoll_add_connection(_epollCtx, connHandle);
        if (result != NativeMethods.NGX_OK)
        {
            NativeMethods.ngx_connection_free(connHandle);
            throw new InvalidOperationException("Failed to add connection to epoll");
        }

        // Create managed wrapper
        var connection = new NginxTlsConnection(connHandle, this);
        _connections.TryAdd(connHandle, connection);

        return connection;
    }

    /// <summary>
    /// Queue an operation to be processed by the worker thread.
    /// This is called from business threads when they call ReadAsync/WriteAsync.
    /// </summary>
    internal void QueueOperation(NginxTlsConnection connection, OperationType opType)
    {
        _postedEvents.Enqueue((connection, opType));
    }

    /// <summary>
    /// Remove connection from worker (called when connection is disposed).
    /// Deferred to avoid race conditions with epoll.
    /// </summary>
    internal void RemoveConnection(NginxTlsConnection connection)
    {
        _pendingRemovals.Enqueue(connection);
    }

    /// <summary>
    /// Main worker loop - this is the ONLY thread that does epoll + SSL interops.
    /// Replicates nginx's ngx_process_events_and_timers().
    /// </summary>
    private void WorkerLoop()
    {
        var readyConns = new IntPtr[_maxEvents];
        var readyEvents = new int[_maxEvents];

        while (!_cts.Token.IsCancellationRequested)
        {
            try
            {
                // 1. Process posted events from business threads (nginx does this first)
                ProcessPostedEvents();

                // 2. Process pending removals
                ProcessPendingRemovals();

                // 3. Call epoll_wait (nginx does this with timeout)
                // Use short timeout (100ms) to process posted events frequently
                int numEvents = NativeMethods.ngx_epoll_wait(
                    _epollCtx,
                    readyConns,
                    readyEvents,
                    _maxEvents,
                    100); // 100ms timeout

                if (numEvents > 0)
                {
                    // 4. Process ready connections (nginx-style event processing)
                    ProcessReadyConnections(readyConns, readyEvents, numEvents);
                }
                else if (numEvents < 0)
                {
                    // Error in epoll_wait (interrupted by signal is OK)
                    int errno = Marshal.GetLastWin32Error();
                    if (errno != 4) // EINTR
                    {
                        Console.WriteLine($"epoll_wait error: {errno}");
                    }
                }

                // Continue loop (no blocking, just like nginx)
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Worker loop error: {ex}");
            }
        }

        Console.WriteLine("Worker thread exiting");
    }

    /// <summary>
    /// Process posted events queue (nginx-style deferred event processing).
    /// These are operations queued from business threads.
    /// </summary>
    private void ProcessPostedEvents()
    {
        // Process up to a reasonable number per iteration to avoid starvation
        int processed = 0;
        const int maxPerIteration = 128;

        while (processed < maxPerIteration && _postedEvents.TryDequeue(out var item))
        {
            var (connection, opType) = item;

            try
            {
                switch (opType)
                {
                    case OperationType.Handshake:
                        // Try to process handshake immediately
                        // If it returns false (NGX_AGAIN), epoll will call us again
                        connection.TryProcessHandshake();
                        break;

                    case OperationType.Read:
                        connection.TryProcessRead();
                        break;

                    case OperationType.Write:
                        connection.TryProcessWrite();
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing posted event: {ex}");
            }

            processed++;
        }
    }

    /// <summary>
    /// Process connections ready for I/O (from epoll_wait).
    /// This is nginx's ngx_epoll_process_events().
    /// </summary>
    private void ProcessReadyConnections(IntPtr[] readyConns, int[] readyEvents, int numEvents)
    {
        for (int i = 0; i < numEvents; i++)
        {
            IntPtr connHandle = readyConns[i];
            int eventType = readyEvents[i];

            if (!_connections.TryGetValue(connHandle, out var connection))
            {
                // Stale event (connection was removed) - nginx detects this with instance counter
                continue;
            }

            try
            {
                if (eventType == NativeMethods.NGX_ERROR)
                {
                    // Error on connection - close it
                    Console.WriteLine($"Connection error on fd {NativeMethods.ngx_connection_get_fd(connHandle)}");
                    connection.Dispose();
                    continue;
                }

                // Process based on what's pending (nginx does this)
                // In edge-triggered mode, we must drain all available data

                // Try handshake first if pending
                if (!connection.TryProcessHandshake())
                {
                    // Handshake still in progress, will be called again on next event
                    continue;
                }

                // Try read if pending and event is read-ready
                if (eventType == NativeMethods.NGX_READ_EVENT)
                {
                    // Keep reading until NGX_AGAIN (edge-triggered requirement)
                    while (connection.TryProcessRead())
                    {
                        // Continue draining
                    }
                }

                // Try write if pending and event is write-ready
                if (eventType == NativeMethods.NGX_WRITE_EVENT)
                {
                    connection.TryProcessWrite();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing ready connection: {ex}");
                connection.Dispose();
            }
        }
    }

    /// <summary>
    /// Process pending connection removals (deferred to avoid epoll race conditions).
    /// </summary>
    private void ProcessPendingRemovals()
    {
        while (_pendingRemovals.TryDequeue(out var connection))
        {
            IntPtr handle = connection.NativeHandle;

            if (_connections.TryRemove(handle, out _))
            {
                // Remove from epoll
                NativeMethods.ngx_epoll_del_connection(_epollCtx, handle);
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        // Signal worker thread to stop
        _cts.Cancel();

        // Wait for worker thread to exit
        if (!_workerThread.Join(TimeSpan.FromSeconds(5)))
        {
            Console.WriteLine("Worker thread did not exit gracefully");
        }

        // Clean up connections
        foreach (var conn in _connections.Values)
        {
            try
            {
                conn.Dispose();
            }
            catch { }
        }
        _connections.Clear();

        // Clean up native resources
        if (_epollCtx != IntPtr.Zero)
        {
            NativeMethods.ngx_epoll_destroy(_epollCtx);
        }

        _cts.Dispose();
    }
}
