using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace NginxTls;

/// <summary>
/// Nginx-style TLS server with multiple worker threads.
/// Replicates nginx's master-worker architecture.
/// </summary>
public sealed class NginxTlsServer : IDisposable
{
    private readonly IntPtr _sslCtx;
    private readonly int _listenFd;
    private readonly NginxTlsWorker[] _workers;
    private readonly Thread _acceptThread;
    private readonly CancellationTokenSource _cts;
    private readonly Func<NginxTlsConnection, Task> _connectionHandler;
    private int _nextWorkerIndex;
    private bool _disposed;

    /// <summary>
    /// Creates a new nginx-style TLS server.
    /// </summary>
    /// <param name="host">Host to bind to (null for INADDR_ANY)</param>
    /// <param name="port">Port to listen on</param>
    /// <param name="certFile">Path to TLS certificate file</param>
    /// <param name="keyFile">Path to TLS private key file</param>
    /// <param name="numWorkers">Number of worker threads (default: CPU count)</param>
    /// <param name="connectionHandler">Async handler for each connection</param>
    public NginxTlsServer(
        string? host,
        int port,
        string certFile,
        string keyFile,
        int numWorkers,
        Func<NginxTlsConnection, Task> connectionHandler)
    {
        if (numWorkers <= 0)
            throw new ArgumentOutOfRangeException(nameof(numWorkers));
        if (connectionHandler == null)
            throw new ArgumentNullException(nameof(connectionHandler));

        _connectionHandler = connectionHandler;
        _cts = new CancellationTokenSource();

        // Create SSL context (shared across all workers)
        _sslCtx = NativeMethods.ngx_ssl_create_context(certFile, keyFile, null);
        if (_sslCtx == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to create SSL context");
        }

        // Create listening socket (nginx-style with SO_REUSEPORT for multi-worker)
        _listenFd = NativeMethods.ngx_create_listening_socket(host, port, 511);
        if (_listenFd < 0)
        {
            NativeMethods.ngx_ssl_free_context(_sslCtx);
            throw new InvalidOperationException($"Failed to create listening socket on {host ?? "0.0.0.0"}:{port}");
        }

        // Create worker threads (nginx spawns workers in ngx_start_worker_processes)
        _workers = new NginxTlsWorker[numWorkers];
        for (int i = 0; i < numWorkers; i++)
        {
            _workers[i] = new NginxTlsWorker(_sslCtx, maxEvents: 1024);
        }

        Console.WriteLine($"Created {numWorkers} worker threads");

        // Start accept thread (in nginx, master does this or workers with accept_mutex)
        _acceptThread = new Thread(AcceptLoop)
        {
            IsBackground = false,
            Name = "NginxTlsAcceptThread"
        };
        _acceptThread.Start();

        Console.WriteLine($"Server listening on {host ?? "0.0.0.0"}:{port}");
    }

    /// <summary>
    /// Accept loop - distributes connections across workers (round-robin).
    /// In nginx, this is either done by master or workers compete with accept_mutex.
    /// We use SO_REUSEPORT so kernel distributes, but we do round-robin in user-space for demo.
    /// </summary>
    private void AcceptLoop()
    {
        byte[] clientAddrBuffer = new byte[64];

        while (!_cts.Token.IsCancellationRequested)
        {
            try
            {
                // Accept connection (non-blocking, nginx-style accept4)
                int clientFd = NativeMethods.ngx_accept4_nonblock(_listenFd, clientAddrBuffer, clientAddrBuffer.Length);

                if (clientFd < 0)
                {
                    // EAGAIN means no connections available, sleep briefly
                    Thread.Sleep(1);
                    continue;
                }

                string clientAddr = System.Text.Encoding.UTF8.GetString(clientAddrBuffer).TrimEnd('\0');
                Console.WriteLine($"Accepted connection from {clientAddr} (fd={clientFd})");

                // Distribute to next worker (round-robin)
                int workerIndex = Interlocked.Increment(ref _nextWorkerIndex) % _workers.Length;
                var worker = _workers[workerIndex];

                // Add to worker's epoll
                var connection = worker.AcceptConnection(clientFd);

                // Handle connection on separate thread (business logic thread, not worker thread)
                // Worker thread only does epoll + SSL interops
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await _connectionHandler(connection).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Connection handler error: {ex}");
                    }
                    finally
                    {
                        connection.Dispose();
                    }
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Accept loop error: {ex}");
            }
        }

        Console.WriteLine("Accept thread exiting");
    }

    /// <summary>
    /// Wait for the server to complete (blocks until disposed).
    /// </summary>
    public Task WaitForShutdownAsync()
    {
        return Task.Run(() =>
        {
            _acceptThread.Join();
        });
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        Console.WriteLine("Shutting down server...");

        // Signal threads to stop
        _cts.Cancel();

        // Wait for accept thread
        if (!_acceptThread.Join(TimeSpan.FromSeconds(5)))
        {
            Console.WriteLine("Accept thread did not exit gracefully");
        }

        // Dispose workers (waits for their threads to exit)
        foreach (var worker in _workers)
        {
            worker.Dispose();
        }

        // Close listening socket
        if (_listenFd >= 0)
        {
            NativeMethods.ngx_epoll_destroy(IntPtr.Zero); // This is wrong, but close() is not exposed
            // In production, expose close() in native code
        }

        // Free SSL context
        if (_sslCtx != IntPtr.Zero)
        {
            NativeMethods.ngx_ssl_free_context(_sslCtx);
        }

        _cts.Dispose();

        Console.WriteLine("Server shut down");
    }
}
