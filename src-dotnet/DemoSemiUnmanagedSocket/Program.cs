using DemoSemiUnmanagedSocket.Interop;
using DemoSemiUnmanagedSocket.Ssl;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace DemoSemiUnmanagedSocket;

/// <summary>
/// Async TLS Server with Dedicated Worker Pool
/// 
/// Architecture:
/// - Socket accept: Managed (await socket.AcceptAsync())
/// - TLS handshake: Dedicated worker threads with epoll (SslWorkerPool)
/// - Application data: Managed processing with native SSL_read/SSL_write
/// 
/// The worker pool has N dedicated threads that:
/// - Each run their own epoll loop
/// - Handle ssl_do_handshake synchronously
/// - Don't use async/await - pure blocking I/O on dedicated threads
/// </summary>
class Program
{
    private const int WorkerCount = 4;

    static async Task Main(string[] args)
    {
        Console.WriteLine("=== TLS Server with Dedicated Worker Pool ===");
        Console.WriteLine();

        // Parse arguments
        int port = args.Length > 0 ? int.Parse(args[0]) : 5007;
        int workerCount = args.Length > 1 ? int.Parse(args[1]) : WorkerCount;
        
        // Find certificate paths
        var (certPath, keyPath) = FindCertificatePaths();
        if (certPath == null || keyPath == null)
        {
            Console.WriteLine("ERROR: No certificate files found!");
            return;
        }

        Console.WriteLine($"Port: {port}");
        Console.WriteLine($"Workers: {workerCount}");
        Console.WriteLine($"Cert: {certPath}");
        Console.WriteLine($"Key: {keyPath}");
        Console.WriteLine();

        // ===== Create SSL Context (shared across all connections) =====
        using var sslContext = new SslContext(certPath, keyPath);
        Console.WriteLine($"✓ SSL_CTX created: {sslContext.Handle}");

        // ===== Create Worker Pool =====
        using var workerPool = SslWorkerPool.GetInstance(sslContext, workerCount);
        Console.WriteLine($"✓ Worker pool created with {workerCount} threads");

        // ===== Create Listening Socket =====
        var listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listenSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        listenSocket.Bind(new IPEndPoint(IPAddress.Any, port));
        listenSocket.Listen(512);
        
        Console.WriteLine($"✓ Listening on port {port}");
        Console.WriteLine();
        Console.WriteLine("Press Ctrl+C to stop...");
        Console.WriteLine();

        // Handle Ctrl+C
        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        var stopwatch = Stopwatch.StartNew();

        // Start stats printer
        _ = PrintStatsAsync(workerPool, stopwatch, cts.Token);

        // Accept loop
        try
        {
            while (!cts.Token.IsCancellationRequested)
            {
                Socket clientSocket;
                try
                {
                    clientSocket = await listenSocket.AcceptAsync(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                // Submit to worker pool and handle response
                _ = HandleConnectionAsync(clientSocket, workerPool, cts.Token);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected on shutdown
        }

        // Final stats
        stopwatch.Stop();
        var (completed, failed, _) = workerPool.GetStats();
        PrintFinalStats(completed, failed, stopwatch.Elapsed);

        listenSocket.Close();
    }

    /// <summary>
    /// Handle a single client connection using the worker pool.
    /// </summary>
    private static async Task HandleConnectionAsync(
        Socket clientSocket, 
        SslWorkerPool workerPool,
        CancellationToken ct)
    {
        try
        {
            // Submit handshake to worker pool
            // This returns when handshake is complete (or failed)
            var result = await workerPool.SubmitHandshakeAsync(clientSocket);

            if (result == HandshakeResult.Success)
            {
                // Handshake complete! 
                // For now, we just close - SSL handle is owned by worker
                // TODO: Get SSL handle and do SSL_write here for response
            }
        }
        catch (Exception ex)
        {
            if (ex is not OperationCanceledException)
            {
                // Console.WriteLine($"[Error] {ex.Message}");
            }
        }
        finally
        {
            // Close the managed socket
            try { clientSocket.Shutdown(SocketShutdown.Both); } catch { }
            clientSocket.Close();
        }
    }

    /// <summary>
    /// Print stats periodically.
    /// </summary>
    private static async Task PrintStatsAsync(SslWorkerPool workerPool, Stopwatch stopwatch, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(5000, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            var elapsed = stopwatch.Elapsed.TotalSeconds;
            var (completed, failed, pending) = workerPool.GetStats();

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Handshakes: {completed} ok, {failed} fail, {pending} pending ({completed / elapsed:F2}/sec)");
        }
    }

    /// <summary>
    /// Print final statistics.
    /// </summary>
    private static void PrintFinalStats(long completed, long failed, TimeSpan elapsed)
    {
        Console.WriteLine();
        Console.WriteLine("=== Final Statistics ===");
        Console.WriteLine($"Runtime: {elapsed.TotalSeconds:F2} seconds");
        Console.WriteLine($"Completed handshakes: {completed}");
        Console.WriteLine($"Failed handshakes: {failed}");
        Console.WriteLine($"Handshakes/sec: {completed / elapsed.TotalSeconds:F2}");
        Console.WriteLine("========================");
    }

    private static (string? certPath, string? keyPath) FindCertificatePaths()
    {
        var basePaths = new[]
        {
            Path.Combine("certs"),
            Path.Combine("..", "..", "certs")
        };

        foreach (var basePath in basePaths)
        {
            var certPath = Path.Combine(basePath, "server.crt");
            var keyPath = Path.Combine(basePath, "server.key");

            if (File.Exists(certPath) && File.Exists(keyPath))
                return (certPath, keyPath);

            certPath = Path.Combine(basePath, "server-p384.crt");
            keyPath = Path.Combine(basePath, "server-p384.key");

            if (File.Exists(certPath) && File.Exists(keyPath))
                return (certPath, keyPath);
        }

        return (null, null);
    }
}
