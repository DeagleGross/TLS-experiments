using DemoSemiUnmanagedSocket.Interop;
using DemoSemiUnmanagedSocket.Ssl;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace DemoSemiUnmanagedSocket;

/// <summary>
/// Async TLS Server with Dedicated Worker Pool (nginx-style)
/// 
/// Architecture:
/// - Socket listen: Managed Socket bound to port
/// - Accept + TLS handshake: Dedicated worker threads with epoll
/// - Workers add listen socket to their epoll with EPOLLEXCLUSIVE
/// - Workers accept connections directly in their epoll loop (no cross-thread handoff)
/// 
/// This eliminates the accept overhead that caused the 18% gap in light load.
/// </summary>
class Program
{
    private const int WorkerCount = 4;

    static async Task Main(string[] args)
    {
        Console.WriteLine("=== TLS Server with Dedicated Worker Pool (nginx-style) ===");
        Console.WriteLine();

        // Parse arguments
        int port = GetPortArgument(args) ?? 5007;
        int workerCount = GetWorkerCountArgument(args) ?? WorkerCount;
        string? curve = GetCurveArgument(args);
        
        // Find certificate paths
        var (certPath, keyPath) = FindCertificatePaths(curve);
        if (certPath == null || keyPath == null)
        {
            Console.WriteLine("ERROR: No certificate files found!");
            PrintUsage();
            return;
        }

        Console.WriteLine($"Port: {port}");
        Console.WriteLine($"Workers: {workerCount}");
        if (curve != null) Console.WriteLine($"Curve: {curve}");
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
        
        // Make listen socket non-blocking for epoll
        SetNonBlocking(listenSocket);
        
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

        // Start workers with the listen socket
        // Workers will add listen_fd to their epoll and accept connections directly
        workerPool.SetListenSocketAndStart(listenSocket);

        // Start stats printer
        _ = PrintStatsAsync(workerPool, stopwatch, cts.Token);

        // Wait for cancellation (workers do all the work)
        try
        {
            await Task.Delay(Timeout.Infinite, cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Expected on shutdown
        }

        // Final stats
        stopwatch.Stop();
        var (completed, failed, _) = workerPool.GetStats();
        PrintFinalStats(completed, failed, stopwatch.Elapsed);

        // Keep listen socket alive until we're done
        listenSocket.Close();
    }

    /// <summary>
    /// Set the socket to non-blocking mode.
    /// </summary>
    private static void SetNonBlocking(Socket socket)
    {
        socket.Blocking = false;
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
                await Task.Delay(1000, ct);
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

    private static (string? certPath, string? keyPath) FindCertificatePaths(string? curve = null)
    {
        var basePaths = new[]
        {
            Path.Combine("certs"),
            Path.Combine("..", "..", "certs")
        };

        // If curve is specified, look for that specific cert
        if (curve != null)
        {
            foreach (var basePath in basePaths)
            {
                var certPath = Path.Combine(basePath, $"server-{curve}.crt");
                var keyPath = Path.Combine(basePath, $"server-{curve}.key");

                if (File.Exists(certPath) && File.Exists(keyPath))
                    return (certPath, keyPath);
            }
            Console.WriteLine($"WARNING: Certificate for curve '{curve}' not found, falling back to default");
        }

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

    private static int? GetPortArgument(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--port" && i + 1 < args.Length && int.TryParse(args[i + 1], out var port))
                return port;
            // First positional number that's likely a port (> 1000)
            if (int.TryParse(args[i], out var p) && p > 1000 && args[i] != "p256" && args[i] != "p384")
                return p;
        }
        return null;
    }

    private static int? GetWorkerCountArgument(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--workers" && i + 1 < args.Length && int.TryParse(args[i + 1], out var workers))
                return workers;
        }
        // Second positional number (small, likely worker count)
        int posCount = 0;
        for (int i = 0; i < args.Length; i++)
        {
            if (int.TryParse(args[i], out var n) && args[i] != "p256" && args[i] != "p384")
            {
                posCount++;
                if (posCount == 2) return n;
            }
        }
        return null;
    }

    private static string? GetCurveArgument(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--curve" && i + 1 < args.Length)
            {
                var curve = args[i + 1].ToLower();
                if (curve == "p256" || curve == "p384")
                    return curve;
                Console.WriteLine($"Unknown curve: {curve}. Supported: p256, p384");
            }
            // Also support positional argument
            if (args[i] == "p256" || args[i] == "p384")
                return args[i].ToLower();
        }
        return null;
    }

    private static void PrintUsage()
    {
        Console.WriteLine();
        Console.WriteLine("Usage: dotnet run -- [port] [workers] [--curve <curve>]");
        Console.WriteLine();
        Console.WriteLine("Curve options (lighter to heavier):");
        Console.WriteLine("  p256   - ECDSA P-256 (fastest)");
        Console.WriteLine("  p384   - ECDSA P-384 (default, most CPU intensive)");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  dotnet run -- 5007 4 --curve p256");
        Console.WriteLine("  dotnet run -- --curve p384");
    }
}
