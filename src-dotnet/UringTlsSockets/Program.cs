using UringTlsSockets.Ssl;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace UringTlsSockets;

/// <summary>
/// io_uring TLS Server with Dedicated Worker Pool (nginx-style)
///
/// Architecture:
/// - Socket listen: Managed Socket bound to port
/// - Accept + TLS handshake: Dedicated worker threads with io_uring
/// - Workers submit accept SQEs on shared listen fd (auto-resubmitted)
/// - Workers use poll_add SQEs for handshake readiness (replaces epoll)
/// - All SQE submissions batched for minimal syscall overhead
///
/// Compared to the epoll-based DemoSemiUnmanagedSocket:
/// - No epoll_ctl ADD/MOD/DEL per connection
/// - Batched SQE submission + CQE reaping
/// - Accept via SQE eliminates separate accept4() syscall
/// </summary>
class Program
{
    private const int WorkerCount = 4;

    static async Task Main(string[] args)
    {
        Console.WriteLine("=== io_uring TLS Server with Dedicated Worker Pool ===");
        Console.WriteLine();

        // Parse arguments
        int port = GetPortArgument(args) ?? 5009;
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
        using var workerPool = UringWorkerPool.GetInstance(sslContext, workerCount);
        Console.WriteLine($"✓ io_uring worker pool created with {workerCount} threads");

        // ===== Create Listening Socket =====
        var listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listenSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        listenSocket.Bind(new IPEndPoint(IPAddress.Any, port));
        listenSocket.Listen(512);

        // Make listen socket non-blocking for io_uring accept
        listenSocket.Blocking = false;

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

        // Start workers — each creates its own io_uring ring and
        // submits an accept SQE on the shared listen fd
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

        listenSocket.Close();
    }

    private static async Task PrintStatsAsync(
        UringWorkerPool workerPool, Stopwatch stopwatch, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(1000, ct); }
            catch (OperationCanceledException) { break; }

            var elapsed = stopwatch.Elapsed.TotalSeconds;
            var (completed, failed, pending) = workerPool.GetStats();

            Console.WriteLine(
                $"[{DateTime.Now:HH:mm:ss}] Handshakes: {completed} ok, " +
                $"{failed} fail, {pending} pending ({completed / elapsed:F2}/sec)");
        }
    }

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

        if (curve != null)
        {
            foreach (var basePath in basePaths)
            {
                var certPath = Path.Combine(basePath, $"server-{curve}.crt");
                var keyPath = Path.Combine(basePath, $"server-{curve}.key");
                if (File.Exists(certPath) && File.Exists(keyPath))
                    return (certPath, keyPath);
            }
            Console.WriteLine(
                $"WARNING: Certificate for curve '{curve}' not found, falling back to default");
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
                var curveVal = args[i + 1].ToLower();
                if (curveVal == "p256" || curveVal == "p384")
                    return curveVal;
                Console.WriteLine($"Unknown curve: {curveVal}. Supported: p256, p384");
            }
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
        Console.WriteLine("Curve options:");
        Console.WriteLine("  p256   - ECDSA P-256 (fastest)");
        Console.WriteLine("  p384   - ECDSA P-384 (default, most CPU intensive)");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  dotnet run -- 5009 4 --curve p256");
        Console.WriteLine("  dotnet run -- --curve p384");
    }
}
