using BioEpollWorkers.Interop;
using BioEpollWorkers.Ssl;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace BioEpollWorkers;

/// <summary>
/// Experiment 05 — mem-BIO + dedicated epoll worker threads.
///
/// Architecturally identical to experiment 04 (DemoSemiUnmanagedSocket):
///   - Same nginx-style worker pool
///   - Same EPOLLEXCLUSIVE accept distribution
///   - Same per-worker epoll loop
///
/// The ONLY difference is the native library it loads. The 04 version
/// uses SSL_set_fd (OpenSSL talks to the socket directly). This version
/// uses memory BIOs: managed code (through the native helper) read()s the
/// socket and BIO_write()s into rbio, then drains wbio and write()s back.
///
/// Pair-difference 04 vs 05 isolates the cost of the SSL_set_fd
/// optimization from threading-model and accept-path effects, which are
/// held constant.
/// </summary>
class Program
{
    private const int WorkerCount = 4;
    private const int DefaultPort = 5008;

    static async Task Main(string[] args)
    {
        Console.WriteLine("=== TLS Server: mem-BIO + dedicated epoll workers (experiment 05) ===");
        Console.WriteLine();

        int port = GetPortArgument(args) ?? DefaultPort;
        int workerCount = GetWorkerCountArgument(args) ?? WorkerCount;
        string? curve = GetCurveArgument(args);

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
        Console.WriteLine($"Key:  {keyPath}");
        Console.WriteLine();

        using var sslContext = new SslContext(certPath, keyPath);
        Console.WriteLine($"✓ SSL_CTX created (TLS 1.3 only, session cache OFF): {sslContext.Handle}");

        using var workerPool = SslWorkerPool.GetInstance(sslContext, workerCount);
        Console.WriteLine($"✓ Worker pool created with {workerCount} threads");

        var listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listenSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        listenSocket.Bind(new IPEndPoint(IPAddress.Any, port));
        listenSocket.Listen(512);
        listenSocket.Blocking = false;

        Console.WriteLine($"✓ Listening on port {port}");
        Console.WriteLine();
        Console.WriteLine("Press Ctrl+C to stop...");
        Console.WriteLine();

        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        var stopwatch = Stopwatch.StartNew();
        workerPool.SetListenSocketAndStart(listenSocket);
        _ = PrintStatsAsync(workerPool, stopwatch, cts.Token);

        try
        {
            await Task.Delay(Timeout.Infinite, cts.Token);
        }
        catch (OperationCanceledException) { }

        stopwatch.Stop();
        var (completed, failed, _) = workerPool.GetStats();
        PrintFinalStats(completed, failed, stopwatch.Elapsed);

        listenSocket.Close();
    }

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

    private static void PrintFinalStats(long completed, long failed, TimeSpan elapsed)
    {
        Console.WriteLine();
        Console.WriteLine("=== Final Statistics ===");
        Console.WriteLine($"Runtime: {elapsed.TotalSeconds:F2} seconds");
        Console.WriteLine($"Completed handshakes: {completed}");
        Console.WriteLine($"Failed handshakes:    {failed}");
        Console.WriteLine($"Handshakes/sec:       {completed / elapsed.TotalSeconds:F2}");
        Console.WriteLine("========================");
    }

    private static (string? certPath, string? keyPath) FindCertificatePaths(string? curve = null)
    {
        var basePaths = new[]
        {
            Path.Combine("certs"),
            Path.Combine("..", "..", "certs"),
            Path.Combine("..", "..", "..", "..", "certs"),
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
                var curve = args[i + 1].ToLower();
                if (curve == "p256" || curve == "p384") return curve;
                Console.WriteLine($"Unknown curve: {curve}. Supported: p256, p384");
            }
            if (args[i] == "p256" || args[i] == "p384") return args[i].ToLower();
        }
        return null;
    }

    private static void PrintUsage()
    {
        Console.WriteLine();
        Console.WriteLine("Usage: dotnet run -- [port] [workers] [--curve <p256|p384>]");
    }
}
