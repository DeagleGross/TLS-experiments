using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

// CONSTS
const int WorkerCount = 4;
const int PORT = 5008;

Console.WriteLine("=== TLS Server with Async socket read \\ write ===");
Console.WriteLine();

// Parse arguments
int port = args.Length > 0 ? int.Parse(args[0]) : PORT;
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
_ = PrintFinalStats(workerPool, stopwatch, cts.Token);

/// <summary> 
/// Print stats periodically.
/// </summary>
static async Task PrintStatsAsync(SslWorkerPool workerPool, Stopwatch stopwatch, CancellationToken ct)
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
static void PrintFinalStats(long completed, long failed, TimeSpan elapsed)
{
    Console.WriteLine();
    Console.WriteLine("=== Final Statistics ===");
    Console.WriteLine($"Runtime: {elapsed.TotalSeconds:F2} seconds");
    Console.WriteLine($"Completed handshakes: {completed}");
    Console.WriteLine($"Failed handshakes: {failed}");
    Console.WriteLine($"Handshakes/sec: {completed / elapsed.TotalSeconds:F2}");
    Console.WriteLine("========================");
}

static (string? certPath, string? keyPath) FindCertificatePaths()
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