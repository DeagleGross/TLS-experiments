using AsyncTlsSockets;
using Serilog;
using System.Buffers;
using System.Diagnostics;

Log.Logger = new LoggerConfiguration()
    // .MinimumLevel.Error()
    //.MinimumLevel.Debug()
    .WriteTo.Console()
    .CreateLogger();

// CONSTS
const int WorkerCount = 16;
const int PORT = 5008;

Log.Information("=== TLS Server with workers ===");
Log.Information("------");

// Parse arguments
int port = GetPortArgument(args) ?? PORT;
int workerCount = GetWorkerCountArgument(args) ?? WorkerCount;
string? curve = GetCurveArgument(args);

// Find certificate paths
var (certPath, keyPath) = FindCertificatePaths(curve);
if (certPath == null || keyPath == null)
{
    Log.Information("ERROR: No certificate files found!");
    PrintUsage();
    return;
}

var controller = new WorkerController(port, certPath, keyPath, workerCount);

Log.Information($"Port: {port}");
Log.Information($"Workers: {workerCount}");
if (curve != null) Log.Information($"Curve: {curve}");
Log.Information($"Cert: {certPath}");
Log.Information($"Key: {keyPath}");
Log.Information("------");

AppDomain.CurrentDomain.UnhandledException += (s, e) => {
    Console.WriteLine($"FATAL: {e.ExceptionObject}");
};

// Handle Ctrl+C
var cts = new CancellationTokenSource();
Console.CancelKeyPress += (s, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

var stopwatch = Stopwatch.StartNew();

Log.Information($"✓ Listening on port {port}");
Log.Information("Press Ctrl+C to stop...");

controller.StartWorkers();

while (!cts.IsCancellationRequested)
{
    // Awaits until ANY worker finishes a TLS handshake
    var connection = await controller.AcceptAsync(cts.Token);

    // Process the request in a background task so we can Accept the next one immediately
    _ = HandleConnection(connection, cts.Token);
}

Log.Information("Server stopped!");

async Task HandleConnection(ConnectionContext connection, CancellationToken cancellationToken)
{
    byte[]? buffer = null;

    // using (connection) // This calls Dispose() and unpins the GCHandle!
    try
    {
        buffer = ArrayPool<byte>.Shared.Rent(4096);
        var bytesRead = await connection.ReadAsync(buffer);

        if (bytesRead > 0)
        {
            // Send minimal HTTP response
            var response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"u8.ToArray();
            await connection.WriteAsync(response);
        }        
    }
    finally
    {
        if (buffer is not null)
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        connection.Dispose(); // closing the connection from server
    }
}

static (string? certPath, string? keyPath) FindCertificatePaths(string? curve = null)
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

static int? GetPortArgument(string[] args)
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

static int? GetWorkerCountArgument(string[] args)
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

static string? GetCurveArgument(string[] args)
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

static void PrintUsage()
{
    Console.WriteLine();
    Console.WriteLine("Usage: dotnet run -- [port] [workers] [--curve <curve>]");
    Console.WriteLine();
    Console.WriteLine("Curve options (lighter to heavier):");
    Console.WriteLine("  p256   - ECDSA P-256 (fastest)");
    Console.WriteLine("  p384   - ECDSA P-384 (default, most CPU intensive)");
    Console.WriteLine();
    Console.WriteLine("Examples:");
    Console.WriteLine("  dotnet run -- 5008 16 --curve p256");
    Console.WriteLine("  dotnet run -- --curve p384");
}