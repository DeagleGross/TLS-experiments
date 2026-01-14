using AsyncTlsSockets;
using Serilog;
using System.Buffers;
using System.Diagnostics;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .WriteTo.Console()
    .CreateLogger();

// CONSTS
const int WorkerCount = 4;
const int PORT = 5008;

Log.Information("=== TLS Server with workers ===");
Log.Information("------");

// Parse arguments
int port = args.Length > 0 ? int.Parse(args[0]) : PORT;
int workerCount = args.Length > 1 ? int.Parse(args[1]) : WorkerCount;

// Find certificate paths
var (certPath, keyPath) = FindCertificatePaths();
if (certPath == null || keyPath == null)
{
    Log.Information("ERROR: No certificate files found!");
    return;
}

var controller = new WorkerController(port, certPath, keyPath, workerCount);

Log.Information($"Port: {port}");
Log.Information($"Workers: {workerCount}");
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