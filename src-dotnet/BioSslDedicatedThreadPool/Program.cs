using BioSslDedicatedThreadPool.Ssl;
using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace BioSslDedicatedThreadPool;

class Program
{
    private static int _connectionCount = 0;
    private static int _requestsProcessed = 0;
    private static SslContext? _sslContext;
    private static HandshakeThreadPool? _handshakeThreadPool;

    static async Task Main(string[] args)
    {
        const int port = 5004;
        
        // Configurable handshake worker count (default: 4, like C async server)
        int handshakeWorkers = args.Length > 0 && int.TryParse(args[0], out var workers) && workers > 0 
            ? workers 
            : 8;

        Console.WriteLine("=== BIO-Based SSL Server with Dedicated Handshake Thread Pool ===");
        Console.WriteLine($"Handshake Workers: {handshakeWorkers} (like C async server)");
        Console.WriteLine("Each worker does ONE handshake iteration, then moves to next connection");
        Console.WriteLine("Gradient approach: fair scheduling across concurrent handshakes");
        Console.WriteLine();

        // Find certificate paths
        var (certPath, keyPath) = FindCertificatePaths();
        if (certPath == null || keyPath == null)
        {
            Console.WriteLine("ERROR: No certificate files found!");
            return;
        }

        // Create SSL context (shared across all connections)
        _sslContext = new SslContext(certPath, keyPath);
        Console.WriteLine($"Certificate loaded from: {certPath}");
        Console.WriteLine();

        // Create dedicated handshake thread pool
        _handshakeThreadPool = new HandshakeThreadPool(handshakeWorkers);
        Console.WriteLine();

        // Start metrics reporting
        _ = Task.Run(() => ReportMetrics());

        // Start server
        var listener = new TcpListener(IPAddress.Any, port);
        listener.Start(backlog: 1024);

        Console.WriteLine($"Server listening on port {port}");
        Console.WriteLine("Press Ctrl+C to stop");
        Console.WriteLine();

        try
        {
            while (true)
            {
                var client = await listener.AcceptTcpClientAsync();
                Interlocked.Increment(ref _connectionCount);

                // Fire and forget - handle connection asynchronously
                _ = Task.Run(() => HandleConnectionAsync(client));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Server error: {ex.Message}");
        }
        finally
        {
            listener.Stop();
            _handshakeThreadPool?.Dispose();
            _sslContext?.Dispose();
        }
    }

    private static async Task HandleConnectionAsync(TcpClient tcpClient)
    {
        Socket? socket = null;
        BioSslConnection? sslConn = null;

        try
        {
            // Get the underlying socket
            socket = tcpClient.Client;
            socket.NoDelay = true;

            // Create BIO-based SSL connection
            sslConn = new BioSslConnection(_sslContext!, socket);

            var sw = Stopwatch.StartNew();

            // **KEY DIFFERENCE**: Queue handshake to dedicated thread pool
            // Workers process ONE iteration at a time (gradient approach)
            // This allows fair scheduling when multiple handshakes are in progress
            bool success = await _handshakeThreadPool!.QueueHandshakeAsync(sslConn, socket);

            sw.Stop();

            if (!success)
            {
                return;
            }

            // Handshake complete! Now we can process HTTP on regular ThreadPool
            // Read HTTP request (async!)
            byte[] buffer = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                int bytesRead = await sslConn.ReadAsync(buffer, 0, buffer.Length);

                if (bytesRead > 0)
                {
                    Interlocked.Increment(ref _requestsProcessed);

                    // Send minimal HTTP response (async!)
                    var response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"u8.ToArray();
                    await sslConn.WriteAsync(response, 0, response.Length);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Connection error: {ex.Message}");
        }
        finally
        {
            sslConn?.Dispose();
            socket?.Close();
            tcpClient?.Close();
        }
    }

    private static async Task ReportMetrics()
    {
        var lastConnections = 0;
        var lastRequests = 0;

        while (true)
        {
            await Task.Delay(1000);

            var currentConnections = _connectionCount;
            var currentRequests = _requestsProcessed;
            var connectionsPerSec = currentConnections - lastConnections;
            var requestsPerSec = currentRequests - lastRequests;

            // Get handshake thread pool statistics
            var stats = _handshakeThreadPool!.GetStatistics();

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] " +
                            $"Connections: {currentConnections} ({connectionsPerSec}/s) | " +
                            $"Requests: {currentRequests} ({requestsPerSec}/s)");
            Console.WriteLine($"  Handshakes: Total={stats.Total}, Success={stats.Success}, Failed={stats.Failed}, " +
                            $"AvgAttempts={stats.AvgAttempts:F2}, Queued={stats.Queued}, CurrentQueueSize={stats.QueueSize}");

            lastConnections = currentConnections;
            lastRequests = currentRequests;
        }
    }

    private static (string? certPath, string? keyPath) FindCertificatePaths()
    {
        var basePaths = new[]
        {
            Path.Combine("certs"),  // Docker: /app/certs
            Path.Combine("..", "..", "certs")  // Development
        };

        foreach (var basePath in basePaths)
        {
            var certPath = Path.Combine(basePath, "server.crt");
            var keyPath = Path.Combine(basePath, "server.key");

            if (File.Exists(certPath) && File.Exists(keyPath))
                return (certPath, keyPath);

            // Try p384
            certPath = Path.Combine(basePath, "server-p384.crt");
            keyPath = Path.Combine(basePath, "server-p384.key");

            if (File.Exists(certPath) && File.Exists(keyPath))
                return (certPath, keyPath);
        }

        return (null, null);
    }
}
