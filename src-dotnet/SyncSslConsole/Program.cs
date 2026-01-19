using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Buffers;
using SyncSslConsole.Ssl;

namespace SyncSslConsole;

class Program
{
    private static int _handshakeCount = 0;
    private static int _connectionCount = 0;
    private static int _errorCount = 0;
    private static int _handshakeAttemptsTotal = 0;
    private static int _handshakeOneShot = 0;  // Completed in first SSL_do_handshake
    private static int _handshakeMultiRound = 0; // Required multiple rounds
    private static SslContext? _sslContext;

    static async Task Main(string[] args)
    {
        const int port = 5002;

        Console.WriteLine("=== Direct OpenSSL TLS Server (Sync Version) ===");
        Console.WriteLine();

        // Parse curve argument (--curve p256|p384)
        string? curve = GetCurveArgument(args);
        
        // Find certificate paths
        var (certPath, keyPath) = FindCertificatePaths(curve);
        if (certPath == null || keyPath == null)
        {
            Console.WriteLine("ERROR: No certificate files found!");
            PrintUsage();
            return;
        }

        // Create SSL context (shared across all connections)
        _sslContext = new SslContext(certPath, keyPath);
        Console.WriteLine($"Certificate loaded from: {certPath}");
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
                _ = Task.Run(() => HandleConnectionSync(client));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Server error: {ex.Message}");
        }
        finally
        {
            listener.Stop();
            _sslContext?.Dispose();
        }
    }

    private static void HandleConnectionSync(TcpClient tcpClient)
    {
        Socket? socket = null;
        SslConnection? sslConn = null;

        try
        {
            // Get the underlying socket
            socket = tcpClient.Client;
            socket.NoDelay = true;

            // Create SSL connection
            sslConn = new SslConnection(_sslContext!, socket);

            var sw = Stopwatch.StartNew();

            // Perform SSL handshake (blocking for now)
            bool handshakeComplete = false;

            while (!handshakeComplete)
            {
                handshakeComplete = sslConn.DoHandshake();
                
                // In sync mode, DoHandshake will block until complete
                // or throw exception on error
            }

            sw.Stop();
            Interlocked.Increment(ref _handshakeCount);

            // Record handshake statistics
            Interlocked.Add(ref _handshakeAttemptsTotal, sslConn.HandshakeAttempts);
            if (sslConn.CompletedOneShot)
                Interlocked.Increment(ref _handshakeOneShot);
            else
                Interlocked.Increment(ref _handshakeMultiRound);

            // Read HTTP request
            byte[] buffer = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                int bytesRead = sslConn.Read(buffer, 0, buffer.Length);

                if (bytesRead > 0)
                {
                    // Send minimal HTTP response
                    var response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"u8.ToArray();
                    sslConn.Write(response, 0, response.Length);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _errorCount);
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
        var lastHandshakes = 0;
        var lastConnections = 0;

        while (true)
        {
            await Task.Delay(1000);

            var currentHandshakes = _handshakeCount;
            var currentConnections = _connectionCount;
            var handshakesPerSec = currentHandshakes - lastHandshakes;
            var connectionsPerSec = currentConnections - lastConnections;

            var avgAttempts = currentHandshakes > 0 ? (double)_handshakeAttemptsTotal / currentHandshakes : 0;
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] " +
                            $"Connections: {currentConnections} ({connectionsPerSec}/s) | " +
                            $"Handshakes: {currentHandshakes} ({handshakesPerSec}/s) | " +
                            $"Errors: {_errorCount}");
            Console.WriteLine($"  Handshake stats: One-shot={_handshakeOneShot}, Multi-round={_handshakeMultiRound}, Avg attempts={avgAttempts:F2}");

            lastHandshakes = currentHandshakes;
            lastConnections = currentConnections;
        }
    }

    private static (string? certPath, string? keyPath) FindCertificatePaths(string? curve = null)
    {
        var basePaths = new[]
        {
            Path.Combine("certs"),  // Docker: /app/certs
            Path.Combine("..", "..", "certs")  // Development
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

            // Try p384
            certPath = Path.Combine(basePath, "server-p384.crt");
            keyPath = Path.Combine(basePath, "server-p384.key");

            if (File.Exists(certPath) && File.Exists(keyPath))
                return (certPath, keyPath);
        }

        return (null, null);
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
        Console.WriteLine("Usage: dotnet run -- [--curve <curve>]");
        Console.WriteLine();
        Console.WriteLine("Curve options (lighter to heavier):");
        Console.WriteLine("  p256   - ECDSA P-256 (fastest)");
        Console.WriteLine("  p384   - ECDSA P-384 (default, most CPU intensive)");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  dotnet run -- --curve p256");
        Console.WriteLine("  dotnet run -- p256");
    }
}
