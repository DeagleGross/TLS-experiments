using NetworkSslConsole.Ssl;
using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace NetworkSslConsole;

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
        const int port = 5003;

        Console.WriteLine("=== Direct FD Async SSL Server (nginx-style) ===");
        Console.WriteLine("Using SSL_set_fd + async I/O (epoll/IOCP)");
        Console.WriteLine("No BIOs, no thread blocking - truly async like nginx!");
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
            _sslContext?.Dispose();
        }
    }

    private static async Task HandleConnectionAsync(TcpClient tcpClient)
    {
        Socket? socket = null;
        DirectSslConnection? sslConn = null;

        try
        {
            // Get the underlying socket
            socket = tcpClient.Client;
            socket.NoDelay = true;

            // Create direct FD SSL connection (nginx-style!)
            sslConn = new DirectSslConnection(_sslContext!, socket);

            var sw = Stopwatch.StartNew();

            // Perform ASYNC SSL handshake using direct socket FD (nginx-style)
            // OpenSSL uses SSL_set_fd and reads/writes directly from/to socket
            // When socket would block, we use async I/O to wait (like epoll/IOCP)
            bool success = await sslConn.DoHandshakeAsync();

            if (!success)
            {
                Interlocked.Increment(ref _errorCount);
                return;
            }

            sw.Stop();
            Interlocked.Increment(ref _handshakeCount);

            // Record handshake statistics
            Interlocked.Add(ref _handshakeAttemptsTotal, sslConn.HandshakeAttempts);
            if (sslConn.CompletedOneShot)
                Interlocked.Increment(ref _handshakeOneShot);
            else
                Interlocked.Increment(ref _handshakeMultiRound);

            // Read HTTP request (async!)
            byte[] buffer = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                int bytesRead = await sslConn.ReadAsync(buffer, 0, buffer.Length);

                if (bytesRead > 0)
                {
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
