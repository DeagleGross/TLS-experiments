using DemoSemiUnmanagedSocket.Interop;
using DemoSemiUnmanagedSocket.Ssl;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace DemoSemiUnmanagedSocket;

/// <summary>
/// Async TLS Server Demo
/// 
/// Architecture:
/// - Socket accept: Managed (await socket.AcceptAsync())
/// - TLS handshake: Native epoll + SSL_do_handshake
/// - Application data: Managed processing with native SSL_read/SSL_write
/// 
/// This replicates the async-mt C server pattern but with managed accept
/// and application layer processing.
/// </summary>
class Program
{
    // Statistics
    private static long _handshakesCompleted;
    private static long _handshakesFailed;
    private static long _totalHandshakeIterations;

    static async Task Main(string[] args)
    {
        Console.WriteLine("=== Async TLS Server (Managed Accept + Native SSL) ===");
        Console.WriteLine();

        // Parse arguments
        int port = args.Length > 0 ? int.Parse(args[0]) : 5007;
        
        // Find certificate paths
        var (certPath, keyPath) = FindCertificatePaths();
        if (certPath == null || keyPath == null)
        {
            Console.WriteLine("ERROR: No certificate files found!");
            return;
        }

        Console.WriteLine($"Port: {port}");
        Console.WriteLine($"Cert: {certPath}");
        Console.WriteLine($"Key: {keyPath}");
        Console.WriteLine();

        // ===== Create SSL Context (shared across all connections) =====
        using var sslContext = new SslContext(certPath, keyPath);
        Console.WriteLine($"✓ SSL_CTX created: {sslContext.Handle}");

        // ===== Create Epoll Instance =====
        // In a multi-worker setup, each worker would have its own epoll
        using var epollContext = new EpollContext();
        Console.WriteLine($"✓ Epoll instance created: {epollContext.Handle}");

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
        _ = PrintStatsAsync(stopwatch, cts.Token);

        // Accept loop
        try
        {
            while (!cts.Token.IsCancellationRequested)
            {
                // Accept connection in MANAGED code
                // This uses the .NET async infrastructure (completion ports on Windows, epoll on Linux)
                Socket clientSocket;
                try
                {
                    clientSocket = await listenSocket.AcceptAsync(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                // Handle connection (fire and forget for now)
                // In production, you'd want to limit concurrency
                _ = Task.Run(() => HandleConnectionAsync(clientSocket, sslContext, epollContext, cts.Token));
            }
        }
        catch (OperationCanceledException)
        {
            // Expected on shutdown
        }

        // Final stats
        stopwatch.Stop();
        PrintFinalStats(stopwatch.Elapsed);

        listenSocket.Close();
    }

    /// <summary>
    /// Handle a single client connection.
    /// 
    /// Flow:
    /// 1. Create AsyncSslConnection (wraps native SSL object)
    /// 2. Perform async handshake (uses epoll internally)
    /// 3. Send HTTP response
    /// 4. Cleanup
    /// </summary>
    private static async Task HandleConnectionAsync(
        Socket clientSocket, 
        SslContext sslContext, 
        EpollContext epollContext,
        CancellationToken ct)
    {
        try
        {
            // Create SSL connection for this client
            // This calls native ssl_connection_create() which:
            // - Makes socket non-blocking
            // - Creates SSL object
            // - Associates with socket FD
            using var sslConnection = new AsyncSslConnection(sslContext, clientSocket, epollContext.Handle);

            // Perform TLS handshake asynchronously
            // This loops calling ssl_try_handshake() and epoll_wait_one()
            // until handshake completes
            await sslConnection.DoHandshakeAsync(ct);

            // Handshake complete! Now we can send/receive application data
            // Send a simple HTTP response
            const string response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            sslConnection.WriteString(response);

            // Update stats
            Interlocked.Increment(ref _handshakesCompleted);
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _handshakesFailed);
            
            // Only log if not a cancellation
            if (ex is not OperationCanceledException)
            {
                Console.WriteLine($"[Error] {ex.Message}");
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
    private static async Task PrintStatsAsync(Stopwatch stopwatch, CancellationToken ct)
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

            var completed = _handshakesCompleted;
            var failed = _handshakesFailed;

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Handshakes: {completed} ok, {failed} fail ({completed / elapsed:F2}/sec)");
        }
    }

    /// <summary>
    /// Print final statistics.
    /// </summary>
    private static void PrintFinalStats(TimeSpan elapsed)
    {
        Console.WriteLine();
        Console.WriteLine("=== Final Statistics ===");
        Console.WriteLine($"Runtime: {elapsed.TotalSeconds:F2} seconds");
        Console.WriteLine($"Completed handshakes: {_handshakesCompleted}");
        Console.WriteLine($"Failed handshakes: {_handshakesFailed}");
        Console.WriteLine($"Handshakes/sec: {_handshakesCompleted / elapsed.TotalSeconds:F2}");
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
