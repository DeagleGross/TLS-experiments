using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using DirectFdSsl.Ssl;

namespace DirectFdSsl;

/// <summary>
/// TLS server using fd-based OpenSSL (no BIOs).
/// 
/// Key differences from BIO-based approach:
/// 1. SSL_set_fd() - OpenSSL reads/writes directly to socket
/// 2. No BIO_write/BIO_read calls needed
/// 3. We use epoll for async notifications instead of ReceiveAsync
/// 4. Potentially fewer copies and P/Invoke calls
/// </summary>
class Program
{
    static async Task Main(string[] args)
    {
        int port = args.Length > 0 ? int.Parse(args[0]) : 6002;
        string certFile = args.Length > 1 ? args[1] : "certs/server-p384.crt";
        string keyFile = args.Length > 2 ? args[2] : "certs/server-p384.key";

        Console.WriteLine("=== Direct fd-based SSL Server (No BIOs) ===");
        Console.WriteLine($"Port: {port}");
        Console.WriteLine($"Cert: {certFile}");
        Console.WriteLine($"Key: {keyFile}");
        Console.WriteLine();

        using var sslCtx = new SslContext(certFile, keyFile, isServer: true);
        using var eventLoop = new EpollEventLoop();

        var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        listener.Bind(new IPEndPoint(IPAddress.Any, port));
        listener.Listen(512);

        Console.WriteLine($"Listening on port {port}...");
        Console.WriteLine("Press Ctrl+C to stop");
        Console.WriteLine();

        // Stats
        long handshakesCompleted = 0;
        long handshakesFailed = 0;
        long totalHandshakeCalls = 0;
        long totalWantRead = 0;
        long totalWantWrite = 0;
        var startTime = Stopwatch.StartNew();

        // Stats printer task
        _ = Task.Run(async () =>
        {
            while (true)
            {
                await Task.Delay(5000);
                double elapsed = startTime.Elapsed.TotalSeconds;
                double rate = handshakesCompleted / elapsed;
                double avgHandshakeCalls = handshakesCompleted > 0 
                    ? (double)totalHandshakeCalls / handshakesCompleted 
                    : 0;
                
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Handshakes: {handshakesCompleted} ok, {handshakesFailed} fail ({rate:F2}/sec) | " +
                                  $"SSL_do_handshake calls: {totalHandshakeCalls} ({avgHandshakeCalls:F2}/req) | " +
                                  $"WANT_READ: {totalWantRead}, WANT_WRITE: {totalWantWrite} | " +
                                  $"epoll_wait: {eventLoop.EpollWaitCalls}");
            }
        });

        // Accept loop
        var response = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        while (true)
        {
            Socket clientSocket;
            try
            {
                clientSocket = await listener.AcceptAsync();
            }
            catch
            {
                continue;
            }

            // Handle connection
            _ = Task.Run(async () =>
            {
                DirectSslConnection? conn = null;
                try
                {
                    // Get the native file descriptor
                    int fd = (int)clientSocket.Handle;

                    // Create fd-based SSL connection (no BIOs!)
                    conn = new DirectSslConnection(sslCtx, fd, eventLoop, isServer: true);

                    // Do handshake
                    await conn.DoHandshakeAsync();

                    // Send response
                    await conn.WriteAsync(response);

                    // Update stats
                    Interlocked.Increment(ref handshakesCompleted);
                    Interlocked.Add(ref totalHandshakeCalls, conn.HandshakeCalls);
                    Interlocked.Add(ref totalWantRead, conn.WantReadCount);
                    Interlocked.Add(ref totalWantWrite, conn.WantWriteCount);
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref handshakesFailed);
                    // Log errors for debugging
                    Console.WriteLine($"Error: {ex.Message}");
                }
                finally
                {
                    conn?.Dispose();
                    try { clientSocket.Close(); } catch { }
                }
            });
        }
    }
}
