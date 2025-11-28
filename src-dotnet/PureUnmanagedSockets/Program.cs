using PureUnmanagedSockets.Interop;
using System.Runtime.InteropServices;
using System.Text;

namespace PureUnmanagedSockets;

class Program
{
    private static volatile bool _running = true;
    private static long _requestsProcessed = 0;

    static async Task Main(string[] args)
    {
        const int port = 5005;
        const int workerCount = 4;
        int processorCount = Environment.ProcessorCount;

        Console.WriteLine("=== Hybrid C/C# SSL Server ===");
        Console.WriteLine("C handles: accept, epoll, SSL handshake, SSL_read/write");
        Console.WriteLine("C# handles: HTTP parsing, response generation");
        Console.WriteLine("Communication: Lock-free queues + eventfd");
        Console.WriteLine();

        var (certPath, keyPath) = FindCertificatePaths();
        if (certPath == null || keyPath == null)
        {
            Console.WriteLine("ERROR: No certificate files found!");
            return;
        }

        Console.WriteLine($"Port: {port}");
        Console.WriteLine($"C Workers: {workerCount}");
        Console.WriteLine($"C# Processors: {processorCount}");
        Console.WriteLine($"Certificate: {certPath}");
        Console.WriteLine();

        // Start C# request processors
        var processors = new Task[processorCount];
        for (int i = 0; i < processorCount; i++)
        {
            int processorId = i;
            processors[i] = Task.Run(() => RequestProcessorAsync(processorId));
        }

        // Start metrics reporting
        _ = Task.Run(ReportMetricsAsync);

        // Start native server (BLOCKS until Ctrl+C)
        // This is a blocking call, but C# processors are already running
        var serverTask = Task.Run(() =>
        {
            int result = OpenSslNative.start_nginx_server(port, certPath, keyPath, workerCount);
            _running = false;
            return result;
        });

        Console.WriteLine("Server started! C# processors active.");
        Console.WriteLine("Press Ctrl+C to stop");
        Console.WriteLine();

        // Wait for server
        await serverTask;
        
        // Wait for processors to finish
        await Task.WhenAll(processors);
        
        Console.WriteLine("Server stopped");
    }

    static async Task RequestProcessorAsync(int processorId)
    {
        Console.WriteLine($"[C# Processor {processorId}] Started");

        // Get eventfd for notifications
        int notifyFd = OpenSslNative.get_request_notify_fd();

        while (_running)
        {
            // Wait for notification from C (eventfd)
            await WaitForEventFdAsync(notifyFd);

            // Process all pending requests
            while (true)
            {
                int connId;
                IntPtr dataPtr;
                int length;

                // Dequeue request from C
                int result = OpenSslNative.dequeue_request(out connId, out dataPtr, out length);

                if (result == 0)
                {
                    // Queue empty
                    break;
                }

                // Marshal data from C
                byte[] requestData = new byte[length];
                Marshal.Copy(dataPtr, requestData, 0, length);
                Marshal.FreeHGlobal(dataPtr); // Free C-allocated memory

                // Process request in C#
                _ = Task.Run(() => ProcessHttpRequestAsync(connId, requestData));

                Interlocked.Increment(ref _requestsProcessed);
            }
        }

        Console.WriteLine($"[C# Processor {processorId}] Stopped");
    }

    static async Task WaitForEventFdAsync(int fd)
    {
        // Use Task.Run to avoid blocking the thread pool
        await Task.Run(() =>
        {
            // Read from eventfd (blocks until C writes to it)
            ulong value;
            unsafe
            {
                int bytesRead = (int)Syscall.read(fd, &value, 8);
                if (bytesRead < 0 && !_running)
                {
                    return;
                }
            }
        });
    }

    static async Task ProcessHttpRequestAsync(int connId, byte[] requestData)
    {
        try
        {
            // Parse HTTP request (simplified)
            string request = Encoding.UTF8.GetString(requestData);

            // Simulate async processing
            await Task.Delay(1); // Minimal delay to show async behavior

            // Generate HTTP response
            string responseBody = "Hello, World!";
            string httpResponse = $"HTTP/1.1 200 OK\r\n" +
                                $"Content-Length: {responseBody.Length}\r\n" +
                                $"Connection: close\r\n" +
                                $"\r\n" +
                                $"{responseBody}";

            byte[] responseBytes = Encoding.UTF8.GetBytes(httpResponse);

            // Enqueue response back to C
            OpenSslNative.enqueue_response(connId, responseBytes, responseBytes.Length);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Processor] Error processing request for conn {connId}: {ex.Message}");
        }
    }

    static async Task ReportMetricsAsync()
    {
        long lastRequests = 0;

        while (_running)
        {
            await Task.Delay(1000);

            long currentRequests = Interlocked.Read(ref _requestsProcessed);
            long requestsPerSec = currentRequests - lastRequests;

            OpenSslNative.get_server_stats(out ulong handshakes, out ulong connections);

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] " +
                            $"Connections: {connections} | " +
                            $"Handshakes: {handshakes} | " +
                            $"C# Requests/s: {requestsPerSec}");

            lastRequests = currentRequests;
        }
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

/// <summary>
/// Minimal syscall wrapper for eventfd read
/// </summary>
internal static class Syscall
{
    [DllImport("libc", SetLastError = true)]
    public static unsafe extern long read(int fd, void* buf, ulong count);
}


