using DemoSemiUnmanagedSocket.Interop;
using DemoSemiUnmanagedSocket.Ssl;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace DemoSemiUnmanagedSocket;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("=== DemoSemiUnmanagedSocket ===");
        Console.WriteLine("Configure socket + SSL context in C#, pass to C for logging");
        Console.WriteLine();

        // Find certificate paths
        var (certPath, keyPath) = FindCertificatePaths();
        if (certPath == null || keyPath == null)
        {
            Console.WriteLine("ERROR: No certificate files found!");
            return;
        }

        // ===== STEP 1: Configure Socket in Managed Code =====
        Console.WriteLine("STEP 1: Configuring socket in managed code...");
        
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
       

        // Configure socket options
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        socket.NoDelay = true; // TCP_NODELAY
        
        // Bind to port
        const int port = 5007;
        socket.Bind(new IPEndPoint(IPAddress.Any, port));
        socket.Listen(1024);
        
        Console.WriteLine($"  ✓ Socket created and bound to port {port}");
        Console.WriteLine($"  ✓ SO_REUSEADDR: enabled");
        Console.WriteLine($"  ✓ TCP_NODELAY: enabled");
        Console.WriteLine($"  ✓ Socket Handle (FD): {socket.Handle}");
        Console.WriteLine();

        // ===== STEP 2: Configure SSL Context in Managed Code =====
        Console.WriteLine("STEP 2: Configuring SSL context in managed code...");
        
        using var sslContext = new SslContext(certPath, keyPath);
        
        Console.WriteLine($"  ✓ SSL_CTX created: {sslContext.Handle}");
        Console.WriteLine($"  ✓ Certificate loaded: {certPath}");
        Console.WriteLine($"  ✓ Private key loaded: {keyPath}");
        Console.WriteLine();

        // ===== STEP 3: Pass to Unmanaged Layer =====
        Console.WriteLine("STEP 3: Passing resources to unmanaged layer...");
        Console.WriteLine();
        
        // Get socket file descriptor (Unix)
        int socketFd = (int)socket.Handle;
        
        // Call native code to log information
        DemoNative.log_socket_and_ssl_context(socketFd, sslContext.Handle);
        
        Console.WriteLine("STEP 4: Demo complete!");
        Console.WriteLine();
        Console.WriteLine("Summary:");
        Console.WriteLine("  - Socket configured in C# (System.Net.Sockets.Socket)");
        Console.WriteLine("  - SSL_CTX configured in C# (OpenSSL P/Invoke)");
        Console.WriteLine("  - Both passed to C native layer via P/Invoke");
        Console.WriteLine("  - Native layer logged all details");
        
        // Cleanup
        socket.Close();
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
