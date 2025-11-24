using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using System.Buffers;

namespace AsyncSslConsole;

class Program
{
    private static int _handshakeCount = 0;
    private static int _connectionCount = 0;
    private static int _errorCount = 0;

    static async Task Main(string[] args)
    {
        const int port = 5001;

        Console.WriteLine("=== Minimal SslStream Server ===");
        Console.WriteLine();

        // Load existing certificate
        var certificate = LoadCertificate();
        Console.WriteLine($"Certificate: {certificate.Subject}");
        Console.WriteLine($"Thumbprint: {certificate.Thumbprint}");
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
                _ = Task.Run(() => HandleConnectionAsync(client, certificate));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Server error: {ex.Message}");
        }
        finally
        {
            listener.Stop();
        }
    }

    private static async Task HandleConnectionAsync(TcpClient client, X509Certificate2 certificate)
    {
        try
        {
            client.NoDelay = true;

            await using var stream = client.GetStream();
            await using var sslStream = new SslStream(stream, leaveInnerStreamOpen: false);

            var sw = Stopwatch.StartNew();

            // This is the key call we're benchmarking
            await sslStream.AuthenticateAsServerAsync(
                serverCertificate: certificate,
                clientCertificateRequired: false,
                enabledSslProtocols: SslProtocols.Tls12 | SslProtocols.Tls13,
                checkCertificateRevocation: false);

            sw.Stop();

            Interlocked.Increment(ref _handshakeCount);

            // Read some data and send response (minimal HTTP-like exchange)
            byte[] buffer = null!;
            try
            {
                buffer = ArrayPool<byte>.Shared.Rent(4096);
                int bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length);

                if (bytesRead > 0)
                {
                    // Send minimal HTTP response
                    var response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"u8.ToArray();
                    await sslStream.WriteAsync(response, 0, response.Length);
                    await sslStream.FlushAsync();
                }
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _errorCount);
                Console.WriteLine($"Data exchange error: {ex.Message}");
            }
            finally
            {
                if (buffer is not null)
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }

            }
        }
        catch (AuthenticationException ex)
        {
            Interlocked.Increment(ref _errorCount);
            Console.WriteLine($"Authentication failed: {ex.Message}");
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _errorCount);
            Console.WriteLine($"Connection error: {ex.Message}");
        }
        finally
        {
            client.Close();
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

            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] " +
                            $"Connections: {currentConnections} ({connectionsPerSec}/s) | " +
                            $"Handshakes: {currentHandshakes} ({handshakesPerSec}/s) | " +
                            $"Errors: {_errorCount}");

            lastHandshakes = currentHandshakes;
            lastConnections = currentConnections;
        }
    }

    private static X509Certificate2 LoadCertificate()
    {
        // Try to load from certs directory
        // In Docker: /app/certs
        // In development: ../../certs
        var basePaths = new[]
        {
            Path.Combine("certs"),  // Docker: /app/certs
            Path.Combine("..", "..", "certs")  // Development
        };

        foreach (var basePath in basePaths)
        {
            var certPath = Path.Combine(basePath, "server.crt");
            var keyPath = Path.Combine(basePath, "server.key");
            var certPathP384 = Path.Combine(basePath, "server-p384.crt");
            var keyPathP384 = Path.Combine(basePath, "server-p384.key");

            // Try standard cert first
            if (File.Exists(certPath) && File.Exists(keyPath))
            {
                Console.WriteLine($"Loading certificate from: {certPath}");
                return LoadCertificateFromPemFiles(certPath, keyPath);
            }
            // Try p384 cert
            else if (File.Exists(certPathP384) && File.Exists(keyPathP384))
            {
                Console.WriteLine($"Loading certificate from: {certPathP384}");
                return LoadCertificateFromPemFiles(certPathP384, keyPathP384);
            }
        }

        Console.WriteLine("No existing certificates found, generating new one...");
        return GenerateSelfSignedCertificate();
    }

    private static X509Certificate2 LoadCertificateFromPemFiles(string certPath, string keyPath)
    {
        // Read PEM files
        var certPem = File.ReadAllText(certPath);
        var keyPem = File.ReadAllText(keyPath);

        // Load using .NET's PEM support
        var cert = X509Certificate2.CreateFromPem(certPem, keyPem);

        // Need to export and re-import to get a cert with private key that works on all platforms
        var certBytes = cert.Export(X509ContentType.Pkcs12);
        return new X509Certificate2(certBytes);
    }

    private static X509Certificate2 GenerateSelfSignedCertificate()
    {
        // Fallback: generate a self-signed certificate
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=localhost",
            rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
                System.Security.Cryptography.X509Certificates.X509KeyUsageFlags.DigitalSignature,
                critical: false));

        request.CertificateExtensions.Add(
            new System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(
                new System.Security.Cryptography.OidCollection
                {
                    new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1") // Server Authentication
                },
                critical: false));

        var sanBuilder = new System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("localhost");
        request.CertificateExtensions.Add(sanBuilder.Build());

        var certificate = request.CreateSelfSigned(
            DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddYears(1));

        return certificate;
    }
}
