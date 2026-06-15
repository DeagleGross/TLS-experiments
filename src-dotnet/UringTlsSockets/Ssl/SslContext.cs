using UringTlsSockets.Interop;

namespace UringTlsSockets.Ssl;

/// <summary>
/// Wrapper around OpenSSL SSL_CTX.
/// Thread-safe — can be shared across all worker threads.
/// </summary>
internal sealed class SslContext : IDisposable
{
    private IntPtr _ctx;
    private bool _disposed;

    public IntPtr Handle => _ctx;

    public SslContext(string certPath, string keyPath)
    {
        if (string.IsNullOrEmpty(certPath))
            throw new ArgumentNullException(nameof(certPath));
        if (string.IsNullOrEmpty(keyPath))
            throw new ArgumentNullException(nameof(keyPath));

        OpenSsl.Initialize();

        var method = OpenSsl.TLS_server_method();
        if (method == IntPtr.Zero)
            throw new InvalidOperationException("Failed to create TLS server method");

        _ctx = OpenSsl.SSL_CTX_new(method);
        if (_ctx == IntPtr.Zero)
            throw new InvalidOperationException(
                $"Failed to create SSL context: {OpenSsl.GetLastErrorString()}");

        if (OpenSsl.SSL_CTX_use_certificate_file(_ctx, certPath, OpenSsl.SSL_FILETYPE_PEM) <= 0)
        {
            Dispose();
            throw new InvalidOperationException(
                $"Failed to load certificate from {certPath}: {OpenSsl.GetLastErrorString()}");
        }

        if (OpenSsl.SSL_CTX_use_PrivateKey_file(_ctx, keyPath, OpenSsl.SSL_FILETYPE_PEM) <= 0)
        {
            Dispose();
            throw new InvalidOperationException(
                $"Failed to load private key from {keyPath}: {OpenSsl.GetLastErrorString()}");
        }

        if (OpenSsl.SSL_CTX_check_private_key(_ctx) <= 0)
        {
            Dispose();
            throw new InvalidOperationException(
                $"Private key does not match certificate: {OpenSsl.GetLastErrorString()}");
        }

        Console.WriteLine($"[SslContext] Initialized with cert: {certPath}");
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_ctx != IntPtr.Zero)
            {
                OpenSsl.SSL_CTX_free(_ctx);
                _ctx = IntPtr.Zero;
            }
            _disposed = true;
        }
    }

    ~SslContext()
    {
        Dispose();
    }
}
