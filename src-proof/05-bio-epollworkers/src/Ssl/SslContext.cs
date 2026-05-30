using BioEpollWorkers.Interop;

namespace BioEpollWorkers.Ssl;

/// <summary>
/// SSL_CTX wrapper.
///
/// Configured for the proof bench:
///   - TLS 1.3 only (so the pair-difference vs experiment 04 isn't muddied
///     by protocol-version differences)
///   - Session cache OFF (so every wrk request forces a full handshake)
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
            throw new InvalidOperationException($"Failed to create SSL context: {OpenSsl.GetLastErrorString()}");

        if (OpenSsl.SSL_CTX_use_certificate_file(_ctx, certPath, OpenSsl.SSL_FILETYPE_PEM) <= 0)
        {
            Dispose();
            throw new InvalidOperationException($"Failed to load certificate from {certPath}: {OpenSsl.GetLastErrorString()}");
        }

        if (OpenSsl.SSL_CTX_use_PrivateKey_file(_ctx, keyPath, OpenSsl.SSL_FILETYPE_PEM) <= 0)
        {
            Dispose();
            throw new InvalidOperationException($"Failed to load private key from {keyPath}: {OpenSsl.GetLastErrorString()}");
        }

        if (OpenSsl.SSL_CTX_check_private_key(_ctx) <= 0)
        {
            Dispose();
            throw new InvalidOperationException($"Private key does not match certificate: {OpenSsl.GetLastErrorString()}");
        }

        // Force TLS 1.3 only — matches the C async-mt baseline (#01).
        if (OpenSsl.SSL_CTX_set_min_proto_version(_ctx, OpenSsl.TLS1_3_VERSION) <= 0)
        {
            Console.WriteLine($"[SslContext] WARNING: set_min_proto_version(TLS1_3) failed: {OpenSsl.GetLastErrorString()}");
        }
        if (OpenSsl.SSL_CTX_set_max_proto_version(_ctx, OpenSsl.TLS1_3_VERSION) <= 0)
        {
            Console.WriteLine($"[SslContext] WARNING: set_max_proto_version(TLS1_3) failed: {OpenSsl.GetLastErrorString()}");
        }

        // Disable session caching so wrk's `Connection: close` forces a real handshake per request.
        OpenSsl.SSL_CTX_set_session_cache_mode(_ctx, OpenSsl.SSL_SESS_CACHE_OFF);

        Console.WriteLine($"[SslContext] Initialized (TLS 1.3 only, session cache OFF) with cert: {certPath}");
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
