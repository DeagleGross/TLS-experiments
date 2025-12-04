using DirectFdSsl.Interop;

namespace DirectFdSsl.Ssl;

/// <summary>
/// Manages an OpenSSL SSL_CTX for fd-based connections.
/// </summary>
public sealed class SslContext : IDisposable
{
    public IntPtr Handle { get; private set; }

    public SslContext(string certFile, string keyFile, bool isServer = true)
    {
        var method = isServer ? OpenSsl.TLS_server_method() : OpenSsl.TLS_client_method();
        Handle = OpenSsl.SSL_CTX_new(method);
        
        if (Handle == IntPtr.Zero)
            throw new Exception($"SSL_CTX_new failed: {OpenSsl.GetLastError()}");

        // Force TLS 1.3
        OpenSsl.SSL_CTX_set_min_proto_version(Handle, OpenSsl.TLS1_3_VERSION);
        OpenSsl.SSL_CTX_set_max_proto_version(Handle, OpenSsl.TLS1_3_VERSION);
        
        // Disable session cache (force full handshake for benchmarking)
        OpenSsl.SSL_CTX_set_session_cache_mode(Handle, OpenSsl.SSL_SESS_CACHE_OFF);

        // Load certificate
        if (OpenSsl.SSL_CTX_use_certificate_file(Handle, certFile, OpenSsl.SSL_FILETYPE_PEM) <= 0)
            throw new Exception($"Failed to load certificate: {OpenSsl.GetLastError()}");

        // Load private key
        if (OpenSsl.SSL_CTX_use_PrivateKey_file(Handle, keyFile, OpenSsl.SSL_FILETYPE_PEM) <= 0)
            throw new Exception($"Failed to load private key: {OpenSsl.GetLastError()}");
    }

    public void Dispose()
    {
        if (Handle != IntPtr.Zero)
        {
            OpenSsl.SSL_CTX_free(Handle);
            Handle = IntPtr.Zero;
        }
    }
}
