using AsyncSslConsole.Interop;
using System.Net.Sockets;

namespace AsyncSslConsole.Ssl;

/// <summary>
/// Represents a single SSL/TLS connection.
/// Handles the SSL handshake state machine with non-blocking I/O support.
/// </summary>
internal sealed unsafe class SslConnection : IDisposable
{
    private IntPtr _ssl;
    private readonly Socket _socket;
    private bool _disposed;
    private bool _handshakeComplete;

    public bool HandshakeComplete => _handshakeComplete;

    public SslConnection(SslContext context, Socket socket)
    {
        if (context == null)
            throw new ArgumentNullException(nameof(context));
        if (socket == null)
            throw new ArgumentNullException(nameof(socket));

        _socket = socket;

        // Create new SSL session
        _ssl = OpenSsl.SSL_new(context.Handle);
        if (_ssl == IntPtr.Zero)
            throw new InvalidOperationException($"Failed to create SSL session: {OpenSsl.GetLastErrorString()}");

        // Get native socket handle (file descriptor on Linux)
        var handle = _socket.Handle;
        var fd = handle.ToInt32();

        // Bind SSL to socket
        if (OpenSsl.SSL_set_fd(_ssl, fd) <= 0)
        {
            OpenSsl.SSL_free(_ssl);
            throw new InvalidOperationException($"Failed to set socket FD: {OpenSsl.GetLastErrorString()}");
        }

        // Set server mode - this is critical!
        OpenSsl.SSL_set_accept_state(_ssl);
    }

    /// <summary>
    /// Performs SSL handshake (blocking version for now).
    /// Returns true if handshake completed, false if needs more I/O.
    /// </summary>
    public bool DoHandshake()
    {
        if (_handshakeComplete)
            return true;

        int ret = OpenSsl.SSL_do_handshake(_ssl);
        
        if (ret == 1)
        {
            // Handshake successful
            _handshakeComplete = true;
            return true;
        }

        // Check error
        int error = OpenSsl.SSL_get_error(_ssl, ret);

        switch (error)
        {
            case OpenSsl.SSL_ERROR_WANT_READ:
                // Need to read more data - socket should wait for read
                return false;

            case OpenSsl.SSL_ERROR_WANT_WRITE:
                // Need to write more data - socket should wait for write
                return false;

            case OpenSsl.SSL_ERROR_SYSCALL:
            case OpenSsl.SSL_ERROR_SSL:
                throw new InvalidOperationException($"SSL handshake failed: {OpenSsl.GetLastErrorString()}");

            default:
                throw new InvalidOperationException($"Unknown SSL error: {error}");
        }
    }

    /// <summary>
    /// Read decrypted data from SSL connection.
    /// </summary>
    public int Read(byte[] buffer, int offset, int count)
    {
        if (!_handshakeComplete)
            throw new InvalidOperationException("Handshake not complete");

        fixed (byte* ptr = &buffer[offset])
        {
            int ret = OpenSsl.SSL_read(_ssl, ptr, count);
            
            if (ret > 0)
                return ret;

            int error = OpenSsl.SSL_get_error(_ssl, ret);
            if (error == OpenSsl.SSL_ERROR_WANT_READ || error == OpenSsl.SSL_ERROR_WANT_WRITE)
                return 0; // No data available yet

            throw new InvalidOperationException($"SSL read failed: {OpenSsl.GetLastErrorString()}");
        }
    }

    /// <summary>
    /// Write encrypted data to SSL connection.
    /// </summary>
    public int Write(byte[] buffer, int offset, int count)
    {
        if (!_handshakeComplete)
            throw new InvalidOperationException("Handshake not complete");

        fixed (byte* ptr = &buffer[offset])
        {
            int ret = OpenSsl.SSL_write(_ssl, ptr, count);
            
            if (ret > 0)
                return ret;

            int error = OpenSsl.SSL_get_error(_ssl, ret);
            if (error == OpenSsl.SSL_ERROR_WANT_READ || error == OpenSsl.SSL_ERROR_WANT_WRITE)
                return 0; // Would block

            throw new InvalidOperationException($"SSL write failed: {OpenSsl.GetLastErrorString()}");
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_ssl != IntPtr.Zero)
            {
                OpenSsl.SSL_shutdown(_ssl);
                OpenSsl.SSL_free(_ssl);
                _ssl = IntPtr.Zero;
            }
            _disposed = true;
        }
    }

    ~SslConnection()
    {
        Dispose();
    }
}
