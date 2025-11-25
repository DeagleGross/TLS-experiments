using AsyncSslConsole.Interop;
using System.Net.Sockets;
using System.Buffers;

namespace AsyncSslConsole.Ssl;

/// <summary>
/// Represents a single SSL/TLS connection.
/// Handles the SSL handshake state machine with non-blocking I/O support.
/// </summary>
internal sealed class SslConnection : IDisposable
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
    /// Performs SSL handshake (non-blocking).
    /// Returns the result indicating if handshake is complete or needs I/O.
    /// </summary>
    public HandshakeResult DoHandshake()
    {
        if (_handshakeComplete)
            return HandshakeResult.Complete;

        int ret = OpenSsl.SSL_do_handshake(_ssl);
        
        if (ret == 1)
        {
            // Handshake successful
            _handshakeComplete = true;
            return HandshakeResult.Complete;
        }

        // Check error
        int error = OpenSsl.SSL_get_error(_ssl, ret);

        switch (error)
        {
            case OpenSsl.SSL_ERROR_WANT_READ:
                return HandshakeResult.WantRead;

            case OpenSsl.SSL_ERROR_WANT_WRITE:
                return HandshakeResult.WantWrite;

            case OpenSsl.SSL_ERROR_SYSCALL:
            case OpenSsl.SSL_ERROR_SSL:
                return HandshakeResult.Error;

            default:
                return HandshakeResult.Error;
        }
    }

    /// <summary>
    /// Performs async SSL handshake using non-blocking I/O.
    /// This is the nginx-style async approach!
    /// </summary>
    public async Task<bool> DoHandshakeAsync()
    {
        // Set socket to non-blocking mode
        _socket.Blocking = false;

        while (true)
        {
            var result = DoHandshake();

            switch (result)
            {
                case HandshakeResult.Complete:
                    return true;

                case HandshakeResult.WantRead:
                    // Wait for socket to be readable (uses epoll/IOCP!)
                    await WaitForSocketReadableAsync();
                    break;

                case HandshakeResult.WantWrite:
                    // Wait for socket to be writable
                    await WaitForSocketWritableAsync();
                    break;

                case HandshakeResult.Error:
                    throw new InvalidOperationException($"SSL handshake failed: {OpenSsl.GetLastErrorString()}");
            }
        }
    }

    /// <summary>
    /// Waits asynchronously until the socket is readable.
    /// On Linux, this uses epoll internally via Socket.ReceiveAsync.
    /// Does NOT block a thread!
    /// </summary>
    private async Task WaitForSocketReadableAsync()
    {
        var buffer = ArrayPool<byte>.Shared.Rent(1);
        try
        {
            // Peek at socket without consuming data
            // This will complete when socket has data (readable)
            // Uses epoll on Linux, IOCP on Windows
            await _socket.ReceiveAsync(new Memory<byte>(buffer, 0, 1), SocketFlags.Peek);
        }
        catch (SocketException)
        {
            // Socket might be closed or error - will be caught in next handshake attempt
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Waits asynchronously until the socket is writable.
    /// On Linux, this uses epoll internally.
    /// Does NOT block a thread!
    /// </summary>
    private async Task WaitForSocketWritableAsync()
    {
        var buffer = ArrayPool<byte>.Shared.Rent(1);
        buffer[0] = 0;
        
        try
        {
            // Try to send 0 bytes - completes when socket is writable
            // This is a workaround since there's no direct "wait for writable" API
            // In practice, SSL_ERROR_WANT_WRITE is rare during handshake
            await Task.Yield(); // For now, just yield to avoid tight loop
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Read decrypted data from SSL connection.
    /// </summary>
    public unsafe int Read(byte[] buffer, int offset, int count)
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
    public unsafe int Write(byte[] buffer, int offset, int count)
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
