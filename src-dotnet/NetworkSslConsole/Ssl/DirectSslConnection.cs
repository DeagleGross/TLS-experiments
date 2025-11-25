using NetworkSslConsole.Interop;
using System.Buffers;
using System.Net.Sockets;

namespace NetworkSslConsole.Ssl;

/// <summary>
/// Direct socket FD-based SSL connection (nginx-style approach).
/// Uses SSL_set_fd to attach OpenSSL directly to the socket file descriptor.
/// Pure async with non-blocking socket I/O - no BIO intermediaries!
/// </summary>
internal sealed class DirectSslConnection : IDisposable
{
    private readonly IntPtr _ssl;
    private readonly Socket _socket;
    private bool _disposed;
    private bool _handshakeComplete;

    public bool HandshakeComplete => _handshakeComplete;

    public DirectSslConnection(SslContext context, Socket socket)
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

        try
        {
            // NGINX-STYLE: Attach socket FD directly to OpenSSL (no BIOs!)
            // This is what nginx does - OpenSSL reads/writes directly from/to socket
            var handle = _socket.Handle;
            var fd = handle.ToInt32();

            if (OpenSsl.SSL_set_fd(_ssl, fd) <= 0)
            {
                throw new InvalidOperationException($"Failed to set socket FD: {OpenSsl.GetLastErrorString()}");
            }

            // Set server mode
            OpenSsl.SSL_set_accept_state(_ssl);
        }
        catch
        {
            OpenSsl.SSL_free(_ssl);
            throw;
        }
    }

    /// <summary>
    /// Performs async SSL handshake using direct socket FD (nginx-style).
    /// Event-driven approach: calls SSL_do_handshake once, waits for I/O event, repeats.
    /// No busy loop - truly event-driven like nginx with epoll.
    /// </summary>
    public async Task<bool> DoHandshakeAsync()
    {
        // CRITICAL: Set socket to non-blocking mode
        // This prevents OpenSSL from blocking the thread on socket I/O
        _socket.Blocking = false;

        int attemptCount = 0;

        // Event-driven handshake: call SSL_do_handshake once, wait for event, repeat
        int ret = OpenSsl.SSL_do_handshake(_ssl);
        attemptCount++;

        // If handshake completed in one shot (rare but possible with session resumption)
        if (ret == 1)
        {
            _handshakeComplete = true;
            HandshakeAttempts = attemptCount;
            CompletedOneShot = true;
            return true;
        }

        // Wait for I/O events until handshake completes
        // This is the nginx-style event loop
        attemptCount = await AwaitHandshakeCompletionAsync(attemptCount);

        _handshakeComplete = true;
        HandshakeAttempts = attemptCount;
        CompletedOneShot = (attemptCount == 1);
        return true;
    }

    /// <summary>
    /// Event-driven handshake completion (nginx-style).
    /// Waits for socket I/O events and calls SSL_do_handshake when ready.
    /// This mimics nginx's epoll event loop for SSL handshakes.
    /// </summary>
    private async Task<int> AwaitHandshakeCompletionAsync(int attemptCount)
    {
        while (true)
        {
            // Get the last SSL error to know what we're waiting for
            int error = OpenSsl.SSL_get_error(_ssl, 0);

            switch (error)
            {
                case OpenSsl.SSL_ERROR_WANT_READ:
                    // Wait for socket to become readable (like epoll_wait with EPOLLIN)
                    await WaitForReadableAsync();
                    break;

                case OpenSsl.SSL_ERROR_WANT_WRITE:
                    // Wait for socket to become writable (like epoll_wait with EPOLLOUT)
                    await WaitForWritableAsync();
                    break;

                case OpenSsl.SSL_ERROR_SYSCALL:
                case OpenSsl.SSL_ERROR_SSL:
                    throw new InvalidOperationException($"SSL handshake failed: {OpenSsl.GetLastErrorString()}");

                default:
                    throw new InvalidOperationException($"Unknown SSL error during handshake: {error}");
            }

            // Socket event fired - try handshake again (EXACTLY ONCE, like nginx)
            int ret = OpenSsl.SSL_do_handshake(_ssl);
            attemptCount++;

            if (ret == 1)
            {
                // Handshake complete!
                return attemptCount;
            }

            // If ret != 1, loop continues and we check error again
            // This continues the event-driven state machine
        }
    }

    public int HandshakeAttempts { get; private set; }
    public bool CompletedOneShot { get; private set; }

    /// <summary>
    /// Wait for socket to become readable (nginx-style async I/O).
    /// Uses a minimal read to trigger the async machinery.
    /// </summary>
    private async Task WaitForReadableAsync()
    {
        // Use Socket.ReceiveAsync to wait for data
        // This will complete when socket has data available
        // We use a tiny buffer just to detect readability (like epoll_wait)
        var buffer = ArrayPool<byte>.Shared.Rent(1);
        try
        {
            // Peek at data without consuming it
            // This is like epoll_wait(EPOLLIN) - just checking for readability
            // Using MSG_PEEK so we don't consume the bytes (OpenSSL will read them)
            await _socket.ReceiveAsync(
                new Memory<byte>(buffer, 0, 1),
                SocketFlags.Peek);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)
        {
            // Socket not ready yet, that's fine - loop will retry
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Wait for socket to become writable (nginx-style async I/O).
    /// </summary>
    private async Task WaitForWritableAsync()
    {
        // For write readiness, we can use SendAsync with zero bytes
        // Or we can do a small dummy send operation
        // The cleanest approach: just wait a tiny bit and let the next handshake attempt proceed
        // In nginx, this would use epoll_wait(EPOLLOUT)
        
        // .NET doesn't have a direct "wait for writable" API like epoll(EPOLLOUT)
        // So we use a small delay and retry
        // This is not ideal but works for the handshake case
        await Task.Delay(1);
    }

    /// <summary>
    /// Read decrypted application data.
    /// With direct FD approach, OpenSSL reads directly from socket.
    /// </summary>
    public async Task<int> ReadAsync(byte[] buffer, int offset, int count)
    {
        if (!_handshakeComplete)
            throw new InvalidOperationException("Handshake not complete");

        while (true)
        {
            // Try to read decrypted data from SSL
            int ret;
            unsafe
            {
                fixed (byte* ptr = &buffer[offset])
                {
                    ret = OpenSsl.SSL_read(_ssl, ptr, count);
                }
            }

            if (ret > 0)
                return ret;

            int error = OpenSsl.SSL_get_error(_ssl, ret);

            switch (error)
            {
                case OpenSsl.SSL_ERROR_WANT_READ:
                    // Need more data from socket
                    await WaitForReadableAsync();
                    break;

                case OpenSsl.SSL_ERROR_WANT_WRITE:
                    // Need to write (renegotiation?)
                    await WaitForWritableAsync();
                    break;

                case OpenSsl.SSL_ERROR_NONE:
                case OpenSsl.SSL_ERROR_ZERO_RETURN:
                    return 0; // EOF

                default:
                    throw new IOException($"SSL read failed: {OpenSsl.GetLastErrorString()}");
            }
        }
    }

    /// <summary>
    /// Write application data (will be encrypted).
    /// With direct FD approach, OpenSSL writes directly to socket.
    /// </summary>
    public async Task WriteAsync(byte[] buffer, int offset, int count)
    {
        if (!_handshakeComplete)
            throw new InvalidOperationException("Handshake not complete");

        while (count > 0)
        {
            int ret;
            unsafe
            {
                fixed (byte* ptr = &buffer[offset])
                {
                    ret = OpenSsl.SSL_write(_ssl, ptr, count);
                }
            }

            if (ret > 0)
            {
                offset += ret;
                count -= ret;
                continue;
            }

            int error = OpenSsl.SSL_get_error(_ssl, ret);

            switch (error)
            {
                case OpenSsl.SSL_ERROR_WANT_READ:
                    await WaitForReadableAsync();
                    break;

                case OpenSsl.SSL_ERROR_WANT_WRITE:
                    await WaitForWritableAsync();
                    break;

                default:
                    throw new IOException($"SSL write failed: {error}, {OpenSsl.GetLastErrorString()}");
            }
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
                // With direct FD, OpenSSL doesn't own the socket, we do
                // So socket is cleaned up separately
            }
            _disposed = true;
        }
    }

    ~DirectSslConnection()
    {
        Dispose();
    }
}
