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
    /// TRUE event-driven: calls SSL_do_handshake once, waits for I/O event via async,
    /// then the event loop (in Program.cs or here) calls again.
    /// This matches nginx's epoll architecture exactly.
    /// </summary>
    public async Task<bool> DoHandshakeAsync()
    {
        // CRITICAL: Set socket to non-blocking mode
        // This prevents OpenSSL from blocking the thread on socket I/O
        _socket.Blocking = false;

        int attemptCount = 0;

        // Nginx-style event-driven loop
        while (!_handshakeComplete)
        {
            // Step 1: Try SSL handshake ONCE (like nginx does per epoll event)
            int ret = OpenSsl.SSL_do_handshake(_ssl);
            attemptCount++;

            if (ret == 1)
            {
                // Handshake complete!
                _handshakeComplete = true;
                HandshakeAttempts = attemptCount;
                CompletedOneShot = (attemptCount == 1);
                return true;
            }

            // Step 2: Check what I/O event we need to wait for
            int error = OpenSsl.SSL_get_error(_ssl, ret);

            switch (error)
            {
                case OpenSsl.SSL_ERROR_WANT_READ:
                    // Register interest in read event (like epoll_ctl with EPOLLIN)
                    // When this completes, it means data arrived - retry handshake
                    await WaitForSocketEventAsync(isRead: true);
                    break;

                case OpenSsl.SSL_ERROR_WANT_WRITE:
                    // Register interest in write event (like epoll_ctl with EPOLLOUT)
                    await WaitForSocketEventAsync(isRead: false);
                    break;

                case OpenSsl.SSL_ERROR_SYSCALL:
                case OpenSsl.SSL_ERROR_SSL:
                    throw new InvalidOperationException($"SSL handshake failed: {OpenSsl.GetLastErrorString()}");

                default:
                    throw new InvalidOperationException($"Unknown SSL error during handshake: {error}");
            }

            // Loop continues - will call SSL_do_handshake() again
            // This is equivalent to nginx's event handler being called again when epoll fires
        }

        return true;
    }

    /// <summary>
    /// Wait for socket I/O event (nginx epoll equivalent).
    /// This is like epoll_ctl(EPOLL_CTL_MOD, fd, EPOLLIN/EPOLLOUT) + epoll_wait().
    /// When this returns, it means the socket is ready for the requested operation.
    /// </summary>
    private async Task WaitForSocketEventAsync(bool isRead)
    {
        if (isRead)
        {
            // Wait for EPOLLIN - socket has data to read
            await WaitForReadableAsync();
        }
        else
        {
            // Wait for EPOLLOUT - socket can accept writes
            await WaitForWritableAsync();
        }
    }

    public int HandshakeAttempts { get; private set; }
    public bool CompletedOneShot { get; private set; }

    /// <summary>
    /// Wait for socket to become readable (nginx-style async I/O).
    /// This is the .NET equivalent of: epoll_ctl(EPOLL_CTL_MOD, fd, EPOLLIN) + epoll_wait()
    /// The Socket.ReceiveAsync registers with IOCP/epoll and yields the thread.
    /// When the OS detects readable data, it completes the Task.
    /// </summary>
    private async Task WaitForReadableAsync()
    {
        // CRITICAL: Use Socket.ReceiveAsync with MSG_PEEK
        // This does NOT consume data (OpenSSL will read it via SSL_do_handshake)
        // It ONLY waits for the socket to become readable
        
        // Allocate minimal buffer - we're just waiting for readability, not actually reading
        var buffer = ArrayPool<byte>.Shared.Rent(1);
        try
        {
            // ReceiveAsync with Peek = epoll_wait(EPOLLIN)
            // The OS kernel will signal when socket has data
            // This is truly async - thread is released to thread pool
            await _socket.ReceiveAsync(
                new Memory<byte>(buffer, 0, 1),
                SocketFlags.Peek);
            
            // When we reach here, socket has data available
            // Now SSL_do_handshake() can read it without blocking
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)
        {
            // Should not happen with async I/O, but handle gracefully
            await Task.Yield();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Wait for socket to become writable (nginx-style async I/O).
    /// This is the .NET equivalent of: epoll_ctl(EPOLL_CTL_MOD, fd, EPOLLOUT) + epoll_wait()
    /// 
    /// NOTE: .NET doesn't have a direct "poll for writable" API.
    /// Sockets are usually writable, so this is rarely hit during handshake.
    /// We use a small delay as a workaround.
    /// 
    /// TODO: Could potentially use Socket.SendAsync with zero bytes,
    /// or implement proper writable polling via P/Invoke to poll()/select().
    /// </summary>
    private async Task WaitForWritableAsync()
    {
        // For now, just yield and retry quickly
        // In practice, sockets are almost always writable unless send buffer is full
        // During TLS handshake, write amounts are small, so this is rare
        await Task.Yield();
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
