using DirectFdSsl.Interop;

namespace DirectFdSsl.Ssl;

/// <summary>
/// fd-based SSL connection (no BIOs!).
/// OpenSSL directly reads/writes to the socket fd.
/// </summary>
public sealed class DirectSslConnection : IDisposable
{
    private readonly IntPtr _ssl;
    private readonly int _fd;
    private readonly EpollEventLoop _eventLoop;
    
    // Stats
    public int HandshakeCalls;
    public int ReadCalls;
    public int WriteCalls;
    public int WantReadCount;
    public int WantWriteCount;

    public DirectSslConnection(SslContext ctx, int fd, EpollEventLoop eventLoop, bool isServer)
    {
        _fd = fd;
        _eventLoop = eventLoop;
        
        // Set socket to non-blocking
        Interop.Socket.SetNonBlocking(fd);
        
        // Create SSL object
        _ssl = OpenSsl.SSL_new(ctx.Handle);
        if (_ssl == IntPtr.Zero)
            throw new Exception($"SSL_new failed: {OpenSsl.GetLastError()}");

        // KEY: Attach fd directly to SSL (no BIOs!)
        if (OpenSsl.SSL_set_fd(_ssl, fd) != 1)
            throw new Exception($"SSL_set_fd failed: {OpenSsl.GetLastError()}");

        if (isServer)
            OpenSsl.SSL_set_accept_state(_ssl);
        else
            OpenSsl.SSL_set_connect_state(_ssl);

        // Register with epoll for async notifications
        _eventLoop.Register(fd);
    }

    /// <summary>
    /// Perform TLS handshake asynchronously using epoll for notifications.
    /// </summary>
    public async Task DoHandshakeAsync()
    {
        while (true)
        {
            int ret = OpenSsl.SSL_do_handshake(_ssl);
            HandshakeCalls++;

            if (ret == 1)
            {
                // Handshake complete!
                return;
            }

            int err = OpenSsl.SSL_get_error(_ssl, ret);

            switch (err)
            {
                case OpenSsl.SSL_ERROR_WANT_READ:
                    WantReadCount++;
                    await _eventLoop.WaitReadableAsync(_fd);
                    break;

                case OpenSsl.SSL_ERROR_WANT_WRITE:
                    WantWriteCount++;
                    await _eventLoop.WaitWritableAsync(_fd);
                    break;

                case OpenSsl.SSL_ERROR_ZERO_RETURN:
                    throw new Exception("Connection closed during handshake");

                case OpenSsl.SSL_ERROR_SYSCALL:
                    throw new Exception($"Syscall error during handshake: {OpenSsl.GetLastError()}");

                default:
                    throw new Exception($"Handshake failed with error {err}: {OpenSsl.GetLastError()}");
            }
        }
    }

    /// <summary>
    /// Read decrypted data. OpenSSL handles decryption internally.
    /// </summary>
    public async Task<int> ReadAsync(Memory<byte> buffer)
    {
        while (true)
        {
            int ret;
            unsafe
            {
                fixed (byte* ptr = buffer.Span)
                {
                    ret = OpenSsl.SSL_read(_ssl, ptr, buffer.Length);
                }
            }
            ReadCalls++;

            if (ret > 0)
            {
                return ret;
            }

            int err = OpenSsl.SSL_get_error(_ssl, ret);

            switch (err)
            {
                case OpenSsl.SSL_ERROR_WANT_READ:
                    WantReadCount++;
                    await _eventLoop.WaitReadableAsync(_fd);
                    break;

                case OpenSsl.SSL_ERROR_WANT_WRITE:
                    // Can happen during renegotiation
                    WantWriteCount++;
                    await _eventLoop.WaitWritableAsync(_fd);
                    break;

                case OpenSsl.SSL_ERROR_ZERO_RETURN:
                    return 0; // Clean shutdown

                case OpenSsl.SSL_ERROR_SYSCALL:
                    if (ret == 0) return 0; // EOF
                    throw new Exception($"Syscall error during read: {OpenSsl.GetLastError()}");

                default:
                    throw new Exception($"Read failed with error {err}: {OpenSsl.GetLastError()}");
            }
        }
    }

    /// <summary>
    /// Write data. OpenSSL handles encryption internally.
    /// </summary>
    public async Task<int> WriteAsync(ReadOnlyMemory<byte> buffer)
    {
        int totalWritten = 0;

        while (totalWritten < buffer.Length)
        {
            int ret;
            unsafe
            {
                fixed (byte* ptr = buffer.Span.Slice(totalWritten))
                {
                    ret = OpenSsl.SSL_write(_ssl, ptr, buffer.Length - totalWritten);
                }
            }
            WriteCalls++;

            if (ret > 0)
            {
                totalWritten += ret;
                continue;
            }

            int err = OpenSsl.SSL_get_error(_ssl, ret);

            switch (err)
            {
                case OpenSsl.SSL_ERROR_WANT_READ:
                    WantReadCount++;
                    await _eventLoop.WaitReadableAsync(_fd);
                    break;

                case OpenSsl.SSL_ERROR_WANT_WRITE:
                    WantWriteCount++;
                    await _eventLoop.WaitWritableAsync(_fd);
                    break;

                case OpenSsl.SSL_ERROR_ZERO_RETURN:
                    throw new Exception("Connection closed during write");

                case OpenSsl.SSL_ERROR_SYSCALL:
                    throw new Exception($"Syscall error during write: {OpenSsl.GetLastError()}");

                default:
                    throw new Exception($"Write failed with error {err}: {OpenSsl.GetLastError()}");
            }
        }

        return totalWritten;
    }

    public void Dispose()
    {
        _eventLoop.Unregister(_fd);
        
        if (_ssl != IntPtr.Zero)
        {
            OpenSsl.SSL_shutdown(_ssl);
            OpenSsl.SSL_free(_ssl);
        }
    }
}
