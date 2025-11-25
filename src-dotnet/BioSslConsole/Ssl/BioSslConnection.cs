using BioSslConsole.Interop;
using System.Buffers;
using System.Net.Sockets;

namespace BioSslConsole.Ssl;

/// <summary>
/// BIO-based SSL connection using memory BIOs.
/// This matches how .NET's SslStream works internally - truly async with no thread blocking.
/// </summary>
internal sealed class BioSslConnection : IDisposable
{
    private readonly IntPtr _ssl;
    private readonly IntPtr _readBio;
    private readonly IntPtr _writeBio;
    private readonly Socket _socket;
    private bool _disposed;
    private bool _handshakeComplete;

    public bool HandshakeComplete => _handshakeComplete;

    public BioSslConnection(SslContext context, Socket socket)
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
            // Create MEMORY BIOs (not socket FD!)
            // This is the key difference - OpenSSL works with memory, we control socket I/O
            _readBio = OpenSsl.BIO_new(OpenSsl.BIO_s_mem());
            if (_readBio == IntPtr.Zero)
                throw new InvalidOperationException("Failed to create read BIO");

            _writeBio = OpenSsl.BIO_new(OpenSsl.BIO_s_mem());
            if (_writeBio == IntPtr.Zero)
            {
                OpenSsl.BIO_free(_readBio);
                throw new InvalidOperationException("Failed to create write BIO");
            }

            // Set BIOs on SSL (OpenSSL takes ownership, we don't free them)
            OpenSsl.SSL_set_bio(_ssl, _readBio, _writeBio);

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
    /// Performs async SSL handshake using the BIO-based approach (like SslStream).
    /// This is truly async - only actual network I/O blocks (via epoll/IOCP).
    /// </summary>
    public async Task<bool> DoHandshakeAsync()
    {
        // Set socket to non-blocking
        _socket.Blocking = false;

        int attemptCount = 0;

        while (true)
        {
            // 1. Try SSL handshake (works on memory BIOs - FAST!)
            int ret = OpenSsl.SSL_do_handshake(_ssl);
            attemptCount++;

            if (ret == 1)
            {
                // Handshake complete!
                _handshakeComplete = true;

                // Record statistics
                HandshakeAttempts = attemptCount;
                CompletedOneShot = (attemptCount == 1);

                // Flush any pending output
                await FlushOutputBioAsync();
                return true;
            }

            // Check what SSL needs
            int error = OpenSsl.SSL_get_error(_ssl, ret);

            switch (error)
            {
                case OpenSsl.SSL_ERROR_WANT_READ:
                    // OpenSSL needs more encrypted data from network
                    // 1. First flush any pending output (handshake response)
                    await FlushOutputBioAsync();
                    
                    // 2. Then read more data from network into input BIO
                    await ReadFromNetworkIntoBioAsync();
                    break;

                case OpenSsl.SSL_ERROR_WANT_WRITE:
                    // OpenSSL has data to send (rare during handshake)
                    await FlushOutputBioAsync();
                    break;

                case OpenSsl.SSL_ERROR_SYSCALL:
                case OpenSsl.SSL_ERROR_SSL:
                    throw new InvalidOperationException($"SSL handshake failed: {OpenSsl.GetLastErrorString()}");

                default:
                    throw new InvalidOperationException($"Unknown SSL error: {error}");
            }
        }
    }

    public int HandshakeAttempts { get; private set; }
    public bool CompletedOneShot { get; private set; }

    /// <summary>
    /// Reads encrypted data from network and writes it into OpenSSL's INPUT BIO.
    /// This is async - uses epoll/IOCP internally.
    /// </summary>
    private async Task ReadFromNetworkIntoBioAsync()
    {
        var buffer = ArrayPool<byte>.Shared.Rent(16384);
        try
        {
            // Async network read - DOES NOT BLOCK THREAD!
            int received = await _socket.ReceiveAsync(new Memory<byte>(buffer), SocketFlags.None);

            if (received <= 0)
            {
                throw new IOException("Connection closed by remote host");
            }

            // Write received encrypted data into INPUT BIO (memory operation - fast!)
            unsafe
            {
                fixed (byte* ptr = buffer)
                {
                    int written = OpenSsl.BIO_write(_readBio, ptr, received);
                    if (written <= 0)
                    {
                        throw new InvalidOperationException("Failed to write to input BIO");
                    }
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Reads encrypted data from OpenSSL's OUTPUT BIO and sends it to network.
    /// This is async - uses epoll/IOCP internally.
    /// </summary>
    private async Task FlushOutputBioAsync()
    {
        // Check if there's any data to send (just a memory check - instant!)
        int pending = OpenSsl.BIO_ctrl_pending(_writeBio);

        if (pending > 0)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(pending);
            try
            {
                // Read from OUTPUT BIO (memory operation - fast!)
                int read;
                unsafe
                {
                    fixed (byte* ptr = buffer)
                    {
                        read = OpenSsl.BIO_read(_writeBio, ptr, pending);
                    }
                }
                
                if (read > 0)
                {
                    // Send to network - ASYNC, DOES NOT BLOCK THREAD!
                    await _socket.SendAsync(new Memory<byte>(buffer, 0, read), SocketFlags.None);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }

    /// <summary>
    /// Read decrypted application data.
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
                    // Need more encrypted data from network
                    await ReadFromNetworkIntoBioAsync();
                    break;

                case OpenSsl.SSL_ERROR_WANT_WRITE:
                    // Need to flush output
                    await FlushOutputBioAsync();
                    break;

                case OpenSsl.SSL_ERROR_NONE:
                    return 0; // EOF

                default:
                    throw new IOException($"SSL read failed: {OpenSsl.GetLastErrorString()}");
            }
        }
    }

    /// <summary>
    /// Write application data (will be encrypted).
    /// </summary>
    public async Task WriteAsync(byte[] buffer, int offset, int count)
    {
        if (!_handshakeComplete)
            throw new InvalidOperationException("Handshake not complete");

        int ret;
        unsafe
        {
            fixed (byte* ptr = &buffer[offset])
            {
                ret = OpenSsl.SSL_write(_ssl, ptr, count);
            }
        }

        if (ret <= 0)
        {
            int error = OpenSsl.SSL_get_error(_ssl, ret);
            throw new IOException($"SSL write failed: {error}, {OpenSsl.GetLastErrorString()}");
        }

        // Flush encrypted data to network
        await FlushOutputBioAsync();
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_ssl != IntPtr.Zero)
            {
                OpenSsl.SSL_shutdown(_ssl);
                OpenSsl.SSL_free(_ssl);
                // BIOs are freed by SSL_free (we gave ownership to SSL)
            }
            _disposed = true;
        }
    }

    ~BioSslConnection()
    {
        Dispose();
    }
}
