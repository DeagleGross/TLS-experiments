using DemoSemiUnmanagedSocket.Interop;
using System.Net.Sockets;

namespace DemoSemiUnmanagedSocket.Ssl;

/// <summary>
/// Async SSL connection wrapper.
/// 
/// This class wraps the native async TLS operations and provides
/// a C#-friendly async API for:
/// - Non-blocking TLS handshake with epoll
/// - SSL read/write for application data
/// 
/// Architecture:
/// - Socket accept is done in managed code (Socket.AcceptAsync)
/// - SSL handshake uses native epoll for async I/O
/// - Application data read/write through SSL
/// </summary>
internal sealed class AsyncSslConnection : IDisposable
{
    private readonly IntPtr _ssl;
    private readonly int _clientFd;
    private readonly int _epollFd;
    private bool _disposed;
    private bool _handshakeComplete;

    /// <summary>
    /// Get the SSL handle (for advanced operations).
    /// </summary>
    public IntPtr Handle => _ssl;

    /// <summary>
    /// Get the client socket file descriptor.
    /// </summary>
    public int ClientFd => _clientFd;

    /// <summary>
    /// Whether the TLS handshake has completed.
    /// </summary>
    public bool IsHandshakeComplete => _handshakeComplete;

    /// <summary>
    /// Create a new async SSL connection.
    /// 
    /// This is called after accepting a socket connection in C#.
    /// The constructor:
    /// 1. Gets the socket FD from the managed Socket
    /// 2. Creates an SSL object in native code
    /// 3. Registers with epoll (EPOLL_CTL_ADD with EPOLLIN)
    /// 
    /// Like async_mt: epoll ADD happens here, then only MOD during handshake.
    /// </summary>
    /// <param name="sslContext">Shared SSL context with certificates</param>
    /// <param name="clientSocket">Accepted client socket</param>
    /// <param name="epollFd">Epoll instance for this worker/context</param>
    public AsyncSslConnection(SslContext sslContext, Socket clientSocket, int epollFd)
    {
        if (sslContext == null) throw new ArgumentNullException(nameof(sslContext));
        if (clientSocket == null) throw new ArgumentNullException(nameof(clientSocket));
        
        _epollFd = epollFd;
        
        // Get the socket file descriptor from the managed Socket
        // On Linux, Socket.Handle is the native FD
        _clientFd = (int)clientSocket.Handle;
        
        // Create SSL object in native code AND register with epoll
        // This makes socket non-blocking, sets up SSL state, and does EPOLL_CTL_ADD
        _ssl = NativeSsl.ssl_connection_create(sslContext.Handle, _clientFd, _epollFd);
        
        if (_ssl == IntPtr.Zero)
        {
            throw new InvalidOperationException("Failed to create SSL connection");
        }
    }

    /// <summary>
    /// Perform the TLS handshake asynchronously.
    /// 
    /// This is the main async operation. It:
    /// 1. Calls ssl_try_handshake() which attempts SSL_do_handshake
    /// 2. If handshake needs I/O, waits on epoll via Task.Run
    /// 3. Repeats until handshake completes or fails
    /// 
    /// The actual waiting (epoll_wait) happens on a thread pool thread,
    /// so this doesn't block the calling async context.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    public async Task DoHandshakeAsync(CancellationToken cancellationToken = default)
    {
        if (_handshakeComplete)
            return;

        int iterations = 0;
        
        while (!cancellationToken.IsCancellationRequested)
        {
            iterations++;
            
            // Try to advance the handshake
            // This calls SSL_do_handshake() and registers with epoll if needed
            int status = NativeSsl.ssl_try_handshake(_ssl, _clientFd, _epollFd);
            
            switch (status)
            {
                case NativeSsl.HANDSHAKE_COMPLETE:
                    _handshakeComplete = true;
                    // Console.WriteLine($"[AsyncSslConnection] Handshake complete after {iterations} iterations");
                    return;
                    
                case NativeSsl.HANDSHAKE_WANT_READ:
                case NativeSsl.HANDSHAKE_WANT_WRITE:
                    // Need to wait for I/O
                    // epoll_wait blocks, so we run it on a thread pool thread
                    int readyFd = await Task.Run(() => 
                        NativeSsl.epoll_wait_one(_epollFd, 5000), // 5 second timeout
                        cancellationToken);
                    
                    if (readyFd < 0)
                    {
                        throw new InvalidOperationException("epoll_wait failed");
                    }
                    
                    if (readyFd == 0)
                    {
                        // Timeout - continue and try again
                        // (In production, you might want to give up after too many timeouts)
                        continue;
                    }
                    
                    // Socket is ready, loop back to try handshake again
                    break;
                    
                case NativeSsl.HANDSHAKE_ERROR:
                default:
                    throw new InvalidOperationException($"TLS handshake failed with status {status}");
            }
        }
        
        cancellationToken.ThrowIfCancellationRequested();
    }

    /// <summary>
    /// Read decrypted data from the connection.
    /// 
    /// Note: This is a synchronous read. For async reads after handshake,
    /// you would need additional epoll integration for data availability.
    /// </summary>
    /// <param name="buffer">Buffer to receive data</param>
    /// <returns>Bytes read, 0 on EOF, -1 would block</returns>
    public unsafe int Read(Span<byte> buffer)
    {
        if (!_handshakeComplete)
            throw new InvalidOperationException("Handshake not complete");

        fixed (byte* ptr = buffer)
        {
            return NativeSsl.ssl_read(_ssl, ptr, buffer.Length);
        }
    }

    /// <summary>
    /// Write data through the SSL connection.
    /// </summary>
    /// <param name="data">Data to send</param>
    /// <returns>Bytes written, -1 would block, -2 error</returns>
    public unsafe int Write(ReadOnlySpan<byte> data)
    {
        if (!_handshakeComplete)
            throw new InvalidOperationException("Handshake not complete");

        fixed (byte* ptr = data)
        {
            return NativeSsl.ssl_write(_ssl, ptr, data.Length);
        }
    }

    /// <summary>
    /// Write a string through the SSL connection (for simple responses).
    /// </summary>
    public int WriteString(string text)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(text);
        return Write(bytes);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_ssl != IntPtr.Zero)
            {
                NativeSsl.ssl_connection_destroy(_ssl);
            }
            _disposed = true;
        }
    }
}
