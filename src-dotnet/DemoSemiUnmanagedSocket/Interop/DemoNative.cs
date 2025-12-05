using System.Runtime.InteropServices;

namespace DemoSemiUnmanagedSocket.Interop;

/// <summary>
/// P/Invoke wrapper for the native async TLS library.
/// 
/// This library provides:
/// - Epoll management for async I/O
/// - Non-blocking SSL handshake with automatic epoll registration
/// - SSL read/write for application data
/// </summary>
internal static class NativeSsl
{
    private const string LibName = "libdemo_native.so";

    // ========================================================================
    // Handshake status codes (must match demo_native.h)
    // ========================================================================
    
    /// <summary>Handshake completed successfully</summary>
    public const int HANDSHAKE_COMPLETE = 0;
    
    /// <summary>Need to wait for socket to be readable</summary>
    public const int HANDSHAKE_WANT_READ = 1;
    
    /// <summary>Need to wait for socket to be writable</summary>
    public const int HANDSHAKE_WANT_WRITE = 2;
    
    /// <summary>Handshake failed</summary>
    public const int HANDSHAKE_ERROR = -1;

    // ========================================================================
    // Epoll Management
    // ========================================================================

    /// <summary>
    /// Create a new epoll instance.
    /// Each async context (or worker) should have its own epoll.
    /// </summary>
    /// <returns>Epoll file descriptor, or -1 on error</returns>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int create_epoll();

    /// <summary>
    /// Close an epoll instance.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void close_epoll(int epoll_fd);

    /// <summary>
    /// Wait for an I/O event on the epoll instance.
    /// This BLOCKS until an event is ready or timeout occurs.
    /// 
    /// Call this from Task.Run() to avoid blocking the async context.
    /// </summary>
    /// <param name="epoll_fd">Epoll instance</param>
    /// <param name="timeout_ms">Timeout in milliseconds (-1 for infinite)</param>
    /// <returns>Ready socket FD, 0 on timeout, -1 on error</returns>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int epoll_wait_one(int epoll_fd, int timeout_ms);

    // ========================================================================
    // Socket Utilities
    // ========================================================================

    /// <summary>
    /// Set a socket to non-blocking mode.
    /// This is called automatically by ssl_connection_create().
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_socket_nonblocking(int fd);

    /// <summary>
    /// Set TCP_NODELAY on socket (disable Nagle's algorithm).
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_tcp_nodelay(int fd);

    // ========================================================================
    // SSL Connection Management
    // ========================================================================

    /// <summary>
    /// Create an SSL object for a client connection AND register with epoll.
    /// 
    /// This function:
    /// 1. Makes the socket non-blocking
    /// 2. Creates SSL object from SSL_CTX
    /// 3. Associates SSL with socket FD (SSL_set_fd)
    /// 4. Sets SSL to accept mode (server-side)
    /// 5. Registers with epoll (EPOLL_CTL_ADD with EPOLLIN)
    /// 
    /// Like async_mt: ADD happens here, then only MOD in ssl_try_handshake.
    /// </summary>
    /// <param name="ssl_ctx">SSL context (from SslContext.Handle)</param>
    /// <param name="client_fd">Accepted client socket FD</param>
    /// <param name="epoll_fd">Epoll instance to register with</param>
    /// <returns>SSL pointer, or IntPtr.Zero on error</returns>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ssl_connection_create(IntPtr ssl_ctx, int client_fd, int epoll_fd);

    /// <summary>
    /// Destroy an SSL connection (calls SSL_shutdown + SSL_free).
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ssl_connection_destroy(IntPtr ssl);

    /// <summary>
    /// Get the socket FD from an SSL object.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ssl_get_fd(IntPtr ssl);

    // ========================================================================
    // Core Async Handshake API
    // ========================================================================

    /// <summary>
    /// Try to advance the TLS handshake.
    /// 
    /// This is the CORE function for async TLS:
    /// 1. Calls SSL_do_handshake() internally
    /// 2. If complete: returns HANDSHAKE_COMPLETE
    /// 3. If needs I/O: registers with epoll, returns HANDSHAKE_WANT_READ/WRITE
    /// 4. On error: returns HANDSHAKE_ERROR
    /// 
    /// Usage pattern in C#:
    /// <code>
    /// while (true) {
    ///     int status = NativeSsl.ssl_try_handshake(ssl, fd, epoll);
    ///     if (status == HANDSHAKE_COMPLETE) break;
    ///     if (status == HANDSHAKE_ERROR) throw ...;
    ///     
    ///     // Wait for I/O readiness
    ///     await Task.Run(() => NativeSsl.epoll_wait_one(epoll, -1));
    /// }
    /// </code>
    /// </summary>
    /// <param name="ssl">SSL object</param>
    /// <param name="client_fd">Client socket FD</param>
    /// <param name="epoll_fd">Epoll instance for event registration</param>
    /// <returns>HANDSHAKE_* status code</returns>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ssl_try_handshake(IntPtr ssl, int client_fd, int epoll_fd);

    // ========================================================================
    // SSL Read/Write
    // ========================================================================

    /// <summary>
    /// Read decrypted data from the SSL connection.
    /// 
    /// After handshake completes, use this to receive application data.
    /// SSL_read handles decryption automatically.
    /// </summary>
    /// <param name="ssl">SSL object (handshake must be complete)</param>
    /// <param name="buffer">Buffer to receive data</param>
    /// <param name="buffer_size">Max bytes to read</param>
    /// <returns>
    /// > 0: Bytes read
    /// 0: Connection closed (EOF)
    /// -1: Would block (no data yet)
    /// -2: Error
    /// </returns>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int ssl_read(IntPtr ssl, byte* buffer, int buffer_size);

    /// <summary>
    /// Write data through the SSL connection (encrypts and sends).
    /// </summary>
    /// <param name="ssl">SSL object (handshake must be complete)</param>
    /// <param name="data">Plaintext data to send</param>
    /// <param name="length">Number of bytes</param>
    /// <returns>
    /// > 0: Bytes written
    /// -1: Would block (buffer full)
    /// -2: Error
    /// </returns>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int ssl_write(IntPtr ssl, byte* data, int length);
}
