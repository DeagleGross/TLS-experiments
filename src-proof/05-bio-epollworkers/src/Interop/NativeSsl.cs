using System.Runtime.InteropServices;

namespace BioEpollWorkers.Interop;

/// <summary>
/// P/Invoke wrapper for libbio_native.so.
///
/// This is intentionally a copy of <c>NativeSsl</c> from experiment 04
/// (DemoSemiUnmanagedSocket) with the SAME public surface — same method
/// names, signatures and status codes — so the worker loop is reusable
/// byte-for-byte. Only the underlying library changes: this version drives
/// memory BIOs from C instead of relying on SSL_set_fd.
/// </summary>
internal static class NativeSsl
{
    private const string LibName = "libbio_native.so";

    public const int HANDSHAKE_COMPLETE = 0;
    public const int HANDSHAKE_WANT_READ = 1;
    public const int HANDSHAKE_WANT_WRITE = 2;
    public const int HANDSHAKE_ERROR = -1;

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int create_epoll();

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void close_epoll(int epoll_fd);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int epoll_wait_one(int epoll_fd, int timeout_ms);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int epoll_wait_batch(int epoll_fd, int timeout_ms, int* fds_out, int max_events);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int epoll_add_listen_fd(int epoll_fd, int listen_fd);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int accept_nonblocking(int listen_fd);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_socket_nonblocking(int fd);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_tcp_nodelay(int fd);

    /// <summary>
    /// Create an opaque BIO-driven SSL connection AND register fd with epoll (EPOLLIN).
    /// Returns an opaque pointer (cast to IntPtr) that must be passed back to
    /// <see cref="ssl_try_handshake"/>, <see cref="ssl_write"/> etc.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ssl_connection_create(IntPtr ssl_ctx, int client_fd, int epoll_fd);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ssl_connection_destroy(IntPtr ssl);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ssl_get_fd(IntPtr ssl);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ssl_try_handshake(IntPtr ssl, int client_fd, int epoll_fd);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int ssl_read(IntPtr ssl, byte* buffer, int buffer_size);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int ssl_write(IntPtr ssl, byte* data, int length);
}
