using System;
using System.Runtime.InteropServices;

namespace NginxTls;

internal static class NativeMethods
{
    private const string LibName = "nginx_tls";

    // Return codes
    public const int NGX_OK = 0;
    public const int NGX_ERROR = -1;
    public const int NGX_AGAIN = -2;
    public const int NGX_DONE = -3;

    // Event types
    public const int NGX_READ_EVENT = 0;
    public const int NGX_WRITE_EVENT = 1;

    // SSL context management
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ngx_ssl_create_context(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string certFile,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string keyFile,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? caFile);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ngx_ssl_free_context(IntPtr ctx);

    // Epoll context
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ngx_epoll_create(int maxEvents);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ngx_epoll_destroy(IntPtr ctx);

    // Socket operations
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ngx_create_listening_socket(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? host,
        int port,
        int backlog);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ngx_accept4_nonblock(
        int listenFd,
        byte[]? clientAddr,
        int addrLen);

    // Connection management
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ngx_connection_create(
        IntPtr epollCtx,
        IntPtr sslCtx,
        int fd);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ngx_connection_free(IntPtr conn);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ngx_epoll_add_connection(
        IntPtr epollCtx,
        IntPtr conn);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ngx_epoll_del_connection(
        IntPtr epollCtx,
        IntPtr conn);

    // Event processing
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ngx_epoll_wait(
        IntPtr epollCtx,
        IntPtr[] readyConns,
        int[] readyEvents,
        int maxEvents,
        int timeoutMs);

    // SSL operations
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ngx_ssl_handshake(IntPtr conn);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ngx_ssl_read(
        IntPtr conn,
        byte[] buffer,
        int size);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ngx_ssl_write(
        IntPtr conn,
        byte[] buffer,
        int size);

    // Query connection state
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ngx_connection_is_handshake_done(IntPtr conn);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ngx_connection_get_fd(IntPtr conn);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ngx_connection_get_ssl_error(IntPtr conn);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ngx_ssl_get_error_string(int errorCode);
}
