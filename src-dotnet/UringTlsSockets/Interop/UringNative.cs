using System.Runtime.InteropServices;

namespace UringTlsSockets.Interop;

/// <summary>
/// P/Invoke wrapper for the native io_uring + SSL library (liburing_native.so).
/// </summary>
internal static class UringNative
{
    private const string LibName = "liburing_native.so";

    /* Handshake status codes (must match uring_native.h) */
    public const int HANDSHAKE_COMPLETE   = 0;
    public const int HANDSHAKE_WANT_READ  = 1;
    public const int HANDSHAKE_WANT_WRITE = 2;
    public const int HANDSHAKE_ERROR      = -1;

    /* CQE type identifiers */
    public const int CQE_TYPE_ACCEPT = 1;
    public const int CQE_TYPE_POLL   = 2;

    /* ── Ring lifecycle ─────────────────────────────────────────────── */

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr uring_create(int queue_depth);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void uring_destroy(IntPtr ctx);

    /* ── Accept / Poll / Wait ───────────────────────────────────────── */

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uring_set_listen_fd(IntPtr ctx, int listen_fd);

    /// <summary>
    /// Prepare a one-shot poll SQE. Does NOT io_uring_submit —
    /// the next uring_wait_batch call flushes pending SQEs.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uring_prep_poll(IntPtr ctx, int fd, int want_write);

    /// <summary>
    /// Flush pending SQEs, wait for completions, fill arrays.
    /// Returns number of completions, or &lt;0 on error.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uring_wait_batch(
        IntPtr ctx,
        int* types, int* fds, int* results,
        int max_cqes, int timeout_ms);

    /* ── Socket helpers ─────────────────────────────────────────────── */

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_socket_nonblocking(int fd);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int set_tcp_nodelay(int fd);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int accept_nonblocking(int listen_fd);

    /* ── SSL connection management ──────────────────────────────────── */

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ssl_connection_create(IntPtr ssl_ctx, int client_fd);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ssl_connection_destroy(IntPtr ssl);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ssl_try_handshake(IntPtr ssl);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int ssl_read_data(IntPtr ssl, byte* buffer, int buffer_size);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int ssl_write_data(IntPtr ssl, byte* data, int length);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int ssl_get_fd(IntPtr ssl);
}
