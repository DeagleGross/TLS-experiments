using System.Runtime.InteropServices;

namespace PureUnmanagedSockets.Interop;

/// <summary>
/// P/Invoke wrapper for nginx-style server with C#/C split.
/// C handles TLS (accept, handshake, SSL_read/write).
/// C# handles HTTP (parsing requests, generating responses).
/// Communication via lock-free queues + eventfd.
/// </summary>
internal static unsafe class OpenSslNative
{
    private const string LibName = "libopenssl_native.so";

    #region Queue-Based Request/Response System

    /// <summary>
    /// Get eventfd that C# should wait on for new requests.
    /// Use poll/epoll_wait on this FD to know when requests are available.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int get_request_notify_fd();

    /// <summary>
    /// Dequeue a request from C.
    /// Returns 1 if request dequeued, 0 if queue empty.
    /// Caller must free 'data' using Marshal.FreeHGlobal!
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int dequeue_request(
        out int connId,
        out IntPtr data,
        out int length);

    /// <summary>
    /// Enqueue a response back to C (will be written via SSL_write).
    /// Returns 0 on success, -1 if queue full.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int enqueue_response(
        int connId,
        byte[] data,
        int length);

    #endregion

    #region Server Control

    /// <summary>
    /// Start nginx-style server.
    /// C handles TLS, C# processes HTTP via queues.
    /// BLOCKS until Ctrl+C.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int start_nginx_server(
        int port,
        [MarshalAs(UnmanagedType.LPStr)] string certFile,
        [MarshalAs(UnmanagedType.LPStr)] string keyFile,
        int workerCount);

    /// <summary>
    /// Get server statistics.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void get_server_stats(
        out ulong totalHandshakes,
        out ulong totalConnections);

    #endregion
}


