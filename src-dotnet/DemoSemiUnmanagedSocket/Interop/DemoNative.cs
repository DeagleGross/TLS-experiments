using System.Runtime.InteropServices;

namespace DemoSemiUnmanagedSocket.Interop;

/// <summary>
/// P/Invoke wrapper for demo_native library.
/// </summary>
internal static class DemoNative
{
    private const string LibName = "libdemo_native.so";

    /// <summary>
    /// Log socket FD and SSL_CTX to native console.
    /// Demonstrates passing managed resources to unmanaged code.
    /// </summary>
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void log_socket_and_ssl_context(int socket_fd, IntPtr ssl_ctx);
}
