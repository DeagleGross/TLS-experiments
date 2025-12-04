using System.Runtime.InteropServices;

namespace DirectFdSsl.Interop;

/// <summary>
/// OpenSSL P/Invoke declarations for fd-based (non-BIO) SSL operations.
/// </summary>
public static unsafe class OpenSsl
{
    private const string LibSsl = "libssl.so.3";
    private const string LibCrypto = "libcrypto.so.3";

    // SSL method and context
    [DllImport(LibSsl)]
    public static extern IntPtr TLS_server_method();

    [DllImport(LibSsl)]
    public static extern IntPtr TLS_client_method();

    [DllImport(LibSsl)]
    public static extern IntPtr SSL_CTX_new(IntPtr method);

    [DllImport(LibSsl)]
    public static extern void SSL_CTX_free(IntPtr ctx);

    // SSL_CTX_set_min/max_proto_version are macros, use SSL_CTX_ctrl
    [DllImport(LibSsl)]
    public static extern long SSL_CTX_ctrl(IntPtr ctx, int cmd, long larg, IntPtr parg);

    // SSL_CTRL commands for version setting
    private const int SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
    private const int SSL_CTRL_SET_MAX_PROTO_VERSION = 124;
    private const int SSL_CTRL_SET_SESS_CACHE_MODE = 44;

    public static int SSL_CTX_set_min_proto_version(IntPtr ctx, int version)
        => (int)SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, IntPtr.Zero);

    public static int SSL_CTX_set_max_proto_version(IntPtr ctx, int version)
        => (int)SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, version, IntPtr.Zero);

    public static long SSL_CTX_set_session_cache_mode(IntPtr ctx, long mode)
        => SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, mode, IntPtr.Zero);

    [DllImport(LibSsl)]
    public static extern int SSL_CTX_use_certificate_file(IntPtr ctx, string file, int type);

    [DllImport(LibSsl)]
    public static extern int SSL_CTX_use_PrivateKey_file(IntPtr ctx, string file, int type);

    // SSL object
    [DllImport(LibSsl)]
    public static extern IntPtr SSL_new(IntPtr ctx);

    [DllImport(LibSsl)]
    public static extern void SSL_free(IntPtr ssl);

    // KEY: fd-based operations (no BIOs!)
    [DllImport(LibSsl)]
    public static extern int SSL_set_fd(IntPtr ssl, int fd);

    [DllImport(LibSsl)]
    public static extern int SSL_get_fd(IntPtr ssl);

    [DllImport(LibSsl)]
    public static extern void SSL_set_accept_state(IntPtr ssl);

    [DllImport(LibSsl)]
    public static extern void SSL_set_connect_state(IntPtr ssl);

    // Handshake and I/O
    [DllImport(LibSsl)]
    public static extern int SSL_do_handshake(IntPtr ssl);

    [DllImport(LibSsl)]
    public static extern int SSL_read(IntPtr ssl, byte* buf, int num);

    [DllImport(LibSsl)]
    public static extern int SSL_write(IntPtr ssl, byte* buf, int num);

    [DllImport(LibSsl)]
    public static extern int SSL_shutdown(IntPtr ssl);

    [DllImport(LibSsl)]
    public static extern int SSL_get_error(IntPtr ssl, int ret);

    // Error codes
    public const int SSL_ERROR_NONE = 0;
    public const int SSL_ERROR_SSL = 1;
    public const int SSL_ERROR_WANT_READ = 2;
    public const int SSL_ERROR_WANT_WRITE = 3;
    public const int SSL_ERROR_WANT_X509_LOOKUP = 4;
    public const int SSL_ERROR_SYSCALL = 5;
    public const int SSL_ERROR_ZERO_RETURN = 6;
    public const int SSL_ERROR_WANT_CONNECT = 7;
    public const int SSL_ERROR_WANT_ACCEPT = 8;

    // TLS versions
    public const int TLS1_2_VERSION = 0x0303;
    public const int TLS1_3_VERSION = 0x0304;

    // File types
    public const int SSL_FILETYPE_PEM = 1;

    // Session cache modes
    public const long SSL_SESS_CACHE_OFF = 0x0000;

    // Error handling
    [DllImport(LibCrypto)]
    public static extern ulong ERR_get_error();

    [DllImport(LibCrypto)]
    public static extern void ERR_error_string_n(ulong e, byte* buf, nuint len);

    public static string GetLastError()
    {
        ulong err = ERR_get_error();
        if (err == 0) return "No error";
        
        byte* buf = stackalloc byte[256];
        ERR_error_string_n(err, buf, 256);
        return Marshal.PtrToStringAnsi((IntPtr)buf) ?? "Unknown error";
    }
}
