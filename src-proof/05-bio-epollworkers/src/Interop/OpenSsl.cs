using System.Runtime.InteropServices;

namespace BioEpollWorkers.Interop;

/// <summary>
/// OpenSSL interop. Extended over the experiment-04 copy with
/// <c>SSL_CTX_set_min_proto_version</c>, <c>SSL_CTX_set_max_proto_version</c>,
/// and <c>SSL_CTX_set_session_cache_mode</c> (via SSL_CTX_ctrl) so we can
/// force TLS 1.3 only and disable session caching for a fair handshake-cost
/// comparison.
/// </summary>
internal static unsafe class OpenSsl
{
    private const string LibSsl = "libssl.so.3";
    private const string LibCrypto = "libcrypto.so.3";

    public const int TLS1_2_VERSION = 0x0303;
    public const int TLS1_3_VERSION = 0x0304;

    public const int SSL_ERROR_NONE = 0;
    public const int SSL_ERROR_WANT_READ = 2;
    public const int SSL_ERROR_WANT_WRITE = 3;
    public const int SSL_ERROR_SYSCALL = 5;
    public const int SSL_ERROR_SSL = 1;

    public const int SSL_FILETYPE_PEM = 1;

    // Session cache modes (openssl/ssl.h)
    public const long SSL_SESS_CACHE_OFF = 0x0000;

    // SSL_CTX_ctrl op codes used for the macro-style helpers above (openssl/ssl.h).
    private const int SSL_CTRL_SET_SESS_CACHE_MODE = 44;
    private const int SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
    private const int SSL_CTRL_SET_MAX_PROTO_VERSION = 124;

    #region SSL Context Management
    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr TLS_server_method();

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SSL_CTX_new(IntPtr method);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_CTX_free(IntPtr ctx);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_CTX_use_certificate_file(IntPtr ctx, string file, int type);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_CTX_use_PrivateKey_file(IntPtr ctx, string file, int type);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_CTX_check_private_key(IntPtr ctx);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern long SSL_CTX_set_options(IntPtr ctx, long options);

    // Real exported functions in libssl 1.1.0+ (not macros).
    // NOTE: SSL_CTX_set_min_proto_version / set_max_proto_version are MACROS in OpenSSL
    // headers (they expand to SSL_CTX_ctrl with SSL_CTRL_SET_MIN/MAX_PROTO_VERSION).
    // They are NOT exported from libssl.so.3 as functions, so we must call SSL_CTX_ctrl.

    // SSL_CTX_ctrl is used to implement SSL_CTX_set_session_cache_mode AND the proto-version macros.
    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern long SSL_CTX_ctrl(IntPtr ctx, int cmd, long larg, IntPtr parg);

    public static long SSL_CTX_set_min_proto_version(IntPtr ctx, int version)
        => SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, IntPtr.Zero);

    public static long SSL_CTX_set_max_proto_version(IntPtr ctx, int version)
        => SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, version, IntPtr.Zero);

    public static long SSL_CTX_set_session_cache_mode(IntPtr ctx, long mode)
        => SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, mode, IntPtr.Zero);
    #endregion

    #region SSL Connection
    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SSL_new(IntPtr ctx);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_free(IntPtr ssl);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_set_fd(IntPtr ssl, int fd);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_accept(IntPtr ssl);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_set_accept_state(IntPtr ssl);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_do_handshake(IntPtr ssl);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_get_error(IntPtr ssl, int ret);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_read(IntPtr ssl, byte* buf, int num);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_write(IntPtr ssl, byte* buf, int num);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_shutdown(IntPtr ssl);
    #endregion

    #region Init
    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int OPENSSL_init_ssl(ulong opts, IntPtr settings);

    [DllImport(LibCrypto, CallingConvention = CallingConvention.Cdecl)]
    public static extern int OPENSSL_init_crypto(ulong opts, IntPtr settings);
    #endregion

    #region Errors
    [DllImport(LibCrypto, CallingConvention = CallingConvention.Cdecl)]
    public static extern ulong ERR_get_error();

    [DllImport(LibCrypto, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ERR_error_string(ulong e, byte* buf);

    public static string GetLastErrorString()
    {
        var error = ERR_get_error();
        if (error == 0) return "No error";

        byte* buffer = stackalloc byte[256];
        ERR_error_string(error, buffer);
        return Marshal.PtrToStringAnsi((IntPtr)buffer) ?? "Unknown error";
    }
    #endregion

    public static void Initialize()
    {
        OPENSSL_init_ssl(0, IntPtr.Zero);
        OPENSSL_init_crypto(0, IntPtr.Zero);
    }
}
