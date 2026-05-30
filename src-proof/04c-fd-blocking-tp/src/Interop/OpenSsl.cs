using System.Runtime.InteropServices;

namespace FdBlockingTp.Interop;

/// <summary>
/// OpenSSL P/Invoke surface for the experiment-04c blocking SSL_set_fd server.
///
/// This is the SAME surface used by experiment 04 (DemoSemiUnmanagedSocket) and 05
/// (BioEpollWorkers) — we keep the contract identical so the only thing that
/// differs between 04 and 04c is the threading / accept / wait model, not the
/// OpenSSL API surface.
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
    #endregion

    #region SSL Connection
    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SSL_new(IntPtr ctx);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_free(IntPtr ssl);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_set_fd(IntPtr ssl, int fd);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_set_accept_state(IntPtr ssl);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_do_handshake(IntPtr ssl);

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_get_error(IntPtr ssl, int ret);

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
        if (error == 0)
        {
            return "No error";
        }

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
