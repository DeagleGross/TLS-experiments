using System.Runtime.InteropServices;

namespace AsyncSslConsole.Interop;

/// <summary>
/// OpenSSL interop definitions for direct SSL/TLS operations.
/// This allows us to bypass SslStream and use non-blocking SSL_do_handshake.
/// </summary>
internal static unsafe class OpenSsl
{
    private const string LibSsl = "libssl.so.3"; // OpenSSL 3.x on Linux
    private const string LibCrypto = "libcrypto.so.3";

    // SSL/TLS Protocol versions
    public const int TLS1_2_VERSION = 0x0303;
    public const int TLS1_3_VERSION = 0x0304;

    // SSL_do_handshake return codes
    public const int SSL_ERROR_NONE = 0;
    public const int SSL_ERROR_WANT_READ = 2;
    public const int SSL_ERROR_WANT_WRITE = 3;
    public const int SSL_ERROR_SYSCALL = 5;
    public const int SSL_ERROR_SSL = 1;

    // File types for SSL_CTX_use_certificate_file
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

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern long SSL_CTX_set_options(IntPtr ctx, long options);

    #endregion

    #region SSL Session Management

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

    #region OpenSSL Initialization

    [DllImport(LibSsl, CallingConvention = CallingConvention.Cdecl)]
    public static extern int OPENSSL_init_ssl(ulong opts, IntPtr settings);

    [DllImport(LibCrypto, CallingConvention = CallingConvention.Cdecl)]
    public static extern int OPENSSL_init_crypto(ulong opts, IntPtr settings);

    #endregion

    #region Error Handling

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

    #region Helper Methods

    public static void Initialize()
    {
        // Initialize OpenSSL library
        OPENSSL_init_ssl(0, IntPtr.Zero);
        OPENSSL_init_crypto(0, IntPtr.Zero);
    }

    #endregion
}
