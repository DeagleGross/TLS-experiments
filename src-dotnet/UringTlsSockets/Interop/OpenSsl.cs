using System.Runtime.InteropServices;

namespace UringTlsSockets.Interop;

/// <summary>
/// OpenSSL interop definitions for direct SSL/TLS operations.
/// Used by SslContext for SSL_CTX lifecycle management.
/// </summary>
internal static unsafe class OpenSsl
{
    private const string LibSsl    = "libssl.so.3";
    private const string LibCrypto = "libcrypto.so.3";

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
        OPENSSL_init_ssl(0, IntPtr.Zero);
        OPENSSL_init_crypto(0, IntPtr.Zero);
    }

    #endregion
}
