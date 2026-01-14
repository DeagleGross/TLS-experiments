using System.Runtime.InteropServices;

namespace AsyncTlsSockets;

internal static class NativeOpenSsl
{
    // OpenSSL Error Codes
    public const int SSL_ERROR_NONE = 0;
    public const int SSL_ERROR_SSL = 1;
    public const int SSL_ERROR_WANT_READ = 2;    // The "Wait and Retry" signal
    public const int SSL_ERROR_WANT_WRITE = 3;   // Socket buffer full signal
    public const int SSL_ERROR_SYSCALL = 5;      // Low-level IO error
    public const int SSL_ERROR_ZERO_RETURN = 6;  // Connection closed gracefully

    #region Context

    [DllImport("libssl.so.3")] // Use .so.1.1 if on older Linux
    public static extern int OPENSSL_init_ssl(ulong opts, IntPtr settings);

    [DllImport("libssl.so.3")]
    public static extern IntPtr TLS_server_method();

    [DllImport("libssl.so.3")]
    public static extern IntPtr SSL_CTX_new(IntPtr method);

    [DllImport("libssl.so.3", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SSL_new(IntPtr ctx);

    [DllImport("libssl.so.3", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_set_fd(IntPtr ssl, int fd);

    [DllImport("libssl.so.3", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_set_accept_state(IntPtr ssl);

    [DllImport("libssl.so.3")]
    public static extern int SSL_CTX_use_certificate_chain_file(IntPtr ctx, string file);

    [DllImport("libssl.so.3")]
    public static extern int SSL_CTX_use_PrivateKey_file(IntPtr ctx, string file, int type);

    [DllImport("libssl.so.3")]
    public static extern int SSL_CTX_check_private_key(IntPtr ctx);

    #endregion

    #region API

    [DllImport("libssl.so.3", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_do_handshake(IntPtr ssl);

    [DllImport("libssl.so.3", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_get_error(IntPtr ssl, int ret);

    [DllImport("libssl.so.3", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_read(IntPtr ssl, IntPtr buf, int num);

    [DllImport("libssl.so.3", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_write(IntPtr ssl, IntPtr buf, int num);

    [DllImport("libssl.so.3", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_free(IntPtr ssl);

    #endregion
}