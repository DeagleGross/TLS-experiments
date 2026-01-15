using System.Runtime.InteropServices;

namespace AsyncTlsSockets;

internal static class NativeOpenSsl
{
    // OpenSSL Error Codes
    public const int SSL_ERROR_NONE = 0;

    // SSL_CTX_set_options flags
    public const long SSL_OP_NO_COMPRESSION = 0x00020000L;           // Disable compression (~522KB/conn saved)
    public const long SSL_OP_SINGLE_ECDH_USE = 0x00080000L;          // Fresh ECDH key per handshake
    public const long SSL_OP_NO_CLIENT_RENEGOTIATION = 0x00001000L;  // Block client renegotiation (DoS protection)
    public const long SSL_OP_IGNORE_UNEXPECTED_EOF = 0x00000080L;    // OpenSSL 3.0+: treat unexpected EOF as normal

    // SSL_CTX_set_mode flags
    public const long SSL_MODE_RELEASE_BUFFERS = 0x00000010L;        // Release buffers when idle (~34KB/conn saved)

    // SSL_CTX_ctrl commands (SSL_CTX_set_mode and SSL_CTX_set_read_ahead are macros)
    public const int SSL_CTRL_MODE = 33;
    public const int SSL_CTRL_SET_READ_AHEAD = 41;
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

    [DllImport("libssl.so.3")]
    public static extern long SSL_CTX_set_options(IntPtr ctx, long options);

    // SSL_CTX_ctrl is the underlying function for SSL_CTX_set_mode and SSL_CTX_set_read_ahead macros
    [DllImport("libssl.so.3")]
    public static extern long SSL_CTX_ctrl(IntPtr ctx, int cmd, long larg, IntPtr parg);

    // Wrapper methods to match the macro API
    public static long SSL_CTX_set_mode(IntPtr ctx, long mode)
        => SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, mode, IntPtr.Zero);

    public static long SSL_CTX_set_read_ahead(IntPtr ctx, int yes)
        => SSL_CTX_ctrl(ctx, SSL_CTRL_SET_READ_AHEAD, yes, IntPtr.Zero);

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

    [DllImport("libssl.so.3", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_shutdown(IntPtr ssl);

    #endregion
}