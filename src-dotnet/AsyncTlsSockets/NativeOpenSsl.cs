using System.Runtime.InteropServices;

namespace AsyncTlsSockets;

internal static class NativeOpenSsl
{
    [DllImport("libssl.so.3")] // Use .so.1.1 if on older Linux
    public static extern int OPENSSL_init_ssl(ulong opts, IntPtr settings);

    [DllImport("libssl.so.3")]
    public static extern IntPtr TLS_server_method();

    [DllImport("libssl.so.3")]
    public static extern IntPtr SSL_CTX_new(IntPtr method);

    [DllImport("libssl.so.3")]
    public static extern int SSL_CTX_use_certificate_chain_file(IntPtr ctx, string file);

    [DllImport("libssl.so.3")]
    public static extern int SSL_CTX_use_PrivateKey_file(IntPtr ctx, string file, int type);

    [DllImport("libssl.so.3")]
    public static extern int SSL_CTX_check_private_key(IntPtr ctx);
}