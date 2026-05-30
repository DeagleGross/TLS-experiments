using System.Net.Sockets;
using FdBlockingWorkers.Interop;

namespace FdBlockingWorkers.Ssl;

/// <summary>
/// One TLS connection on a BLOCKING socket. Identical body to experiment 04c —
/// see that file for the full rationale. Duplicated here intentionally to keep
/// each proof experiment self-contained.
/// </summary>
internal sealed unsafe class SslConnection : IDisposable
{
    private IntPtr _ssl;
    private bool _disposed;

    public SslConnection(SslContext ctx, Socket socket)
    {
        ArgumentNullException.ThrowIfNull(ctx);
        ArgumentNullException.ThrowIfNull(socket);

        _ssl = OpenSsl.SSL_new(ctx.Handle);
        if (_ssl == IntPtr.Zero)
        {
            throw new InvalidOperationException($"SSL_new failed: {OpenSsl.GetLastErrorString()}");
        }

        int fd = socket.Handle.ToInt32();
        if (OpenSsl.SSL_set_fd(_ssl, fd) <= 0)
        {
            OpenSsl.SSL_free(_ssl);
            _ssl = IntPtr.Zero;
            throw new InvalidOperationException($"SSL_set_fd failed: {OpenSsl.GetLastErrorString()}");
        }

        OpenSsl.SSL_set_accept_state(_ssl);
    }

    public void Handshake()
    {
        int ret = OpenSsl.SSL_do_handshake(_ssl);
        if (ret == 1)
        {
            return;
        }

        int err = OpenSsl.SSL_get_error(_ssl, ret);
        throw new InvalidOperationException($"SSL_do_handshake failed: err={err} {OpenSsl.GetLastErrorString()}");
    }

    public void WriteHttpResponse()
    {
        ReadOnlySpan<byte> response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"u8;
        fixed (byte* ptr = response)
        {
            int written = OpenSsl.SSL_write(_ssl, ptr, response.Length);
            if (written <= 0)
            {
                int err = OpenSsl.SSL_get_error(_ssl, written);
                throw new InvalidOperationException($"SSL_write failed: err={err} {OpenSsl.GetLastErrorString()}");
            }
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_ssl != IntPtr.Zero)
            {
                OpenSsl.SSL_shutdown(_ssl);
                OpenSsl.SSL_free(_ssl);
                _ssl = IntPtr.Zero;
            }
            _disposed = true;
        }
    }

    ~SslConnection()
    {
        Dispose();
    }
}
