using System.Net.Sockets;
using FdBlockingTp.Interop;

namespace FdBlockingTp.Ssl;

/// <summary>
/// One TLS connection on a BLOCKING socket. The whole point of 04c is to bind
/// OpenSSL to a blocking fd via <c>SSL_set_fd</c> and let <c>SSL_do_handshake</c>
/// run to completion in a single call — no epoll, no <c>WANT_READ</c> bouncing,
/// no managed/native event loop. The thread that calls <see cref="Handshake"/>
/// will be parked in the kernel until the handshake either completes or fails.
///
/// 04 (DemoSemiUnmanagedSocket) does the same handshake against the same fd,
/// but with the socket in non-blocking mode and the handshake driven by per-worker
/// epoll loops. The 04 vs 04c/04d pair-difference therefore isolates that
/// difference (blocking-in-kernel vs epoll-driven nonblocking state machine).
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

        // Socket.Handle on Linux is the raw fd. SSL_set_fd uses it directly for
        // read()/write(), exactly the same way experiment 04 does. The socket
        // must be in blocking mode (Socket.Blocking = true, which is the default)
        // so SSL_do_handshake can block in the kernel instead of returning
        // SSL_ERROR_WANT_READ / WANT_WRITE.
        int fd = socket.Handle.ToInt32();
        if (OpenSsl.SSL_set_fd(_ssl, fd) <= 0)
        {
            OpenSsl.SSL_free(_ssl);
            _ssl = IntPtr.Zero;
            throw new InvalidOperationException($"SSL_set_fd failed: {OpenSsl.GetLastErrorString()}");
        }

        OpenSsl.SSL_set_accept_state(_ssl);
    }

    /// <summary>
    /// Drive the TLS handshake to completion. Because the underlying socket is
    /// blocking, a single SSL_do_handshake call is enough — OpenSSL will issue
    /// the read()/write() syscalls itself and the calling thread is parked in
    /// the kernel between handshake messages.
    /// </summary>
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

    /// <summary>
    /// Single-shot SSL_write of the canned HTTP response. We never SSL_read the
    /// request body — same shortcut experiment 04 / 05 take, so the workload
    /// stays apples-to-apples: handshake + one record write + close.
    /// </summary>
    public void WriteHttpResponse()
    {
        // Same response bytes as experiments 04 and 05 — 52 bytes plaintext.
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
                // Matches experiment 04 / 05's ssl_connection_destroy: SSL_shutdown
                // then SSL_free. We intentionally do NOT skip SSL_shutdown — the
                // tuned C ceiling (01b) drops it for max perf, but the C# epoll
                // baseline (04) still calls it, so 04c must too for fair compare.
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
