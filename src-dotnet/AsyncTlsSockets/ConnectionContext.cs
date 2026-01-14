namespace AsyncTlsSockets;

public class ConnectionContext
{
    public readonly int Fd;
    public readonly IntPtr SslPtr;
    private TaskCompletionSource<int>? _readTcs;
    private Memory<byte> _currentReadBuffer;

    public bool HandshakeComplete { get; private set; }

    public ConnectionContext(int fd, IntPtr sslPtr)
    {
        Fd = fd;
        SslPtr = sslPtr;
    }

    // --- The Worker Thread calls these ---

    public void OnDataAvailable()
    {
        if (!HandshakeComplete)
        {
            DoHandshake();
            return;
        }

        // If a ReadAsync is waiting, fulfill it
        if (_readTcs != null)
        {
            int bytes = DecryptAndFillBuffer();
            if (bytes > 0)
            {
                var tcs = _readTcs;
                _readTcs = null;
                tcs.SetResult(bytes);
            }
        }
    }

    public void DoHandshake()
    {
        int result = NativeOpenSsl.SSL_do_handshake(SslPtr);
        if (result == 1)
        {
            HandshakeComplete = true;
            // Notify application that connection is ready if needed
        }
        else
        {
            int error = NativeOpenSsl.SSL_get_error(SslPtr, result);
            // If error is WANT_READ, we just return to the loop.
            // Epoll will wake us up again when more data arrives.
        }
    }

    private unsafe int DecryptAndFillBuffer()
    {
        using var pin = _currentReadBuffer.Pin();
        int bytes = NativeOpenSsl.SSL_read(SslPtr, (IntPtr)pin.Pointer, _currentReadBuffer.Length);

        if (bytes <= 0)
        {
            int error = NativeOpenSsl.SSL_get_error(SslPtr, bytes);
            // Handle close or WANT_READ
            return 0;
        }
        return bytes;
    }

    // --- The Application Logic calls this ---

    public ValueTask<int> ReadAsync(Memory<byte> buffer)
    {
        if (_readTcs != null) throw new InvalidOperationException("Read already in progress");

        _currentReadBuffer = buffer;
        // Use RunContinuationsAsynchronously to keep app logic off the worker thread
        _readTcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

        // Try an immediate read in case data is already in OpenSSL internal buffers
        int immediate = DecryptAndFillBuffer();
        if (immediate > 0)
        {
            _readTcs = null;
            return new ValueTask<int>(immediate);
        }

        return new ValueTask<int>(_readTcs.Task);
    }
}
