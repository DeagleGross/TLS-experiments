using Serilog;
using System.Runtime.InteropServices;
using System.Threading.Channels;

namespace AsyncTlsSockets;

public class ConnectionContext : IDisposable
{
    public readonly int _fd;
    public readonly IntPtr _ssl;
    private GCHandle _handle;
    private int _disposed = 0; // To prevent double-disposal

    private TaskCompletionSource<int>? _readTcs;
    private TaskCompletionSource<int>? _writeTcs;

    private Memory<byte> _currentReadBuffer;

    private readonly ChannelWriter<ConnectionContext> _acceptQueue;

    public bool HandshakeComplete { get; private set; }

    public ConnectionContext(int fd, IntPtr sslPtr, ChannelWriter<ConnectionContext> acceptQueue)
    {
        _fd = fd;
        _ssl = sslPtr;

        _acceptQueue = acceptQueue;
    }

    /// <summary>
    /// Stores the GCHandle created during HandleAccept.
    /// This handle keeps the object pinned for Linux epoll.
    /// </summary>
    public void SetHandle(GCHandle handle)
    {
        _handle = handle;
    }

    #region TLS Worker Callbacks

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
        int result = NativeOpenSsl.SSL_do_handshake(_ssl);

        if (result == 1) // 1 means Handshake Success
        {
            HandshakeComplete = true;

            // This is the "Return" to the controller.
            // It makes the 'await AcceptAsync()' in Program.cs continue.
            if (!_acceptQueue.TryWrite(this))
            {
                // If the queue was closed/full (unlikely here)
                Dispose();
            }
        }
        else
        {
            int err = NativeOpenSsl.SSL_get_error(_ssl, result);
            if (err == 2) // SSL_ERROR_WANT_READ
            {
                // Normal. Do nothing. Worker loop will call OnDataAvailable()
                // which calls DoHandshake() again later.
                return;
            }
            else
            {
                // Handshake failed (bad cert, protocol, etc.)
                Dispose();
            }
        }
    }

    #endregion

    #region App Logic API

    public ValueTask<int> WriteAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        if (_writeTcs != null) throw new InvalidOperationException("Write already in progress");

        return new ValueTask<int>(_readTcs.Task);
    }

    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
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

    #endregion

    private unsafe int DecryptAndFillBuffer()
    {
        using var pin = _currentReadBuffer.Pin();
        int bytes = NativeOpenSsl.SSL_read(_ssl, (IntPtr)pin.Pointer, _currentReadBuffer.Length);

        if (bytes <= 0)
        {
            int error = NativeOpenSsl.SSL_get_error(_ssl, bytes);
            // Handle close or WANT_READ
            return 0;
        }
        return bytes;
    }

    public void Dispose()
    {
        Log.Debug("[ConnectionContext] Disposing connection on FD {Fd}", _fd);

        // Interlocked ensures that even if the Worker and App Thread 
        // both try to close the connection, we only free memory once.
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
            return;

        // 1. Clean up OpenSSL
        if (_ssl != IntPtr.Zero)
        {
            // This frees the SSL state machine memory
            NativeOpenSsl.SSL_free(_ssl);
        }

        // 2. Close the Linux Socket
        if (_fd > 0)
        {
            // This closes the actual TCP connection
            Libc.close(_fd);
        }

        // 3. Unpin from the Garbage Collector
        if (_handle.IsAllocated)
        {
            // CRITICAL: Now the GC is allowed to move or collect this object.
            // After this call, the pointer stored in epoll is INVALID.
            _handle.Free();
        }

        // Optional: If you use a TaskCompletionSource for ReadAsync, 
        // cancel it here so the app doesn't hang forever.
        _readTcs?.TrySetCanceled();
        _writeTcs?.TrySetCanceled();
    }
}
