using Serilog;
using System.Runtime.InteropServices;
using System.Threading.Channels;

namespace AsyncTlsSockets;

public class ConnectionContext : IDisposable
{
    private readonly int _epollFd;
    public readonly int _fd;
    public readonly IntPtr _ssl;
    private GCHandle _handle;
    private int _disposed = 0; // To prevent double-disposal
    
    private readonly ChannelWriter<ConnectionContext> _acceptQueue;

    private TaskCompletionSource<int>? _writeTcs;
    private ReadOnlyMemory<byte> _pendingWriteBuffer;

    private TaskCompletionSource<int>? _readTcs;
    private Memory<byte> _currentReadBuffer;

    public bool HandshakeComplete { get; private set; }

    public ConnectionContext(int epollFd, int fd, IntPtr sslPtr, ChannelWriter<ConnectionContext> acceptQueue)
    {
        _epollFd = epollFd;
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

    internal void OnSocketReady()
    {
        if (!HandshakeComplete)
        {
            Log.Debug("[ConnectionContext] Continuing handshake on FD {Fd}", _fd);
            DoHandshake();
            return;
        }

        // Handle Pending Write First (usually higher priority to clear buffers)
        if (_writeTcs != null)
        {
            Log.Debug("[ConnectionContext] Continuing pending write on FD {Fd}", _fd);
            int written = TrySslWrite(_pendingWriteBuffer);
            if (written > 0)
            {
                var tcs = _writeTcs;
                _writeTcs = null;
                tcs.TrySetResult(written);
            }
        }

        // Handle Pending Read
        if (_readTcs != null)
        {
            Log.Debug("[ConnectionContext] Continuing pending read on FD {Fd}", _fd);
            // TrySslRead implementation from previous step
            int read = TrySslRead(_currentReadBuffer); 
            if (read != 0)
            {
                var tcs = _readTcs;
                _readTcs = null;
                tcs.TrySetResult(read > 0 ? read : 0);
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

    public ValueTask<int> WriteAsync(ReadOnlyMemory<byte> buffer)
    {
        if (_writeTcs != null) throw new InvalidOperationException("Write already in progress");

        // 1. Try to write immediately
        int written = TrySslWrite(buffer);
        
        if (written > 0) return new ValueTask<int>(written);
        
        // 2. If written == 0, it means WANT_WRITE (Buffer full)
        _pendingWriteBuffer = buffer;
        _writeTcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        
        // We don't need to 'MOD' epoll because we already registered with EPOLLET 
        // and potentially EPOLLOUT. If you didn't include EPOLLOUT in the initial 
        // ADD, you must call EpollCtl MOD here.
        
        return new ValueTask<int>(_writeTcs.Task);
    }

    public ValueTask<int> ReadAsync(Memory<byte> buffer)
    {
        // Ensure we aren't already waiting for a read
        if (_readTcs != null) throw new InvalidOperationException("Read already in progress");

        // 1. Try an immediate read. 
        // Data might already be sitting in OpenSSL's internal BIO buffers.
        int immediateRead = TrySslRead(buffer);

        if (immediateRead > 0) 
        {
            return new ValueTask<int>(immediateRead);
        }
        
        if (immediateRead < 0) 
        {
            return new ValueTask<int>(0); // EOF
        }

        // 2. Data not ready. Store the state and return the Task.
        _currentReadBuffer = buffer;
        
        // Use RunContinuationsAsynchronously to ensure the 'App' code 
        // doesn't run on our 'Worker' CPU core.
        _readTcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        
        return new ValueTask<int>(_readTcs.Task);
    }

    #endregion

    private unsafe int TrySslWrite(ReadOnlyMemory<byte> buffer)
    {
        using var pin = buffer.Pin();
        int result = NativeOpenSsl.SSL_write(_ssl, (IntPtr)pin.Pointer, buffer.Length);

        if (result > 0) return result;

        int err = NativeOpenSsl.SSL_get_error(_ssl, result);
        if (err == NativeOpenSsl.SSL_ERROR_WANT_WRITE || err == NativeOpenSsl.SSL_ERROR_WANT_READ)
        {
            return 0; // Blocked
        }

        return -1; // Critical Error
    }

    private unsafe int TrySslRead(Memory<byte> buffer)
    {
        int totalRead = 0;
        using var pin = buffer.Pin();
        byte* ptr = (byte*)pin.Pointer;

        while (totalRead < buffer.Length)
        {
            int result = NativeOpenSsl.SSL_read(_ssl, (IntPtr)(ptr + totalRead), buffer.Length - totalRead);

            if (result > 0)
            {
                totalRead += result;
                // In Edge-Triggered, we keep reading until we hit an error or buffer is full
                continue; 
            }

            int err = NativeOpenSsl.SSL_get_error(_ssl, result);

            if (err == NativeOpenSsl.SSL_ERROR_WANT_READ)
            {
                // The kernel buffer is officially empty.
                return totalRead;
            }

            if (err == NativeOpenSsl.SSL_ERROR_ZERO_RETURN)
            {
                // Peer closed TLS session gracefully
                return -1; 
            }

            // Critical error (SYSCALL or SSL)
            return -1; 
        }

        return totalRead;
    }

    public void Dispose()
    {
        Log.Debug("[ConnectionContext] Disposing connection on FD {Fd}", _fd);

        // Interlocked ensures that even if the Worker and App Thread 
        // both try to close the connection, we only free memory once.
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
            return;

        // 0. Unregister from epoll so no more events arrive
        var ev = new EpollEvent();
        Libc.EpollCtl(_epollFd, (int)EpollOp.DEL, _fd, ref ev);

        // 1. Clean up OpenSSL
        if (_ssl != IntPtr.Zero)
        {
            // 1. Send the "close_notify" alert to the client
            // This tells the OpenSSL CLI that the stream is officially over
            NativeOpenSsl.SSL_shutdown(_ssl);

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
