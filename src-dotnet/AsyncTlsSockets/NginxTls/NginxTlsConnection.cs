using System;
using System.Threading;
using System.Threading.Tasks;

namespace NginxTls;

/// <summary>
/// Represents a TLS connection managed by nginx-style worker threads.
/// Provides async/await API for business code while actual SSL operations
/// happen on dedicated worker threads.
/// </summary>
public sealed class NginxTlsConnection : IDisposable
{
    private readonly IntPtr _nativeHandle;
    private readonly NginxTlsWorker _worker;
    private bool _disposed;

    // Pending async operations (nginx-style posted events)
    private TaskCompletionSource<int>? _pendingRead;
    private TaskCompletionSource<int>? _pendingWrite;
    private TaskCompletionSource<bool>? _pendingHandshake;

    private byte[]? _readBuffer;
    private int _readOffset;
    private int _readSize;

    private byte[]? _writeBuffer;
    private int _writeSize;

    internal NginxTlsConnection(IntPtr nativeHandle, NginxTlsWorker worker)
    {
        _nativeHandle = nativeHandle;
        _worker = worker;
    }

    public IntPtr NativeHandle => _nativeHandle;

    /// <summary>
    /// Performs TLS handshake. Returns when handshake is complete.
    /// This is called automatically before first read/write if needed.
    /// </summary>
    public Task<bool> HandshakeAsync(CancellationToken cancellationToken = default)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(NginxTlsConnection));

        // Check if already handshaked
        if (NativeMethods.ngx_connection_is_handshake_done(_nativeHandle) != 0)
        {
            return Task.FromResult(true);
        }

        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        if (Interlocked.CompareExchange(ref _pendingHandshake, tcs, null) != null)
        {
            throw new InvalidOperationException("Handshake already in progress");
        }

        // Register cancellation
        if (cancellationToken.CanBeCanceled)
        {
            cancellationToken.Register(() =>
            {
                if (Interlocked.CompareExchange(ref _pendingHandshake, null, tcs) == tcs)
                {
                    tcs.TrySetCanceled(cancellationToken);
                }
            });
        }

        // Queue handshake operation to worker thread
        _worker.QueueOperation(this, OperationType.Handshake);

        return tcs.Task;
    }

    /// <summary>
    /// Reads decrypted data from the TLS connection.
    /// This is the async API that your business code calls.
    /// Actual SSL_read happens on worker thread.
    /// </summary>
    public Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(NginxTlsConnection));
        if (buffer == null)
            throw new ArgumentNullException(nameof(buffer));
        if (offset < 0 || count < 0 || offset + count > buffer.Length)
            throw new ArgumentOutOfRangeException();

        // Ensure handshake is done first
        if (NativeMethods.ngx_connection_is_handshake_done(_nativeHandle) == 0)
        {
            return ReadAsyncAfterHandshake(buffer, offset, count, cancellationToken);
        }

        return ReadAsyncInternal(buffer, offset, count, cancellationToken);
    }

    private async Task<int> ReadAsyncAfterHandshake(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        await HandshakeAsync(cancellationToken).ConfigureAwait(false);
        return await ReadAsyncInternal(buffer, offset, count, cancellationToken).ConfigureAwait(false);
    }

    private Task<int> ReadAsyncInternal(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        var tcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

        if (Interlocked.CompareExchange(ref _pendingRead, tcs, null) != null)
        {
            throw new InvalidOperationException("Read already in progress");
        }

        _readBuffer = buffer;
        _readOffset = offset;
        _readSize = count;

        // Register cancellation
        if (cancellationToken.CanBeCanceled)
        {
            cancellationToken.Register(() =>
            {
                if (Interlocked.CompareExchange(ref _pendingRead, null, tcs) == tcs)
                {
                    _readBuffer = null;
                    tcs.TrySetCanceled(cancellationToken);
                }
            });
        }

        // Queue read operation to worker thread
        _worker.QueueOperation(this, OperationType.Read);

        return tcs.Task;
    }

    /// <summary>
    /// Writes encrypted data to the TLS connection.
    /// This is the async API that your business code calls.
    /// Actual SSL_write happens on worker thread.
    /// </summary>
    public Task<int> WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(NginxTlsConnection));
        if (buffer == null)
            throw new ArgumentNullException(nameof(buffer));
        if (offset < 0 || count < 0 || offset + count > buffer.Length)
            throw new ArgumentOutOfRangeException();

        // Ensure handshake is done first
        if (NativeMethods.ngx_connection_is_handshake_done(_nativeHandle) == 0)
        {
            return WriteAsyncAfterHandshake(buffer, offset, count, cancellationToken);
        }

        return WriteAsyncInternal(buffer, offset, count, cancellationToken);
    }

    private async Task<int> WriteAsyncAfterHandshake(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        await HandshakeAsync(cancellationToken).ConfigureAwait(false);
        return await WriteAsyncInternal(buffer, offset, count, cancellationToken).ConfigureAwait(false);
    }

    private Task<int> WriteAsyncInternal(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        var tcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

        if (Interlocked.CompareExchange(ref _pendingWrite, tcs, null) != null)
        {
            throw new InvalidOperationException("Write already in progress");
        }

        // Copy buffer to avoid issues with caller modifying it (nginx-style buffer management)
        _writeBuffer = new byte[count];
        Buffer.BlockCopy(buffer, offset, _writeBuffer, 0, count);
        _writeSize = count;

        // Register cancellation
        if (cancellationToken.CanBeCanceled)
        {
            cancellationToken.Register(() =>
            {
                if (Interlocked.CompareExchange(ref _pendingWrite, null, tcs) == tcs)
                {
                    _writeBuffer = null;
                    tcs.TrySetCanceled(cancellationToken);
                }
            });
        }

        // Queue write operation to worker thread
        _worker.QueueOperation(this, OperationType.Write);

        return tcs.Task;
    }

    // Called by worker thread when handshake completes
    internal void CompleteHandshake(bool success, Exception? error = null)
    {
        var tcs = Interlocked.Exchange(ref _pendingHandshake, null);
        if (tcs != null)
        {
            if (error != null)
            {
                tcs.TrySetException(error);
            }
            else
            {
                tcs.TrySetResult(success);
            }
        }
    }

    // Called by worker thread when read completes
    internal void CompleteRead(int bytesRead, Exception? error = null)
    {
        var tcs = Interlocked.Exchange(ref _pendingRead, null);
        _readBuffer = null;

        if (tcs != null)
        {
            if (error != null)
            {
                tcs.TrySetException(error);
            }
            else
            {
                tcs.TrySetResult(bytesRead);
            }
        }
    }

    // Called by worker thread when write completes
    internal void CompleteWrite(int bytesWritten, Exception? error = null)
    {
        var tcs = Interlocked.Exchange(ref _pendingWrite, null);
        _writeBuffer = null;

        if (tcs != null)
        {
            if (error != null)
            {
                tcs.TrySetException(error);
            }
            else
            {
                tcs.TrySetResult(bytesWritten);
            }
        }
    }

    // Called by worker thread to process operations
    internal bool TryProcessHandshake()
    {
        if (_pendingHandshake == null) return false;

        int result = NativeMethods.ngx_ssl_handshake(_nativeHandle);

        if (result == NativeMethods.NGX_OK)
        {
            CompleteHandshake(true);
            return true;
        }
        else if (result == NativeMethods.NGX_AGAIN)
        {
            // Need more I/O - will be called again when epoll signals ready
            return false;
        }
        else
        {
            CompleteHandshake(false, new InvalidOperationException($"Handshake failed: {result}"));
            return true;
        }
    }

    internal bool TryProcessRead()
    {
        if (_pendingRead == null || _readBuffer == null) return false;

        // Create temporary buffer for native call
        byte[] tempBuffer = new byte[_readSize];
        int result = NativeMethods.ngx_ssl_read(_nativeHandle, tempBuffer, _readSize);

        if (result > 0)
        {
            // Copy to user buffer
            Buffer.BlockCopy(tempBuffer, 0, _readBuffer, _readOffset, result);
            CompleteRead(result);
            return true;
        }
        else if (result == NativeMethods.NGX_AGAIN)
        {
            // Need more I/O - will be called again when epoll signals ready
            return false;
        }
        else if (result == NativeMethods.NGX_DONE)
        {
            // Connection closed cleanly
            CompleteRead(0);
            return true;
        }
        else
        {
            int sslError = NativeMethods.ngx_connection_get_ssl_error(_nativeHandle);
            CompleteRead(0, new InvalidOperationException($"SSL read failed: {sslError}"));
            return true;
        }
    }

    internal bool TryProcessWrite()
    {
        if (_pendingWrite == null || _writeBuffer == null) return false;

        int result = NativeMethods.ngx_ssl_write(_nativeHandle, _writeBuffer, _writeSize);

        if (result > 0)
        {
            CompleteWrite(result);
            return true;
        }
        else if (result == NativeMethods.NGX_AGAIN)
        {
            // Need more I/O - will be called again when epoll signals ready
            return false;
        }
        else
        {
            int sslError = NativeMethods.ngx_connection_get_ssl_error(_nativeHandle);
            CompleteWrite(0, new InvalidOperationException($"SSL write failed: {sslError}"));
            return true;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        // Cancel any pending operations
        _pendingHandshake?.TrySetCanceled();
        _pendingRead?.TrySetCanceled();
        _pendingWrite?.TrySetCanceled();

        // Remove from worker
        _worker.RemoveConnection(this);

        // Free native resources
        NativeMethods.ngx_connection_free(_nativeHandle);
    }
}

internal enum OperationType
{
    Handshake,
    Read,
    Write
}
