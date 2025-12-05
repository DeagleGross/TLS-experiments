using DemoSemiUnmanagedSocket.Interop;

namespace DemoSemiUnmanagedSocket.Ssl;

/// <summary>
/// Manages an epoll instance for async I/O operations.
/// 
/// In the async-mt C server, each worker thread has its own epoll.
/// Similarly, in C# you might have:
/// - One EpollContext per worker thread
/// - Or one shared EpollContext for simple scenarios
/// 
/// The epoll instance is used by AsyncSslConnection to wait for
/// socket readiness during the TLS handshake.
/// </summary>
internal sealed class EpollContext : IDisposable
{
    private readonly int _epollFd;
    private bool _disposed;

    /// <summary>
    /// Get the epoll file descriptor.
    /// </summary>
    public int Handle => _epollFd;

    /// <summary>
    /// Create a new epoll context.
    /// </summary>
    public EpollContext()
    {
        _epollFd = NativeSsl.create_epoll();
        
        if (_epollFd < 0)
        {
            throw new InvalidOperationException("Failed to create epoll instance");
        }
    }

    /// <summary>
    /// Wait for an event on any registered socket.
    /// 
    /// This blocks until a socket is ready or timeout occurs.
    /// Use with Task.Run() for async waiting:
    /// 
    /// <code>
    /// int readyFd = await Task.Run(() => epoll.WaitOne(5000));
    /// </code>
    /// </summary>
    /// <param name="timeoutMs">Timeout in milliseconds (-1 for infinite)</param>
    /// <returns>Ready socket FD, 0 on timeout, -1 on error</returns>
    public int WaitOne(int timeoutMs = -1)
    {
        return NativeSsl.epoll_wait_one(_epollFd, timeoutMs);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_epollFd >= 0)
            {
                NativeSsl.close_epoll(_epollFd);
            }
            _disposed = true;
        }
    }
}
