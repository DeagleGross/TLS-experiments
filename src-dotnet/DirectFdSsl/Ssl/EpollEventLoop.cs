using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using DirectFdSsl.Interop;

namespace DirectFdSsl.Ssl;

/// <summary>
/// Epoll-based event loop that notifies when fds are ready.
/// This replaces .NET's async notification with direct epoll.
/// </summary>
public sealed class EpollEventLoop : IDisposable
{
    private readonly int _epollFd;
    private readonly Thread _pollThread;
    private readonly ConcurrentDictionary<int, TaskCompletionSource<uint>> _readWaiters = new();
    private readonly ConcurrentDictionary<int, TaskCompletionSource<uint>> _writeWaiters = new();
    private volatile bool _running = true;
    
    // Stats
    public long EpollWaitCalls;
    public long EventsProcessed;

    public EpollEventLoop()
    {
        _epollFd = Epoll.epoll_create1(0);
        if (_epollFd < 0)
            throw new Exception($"epoll_create1 failed: {_epollFd}");

        _pollThread = new Thread(EventLoop)
        {
            IsBackground = true,
            Name = "EpollEventLoop"
        };
        _pollThread.Start();
    }

    /// <summary>
    /// Register a file descriptor with epoll.
    /// </summary>
    public void Register(int fd, uint events = Epoll.EPOLLIN | Epoll.EPOLLOUT | Epoll.EPOLLET)
    {
        var ev = new Epoll.epoll_event
        {
            events = events,
            data = fd  // Store fd in data field
        };
        
        int result = Epoll.epoll_ctl(_epollFd, Epoll.EPOLL_CTL_ADD, fd, ref ev);
        if (result < 0)
            throw new Exception($"epoll_ctl ADD failed for fd {fd}, errno: {Marshal.GetLastWin32Error()}");
    }

    /// <summary>
    /// Unregister a file descriptor from epoll.
    /// </summary>
    public void Unregister(int fd)
    {
        var ev = new Epoll.epoll_event();
        Epoll.epoll_ctl(_epollFd, Epoll.EPOLL_CTL_DEL, fd, ref ev);
        _readWaiters.TryRemove(fd, out _);
        _writeWaiters.TryRemove(fd, out _);
    }

    /// <summary>
    /// Wait asynchronously for the fd to be readable.
    /// </summary>
    public Task WaitReadableAsync(int fd)
    {
        var tcs = new TaskCompletionSource<uint>(TaskCreationOptions.RunContinuationsAsynchronously);
        _readWaiters[fd] = tcs;
        return tcs.Task;
    }

    /// <summary>
    /// Wait asynchronously for the fd to be writable.
    /// </summary>
    public Task WaitWritableAsync(int fd)
    {
        var tcs = new TaskCompletionSource<uint>(TaskCreationOptions.RunContinuationsAsynchronously);
        _writeWaiters[fd] = tcs;
        return tcs.Task;
    }

    private void EventLoop()
    {
        var events = new Epoll.epoll_event[256];

        while (_running)
        {
            int nfds = Epoll.epoll_wait(_epollFd, events, events.Length, timeout: 10);
            Interlocked.Increment(ref EpollWaitCalls);

            if (nfds < 0)
            {
                // EINTR or error
                continue;
            }

            for (int i = 0; i < nfds; i++)
            {
                int fd = (int)events[i].data;  // Get fd from data field
                uint ev = events[i].events;
                
                Interlocked.Increment(ref EventsProcessed);

                // Complete read waiters
                if ((ev & (Epoll.EPOLLIN | Epoll.EPOLLERR | Epoll.EPOLLHUP)) != 0)
                {
                    if (_readWaiters.TryRemove(fd, out var readTcs))
                    {
                        readTcs.TrySetResult(ev);
                    }
                }

                // Complete write waiters
                if ((ev & (Epoll.EPOLLOUT | Epoll.EPOLLERR | Epoll.EPOLLHUP)) != 0)
                {
                    if (_writeWaiters.TryRemove(fd, out var writeTcs))
                    {
                        writeTcs.TrySetResult(ev);
                    }
                }
            }
        }
    }

    public void Dispose()
    {
        _running = false;
        _pollThread.Join(timeout: TimeSpan.FromSeconds(1));
        Epoll.close(_epollFd);
    }
}
