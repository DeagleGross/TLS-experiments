using System.Runtime.InteropServices;

namespace DirectFdSsl.Interop;

/// <summary>
/// Linux epoll P/Invoke for efficient socket polling.
/// </summary>
public static class Epoll
{
    private const string LibC = "libc";

    // On x86_64 Linux, epoll_event is:
    // struct epoll_event {
    //     uint32_t events;      // 4 bytes
    //     epoll_data_t data;    // 8 bytes (union, aligned)
    // } __attribute__((packed));
    // Total: 12 bytes, but data starts at offset 4
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct epoll_event
    {
        public uint events;      // 4 bytes at offset 0
        public long data;        // 8 bytes at offset 4 (can hold fd or ptr)
    }

    [DllImport(LibC, SetLastError = true)]
    public static extern int epoll_create1(int flags);

    [DllImport(LibC, SetLastError = true)]
    public static extern int epoll_ctl(int epfd, int op, int fd, ref epoll_event ev);

    [DllImport(LibC, SetLastError = true)]
    public static extern int epoll_wait(int epfd, [Out] epoll_event[] events, int maxevents, int timeout);

    [DllImport(LibC, SetLastError = true)]
    public static extern int close(int fd);

    // epoll_ctl operations
    public const int EPOLL_CTL_ADD = 1;
    public const int EPOLL_CTL_DEL = 2;
    public const int EPOLL_CTL_MOD = 3;

    // epoll events
    public const uint EPOLLIN = 0x001;
    public const uint EPOLLOUT = 0x004;
    public const uint EPOLLERR = 0x008;
    public const uint EPOLLHUP = 0x010;
    public const uint EPOLLRDHUP = 0x2000;
    public const uint EPOLLET = 1u << 31;  // Edge-triggered
}

/// <summary>
/// Socket-related syscalls for non-blocking mode.
/// </summary>
public static class Socket
{
    private const string LibC = "libc";

    [DllImport(LibC, SetLastError = true)]
    public static extern int fcntl(int fd, int cmd, int arg);

    public const int F_GETFL = 3;
    public const int F_SETFL = 4;
    public const int O_NONBLOCK = 2048;

    public static int SetNonBlocking(int fd)
    {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) return -1;
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}
