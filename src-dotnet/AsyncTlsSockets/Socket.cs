using System.Runtime.InteropServices;

namespace AsyncTlsSockets;

internal static partial class Libc
{
    // TCP socket options
    public const int IPPROTO_TCP = 6;
    public const int TCP_NODELAY = 1;      // Disable Nagle's algorithm - send small packets immediately
    public const int TCP_QUICKACK = 12;    // Disable delayed ACKs
    public const int TCP_DEFER_ACCEPT = 9; // Don't accept until client sends data (e.g., ClientHello)

    // Busy polling (trades CPU for latency)
    public const int SO_BUSY_POLL = 46;

    [LibraryImport("libc")]
    public static partial int socket(int domain, int type, int protocol);

    [LibraryImport("libc")]
    public static unsafe partial int setsockopt(int fd, int level, int optname, void* optval, int optlen);

    [LibraryImport("libc")]
    public static partial int bind(int fd, ref SockAddrIn addr, int addrlen);

    [LibraryImport("libc")]
    public static partial int listen(int fd, int backlog);

    [LibraryImport("libc")]
    public static partial int fcntl(int fd, int cmd, int arg);
}
