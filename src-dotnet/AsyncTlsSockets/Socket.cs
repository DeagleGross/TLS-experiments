using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace AsyncTlsSockets;

internal static partial class Libc
{
    [DllImport("libc")]
    public static extern int socket(int domain, int type, int protocol);

    [DllImport("libc")]
    public static extern unsafe int setsockopt(int fd, int level, int optname, void* optval, int optlen);

    [DllImport("libc")]
    public static extern int bind(int fd, ref SockAddrIn addr, int addrlen);

    [DllImport("libc")]
    public static extern int listen(int fd, int backlog);

    [DllImport("libc")]
    public static extern int fcntl(int fd, int cmd, int arg);
}
