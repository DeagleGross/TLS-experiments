using System.Runtime.InteropServices;

namespace AsyncTlsSockets;

internal static partial class Libc
{
    public const int SOL_SOCKET = 1;
    public const int SO_REUSEPORT = 15;
    public const int AF_INET = 2;
    public const int SOCK_STREAM = 1;
    public const int F_GETFL = 3;
    public const int F_SETFL = 4;
    public const int SOCK_NONBLOCK = 0x800; // 0x800 is the value for SOCK_NONBLOCK on Linux x86_64

    [DllImport("libc", SetLastError = true)]
    public static extern int accept4(int sockfd, IntPtr addr, IntPtr addrlen, int flags);

    [DllImport("libc", SetLastError = true)]
    public static extern int close(int fd);
}

[StructLayout(LayoutKind.Sequential)]
public struct SockAddrIn
{
    public short sin_family;
    public ushort sin_port;
    public uint sin_addr;
    public long sin_zero;
}