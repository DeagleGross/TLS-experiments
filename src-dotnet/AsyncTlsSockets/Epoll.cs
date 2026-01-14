using System.Runtime.InteropServices;

namespace AsyncTlsSockets;

public enum EpollOp
{
    ADD = 1,
    DEL = 2,
    MOD = 3
}

[Flags]
public enum EpollEvents : uint
{
    EPOLLIN = 0x001,
    EPOLLOUT = 0x004,
    EPOLLERR = 0x008,
    EPOLLHUP = 0x010,
    EPOLLET = 1u << 31 // Edge-Triggered
}

[StructLayout(LayoutKind.Explicit)]
public struct EpollData
{
    [FieldOffset(0)] public IntPtr ptr;
    [FieldOffset(0)] public int fd;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct EpollEvent
{
    public uint events;
    public EpollData data;
}

internal static partial class Libc
{
    [DllImport("libc", EntryPoint = "epoll_create1")]
    public static extern int EpollCreate1(int flags);

    [DllImport("libc", EntryPoint = "epoll_ctl")]
    public static extern int EpollCtl(int epfd, int op, int fd, ref EpollEvent ev);

    [DllImport("libc", EntryPoint = "epoll_wait")]
    public static extern int EpollWait(int epfd, [Out] EpollEvent[] events, int maxevents, int timeout);

    [DllImport("libc", EntryPoint = "fcntl")]
    public static extern int Fcntl(int fd, int cmd, int arg);
}