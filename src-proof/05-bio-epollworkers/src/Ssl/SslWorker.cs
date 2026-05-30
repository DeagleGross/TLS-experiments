using BioEpollWorkers.Interop;
using BioEpollWorkers.Ssl.Requests;
using System;
using System.Collections.Generic;
using System.Text;

namespace BioEpollWorkers.Ssl;

/// <summary>
/// A single SSL worker thread (nginx-style).
///
/// Identical to experiment 04's <c>SslWorker</c>. The only thing that
/// changes between 04 and 05 is which native library backs <c>NativeSsl</c>.
/// </summary>
internal sealed class SslWorker
{
    private const int MaxBatchEvents = 64;
    private const int EpollTimeoutMs = 100;

    private readonly int _workerId;
    private readonly SslContext _sslContext;
    private readonly int _epollFd;
    private readonly Thread _thread;
    private readonly Dictionary<int, ActiveConnection> _activeConnections = new();
    private int _listenFd = -1;
    private volatile bool _running;

    private long _completed;
    private long _failed;
    private long _accepted;

    private struct ActiveConnection
    {
        public IntPtr Ssl;
        public int ClientFd;
    }

    public SslWorker(int workerId, SslContext sslContext)
    {
        _workerId = workerId;
        _sslContext = sslContext;

        _epollFd = NativeSsl.create_epoll();
        if (_epollFd < 0)
        {
            throw new InvalidOperationException($"Failed to create epoll for worker {workerId}");
        }

        _thread = new Thread(WorkerLoop)
        {
            Name = $"SslWorker-{_workerId}",
            IsBackground = true
        };
    }

    public void Start(int listenFd)
    {
        _listenFd = listenFd;

        int result = NativeSsl.epoll_add_listen_fd(_epollFd, listenFd);
        if (result < 0)
        {
            throw new InvalidOperationException($"Failed to add listen_fd to epoll for worker {_workerId}");
        }

        _running = true;
        _thread.Start();
    }

    public void Stop()
    {
        _running = false;
        _thread.Join(timeout: TimeSpan.FromSeconds(2));
        NativeSsl.close_epoll(_epollFd);
    }

    public (long completed, long failed, long pending) GetStats()
    {
        return (
            Interlocked.Read(ref _completed),
            Interlocked.Read(ref _failed),
            _activeConnections.Count
        );
    }

    private unsafe void WorkerLoop()
    {
        Console.WriteLine($"[Worker {_workerId}] Started, epoll_fd={_epollFd}, listen_fd={_listenFd}");

        int* readyFds = stackalloc int[MaxBatchEvents];

        while (_running)
        {
            int timeout = _activeConnections.Count == 0 ? EpollTimeoutMs : 10;

            int numReady = NativeSsl.epoll_wait_batch(_epollFd, timeout, readyFds, MaxBatchEvents);

            for (int i = 0; i < numReady; i++)
            {
                int fd = readyFds[i];

                if (fd == _listenFd)
                {
                    AcceptConnections();
                }
                else
                {
                    ProcessReadySocket(fd);
                }
            }
        }

        foreach (var kvp in _activeConnections)
        {
            var conn = kvp.Value;
            if (conn.Ssl != IntPtr.Zero)
            {
                NativeSsl.ssl_connection_destroy(conn.Ssl);
            }
            Close(conn.ClientFd);
        }
        _activeConnections.Clear();

        Console.WriteLine($"[Worker {_workerId}] Stopped. Accepted: {_accepted}, Completed: {_completed}, Failed: {_failed}");
    }

    private void AcceptConnections()
    {
        while (true)
        {
            int clientFd = NativeSsl.accept_nonblocking(_listenFd);

            if (clientFd == -1)
            {
                break;
            }

            if (clientFd == -2)
            {
                continue;
            }

            Interlocked.Increment(ref _accepted);

            IntPtr ssl = NativeSsl.ssl_connection_create(
                _sslContext.Handle,
                clientFd,
                _epollFd);

            if (ssl == IntPtr.Zero)
            {
                Interlocked.Increment(ref _failed);
                Close(clientFd);
                continue;
            }

            _activeConnections[clientFd] = new ActiveConnection
            {
                Ssl = ssl,
                ClientFd = clientFd
            };

            TryAdvanceHandshake(clientFd, ssl);
        }
    }

    private void ProcessReadySocket(int fd)
    {
        if (!_activeConnections.TryGetValue(fd, out var conn))
        {
            return;
        }

        TryAdvanceHandshake(fd, conn.Ssl);
    }

    private unsafe void TryAdvanceHandshake(int clientFd, IntPtr ssl)
    {
        int status = NativeSsl.ssl_try_handshake(ssl, clientFd, _epollFd);

        switch (status)
        {
            case NativeSsl.HANDSHAKE_COMPLETE:
                SendHttpResponse(ssl);

                _activeConnections.Remove(clientFd);
                NativeSsl.ssl_connection_destroy(ssl);
                Close(clientFd);

                Interlocked.Increment(ref _completed);
                break;

            case NativeSsl.HANDSHAKE_WANT_READ:
            case NativeSsl.HANDSHAKE_WANT_WRITE:
                break;

            case NativeSsl.HANDSHAKE_ERROR:
            default:
                _activeConnections.Remove(clientFd);
                NativeSsl.ssl_connection_destroy(ssl);
                Close(clientFd);
                Interlocked.Increment(ref _failed);
                break;
        }
    }

    private static unsafe void SendHttpResponse(IntPtr ssl)
    {
        ReadOnlySpan<byte> response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"u8;
        fixed (byte* ptr = response)
        {
            int written = NativeSsl.ssl_write(ssl, ptr, response.Length);
        }
    }

    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    private static void Close(int fd)
    {
        if (fd >= 0)
        {
            close(fd);
        }
    }
}
