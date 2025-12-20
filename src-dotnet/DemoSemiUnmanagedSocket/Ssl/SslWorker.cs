using DemoSemiUnmanagedSocket.Interop;
using DemoSemiUnmanagedSocket.Ssl.Requests;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;

namespace DemoSemiUnmanagedSocket.Ssl;

/// <summary>
/// A single SSL worker thread.
/// 
/// Runs a synchronous loop:
/// 1. Check for new connection requests from shared queue
/// 2. Call epoll_wait to get ready sockets
/// 3. Call ssl_do_handshake on ready sockets
/// 4. Complete finished handshakes
/// </summary>
internal sealed class SslWorker
{
    private readonly int _workerId;
    private readonly SslContext _sslContext;
    private readonly int _epollFd;
    private readonly Thread _thread;
    private readonly ConcurrentQueue<HandshakeRequest> _sharedQueue; // Shared with other workers
    private readonly Dictionary<int, HandshakeRequest> _activeConnections = new(); // fd -> request (local to this worker)
    private volatile bool _running;

    // Stats
    private long _completed;
    private long _failed;

    public SslWorker(int workerId, SslContext sslContext, ConcurrentQueue<HandshakeRequest> sharedQueue)
    {
        _workerId = workerId;
        _sslContext = sslContext;
        _sharedQueue = sharedQueue;

        // Create epoll instance for this worker
        _epollFd = NativeSsl.create_epoll();
        if (_epollFd < 0)
        {
            throw new InvalidOperationException($"Failed to create epoll for worker {workerId}");
        }

        _thread = new Thread(WorkerLoop)
        {
            Name = $"SslWorker-{workerId}",
            IsBackground = true
        };
    }

    public void Start()
    {
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

    /// <summary>
    /// Main worker loop - runs synchronously on dedicated thread.
    /// </summary>
    private void WorkerLoop()
    {
        Console.WriteLine($"[Worker {_workerId}] Started, epoll_fd={_epollFd}");

        while (_running)
        {
            // 1. Try to pick up new requests from shared queue
            ProcessNewRequests();

            // 2. If no active connections, just wait a bit and check again
            if (_activeConnections.Count == 0)
            {
                Thread.Sleep(1); // Avoid busy spin
                continue;
            }

            // 3. Wait for socket events (short timeout to check for new requests)
            int readyFd = NativeSsl.epoll_wait_one(_epollFd, 10);
            if (readyFd > 0)
            {
                // 4. Handle the ready socket
                ProcessReadySocket(readyFd);
            }
        }

        // Cleanup remaining connections
        foreach (var kvp in _activeConnections)
        {
            var request = kvp.Value;
            if (request.Ssl != IntPtr.Zero)
            {
                NativeSsl.ssl_connection_destroy(request.Ssl);
            }
            request.Completion.TrySetResult(HandshakeResult.Failed);
        }
        _activeConnections.Clear();

        Console.WriteLine($"[Worker {_workerId}] Stopped");
    }

    /// <summary>
    /// Process new handshake requests from the shared queue.
    /// Each worker competes to dequeue - natural load balancing.
    /// </summary>
    private void ProcessNewRequests()
    {
        // Try to grab one or more requests from shared queue
        while (_sharedQueue.TryDequeue(out var request))
        {
            // Create SSL connection and register with our epoll
            IntPtr ssl = NativeSsl.ssl_connection_create(
                _sslContext.Handle,
                request.ClientFd,
                _epollFd);

            if (ssl == IntPtr.Zero)
            {
                Interlocked.Increment(ref _failed);
                request.Completion.TrySetResult(HandshakeResult.Failed);
                continue;
            }

            request.Ssl = ssl;
            request.WorkerId = _workerId; // Track which worker owns this
            _activeConnections[request.ClientFd] = request;

            // Try handshake immediately (might complete in one call for resumed sessions)
            TryAdvanceHandshake(request);
        }
    }

    /// <summary>
    /// Process a socket that epoll reported as ready.
    /// </summary>
    private void ProcessReadySocket(int fd)
    {
        if (!_activeConnections.TryGetValue(fd, out var request))
        {
            // Unknown fd - shouldn't happen, but remove from epoll
            NativeSsl.epoll_wait_one(_epollFd, 0); // Clear it
            return;
        }

        TryAdvanceHandshake(request);
    }

    /// <summary>
    /// Try to advance the TLS handshake for a connection.
    /// </summary>
    private unsafe void TryAdvanceHandshake(HandshakeRequest request)
    {
        int status = NativeSsl.ssl_try_handshake(request.Ssl, request.ClientFd, _epollFd);

        switch (status)
        {
            case NativeSsl.HANDSHAKE_COMPLETE:
                // Success! Send HTTP response immediately on this worker thread
                SendHttpResponse(request.Ssl);

                // Cleanup SSL and remove from active
                _activeConnections.Remove(request.ClientFd);
                NativeSsl.ssl_connection_destroy(request.Ssl);
                request.Ssl = IntPtr.Zero;

                Interlocked.Increment(ref _completed);
                request.Completion.TrySetResult(HandshakeResult.Success);
                break;

            case NativeSsl.HANDSHAKE_WANT_READ:
            case NativeSsl.HANDSHAKE_WANT_WRITE:
                // Need more I/O - epoll is already updated by ssl_try_handshake
                // Just wait for next epoll_wait to return this fd
                break;

            case NativeSsl.HANDSHAKE_ERROR:
            default:
                // Failed - cleanup and complete with error
                _activeConnections.Remove(request.ClientFd);
                NativeSsl.ssl_connection_destroy(request.Ssl);
                request.Ssl = IntPtr.Zero;
                Interlocked.Increment(ref _failed);
                request.Completion.TrySetResult(HandshakeResult.Failed);
                break;
        }
    }

    /// <summary>
    /// Send HTTP response through SSL connection.
    /// </summary>
    private static unsafe void SendHttpResponse(IntPtr ssl)
    {
        ReadOnlySpan<byte> response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"u8;
        fixed (byte* ptr = response)
        {
            int written = NativeSsl.ssl_write(ssl, ptr, response.Length);
            // Note: In production, should handle partial writes and errors
            // written == -1 means WANT_WRITE (would block)
            // written == -2 means error
        }
    }
}