# CSharp servers

These apps are trying to come up with the best TLS performance for the server written in CSharp.

## 1) [AsyncTlsSockets](./AsyncTlsSockets/)

**Familiar async/await API with high performance**

This implementation provides a developer-friendly async API while using OpenSSL's BIO (non-blocking I/O) under the hood. The architecture uses dedicated worker threads with epoll for TLS handshakes, but exposes a clean async interface to the caller.

**Key features:**
- Familiar async/await pattern: `await controller.AcceptAsync()`, `await connection.ReadAsync()`, `await connection.WriteAsync()`
- Workers handle TLS handshakes on dedicated threads with epoll
- Connection objects are returned to caller for easy request/response handling
- Good balance between performance and API ergonomics

```csharp
// Usage example
var controller = new WorkerController(port, certPath, keyPath, workerCount);
controller.StartWorkers();

while (!cts.IsCancellationRequested)
{
    var connection = await controller.AcceptAsync(cts.Token);
    
    _ = Task.Run(async () => {
        var buffer = new byte[4096];
        var bytesRead = await connection.ReadAsync(buffer);
        await connection.WriteAsync(response);
        connection.Dispose();
    });
}
```

```
┌─────────────────┐       ┌────────────────────────────────────────────────┐
│  Main Thread    │       │  Worker Pool (N threads)                       │
│  (async/await)  │       │                                                │
│                 │       │  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│ AcceptAsync()───┼──────>│  │ Worker 1 │  │ Worker 2 │  │ Worker N │     │
│   awaits...     │       │  │ epoll +  │  │ epoll +  │  │ epoll +  │     │
│      ↓          │       │  │ OpenSSL  │  │ OpenSSL  │  │ OpenSSL  │     │
│ connection ←────┼───────│  │ BIO I/O  │  │ BIO I/O  │  │ BIO I/O  │     │
│      ↓          │       │  └──────────┘  └──────────┘  └──────────┘     │
│ ReadAsync()     │       └────────────────────────────────────────────────┘
│ WriteAsync()    │
│ Dispose()       │
└─────────────────┘
```

## 2) [DemoSemiUnmanagedSocket](./DemoSemiUnmanagedSocket/)

**Maximum performance, nginx-style architecture**

This implementation prioritizes raw performance over API convenience. It uses an nginx-style architecture where workers directly accept connections and perform TLS handshakes in their epoll loops, eliminating cross-thread handoff overhead.

**Key features:**
- Workers add listen socket to their epoll with `EPOLLEXCLUSIVE`
- Workers accept connections directly (no producer-consumer queue)
- Lower-level API - does NOT follow async/await patterns
- Minimal overhead, closest to C performance

**Trade-off:** Less ergonomic API, but ~18% better performance under light load due to eliminated accept overhead.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Worker Pool - Each worker has listen_fd in its epoll (EPOLLEXCLUSIVE)  │
│                                                                         │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐      │
│  │ Worker Thread 1  │  │ Worker Thread 2  │  │ Worker Thread N  │      │
│  │                  │  │                  │  │                  │      │
│  │ epoll_wait()     │  │ epoll_wait()     │  │ epoll_wait()     │      │
│  │   ↓              │  │   ↓              │  │   ↓              │      │
│  │ if listen_fd:    │  │ if listen_fd:    │  │ if listen_fd:    │      │
│  │   accept()       │  │   accept()       │  │   accept()       │      │
│  │   SSL_new()      │  │   SSL_new()      │  │   SSL_new()      │      │
│  │   BIO handshake  │  │   BIO handshake  │  │   BIO handshake  │      │
│  │ else:            │  │ else:            │  │ else:            │      │
│  │   continue TLS   │  │   continue TLS   │  │   continue TLS   │      │
│  │   read/write     │  │   read/write     │  │   read/write     │      │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘      │
│                                                                         │
│  No cross-thread handoff! Workers accept directly from listen socket.   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Comparison

| Feature | AsyncTlsSockets | DemoSemiUnmanagedSocket |
|---------|-----------------|-------------------------|
| API Style | `async/await` ✅ | Low-level callbacks |
| `connection.ReadAsync()` | ✅ | ❌ |
| `connection.WriteAsync()` | ✅ | ❌ |
| `controller.AcceptAsync()` | ✅ | ❌ |
| Accept overhead | Some (cross-thread) | Minimal (direct) |
| Performance | High | Highest |
