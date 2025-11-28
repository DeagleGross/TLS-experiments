# PureUnmanagedSockets - Hybrid C/C# Architecture

**C handles TLS, C# handles HTTP** - Perfect separation of concerns!

## Architecture

```
??????????????????????????????????????????????????????????????
?  C Worker Threads (4 threads)                              ?
?  ?? epoll_wait() for socket events                         ?
?  ?? accept() new connections                               ?
?  ?? SSL_do_handshake() until complete                      ?
?  ?? SSL_read() request data                                ?
?  ?? enqueue_request(conn_id, data) ? LOCK-FREE QUEUE       ?
??????????????????????????????????????????????????????????????
                     ? Lock-free queue
                     ? eventfd notification
??????????????????????????????????????????????????????????????
?  C# Processor Threads (CPU count)                          ?
?  ?? await WaitForEventFdAsync() ? blocks until C notifies  ?
?  ?? dequeue_request() from queue                           ?
?  ?? Parse HTTP request (C#)                                ?
?  ?? Generate HTTP response (C#)                            ?
?  ?? enqueue_response(conn_id, data) ? LOCK-FREE QUEUE      ?
??????????????????????????????????????????????????????????????
                     ? Lock-free queue
                     ? eventfd notification
??????????????????????????????????????????????????????????????
?  C Worker Threads                                          ?
?  ?? epoll_wait() gets notification                         ?
?  ?? dequeue_response() from queue                          ?
?  ?? SSL_write() response data                              ?
?  ?? SSL_shutdown() + cleanup                               ?
??????????????????????????????????????????????????????????????
```

## What Each Layer Does

### C Layer (nginx_server.c)
**Responsibilities:**
- ? Socket operations (accept, epoll, non-blocking I/O)
- ? SSL/TLS (handshake, SSL_read, SSL_write)
- ? Lock-free request/response queues
- ? eventfd notifications

**Does NOT:**
- ? Parse HTTP
- ? Generate responses
- ? Call into C# (no callbacks!)

### C# Layer (Program.cs)
**Responsibilities:**
- ? Parse HTTP requests
- ? Generate HTTP responses
- ? Async processing (can use async/await, DB calls, etc.)
- ? Wait on eventfd for requests

**Does NOT:**
- ? Touch sockets
- ? Touch SSL/TLS
- ? Block C workers

## Lock-Free Communication

### Request Queue (C ? C#)
```c
// C enqueues request (NON-BLOCKING!)
enqueue_request(conn_id, request_data, length);
write(eventfd, 1); // Notify C#
```

```csharp
// C# waits for notification
await WaitForEventFdAsync(eventfd);

// C# dequeues requests
while (dequeue_request(out connId, out data, out length)) {
    _ = Task.Run(() => ProcessAsync(connId, data));
}
```

### Response Queue (C# ? C)
```csharp
// C# enqueues response (NON-BLOCKING!)
enqueue_response(connId, response_data, length);
```

```c
// C dequeues in epoll loop (NON-BLOCKING!)
while (dequeue_response(&conn_id, &data, &length)) {
    SSL_write(conn->ssl, data, length);
}
```

## Files

### Native C (src-dotnet/PureUnmanagedSockets/native/)

**nginx_server.c** - Complete TLS + queue implementation
- `init_queues()` - Creates lock-free request/response queues
- `enqueue_request()` - C?C# (called after SSL_read)
- `dequeue_response()` - C?C# (called before SSL_write)
- `worker_thread()` - nginx-style epoll event loop
- `handle_ssl_handshake()` - Pure SSL handshake
- `handle_ssl_read()` - SSL_read ? enqueue

**nginx_server.h** - Public API
- `start_nginx_server()` - Start C workers
- `get_request_notify_fd()` - Get eventfd for C#
- `dequeue_request()` - Called from C#
- `enqueue_response()` - Called from C#

### C# (src-dotnet/PureUnmanagedSockets/)

**Program.cs** - HTTP processing
- `RequestProcessorAsync()` - Waits on eventfd, processes requests
- `ProcessHttpRequestAsync()` - Parse HTTP, generate response
- `WaitForEventFdAsync()` - Async wait on eventfd

**Interop/OpenSslNative.cs** - P/Invoke definitions
- `get_request_notify_fd()`
- `dequeue_request()`
- `enqueue_response()`
- `start_nginx_server()`

## Performance Benefits

1. ? **No callbacks** - C never calls into C#, no thread blocking
2. ? **Lock-free queues** - Atomic operations, no mutexes on hot path
3. ? **eventfd notifications** - Kernel-level async wake-up
4. ? **C handles TLS** - All SSL operations in fast C code
5. ? **C# async processing** - Can use async/await, DB, etc.
6. ? **Parallel processing** - Multiple C# processors run in parallel

## Building

```bash
cd src-dotnet/PureUnmanagedSockets/native
make

cd ..
dotnet build
```

## Running

```bash
docker-compose up --build pureunmanagedsockets

# Benchmark
wrk -t12 -c400 -d30s https://localhost:5005
```

## Example Output

```
=== Hybrid C/C# SSL Server ===
C handles: accept, epoll, SSL handshake, SSL_read/write
C# handles: HTTP parsing, response generation
Communication: Lock-free queues + eventfd

Port: 5005
C Workers: 4
C# Processors: 16

[C# Processor 0] Started
[C# Processor 1] Started
...
[Worker 0] Started
[Worker 1] Started
...

[19:30:45] Connections: 1234 | Handshakes: 1234 | C# Requests/s: 456
```

## Comparison to Other Approaches

| Approach | TLS | HTTP | Communication |
|----------|-----|------|---------------|
| **Kestrel** | C# (SslStream) | C# | N/A |
| **nginx** | C (OpenSSL) | C (or proxy) | N/A |
| **PureUnmanagedSockets** | **C (OpenSSL)** | **C#** | **Lock-free queues** |

**Best of both worlds:**
- C's performance for TLS
- C#'s productivity for HTTP
- No callbacks, no blocking!


