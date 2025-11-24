# TLS Experiments

This repo is dedicated to TLS experiments to understand the best potential way to work with it on UNIX systems;
The goal is to determine why nginx is the best server to perform TLS handshakes performantly, compared to Kestrel for example.

## C apps runs

In [src](./src/) you can find different C server apps which simulate different architectures and showcase different usage of TLS handshake.
Here is a brief comparison + results i get on my WSL:

1) [Single-Threaded Async](./src/tls_handshake_server.c)

It uses a single CPU core, and can't do parallel SSL operations.

On benchmark with wrk got these results:
```
Duration: 10s, Threads: 64, Connections: 500
Requests/sec:   1823.33
```

```
┌─────────────────────────────────────┐
│  Main Thread (single thread)        │
│                                     │
│  while (running) {                  │
│    epoll_wait() ← SLEEPS HERE       │
│    for each ready socket:           │
│      if (listen_fd):                │
│        accept() + SSL_new()         │
│        epoll_ctl(ADD)               │
│      else:                          │
│        SSL_do_handshake()           │
│        if (WANT_READ/WRITE):        │
│          epoll_ctl(MOD) ← change    │
│                           what we   │
│                           watch for │
│  }                                  │
└─────────────────────────────────────┘
```

2) [Multi-Threaded Sync (thread per `accept()`)](./src/tls_handshake_server_sync.c)

This one is closer to .NET implementation, because Kestrel does the following:
```csharp
await using var sslStream = new SslStream(networkStream);
await sslStream.AuthenticateAsServerAsync(serverOptions);
```
and under the hood `SslStream` is calling [`Ssl.SslDoHandshake()`](https://github.com/dotnet/runtime/blob/0fe3eb128bc11a78d9685075d2a787dd2740fc2d/src/libraries/Common/src/Interop/Unix/System.Security.Cryptography.Native/Interop.OpenSsl.cs#L689) which is interop and it **blocks** thread here waiting for the whole SSL handshake to be performed.

On benchmark with wrk got these results:
```
Duration: 10s, Threads: 64, Connections: 500
Requests/sec:   4688.96
```

```
┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│ Main Thread      │       │ Worker Thread 1  │       │ Worker Thread 2  │
│                  │       │                  │       │                  │
│ while (running): │───┬──>│ SSL_do_handshake │       │ SSL_do_handshake │
│   accept()       │   │   │       ↓          │       │       ↓          │
│   pthread_create─┼───┤   │    BLOCKS HERE   │       │    BLOCKS HERE   │
│                  │   │   │       ↓          │       │       ↓          │
└──────────────────┘   │   │ Send response    │       │ Send response    │
                       │   │ close()          │       │ close()          │
                       │   │ thread exits     │       │ thread exits     │
                       │   └──────────────────┘       └──────────────────┘
                       │
                       └──>│ Worker Thread 3  │  ... up to 1000 threads
                           │ SSL_do_handshake │
                           │    BLOCKS HERE   │
                           └──────────────────┘
```

3) [Thread Pool with Producer-Consumer Queue](./src/tls_handshake_server_sync_pool.c)

This is an attempt to scale sync version somehow, but it failed.
Mostly because every operation is locked on the queue, and multiple blocks are encountered along a single attempt to work with the queue

On benchmark with wrk got these results:
```
Duration: 10s, Threads: 64, Connections: 500
Requests/sec:   383.56
```

```
┌─────────────────┐         ┌──────────────────────┐
│  Main Thread    │         │  Shared Queue        │
│  (Producer)     │         │  (MUTEX PROTECTED)   │
│                 │         │                      │
│ while (running):│         │  [fd1] [fd2] [fd3]   │
│   accept()  ────┼────────>│         ↓            │
│   queue_push()  │  LOCK   │    Queue Size: 1000  │
│                 │  MUTEX  │         ↓            │
└─────────────────┘         └──────────────────────┘
                                      ↓
                            ┌─────────┴──────────┬─────────────┬─────────────┐
                            ↓                    ↓             ↓             ↓
                     ┌─────────────┐      ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
                     │ Worker 0    │      │ Worker 1    │  │ Worker 2    │  │ Worker 3    │
                     │ (Consumer)  │      │ (Consumer)  │  │ (Consumer)  │  │ (Consumer)  │
                     │             │      │             │  │             │  │             │
                     │ queue_pop() │      │ queue_pop() │  │ queue_pop() │  │ queue_pop() │
                     │   ↓ LOCK    │      │   ↓ LOCK    │  │   ↓ LOCK    │  │   ↓ LOCK    │
                     │   ↓ MUTEX   │      │   ↓ MUTEX   │  │   ↓ MUTEX   │  │   ↓ MUTEX   │
                     │ SSL_do_     │      │ SSL_do_     │  │ SSL_do_     │  │ SSL_do_     │
                     │ handshake() │      │ handshake() │  │ handshake() │  │ handshake() │
                     │   BLOCKS    │      │   BLOCKS    │  │   BLOCKS    │  │   BLOCKS    │
                     └─────────────┘      └─────────────┘  └─────────────┘  └─────────────┘
```

4) [Multi-Threaded Async (nginx-style)](/src/tls_handshake_server_async_mt.c)

This is a winner based on the RPS:
```
Duration: 10s, Threads: 64, Connections: 500
Requests/sec:  6506.50
```

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Listen Socket (8443)                          │
│                     SO_REUSEPORT enabled                             │
│     Kernel distributes incoming connections across workers           │
└────────┬────────────┬────────────┬────────────┬─────────────────────┘
         │            │            │            │
         ↓            ↓            ↓            ↓
  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
  │  Worker 0   │ │  Worker 1   │ │  Worker 2   │ │  Worker 3   │
  │             │ │             │ │             │ │             │
  │ epoll_fd=5  │ │ epoll_fd=6  │ │ epoll_fd=7  │ │ epoll_fd=8  │
  │             │ │             │ │             │ │             │
  │ while(1):   │ │ while(1):   │ │ while(1):   │ │ while(1):   │
  │   epoll_    │ │   epoll_    │ │   epoll_    │ │   epoll_    │
  │   wait()    │ │   wait()    │ │   wait()    │ │   wait()    │
  │   ↓ SLEEP   │ │   ↓ SLEEP   │ │   ↓ SLEEP   │ │   ↓ SLEEP   │
  │   ↓ (0%CPU) │ │   ↓ (0%CPU) │ │   ↓ (0%CPU) │ │   ↓ (0%CPU) │
  │   ↓         │ │   ↓         │ │   ↓         │ │   ↓         │
  │   accept()  │ │   accept()  │ │   accept()  │ │   accept()  │
  │   SSL_do_   │ │   SSL_do_   │ │   SSL_do_   │ │   SSL_do_   │
  │   handshake │ │   handshake │ │   handshake │ │   handshake │
  │             │ │             │ │             │ │             │
  │ Handles:    │ │ Handles:    │ │ Handles:    │ │ Handles:    │
  │ 125 conns   │ │ 125 conns   │ │ 125 conns   │ │ 125 conns   │
  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
```