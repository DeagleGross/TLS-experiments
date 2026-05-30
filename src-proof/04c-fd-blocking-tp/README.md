# 04c — `SSL_set_fd` + BLOCKING socket + `Task.Run` (ThreadPool dispatch)

> **Pair-difference target:** experiment 04 (`SSL_set_fd` + epoll workers) ⇄ 04c (`SSL_set_fd` + blocking socket + ThreadPool).
>
> Isolates **the value of the epoll dispatcher on the `SSL_set_fd` data path**.

## Why this experiment exists

The existing matrix could not answer that directly because **every** SSL_set_fd row in the matrix uses epoll. 04c is the missing baseline: same TLS data path as 04 (OpenSSL bound to the raw socket fd via `SSL_set_fd`), but the IO is driven by **blocking syscalls** on the calling thread instead of an epoll-based readiness state machine.

If 04c ≈ 04, epoll buys little/nothing on top of `SSL_set_fd`. If 04c << 04, epoll is essential. Either result lets us answer the reviewer with data instead of opinion.

## What's different vs experiment 04

| Dimension | 04 (`SSL_set_fd` + epoll workers) | 04c (`SSL_set_fd` + blocking + ThreadPool) |
|---|---|---|
| Accept | `accept4(SOCK_NONBLOCK)` on a per-worker epoll set (4 workers + `EPOLLEXCLUSIVE`) | Blocking `Socket.Accept()` on a single dedicated thread (the Main thread) |
| Handshake socket mode | non-blocking | **blocking** |
| Handshake state machine | `SSL_do_handshake` returning `SSL_ERROR_WANT_READ` / `WANT_WRITE`, rearmed via epoll | **Single `SSL_do_handshake` call** — OpenSSL issues `read()`/`write()` itself; the calling thread is parked in the kernel between handshake messages |
| Dispatch | 4 dedicated OS threads, each holding its own epoll set | **.NET `ThreadPool`** via `Task.Run` (one ThreadPool work item per accepted connection) |
| epoll syscalls per connection | yes (register + readiness events + unregister) | **zero** |

Everything else is the same as 04:

- TLS layer: `SSL_set_fd` binds OpenSSL to the raw socket fd (no mem-BIO copies)
- `SslContext` configuration: `TLS_server_method()` default (matches 04 byte-for-byte — TLS 1.3 negotiated in practice, default session cache mode, default cipher list)
- Response body: `"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"` (52 bytes plaintext)
- `SSL_shutdown` is called before `SSL_free` (matching 04, not 01b which drops it)
- Cert: ECDSA P-384 (`certs/server-p384.{crt,key}`)
- `cpuset: 0-3`, `mem_limit: 2g`, `nofile: 65535`
- wrk client: `-t64 -c500 -d10s --latency` with `Connection: close`

## Why a single accept thread (not `AcceptAsync`)

`Socket.AcceptAsync` uses .NET's `SocketAsyncEngine`, which is itself epoll-backed on Linux. Using it here would smuggle epoll back into the experiment via the accept path and muddy the comparison. 04c does a hard blocking `Socket.Accept()` on a dedicated thread so the entire server has **zero `epoll_*` syscalls** anywhere — accept, handshake, or shutdown.

## Why `ThreadPool.SetMinThreads(256, 256)`

The .NET ThreadPool grows by ~1 thread/sec after exhausting `Environment.ProcessorCount` (4 in our `cpuset 0-3`). Each blocking `SSL_do_handshake` parks a ThreadPool thread for the entire handshake (~5–10ms on loopback p384). With wrk `-c500` the pool would starve for the entire 10s bench window and the measured RPS would just be "how fast does .NET hill-climb?", not "what does the dispatch model cost?".

Pre-sizing to 256 worker / 256 IO removes that confounder. The 04 vs 04c delta is then attributable to the dispatch model (ThreadPool overhead, syscall pattern, scheduler decisions), not to thread-injection latency.

If you want to see what unprepared blocking-on-ThreadPool looks like, set `MIN_THREADS=4` in `compose.yml` and re-run.

## What this experiment does **not** answer

- It does not isolate "the epoll syscall itself" — it isolates the larger "epoll-driven nonblocking state machine + dedicated worker threads" model vs "blocking syscalls + .NET ThreadPool". See sibling experiment **04d** (`fd-blocking-workers`) for the comparison that holds the thread model constant (fixed OS-thread pool, just no epoll).
- It does not answer "should production Kestrel use this shape" — blocking-thread-per-connection is famously a poor fit for high-concurrency servers. The question this experiment answers is the narrow one the reviewer asked.

## Result

Run:

```bash
docker compose -f src-proof/04c-fd-blocking-tp/compose.yml up --build -d
src-proof/bench/bench-one.sh 5011 csharp-tls-server-fd-blocking-tp "04c-fd-blocking-tp"
docker compose -f src-proof/04c-fd-blocking-tp/compose.yml down
```

| Label | RPS | mean CPU% | RPS/core | latency avg | latency p99 |
|---|---:|---:|---:|---:|---:|
| 04 (epoll workers)       | 6755.59 | 274.75 | 2458.81 | 24.81ms | 112.19ms |
| **04c (blocking + TP)**  | 6182.24 | 292.59 | 2112.94 |  6.66ms |  73.63ms |
| **Δ (04c vs 04)**        | −8.5%   | +6.5%  | −14.1%  | −73%    | −34%     |

**Verdict — does epoll help on the `SSL_set_fd` path?**

Yes, but only on **per-core CPU efficiency** — about **+14% RPS/core** in epoll's favor, even with the ThreadPool pre-tuned to remove hill-climbing. The blocking + ThreadPool dispatch costs ~6.5% more CPU to do ~8.5% less work per second.

Two caveats before reading the +14% as the final answer:

1. **04c also pays a `Task.Run` cost** on every accepted connection (allocation + global-queue enqueue + ThreadPool wake-up). Sibling experiment **04d** strips that out (fixed OS-thread worker pool, no ThreadPool) and is the cleaner pair-difference for "epoll alone".
2. **Latency is much lower on 04c** (p99 73ms vs 112ms; avg 6.7ms vs 24.8ms). The epoll path bounces through `SSL_ERROR_WANT_READ` → epoll re-arm → dispatch → resume on every handshake message, and that bouncing shows up as tail latency. The blocking path just parks the thread in `read()` and gets woken by the kernel on the next byte — fewer context-switches per handshake.

So the headline you take away depends on what you optimize for: **epoll wins on throughput-per-core**, **blocking wins on per-request latency** and on absolute RPS-per-thread when threads are cheap (the next experiment, 04d).
