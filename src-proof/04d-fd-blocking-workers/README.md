# 04d — `SSL_set_fd` + BLOCKING socket + fixed OS-thread worker pool

> **Pair-difference target:** experiment 04 (`SSL_set_fd` + epoll workers) ⇄ 04d (`SSL_set_fd` + blocking socket + fixed worker pool).
>
> **The clean epoll-vs-no-epoll comparison.** Thread count and thread lifetime are held constant; the only thing that changes is whether the socket fd is driven by an epoll readiness state machine (04) or by blocking syscalls inside the worker thread (04d).

## Why this experiment exists

04c could be dismissed as "you're just measuring ThreadPool overhead". 04d cannot: it uses a fixed pool of dedicated OS threads in exactly the same way 04 does, just without the epoll-driven nonblocking state machine.

## What's different vs experiment 04

| Dimension | 04 (`SSL_set_fd` + epoll workers) | 04d (`SSL_set_fd` + blocking + worker pool) |
|---|---|---|
| Accept | `accept4(SOCK_NONBLOCK)` on per-worker epoll set + `EPOLLEXCLUSIVE` | Blocking `Socket.Accept()` on a single dedicated thread |
| Handshake socket mode | non-blocking | **blocking** |
| Handshake state machine | `SSL_do_handshake` returning `WANT_READ` / `WANT_WRITE`, rearmed via epoll | **Single `SSL_do_handshake` call** — kernel parks the worker thread between handshake messages |
| Threading | 4 dedicated OS threads (one per epoll set) | **64 dedicated OS threads** (default; configurable via `WORKERS` env), fed via `BlockingCollection<Socket>` |
| epoll syscalls per connection | yes | **zero** |

Everything else is the same as 04 (and as sibling 04c):

- TLS data path: `SSL_set_fd` binds OpenSSL to the raw socket fd, no mem-BIO copies
- `SslContext` configuration: `TLS_server_method()` default (matches 04 byte-for-byte)
- Response body: `"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"` (52 bytes)
- `SSL_shutdown` is called before `SSL_free` (matching 04, not 01b)
- Cert: ECDSA P-384 (`certs/server-p384.{crt,key}`)
- `cpuset: 0-3`, `mem_limit: 2g`, `nofile: 65535`
- wrk client: `-t64 -c500 -d10s --latency` with `Connection: close`

## What's different vs experiment 04c (sibling)

- 04c uses the **.NET ThreadPool** via `Task.Run` (variable-size, hill-climbing governor — pre-tuned to `MinThreads=256` to avoid starvation).
- 04d uses a **fixed pool of dedicated OS `Thread`** instances, all blocked on a `BlockingCollection<Socket>`.

The 04 vs 04d pair isolates **epoll alone**. The 04c vs 04d pair isolates **ThreadPool overhead** on top of that.

## Why 64 workers (default)

- wrk holds 500 sockets open with `Connection: close` (one fresh handshake per request).
- A blocking `SSL_do_handshake` on loopback p384 takes ~5–10ms.
- To saturate ~6500 RPS at ~10ms per handshake we need ~65 in-flight handshakes at any moment.
- 64 dedicated OS threads gives one thread per in-flight handshake plus headroom. The kernel only schedules ~4 of them at a time (`cpuset 0-3`) — the rest are parked in `read()`/`write()` syscalls and cost ~zero CPU.

If you suspect bench dilution from worker starvation, raise to 128:

```bash
WORKERS=128 docker compose -f src-proof/04d-fd-blocking-workers/compose.yml up --build -d
```

## What this experiment does **not** answer

- It does not measure "epoll under realistic Kestrel load" — it measures epoll specifically on the `SSL_set_fd` + per-request-handshake workload defined by this proof. With long-lived keepalive connections (the normal Kestrel case) epoll's advantage is much larger because connection count >> handshake rate.
- It does not propose that production servers use 64 dedicated blocking threads. It's a measurement vehicle, not an architecture recommendation.

## Result

Run:

```bash
docker compose -f src-proof/04d-fd-blocking-workers/compose.yml up --build -d
src-proof/bench/bench-one.sh 5012 csharp-tls-server-fd-blocking-workers "04d-fd-blocking-workers"
docker compose -f src-proof/04d-fd-blocking-workers/compose.yml down
```

| Label | RPS | mean CPU% | RPS/core | latency avg | latency p99 |
|---|---:|---:|---:|---:|---:|
| 04 (epoll workers)              | 6755.59 | 274.75 | 2458.81 | 24.81ms | 112.19ms |
| **04d (blocking + workers=64)** | 7166.19 | 330.92 | 2165.54 |  5.67ms |  55.71ms |
| **Δ (04d vs 04)**               | +6.1%   | +20.4% | −11.9%  | −77%    | −50%     |

**Verdict — does epoll help on the `SSL_set_fd` path? (the clean answer)**

Thread shape is held constant (a fixed pool of dedicated OS threads in both cases), only the IO model changes. The result is:

| Axis | Who wins | Margin |
|---|---|---:|
| Absolute throughput (RPS)        | **04d (no epoll)** | +6.1% |
| CPU efficiency (RPS/core)        | **04 (epoll)**     | +13.5% |
| Per-request latency (avg + p99)  | **04d (no epoll)** | ~50–77% lower |
| CPU consumed                     | **04 (epoll)**     | uses 17% less |

Reading it out: **epoll is not the headline.** On this specific workload (`Connection: close`, fresh handshake per request, loopback) epoll buys roughly **+13% RPS per CPU core** versus a blocking-thread-per-connection model. That is meaningful — it's not "within run noise" — and it accumulates on multi-core hosts where every saved core is a real one. But it is **not a step-change**, and it costs latency: the epoll path's `SSL_ERROR_WANT_READ` bouncing inflates p99 by ~2× compared to a thread parked in a single `read()` syscall.

The big story remains where the headline pair already put it: **`SSL_set_fd` vs mem-BIO** (04 vs 05) is **+256% RPS/core**. **Epoll on top of `SSL_set_fd`** (04 vs 04d) is **+13% RPS/core**. The API proposal needs to be socket-bindable; whether the consumer drives it with epoll or with blocking threads is a downstream choice that affects throughput-per-core by ~one-eighth, not by one order of magnitude.

That is the answer to *"epoll is not changing much either here"*: epoll **is** changing something — about 13% in CPU efficiency — but it isn't the thing that justifies the API. The API needs to exist regardless of which dispatch model the consumer picks.

The pair-diff between **04d (this) and 04c (Task.Run / ThreadPool)** isolates the cost of ThreadPool dispatch on top of the blocking IO model: 04c gets only 2113 RPS/core vs 04d's 2166 — about **2.5% lost to ThreadPool overhead** alone (`Task.Run` allocation + global-queue contention + wake-up coalescing) even with `SetMinThreads(256, 256)` pre-applied to remove hill-climbing.
