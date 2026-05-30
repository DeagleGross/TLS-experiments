# 01b — C async-mt (TUNED ceiling)

**TLS path:** `SSL_set_fd`
**Threading:** 4 dedicated worker threads, each with its own epoll
**Accept distribution:** `EPOLLEXCLUSIVE` on the shared listen fd (no thundering herd)
**Accept syscall:** `accept4(SOCK_NONBLOCK)` — one syscall, not two
**Connection teardown:** `SSL_free` + `close` — no `SSL_shutdown` (no TLS close_notify)
**Port:** 6002

**Source:** `src/tls_handshake_server_async_mt_tuned.c`

## What this experiment proves

This is the **actual** C ceiling, after applying the three micro-optimizations
the original `01` was missing. The diff vs `01` cleanly attributes to:

1. `accept4(SOCK_NONBLOCK)` instead of `accept()` + `fcntl(O_NONBLOCK)`
   (saves one syscall per accept)
2. `EPOLLEXCLUSIVE` on the listen socket instead of `EPOLLET` across multiple
   epoll instances (no thundering herd: kernel wakes exactly one worker per
   incoming connection)
3. Skipping `SSL_shutdown()` before `SSL_free()` (no encrypted close_notify
   alert per request)

These are the same three optimizations our C# fd-binding worker
(`04-fd-epollworkers`) already applies. So the gap between `01b` and `04`
isolates **C# runtime/interop overhead** (JIT, GC, P/Invoke marshalling) on
an otherwise identical TLS pipeline.

## Why we keep `01` around too

`01` (the original) shows what "naive C with safe cleanup" gets you. The
gap between `01` and `01b` quantifies the value of these three micro-tunings
in isolation, which itself is interesting (`SSL_shutdown` alone is a
non-trivial encrypt + write per request).

## How to run

```bash
docker compose -f src-proof/01b-c-ceiling-tuned/compose.yml up --build -d
src-proof/bench/bench-one.sh 6002 c-tls-server-tuned "01b-C-tuned"
docker compose -f src-proof/01b-c-ceiling-tuned/compose.yml down
```

## Expected outcome

- `01b` should outperform `01` (real cost of `SSL_shutdown` + extra accept syscall + thundering herd).
- `01b` should set the upper bound for C# fd-binding (`04`). If `04` lands
  within ~10% of `01b` in RPS/core, the C# managed runtime tax is small and
  any further wins must come from a different API design.

## Result

| RPS | mean CPU% | RPS / CPU-core | latency avg | latency p99 |
|---:|---:|---:|---:|---:|
| 6783.91 | 247.97 | 2735.78 | 16.99 ms | 85.89 ms |

### Interpretation

- vs `01` (naive C): **+36% RPS** and **+36% RPS/core** at iso-CPU. The bulk
  of this is almost certainly `SSL_shutdown` (a synchronous encrypted
  close_notify alert + write + flush per request); `EPOLLEXCLUSIVE` removes
  the thundering-herd CPU cost; `accept4` saves one syscall per accept.
- vs `04` (C# fd-binding): essentially **the same RPS** (6784 vs 6756, within
  0.4%) but `04` uses **~10% more CPU** (275% vs 248%). So C# fd-binding lands
  at **~90% RPS/core of the optimized C ceiling** — the gap is the managed-
  runtime tax (JIT + GC + P/Invoke), not an API-design issue.
- Both `01b` and `04` cap at ~6.7–6.8K RPS — that's the single-host
  WSL+loopback+wrk wall, not the server.
