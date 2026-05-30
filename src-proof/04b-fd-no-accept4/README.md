# 04b — `SSL_set_fd` + epoll workers, **without** `accept4`

**TLS path:** `SSL_set_fd` (identical to exp 04)
**Threading:** 4 dedicated worker threads, each with its own epoll (identical to exp 04)
**Accept:** `accept()` + `fcntl(O_NONBLOCK)` + `fcntl(FD_CLOEXEC)` — **the one variable under test**
**Port:** 5009

## What this experiment proves

This is exp 04 with **one** change: the worker uses the legacy `accept()` path
instead of `accept4(SOCK_NONBLOCK)`. Everything else — `SSL_set_fd`, epoll
workers, `EPOLLEXCLUSIVE`, `TCP_NODELAY` — is bit-identical to exp 04.

The pair-difference **04 → 04b** isolates the cost of the extra syscall pair
(`fcntl × 2`) versus the fused `accept4(..., SOCK_NONBLOCK)` syscall.

Use this to answer the maintainer question: *"do you really need a TryAccept
(`accept4`) public API, or is `accept` + `fcntl` good enough?"*

## Implementation note

The shared code in `src-dotnet/DemoSemiUnmanagedSocket/` reads the env var
`USE_ACCEPT4` in `Ssl/SslWorker.cs`:

```csharp
bool useAccept4 = Environment.GetEnvironmentVariable("USE_ACCEPT4") != "0";
int clientFd = useAccept4
    ? NativeSsl.accept_nonblocking(_listenFd)         // accept4
    : NativeSsl.accept_nonblocking_legacy(_listenFd); // accept + fcntl
```

The legacy variant lives in
`native/demo_native.c::accept_nonblocking_legacy()`.

## Expected outcome

At ~6 K conn/s with `cpuset=0-3`, two extra `fcntl` syscalls per accept
amount to ~12 K extra syscalls/s — roughly 0.05% of a busy worker's syscall
budget. **The expected delta is within run-to-run noise (±5% RPS).**

That **is** the honest finding: `accept4` is a syscall ergonomics
improvement, not a perf differentiator at this scale. The proposal can drop
it as a justification, or keep it as a nice-to-have without claiming perf
gain.

## How to run

```bash
docker compose -f src-proof/04b-fd-no-accept4/compose.yml up --build -d
src-proof/bench/bench-one.sh 5009 csharp-tls-server-fd-no-accept4 "04b-fd-no-accept4"
docker compose -f src-proof/04b-fd-no-accept4/compose.yml down
```

## Result (fill in after running)

| RPS | mean CPU% | RPS / CPU-core | latency avg | latency p99 | delta vs 04 |
|---:|---:|---:|---:|---:|---:|
| 5997.13 | 253.29 | 2367.69 | 23.70ms | 118.34ms | −11% RPS, −4% RPS/core (cost of dropping `accept4`) |
