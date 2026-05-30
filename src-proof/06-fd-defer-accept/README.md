# 06 — `SSL_set_fd` + epoll workers + **`TCP_DEFER_ACCEPT`**

**TLS path:** `SSL_set_fd` (identical to exp 04)
**Threading:** 4 dedicated worker threads, each with its own epoll (identical to exp 04)
**Accept:** `accept4(SOCK_NONBLOCK)` + `EPOLLEXCLUSIVE` (identical to exp 04)
**The one variable under test:** `TCP_DEFER_ACCEPT=1` on the listen socket
**Port:** 5010

## What `TCP_DEFER_ACCEPT` does

Linux-only `setsockopt(IPPROTO_TCP, TCP_DEFER_ACCEPT, timeout_seconds)`.

**Without it:** the kernel completes the TCP 3-way handshake and immediately
hands the connection back from `accept()`. The application then waits in
`epoll_wait` for the ClientHello to arrive. That's one extra wakeup per
connection.

**With it:** the kernel completes the TCP handshake but holds the connection
internally until the client actually sends data (or `timeout_seconds`
elapse, at which point the kernel drops it). `accept()` only returns once
there's real data to read, and the worker can call `SSL_do_handshake`
immediately — saving the `epoll_wait` round-trip.

Because wrk is a real TLS-aware client, every connection it opens sends a
TLS ClientHello in the very first packet — the **realistic handshake data**
case the proposal cares about.

## What this experiment proves

The pair-difference **04 → 06** isolates the value of `TCP_DEFER_ACCEPT`:

- If RPS goes up: the saved wakeup matters at this load.
- If RPS is flat but **mean CPU% drops**: it's saving work even if it
  doesn't change throughput. That's still a real win.
- If both are flat: it's a DoS / SYN-flood hardening feature, not a perf
  feature, and the proposal should pitch it on those grounds.

## Implementation note

`Program.cs` reads `DEFER_ACCEPT_SEC` and calls
`NativeSsl.set_tcp_defer_accept(listenFd, seconds)` right after `Listen()`:

```csharp
var deferEnv = Environment.GetEnvironmentVariable("DEFER_ACCEPT_SEC");
if (int.TryParse(deferEnv, out var deferSeconds) && deferSeconds > 0)
{
    int listenFd = (int)listenSocket.Handle;
    NativeSsl.set_tcp_defer_accept(listenFd, deferSeconds);
}
```

The native wrapper (`demo_native.c::set_tcp_defer_accept`) just calls
`setsockopt(listen_fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, ...)`.

## Realistic-data caveat

wrk is a closed-loop benchmark with persistent ClientHello in the first
packet. `TCP_DEFER_ACCEPT`'s biggest production win is against slow or
malicious clients that complete the TCP handshake but never send data.
This bench cannot measure that; it can only measure the **fast-path wakeup
elimination**.

## How to run

```bash
docker compose -f src-proof/06-fd-defer-accept/compose.yml up --build -d
src-proof/bench/bench-one.sh 5010 csharp-tls-server-fd-defer-accept "06-fd-defer-accept"
docker compose -f src-proof/06-fd-defer-accept/compose.yml down
```

## Result (fill in after running)

| RPS | mean CPU% | RPS / CPU-core | latency avg | latency p99 | delta vs 04 |
|---:|---:|---:|---:|---:|---:|
| 6172.05 | 268.10 | 2302.14 | 24.69ms | 115.76ms | −9% RPS, −6% RPS/core (defer-timer adds latency on fast-LAN traffic) |
