# 04 — `SSL_set_fd` + epoll workers + EPOLLEXCLUSIVE

**TLS path:** `SSL_set_fd` — OpenSSL reads/writes the socket directly
**Threading:** 4 dedicated worker threads, each with its own epoll
**Accept:** Workers add the listen fd to their own epoll with `EPOLLEXCLUSIVE` and `accept4` directly
**Port:** 5007

**Source:** `src-dotnet/DemoSemiUnmanagedSocket/` — unchanged from the existing project.
This is what the `TlsSocketBoundSession` API would look like in production code.

## What this experiment proves

This is the **proposed shape** of `TlsSocketBoundSession` — `SSL_set_fd` on a socket the
app owns, driven by an nginx-style worker pool the app also owns. The native lib
([`native/demo_native.c`](../../src-dotnet/DemoSemiUnmanagedSocket/native/demo_native.c))
calls `SSL_set_fd(ssl, client_fd)` on line 168 and lets `SSL_do_handshake` use the
socket directly.

The number to compare against:
- **01-C-async-mt-ceiling** — same architecture in pure C. If 04 is within 10–15% of 01,
  the C# runtime tax on this path is small.
- **05-bio-epollworkers** — same architecture, but with mem-BIO instead of `SSL_set_fd`.
  This is THE pair-difference that decides whether fd-binding earns its own API.

## How to run

```bash
docker compose -f src-proof/04-fd-epollworkers/compose.yml up --build -d
../bench/bench-one.sh 5007 csharp-tls-server-fd-epollworkers "04-fd-epollworkers"
docker compose -f src-proof/04-fd-epollworkers/compose.yml down
```

## Result (fill in after running)

| RPS | mean CPU% | RPS / CPU-core | latency avg | latency p99 |
|---:|---:|---:|---:|---:|
| 6755.59 | 274.75 | 2458.81 | 24.81ms | 112.19ms |
