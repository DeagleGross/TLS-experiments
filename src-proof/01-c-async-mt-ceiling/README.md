# 01 — C async-mt (ceiling)

**TLS path:** `SSL_set_fd`
**Threading:** 4 dedicated worker threads, each with its own epoll
**Accept:** SO_REUSEPORT (kernel distributes accept across listeners)
**Port:** 6001

**Source:** `src/tls_handshake_server_async_mt.c` — copy of the nginx-style C server
already in this repo.

## What this experiment proves

This is the **ceiling**. It's pure C with no managed-runtime overhead, written in the
classic nginx pattern: each worker pins its own epoll loop on a CPU, accepts directly,
and runs `SSL_set_fd` + `SSL_do_handshake` synchronously.

The gap between this server and `04-fd-epollworkers` is the C# runtime/interop overhead.
If the C# version comes within a few percent, the runtime tax is small and any further
gain has to come from a better API design.

## How to run

```bash
docker compose -f src-proof/01-c-async-mt-ceiling/compose.yml up --build -d
../bench/bench-one.sh 6001 c-tls-server-async-mt "01-C-async-mt"
docker compose -f src-proof/01-c-async-mt-ceiling/compose.yml down
```

## Result (fill in after running)

| RPS | mean CPU% | RPS / CPU-core | latency avg | latency p99 |
|---:|---:|---:|---:|---:|
| 4976.37 | 247.00 | 2014.72 | 13.23ms | 73.91ms |
