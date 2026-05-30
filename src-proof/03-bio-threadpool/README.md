# 03 — mem-BIO + Task.Run

**TLS path:** mem-BIO (OpenSSL `BIO_s_mem`) — managed code drives the BIO directly
**Threading:** ThreadPool (`Task.Run` per accepted connection)
**Accept:** `TcpListener.AcceptTcpClientAsync`
**Port:** 5003

**Source:** `src-dotnet/BioSslConsole/` — unchanged from the existing project.

## What this experiment proves

This is the **counterfactual** for fixing `SslStream` directly:
"What if we just took the `SslStream` overhead out and let managed code drive an
OpenSSL mem-BIO, keeping ThreadPool as the threading model?"

The **02 → 03 pair-difference** isolates SslStream's own cost (state-machine,
intermediate buffers, Stream-shaped API) from anything else. If 03 closes most of
the gap to 04, then the right answer might simply be **"improve `SslStream`"** rather
than ship a new TLS API.

If 03 doesn't close much of the gap, then the wins are coming from the threading
model and/or fd-binding — not from `SslStream`-vs-BIO.

## How to run

```bash
docker compose -f src-proof/03-bio-threadpool/compose.yml up --build -d
../bench/bench-one.sh 5003 csharp-tls-server-biossl "03-BIO-ThreadPool"
docker compose -f src-proof/03-bio-threadpool/compose.yml down
```

## Result (fill in after running)

| RPS | mean CPU% | RPS / CPU-core | latency avg | latency p99 |
|---:|---:|---:|---:|---:|
| 2648.35 | 379.60 | 697.67 | 49.12ms | 181.02ms |
