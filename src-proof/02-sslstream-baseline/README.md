# 02 — SslStream + Task.Run (today's floor)

**TLS path:** `SslStream` (System.Net.Security)
**Threading:** ThreadPool (`Task.Run` per accepted connection)
**Accept:** `TcpListener.AcceptTcpClientAsync`
**Port:** 5001

**Source:** `src-dotnet/SslStreamConsole/` — unchanged from the existing project.

## What this experiment proves

This is **today's floor** — the path every Kestrel + HTTPS connection currently takes.
The gap between this and any of the others tells us what's left on the table when we
keep the `SslStream`/Stream model.

The number to watch is **RPS-per-CPU-core**, not absolute RPS — that tells us whether
`SslStream` is *CPU-efficient*, even if it doesn't peak as high.

## How to run

```bash
docker compose -f src-proof/02-sslstream-baseline/compose.yml up --build -d
../bench/bench-one.sh 5001 csharp-tls-server-sslstream "02-SslStream"
docker compose -f src-proof/02-sslstream-baseline/compose.yml down
```

## Result (fill in after running)

| RPS | mean CPU% | RPS / CPU-core | latency avg | latency p99 |
|---:|---:|---:|---:|---:|
| 1336.13 | 393.13 | 339.87 | 90.58ms | 275.13ms |

## Caveat

This server today allows TLS 1.2 fallback (`SslProtocols.Tls12 | SslProtocols.Tls13`).
For a 100%-fair pair-comparison with the C ceiling, force TLS 1.3 only.
See `Program.cs` in the source project — the change is one line.
