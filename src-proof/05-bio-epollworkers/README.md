# Experiment 05 — mem-BIO + dedicated epoll workers (NEW)

## What this proves

This is the **most important experiment** for the proposal: it isolates the
value of `SSL_set_fd` (binding `SafeTlsHandle` directly to a socket fd) from
every other variable.

| | Experiment 04 (`DemoSemiUnmanagedSocket`) | Experiment 05 (this folder) |
| - | - | - |
| Accept path | EPOLLEXCLUSIVE | EPOLLEXCLUSIVE |
| Worker model | 4 dedicated epoll threads | 4 dedicated epoll threads |
| Socket-level knobs | identical | identical |
| TLS version | TLS 1.3 only | TLS 1.3 only |
| Session cache | OFF | OFF |
| **TLS data path** | **`SSL_set_fd`** (OpenSSL ↔ socket directly) | **mem-BIO** (we `read()`/`write()` and pump bytes into BIOs) |

Every line of C# is byte-for-byte the same as experiment 04 except for
`Interop/NativeSsl.cs` (loads `libbio_native.so` instead of
`libdemo_native.so`) and `Ssl/SslContext.cs` (which forces TLS 1.3 + cache
off — the upstream `DemoSemiUnmanagedSocket` should be patched the same way
when running the bench for clean A/B; see `../README.md`).

## Pair-difference reading

**Measured result** (`bench-all.sh`, see [`bench/results-20260530-094628-summary.md`](../bench/results-20260530-094628-summary.md)):

| | RPS | mean CPU% | RPS / CPU-core | latency avg | latency p99 |
|---|---:|---:|---:|---:|---:|
| **04** (`SSL_set_fd`) | **6755.59** | 274.75 | **2458.81** | 24.81ms | 112.19ms |
| **05** (mem-BIO) | **2719.74** | 394.10 | **690.11** | 113.00ms | 275.94ms |
| **Δ (04 over 05)** | **+148% RPS** | **−30% CPU** | **+256% RPS/core** | — | — |

This is **the headline pair-difference** for the proposal. `SSL_set_fd`
earns its own API surface: per-core efficiency more than triples while CPU
actually drops by 30%. The cost of pumping bytes through managed code
between socket and BIOs is the bottleneck, not threading or accept handling
(both pinned identical between 04 and 05).

> Verdict: `SafeTlsHandle` must be **socket-bindable** (not just
> buffer-driven). A buffer-only fallback (mem-BIO shape) is still useful
> for Schannel / Network.framework where `SSL_set_fd` doesn't exist —
> but on Linux the socket-bound form is where the win lives.

## What's in here

- `src/native/bio_native.c` — drop-in replacement for `demo_native.c`. Same
  public ABI (so `SslWorker.cs` is reusable verbatim), but the
  per-connection struct keeps the SSL bound to two memory BIOs and the C
  code is responsible for `read()`/`write()` against the socket and feeding
  bytes between socket and BIOs.
- `src/native/Makefile` — same recipe as #04, only the output name differs.
- `src/Interop/NativeSsl.cs` — `[DllImport]` of `libbio_native.so`. Signatures
  match experiment 04's `NativeSsl` 1:1 so the worker code stays identical.
- `src/Interop/OpenSsl.cs` — adds `SSL_CTX_set_min_proto_version`,
  `SSL_CTX_set_max_proto_version`, and a helper for
  `SSL_CTX_set_session_cache_mode` (via `SSL_CTX_ctrl`).
- `src/Ssl/SslContext.cs` — forces TLS 1.3 + session cache OFF.
- `src/Ssl/SslWorker.cs`, `SslWorkerPool.cs` — unchanged logic vs. #04.
- `Dockerfile`, `compose.yml` — same build/run shape as #04, listens on `5008`.

## Run

```bash
# Build + bench just this experiment
cd src-proof
docker compose -f 05-bio-epollworkers/compose.yml build
docker compose -f 05-bio-epollworkers/compose.yml up -d
sleep 3
bench/bench-one.sh 05-bio-epollworkers csharp-tls-server-bio-epollworkers 5008
docker compose -f 05-bio-epollworkers/compose.yml down
```

## Results

(Filled in after running `bench/bench-all.sh`.)
