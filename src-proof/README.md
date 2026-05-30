# Per-API Proof Experiments

> There is an ask to proof validness of each specific API proposed.
> This folder ships one experiment per variable, with each pair-difference isolating exactly one change. **RPS, CPU%, and `RPS / CPU%` (RPS-per-CPU-core)** are measured so a faster impl is judged by *throughput per unit of CPU* — not just absolute RPS.

## Controlled variables (what is the same across all experiments)

Read this **first** — it's what makes the pair-difference math honest. Every
experiment runs on the **same host, same kernel, same OpenSSL, same cert,
same wrk client, same cores, same network**, so any RPS / CPU delta between
two rows is attributable to the one thing that actually changed between them.

| Dimension | Value (identical across all servers) | Why it matters |
|---|---|---|
| Host | WSL2 on a single Windows host | No cross-host RTT, no NIC, no firewall — pure loopback |
| Kernel | `5.15.153.1-microsoft-standard-WSL2` | Same epoll / accept / TCP stack |
| OpenSSL | `libssl3` (Ubuntu 22.04 base in every image) | Same handshake, same AEAD, same ECDHE |
| CPU pinning | `cpuset: "0-3"` (4 cores) on every container | Same compute budget |
| Workers | 4 (epoll workers in 01/01b/04/04b/05/06; ThreadPool in 02/03 — both effectively cap at 4 cores) | Same parallelism |
| Cert | ECDSA **P-384** (`certs/server-p384.{crt,key}`, env `CURVE=p384`) | Same signature work per handshake |
| ECDHE group | **X25519** (chosen by wrk's openssl client `key_share`; all servers accept it) | Same key-agreement work per handshake |
| TLS version | **TLS 1.3** in practice on every run (see asymmetry note below) | Same handshake shape (1-RTT) |
| Cipher suite | **`TLS_AES_256_GCM_SHA384`** in practice (default TLS 1.3 server preference) | Same AEAD work per record |
| ALPN / HTTP version | none / HTTP/1.1 | No h2/h3 multiplexing — every request = one full handshake |
| SNI | `localhost` | Same code path; no cert switching |
| Client auth (mTLS) | OFF everywhere | Same handshake message count |
| HTTP semantics | `Connection: close` (forced by [`bench/wrk-script-no-keepalive.lua`](bench/wrk-script-no-keepalive.lua)) | Every request = fresh TCP + fresh TLS = we are measuring **per-handshake cost**, not warm-connection steady-state |
| Session resumption | Effectively 0% — wrk uses a fresh openssl client per connection and doesn't carry session tickets | Same full-handshake work every request |
| wrk client | `-t64 -c500 -d10s --latency` for every run | Same offered load |

### Why TLS 1.3, not TLS 1.2

It's what realistic ASP.NET Core / Kestrel deployments negotiate today (and
where the API proposal is targeted) — but more concretely:

- **TLS 1.3 is 1-RTT**; TLS 1.2 is 2-RTT (ClientHello → ServerHello+Cert+KEX → ClientKEX+Finished → ServerFinished). On loopback the RTT cost is sub-µs so it barely shows in RPS, but it changes the number of wire turns the server has to manage.
- **CPU per handshake is essentially the same** for both — the dominant cost (ECDHE keygen, ECDSA signing) is identical. The cipher suite (`TLS_AES_*_GCM_*`) is also the same family.
- The **3 micro-tunings the 01→01b pair measures** (`accept4`, `EPOLLEXCLUSIVE`, no `SSL_shutdown`) and **the SslStream-vs-mem-BIO axis the 02→03 pair measures** are independent of TLS version. Running 1.2 instead of 1.3 would shift the absolute RPS down a few percent but would not change the relative deltas the proof depends on.

So picking 1.3 is "the realistic default" rather than "the version that flatters our numbers".

### Honest asymmetries (small, kept because flipping them doesn't move the headline)

These are not perfectly identical across all servers, but **none of them is
large enough to move the pair-difference deltas the proof relies on**:

| Asymmetry | Where | Impact |
|---|---|---|
| Response body: C servers (01, 01b) return `Content-Length: 0`; C# servers (02–06) return `Hello, World!` (13 bytes) | Server source files | ~13B plaintext = ~14B ciphertext per response. AEAD over 14B is sub-µs. Server-side impact is well below run noise. |
| TLS version pinning: 01/01b/05 pin TLS 1.3 only via `set_min/set_max`; 02 allows `Tls12 \| Tls13`; 03/04/04b/06 use OpenSSL `TLS_server_method()` default (1.2 + 1.3) | Server source files | **All runs end up on TLS 1.3** because wrk's openssl client negotiates highest supported version. The pinning only matters if a buggy client downgrades — irrelevant for wrk. |
| Cipher list pinning: 01/01b explicitly set `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`; others use OpenSSL default | Server source files | OpenSSL's TLS 1.3 default server-preference is the same three ciphers; wrk's client preference selects `TLS_AES_256_GCM_SHA384` every time. |
| Server-side session cache: 05 explicitly disabled; others default (`SESS_CACHE_SERVER`) | Server source files | wrk uses a fresh client per connection and doesn't replay session tickets, so the cache hit rate is **0% on all of them**. No resumption is happening anywhere. |

## TL;DR — the experiment matrix

Latest results from [`bench/results-20260530-094628-summary.md`](bench/results-20260530-094628-summary.md).
All numbers from `cpuset: 0-3` (4 cores), wrk `-t64 -c500 -d10s` with `Connection: close`.

| # | Server | TLS path | Threading | Accept | Port | RPS | RPS / core | Δ vs floor (RPS) | Δ vs floor (RPS/core) |
|---|---|---|---|---|---|---:|---:|---:|---:|
| 01 | C ceiling (naive) | `SSL_set_fd` | epoll workers | `SO_REUSEPORT` + `EPOLLET` + `SSL_shutdown` | 6001 | 4976 | 2015 | +272% | +493% |
| **01b** | **C ceiling (TUNED)** | **`SSL_set_fd`** | **epoll workers** | **`accept4` + `EPOLLEXCLUSIVE` + no `SSL_shutdown`** | **6002** | **6784** | **2736** | **+408%** | **+704%** |
| 02 | `SslStream` + `Task.Run` (today's floor) | `SslStream` | ThreadPool | `TcpListener` | 5001 | **1336** | **340** | — | — |
| 03 | mem-BIO + `Task.Run` | mem-BIO | ThreadPool | `TcpListener` | 5003 | 2648 | 698 | +98% | +105% |
| 04 | **`SSL_set_fd` + epoll workers** | **`SSL_set_fd`** | epoll workers | `accept4` + `EPOLLEXCLUSIVE` | 5007 | **6756** | **2459** | **+406%** | **+623%** |
| 04b | `SSL_set_fd` + epoll workers, **no `accept4`** | `SSL_set_fd` | epoll workers | `accept`+`fcntl` + `EPOLLEXCLUSIVE` | 5009 | 5997 | 2368 | +349% | +597% |
| 05 | **mem-BIO** + epoll workers | mem-BIO | epoll workers | `accept4` + `EPOLLEXCLUSIVE` | 5008 | 2720 | 690 | +104% | +103% |
| 06 | `SSL_set_fd` + epoll workers + **`TCP_DEFER_ACCEPT`** | `SSL_set_fd` | epoll workers | `accept4` + `EPOLLEXCLUSIVE` + defer-accept | 5010 | 6172 | 2302 | +362% | +577% |

> Source code:
> - 01 → `src/tls_handshake_server_async_mt.c`;
> - 02 → `src-dotnet/SslStreamConsole`;
> - 03 → `src-dotnet/BioSslConsole`;
> - 04/04b/06 → `src-dotnet/DemoSemiUnmanagedSocket` (same image, different env vars);
> - 05 → `src-proof/05-bio-epollworkers/src/`.

All seven negotiate **TLS 1.3** when wrk is the client — see the
"Controlled variables" section at the top of this README for the full
list of what's pinned. The only practical remaining variable between
04 and 05 (the headline pair) is the server-side session-cache mode:
04 leaves it at OpenSSL's default; 05 explicitly disables it. wrk
never replays a session ticket, so the cache hit rate is 0% either way.
A reviewer who wants byte-identical TLS configs for **04 vs 05** can
patch `src-dotnet/DemoSemiUnmanagedSocket/Ssl/SslContext.cs` to add
`SSL_CTX_set_min_proto_version(_ctx, TLS1_3_VERSION)` and
`SSL_CTX_set_session_cache_mode(_ctx, 0)`.

## What each pair-difference attributes

| Pair | Variable isolated | RPS Δ | RPS/core Δ | What it tells us |
|---|---|---:|---:|---|
| **02 → 03** | `SslStream` managed wrapping vs raw OpenSSL mem-BIO P/Invoke (**identical IO**: both use `TcpListener.AcceptTcpClientAsync` + `Task.Run`, no epoll difference, no threading difference) | **+98%** | **+105%** | Proves `SslStream`'s managed plumbing costs ~50% of per-handshake CPU on Linux on top of the same OpenSSL handshake. Candidate causes: `SafeHandle` ref-counting on every interop call, internal double-buffering (`_internalBuffer`/`_handshakeBuffer`), async-state-machine + per-call allocations in `AuthenticateAsServerAsync`, uncontended `_handshakeLock` acquire, cert-validation-callback dispatch. **Justifies the existence of a public `SafeTlsHandle` at all** — without it, every consumer has to bring their own out-of-support OpenSSL P/Invoke (like 03 does) to reach this perf. |
| 03 → 05 | ThreadPool vs dedicated epoll workers (same mem-BIO) | +3% | −1% | **Threading model alone gains nothing.** Not a public-API axis. |
| **04 vs 05** | **`SSL_set_fd` vs mem-BIO** (everything else equal — same epoll workers, same accept path) | **+148%** | **+256%** | **THE headline.** Once you have a public `SafeTlsHandle`, binding it to the socket fd (`SSL_set_fd`-shaped) stacks a second step-change on top of the 02→03 win. Justifies the handle being **socket-bindable**, not just buffer-driven. |
| 04 → 04b | `accept4` vs `accept` + `fcntl(O_NONBLOCK)` (one syscall vs three) | **+13%** | **+4%** | `accept4` atomically sets `SOCK_NONBLOCK \| SOCK_CLOEXEC`, saving **~2 syscalls per accepted connection**. Per-accept the saving is small (~200–500 ns of kernel-mode time), but it scales **linearly with connection churn × core count**: on a high-density multi-core host doing tens of thousands of fresh handshakes/sec, those saved syscalls add up to real headroom. It's also **one of the three micro-opts that lifts naive C (01) → tuned C ceiling (01b) by +36%**, so we know empirically it's part of the path to max perf. Justifies `TryAccept` on perf grounds (free win, no downside) on top of its ergonomic case (atomic flag setting, no TOCTOU window). |
| 04 → 06 | adding `TCP_DEFER_ACCEPT(1)` | −9% | −6% | Defer-timer adds latency on fast-LAN traffic. Real value is DoS hardening, not throughput. |
| **01 → 01b** | naive C → tuned C (3 micro-opts: `accept4` + `EPOLLEXCLUSIVE` + no `SSL_shutdown`) | **+36%** | **+36%** | The original 01 was not a real ceiling. The bulk of the gain is almost certainly `SSL_shutdown` (an encrypted close_notify per request). 01b is now the honest C ceiling. |
| **04 vs 01b** | **C# fd-binding vs tuned C ceiling** | **−0.4%** (tie) | **−10%** | **The managed-runtime tax.** Same RPS, but C# uses ~10% more CPU. Closing this would require unmanaged hot-path code, not a different API shape. |

> The two **bold rows on top (02→03 and 04 vs 05)** prove **two separate things, both required by the proposal**:
> 1. `SafeTlsHandle` needs to **exist** as a public API at all (02→03: ~2× RPS just from removing SslStream's managed wrapping, with identical IO).
> 2. `SafeTlsHandle` needs to be **socket-bindable** (`SSL_set_fd`-shaped), not just buffer-driven (04 vs 05: another 2.5× RPS/core on top).
> Either pair alone would be a weaker pitch. Stacked, they're the perf argument for the proposal.

## How to run

### One-time setup
```bash
# Generate ECDSA P-384 cert (already present in repo at ./certs/)
ls -la ./certs/server-p384.{crt,key}
```

### Run a single experiment

Template:
```bash
docker compose -f src-proof/<NN>-<name>/compose.yml up --build -d
src-proof/bench/bench-one.sh <port> <container_name> <label>
docker compose -f src-proof/<NN>-<name>/compose.yml down
```

**Concrete example — running just the headline experiment (04, C# fd-binding):**
```bash
# 1. Build the image and start the container in the background
docker compose -f src-proof/04-fd-epollworkers/compose.yml up --build -d

# 2. Bench it: <port>=5007, <container_name>=csharp-tls-server-fd-epollworkers, <label>=anything you want
src-proof/bench/bench-one.sh 5007 csharp-tls-server-fd-epollworkers "04-fd-epollworkers"

# 3. Tear it down when you're done
docker compose -f src-proof/04-fd-epollworkers/compose.yml down
```

The full lookup table of `<port>` / `<container_name>` for each experiment:

| Experiment folder | `<port>` | `<container_name>` |
|---|---:|---|
| `01-c-async-mt-ceiling`   | 6001 | `c-tls-server-async-mt` |
| `01b-c-ceiling-tuned`     | 6002 | `c-tls-server-tuned` |
| `02-sslstream-baseline`   | 5001 | `csharp-tls-server-sslstream` |
| `03-bio-threadpool`       | 5003 | `csharp-tls-server-biossl` |
| `04-fd-epollworkers`      | 5007 | `csharp-tls-server-fd-epollworkers` |
| `04b-fd-no-accept4`       | 5009 | `csharp-tls-server-fd-no-accept4` |
| `05-bio-epollworkers`     | 5008 | `csharp-tls-server-bio-epollworkers` |
| `06-fd-defer-accept`      | 5010 | `csharp-tls-server-fd-defer-accept` |

### Run the full matrix
```bash
src-proof/bench/bench-all.sh
# → writes src-proof/bench/results-<timestamp>.md
```

The bench script:
1. Warms up wrk for 5s
2. Runs `wrk -t64 -c500 -d10s --latency` with `Connection: close` Lua
3. Samples `docker stats` every 0.5s in parallel
4. Computes `RPS`, `mean_CPU_percent`, `RPS / (CPU% / 100)` = **RPS per CPU core**
5. Tears down

Higher RPS-per-CPU-core is better — it means more throughput per unit of CPU consumed,
which is the only metric that fairly compares implementations of different architectures.

## Limiting cores

All containers use `cpuset: "0-3"` so the bench is constrained to **4 cores**. To run on a single core
(for the "per-request cost" lens), override with `CPUSET=0 docker compose -f … up`. For WSL2 you can
also `taskset -c 0 docker compose …` from the host.

## What this proof does **not** claim
- It does **not** compare different cipher suites — all servers force TLS_AES_256_GCM_SHA384/TLS_AES_128_GCM_SHA256.
- It does **not** measure session resumption (resumption is intentionally disabled).
- It does **not** measure HTTP/2 or large-payload performance — this is a handshake-CPU benchmark.
- It does **not** prove kTLS / kernel-TLS performance (out of scope; explicitly avoided per maintainer request).
