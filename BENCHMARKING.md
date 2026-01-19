# TLS Performance Benchmarking Guide

## Quick Start

### 1. Install Required Tools

```bash
# Profiling tools
sudo apt-get update
sudo apt-get install -y linux-tools-common linux-tools-generic linux-tools-$(uname -r) bpftrace

# FlameGraph (for visualization)
git clone https://github.com/brendangregg/FlameGraph ~/FlameGraph

# .NET profiling
dotnet tool install --global dotnet-trace
dotnet tool install --global dotnet-counters
```

### 2. Run Benchmark Servers

**DemoSemiUnmanagedSocket** (TLS-experiments - C# + native epoll):
```bash
cd /home/adityam/code/TLS-experiments
sudo docker compose -f compose-csharp-demo.yml up --build
# Listens on port 5007
```

**C Async Multi-Threaded** (nginx-style baseline):
```bash
cd /home/adityam/code/TLS-experiments  
sudo docker compose -f compose-c-async-mt.yml up --build
# Listens on port 6001
```

**DirectSsl Kestrel** (from aspnetcore repo):
```bash
cd /home/adityam/code/aspnetcore/src/Servers/Kestrel/samples/DirectSslTransportApp
# Build aspnetcore first if needed
dotnet run -c Release
# Listens on port 5001
```

### 3. Run Benchmarks

```bash
cd /home/adityam/code/TLS-experiments/scripts

# Single server benchmark
./benchmark.sh 5007 10 64 500   # port duration threads connections

# Compare all running servers
./benchmark-all.sh 10 64 500
```

### 4. Profile with perf

```bash
# Get container PID
docker top csharp-tls-server-demo-semiunmanaged-socket

# Or for dotnet process
pgrep -f DemoSemiUnmanagedSocket

# Record CPU profile
sudo perf record -F 997 -p <PID> -g --call-graph dwarf -o perf.data -- sleep 10

# While recording, run benchmark in another terminal:
./benchmark.sh 5007 10

# View results
sudo perf report -i perf.data

# Generate flame graph
sudo perf script -i perf.data | ~/FlameGraph/stackcollapse-perf.pl | ~/FlameGraph/flamegraph.pl > flamegraph.svg
```

### 5. Profile with bpftrace (syscall analysis)

```bash
# Get PID first
PID=$(pgrep -f DemoSemiUnmanagedSocket)

# Run syscall tracer
sudo bpftrace scripts/tls-syscall-trace.bt -p $PID

# In another terminal, run benchmark
./benchmark.sh 5007 10
```

### 6. .NET-specific profiling

```bash
# dotnet-counters (live metrics)
dotnet-counters monitor --process-id <PID> --counters System.Runtime,Microsoft.AspNetCore.Hosting

# dotnet-trace (detailed trace)
dotnet-trace collect --process-id <PID> --duration 00:00:10 --output trace.nettrace

# Convert to speedscope format
dotnet-trace convert trace.nettrace --format speedscope
# Open at https://www.speedscope.app/
```

---

## What to Look For

### Healthy Profile (nginx-like)
- Most time in `SSL_do_handshake` / OpenSSL functions
- Low futex contention
- Minimal context switches
- epoll_wait returns quickly when data available

### Problematic Patterns (DirectSsl issues)

1. **High futex contention** → ThreadPool lock overhead
2. **Many context switches** → Cross-thread TCS completions  
3. **Long epoll_wait with short bursts** → Work not distributed well
4. **Time in `Task`/`async` machinery** → Async overhead

---

## Benchmarks to Compare

| Implementation | Port | Description |
|----------------|------|-------------|
| C async-mt | 6001 | nginx-style baseline (best expected) |
| DemoSemiUnmanagedSocket | 5007 | C# accept + native SSL workers |
| DirectSsl Kestrel | 5001 | Full Kestrel with DirectSsl transport |
| SslStream | 5001 | Standard .NET SslStream (for reference) |

Expected performance order (best to worst):
1. C async-mt (~6500 RPS on 4 cores)
2. DemoSemiUnmanagedSocket (~5000-6000 RPS)
3. DirectSsl Kestrel (unknown - this is what we're investigating)
4. SslStream (~3000-4000 RPS)
