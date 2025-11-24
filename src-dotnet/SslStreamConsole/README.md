# SslStream Server - Docker Setup

Run the minimal SslStream TLS server in a Linux container using .NET 10.

## Quick Start

### Using Docker Compose (Recommended)

From the **repository root**:

```bash
docker-compose up --build
```

This will:
- Build the .NET 10 app in a Linux container
- Mount the certificates from `./certs`
- Expose port 5001
- Show live metrics in the console

### Using Docker Commands

```bash
# Build the image
docker build -t sslstream-server ./src-dotnet/SslStreamConsole

# Run the container (from repository root)
docker run -p 5001:5001 -v "$(pwd)/certs:/app/certs:ro" sslstream-server

# Or on Windows PowerShell
docker run -p 5001:5001 -v "${PWD}/certs:/app/certs:ro" sslstream-server
```

## Testing the Server

### Simple Connectivity Test

```bash
# Simple test
curl -k https://localhost:5001
```

### Benchmarking with wrk

`wrk` is an excellent HTTP benchmarking tool. Install it in WSL:

```bash
# Ubuntu/Debian
sudo apt install wrk

# Or build from source for latest version
git clone https://github.com/wg/wrk.git
cd wrk
make
sudo cp wrk /usr/local/bin/
```

**Run benchmarks:**

```bash
# Basic test: 12 threads, 400 connections, 30 seconds
wrk -t12 -c400 -d30s https://localhost:5001

# Higher concurrency test
wrk -t12 -c1000 -d30s https://localhost:5001

# With custom script (see below)
wrk -t12 -c400 -d30s -s test.lua https://localhost:5001
```

**Example wrk output:**
```
Running 30s test @ https://localhost:5001
  12 threads and 400 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    45.32ms   12.15ms 150.23ms   78.45%
    Req/Sec   742.23    123.45     1.05k    68.23%
  266845 requests in 30.10s, 45.67MB read
Requests/sec:   8865.12
Transfer/sec:      1.52MB
```

**wrk Lua script for custom headers** (`test.lua`):
```lua
wrk.method = "GET"
wrk.headers["User-Agent"] = "wrk-benchmark"
```

### Benchmarking with h2load

```bash
# Install in WSL
sudo apt install nghttp2-client

# Test TLS handshake performance
h2load -n 10000 -c 100 -t 4 https://localhost:5001

# Higher concurrency test
h2load -n 50000 -c 500 -t 8 https://localhost:5001
```

### OpenSSL TLS Handshake Test

```bash
# Test raw TLS handshake performance (focuses purely on SSL/TLS)
openssl s_time -connect localhost:5001 -time 10 -new

# More detailed handshake timing
openssl s_time -connect localhost:5001 -time 10 -new -www /
```

### Comparing Results

| Tool | Focus | Best For |
|------|-------|----------|
| **wrk** | HTTP throughput | Overall request/response performance |
| **h2load** | HTTP/2 support | Testing HTTP/2 and concurrent streams |
| **openssl s_time** | TLS handshakes | Pure TLS handshake performance (what you're optimizing) |

For your TLS handshake optimization goal, **openssl s_time** gives the most relevant metrics since it focuses purely on the handshake without HTTP overhead.

## Stopping the Server

```bash
# If using docker-compose
docker-compose down

# If using docker run
docker ps  # Find container ID
docker stop <container-id>
```

## Viewing Logs

```bash
# Follow logs
docker-compose logs -f

# Or with docker run
docker logs -f <container-id>
```

## Architecture

- **Base Image**: .NET 10 nightly (Linux)
- **OpenSSL**: Native Linux OpenSSL (same as nginx)
- **Certificates**: Mounted from `certs/` directory
- **Port**: 5001 (HTTPS)

This gives you a true Linux environment to compare against your C implementations running on Linux.

## Expected Performance Baseline

Since this uses `SslStream.AuthenticateAsServerAsync()` which makes blocking calls to `SSL_do_handshake()`, expect performance similar to:
- Your C **sync** implementation (each connection on new thread)
- Lower than **tls_handshake_server_async_mt** (your async multi-threaded version)
- Lower than **nginx** (uses non-blocking OpenSSL)

The goal is to measure this baseline, then implement a custom async TLS layer to match nginx/async_mt performance.
