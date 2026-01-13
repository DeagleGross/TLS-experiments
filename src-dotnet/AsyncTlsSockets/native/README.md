# Nginx-Style TLS Native Library

This directory contains the native C library that provides nginx-style TLS operations using OpenSSL and epoll.

## Architecture

The library replicates nginx's approach:

1. **Non-blocking I/O**: All operations use edge-triggered epoll
2. **Direct OpenSSL**: No BIO buffering overhead (unlike SslStream)
3. **Worker-friendly**: Designed to be called only from dedicated worker threads
4. **State management**: Handles bidirectional SSL events (read needs write, write needs read)

## Building

### Prerequisites

- GCC or Clang
- OpenSSL development headers (`libssl-dev` on Ubuntu)
- Linux (uses epoll)

### Compile

```bash
cd native
make
```

This produces `libnginx_tls.so`.

### Install

To install system-wide:

```bash
sudo make install
```

Or copy to your project's output directory:

```bash
make install-local
```

## Key Functions

### SSL Context Management

- `ngx_ssl_create_context()`: Initialize SSL context with cert/key
- `ngx_ssl_free_context()`: Clean up SSL context

### Epoll Operations

- `ngx_epoll_create()`: Create epoll context (one per worker)
- `ngx_epoll_wait()`: Wait for events (edge-triggered)
- `ngx_epoll_add_connection()`: Add connection to epoll
- `ngx_epoll_del_connection()`: Remove connection from epoll

### Connection Management

- `ngx_connection_create()`: Create SSL connection object
- `ngx_connection_free()`: Free connection and close socket

### SSL Operations (Non-blocking)

- `ngx_ssl_handshake()`: Perform TLS handshake (returns NGX_AGAIN if needs I/O)
- `ngx_ssl_read()`: Read decrypted data (returns NGX_AGAIN if needs I/O)
- `ngx_ssl_write()`: Write encrypted data (returns NGX_AGAIN if needs I/O)

### Return Codes

- `NGX_OK` (0): Success
- `NGX_ERROR` (-1): Error occurred
- `NGX_AGAIN` (-2): Operation would block, retry when I/O ready
- `NGX_DONE` (-3): Connection closed cleanly

## Nginx Patterns Implemented

1. **Edge-triggered epoll**: `EPOLLET` flag set on all connections
2. **accept4() with SOCK_NONBLOCK**: Atomic accept + set non-blocking
3. **SO_REUSEPORT**: Allows multiple workers to bind same port
4. **TCP_NODELAY**: Disabled Nagle's algorithm for low latency
5. **SSL modes**: `ENABLE_PARTIAL_WRITE`, `ACCEPT_MOVING_WRITE_BUFFER`, `RELEASE_BUFFERS`
6. **Bidirectional SSL events**: Saves state when read needs write or vice versa
7. **Error clearing**: `ERR_clear_error()` before each OpenSSL call

## Testing

You can test with OpenSSL s_client:

```bash
openssl s_client -connect 127.0.0.1:8443 -tls1_3
```

Or with curl:

```bash
curl -k https://127.0.0.1:8443/
```

## Performance Characteristics

Compared to SslStream:

- **No BIO buffering**: Direct socket I/O
- **Edge-triggered epoll**: Fewer syscalls
- **Dedicated workers**: No thread pool starvation
- **Zero-copy paths**: Minimal data copying

Expected performance gain: 20-40% lower latency, 15-25% higher throughput for TLS workloads.
