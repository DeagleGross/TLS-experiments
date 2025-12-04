# Direct fd-based SSL (No BIOs)

This experiment bypasses OpenSSL's memory BIOs and uses `SSL_set_fd()` to let OpenSSL directly read/write to the socket file descriptor.

## Architecture Comparison

### BIO-based (Current Kestrel Approach)
```
┌─────────────────────────────────────────────────────────────┐
│                    Managed (.NET)                            │
│                                                              │
│  await socket.ReceiveAsync(buffer)  ←── async notification  │
│         │                                                    │
│         ▼ encrypted data                                     │
│  BIO_write(rbio, buffer, n)  ──────────────────────────────┐│
│                                                             ││
│  plaintext = SSL_read(ssl, buf, len)  ◄─────────────────────┤│
│         │                                                   ││
│         │ For sending:                                      ││
│         ▼                                                   ││
│  SSL_write(ssl, plaintext, len)                            ││
│         │                                                   ││
│         ▼                                                   ││
│  encrypted = BIO_read(wbio, buf, pending)                  ││
│         │                                                   ││
│         ▼                                                   ││
│  await socket.SendAsync(encrypted)                         ││
└─────────────────────────────────────────────────────────────┘│
```

**Copies per receive:**
1. Kernel → managed buffer (ReceiveAsync)
2. Managed buffer → BIO memory (BIO_write)
3. BIO memory → OpenSSL internal → plaintext buffer (SSL_read)

### fd-based (This Experiment)
```
┌─────────────────────────────────────────────────────────────┐
│                    Managed (.NET)                            │
│                                                              │
│  await epollEventLoop.WaitReadableAsync(fd)  ←── epoll      │
│         │                                                    │
│         ▼ fd is ready                                        │
│  plaintext = SSL_read(ssl, buf, len)  ◄── OpenSSL reads fd  │
│                                            directly!         │
│                                                              │
│  For sending:                                                │
│  SSL_write(ssl, plaintext, len)  ──► OpenSSL writes fd      │
│                                       directly!              │
└─────────────────────────────────────────────────────────────┘
```

**Copies per receive:**
1. Kernel → OpenSSL internal buffer (recv inside SSL_read)
2. OpenSSL internal → plaintext buffer (decryption output)

## Potential Benefits

1. **Fewer buffer copies** - No intermediate managed buffer for encrypted data
2. **Fewer P/Invoke calls** - No BIO_write/BIO_read
3. **OpenSSL optimizations** - Direct fd access may enable kernel optimizations
4. **Simpler data flow** - Less shuffling between managed and native

## Potential Drawbacks

1. **Custom epoll handling** - Need our own event loop instead of .NET's
2. **Less portable** - Tied to Linux (epoll) vs. cross-platform ReceiveAsync
3. **Thread model** - Dedicated epoll thread vs. IOCP/epoll integration

## Usage

```bash
# Build and run
docker compose -f compose-csharp-directfd.yml up --build

# Benchmark
wrk -t4 -c100 -d30s https://localhost:6002/ --timeout 5s
```

## Comparison Tests

Run both servers and compare:

```bash
# BIO-based (port 5003)
docker compose -f compose-csharp-bio.yml up --build -d

# fd-based (port 6002)  
docker compose -f compose-csharp-directfd.yml up --build -d

# Benchmark BIO-based
wrk -t4 -c100 -d30s https://localhost:5003/

# Benchmark fd-based
wrk -t4 -c100 -d30s https://localhost:6002/
```

## Key Code Differences

### BIO-based
```csharp
// Create memory BIOs
IntPtr rbio = BIO_new(BIO_s_mem());
IntPtr wbio = BIO_new(BIO_s_mem());
SSL_set_bio(ssl, rbio, wbio);

// Receive encrypted → feed to OpenSSL → get plaintext
int received = await socket.ReceiveAsync(buffer);
BIO_write(rbio, buffer, received);
int plaintext = SSL_read(ssl, outputBuffer, len);
```

### fd-based (this experiment)
```csharp
// Attach fd directly
SSL_set_fd(ssl, (int)socket.Handle);

// Wait for fd ready → OpenSSL reads directly → get plaintext
await epollLoop.WaitReadableAsync(fd);
int plaintext = SSL_read(ssl, outputBuffer, len);  // OpenSSL calls recv() internally
```
