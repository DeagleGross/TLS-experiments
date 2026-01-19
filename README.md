# TLS Experiments

This repo is dedicated to TLS experiments to understand the best potential way to work with it on UNIX systems;
The goal is to determine why nginx is the best server to perform TLS handshakes performantly, compared to Kestrel for example.

## Certificates

**Available curves:**
| Curve | Key Type | CPU Cost | Notes |
|-------|----------|----------|-------|
| `p256` | ECDSA P-256 (secp256r1) | Fastest | Most common, good balance |
| `p384` | ECDSA P-384 (secp384r1) | Heaviest | Higher security margin |

## Running with Different Curves

### C Programs
```bash
# Using curve name
./bin/tls_handshake_server_async_mt 6001 p256
./bin/tls_handshake_server_async_mt 6001 p384
```

### C# Programs
```bash
# Using --curve flag
dotnet run --curve p256
dotnet run --curve p384
```

### Docker compose

In order to simulate running app in the constrained environment, you can run servers via docker-compose which restrict cpuset: `cpuset: "0-3"`
```bash
# use $env:CURVE="p256" or $env:CURVE="p384" to control which cert will be used
$env:CURVE="p256"; docker compose -f compose-c-async-mt.yml up --build
```

## C servers

In [src](./src/) you can find different C server apps which simulate different architectures and showcase different usage of TLS handshake.
[See architectural differences and results](./src/README.md)

## CSharp servers

In [src-dotnet](./src-dotnet/) you can find different CSharp server apps which simulate different architectures and showcase different usage of TLS handshake.
[See architectural differences and results](./src-dotnet/README.md).