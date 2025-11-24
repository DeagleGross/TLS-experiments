#!/bin/bash

# Simple wrk benchmark with no keep-alive (forces new TLS handshake per request)

PORT=${1:-8443}
DURATION=${2:-10}
THREADS=${3:-64}
CONNECTIONS=${4:-500}

echo "=== TLS Handshake Benchmark ==="
echo "Target: https://localhost:$PORT/"
echo "Duration: ${DURATION}s, Threads: $THREADS, Connections: $CONNECTIONS"
echo "Mode: Connection: close (new handshake per request)"
echo ""

wrk -t$THREADS -c$CONNECTIONS -d${DURATION}s \
    -s wrk-script-no-keepalive.lua \
    https://localhost:$PORT/ \
    --latency

echo ""
echo "Usage: $0 [port] [duration] [threads] [connections]"
echo "Example: $0 8443 10 4 500"
