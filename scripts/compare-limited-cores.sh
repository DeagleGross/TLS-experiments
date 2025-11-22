#!/bin/bash

# Compare async vs sync servers both limited to 4 cores

echo "=== Starting servers limited to 4 CPU cores ==="
echo ""

# Kill any existing servers
pkill -f tls_handshake_server 2>/dev/null

# Start async server on 4 cores
echo "Starting ASYNC server (epoll-based) on cores 0-3..."
taskset -c 0-3 ./src/tls_handshake_server 8443 &
ASYNC_PID=$!
sleep 2

# Check it started
if ps -p $ASYNC_PID > /dev/null; then
    echo "✓ Async server running (PID: $ASYNC_PID)"
    taskset -cp $ASYNC_PID
else
    echo "✗ Failed to start async server"
    exit 1
fi

echo ""
echo "Run benchmark with: ./scripts/benchmark.sh 8443 30 32 5000"
echo "Then Ctrl+C this script and start sync server with:"
echo "  taskset -c 0-3 ./src/tls_handshake_server_sync 8443"
echo ""
echo "Press Ctrl+C to stop async server..."

wait $ASYNC_PID
