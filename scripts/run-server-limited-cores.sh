#!/bin/bash

# Run server with limited CPU cores (simulate cloud environment)

CORES=${1:-4}
SERVER=${2:-./src/tls_handshake_server}
PORT=${3:-8443}

# Create CPU list (0,1,2,3 for 4 cores)
CPU_LIST=$(seq -s, 0 $((CORES-1)))

echo "=== Running server with $CORES CPU cores ==="
echo "Server: $SERVER"
echo "Port: $PORT"
echo "CPU affinity: $CPU_LIST"
echo ""

# Use taskset to limit to specific cores
taskset -c $CPU_LIST $SERVER $PORT
