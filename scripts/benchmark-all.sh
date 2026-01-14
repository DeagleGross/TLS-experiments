#!/bin/bash

# Comprehensive TLS benchmark script
# Compares multiple implementations

DURATION=${1:-10}
THREADS=${2:-64}
CONNECTIONS=${3:-500}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Lua script path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LUA_SCRIPT="$SCRIPT_DIR/wrk-script-no-keepalive.lua"

run_benchmark() {
    local name=$1
    local port=$2
    
    echo -e "${YELLOW}=== $name (port $port) ===${NC}"
    
    # Check if server is responding
    if ! timeout 2 bash -c "echo | openssl s_client -connect localhost:$port -servername localhost 2>/dev/null | head -1" | grep -q "CONNECTED"; then
        echo -e "${RED}Server not responding on port $port${NC}"
        return 1
    fi
    
    echo "Duration: ${DURATION}s, Threads: $THREADS, Connections: $CONNECTIONS"
    echo "Mode: Connection: close (new handshake per request)"
    echo ""
    
    wrk -t$THREADS -c$CONNECTIONS -d${DURATION}s \
        -s "$LUA_SCRIPT" \
        "https://localhost:$port/" \
        --latency
    
    echo ""
    echo "---"
    echo ""
}

echo "=============================================="
echo "  TLS Handshake Benchmark Suite"
echo "=============================================="
echo ""
echo "Parameters: Duration=${DURATION}s, Threads=$THREADS, Connections=$CONNECTIONS"
echo ""

# Run benchmarks for each server that's up
run_benchmark "DemoSemiUnmanagedSocket (C# + native epoll)" 5007
run_benchmark "C Async Multi-Threaded (nginx-style)" 6001
run_benchmark "DirectSsl Kestrel" 5001
run_benchmark "SslStream (.NET built-in)" 5001  # If using standard Kestrel

echo ""
echo "=============================================="
echo "  Benchmark Complete"
echo "=============================================="
