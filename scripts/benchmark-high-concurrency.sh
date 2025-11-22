#!/bin/bash

# Test at different concurrency levels to find where sync breaks

PORT=${1:-8443}
DURATION=10

echo "=== High Concurrency TLS Benchmark ==="
echo "Testing at different concurrency levels..."
echo ""

for CONNECTIONS in 50 100 500 1000 2000 5000; do
    echo "================================================"
    echo "Testing with $CONNECTIONS concurrent connections"
    echo "================================================"
    
    wrk -t8 -c$CONNECTIONS -d${DURATION}s \
        -s wrk-script-no-keepalive.lua \
        https://localhost:$PORT/ \
        --latency | grep -E "Requests/sec|Latency|Thread Stats" | head -3
    
    echo ""
    sleep 2
done
