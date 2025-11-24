#!/bin/bash

# Simple benchmark script for the SslStream server
# Requires: curl, h2load (nghttp2), openssl

echo "=== SslStream Server Benchmark Suite ==="
echo ""

SERVER_URL="https://localhost:5001"
SERVER_HOST="localhost:5001"

# Check if server is running
echo "Checking if server is running..."
if ! curl -k -s --connect-timeout 2 "$SERVER_URL" > /dev/null 2>&1; then
    echo "ERROR: Server is not running on $SERVER_URL"
    echo "Start the server with: dotnet run"
    exit 1
fi
echo "? Server is running"
echo ""

# Test 1: Simple connectivity
echo "Test 1: Simple connectivity test"
echo "--------------------------------"
response=$(curl -k -s "$SERVER_URL")
echo "Response: $response"
echo ""

# Test 2: Burst test with curl
echo "Test 2: Burst test (100 requests with curl)"
echo "-------------------------------------------"
start=$(date +%s)
for i in {1..100}; do
    curl -k -s "$SERVER_URL" > /dev/null
done
end=$(date +%s)
duration=$((end - start))
rps=$((100 / duration))
echo "Completed 100 requests in ${duration}s (~${rps} req/s)"
echo ""

# Test 3: h2load benchmark (if available)
if command -v h2load &> /dev/null; then
    echo "Test 3: h2load benchmark (10,000 requests, 100 concurrent)"
    echo "----------------------------------------------------------"
    h2load -n 10000 -c 100 -t 4 "$SERVER_URL"
    echo ""
    
    echo "Test 4: h2load high concurrency (50,000 requests, 500 concurrent)"
    echo "-----------------------------------------------------------------"
    h2load -n 50000 -c 500 -t 8 "$SERVER_URL"
    echo ""
else
    echo "Test 3: h2load not found (skipping)"
    echo "Install with: apt install nghttp2-client (Ubuntu) or brew install nghttp2 (macOS)"
    echo ""
fi

# Test 4: OpenSSL s_time (raw TLS handshake)
if command -v openssl &> /dev/null; then
    echo "Test 5: OpenSSL s_time (raw TLS handshakes for 10 seconds)"
    echo "----------------------------------------------------------"
    openssl s_time -connect "$SERVER_HOST" -time 10 -new 2>&1 | grep -E "(connections|per second)"
    echo ""
else
    echo "Test 5: openssl not found (skipping)"
    echo ""
fi

echo "=== Benchmark Complete ==="
echo "Check server console for detailed metrics"
