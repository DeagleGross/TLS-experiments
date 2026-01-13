#!/bin/bash

set -e

echo "=== Building Nginx-Style TLS Server ==="
echo

# Build native library
echo "1. Building native library..."
cd native
make clean
make
cd ..
echo "   ✓ Native library built"
echo

# Build C# project
echo "2. Building C# project..."
dotnet build -c Release
echo "   ✓ C# project built"
echo

# Copy native library to output directory
echo "3. Copying native library to output..."
mkdir -p bin/Release/net10.0
cp native/libnginx_tls.so bin/Release/net10.0/
echo "   ✓ Native library copied"