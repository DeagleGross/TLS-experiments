#!/bin/bash

# Profile TLS handshake performance using perf
# Run with: sudo ./profile-tls.sh <pid> <duration>

PID=${1:-}
DURATION=${2:-10}
OUTPUT_DIR="./perf-results"

if [ -z "$PID" ]; then
    echo "Usage: $0 <pid> [duration_seconds]"
    echo ""
    echo "Find the server PID first:"
    echo "  docker top <container_name>"
    echo "  or: pgrep -f 'DemoSemiUnmanagedSocket\|DirectSslTransportApp'"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "=== Profiling PID $PID for ${DURATION}s ==="

# CPU profiling with stack traces
echo "[1/3] Recording CPU profile..."
perf record -F 997 -p $PID -g --call-graph dwarf -o "$OUTPUT_DIR/perf_cpu_$TIMESTAMP.data" -- sleep $DURATION &
PERF_PID=$!

# While recording, run the benchmark
echo "[2/3] Run benchmark now in another terminal:"
echo "  cd /home/adityam/code/TLS-experiments/scripts"
echo "  ./benchmark.sh 5007 $DURATION"
echo ""
echo "Waiting for perf to finish..."
wait $PERF_PID

# Generate flame graph
echo "[3/3] Generating flame graph..."
if command -v flamegraph.pl &> /dev/null; then
    perf script -i "$OUTPUT_DIR/perf_cpu_$TIMESTAMP.data" | stackcollapse-perf.pl | flamegraph.pl > "$OUTPUT_DIR/flamegraph_$TIMESTAMP.svg"
    echo "Flame graph: $OUTPUT_DIR/flamegraph_$TIMESTAMP.svg"
else
    echo "FlameGraph tools not found. To generate flame graph:"
    echo "  git clone https://github.com/brendangregg/FlameGraph"
    echo "  perf script -i $OUTPUT_DIR/perf_cpu_$TIMESTAMP.data | ./FlameGraph/stackcollapse-perf.pl | ./FlameGraph/flamegraph.pl > flamegraph.svg"
fi

# Quick stats
echo ""
echo "=== Quick Stats ==="
perf report -i "$OUTPUT_DIR/perf_cpu_$TIMESTAMP.data" --stdio --sort=dso -n | head -30

echo ""
echo "For detailed analysis:"
echo "  perf report -i $OUTPUT_DIR/perf_cpu_$TIMESTAMP.data"
