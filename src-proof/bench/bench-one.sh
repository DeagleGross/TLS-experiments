#!/usr/bin/env bash
#
# bench-one.sh — bench a single TLS server (already running) and emit:
#                RPS, mean CPU%, and RPS-per-CPU-core ratio.
#
# Usage:
#   bench-one.sh <port> <container_name> <label> [duration_s] [warmup_s]
#
# Outputs (to stdout) a one-line summary plus the full wrk output and CPU samples.
# Exit codes: 0 on success, non-zero if wrk or stats sampling fails.

set -euo pipefail

PORT="${1:?usage: bench-one.sh <port> <container_name> <label> [duration] [warmup]}"
CONTAINER="${2:?missing container_name}"
LABEL="${3:?missing label}"
DURATION="${4:-10}"
WARMUP="${5:-5}"
THREADS="${THREADS:-64}"
CONNS="${CONNS:-500}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LUA="${SCRIPT_DIR}/wrk-script-no-keepalive.lua"

if ! command -v wrk >/dev/null 2>&1; then
    echo "ERROR: wrk not found in PATH. Install with: sudo apt-get install -y wrk" >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker not found in PATH" >&2
    exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -qx "${CONTAINER}"; then
    echo "ERROR: container '${CONTAINER}' is not running. Start it first." >&2
    exit 1
fi

URL="https://localhost:${PORT}/"

echo "============================================================"
echo "[bench] label=${LABEL} container=${CONTAINER} port=${PORT}"
echo "[bench] warmup=${WARMUP}s duration=${DURATION}s threads=${THREADS} conns=${CONNS}"
echo "============================================================"

# Warmup — exercises the JIT and warms socket buffers
echo "[bench] warmup ${WARMUP}s ..."
wrk -t"${THREADS}" -c"${CONNS}" -d"${WARMUP}"s -s "${LUA}" "${URL}" >/dev/null 2>&1 || true

# Start docker-stats sampler in the background
# `docker stats --no-stream` returns one line per call with CPU% in the
# format "12.34%" — easy to parse.
SAMPLES_FILE="$(mktemp -t cpu-samples.XXXXXX)"
echo "[bench] sampling docker stats every 0.5s -> ${SAMPLES_FILE}"
(
    while true; do
        docker stats --no-stream --format '{{.Name}} {{.CPUPerc}}' "${CONTAINER}" 2>/dev/null \
            | awk -v ts="$(date +%s.%N)" '{print ts" "$0}' >>"${SAMPLES_FILE}" || true
        sleep 0.5
    done
) &
SAMPLER_PID=$!
trap 'kill ${SAMPLER_PID} 2>/dev/null || true; rm -f "${SAMPLES_FILE}"' EXIT

# Measurement
WRK_OUT="$(mktemp -t wrk-out.XXXXXX)"
echo "[bench] measuring ${DURATION}s ..."
wrk -t"${THREADS}" -c"${CONNS}" -d"${DURATION}"s -s "${LUA}" "${URL}" --latency \
    | tee "${WRK_OUT}"

# Stop the sampler
kill "${SAMPLER_PID}" 2>/dev/null || true
wait "${SAMPLER_PID}" 2>/dev/null || true

# Parse wrk RPS — line looks like:  "Requests/sec:   3456.78"
RPS=$(awk '/^Requests\/sec:/ {print $2}' "${WRK_OUT}")
TOTAL_REQ=$(awk '/^  [0-9]+ requests in/ {print $1}' "${WRK_OUT}" | head -n1)
LATENCY_AVG=$(awk '/^    Latency / {print $2}' "${WRK_OUT}" | head -n1)
LATENCY_P99=$(awk '/^     99%/ {print $2}' "${WRK_OUT}" | head -n1)

# Parse CPU samples — average over all samples taken during measurement.
# docker stats output: "<container_name> 312.5%"
# 312.5% means 3.125 cores used.
MEAN_CPU=$(awk '
    {
        # 2nd-to-last field is the container name (no spaces), last is CPU%
        cpu = $NF
        gsub(/%/, "", cpu)
        sum += cpu
        n++
    }
    END {
        if (n > 0) printf "%.2f", sum/n
        else print "0.00"
    }
' "${SAMPLES_FILE}")

SAMPLE_COUNT=$(wc -l < "${SAMPLES_FILE}")

# RPS per CPU core = RPS / (CPU% / 100)
RPS_PER_CORE=$(awk -v r="${RPS:-0}" -v c="${MEAN_CPU:-0}" \
    'BEGIN { if (c > 0) printf "%.2f", r / (c / 100); else print "n/a" }')

echo
echo "============================================================"
echo "[bench:summary] label=${LABEL}"
echo "[bench:summary] RPS              = ${RPS}"
echo "[bench:summary] total_requests   = ${TOTAL_REQ}"
echo "[bench:summary] latency_avg      = ${LATENCY_AVG}"
echo "[bench:summary] latency_p99      = ${LATENCY_P99}"
echo "[bench:summary] mean_CPU%        = ${MEAN_CPU}  (over ${SAMPLE_COUNT} samples)"
echo "[bench:summary] CPU_cores_used   = $(awk -v c=${MEAN_CPU:-0} 'BEGIN{printf "%.2f", c/100}')"
echo "[bench:summary] RPS_per_CPU_core = ${RPS_PER_CORE}    <-- the headline metric"
echo "============================================================"

# Emit a final machine-parseable line so bench-all.sh can scrape it
echo "RESULT|${LABEL}|${RPS}|${MEAN_CPU}|${RPS_PER_CORE}|${LATENCY_AVG}|${LATENCY_P99}"

rm -f "${WRK_OUT}"
