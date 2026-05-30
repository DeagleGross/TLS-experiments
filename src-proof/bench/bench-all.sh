#!/usr/bin/env bash
#
# bench-all.sh — bring up each experiment, bench it, tear it down.
# Writes a results markdown file with the per-experiment RPS/CPU/RPS-per-core.
#
# Usage:
#   src-proof/bench/bench-all.sh
#
# Set SKIP_BUILD=1 if you've already built all images.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROOF_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${PROOF_DIR}/.." && pwd)"

cd "${REPO_DIR}"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULTS="${SCRIPT_DIR}/results-${TIMESTAMP}.md"

# Each row: id|label|port|container_name|compose_file
EXPERIMENTS=(
    "01|C async-mt (naive) — SSL_set_fd + SO_REUSEPORT + EPOLLET + SSL_shutdown|6001|c-tls-server-async-mt|src-proof/01-c-async-mt-ceiling/compose.yml"
    "01b|C async-mt (TUNED ceiling) — accept4 + EPOLLEXCLUSIVE + no SSL_shutdown|6002|c-tls-server-tuned|src-proof/01b-c-ceiling-tuned/compose.yml"
    "02|C# SslStream + Task.Run (today's floor)|5001|csharp-tls-server-sslstream|src-proof/02-sslstream-baseline/compose.yml"
    "03|C# mem-BIO + Task.Run|5003|csharp-tls-server-biossl|src-proof/03-bio-threadpool/compose.yml"
    "04|C# SSL_set_fd + epoll workers + EPOLLEXCLUSIVE|5007|csharp-tls-server-fd-epollworkers|src-proof/04-fd-epollworkers/compose.yml"
    "04b|C# SSL_set_fd + epoll workers (no accept4)|5009|csharp-tls-server-fd-no-accept4|src-proof/04b-fd-no-accept4/compose.yml"
    "05|C# mem-BIO + epoll workers + EPOLLEXCLUSIVE|5008|csharp-tls-server-bio-epollworkers|src-proof/05-bio-epollworkers/compose.yml"
    "06|C# SSL_set_fd + epoll workers + TCP_DEFER_ACCEPT|5010|csharp-tls-server-fd-defer-accept|src-proof/06-fd-defer-accept/compose.yml"
)

cat > "${RESULTS}" <<EOF
# TLS proof results — ${TIMESTAMP}

Host: \`$(uname -a)\`
CPU: \`$(grep -c ^processor /proc/cpuinfo 2>/dev/null || sysctl -n hw.ncpu) cores\`
Each container constrained to \`cpuset: "0-3"\` (4 cores).
wrk: \`-t64 -c500 -d10s\` with \`Connection: close\` Lua script.

| # | Label | RPS | mean CPU% | RPS / CPU core | latency avg | latency p99 |
|---|---|---:|---:|---:|---:|---:|
EOF

for exp in "${EXPERIMENTS[@]}"; do
    IFS='|' read -r ID LABEL PORT CONTAINER COMPOSE <<<"${exp}"

    echo
    echo "############################################################"
    echo "# Experiment ${ID}: ${LABEL}"
    echo "############################################################"

    # Bring up
    if [ -z "${SKIP_BUILD:-}" ]; then
        docker compose -f "${COMPOSE}" up --build -d
    else
        docker compose -f "${COMPOSE}" up -d
    fi

    # Wait for container to be ready
    echo "[bench-all] waiting 3s for ${CONTAINER} to be ready..."
    sleep 3

    # Bench
    set +e
    OUTPUT=$("${SCRIPT_DIR}/bench-one.sh" "${PORT}" "${CONTAINER}" "${LABEL}" 10 5)
    BENCH_EXIT=$?
    set -e

    echo "${OUTPUT}"

    # Parse the RESULT line and append a markdown row
    RESULT_LINE=$(echo "${OUTPUT}" | grep '^RESULT|' | tail -n1)
    if [ -n "${RESULT_LINE}" ]; then
        IFS='|' read -r _ LBL RPS CPU RPC LAT_AVG LAT_P99 <<<"${RESULT_LINE}"
        echo "| ${ID} | ${LBL} | ${RPS} | ${CPU} | ${RPC} | ${LAT_AVG} | ${LAT_P99} |" >> "${RESULTS}"
    else
        echo "| ${ID} | ${LABEL} | ERROR | - | - | - | - |" >> "${RESULTS}"
    fi

    # Tear down
    docker compose -f "${COMPOSE}" down --remove-orphans

    # Cool down before next experiment so CPU samples don't bleed
    sleep 5
done

# Append pair-difference analysis section
cat >> "${RESULTS}" <<EOF

## Pair-difference analysis

| Pair | Variable isolated | RPS gain | RPS-per-CPU gain |
|---|---|---:|---:|
| 02 → 03 | \`SslStream\` overhead vs raw mem-BIO | TBD | TBD |
| 03 → 05 | ThreadPool vs dedicated epoll workers (mem-BIO) | TBD | TBD |
| **04 vs 05** | **\`SSL_set_fd\` vs mem-BIO** (same arch) | **TBD** | **TBD** |
| 04 → 04b | \`accept4\` vs \`accept\` + \`fcntl\` | TBD | TBD |
| 04 → 06 | adding \`TCP_DEFER_ACCEPT\` | TBD | TBD |
| 01 → 01b | naive C vs tuned C (3 micro-optimizations) | TBD | TBD |
| **04 vs 01b** | **C# fd-binding vs tuned C ceiling** (managed-runtime tax) | **TBD** | **TBD** |

> Fill in the TBDs by computing the delta between the rows above.

## Reading the results

- If **04 ≈ 05** in *RPS-per-CPU-core*, then \`TlsSocketBoundSession\` (SSL_set_fd) is NOT
  justified as a separate API — the win came from threading, not fd-binding. The proposal
  should collapse to \`TlsDetachedSession\` (mem-BIO, portable).

- If **04 > 05** by a meaningful margin (say >15%), then \`SSL_set_fd\` is doing real work
  beyond what mem-BIO can match, and the dedicated fd-bound API stays.

- If **04 ≈ 04b** within noise (±5%), the \`accept4\` (TryAccept) syscall fusion has no
  measurable perf value at this load — keep the API or drop it on syscall-ergonomics
  grounds, not perf.

- If **04 ≈ 06** in RPS but 06 has lower mean CPU%, \`TCP_DEFER_ACCEPT\` is saving real
  wakeup work even though throughput is bounded elsewhere — worth keeping.
EOF

echo
echo "============================================================"
echo "Results written to: ${RESULTS}"
echo "============================================================"
cat "${RESULTS}"
