#!/usr/bin/env bash
# Every libFuzzer target for a fixed time on its checked-in corpus, then one table: runs,
# coverage, corpus size and the verdict. The campaign before a tag, the weekly CI job and a
# check after a parser change all run this (docs/security-control-plane.md, "Sanitizer and
# fuzz record"). New inputs land in a scratch corpus, never in tests/fuzz/regressions/;
# a finding (crash, leak, timeout, sanitizer report) is kept under the output directory
# with its log, and the script exits 1.
#
# The whole machine by default: as many processes as the cores, or as the free memory holds at
# 600 MB each (an ASan fuzzer peaks there, most well below), every fuzzer at once when they fit, and the
# processes left over shared among them, each fuzzer's processes running libFuzzer's -jobs on one
# corpus. One fuzzer alone gets them all (a parser change); twenty on 24 cores get one each and
# finish in one wave of -t seconds (until 2026-10-17 half the cores ran, the targets in two waves,
# and a fuzzer alone on one core).
#
# usage: scripts/fuzz-all.sh [-t SECONDS] [-j FUZZERS] [-w PROCESSES] [-o DIR] [-b BUILD_DIR] [fuzzer ...]
#   -t  seconds per fuzzer (default 60)
#   -j  fuzzers run at once (default all of them, as many as the processes allow)
#   -w  processes per fuzzer (default the processes left over, shared)
#   -o  output directory (default bench/tmp/fuzz-<stamp>)
#   -b  the fuzz build directory (default build-fuzz-all; configured here when missing, with
#       clang++ or $CXX, TLS on so fuzz_quic_conn is built where OpenSSL has QUIC, 3.5+)
#   fuzzer names without the fuzz_ prefix (default: every target the build has)
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
SECS=60; JOBS=""; WORKERS=""; OUT=""; BUILD=build-fuzz-all
while getopts "t:j:w:o:b:" opt; do
  case $opt in t) SECS=$OPTARG ;; j) JOBS=$OPTARG ;; w) WORKERS=$OPTARG ;; o) OUT=$OPTARG ;; b) BUILD=$OPTARG ;; *) exit 2 ;; esac
done
shift $((OPTIND - 1))
OUT=${OUT:-bench/tmp/fuzz-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
OUT=$(readlink -f "$OUT")

if [ ! -f "$BUILD/CMakeCache.txt" ]; then
  CXX_FUZZ=${CXX:-clang++}
  cmake -S . -B "$BUILD" -G Ninja -DAGENSIO_FUZZ=ON -DAGENSIO_TESTS=OFF -DAGENSIO_TLS=ON \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_CXX_COMPILER="$CXX_FUZZ" >/dev/null || exit 1
fi
cmake --build "$BUILD" >/dev/null || { echo "fuzz build failed"; exit 1; }

# The longest input each target is given (the parsers' natural sizes); others take libFuzzer's.
max_len() {
  case $1 in parser|json) echo 4096 ;; archive) echo 65536 ;; quic_packet) echo 2048 ;; h2_conn) echo 8192 ;; *) echo 0 ;; esac
}
if [ $# -gt 0 ]; then names=("$@")
else names=(); for f in "$BUILD"/fuzz_*; do [ -x "$f" ] && names+=("${f##*/fuzz_}"); done; fi
BUILD=$(readlink -f "$BUILD")

# The processes the machine holds: its cores, or its free memory at 600 MB a process.
cores=$(nproc)
avail_mb=$(awk '/^MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null)
procs=$cores
[ -n "$avail_mb" ] && [ $(( avail_mb / 600 )) -lt "$procs" ] && procs=$(( avail_mb / 600 ))
[ "$procs" -ge 1 ] || procs=1
if [ -z "$JOBS" ]; then JOBS=${#names[@]}; [ "$JOBS" -le "$procs" ] || JOBS=$procs; fi
[ "$JOBS" -ge 1 ] || JOBS=1
if [ -z "$WORKERS" ]; then WORKERS=$(( procs / JOBS )); fi
[ "$WORKERS" -ge 1 ] || WORKERS=1
echo "${#names[@]} fuzzer(s), $JOBS at once, $WORKERS process(es) each, $SECS s ($cores cores, ${avail_mb:-?} MB free)"

run_one() {
  local n=$1 bin="$BUILD/fuzz_$1" corpus="$OUT/corpus/$1" seeds="$PWD/tests/fuzz/regressions/$1" work="$OUT/work/$1" args=()
  mkdir -p "$corpus" "$OUT/findings/$1" "$work"
  [ -d "$seeds" ] && args+=("$seeds")
  local ml; ml=$(max_len "$n"); [ "$ml" != 0 ] && args+=("-max_len=$ml")
  # Several processes: libFuzzer's -jobs, each a fuzzer of its own on the shared corpus (it reloads
  # what the others find), its log fuzz-N.log in the work directory, appended to the fuzzer's log.
  [ "$WORKERS" -gt 1 ] && args+=("-jobs=$WORKERS" "-workers=$WORKERS")
  # -print_funcs=0: no symbolizer for each newly covered function (with every fuzzer starting at
  # once they stalled each other for half a minute); a crash's report is still symbolized.
  (cd "$work" && "$bin" "$corpus" "${args[@]}" -max_total_time="$SECS" -timeout=10 -rss_limit_mb=2048 -print_funcs=0 \
         -artifact_prefix="$OUT/findings/$1/" -print_final_stats=1 > "$OUT/$1.log" 2>&1)
  echo $? > "$OUT/$1.rc"
  for f in "$work"/fuzz-*.log; do [ -f "$f" ] && cat "$f" >> "$OUT/$1.log"; done
  rm -rf "$work"
}
export -f run_one max_len; export OUT BUILD SECS WORKERS
printf '%s\n' "${names[@]}" | xargs -P "$JOBS" -I{} bash -c 'run_one {}'

# The table: libFuzzer's final lines ("#N DONE cov: C ft: F corp: K/...") and its stats, over the
# fuzzer's processes: the runs summed, the longest time, the highest coverage and corpus.
fail=0
{
  echo "| fuzzer | runs | seconds | cov | corpus | result |"
  echo "|---|---|---|---|---|---|"
  for n in "${names[@]}"; do
    log="$OUT/$n.log"; rc=$(cat "$OUT/$n.rc" 2>/dev/null || echo 1)
    runs=$(sed -n 's/^stat::number_of_executed_units: *//p' "$log" | awk '{s += $1} END {if (NR) print s}')
    took=$(sed -n 's/^Done [0-9]* runs in \([0-9]*\) second.*/\1/p' "$log" | sort -n | tail -1)
    cov=$(grep -o 'cov: [0-9]*' "$log" | awk '{print $2}' | sort -n | tail -1)
    corp=$(grep -o 'corp: [0-9]*' "$log" | awk '{print $2}' | sort -n | tail -1)
    if [ "$rc" = 0 ] && [ -z "$(ls -A "$OUT/findings/$n")" ]; then res="clean"
    else res="FINDING (rc $rc): $(grep -m1 -E 'ERROR: (AddressSanitizer|libFuzzer|LeakSanitizer)|runtime error' "$log" | cut -c1-120)"; fail=1; fi
    echo "| $n | ${runs:-?} | ${took:-?} | ${cov:-?} | ${corp:-?} | $res |"
  done
} | tee "$OUT/summary.md"
echo "logs, corpora and findings: $OUT"
exit $fail
