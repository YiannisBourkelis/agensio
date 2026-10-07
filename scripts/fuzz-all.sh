#!/usr/bin/env bash
# Every libFuzzer target for a fixed time on its checked-in corpus, then one table: runs,
# coverage, corpus size and the verdict. The campaign before a tag, the weekly CI job and a
# check after a parser change all run this (docs/security-control-plane.md, "Sanitizer and
# fuzz record"). New inputs land in a scratch corpus, never in tests/fuzz/regressions/;
# a finding (crash, leak, timeout, sanitizer report) is kept under the output directory
# with its log, and the script exits 1.
#
# usage: scripts/fuzz-all.sh [-t SECONDS] [-j JOBS] [-o DIR] [-b BUILD_DIR] [fuzzer ...]
#   -t  seconds per fuzzer (default 60)
#   -j  fuzzers run at once (default half the CPUs)
#   -o  output directory (default bench/tmp/fuzz-<stamp>)
#   -b  the fuzz build directory (default build-fuzz-all; configured here when missing, with
#       clang++ or $CXX, TLS on so fuzz_quic_conn is built where OpenSSL has QUIC, 3.5+)
#   fuzzer names without the fuzz_ prefix (default: every target the build has)
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
SECS=60; JOBS=$(( $(nproc) / 2 )); OUT=""; BUILD=build-fuzz-all
while getopts "t:j:o:b:" opt; do
  case $opt in t) SECS=$OPTARG ;; j) JOBS=$OPTARG ;; o) OUT=$OPTARG ;; b) BUILD=$OPTARG ;; *) exit 2 ;; esac
done
shift $((OPTIND - 1))
[ "$JOBS" -ge 1 ] || JOBS=1
OUT=${OUT:-bench/tmp/fuzz-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"

if [ ! -f "$BUILD/CMakeCache.txt" ]; then
  CXX_FUZZ=${CXX:-clang++}
  cmake -S . -B "$BUILD" -G Ninja -DAGENSIO_FUZZ=ON -DAGENSIO_TESTS=OFF -DAGENSIO_TLS=ON \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_CXX_COMPILER="$CXX_FUZZ" >/dev/null || exit 1
fi
cmake --build "$BUILD" >/dev/null || { echo "fuzz build failed"; exit 1; }

# The longest input each target is given (the parsers' natural sizes); others take libFuzzer's.
max_len() {
  case $1 in parser|json) echo 4096 ;; archive) echo 65536 ;; quic_packet) echo 2048 ;; *) echo 0 ;; esac
}
if [ $# -gt 0 ]; then names=("$@")
else names=(); for f in "$BUILD"/fuzz_*; do [ -x "$f" ] && names+=("${f##*/fuzz_}"); done; fi

run_one() {
  local n=$1 bin="$BUILD/fuzz_$1" corpus="$OUT/corpus/$1" seeds="tests/fuzz/regressions/$1" args=()
  mkdir -p "$corpus" "$OUT/findings/$1"
  [ -d "$seeds" ] && args+=("$seeds")
  local ml; ml=$(max_len "$n"); [ "$ml" != 0 ] && args+=("-max_len=$ml")
  "$bin" "$corpus" "${args[@]}" -max_total_time="$SECS" -timeout=10 -rss_limit_mb=2048 \
         -artifact_prefix="$OUT/findings/$1/" -print_final_stats=1 > "$OUT/$1.log" 2>&1
  echo $? > "$OUT/$1.rc"
}
export -f run_one max_len; export OUT BUILD SECS
printf '%s\n' "${names[@]}" | xargs -P "$JOBS" -I{} bash -c 'run_one {}'

# The table: libFuzzer's final line ("#N DONE cov: C ft: F corp: K/...") and its stats.
fail=0
{
  echo "| fuzzer | runs | seconds | cov | corpus | result |"
  echo "|---|---|---|---|---|---|"
  for n in "${names[@]}"; do
    log="$OUT/$n.log"; rc=$(cat "$OUT/$n.rc" 2>/dev/null || echo 1)
    runs=$(sed -n 's/^stat::number_of_executed_units: *//p' "$log" | tail -1)
    took=$(sed -n 's/^Done [0-9]* runs in \([0-9]*\) second.*/\1/p' "$log" | tail -1)
    cov=$(grep -o 'cov: [0-9]*' "$log" | tail -1 | awk '{print $2}')
    corp=$(grep -o 'corp: [0-9]*' "$log" | tail -1 | awk '{print $2}')
    if [ "$rc" = 0 ] && [ -z "$(ls -A "$OUT/findings/$n")" ]; then res="clean"
    else res="FINDING (rc $rc): $(grep -m1 -E 'ERROR: (AddressSanitizer|libFuzzer|LeakSanitizer)|runtime error' "$log" | cut -c1-120)"; fail=1; fi
    echo "| $n | ${runs:-?} | ${took:-?} | ${cov:-?} | ${corp:-?} | $res |"
  done
} | tee "$OUT/summary.md"
echo "logs, corpora and findings: $OUT"
exit $fail
