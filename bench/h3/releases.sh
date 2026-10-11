#!/usr/bin/env bash
# The h3 row "h3:/:64:64" of bench/ab.sh (same config, warm-up, h2load and CPU accounting) for
# several binaries, rotated through ROUNDS rounds in one session (each round starts one binary
# later), so drift and position cancel out: which release, if any, made the row dearer. Run in
# the devbox from the repository root, after a bench/ab.sh -3 run has written
# bench/tmp/ab-agensio-h3.toml; build each release as ab.sh builds its base (bench/tmp/ab/<commit>).
# usage: bench/h3/releases.sh ROUNDS label=binary ...    (2026-10-11: alpha.23 to alpha.69)
set -uo pipefail
ROUNDS=$1; shift
LABELS=(); BINS=()
for a in "$@"; do LABELS+=("${a%%=*}"); BINS+=("$(readlink -f "${a#*=}")"); done
BENCH=$PWD/bench
CFG=$BENCH/tmp/ab-agensio-h3.toml
H2LOAD=/opt/nghttp2/bin/h2load
OUT=$BENCH/tmp/h3-releases; mkdir -p "$OUT"; : > "$OUT/rows"
export LC_NUMERIC=C
ulimit -n 65536 2>/dev/null || true
cpu() { awk -v t="$(getconf CLK_TCK)" '{printf "%.3f", ($14+$15)/t}' "/proc/$1/stat"; }
one() {  # label binary round
  (cd "$BENCH" && exec "$2" -c "$CFG") >> "$OUT/server.log" 2>&1 &
  local pid=$! c0 c1 n
  for _ in $(seq 1 50); do nc -z 127.0.0.1 8443 2>/dev/null && break; sleep 0.1; done
  curl -sk --http3-only -o /dev/null https://127.0.0.1:8443/
  c0=$(cpu $pid)
  $H2LOAD --alpn-list=h3 -D 5 -c64 -m64 -t4 https://127.0.0.1:8443/ > "$OUT/$1-r$3.txt" 2>&1
  c1=$(cpu $pid)
  n=$(awk '/^requests:/{print $6}' "$OUT/$1-r$3.txt")
  kill $pid; wait $pid 2>/dev/null; sleep 0.3
  awk -v l="$1" -v r="$3" -v a="$c0" -v b="$c1" -v n="${n:-0}" 'BEGIN{printf "%s %d %.3f %d\n", l, r, (n>0 ? (b-a)*1e6/n : -1), n}' | tee -a "$OUT/rows"
}
k=${#BINS[@]}
for r in $(seq 1 "$ROUNDS"); do
  for i in $(seq 0 $((k - 1))); do j=$(( (i + r - 1) % k )); one "${LABELS[$j]}" "${BINS[$j]}" "$r"; done
done
echo "--- median us/req (all rounds), relative to the first"
for l in "${LABELS[@]}"; do
  awk -v l="$l" '$1 == l {print $3}' "$OUT/rows" | sort -n | awk -v l="$l" '{v[NR]=$1} END{m = NR%2 ? v[(NR+1)/2] : (v[NR/2]+v[NR/2+1])/2; printf "%s %.3f %.3f %.3f\n", l, m, v[1], v[NR]}'
done | awk 'NR==1{b=$2} {printf "%-10s median %.3f  (min %.3f max %.3f)  x%.3f\n", $1, $2, $3, $4, $2/b}'
