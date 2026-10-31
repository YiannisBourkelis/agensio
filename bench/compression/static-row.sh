#!/usr/bin/env bash
# The comp-plain row by hand (bench/results/brotli-faults-20261031.md, last section): a static site with response_compression on, the 100 KB /style.css
# without Accept-Encoding, one worker, wrk 4x64 for 5 s after 2 s of warm-up; CPU us and minor
# faults per request from /proc. Sides: base, base with glibc's thresholds from the environment
# (what tune_heap sets), new. Alternated, ROUNDS rounds.
# Run in the devbox: bench/compression/static-row.sh BASE_BINARY NEW_BINARY
set -uo pipefail
ROOT=$(pwd); T=$ROOT/bench/tmp/static-row; mkdir -p "$T"; BASE=$1; NEW=$2; ROUNDS=${ROUNDS:-4}
cat > "$T/agensio.toml" <<TOML
[server]
workers = 1
idle_timeout = 65
max_requests_per_connection = 1000000
reuse_port = "auto"
tcp_nodelay = true
sendfile = true
[log]
access = "off"
[cache]
max_file_size = "4MB"
max_size = "256MB"
sendfile_min_size = "48KB"
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:8087"]
root = "$ROOT/bench/www"
response_compression = "on"
TOML
cpu() { awk -v tck="$(getconf CLK_TCK)" '{ printf "%.3f", ($14+$15)/tck }' "/proc/$1/stat"; }
flt() { awk '{ print $10 }' "/proc/$1/stat"; }
side() {  # name binary [env...]
  local name=$1 bin=$2; shift 2
  env "$@" "$bin" -c "$T/agensio.toml" > "$T/server.log" 2>&1 & local PID=$!
  for _ in $(seq 1 50); do nc -z 127.0.0.1 8087 2>/dev/null && break; sleep 0.1; done
  wrk -t4 -c64 -d2s http://127.0.0.1:8087/style.css > /dev/null 2>&1
  local c0 f0 c1 f1 out reqs
  c0=$(cpu $PID); f0=$(flt $PID)
  out=$(wrk -t4 -c64 -d5s http://127.0.0.1:8087/style.css)
  c1=$(cpu $PID); f1=$(flt $PID)
  reqs=$(echo "$out" | awk '/requests in/{print $1}')
  echo "$name $(awk -v a=$c0 -v b=$c1 -v n=$reqs 'BEGIN{printf "%.2f", (b-a)*1e6/n}') $(awk -v a=$f0 -v b=$f1 -v n=$reqs 'BEGIN{printf "%.3f", (b-a)/n}')"
  kill $PID; wait $PID 2>/dev/null; sleep 0.3
}
for r in $(seq 1 $ROUNDS); do
  side base "$BASE"
  side base+env "$BASE" MALLOC_MMAP_THRESHOLD_=2097152 MALLOC_TRIM_THRESHOLD_=8388608
  side new "$NEW"
done | awk '{s[$1]+=$2; f[$1]+=$3; n[$1]++; all[$1]=all[$1] " " $2} END{for (k in s) printf "%-9s us/req %s  mean %.2f  faults/req %.3f\n", k, all[k], s[k]/n[k], f[k]/n[k]}'
