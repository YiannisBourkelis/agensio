#!/usr/bin/env bash
# The comp-gzip row by hand: a static site with response_compression on, the 100 KB /style.css
# asked with Accept-Encoding: gzip (its gzip copy from memory), one worker, wrk 4x64 for 5 s after 2 s
# of warm-up; CPU us per request from /proc, instructions and L1 instruction-cache misses per request
# from perf stat (work against layout). Sides: base, new. Alternated, ROUNDS rounds.
# Run in the perf devbox: docker run --rm --cap-add SYS_ADMIN --cap-add PERFMON --user root ...
#   agensio-devbox-perf:latest bench/compression/gzip-row.sh BASE_BINARY NEW_BINARY
set -uo pipefail
ROOT=$(pwd); T=$ROOT/bench/tmp/gzip-row; mkdir -p "$T"; BASE=$1; NEW=$2; ROUNDS=${ROUNDS:-4}
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
response_compression = @ON@
TOML
# The switch as each binary spells it: true since 2026-10-31, "on" in the binaries before.
conf_for() {
  sed 's/@ON@/true/' "$T/agensio.toml" > "$T/agensio-side.toml"
  "$1" -t -c "$T/agensio-side.toml" > /dev/null 2>&1 || sed 's/@ON@/"on"/' "$T/agensio.toml" > "$T/agensio-side.toml"
  echo "$T/agensio-side.toml"
}
cpu() { awk -v tck="$(getconf CLK_TCK)" '{ printf "%.3f", ($14+$15)/tck }' "/proc/$1/stat"; }
flt() { awk '{ print $10 }' "/proc/$1/stat"; }
side() {  # name binary [env...]
  local name=$1 bin=$2; shift 2
  local conf; conf=$(conf_for "$bin")
  env "$@" "$bin" -c "$conf" > "$T/server.log" 2>&1 & local PID=$!
  for _ in $(seq 1 50); do nc -z 127.0.0.1 8087 2>/dev/null && break; sleep 0.1; done
  wrk -t4 -c64 -d2s -H "Accept-Encoding: gzip" http://127.0.0.1:8087/style.css > /dev/null 2>&1
  local c0 f0 c1 f1 out reqs
  c0=$(cpu $PID); f0=$(flt $PID)
  perf stat -x, -e instructions,L1-icache-load-misses -p $PID -o "$T/perf.txt" -- sleep 5 > /dev/null 2>&1 &
  local PP=$!
  out=$(wrk -t4 -c64 -d5s -H "Accept-Encoding: gzip" http://127.0.0.1:8087/style.css)
  wait $PP
  c1=$(cpu $PID); f1=$(flt $PID)
  reqs=$(echo "$out" | awk '/requests in/{print $1}')
  local ins mis
  ins=$(awk -F, '/instructions/{print $1}' "$T/perf.txt"); mis=$(awk -F, '/L1-icache-load-misses/{print $1}' "$T/perf.txt")
  echo "$name $(awk -v a=$c0 -v b=$c1 -v n=$reqs 'BEGIN{printf "%.2f", (b-a)*1e6/n}') $(awk -v i=$ins -v n=$reqs 'BEGIN{printf "%.0f", i/n}') $(awk -v m=$mis -v n=$reqs 'BEGIN{printf "%.1f", m/n}')"
  kill $PID; wait $PID 2>/dev/null; sleep 0.3
}
for r in $(seq 1 $ROUNDS); do
  side base "$BASE"
  side new "$NEW"
done | awk '{s[$1]+=$2; i[$1]+=$3; m[$1]+=$4; n[$1]++; all[$1]=all[$1] " " $2} END{for (k in s) printf "%-5s us/req %s  mean %.2f  instructions/req %.0f  L1i misses/req %.1f\n", k, all[k], s[k]/n[k], i[k]/n[k], m[k]/n[k]}'
