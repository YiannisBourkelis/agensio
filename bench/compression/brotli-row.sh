#!/usr/bin/env bash
# One proxied, compressed row by hand, with page faults (bench/results/brotli-faults-20261031.md):
# for each binary given, the proxy site with response_compression on in front of the benchmark
# upstream (build/agensio_upstream on 9100), wrk with one Accept-Encoding (HDR, default br) on one
# URL (URL, default /page, the upstream's 32 KB page), two rounds, CPU microseconds and minor page
# faults per request read from /proc. Run in the devbox:
#   docker run --rm --network none -v $PWD:$PWD -w $PWD --user $(id -u):$(id -g) agensio-devbox \
#     bench/compression/brotli-row.sh bench/tmp/ab/<base>/build/agensio build/agensio
# MALLOC_TRIM_THRESHOLD_ and MALLOC_MMAP_THRESHOLD_ in the environment reach the server, to try
# glibc's thresholds without a rebuild.
set -uo pipefail
ROOT=$(pwd); T=$ROOT/bench/tmp/brotli-row; mkdir -p "$T"
HDR=${HDR:-br}; URL=${URL:-/page}; D=${D:-5s}
cat > "$T/agensio.toml" <<TOML
[server]
workers = 1
idle_timeout = 65
max_requests_per_connection = 1000000
reuse_port = "auto"
tcp_nodelay = true
[log]
access = "off"
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:8085"]
root = "$ROOT/bench/www"
response_compression = "on"
[[site.location]]
path = "/"
upstream = "http://127.0.0.1:9100"
TOML
"$ROOT/build/agensio_upstream" -p 9100 -w 1 > "$T/upstream.log" 2>&1 & UP=$!
sleep 0.3
cpu() { awk -v tck="$(getconf CLK_TCK)" '{ printf "%.3f", ($14+$15)/tck }' "/proc/$1/stat"; }
flt() { awk '{ print $10 }' "/proc/$1/stat"; }
for round in 1 2; do
  for BIN in "$@"; do
    "$BIN" -c "$T/agensio.toml" > "$T/server.log" 2>&1 & PID=$!
    for _ in $(seq 1 50); do nc -z 127.0.0.1 8085 2>/dev/null && break; sleep 0.1; done
    curl -sS -o /dev/null -H "Accept-Encoding: $HDR" "http://127.0.0.1:8085$URL"
    wrk -t4 -c64 -d2s -H "Accept-Encoding: $HDR" "http://127.0.0.1:8085$URL" > /dev/null 2>&1
    c0=$(cpu $PID); f0=$(flt $PID)
    out=$(wrk -t4 -c64 -d$D -H "Accept-Encoding: $HDR" "http://127.0.0.1:8085$URL")
    c1=$(cpu $PID); f1=$(flt $PID)
    reqs=$(echo "$out" | awk '/requests in/{print $1}')
    rps=$(echo "$out" | awk '/Requests\/sec/{print $2}')
    bytes=$(echo "$out" | awk '/Transfer\/sec/{print $2}')
    echo "round $round $BIN: $(awk -v a=$c0 -v b=$c1 -v n=$reqs 'BEGIN{printf "%.1f", (b-a)*1e6/n}') us/req, $(awk -v a=$f0 -v b=$f1 -v n=$reqs 'BEGIN{printf "%.1f", (b-a)/n}') faults/req, $rps req/s, $bytes/s"
    kill $PID; wait $PID 2>/dev/null
  done
done
kill $UP; wait $UP 2>/dev/null
