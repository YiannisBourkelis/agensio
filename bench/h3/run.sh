#!/usr/bin/env bash
# HTTP/3 benchmark (phase I, docs/design-http3.md 8.3): agensio against nginx and Caddy with
# h2load over QUIC, the same static docroot, certificate and ports as bench/h2/run.sh, the
# same metric: server CPU microseconds per request (CPU time of the server's processes over
# h2load's request count) plus RSS. Each row is "h3:path:connections:streams", h2load
# --alpn-list=h3 against the TLS port over UDP (agensio 8443, nginx 8444, Caddy 8445).
# H2LOAD names an h2load built with QUIC (Debian's is not; the devbox carries one under
# /opt/nghttp2/bin, the arena's image is docker run --network host h2load-h3:local h2load).
#
# usage: bench/h3/run.sh [-w WORKERS] [-t THREADS] [-d SECONDS] [-s "agensio nginx caddy"] [-u ROWSPEC ...]
#   -w  server workers (agensio workers, nginx worker_processes, caddy GOMAXPROCS), default 1
#   -t  h2load threads, default 4
#   -d  seconds per row, default 5 (h2load runs a request count: derived from a 1 s probe)
#   -u  "h3:path:conns:streams", repeatable; default the six rows of docs/design-http3.md 8.3
# Results: bench/results/h3-<stamp>.md, raw h2load output in bench/results/raw/h3-<stamp>/.
set -euo pipefail
BENCH="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(dirname "$BENCH")"
WORKERS=1; THREADS=4; DURATION=5; SERVERS="agensio nginx caddy"; SPECS=()
while getopts "w:t:d:s:u:" opt; do
  case $opt in
    w) WORKERS=$OPTARG ;; t) THREADS=$OPTARG ;; d) DURATION=$OPTARG ;; s) SERVERS=$OPTARG ;; u) SPECS+=("$OPTARG") ;; *) exit 2 ;;
  esac
done
[ ${#SPECS[@]} -eq 0 ] && SPECS=("h3:/:64:1" "h3:/:64:10" "h3:/:64:64" "h3:/style.css:64:10" "h3:/big.bin:16:1" "h3:/:256:10")
H2LOAD="${H2LOAD:-$( [ -x /opt/nghttp2/bin/h2load ] && echo /opt/nghttp2/bin/h2load || echo h2load )}"
$H2LOAD --help 2>&1 | grep -q 'udp-gso' || { echo "$H2LOAD has no QUIC support (set H2LOAD to one that has)"; exit 1; }
command -v curl >/dev/null || { echo "missing tool: curl"; exit 1; }
AGENSIO_BIN="${AGENSIO_BIN:-$ROOT/build/agensio}"
[ -x "$AGENSIO_BIN" ] || { echo "build first: cmake --build build"; exit 1; }
[ -f "$BENCH/www/big.bin" ] || "$BENCH/gen-www.sh" >/dev/null
[ -f "$BENCH/certs/cert.pem" ] || "$BENCH/certs/gen-cert.sh" >/dev/null
export LC_NUMERIC=C
ulimit -n 65536 2>/dev/null || true
mkdir -p "$BENCH/tmp" "$BENCH/results/raw"
STAMP=$(date +%Y%m%d-%H%M%S); RAW="$BENCH/results/raw/h3-$STAMP"; mkdir -p "$RAW"
OUT="$BENCH/results/h3-$STAMP.md"

# ---- configs (as bench/run.sh, with h3 on the TLS listener) ----
sed "s#@WORKERS@#$WORKERS#g; s#@BENCH@#$BENCH#g; s#@ACCESS_LOG@##g; s#@SENDFILE_MIN@#48KB#g; s#@H3@#, \"h3\"#g" "$BENCH/agensio.toml" > "$BENCH/tmp/agensio-h3.toml"
NGINX_WORKERS=$WORKERS; [ "$WORKERS" = 0 ] && NGINX_WORKERS=auto
# nginx: the TLS server also listens with quic on the same port (needs the http_v3 module).
sed "s#@WORKERS@#$NGINX_WORKERS#g; s#@BENCH@#$BENCH#g; s#listen 127.0.0.1:8444 ssl backlog=4096;#listen 127.0.0.1:8444 ssl backlog=4096;\n        listen 127.0.0.1:8444 quic reuseport;\n        http3 on;#" "$BENCH/nginx.conf" > "$BENCH/tmp/nginx-h3.conf"

# Caddy: the bench Caddyfile keeps h3 off for the HTTP/2 rows; here it is on (UDP 8445).
sed 's/protocols h1 h2 h2c/protocols h1 h2 h2c h3/' "$BENCH/Caddyfile" > "$BENCH/tmp/Caddyfile-h3"

port() { case "$1" in agensio) echo 8443 ;; nginx) echo 8444 ;; caddy) echo 8445 ;; esac; }
busy() { curl -sS -o /dev/null --max-time 1 -k "https://127.0.0.1:$1/" 2>/dev/null; }
for s in $SERVERS; do busy "$(port $s)" && { echo "port $(port $s) is busy: stop whatever serves it"; exit 1; }; done

start_server() {
  case $1 in
    agensio) "$AGENSIO_BIN" -c "$BENCH/tmp/agensio-h3.toml" >"$RAW/$1.log" 2>&1 & ;;
    nginx)   (cd "$BENCH" && exec nginx -p "$BENCH" -c "$BENCH/tmp/nginx-h3.conf" -g 'daemon off;') >"$RAW/$1.log" 2>&1 & ;;
    caddy)   if [ "$WORKERS" = "0" ]; then (cd "$BENCH" && exec caddy run --config tmp/Caddyfile-h3 --adapter caddyfile) >"$RAW/$1.log" 2>&1 &
             else (cd "$BENCH" && GOMAXPROCS=$WORKERS exec caddy run --config tmp/Caddyfile-h3 --adapter caddyfile) >"$RAW/$1.log" 2>&1 & fi ;;
  esac
  for _ in $(seq 1 50); do busy "$(port $1)" && return 0; sleep 0.1; done
  echo "$1 did not start"; cat "$RAW/$1.log"; exit 1
}
stop_server() { pkill -f "^$1( |:)" 2>/dev/null || true; pkill -x "$1" 2>/dev/null || true; sleep 0.5; }
pids_of() { case $1 in nginx) pgrep -f 'nginx: ' ;; *) pgrep -x "$1" ;; esac; }
cpu_of() { local t=0; for p in $(pids_of $1); do t=$((t + $(awk '{print $14+$15}' /proc/$p/stat 2>/dev/null || echo 0))); done; echo $t; }  # clock ticks
rss_of() { local t=0; for p in $(pids_of $1); do t=$((t + $(awk '/^VmRSS/{print $2}' /proc/$p/status 2>/dev/null || echo 0))); done; echo $t; }
HZ=$(getconf CLK_TCK)

run_row() {  # server path conns streams
  local s=$1 path=$2 conns=$3 streams=$4 url
  url="https://127.0.0.1:$(port $s)$path"
  # A first request proves the server speaks h3 at all (curl's own QUIC).
  if ! curl -sk --http3-only -m 3 -o /dev/null "$url"; then echo "  $s: no HTTP/3 answer on $url"; printf "| %s | h3 %s c=%s m=%s | - | - | no h3 | - |\n" "$s" "$path" "$conns" "$streams" >> "$OUT"; return; fi
  local probe; probe=$($H2LOAD --alpn-list=h3 -D 1 -c "$conns" -m "$streams" -t "$THREADS" "$url" 2>/dev/null | awk '/^finished in/{print $4}')
  local n=$(( ${probe%%.*} * DURATION )); [ "$n" -lt 1000 ] && n=1000
  local c0 c1
  c0=$(cpu_of $s)
  local out="$RAW/$s-h3-${path//\//_}-$conns-$streams.txt"
  $H2LOAD --alpn-list=h3 -n "$n" -c "$conns" -m "$streams" -t "$THREADS" "$url" > "$out" 2>&1
  c1=$(cpu_of $s)
  local done_n; done_n=$(awk '/^requests:/{print $4}' "$out")
  local rps; rps=$(awk '/^finished in/{print $4}' "$out")
  local failed; failed=$(awk '/^requests:/{print $10}' "$out")
  local us; us=$(awk -v c=$((c1 - c0)) -v hz=$HZ -v n="$done_n" 'BEGIN{ if (n>0) printf "%.2f", c/hz*1e6/n; else print "-" }')
  printf "| %s | h3 %s c=%s m=%s | %s | %s | %s | %s KB |\n" "$s" "$path" "$conns" "$streams" "$us" "$rps" "$failed" "$(( $(rss_of $s) ))" >> "$OUT"
  printf "  %-8s h3   %-12s c=%-4s m=%-3s %8s us/req %12s req/s  failed %s\n" "$s" "$path" "$conns" "$streams" "$us" "$rps" "$failed"
}

{
  echo "# HTTP/3 benchmark $STAMP"
  echo
  echo "- machine: $(uname -m), $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //'), $(uname -sr)"
  echo "- agensio $(git -C "$ROOT" rev-parse --short HEAD)$(git -C "$ROOT" diff --quiet HEAD -- src || echo '+dirty'), workers=$WORKERS; nginx $(nginx -v 2>&1 | sed 's#nginx version: ##'); caddy $(caddy version 2>/dev/null | awk '{print $1}')"
  echo "- $($H2LOAD --version | head -1) ($H2LOAD), threads=$THREADS, about ${DURATION} s per row; CPU us/req = server CPU time / requests done; RSS after the row"
  echo
  echo "| server | row | CPU us/req | req/s | failed | RSS |"
  echo "|---|---|---|---|---|---|"
} > "$OUT"
for s in $SERVERS; do
  command -v "$s" >/dev/null || [ "$s" = agensio ] || { echo "skip $s (not installed)"; continue; }
  start_server "$s"
  sleep 0.5
  for spec in "${SPECS[@]}"; do IFS=: read -r _ path conns streams <<< "$spec"; run_row "$s" "$path" "$conns" "$streams"; done
  stop_server "$s"
done
echo "summary written to $OUT"
