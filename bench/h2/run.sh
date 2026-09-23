#!/usr/bin/env bash
# HTTP/2 benchmark (phase G): agensio against nginx and Caddy with h2load (nghttp2), the
# same static docroot, certificate and ports as bench/run.sh, the same metric: server CPU
# microseconds per request (CPU time of the server's processes over h2load's request
# count) plus RSS. Each row is "proto:path:connections:streams": h2c is prior-knowledge
# HTTP/2 on the plain port, h2 is HTTP/2 through ALPN on the TLS port.
#
# usage: bench/h2/run.sh [-w WORKERS] [-t THREADS] [-d SECONDS] [-s "agensio nginx caddy"] [-u ROWSPEC ...]
#   -w  server workers (agensio workers, nginx worker_processes, caddy GOMAXPROCS), default 1
#   -t  h2load threads, default 4
#   -d  seconds per row, default 5 (h2load runs a request count: derived from a 1 s probe)
#   -u  "proto:path:conns:streams", repeatable; default the six rows of docs/design-http2.md 7.4
# Results: bench/results/h2-<stamp>.md, raw h2load output in bench/results/raw/h2-<stamp>/.
set -euo pipefail
BENCH="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(dirname "$BENCH")"
WORKERS=1; THREADS=4; DURATION=5; SERVERS="agensio nginx caddy"; SPECS=()
while getopts "w:t:d:s:u:" opt; do
  case $opt in
    w) WORKERS=$OPTARG ;; t) THREADS=$OPTARG ;; d) DURATION=$OPTARG ;; s) SERVERS=$OPTARG ;; u) SPECS+=("$OPTARG") ;; *) exit 2 ;;
  esac
done
[ ${#SPECS[@]} -eq 0 ] && SPECS=("h2c:/:64:1" "h2c:/:64:10" "h2:/:64:1" "h2:/:64:10" "h2:/style.css:64:10" "h2:/big.bin:16:1" "h2:/:256:10")
for tool in h2load curl; do command -v "$tool" >/dev/null || { echo "missing tool: $tool (Debian: nghttp2-client)"; exit 1; }; done
AGENSIO_BIN="${AGENSIO_BIN:-$ROOT/build/agensio}"   # a sanitizer build, for instance
[ -x "$AGENSIO_BIN" ] || { echo "build first: cmake --build build"; exit 1; }
[ -f "$BENCH/www/big.bin" ] || "$BENCH/gen-www.sh" >/dev/null
[ -f "$BENCH/certs/cert.pem" ] || "$BENCH/certs/gen-cert.sh" >/dev/null
export LC_NUMERIC=C
ulimit -n 65536 2>/dev/null || true
mkdir -p "$BENCH/tmp" "$BENCH/results/raw"
STAMP=$(date +%Y%m%d-%H%M%S); RAW="$BENCH/results/raw/h2-$STAMP"; mkdir -p "$RAW"
OUT="$BENCH/results/h2-$STAMP.md"

# ---- configs (as bench/run.sh) ----
sed "s#@WORKERS@#$WORKERS#g; s#@BENCH@#$BENCH#g; s#@ACCESS_LOG@##g; s#@SENDFILE_MIN@#48KB#g" "$BENCH/agensio.toml" > "$BENCH/tmp/agensio-h2.toml"
NGINX_WORKERS=$WORKERS; [ "$WORKERS" = 0 ] && NGINX_WORKERS=auto
sed "s#@WORKERS@#$NGINX_WORKERS#g; s#@BENCH@#$BENCH#g" "$BENCH/nginx.conf" > "$BENCH/tmp/nginx-h2.conf"

port() { case "$1-$2" in agensio-h2c) echo 8080 ;; agensio-h2) echo 8443 ;; nginx-h2c) echo 8081 ;; nginx-h2) echo 8444 ;; caddy-h2c) echo 8082 ;; caddy-h2) echo 8445 ;; esac; }
busy() { curl -sS -o /dev/null --max-time 1 "http://127.0.0.1:$1/" 2>/dev/null; }
for s in $SERVERS; do for p in h2c h2; do busy "$(port $s $p)" && { echo "port $(port $s $p) is busy: stop whatever serves it"; exit 1; }; done; done

start_server() {
  case $1 in
    agensio) "$AGENSIO_BIN" -c "$BENCH/tmp/agensio-h2.toml" >"$RAW/$1.log" 2>&1 & ;;
    nginx)   (cd "$BENCH" && exec nginx -p "$BENCH" -c "$BENCH/tmp/nginx-h2.conf" -g 'daemon off;') >"$RAW/$1.log" 2>&1 & ;;
    caddy)   if [ "$WORKERS" = "0" ]; then (cd "$BENCH" && exec caddy run --config Caddyfile --adapter caddyfile) >"$RAW/$1.log" 2>&1 &
             else (cd "$BENCH" && GOMAXPROCS=$WORKERS exec caddy run --config Caddyfile --adapter caddyfile) >"$RAW/$1.log" 2>&1 & fi ;;
  esac
  for _ in $(seq 1 50); do busy "$(port $1 h2c)" && return 0; sleep 0.1; done
  echo "$1 did not start"; cat "$RAW/$1.log"; exit 1
}
stop_server() { pkill -f "^$1( |:)" 2>/dev/null || true; pkill -x "$1" 2>/dev/null || true; sleep 0.5; }
pids_of() { case $1 in nginx) pgrep -f 'nginx: ' ;; *) pgrep -x "$1" ;; esac; }
cpu_of() { local t=0; for p in $(pids_of $1); do t=$((t + $(awk '{print $14+$15}' /proc/$p/stat 2>/dev/null || echo 0))); done; echo $t; }  # clock ticks
rss_of() { local t=0; for p in $(pids_of $1); do t=$((t + $(awk '/^VmRSS/{print $2}' /proc/$p/status 2>/dev/null || echo 0))); done; echo $t; }
HZ=$(getconf CLK_TCK)

run_row() {  # server proto path conns streams
  local s=$1 proto=$2 path=$3 conns=$4 streams=$5 url opts
  if [ "$proto" = h2c ]; then url="http://127.0.0.1:$(port $s h2c)$path"; opts=""; else url="https://127.0.0.1:$(port $s h2)$path"; opts=""; fi
  # h2load needs a request count: a 1 s probe sizes it for DURATION seconds.
  local probe; probe=$(h2load -D 1 -c "$conns" -m "$streams" -t "$THREADS" $opts "$url" 2>/dev/null | awk '/^finished in/{print $4}')
  local n=$(( ${probe%%.*} * DURATION )); [ "$n" -lt 1000 ] && n=1000
  local c0 c1 t0 t1
  c0=$(cpu_of $s); t0=$(date +%s.%N)
  h2load -n "$n" -c "$conns" -m "$streams" -t "$THREADS" $opts "$url" > "$RAW/$s-$proto-${path//\//_}-$conns-$streams.txt" 2>&1
  t1=$(date +%s.%N); c1=$(cpu_of $s)
  local out="$RAW/$s-$proto-${path//\//_}-$conns-$streams.txt"
  local done_n; done_n=$(awk '/^requests:/{print $4}' "$out")
  local rps; rps=$(awk '/^finished in/{print $4}' "$out")
  local failed; failed=$(awk '/^requests:/{print $10}' "$out")
  local us; us=$(awk -v c=$((c1 - c0)) -v hz=$HZ -v n="$done_n" 'BEGIN{ if (n>0) printf "%.2f", c/hz*1e6/n; else print "-" }')
  printf "| %s | %s %s c=%s m=%s | %s | %s | %s | %s KB |\n" "$s" "$proto" "$path" "$conns" "$streams" "$us" "$rps" "$failed" "$(( $(rss_of $s) ))" >> "$OUT"
  printf "  %-8s %-4s %-12s c=%-4s m=%-3s %8s us/req %12s req/s  failed %s\n" "$s" "$proto" "$path" "$conns" "$streams" "$us" "$rps" "$failed"
}

{
  echo "# HTTP/2 benchmark $STAMP"
  echo
  echo "- machine: $(uname -m), $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //'), $(uname -sr)"
  echo "- agensio $(git -C "$ROOT" rev-parse --short HEAD)$(git -C "$ROOT" diff --quiet HEAD -- src || echo '+dirty'), workers=$WORKERS; nginx $(nginx -v 2>&1 | sed 's#nginx version: ##'); caddy $(caddy version 2>/dev/null | awk '{print $1}')"
  echo "- h2load $(h2load --version | head -1), threads=$THREADS, about ${DURATION} s per row; CPU us/req = server CPU time / requests done; RSS after the row"
  echo
  echo "| server | row | CPU us/req | req/s | failed | RSS |"
  echo "|---|---|---|---|---|---|"
} > "$OUT"
for s in $SERVERS; do
  command -v "$s" >/dev/null || [ "$s" = agensio ] || { echo "skip $s (not installed)"; continue; }
  start_server "$s"
  sleep 0.5
  for spec in "${SPECS[@]}"; do IFS=: read -r proto path conns streams <<< "$spec"; run_row "$s" "$proto" "$path" "$conns" "$streams"; done
  stop_server "$s"
done
echo "summary written to $OUT"
