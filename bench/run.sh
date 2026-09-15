#!/usr/bin/env bash
# Benchmarks agensio against nginx and Caddy serving the same static docroot.
#
# usage: bench/run.sh [-d DURATION] [-t THREADS] [-s "agensio nginx caddy"] [-p "http https"] [-u URLSPEC ...]
#   URLSPEC is "path:conns[,conns...]", default: "/:64,256" "/style.css:64,256" "/big.bin:16"
#
# Servers run one at a time so they never compete for CPU. Raw wrk output goes to
# bench/results/raw/, a summary table to bench/results/<timestamp>.md.
set -euo pipefail

BENCH="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$BENCH")"
DURATION=15s
THREADS="$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
SERVERS="agensio nginx caddy"
PROTOS="http https"
URLSPECS=()
while getopts "d:t:s:p:u:" opt; do
  case $opt in
    d) DURATION=$OPTARG ;;
    t) THREADS=$OPTARG ;;
    s) SERVERS=$OPTARG ;;
    p) PROTOS=$OPTARG ;;
    u) URLSPECS+=("$OPTARG") ;;
    *) exit 2 ;;
  esac
done
[ ${#URLSPECS[@]} -eq 0 ] && URLSPECS=("/:64,256" "/style.css:64,256" "/big.bin:16")

for tool in wrk curl nc; do command -v "$tool" >/dev/null || { echo "missing tool: $tool"; exit 1; }; done
[ -x "$ROOT/build/agensio" ] || { echo "build agensio first: cmake --build build"; exit 1; }
[ -f "$BENCH/www/big.bin" ] || "$BENCH/gen-www.sh" >/dev/null
[ -f "$BENCH/certs/cert.pem" ] || "$BENCH/certs/gen-cert.sh" >/dev/null
ulimit -n 65536 2>/dev/null || true

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$BENCH/results/$STAMP.md"
RAW="$BENCH/results/raw/$STAMP"
mkdir -p "$RAW" "$BENCH/tmp"

port_of() {  # server proto -> port
  case "$1-$2" in
    agensio-http) echo 8080 ;; agensio-https) echo 8443 ;;
    nginx-http)   echo 8081 ;; nginx-https)   echo 8444 ;;
    caddy-http)   echo 8082 ;; caddy-https)   echo 8445 ;;
  esac
}

SERVER_PID=""
start_server() {
  case "$1" in
    agensio) (cd "$BENCH" && exec "$ROOT/build/agensio" -c agensio.toml) >"$RAW/$1.log" 2>&1 & ;;
    nginx)   (cd "$BENCH" && exec nginx -p "$BENCH" -c "$BENCH/nginx.conf" -g 'daemon off;') >"$RAW/$1.log" 2>&1 & ;;
    caddy)   (cd "$BENCH" && exec caddy run --config Caddyfile --adapter caddyfile) >"$RAW/$1.log" 2>&1 & ;;
  esac
  SERVER_PID=$!
  local port; port=$(port_of "$1" http)
  for _ in $(seq 1 50); do nc -z 127.0.0.1 "$port" 2>/dev/null && return 0; sleep 0.1; done
  echo "$1 did not start (see $RAW/$1.log)"; cat "$RAW/$1.log"; exit 1
}
stop_server() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
  pkill -x "$1" 2>/dev/null || true   # nginx forks workers
  SERVER_PID=""
  sleep 0.5
}
trap 'for s in $SERVERS; do pkill -x $s 2>/dev/null || true; done' EXIT

version_of() {
  case "$1" in
    agensio) "$ROOT/build/agensio" -v ;;
    nginx)   nginx -v 2>&1 | sed 's#nginx version: ##' ;;
    caddy)   caddy version | awk '{print "caddy " $1}' ;;
  esac
}

{
  echo "# Static file benchmark $STAMP"
  echo
  echo "- machine: $(uname -m), $(sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo | cut -d: -f2), $(uname -sr)"
  echo "- commit: $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo uncommitted)"
  echo "- load generator: $(wrk -v 2>&1 | head -1 | awk '{print $1, $2, $3}'), threads=$THREADS, duration=$DURATION, keep-alive"
  for s in $SERVERS; do echo "- $s: $(version_of "$s")"; done
  echo
  echo "| server | proto | path | conns | req/s | transfer/s | p50 | p99 | errors |"
  echo "|---|---|---|---|---|---|---|---|---|"
} > "$OUT"

for server in $SERVERS; do
  echo "=== $server"
  start_server "$server"
  for proto in $PROTOS; do
    port=$(port_of "$server" "$proto")
    for spec in "${URLSPECS[@]}"; do
      path="${spec%%:*}"; conns="${spec#*:}"
      url="$proto://127.0.0.1:$port$path"
      # correctness + warm-up: body must match the file on disk
      expected=$(shasum -a 256 "$BENCH/www/${path#/}" 2>/dev/null | cut -c1-16 || true)
      [ "$path" = "/" ] && expected=$(shasum -a 256 "$BENCH/www/index.html" | cut -c1-16)
      got=$(curl -sk "$url" | shasum -a 256 | cut -c1-16)
      [ "$got" = "$expected" ] || { echo "BODY MISMATCH for $server $url"; exit 1; }
      curl -sk -o /dev/null "$url"
      for c in ${conns//,/ }; do
        t=$THREADS; [ "$c" -lt "$t" ] && t=$c
        rawfile="$RAW/$server-$proto-${path//\//_}-c$c.txt"
        printf '  %-6s %-11s c=%-4s ' "$proto" "$path" "$c"
        wrk -t"$t" -c"$c" -d"$DURATION" --latency "$url" > "$rawfile" 2>&1
        rps=$(awk '/^Requests\/sec/{print $2}' "$rawfile")
        tps=$(awk '/^Transfer\/sec/{print $2}' "$rawfile")
        p50=$(awk '/^ +50%/{print $2}' "$rawfile")
        p99=$(awk '/^ +99%/{print $2}' "$rawfile")
        errs=$(awk '/Socket errors/{sub(/^ +Socket errors: /,""); print} /Non-2xx/{print}' "$rawfile" | tr '\n' ' ')
        [ -z "$errs" ] && errs="-"
        echo "$rps req/s  $tps  p50=$p50 p99=$p99 $errs"
        echo "| $server | $proto | $path | $c | $rps | $tps | $p50 | $p99 | $errs |" >> "$OUT"
      done
    done
  done
  stop_server "$server"
done

echo
echo "summary written to $OUT"
cat "$OUT"
