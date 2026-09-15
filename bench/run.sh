#!/usr/bin/env bash
# Benchmarks agensio against nginx and Caddy serving the same static docroot.
#
# usage: bench/run.sh [-w WORKERS] [-t THREADS] [-d DURATION] [-s "agensio nginx caddy"] [-p "http https"] [-u URLSPEC ...]
#   -w  server workers: agensio workers, nginx worker_processes, caddy GOMAXPROCS (default 1)
#       Per-server override via env: AGENSIO_WORKERS=1 NGINX_WORKERS=auto CADDY_WORKERS=0
#       (agensio 0 = all cores, nginx auto = all cores, caddy 0 = leave GOMAXPROCS unset).
#   Each row also reports server CPU microseconds per request (CPU time of all server
#   processes divided by requests served) and resident memory after the run.
#   -t  wrk threads (default 4). Keep WORKERS + THREADS well below the core count, otherwise
#       the load generator steals CPU from the server and the numbers measure wrk, not the server.
#   -d  duration per case (default 5s; use 15s for numbers worth publishing)
#   URLSPEC is "path:conns[,conns...]", default: "/:64,256" "/style.css:64,256" "/big.bin:16"
#
# Servers run one at a time with configs generated from the templates in this directory
# (bench/tmp/agensio.toml, bench/tmp/nginx.conf). Raw wrk output goes to
# bench/results/raw/, a summary table to bench/results/<timestamp>.md.
set -euo pipefail

BENCH="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$BENCH")"
DURATION=5s
WORKERS=1
THREADS=4
SERVERS="agensio nginx caddy"
PROTOS="http https"
URLSPECS=()
while getopts "w:d:t:s:p:u:" opt; do
  case $opt in
    w) WORKERS=$OPTARG ;;
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

CORES="$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
if [ $((WORKERS + THREADS)) -gt "$CORES" ]; then
  echo "warning: $WORKERS worker(s) + $THREADS wrk thread(s) exceed $CORES cores; results will be load-generator bound"
fi

AGENSIO_WORKERS="${AGENSIO_WORKERS:-$WORKERS}"
NGINX_WORKERS="${NGINX_WORKERS:-$WORKERS}"
CADDY_WORKERS="${CADDY_WORKERS:-$WORKERS}"

# Generate server configs from the templates.
SENDFILE_MIN="${SENDFILE_MIN:-48KB}"   # env override for experiments: cached files >= this go out via sendfile
sed "s#@WORKERS@#$AGENSIO_WORKERS#g; s#@BENCH@#$BENCH#g; s#@SENDFILE_MIN@#$SENDFILE_MIN#g" "$BENCH/agensio.toml" > "$BENCH/tmp/agensio.toml"
sed "s#@WORKERS@#$NGINX_WORKERS#g; s#@BENCH@#$BENCH#g" "$BENCH/nginx.conf" > "$BENCH/tmp/nginx.conf"
"$ROOT/build/agensio" -t -c "$BENCH/tmp/agensio.toml" >/dev/null
nginx -p "$BENCH" -c "$BENCH/tmp/nginx.conf" -t >/dev/null 2>&1 || { nginx -p "$BENCH" -c "$BENCH/tmp/nginx.conf" -t; exit 1; }

port_of() {  # server proto -> port
  case "$1-$2" in
    agensio-http) echo 8080 ;; agensio-https) echo 8443 ;;
    nginx-http)   echo 8081 ;; nginx-https)   echo 8444 ;;
    caddy-http)   echo 8082 ;; caddy-https)   echo 8445 ;;
  esac
}

SERVER_PID=""
start_server() {
  # A stale instance from an earlier run would silently serve the benchmark instead.
  for proto in http https; do
    port=$(port_of "$1" "$proto")
    if nc -z 127.0.0.1 "$port" 2>/dev/null; then
      echo "port $port is already in use; stop the running $1 first (pkill -f '$1')"; exit 1
    fi
  done
  case "$1" in
    agensio) (cd "$BENCH" && exec "$ROOT/build/agensio" -c "$BENCH/tmp/agensio.toml") >"$RAW/$1.log" 2>&1 & ;;
    nginx)   (cd "$BENCH" && exec nginx -p "$BENCH" -c "$BENCH/tmp/nginx.conf" -g 'daemon off;') >"$RAW/$1.log" 2>&1 & ;;
    caddy)   if [ "$CADDY_WORKERS" = "0" ]; then
               (cd "$BENCH" && exec caddy run --config Caddyfile --adapter caddyfile) >"$RAW/$1.log" 2>&1 &
             else
               (cd "$BENCH" && GOMAXPROCS=$CADDY_WORKERS exec caddy run --config Caddyfile --adapter caddyfile) >"$RAW/$1.log" 2>&1 &
             fi ;;
  esac
  SERVER_PID=$!
  local port; port=$(port_of "$1" http)
  for _ in $(seq 1 50); do nc -z 127.0.0.1 "$port" 2>/dev/null && return 0; sleep 0.1; done
  echo "$1 did not start (see $RAW/$1.log)"; cat "$RAW/$1.log"; exit 1
}
stop_server() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
  pkill -x "$1" 2>/dev/null || true
  pkill -f "^$1( |:)" 2>/dev/null || true   # nginx retitles its master and worker processes
  SERVER_PID=""
  sleep 0.5
}
trap 'for s in $SERVERS; do pkill -x "$s" 2>/dev/null || true; pkill -f "^$s( |:)" 2>/dev/null || true; done' EXIT

# All processes of a server (nginx retitles master and workers).
pids_of() { { pgrep -x "$1" 2>/dev/null; pgrep -f "^$1( |:)" 2>/dev/null; } | sort -u | paste -sd, - ; }
cpu_seconds() {  # sum of CPU time over the server's processes
  local pids; pids=$(pids_of "$1"); [ -z "$pids" ] && { echo 0; return; }
  ps -o cputime= -p "$pids" | LC_NUMERIC=C awk -F'[:.]' '{ if (NF==3) s+=$1*60+$2+$3/100; else s+=$1*3600+$2*60+$3+$4/100 } END{printf "%.2f", s}'
}
rss_mb() {  # resident memory summed over the server's processes
  local pids; pids=$(pids_of "$1"); [ -z "$pids" ] && { echo 0; return; }
  ps -o rss= -p "$pids" | awk '{s+=$1} END{printf "%.0f", s/1024}'
}

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
  echo "- server workers: agensio=$AGENSIO_WORKERS nginx=$NGINX_WORKERS caddy=$CADDY_WORKERS (0/auto = all cores), cores: $CORES"
  echo "- load generator: $(wrk -v 2>&1 | head -1 | awk '{print $1, $2, $3}'), threads=$THREADS, duration=$DURATION, keep-alive"
  for s in $SERVERS; do echo "- $s: $(version_of "$s")"; done
  echo
  echo "| server | proto | path | conns | req/s | transfer/s | p50 | p99 | cpu us/req | rss MB | errors |"
  echo "|---|---|---|---|---|---|---|---|---|---|---|"
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
        cpu0=$(cpu_seconds "$server")
        wrk -t"$t" -c"$c" -d"$DURATION" --latency "$url" > "$rawfile" 2>&1
        cpu1=$(cpu_seconds "$server")
        total=$(awk '/requests in/{print $1}' "$rawfile")
        cpureq=$(LC_NUMERIC=C awk -v a="$cpu0" -v b="$cpu1" -v n="$total" 'BEGIN{ if (n>0) printf "%.1f", (b-a)*1e6/n; else print "-" }')
        rss=$(rss_mb "$server")
        rps=$(awk '/^Requests\/sec/{print $2}' "$rawfile")
        tps=$(awk '/^Transfer\/sec/{print $2}' "$rawfile")
        p50=$(awk '/^ +50%/{print $2}' "$rawfile")
        p99=$(awk '/^ +99%/{print $2}' "$rawfile")
        errs=$(awk '/Socket errors/{sub(/^ +Socket errors: /,""); print} /Non-2xx/{print}' "$rawfile" | tr '\n' ' ')
        [ -z "$errs" ] && errs="-"
        echo "$rps req/s  $tps  p50=$p50 p99=$p99  cpu=${cpureq}us/req rss=${rss}MB $errs"
        echo "| $server | $proto | $path | $c | $rps | $tps | $p50 | $p99 | $cpureq | $rss | $errs |" >> "$OUT"
      done
    done
  done
  stop_server "$server"
done

echo
echo "summary written to $OUT"
cat "$OUT"
