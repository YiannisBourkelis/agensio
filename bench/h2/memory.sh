#!/usr/bin/env bash
# Memory per connection (phase G, step G2): the server's RSS with N idle HTTP/2 connections
# held open by tests/h2/hold.py, and under h2load with B busy connections, for agensio,
# nginx and Caddy with the same configuration as bench/h2/run.sh. Prints a table and
# writes bench/results/h2-memory-<stamp>.md.
# usage: bench/h2/memory.sh [-n IDLE] [-b BUSY] [-w WORKERS] [-s "agensio nginx caddy"]
set -uo pipefail
BENCH="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(dirname "$BENCH")"
IDLE=10000; BUSY=1000; WORKERS=1; SERVERS="agensio nginx caddy"
while getopts "n:b:w:s:" opt; do
  case $opt in n) IDLE=$OPTARG ;; b) BUSY=$OPTARG ;; w) WORKERS=$OPTARG ;; s) SERVERS=$OPTARG ;; *) exit 2 ;; esac
done
command -v h2load >/dev/null || { echo "missing h2load"; exit 1; }
python3 -c 'import h2' 2>/dev/null || { echo "missing python3-h2"; exit 1; }
AGENSIO_BIN="${AGENSIO_BIN:-$ROOT/build/agensio}"
export LC_NUMERIC=C
ulimit -n 65536 2>/dev/null || true
mkdir -p "$BENCH/tmp" "$BENCH/results"
STAMP=$(date +%Y%m%d-%H%M%S); OUT="$BENCH/results/h2-memory-$STAMP.md"
sed "s#@WORKERS@#$WORKERS#g; s#@BENCH@#$BENCH#g; s#@ACCESS_LOG@##g; s#@SENDFILE_MIN@#48KB#g" "$BENCH/agensio.toml" > "$BENCH/tmp/agensio-h2.toml"
NGINX_WORKERS=$WORKERS; [ "$WORKERS" = 0 ] && NGINX_WORKERS=auto
sed "s#@WORKERS@#$NGINX_WORKERS#g; s#@BENCH@#$BENCH#g" "$BENCH/nginx.conf" > "$BENCH/tmp/nginx-h2.conf"
port() { case "$1" in agensio) echo 8080 ;; nginx) echo 8081 ;; caddy) echo 8082 ;; esac; }
busy() { curl -sS -o /dev/null --max-time 1 "http://127.0.0.1:$1/" 2>/dev/null; }
start_server() {
  case $1 in
    agensio) "$AGENSIO_BIN" -c "$BENCH/tmp/agensio-h2.toml" >"$BENCH/tmp/mem-$1.log" 2>&1 & ;;
    nginx)   (cd "$BENCH" && exec nginx -p "$BENCH" -c "$BENCH/tmp/nginx-h2.conf" -g 'daemon off;') >"$BENCH/tmp/mem-$1.log" 2>&1 & ;;
    caddy)   (cd "$BENCH" && GOMAXPROCS=$WORKERS exec caddy run --config Caddyfile --adapter caddyfile) >"$BENCH/tmp/mem-$1.log" 2>&1 & ;;
  esac
  for _ in $(seq 1 50); do busy "$(port $1)" && return 0; sleep 0.1; done
  echo "$1 did not start"; exit 1
}
stop_server() { pkill -f "^$1( |:)" 2>/dev/null || true; pkill -x "$1" 2>/dev/null || true; sleep 0.5; }
pids_of() { case $1 in nginx) pgrep -f 'nginx: ' ;; *) pgrep -x "$1" ;; esac; }
rss_kb() { local t=0; for p in $(pids_of $1); do t=$((t + $(awk '/^VmRSS/{print $2}' /proc/$p/status 2>/dev/null || echo 0))); done; echo $t; }
{
  echo "# HTTP/2 memory per connection $STAMP"
  echo
  echo "- machine: $(uname -m), $(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //'), $(uname -sr); workers=$WORKERS"
  echo "- idle: $IDLE prior-knowledge HTTP/2 connections, one GET each, then held 5 s (tests/h2/hold.py); busy: h2load -c $BUSY -m 10 on / for 5 s, RSS sampled mid-run"
  echo "- RSS of every process of the server, in KB; per connection = (idle - baseline) / $IDLE"
  echo
  echo "| server | baseline | $IDLE idle | per idle connection | $BUSY busy |"
  echo "|---|---|---|---|---|"
} > "$OUT"
for s in $SERVERS; do
  command -v "$s" >/dev/null || [ "$s" = agensio ] || { echo "skip $s"; continue; }
  start_server "$s"; sleep 0.5
  base=$(rss_kb $s)
  python3 "$ROOT/tests/h2/hold.py" "$IDLE" "$(port $s)" --seconds 120 > "$BENCH/tmp/hold-$s.txt" 2>&1 &
  HOLD=$!
  for _ in $(seq 1 600); do grep -q '^opened' "$BENCH/tmp/hold-$s.txt" 2>/dev/null && break; sleep 0.2; done
  opened=$(awk '/^opened/{print $2}' "$BENCH/tmp/hold-$s.txt"); sleep 5  # past agensio's 2 s shed point
  idle=$(rss_kb $s)
  kill $HOLD 2>/dev/null; wait $HOLD 2>/dev/null; sleep 1
  h2load -D 5 -c "$BUSY" -m 10 -t 4 "http://127.0.0.1:$(port $s)/" > "$BENCH/tmp/h2load-mem-$s.txt" 2>&1 &
  LOAD=$!; sleep 3
  busyrss=$(rss_kb $s)
  wait $LOAD 2>/dev/null
  per=$(( (idle - base) * 1024 / (opened > 0 ? opened : 1) ))
  printf "| %s | %s KB | %s KB (%s opened) | %s bytes | %s KB |\n" "$s" "$base" "$idle" "$opened" "$per" "$busyrss" >> "$OUT"
  printf "  %-8s baseline %7s KB  idle %8s KB (%s opened)  per connection %6s bytes  busy %8s KB\n" "$s" "$base" "$idle" "$opened" "$per" "$busyrss"
  stop_server "$s"
done
echo "summary written to $OUT"
