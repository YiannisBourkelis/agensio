#!/usr/bin/env bash
# WordPress through agensio with response compression (docs/design-compression.md 10): the ddev
# bed's pool on 127.0.0.1:9002, one worker, wrk on the host asking for one coding.
#   bench/wordpress/.ddev/bench.sh BIN off|zstd|br|gzip [DUR] [CONNS]   (the bed up: ddev start in bench/wordpress)
# Prints one row: req/s, p50, p99, agensio us/req, php us/req (the web container's cgroup), bytes per answer.
set -euo pipefail
export LC_NUMERIC=C
BIN=$1; CODING=$2; DUR=${3:-10s}; CONNS=${4:-64}; THREADS=4
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP=$ROOT/bench/tmp/wp-bench; mkdir -p "$TMP"
PORT=8072; HOST="wp.agensio.ddev.site:$PORT"; CONTAINER=ddev-agensio-wordpress-web
nc -z 127.0.0.1 9002 || { echo "pool 9002 down" >&2; exit 1; }
nc -z 127.0.0.1 $PORT 2>/dev/null && { echo "port $PORT busy" >&2; exit 1; }
{
  printf '[server]\nworkers = 1\nidle_timeout = 65\n[log]\naccess = "off"\nerror = "%s/error.log"\n' "$TMP"
  [ "$CODING" = off ] || printf '[response_compression]\ncodings = ["%s"]\n' "$CODING"
  printf '[[site]]\nserver_name = ["wp.agensio.ddev.site"]\nlisten = ["127.0.0.1:%s"]\nroot = "%s/bench/wordpress"\napp = "wordpress"\nphp = { socket = "127.0.0.1:9002", remote_root = "/var/www/html", read_timeout = 120 }\n' "$PORT" "$ROOT"
  [ "$CODING" = off ] || printf 'response_compression = "on"\n'
} > "$TMP/agensio.toml"
"$BIN" -c "$TMP/agensio.toml" > "$TMP/agensio.out" 2>&1 & PID=$!
trap 'kill $PID 2>/dev/null; wait $PID 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do nc -z 127.0.0.1 $PORT 2>/dev/null && break; sleep 0.1; done
HDR=(-H "Host: $HOST"); [ "$CODING" = off ] || HDR+=(-H "Accept-Encoding: $CODING")
code=$(curl -sS -o "$TMP/home.body" -D "$TMP/home.head" -w '%{http_code}' "${HDR[@]}" "http://127.0.0.1:$PORT/")
[ "$code" = 200 ] || { echo "home: HTTP $code" >&2; cat "$TMP/home.head"; exit 1; }
enc=$(tr -d '\r' < "$TMP/home.head" | awk 'tolower($1)=="content-encoding:"{print $2}'); [ -n "$enc" ] || enc=identity
CG="/sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' $CONTAINER).scope/cpu.stat"
cpu() { awk -v tck="$(getconf CLK_TCK)" '{ printf "%.3f", ($14+$15)/tck }' /proc/$PID/stat; }
fpm() { awk '/^usage_usec/ {printf "%.3f", $2/1e6}' "$CG"; }
wrk -t$THREADS -c$CONNS -d2s "${HDR[@]}" "http://127.0.0.1:$PORT/" > /dev/null 2>&1; sleep 2
c0=$(cpu); f0=$(fpm)
wrk -t$THREADS -c$CONNS -d"$DUR" --latency "${HDR[@]}" "http://127.0.0.1:$PORT/" > "$TMP/wrk-$CODING.txt" 2>&1
c1=$(cpu); f1=$(fpm)
reqs=$(awk '/requests in/ {print $1}' "$TMP/wrk-$CODING.txt"); rps=$(awk '/Requests\/sec/ {print $2}' "$TMP/wrk-$CODING.txt")
p50=$(awk '$1=="50%" {print $2}' "$TMP/wrk-$CODING.txt"); p99=$(awk '$1=="99%" {print $2}' "$TMP/wrk-$CODING.txt")
errs=$( (grep -E 'Socket errors|Non-2xx' "$TMP/wrk-$CODING.txt" || true) | sed 's/^ *//' | paste -sd';' - ); [ -z "$errs" ] && errs="-"
bytes=$(awk '/requests in/ {v=$5; u=v; gsub(/[0-9.]/, "", u); gsub(/[A-Za-z]/, "", v); m=1; if (u=="KB") m=1024; else if (u=="MB") m=1048576; else if (u=="GB") m=1073741824; printf "%.0f", v*m/$1}' "$TMP/wrk-$CODING.txt")
web=$(awk -v a="$c0" -v b="$c1" -v n="$reqs" 'BEGIN{ printf "%.1f", (b-a)*1e6/n }')
php=$(awk -v a="$f0" -v b="$f1" -v n="$reqs" 'BEGIN{ printf "%.0f", (b-a)*1e6/n }')
echo "| agensio | $CODING | $enc | $CONNS | $rps | $p50 | $p99 | $web | $php | $(stat -c %s "$TMP/home.body") | $bytes | $errs |"
