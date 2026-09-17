#!/usr/bin/env bash
# WebSocket echo benchmark (roadmap D7): CONNS tunnels through each proxy to the D0 upstream's
# echo (Upgrade: echo, a WebSocket without the framing), 1 KB messages, each connection
# sending the next message when the echo of the previous one arrived. Records messages/s and
# the proxy's CPU per message (its processes only); the Python client is the load generator
# and is the bottleneck for the direct row, so "direct" is a ceiling for the client, not the
# origin. usage: bench/proxy/ws.sh [-d 10] [-c 64] [-b 1024] [-s "direct nginx caddy agensio"]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DUR=10; CONNS=64; BYTES=1024; SERVERS="direct nginx caddy agensio"
while getopts 'd:c:b:s:' o; do case $o in d) DUR=$OPTARG ;; c) CONNS=$OPTARG ;; b) BYTES=$OPTARG ;; s) SERVERS=$OPTARG ;; *) exit 2 ;; esac; done
export LC_NUMERIC=C
# Reuse the proxy harness (bench/proxy/run.sh) for configs, process control and CPU
# accounting: its variables first, then its "configs" and "process control" sections.
RUN="$ROOT/bench/proxy/run.sh"
TMP="$ROOT/bench/tmp/proxy"; mkdir -p "$TMP"
UP=127.0.0.1:9100; ORIGIN=d0
PORT_DIRECT=9100; PORT_AGENSIO=8093; PORT_NGINX=8094; PORT_CADDY=8095
for p in $PORT_DIRECT $PORT_AGENSIO $PORT_NGINX $PORT_CADDY; do nc -z 127.0.0.1 $p 2>/dev/null && { echo "port $p busy" >&2; exit 1; }; done
[ -x "$ROOT/build/agensio_upstream" ] || { echo "build/agensio_upstream missing" >&2; exit 1; }
DOCKER_IMAGE=agensio-devbox
run_mode() { command -v "$1" >/dev/null 2>&1 && echo native || echo docker; }
NGINX_MODE=$(run_mode nginx); CADDY_MODE=$(run_mode caddy)
STAMP=$(date -u +%Y%m%d-%H%M%S)
OUT="$ROOT/bench/results/proxy-ws-$STAMP.md"
# shellcheck disable=SC1090
source <(sed -n '/^# ---- configs/,/^# ---- run/p' "$RUN" | sed '$d')
start_upstream
{
  echo "# WebSocket echo benchmark $STAMP (D7)"
  echo
  echo "- machine: $(uname -m), $(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //'), $(uname -sr)"
  echo "- commit: $(git -C "$ROOT" rev-parse --short HEAD)$(git -C "$ROOT" diff --quiet || echo '+dirty')"
  echo "- $CONNS tunnels through each proxy (one worker each) to the D0 upstream's echo, $BYTES-byte messages, ${DUR}s; the Python client (asyncio, one process) generates the load and bounds every row"
  echo "- proxy us/msg = CPU of the proxy's processes / messages (each message crosses the proxy twice)"
  echo
  echo "| server | tunnels | messages/s | proxy us/msg | rss MB | failures |"
  echo "|---|---|---|---|---|---|"
} > "$OUT"
for s in $SERVERS; do
  start_server "$s"
  port=$(port_of "$s")
  python3 "$ROOT/bench/proxy/ws_load.py" "$port" 8 2 "$BYTES" > /dev/null  # warm-up
  c0=$(cpu_seconds "$s")
  line=$(python3 "$ROOT/bench/proxy/ws_load.py" "$port" "$CONNS" "$DUR" "$BYTES")
  c1=$(cpu_seconds "$s")
  msgs=$(echo "$line" | awk '{print $2}'); rate=$(echo "$line" | awk '{print $4}'); fails=$(echo "$line" | sed 's/.*failures=//')
  us=$(awk -v a="$c0" -v b="$c1" -v n="$msgs" 'BEGIN{ if (n>0) printf "%.2f", (b-a)*1e6/n; else print "n/a" }')
  [ "$s" = direct ] && us="-"
  rss=$(rss_mb "$s")
  echo "$s: $CONNS tunnels, $rate msg/s, proxy=${us}us/msg rss=${rss}MB failures=$fails"
  echo "| $s | $CONNS | $rate | $us | $rss | $fails |" >> "$OUT"
  stop_server
done
echo; echo "results: $OUT"
