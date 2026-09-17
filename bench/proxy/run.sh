#!/usr/bin/env bash
# Reverse proxy benchmark (roadmap D0/D7): the benchmark upstream (`agensio_upstream`,
# one worker, 127.0.0.1:9100) behind agensio, nginx and Caddy, one worker each, plus the
# upstream reached directly as the ceiling. Records req/s, latency, the proxy's CPU per
# request (its processes only) and how many connections the proxy opened to the upstream
# during the run (from /stats: a proxy that reuses connections opens a few, one that does
# not opens one per request).
#
#   bench/proxy/run.sh [-d 10s] [-t 4] [-s "direct nginx caddy agensio"] [-u /json:64 -u /big:64 ...] [-r 1]
#
# nginx and Caddy: the host binaries if present, else the agensio-devbox image on the host
# network. agensio runs from build/agensio with bench/proxy/agensio.toml once phase D1 exists.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP="$ROOT/bench/tmp/proxy"
DUR=10s; THREADS=4; ROUNDS=1; SERVERS="direct nginx caddy agensio"; URLS=()
UP=127.0.0.1:9100
PORT_DIRECT=9100; PORT_AGENSIO=8093; PORT_NGINX=8094; PORT_CADDY=8095
while getopts 'd:t:s:u:r:' o; do
  case $o in
    d) DUR=$OPTARG ;; t) THREADS=$OPTARG ;; s) SERVERS=$OPTARG ;; u) URLS+=("$OPTARG") ;; r) ROUNDS=$OPTARG ;;
    *) exit 2 ;;
  esac
done
[ ${#URLS[@]} -eq 0 ] && URLS=(/json:64 /json:16 /big:64 "/slow?ms=20:256")
export LC_NUMERIC=C
mkdir -p "$TMP"
[ -x "$ROOT/build/agensio_upstream" ] || { echo "build/agensio_upstream missing (cmake --build build --target agensio_upstream)" >&2; exit 1; }
for p in $PORT_DIRECT $PORT_AGENSIO $PORT_NGINX $PORT_CADDY; do
  nc -z 127.0.0.1 $p 2>/dev/null && { echo "port $p busy" >&2; exit 1; }
done
if [[ " $SERVERS " == *" agensio "* ]] && [ ! -f "$ROOT/bench/proxy/agensio.toml" ]; then
  echo "note: bench/proxy/agensio.toml does not exist yet (phase D1); skipping agensio"
  SERVERS=${SERVERS// agensio/}; SERVERS=${SERVERS//agensio /}; SERVERS=${SERVERS//agensio/}
fi
DOCKER_IMAGE=agensio-devbox
run_mode() { command -v "$1" >/dev/null 2>&1 && echo native || echo docker; }
NGINX_MODE=$(run_mode nginx); CADDY_MODE=$(run_mode caddy)
if { [ $NGINX_MODE = docker ] || [ $CADDY_MODE = docker ]; } && ! docker image inspect $DOCKER_IMAGE >/dev/null 2>&1; then
  echo "no nginx/caddy on the host and no $DOCKER_IMAGE image" >&2; exit 1
fi

# ---- configs -----------------------------------------------------------------
mkdir -p "$TMP/nginx"
cat > "$TMP/nginx.conf" <<NGX
worker_processes 1;
pid $TMP/nginx/nginx.pid;
error_log $TMP/nginx-error.log warn;
events { worker_connections 4096; multi_accept on; }
http {
  access_log off;
  sendfile on; tcp_nopush on; tcp_nodelay on;
  keepalive_timeout 65; keepalive_requests 1000000;
  client_body_temp_path $TMP/nginx/body; fastcgi_temp_path $TMP/nginx/fastcgi;
  proxy_temp_path $TMP/nginx/proxy; uwsgi_temp_path $TMP/nginx/uwsgi; scgi_temp_path $TMP/nginx/scgi;
  upstream origin { server $UP; keepalive 64; keepalive_requests 1000000; }
  server {
    listen 127.0.0.1:$PORT_NGINX default_server;
    location / {
      proxy_pass http://origin;
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_set_header Host \$host;
      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
  }
}
NGX
cat > "$TMP/Caddyfile" <<CADDY
{
  admin off
  auto_https off
}
http://127.0.0.1:$PORT_CADDY {
  reverse_proxy $UP
}
CADDY

# ---- process control ---------------------------------------------------------
UP_PID=""; SERVER_PID=""; CONTAINER=""
start_upstream() {
  "$ROOT/build/agensio_upstream" -p $PORT_DIRECT -w 1 > "$TMP/upstream.out" 2>&1 &
  UP_PID=$!
  for _ in $(seq 1 50); do nc -z 127.0.0.1 $PORT_DIRECT 2>/dev/null && return 0; sleep 0.1; done
  echo "upstream did not start" >&2; exit 1
}
docker_start() {  # name, command...
  CONTAINER=$1; shift
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$CONTAINER" --network host --init --ulimit nofile=65536:65536 \
    -v "$ROOT:$ROOT" -w "$ROOT" -e GOMAXPROCS=1 $DOCKER_IMAGE "$@" >/dev/null
}
start_server() {
  case $1 in
    direct) return 0 ;;
    nginx)
      if [ $NGINX_MODE = native ]; then nginx -c "$TMP/nginx.conf" -g 'daemon off;' > "$TMP/nginx.out" 2>&1 & SERVER_PID=$!
      else docker_start agensio-bench-proxy-nginx nginx -c "$TMP/nginx.conf" -g 'daemon off;'; fi ;;
    caddy)
      if [ $CADDY_MODE = native ]; then GOMAXPROCS=1 caddy run --config "$TMP/Caddyfile" --adapter caddyfile > "$TMP/caddy.out" 2>&1 & SERVER_PID=$!
      else docker_start agensio-bench-proxy-caddy caddy run --config "$TMP/Caddyfile" --adapter caddyfile; fi ;;
    agensio)
      "$ROOT/build/agensio" -c "$ROOT/bench/proxy/agensio.toml" > "$TMP/agensio.out" 2>&1 & SERVER_PID=$! ;;
  esac
  local port; port=$(port_of "$1")
  for _ in $(seq 1 50); do nc -z 127.0.0.1 "$port" 2>/dev/null && return 0; sleep 0.1; done
  echo "$1 did not come up on $port" >&2; cat "$TMP/$1.out" 2>/dev/null; [ -n "$CONTAINER" ] && docker logs "$CONTAINER" 2>&1 | tail -5; exit 1
}
stop_server() {
  if [ -n "$CONTAINER" ]; then docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; CONTAINER=""; fi
  if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""; fi
  sleep 0.5
}
trap 'stop_server; [ -n "$UP_PID" ] && kill "$UP_PID" 2>/dev/null; true' EXIT
port_of() { case $1 in direct) echo $PORT_DIRECT ;; agensio) echo $PORT_AGENSIO ;; nginx) echo $PORT_NGINX ;; caddy) echo $PORT_CADDY ;; esac; }
pids_of() {
  case $1 in
    direct) echo "$UP_PID" ;;
    *) if [ -n "$CONTAINER" ]; then docker top "$CONTAINER" -o pid 2>/dev/null | tail -n +2 | paste -sd, -
       else { echo "$SERVER_PID"; pgrep -P "$SERVER_PID" 2>/dev/null; } | paste -sd, -; fi ;;
  esac
}
cpu_seconds() {
  local pids; pids=$(pids_of "$1"); [ -z "$pids" ] && { echo 0; return; }
  local tck; tck=$(getconf CLK_TCK)
  for p in ${pids//,/ }; do cat /proc/"$p"/stat 2>/dev/null; done | awk -v tck="$tck" '{ s+=($14+$15)/tck } END{printf "%.3f", s+0}'
}
rss_mb() { local pids; pids=$(pids_of "$1"); [ -z "$pids" ] && { echo 0; return; }; ps -o rss= -p "$pids" | awk '{s+=$1} END{printf "%.0f", s/1024}'; }
upstream_connections() { curl -s "http://127.0.0.1:$PORT_DIRECT/stats" | sed 's/.*"connections":\([0-9]*\).*/\1/'; }
version_of() {
  case $1 in
    direct) echo "agensio_upstream" ;;
    agensio) "$ROOT/build/agensio" -v ;;
    nginx) if [ $NGINX_MODE = docker ]; then docker run --rm $DOCKER_IMAGE nginx -v 2>&1; else nginx -v 2>&1; fi | sed 's#nginx version: ##' ;;
    caddy) if [ $CADDY_MODE = docker ]; then docker run --rm $DOCKER_IMAGE caddy version; else caddy version; fi | awk '{print "caddy " $1}' ;;
  esac
}

# ---- run ---------------------------------------------------------------------
STAMP=$(date -u +%Y%m%d-%H%M%S)
OUT="$ROOT/bench/results/proxy-$STAMP.md"
RAW="$ROOT/bench/results/raw/proxy-$STAMP"; mkdir -p "$RAW"
start_upstream
{
  echo "# Reverse proxy benchmark $STAMP"
  echo
  echo "- machine: $(uname -m), $(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //'), $(uname -sr), $(nproc) threads"
  echo "- commit: $(git -C "$ROOT" rev-parse --short HEAD)$(git -C "$ROOT" diff --quiet || echo '+dirty')"
  echo "- servers: $(for s in $SERVERS; do printf '%s; ' "$(version_of "$s")"; done)nginx via $NGINX_MODE, caddy via $CADDY_MODE"
  echo "- upstream: agensio_upstream, one worker on $UP; one proxy worker each (nginx worker_processes 1, caddy GOMAXPROCS=1)"
  echo "- wrk $THREADS threads, $DUR, $ROUNDS round(s); command: \`$0 $*\`"
  echo "- proxy us/req = CPU of the proxy's processes / requests (direct: the upstream's own CPU); upstream conns = connections the proxy opened to the upstream during the run"
  echo
  echo "| server | path | conns | req/s | p50 | p99 | proxy us/req | upstream conns | rss MB | errors |"
  echo "|---|---|---|---|---|---|---|---|---|---|"
} > "$OUT"

verify() {
  local s=$1 port; port=$(port_of "$s")
  local body; body=$(curl -s "http://127.0.0.1:$port/json")
  [ "$body" = '{"ok":true,"service":"upstream"}' ] || { echo "$s: unexpected /json body: $body" >&2; exit 1; }
  local size; size=$(curl -s -o /dev/null -w '%{size_download}' "http://127.0.0.1:$port/big")
  [ "$size" = "$(curl -s -o /dev/null -w '%{size_download}' "http://127.0.0.1:$PORT_DIRECT/big")" ] || { echo "$s: /big size differs" >&2; exit 1; }
  [ "$(curl -s "http://127.0.0.1:$port/chunked")" = '{"ok":true,"service":"upstream"}' ] || { echo "$s: /chunked body differs" >&2; exit 1; }
}

for round in $(seq 1 "$ROUNDS"); do
  for s in $SERVERS; do
    start_server "$s"
    verify "$s"
    port=$(port_of "$s")
    wrk -t"$THREADS" -c64 -d2s "http://127.0.0.1:$port/json" >/dev/null 2>&1  # warm-up
    sleep 1
    for spec in "${URLS[@]}"; do
      u=${spec%:*}; c=${spec##*:}
      raw="$RAW/$s$(echo "$u" | tr '/?=' '___')-c$c-r$round.txt"
      c0=$(cpu_seconds "$s"); k0=$(upstream_connections)
      wrk -t"$THREADS" -c"$c" -d"$DUR" --latency "http://127.0.0.1:$port$u" > "$raw" 2>&1
      c1=$(cpu_seconds "$s"); k1=$(upstream_connections)
      reqs=$(awk '/requests in/ {print $1}' "$raw")
      rps=$(awk '/Requests\/sec/ {print $2}' "$raw")
      p50=$(awk '$1=="50%" {print $2}' "$raw"); p99=$(awk '$1=="99%" {print $2}' "$raw")
      errs=$( (grep -E 'Socket errors|Non-2xx' "$raw" || true) | sed 's/^ *//' | paste -sd';' - ); [ -z "$errs" ] && errs="-"
      us=$(awk -v a="$c0" -v b="$c1" -v n="$reqs" 'BEGIN{ if (n>0) printf "%.2f", (b-a)*1e6/n; else print "n/a" }')
      conns=$((k1 - k0)); [ "$s" = direct ] && conns="-"
      rss=$(rss_mb "$s")
      echo "$s $u c=$c: $rps req/s p50=$p50 p99=$p99 proxy=${us}us/req upstream-conns=$conns rss=${rss}MB $errs"
      echo "| $s | $u | $c | $rps | $p50 | $p99 | $us | $conns | $rss | $errs |" >> "$OUT"
      sleep 1
    done
    stop_server
  done
done
echo; echo "results: $OUT"
