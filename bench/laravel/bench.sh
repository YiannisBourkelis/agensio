#!/usr/bin/env bash
# C5: Laravel through agensio vs nginx, same php-fpm pool (the ddev bed's TCP pool on
# 127.0.0.1:9000, 8 static children). One web-server worker each, wrk on the host.
# Records req/s, latency and the CPU the *web server* spent per request (php-fpm's own
# CPU is listed separately so the reader sees where the time goes).
#
#   bench/laravel/bench.sh [-d 10s] [-c 64] [-t 4] [-s "agensio nginx"] [-u / -u /json] [-r 1] [-p tcp|unix]
#   -p unix uses the pool on the bind-mounted socket .ddev/run/php-fpm.sock (Linux hosts) instead
#   of the TCP pool published through docker-proxy.
#   AGENSIO_PHP_EXTRA=', keep_conn = true' bench/laravel/bench.sh -s agensio   # extra php = { } options
#
# nginx: the host binary if there is one, else the agensio-devbox image (docs/linux-dev-setup.md)
# on the host network with the repo mounted at the same path. Needs the bed running
# (`ddev start` in bench/laravel) and `build/agensio`.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BED="$ROOT/bench/laravel"
PUBLIC="$BED/public"
TMP="$ROOT/bench/tmp/laravel-bench"
DUR=10s; CONNS=64; THREADS=4; ROUNDS=1; SERVERS="agensio nginx"; URLS=(); POOL=tcp
FPM_TCP=${FPM_TCP:-127.0.0.1:9000}; FPM_SOCK="$BED/.ddev/run/php-fpm.sock"  # FPM_TCP=<container ip>:9000 skips docker-proxy
REMOTE_ROOT=/var/www/html/public; FPM_CONTAINER=ddev-agensio-laravel-web
PORT_AGENSIO=8073; PORT_NGINX=8074
while getopts 'd:c:t:s:u:r:p:' o; do
  case $o in
    d) DUR=$OPTARG ;; c) CONNS=$OPTARG ;; t) THREADS=$OPTARG ;; s) SERVERS=$OPTARG ;;
    u) URLS+=("$OPTARG") ;; r) ROUNDS=$OPTARG ;; p) POOL=$OPTARG ;;
    *) exit 2 ;;
  esac
done
case $POOL in
  tcp) FPM=$FPM_TCP; FPM_AGENSIO=$FPM_TCP; FPM_NGINX=$FPM_TCP; POOL_NAME="agensio" ;;
  unix) FPM=$FPM_SOCK; FPM_AGENSIO="unix:$FPM_SOCK"; FPM_NGINX="unix:$FPM_SOCK"; POOL_NAME="agensio-unix" ;;
  *) echo "-p tcp|unix" >&2; exit 2 ;;
esac
[ ${#URLS[@]} -eq 0 ] && URLS=(/ /json)
export LC_NUMERIC=C
mkdir -p "$TMP"

[ -x "$ROOT/build/agensio" ] || { echo "build/agensio missing" >&2; exit 1; }
[ -f "$PUBLIC/index.php" ] || { echo "$PUBLIC/index.php missing: run bench/laravel/.ddev/setup.sh" >&2; exit 1; }
if [ $POOL = tcp ]; then nc -z "${FPM_TCP%:*}" "${FPM_TCP##*:}" 2>/dev/null || { echo "php-fpm pool $FPM not reachable: ddev start in bench/laravel" >&2; exit 1; }
else [ -S "$FPM_SOCK" ] || { echo "no socket at $FPM_SOCK: ddev restart in bench/laravel after adding the pool" >&2; exit 1; }; fi
for p in $PORT_AGENSIO $PORT_NGINX; do
  nc -z 127.0.0.1 $p 2>/dev/null && { echo "port $p busy" >&2; exit 1; }
done

NGINX_MODE=native
if ! command -v nginx >/dev/null 2>&1; then
  docker image inspect agensio-devbox >/dev/null 2>&1 || { echo "no nginx and no agensio-devbox image" >&2; exit 1; }
  NGINX_MODE=docker
fi

# ---- configs -----------------------------------------------------------------
cat > "$TMP/agensio.toml" <<TOML
[server]
workers = 1
idle_timeout = 65
[log]
access = "off"
error = "$TMP/agensio-error.log"
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:$PORT_AGENSIO"]
root = "$BED"
app = "laravel"
php = { socket = "$FPM_AGENSIO", remote_root = "$REMOTE_ROOT", read_timeout = 60${AGENSIO_PHP_EXTRA:-} }
TOML

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
  server {
    listen 127.0.0.1:$PORT_NGINX default_server;
    root $PUBLIC;
    index index.php;
    location / { try_files \$uri \$uri/ /index.php?\$query_string; }
    location = /index.php {
      fastcgi_pass $FPM_NGINX;
      fastcgi_param SCRIPT_FILENAME $REMOTE_ROOT\$fastcgi_script_name;
      fastcgi_param DOCUMENT_ROOT $REMOTE_ROOT;
      fastcgi_param QUERY_STRING \$query_string;
      fastcgi_param REQUEST_METHOD \$request_method;
      fastcgi_param CONTENT_TYPE \$content_type;
      fastcgi_param CONTENT_LENGTH \$content_length;
      fastcgi_param SCRIPT_NAME \$fastcgi_script_name;
      fastcgi_param REQUEST_URI \$request_uri;
      fastcgi_param DOCUMENT_URI \$document_uri;
      fastcgi_param SERVER_PROTOCOL \$server_protocol;
      fastcgi_param REQUEST_SCHEME \$scheme;
      fastcgi_param HTTPS \$https if_not_empty;
      fastcgi_param GATEWAY_INTERFACE CGI/1.1;
      fastcgi_param SERVER_SOFTWARE nginx/\$nginx_version;
      fastcgi_param REMOTE_ADDR \$remote_addr;
      fastcgi_param REMOTE_PORT \$remote_port;
      fastcgi_param SERVER_ADDR \$server_addr;
      fastcgi_param SERVER_PORT \$server_port;
      fastcgi_param SERVER_NAME \$server_name;
      fastcgi_param REDIRECT_STATUS 200;
    }
    location ~ \.php$ { return 404; }
  }
}
NGX

# ---- process control ---------------------------------------------------------
SERVER_PID=""
NGINX_CONTAINER=agensio-bench-nginx
start_server() {
  case $1 in
    agensio)
      "$ROOT/build/agensio" -c "$TMP/agensio.toml" >"$TMP/agensio.out" 2>&1 &
      SERVER_PID=$! ;;
    nginx)
      if [ $NGINX_MODE = native ]; then
        nginx -c "$TMP/nginx.conf" -g 'daemon off;' >"$TMP/nginx.out" 2>&1 &
        SERVER_PID=$!
      else
        docker rm -f $NGINX_CONTAINER >/dev/null 2>&1 || true
        docker run -d --name $NGINX_CONTAINER --network host --init --ulimit nofile=65536:65536 \
          -v "$ROOT:$ROOT" -w "$ROOT" agensio-devbox nginx -c "$TMP/nginx.conf" -g 'daemon off;' >/dev/null
      fi ;;
  esac
  local port; port=$(port_of "$1")
  for _ in $(seq 1 50); do nc -z 127.0.0.1 "$port" 2>/dev/null && return 0; sleep 0.1; done
  echo "$1 did not come up on $port" >&2; cat "$TMP/$1.out" 2>/dev/null; exit 1
}
stop_server() {
  if [ "$1" = nginx ] && [ $NGINX_MODE = docker ]; then docker rm -f $NGINX_CONTAINER >/dev/null 2>&1 || true
  elif [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true; fi
  SERVER_PID=""; sleep 0.5
}
trap 'stop_server nginx; [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null; true' EXIT
port_of() { [ "$1" = agensio ] && echo $PORT_AGENSIO || echo $PORT_NGINX; }
pids_of() {
  case $1 in
    agensio) echo "$SERVER_PID" ;;
    nginx) if [ $NGINX_MODE = docker ]; then docker top $NGINX_CONTAINER -o pid 2>/dev/null | tail -n +2 | paste -sd, -
           else { echo "$SERVER_PID"; pgrep -P "$SERVER_PID"; } | paste -sd, -; fi ;;
    fpm) docker top $FPM_CONTAINER -o pid,args 2>/dev/null | awk -v p="php-fpm: pool $POOL_NAME\$" '$0 ~ p {print $1}' | paste -sd, - ;;
  esac
}
# The php-fpm children respawn (pm.max_requests), so their CPU is read from the web
# container's cgroup: everything in it, but only our pool does work during a run.
FPM_CGROUP="/sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' $FPM_CONTAINER 2>/dev/null).scope/cpu.stat"
cpu_seconds() {  # user + system over the processes, from /proc (clock ticks)
  if [ "$1" = fpm ]; then
    [ -r "$FPM_CGROUP" ] && awk '/^usage_usec/ {printf "%.3f", $2/1e6}' "$FPM_CGROUP" || echo 0
    return
  fi
  local pids; pids=$(pids_of "$1"); [ -z "$pids" ] && { echo 0; return; }
  local tck; tck=$(getconf CLK_TCK)
  for p in ${pids//,/ }; do cat /proc/"$p"/stat 2>/dev/null; done | awk -v tck="$tck" '{ s+=($14+$15)/tck } END{printf "%.3f", s+0}'
}
rss_mb() { local pids; pids=$(pids_of "$1"); [ -z "$pids" ] && { echo 0; return; }; ps -o rss= -p "$pids" | awk '{s+=$1} END{printf "%.0f", s/1024}'; }
version_of() {
  case $1 in
    agensio) "$ROOT/build/agensio" -v ;;
    nginx) if [ $NGINX_MODE = docker ]; then docker run --rm agensio-devbox nginx -v 2>&1; else nginx -v 2>&1; fi | sed 's#nginx version: ##' ;;
  esac
}

# ---- run ---------------------------------------------------------------------
STAMP=$(date -u +%Y%m%d-%H%M%S)
OUT="$ROOT/bench/results/laravel-$STAMP.md"
RAW="$ROOT/bench/results/raw/laravel-$STAMP"; mkdir -p "$RAW"
PHPV=$(docker exec $FPM_CONTAINER php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)
LARAVELV=$(docker exec $FPM_CONTAINER php artisan --version 2>/dev/null | sed 's/Laravel Framework //' || echo unknown)
CHILDREN=$(pids_of fpm | tr ',' '\n' | grep -c . || true)
{
  echo "# Laravel benchmark $STAMP (C5)"
  echo
  echo "- machine: $(uname -m), $(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //'), $(uname -sr), $(nproc) threads"
  echo "- commit: $(git -C "$ROOT" rev-parse --short HEAD)$(git -C "$ROOT" diff --quiet || echo '+dirty')"
  echo "- servers: $(for s in $SERVERS; do printf '%s; ' "$(version_of "$s")"; done)nginx via $NGINX_MODE"
  echo "- app: Laravel $LARAVELV on PHP $PHPV, php-fpm pool \`$POOL_NAME\` in $FPM_CONTAINER ($CHILDREN static children, $POOL $FPM), same pool for both servers; agensio php options: ${AGENSIO_PHP_EXTRA:-none beyond the defaults}"
  echo "- one web-server worker each; wrk $THREADS threads, $CONNS connections, $DUR, $ROUNDS round(s); command: \`$0 $*\`"
  echo "- web us/req = CPU time of the web server's processes / requests; php us/req = CPU of the web container (cgroup, i.e. the php-fpm children) / requests: the application's cost, the same work for both servers"
  echo
  echo "| server | path | conns | req/s | p50 | p99 | web us/req | php us/req | rss MB | errors |"
  echo "|---|---|---|---|---|---|---|---|---|---|"
} > "$OUT"

verify() {  # same answer from both servers before measuring
  local s=$1 port; port=$(port_of "$s")
  for u in "${URLS[@]}"; do
    local code; code=$(curl -sS -o "$TMP/$s${u//\//_}.body" -w '%{http_code}' "http://127.0.0.1:$port$u")
    [ "$code" = 200 ] || { echo "$s $u: HTTP $code" >&2; cat "$TMP/$s.out" 2>/dev/null; exit 1; }
  done
}

for round in $(seq 1 "$ROUNDS"); do
  for s in $SERVERS; do
    start_server "$s"
    verify "$s"
    port=$(port_of "$s")
    wrk -t"$THREADS" -c"$CONNS" -d2s "http://127.0.0.1:$port${URLS[0]}" >/dev/null 2>&1  # warm-up
    # wrk drops its connections with their requests still queued for php-fpm; let those
    # drain (they hold pool slots until the child has answered) before measuring.
    sleep 2
    for u in "${URLS[@]}"; do
      raw="$RAW/$s${u//\//_}-r$round.txt"
      c0=$(cpu_seconds "$s"); f0=$(cpu_seconds fpm)
      wrk -t"$THREADS" -c"$CONNS" -d"$DUR" --latency "http://127.0.0.1:$port$u" > "$raw" 2>&1
      c1=$(cpu_seconds "$s"); f1=$(cpu_seconds fpm)
      reqs=$(awk '/requests in/ {print $1}' "$raw")
      rps=$(awk '/Requests\/sec/ {print $2}' "$raw")
      p50=$(awk '$1=="50%" {print $2}' "$raw"); p99=$(awk '$1=="99%" {print $2}' "$raw")
      errs=$( (grep -E 'Socket errors|Non-2xx' "$raw" || true) | sed 's/^ *//' | paste -sd';' - ); [ -z "$errs" ] && errs="-"
      web=$(awk -v a="$c0" -v b="$c1" -v n="$reqs" 'BEGIN{ if (n>0) printf "%.1f", (b-a)*1e6/n; else print "n/a" }')
      php=$(awk -v a="$f0" -v b="$f1" -v n="$reqs" 'BEGIN{ if (n>0) printf "%.0f", (b-a)*1e6/n; else print "n/a" }')
      rss=$(rss_mb "$s")
      echo "$s $u c=$CONNS: $rps req/s p50=$p50 p99=$p99 web=${web}us/req php=${php}us/req rss=${rss}MB $errs"
      echo "| $s | $u | $CONNS | $rps | $p50 | $p99 | $web | $php | $rss | $errs |" >> "$OUT"
      sleep 2  # same drain between cases
    done
    stop_server "$s"
  done
done
echo; echo "results: $OUT"
