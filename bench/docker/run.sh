#!/usr/bin/env bash
# Linux container benchmark: agensio, nginx, Caddy and OpenLiteSpeed, one worker each on
# CPU 0, wrk on the remaining CPUs, all on one Docker network (no host port forwarding).
# usage: bench/docker/run.sh [-d DURATION] [-t THREADS] [-s "agensio nginx caddy openlitespeed"] [-p "http https"] [-u URLSPEC ...]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; BENCH="$(dirname "$HERE")"; ROOT="$(dirname "$BENCH")"
DURATION=5s; THREADS=2; SERVERS="agensio nginx caddy openlitespeed"; PROTOS="http https"; URLSPECS=()
while getopts "d:t:s:p:u:" opt; do case $opt in d) DURATION=$OPTARG;; t) THREADS=$OPTARG;; s) SERVERS=$OPTARG;; p) PROTOS=$OPTARG;; u) URLSPECS+=("$OPTARG");; *) exit 2;; esac; done
[ ${#URLSPECS[@]} -eq 0 ] && URLSPECS=("/:64,256" "/style.css:64,256" "/big.bin:16")
[ -f "$BENCH/www/big.bin" ] || "$BENCH/gen-www.sh" >/dev/null
[ -f "$BENCH/certs/cert.pem" ] || "$BENCH/certs/gen-cert.sh" >/dev/null
cd "$HERE"
if docker compose version >/dev/null 2>&1; then dc() { docker compose "$@"; }
elif command -v docker-compose >/dev/null; then dc() { docker-compose "$@"; }
else echo "need Docker Compose (brew install docker-compose)"; exit 1; fi
port_of() { case "$2" in http) echo 80;; https) echo 443;; esac; }  # OpenLiteSpeed serves the docker vhost on 80/443 (8088 is the Example vhost)

STAMP="$(date +%Y%m%d-%H%M%S)"; OUT="$BENCH/results/docker-$STAMP.md"; RAW="$BENCH/results/raw/docker-$STAMP"; mkdir -p "$RAW"
echo "building images"; dc build -q agensio wrk
dc up -d wrk >/dev/null
wexec() { dc exec -T wrk "$@"; }
cpu_usec() { dc exec -T "$1" cat /sys/fs/cgroup/cpu.stat 2>/dev/null | awk '/^usage_usec/{print $2}'; }
rss_mb() { docker stats --no-stream --format '{{.MemUsage}}' "$(dc ps -q "$1")" | awk '{v=$1; if (v ~ /GiB/) printf "%.0f", v*1024; else printf "%.0f", v+0}'; }

{
  echo "# Container benchmark $STAMP (Linux, Docker)"; echo
  echo "- host: $(uname -m), $(sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo | cut -d: -f2); VM: $(docker info --format '{{.NCPU}} CPUs, {{.MemTotal}} bytes, {{.KernelVersion}}')"
  echo "- commit: $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo uncommitted)"
  echo "- servers: one worker each, pinned to CPU 0; wrk threads=$THREADS on CPUs 1-3, duration=$DURATION, keep-alive"
  echo "- images: nginx:1.27-alpine, caddy:2-alpine, litespeedtech/openlitespeed:latest, agensio built from source (Debian 12, GCC 12)"
  echo; echo "| server | proto | path | conns | req/s | transfer/s | p50 | p99 | cpu us/req | rss MB | errors |"; echo "|---|---|---|---|---|---|---|---|---|---|---|"
} > "$OUT"

for server in $SERVERS; do
  echo "=== $server"
  dc up -d "$server" >/dev/null
  port=$(port_of "$server" http)
  for _ in $(seq 1 60); do wexec curl -s -o /dev/null "http://$server:$port/" 2>/dev/null && break; sleep 0.5; done
  wexec curl -s -o /dev/null "http://$server:$port/" || { echo "$server did not start"; dc logs "$server" | tail -20; dc stop "$server" >/dev/null; continue; }
  for proto in $PROTOS; do
    port=$(port_of "$server" "$proto")
    for spec in "${URLSPECS[@]}"; do
      path="${spec%%:*}"; conns="${spec#*:}"; url="$proto://$server:$port$path"
      f="${path#/}"; [ "$path" = "/" ] && f=index.html
      expected=$(sha256sum "$BENCH/www/$f" | cut -c1-16)
      got=$(wexec sh -c "curl -sk '$url' | sha256sum | cut -c1-16")
      [ "$got" = "$expected" ] || { echo "BODY MISMATCH for $server $url"; exit 1; }
      for c in ${conns//,/ }; do
        t=$THREADS; [ "$c" -lt "$t" ] && t=$c
        rawfile="$RAW/$server-$proto-${path//\//_}-c$c.txt"
        printf '  %-6s %-11s c=%-4s ' "$proto" "$path" "$c"
        cpu0=$(cpu_usec "$server")
        wexec wrk -t"$t" -c"$c" -d"$DURATION" --latency "$url" > "$rawfile" 2>&1 || true
        cpu1=$(cpu_usec "$server")
        total=$(awk '/requests in/{print $1}' "$rawfile")
        cpureq=$(LC_NUMERIC=C awk -v a="$cpu0" -v b="$cpu1" -v n="$total" 'BEGIN{ if (n>0) printf "%.1f", (b-a)/n; else print "-" }')
        rss=$(rss_mb "$server")
        rps=$(awk '/^Requests\/sec/{print $2}' "$rawfile"); tps=$(awk '/^Transfer\/sec/{print $2}' "$rawfile")
        p50=$(awk '/^ +50%/{print $2}' "$rawfile"); p99=$(awk '/^ +99%/{print $2}' "$rawfile")
        errs=$(awk '/Socket errors/{sub(/^ +Socket errors: /,""); print} /Non-2xx/{print}' "$rawfile" | tr '\n' ' '); [ -z "$errs" ] && errs="-"
        echo "$rps req/s  $tps  p50=$p50 p99=$p99  cpu=${cpureq}us/req rss=${rss}MB $errs"
        echo "| $server | $proto | $path | $c | $rps | $tps | $p50 | $p99 | $cpureq | $rss | $errs |" >> "$OUT"
      done
    done
  done
  dc stop "$server" >/dev/null
done
dc stop wrk >/dev/null
echo; echo "summary written to $OUT"; cat "$OUT"
