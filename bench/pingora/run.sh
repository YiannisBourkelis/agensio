#!/usr/bin/env bash
# agensio against Pingora as a reverse proxy. Pingora (https://github.com/cloudflare/pingora) is
# a Rust library, not a server: bench/pingora/proxy is the proxy program, written as Pingora's own
# examples write one, built by bench/pingora/build.sh. Both stand in front of the benchmark
# upstream (build/agensio_upstream), forward the same request (Host, X-Forwarded-For,
# X-Forwarded-Proto, X-Real-IP), keep their connections to the origin, and write no access log.
#
# What is measured, per row: requests per second, latency, the proxy's CPU microseconds per
# request (CPU time of its process, all threads, over the requests answered), its resident
# memory after the row, and the connections it opened to origins. Six groups (-T):
#   proxy    plain HTTP/1.1 clients, one worker: small JSON at 64 and 16 connections, a 100 KB
#            body, a 20 ms application at 256 connections; the upstream alone as the ceiling
#   tls      the same over HTTPS (HTTP/1.1): small JSON and the 100 KB body
#   h2       HTTP/2 over TLS (h2load): one and ten streams per connection, the 100 KB body
#   mixed    HTTPS, 256 connections, a fixed mix of requests (bench/pingora/mixed.lua): what a
#            proxy in front of an application sees
#   origins  ORIGINS different origins chosen by Host (bench/pingora/origins.lua), measured from a
#            cold start and again warm: how many connections to origins each design opens. This
#            is the row Pingora's shared connection pool is built for.
#   memory   resident memory with IDLE idle client connections: HTTP/1.1, HTTP/1.1 over TLS,
#            HTTP/2 over TLS
# mixed and origins run once per worker count of -w (default "1 4"); the rest with one worker.
#
#   bench/pingora/run.sh [-d SECONDS] [-r ROUNDS] [-T "proxy tls h2 mixed origins memory"]
#                        [-s "agensio pingora"] [-w "1 4"] [-n ORIGINS] [-i IDLE] [-P]
#   -P  no CPU pinning. By default (24 CPUs or more) the proxy runs on CPUs 0..W-1, the upstream
#       on 4-7 and the load generator on 8-11 and their siblings, so none takes another's time.
#
# Run it where wrk, h2load and python3 with h2 are: the devbox,
#   docker run --rm --init --ulimit nofile=65536:65536 -v $PWD:$PWD -w $PWD --user 1000:1000 \
#     -e HOME=/home/dev agensio-devbox:latest bench/pingora/run.sh
# Results: bench/results/pingora-<stamp>.md, raw output in bench/results/raw/pingora-<stamp>/.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE="$ROOT/bench/pingora"
TMP="$ROOT/bench/tmp/pingora/run"
DUR=10; ROUNDS=1; TESTS="proxy tls h2 mixed origins memory"; SERVERS="agensio pingora"; WORKER_SETS="1 4"
ORIGINS=2000; IDLE=10000; PIN=1
ARGS="$*"
while getopts 'd:r:T:s:w:n:i:P' o; do
  case $o in
    d) DUR=$OPTARG ;; r) ROUNDS=$OPTARG ;; T) TESTS=$OPTARG ;; s) SERVERS=$OPTARG ;; w) WORKER_SETS=$OPTARG ;;
    n) ORIGINS=$OPTARG ;; i) IDLE=$OPTARG ;; P) PIN=0 ;; *) exit 2 ;;
  esac
done
export LC_NUMERIC=C
AGENSIO_BIN="${AGENSIO_BIN:-$ROOT/build/agensio}"
UPSTREAM_BIN="$ROOT/build/agensio_upstream"
PINGORA_BIN="${PINGORA_BIN:-$ROOT/bench/tmp/pingora/target/release/pingora-bench-proxy}"
CERT="$ROOT/bench/certs/cert.pem"; KEY="$ROOT/bench/certs/key.pem"
for tool in wrk h2load curl nc python3; do command -v $tool >/dev/null || { echo "missing tool: $tool (run in the devbox)" >&2; exit 1; }; done
[ -x "$AGENSIO_BIN" ] || { echo "build first: cmake --build build" >&2; exit 1; }
[ -x "$UPSTREAM_BIN" ] || { echo "build first: cmake --build build --target agensio_upstream" >&2; exit 1; }
[[ " $SERVERS " != *" pingora "* ]] || [ -x "$PINGORA_BIN" ] || { echo "build first: bench/pingora/build.sh" >&2; exit 1; }
[ -f "$CERT" ] || "$ROOT/bench/certs/gen-cert.sh" >/dev/null
[ "$ORIGINS" -le 60000 ] || { echo "-n at most 60000" >&2; exit 2; }
ulimit -n 65536 2>/dev/null || true

PORT_UP=9100
port_of() { case "$1-$2" in agensio-plain) echo 8093 ;; agensio-tls) echo 8493 ;; pingora-plain) echo 8096 ;; pingora-tls) echo 8496 ;; direct-*) echo $PORT_UP ;; esac; }
for p in $PORT_UP 8093 8493 8096 8496; do nc -z 127.0.0.1 $p 2>/dev/null && { echo "port $p is busy" >&2; exit 1; }; done

# ---- CPU pinning ---------------------------------------------------------------------------
if [ $PIN = 1 ] && { [ "$(nproc)" -lt 24 ] || ! command -v taskset >/dev/null; }; then PIN=0; fi
for w in $WORKER_SETS; do [ "$w" -ge 1 ] && [ "$w" -le 4 ] || { echo "-w takes worker counts from 1 to 4" >&2; exit 2; }; done
UP_WORKERS=${UP_WORKERS:-4}
pin() {  # role [workers]: the command prefix that pins a process
  [ $PIN = 1 ] || return 0
  case $1 in
    proxy) echo "taskset -c 0-$(($2 - 1))" ;;
    upstream) echo "taskset -c 4-7" ;;
    load) echo "taskset -c 8-11,20-23" ;;
  esac
}

# ---- configurations ------------------------------------------------------------------------
mkdir -p "$TMP"
STAMP=$(date -u +%Y%m%d-%H%M%S)
OUT="$ROOT/bench/results/pingora-$STAMP.md"
RAW="$ROOT/bench/results/raw/pingora-$STAMP"; mkdir -p "$RAW"
ROWS="$RAW/rows.tsv"; MEM="$RAW/memory.tsv"; : > "$ROWS"; : > "$MEM"

origin_address() { echo "127.1.$(($1 / 250)).$(($1 % 250 + 1))"; }  # the K-th origin, as bench/pingora/proxy maps it
agensio_conf() {  # workers origins
  {
    printf '[server]\nworkers = %s\nidle_timeout = 65\nmax_requests_per_connection = 1000000\n\n[log]\naccess = "off"\nerror = "stderr"\n' "$1"
    for l in "127.0.0.1:8093" "127.0.0.1:8493"; do
      printf '\n[[site]]\nserver_name = ["*"]\nlisten = ["%s"]\nroot = "%s/bench/www"\nproxy = { max_idle = 256 }\n' "$l" "$ROOT"
      [ "$l" = "127.0.0.1:8493" ] && printf 'tls = { cert = "%s", key = "%s" }\n' "$CERT" "$KEY"
      printf '\n[[site.location]]\npath = "/"\nupstream = "http://127.0.0.1:%s"\n' $PORT_UP
    done
    for k in $(seq 0 $(($2 - 1))); do
      printf '\n[[site]]\nserver_name = ["o%s.test"]\nlisten = ["127.0.0.1:8093"]\nroot = "%s/bench/www"\n\n[[site.location]]\npath = "/"\nupstream = "http://%s:%s"\n' \
        "$k" "$ROOT" "$(origin_address "$k")" $PORT_UP
    done
  } > "$TMP/agensio.toml"
}

# ---- processes -----------------------------------------------------------------------------
UP_PID=""; SERVER_PID=""; HOLD_PID=""
start_upstream() {
  $(pin upstream) "$UPSTREAM_BIN" -p $PORT_UP -w $UP_WORKERS -a 0.0.0.0 > "$RAW/upstream.log" 2>&1 &
  UP_PID=$!
  for _ in $(seq 1 100); do nc -z 127.0.0.1 $PORT_UP 2>/dev/null && return 0; sleep 0.1; done
  echo "the upstream did not start" >&2; exit 1
}
start_server() {  # server workers origins tag
  local s=$1 w=$2 n=$3 log="$RAW/$1-$4.log"
  case $s in
    direct) return 0 ;;
    agensio)
      agensio_conf "$w" "$n"
      $(pin proxy "$w") "$AGENSIO_BIN" -c "$TMP/agensio.toml" > "$log" 2>&1 & SERVER_PID=$! ;;
    pingora)
      # Idle connections kept to origins: at least the clients' count, and four per origin in the
      # many-origins rows (Pingora's default of 128 for the whole process would close most there).
      local pool=1024; [ "$n" -gt 0 ] && pool=$((n * 4))
      PB_LISTEN=127.0.0.1:8096 PB_LISTEN_TLS=127.0.0.1:8496 PB_CERT="$CERT" PB_KEY="$KEY" PB_THREADS="$w" \
        PB_UPSTREAM=127.0.0.1:$PORT_UP PB_ORIGINS="$n" PB_POOL=$pool $(pin proxy "$w") "$PINGORA_BIN" > "$log" 2>&1 & SERVER_PID=$! ;;
  esac
  for _ in $(seq 1 100); do
    nc -z 127.0.0.1 "$(port_of "$s" plain)" 2>/dev/null && nc -z 127.0.0.1 "$(port_of "$s" tls)" 2>/dev/null && return 0
    kill -0 "$SERVER_PID" 2>/dev/null || break
    sleep 0.1
  done
  echo "$s did not start:" >&2; tail -5 "$log" >&2; exit 1
}
stop_server() {  # SIGTERM, and SIGKILL a second later: Pingora's answer to SIGTERM is a graceful exit of minutes
  [ -n "$SERVER_PID" ] || return 0
  kill "$SERVER_PID" 2>/dev/null || true
  for _ in $(seq 1 10); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.1; done
  kill -9 "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""; sleep 0.5
}
trap 'stop_server; [ -n "$HOLD_PID" ] && kill "$HOLD_PID" 2>/dev/null; [ -n "$UP_PID" ] && kill "$UP_PID" 2>/dev/null; true' EXIT
pid_of() { [ "$1" = direct ] && echo "$UP_PID" || echo "$SERVER_PID"; }
TCK=$(getconf CLK_TCK)
cpu_seconds() { awk -v tck="$TCK" '{ sub(/.*\) /, ""); printf "%.3f", ($12 + $13) / tck }' "/proc/$(pid_of "$1")/stat"; }
rss_kb() { awk '/^VmRSS/{print $2}' "/proc/$(pid_of "$1")/status"; }
upstream_connections() { curl -s "http://127.0.0.1:$PORT_UP/stats" | sed 's/.*"connections":\([0-9]*\).*/\1/'; }

# ---- correctness before speed --------------------------------------------------------------
verify() {  # server origins
  local s=$1 d="http://127.0.0.1:$PORT_UP" body; body=$(printf 'x%.0s' $(seq 1 2048))
  for base in "http://127.0.0.1:$(port_of "$s" plain)" "https://127.0.0.1:$(port_of "$s" tls)"; do
    [ "$(curl -sk "$base/json")" = "$(curl -s "$d/json")" ] || { echo "$s: /json differs at $base" >&2; exit 1; }
    for path in /big /page /chunked; do
      [ "$(curl -sk "$base$path" | md5sum)" = "$(curl -s "$d$path" | md5sum)" ] || { echo "$s: $path differs at $base" >&2; exit 1; }
    done
    [ "$(curl -sk -X POST --data-binary "$body" "$base/echo")" = "$body" ] || { echo "$s: POST /echo differs at $base" >&2; exit 1; }
  done
  [ "$(curl -sk --http2 -o /dev/null -w '%{http_version}' "https://127.0.0.1:$(port_of "$s" tls)/json")" = 2 ] || { echo "$s: no HTTP/2 over TLS" >&2; exit 1; }
  for field in "X-Forwarded-For: 127.0.0.1" "X-Forwarded-Proto: http" "X-Real-IP: 127.0.0.1"; do
    curl -s "http://127.0.0.1:$(port_of "$s" plain)/headers" | grep -qi "^$field" || { echo "$s: the origin did not receive $field" >&2; exit 1; }
  done
  if [ "$2" -gt 0 ]; then
    local last=$(($2 - 1))
    [ "$(curl -s -H "Host: o$last.test" "http://127.0.0.1:$(port_of "$s" plain)/json")" = "$(curl -s "$d/json")" ] || { echo "$s: o$last.test is not proxied" >&2; exit 1; }
    curl -s -H "Host: o$last.test" "http://127.0.0.1:$(port_of "$s" plain)/headers" | grep -qi "^Host: o$last.test" || { echo "$s: Host not passed on" >&2; exit 1; }
  fi
}

# ---- one measured row ----------------------------------------------------------------------
# test label workers server round tool url conns [streams | lua script]
row() {
  local test=$1 label=$2 w=$3 s=$4 round=$5 tool=$6 url=$7 conns=$8 extra=${9:-}
  local raw="$RAW/$test-$(echo "$label" | tr ' /?=,' '_____')-w$w-$s-r$round.txt"
  local threads=4; [ "$w" -gt 1 ] && threads=8
  local c0 k0 c1 k1 reqs rps p50 p99 errs
  c0=$(cpu_seconds "$s"); k0=$(upstream_connections)
  if [ "$tool" = wrk ]; then
    ORIGINS=$ORIGINS $(pin load) wrk -t$threads -c"$conns" -d"${DUR}s" --latency ${extra:+-s "$extra"} "$url" > "$raw" 2>&1
    c1=$(cpu_seconds "$s"); k1=$(upstream_connections)
    reqs=$(awk '/requests in/ {print $1}' "$raw"); rps=$(awk '/Requests\/sec/ {print $2}' "$raw")
    p50=$(awk '$1=="50%" {print $2}' "$raw"); p99=$(awk '$1=="99%" {print $2}' "$raw")
    errs=$( (grep -E 'Socket errors|Non-2xx' "$raw" || true) | sed 's/^ *//' | paste -sd';' - )
  else  # h2load runs a request count: a one-second probe sizes it for DUR seconds
    local probe n
    probe=$($(pin load) h2load -D 1 -c "$conns" -m "$extra" -t $threads "$url" 2>/dev/null | awk '/^finished in/{print $4}')
    n=$(awk -v r="${probe:-1000}" -v d="$DUR" 'BEGIN{printf "%d", r * d}'); [ "$n" -lt 1000 ] && n=1000
    sleep 1
    c0=$(cpu_seconds "$s"); k0=$(upstream_connections)
    $(pin load) h2load -n "$n" -c "$conns" -m "$extra" -t $threads "$url" > "$raw" 2>&1
    c1=$(cpu_seconds "$s"); k1=$(upstream_connections)
    reqs=$(awk '/^requests:/ {print $8}' "$raw"); rps=$(awk '/^finished in/ {print $4}' "$raw")
    p50="$(awk '/^time for request:/ {print $6}' "$raw") (mean)"; p99="$(awk '/^time for request:/ {print $5}' "$raw") (max)"
    errs=$(awk '/^requests:/ { f=$10+0; e=$12+0; if (f+e > 0) print f " failed, " e " errored" }' "$raw")
  fi
  [ -n "$errs" ] || errs="-"
  [ -n "$reqs" ] && [ "$reqs" -gt 0 ] || { echo "$s $test $label: no requests answered, see $raw" >&2; exit 1; }
  local us opened per rss
  us=$(awk -v a="$c0" -v b="$c1" -v n="$reqs" 'BEGIN{ printf "%.2f", (b - a) * 1e6 / n }')
  opened=$((k1 - k0)); per=$(awk -v o="$opened" -v n="$reqs" 'BEGIN{ printf "%.2f", o * 1000 / n }')
  rss=$(awk -v k="$(rss_kb "$s")" 'BEGIN{ printf "%.1f", k / 1024 }')
  [ "$s" = direct ] && { opened="-"; per="-"; }
  printf '  %-8s %-7s w=%s %-28s %10s req/s  p50 %-9s p99 %-9s %7s us/req  %6s origin conns  %6s MB  %s\n' "$s" "$test" "$w" "$label" "$rps" "$p50" "$p99" "$us" "$opened" "$rss" "$errs"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$test" "$label" "$w" "$s" "$round" "$rps" "$p50" "$p99" "$us" "$opened" "$per" "$rss" "$errs" >> "$ROWS"
  sleep 1
}

# ---- the groups ----------------------------------------------------------------------------
group() {  # test workers server round
  local test=$1 w=$2 s=$3 round=$4 n=0 plain tls
  [ "$test" = origins ] && n=$ORIGINS
  start_server "$s" "$w" "$n" "$test-w$w-r$round"
  [ "$s" = direct ] || verify "$s" "$n"
  plain="http://127.0.0.1:$(port_of "$s" plain)"; tls="https://127.0.0.1:$(port_of "$s" tls)"
  # A warm-up, except where the cold start is the measurement.
  [ "$test" = origins ] || { $(pin load) wrk -t4 -c64 -d2s "$plain/json" >/dev/null 2>&1; sleep 1; }
  case $test in
    proxy)
      row proxy "/json, 64 conns" "$w" "$s" "$round" wrk "$plain/json" 64
      row proxy "/json, 16 conns" "$w" "$s" "$round" wrk "$plain/json" 16
      row proxy "/big 100 KB, 64 conns" "$w" "$s" "$round" wrk "$plain/big" 64
      row proxy "/slow 20 ms, 256 conns" "$w" "$s" "$round" wrk "$plain/slow?ms=20" 256 ;;
    tls)
      row tls "/json, 64 conns" "$w" "$s" "$round" wrk "$tls/json" 64
      row tls "/big 100 KB, 64 conns" "$w" "$s" "$round" wrk "$tls/big" 64 ;;
    h2)
      row h2 "/json, 64 conns x 1" "$w" "$s" "$round" h2load "$tls/json" 64 1
      row h2 "/json, 64 conns x 10" "$w" "$s" "$round" h2load "$tls/json" 64 10
      row h2 "/big 100 KB, 64 conns x 10" "$w" "$s" "$round" h2load "$tls/big" 64 10 ;;
    mixed)
      row mixed "mixed traffic, 256 conns" "$w" "$s" "$round" wrk "$tls/" 256 "$HERE/mixed.lua" ;;
    origins)
      row origins "$ORIGINS origins, cold" "$w" "$s" "$round" wrk "$plain/" 256 "$HERE/origins.lua"
      row origins "$ORIGINS origins, warm" "$w" "$s" "$round" wrk "$plain/" 256 "$HERE/origins.lua" ;;
  esac
  stop_server
}

memory() {  # server mode
  local s=$1 mode=$2 flags="" port
  port=$(port_of "$s" plain)
  case $mode in
    "HTTP/1.1") ;;
    "HTTP/1.1 over TLS") flags="--tls"; port=$(port_of "$s" tls) ;;
    "HTTP/2 over TLS") flags="--tls --h2"; port=$(port_of "$s" tls) ;;
  esac
  local tag; tag="memory-$(echo "$mode" | tr ' /.' '___')"
  start_server "$s" 1 0 "$tag"
  $(pin load) wrk -t2 -c16 -d1s "http://127.0.0.1:$(port_of "$s" plain)/json" >/dev/null 2>&1; sleep 3  # the process has served; past agensio's idle shed
  local base idle alive hold="$RAW/hold-$s-$tag.txt"
  base=$(rss_kb "$s")
  # shellcheck disable=SC2086
  $(pin load) python3 "$HERE/hold.py" "$IDLE" "$port" $flags --settle 6 > "$hold" 2>&1 &
  HOLD_PID=$!
  for _ in $(seq 1 1500); do grep -q '^alive' "$hold" 2>/dev/null && break; kill -0 $HOLD_PID 2>/dev/null || break; sleep 0.2; done
  alive=$(awk '/^alive/{print $2}' "$hold"); idle=$(rss_kb "$s")
  kill $HOLD_PID 2>/dev/null || true; wait $HOLD_PID 2>/dev/null || true; HOLD_PID=""
  [ -n "$alive" ] && [ "$alive" -gt 0 ] || { echo "$s $mode: no connection held, see $hold" >&2; exit 1; }
  local per; per=$(( (idle - base) * 1024 / alive ))
  printf '  %-8s memory  %-18s baseline %7s KB  with %s idle %8s KB  per connection %6s bytes\n' "$s" "$mode" "$base" "$alive" "$idle" "$per"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$mode" "$s" "$base" "$idle" "$alive" "$per" >> "$MEM"
  stop_server
}

start_upstream
for round in $(seq 1 "$ROUNDS"); do
  for test in $TESTS; do
    case $test in
      proxy) for s in direct $SERVERS; do
               if [ "$s" = direct ]; then
                 row proxy "/json, 64 conns" 1 direct "$round" wrk "http://127.0.0.1:$PORT_UP/json" 64
                 row proxy "/big 100 KB, 64 conns" 1 direct "$round" wrk "http://127.0.0.1:$PORT_UP/big" 64
               else group proxy 1 "$s" "$round"; fi
             done ;;
      tls|h2) for s in $SERVERS; do group "$test" 1 "$s" "$round"; done ;;
      mixed|origins) for w in $WORKER_SETS; do for s in $SERVERS; do group "$test" "$w" "$s" "$round"; done; done ;;
      memory) [ "$round" = 1 ] && for mode in "HTTP/1.1" "HTTP/1.1 over TLS" "HTTP/2 over TLS"; do for s in $SERVERS; do memory "$s" "$mode"; done; done ;;
      *) echo "unknown test: $test" >&2; exit 2 ;;
    esac
  done
done

# ---- the report ----------------------------------------------------------------------------
PINGORA_VERSION=$(cat "$RAW"/pingora-*.log 2>/dev/null | awk '/^pingora [0-9]/ {print $1 " " $2; exit}' || true)   # its start line
PINGORA_TLS=$(strings -a "$PINGORA_BIN" 2>/dev/null | awk '/^OpenSSL [0-9]/ {print $1 " " $2; exit}' || true)
{
  echo "# agensio and Pingora as reverse proxies, $STAMP"
  echo
  echo "- machine: $(uname -m), $(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //'), $(nproc) CPUs, $(uname -sr)"
  echo "- commit: $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo '?')$(git -C "$ROOT" diff --quiet 2>/dev/null || echo '+dirty'); command: \`bench/pingora/run.sh $ARGS\`"
  echo "- agensio: $("$AGENSIO_BIN" -v 2>&1 | head -1), $(openssl version 2>/dev/null | cut -d' ' -f1-2) from the system"
  echo "- Pingora: ${PINGORA_VERSION:-not run} (bench/pingora/proxy, release build with LTO), its own ${PINGORA_TLS:-OpenSSL} linked in (the crate's \`openssl\` feature)"
  echo "- origin: build/agensio_upstream, $UP_WORKERS workers; load: $(wrk -v 2>&1 | head -1 | cut -d' ' -f1-2), h2load $(h2load --version | awk '{print $2}'), ${DUR} s a row, $ROUNDS round(s), 4 load threads (8 with more than one proxy worker)"
  if [ $PIN = 1 ]; then echo "- pinned: the proxy on CPUs 0..W-1 (W workers or threads), the origin on 4-7, the load generator on 8-11 and 20-23"
  else echo "- not pinned: the proxy, the origin and the load generator share the CPUs"; fi
  echo "- both forward Host, X-Forwarded-For, X-Forwarded-Proto and X-Real-IP, keep connections to the origin, write no access log; agensio \`workers = W\`, Pingora \`threads = W\` (work stealing on, its default)"
  echo "- CPU us/req = CPU time of the proxy's process (all threads) / requests answered; RSS after the row; origin conns = connections the proxy opened to origins during the row"
  echo
  echo "## Summary: Pingora relative to agensio"
  echo
  echo "A ratio above 1 in the last two columns means agensio used less. Means over the rounds."
  echo
  echo "| group | row | workers | agensio req/s | Pingora req/s | agensio CPU us/req | Pingora CPU us/req | Pingora CPU / agensio CPU | Pingora RSS / agensio RSS |"
  echo "|---|---|---|---|---|---|---|---|---|"
  awk -F'\t' '
    $4 == "agensio" || $4 == "pingora" {
      k = $1 "\t" $2 "\t" $3; if (!(k in seen)) { seen[k] = 1; order[++n] = k }
      rps[k, $4] += $6; us[k, $4] += $9; rss[k, $4] += $12; cnt[k, $4]++
    }
    END {
      for (i = 1; i <= n; i++) {
        k = order[i]; split(k, f, "\t"); a = cnt[k, "agensio"]; p = cnt[k, "pingora"]
        if (!a || !p) continue
        ar = rps[k, "agensio"] / a; pr = rps[k, "pingora"] / p; au = us[k, "agensio"] / a; pu = us[k, "pingora"] / p
        am = rss[k, "agensio"] / a; pm = rss[k, "pingora"] / p
        printf "| %s | %s | %s | %.0f | %.0f | %.2f | %.2f | %.2f | %.2f |\n", f[1], f[2], f[3], ar, pr, au, pu, (au > 0 ? pu / au : 0), (am > 0 ? pm / am : 0)
      }
    }' "$ROWS"
  if grep -q '^origins' "$ROWS"; then
    echo
    echo "## Connections to origins"
    echo
    echo "$ORIGINS origins, 256 client connections, each request to an origin drawn evenly. Cold: the first ${DUR} s after the start. Warm: the next ${DUR} s. agensio keeps a pool per worker, Pingora one pool for all its threads."
    echo
    echo "| workers | phase | agensio opened | Pingora opened | agensio per 1000 req | Pingora per 1000 req | agensio / Pingora |"
    echo "|---|---|---|---|---|---|---|"
    awk -F'\t' '
      $1 == "origins" {
        k = $3 "\t" $2; if (!(k in seen)) { seen[k] = 1; order[++n] = k }
        opened[k, $4] += $10; per[k, $4] += $11; cnt[k, $4]++
      }
      END {
        for (i = 1; i <= n; i++) {
          k = order[i]; split(k, f, "\t"); a = cnt[k, "agensio"]; p = cnt[k, "pingora"]
          if (!a || !p) continue
          ao = opened[k, "agensio"] / a; po = opened[k, "pingora"] / p
          printf "| %s | %s | %.0f | %.0f | %.2f | %.2f | %.2f |\n", f[1], (f[2] ~ /cold/ ? "cold" : "warm"), ao, po, per[k, "agensio"] / a, per[k, "pingora"] / p, (po > 0 ? ao / po : 0)
        }
      }' "$ROWS"
  fi
  if [ -s "$MEM" ]; then
    echo
    echo "## Memory with idle client connections"
    echo
    echo "$IDLE connections opened, one request answered on each, then left idle; resident memory read six seconds later. Per connection = (idle - baseline) / connections still open."
    echo
    echo "| connections | server | baseline KB | idle KB | still open | bytes per connection |"
    echo "|---|---|---|---|---|---|"
    awk -F'\t' '{ printf "| %s | %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5, $6 }' "$MEM"
  fi
  echo
  echo "## Every row"
  echo
  echo "| group | row | workers | server | round | req/s | p50 | p99 | CPU us/req | origin conns | origin conns per 1000 req | RSS MB | errors |"
  echo "|---|---|---|---|---|---|---|---|---|---|---|---|---|"
  awk -F'\t' '{ printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13 }' "$ROWS"
} > "$OUT"
echo; echo "results: $OUT"
