#!/usr/bin/env bash
# PHP through a generated php-fpm pool (a site with `user`, docs/configuration.md 7), the way a
# hosted PHP site runs: throughput, latency, and the CPU per request of agensio and of php-fpm
# (master, children, and the children it reaped) for a small script and a 20 KB page; then a
# burst of slow requests that opens many FastCGI connections at once (the alpha.66 report: an
# ondemand pool behind kept connections left some waiting until read_timeout). With two binaries
# they are alternated in one session, as bench/ab.sh does. Linux, as root (the devbox as root):
#
#   docker run --rm --init --ulimit nofile=65536:65536 --user root -v "$PWD:$PWD" -w "$PWD" \
#     agensio-devbox bench/php/pool.sh BIN [BIN2] [-r ROUNDS] [-d SECONDS] [-c CONNECTIONS] [-m PM] [-o 'KEY = VALUE']
#
# Defaults: 3 rounds, 10 s per row, wrk with 8 connections, pm = ondemand, 8 children, one
# worker, the pool's other settings as generated (max_requests 500); -o adds to the site's
# php table (for example -o 'keep_conn = false'). Writes
# bench/results/php-pool-<stamp>.md.
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "pool.sh: run as root (the devbox as root)"; exit 1; }
BINS=("$(readlink -f "$1")"); shift
if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then BINS+=("$(readlink -f "$1")"); shift; fi
ROUNDS=3; DUR=10; CONNS=8; PM=ondemand; CHILDREN=8; EXTRA=""
while getopts r:d:c:m:o: o; do case $o in r) ROUNDS=$OPTARG ;; d) DUR=$OPTARG ;; c) CONNS=$OPTARG ;; m) PM=$OPTARG ;; o) EXTRA=", $OPTARG" ;; *) exit 2 ;; esac; done
FPM=$(ls /usr/sbin/php-fpm* | head -1)
ROOT=$(pwd)
STAMP=$(date -u +%Y%m%d-%H%M%S)
OUT=$ROOT/bench/results/php-pool-$STAMP.md
T=$(mktemp -d /tmp/agensio-phpbench.XXXXXX); chmod 755 "$T"
PORT=18096
cleanup() { pkill -f "^/.*agensio -c $T/" 2>/dev/null; [ -f "$T/fpm.pid" ] && kill "$(cat "$T/fpm.pid")" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

for u in web1 agensio; do id -u $u > /dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin $u; done
mkdir -p "$T/run" "$T/state" "$T/logs" "$T/pool.d" "$T/web1/site/public"
chown agensio:agensio "$T/logs"; chmod 750 "$T/logs"
P=$T/web1/site/public
echo '<?php echo "hello\n";' > "$P/hello.php"
echo '<?php echo str_repeat("<p>agensio php benchmark page, twenty kilobytes of markup.</p>\n", 320);' > "$P/page.php"
echo '<?php usleep(150000); echo "slow\n";' > "$P/slow.php"
chown -R web1:agensio "$T/web1"; chmod 2750 "$T/web1" "$T/web1/site" "$P"; chmod 644 "$P"/*.php
cat > "$T/agensio.toml" <<EOF
[server]
workers = 1
user = "agensio"
pools_run = "$T/run"
state_dir = "$T/state"
[log]
access = "off"
error = "$T/logs/error.log"
[[site]]
server_name = ["php.test"]
listen = ["127.0.0.1:$PORT"]
root = "$P"
user = "web1"
app = "php"
php = { children = $CHILDREN, pm = "$PM", read_timeout = 5$EXTRA }
EOF
"${BINS[0]}" pools -c "$T/agensio.toml" --out "$T/pool.d" > /dev/null
printf '[global]\npid = %s/fpm.pid\nerror_log = %s/fpm.log\ninclude = %s/pool.d/*.conf\n' "$T" "$T" "$T" > "$T/fpm.conf"
cat > "$T/burst.py" <<'EOF'
# conns keep-alive connections, `per` GETs each, all at once: the statuses and the wall time.
import http.client, sys, threading, time
port, conns, per, path = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
codes, lock = [], threading.Lock()
def run():
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    for _ in range(per):
        try:
            c.request("GET", path, headers={"Host": "php.test"})
            r = c.getresponse(); r.read(); s = r.status
        except Exception:
            s = 0; c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        with lock: codes.append(s)
t0 = time.time()
ts = [threading.Thread(target=run) for _ in range(conns)]
for t in ts: t.start()
for t in ts: t.join()
print(codes.count(200), codes.count(504), sum(1 for x in codes if x not in (200, 504)), "%.2f" % (time.time() - t0))
EOF

# CPU in clock ticks (utime + stime; for php-fpm's master also its reaped children), read after
# the ") " that ends the command name.
ticks() { sed 's/.*) //' "/proc/$1/stat" | awk '{print $12 + $13}'; }
fpm_ticks() {
  local m=$1 t c
  t=$(sed 's/.*) //' "/proc/$m/stat" | awk '{print $12 + $13 + $14 + $15}')
  for c in $(pgrep -P "$m"); do t=$((t + $(sed 's/.*) //' "/proc/$c/stat" 2>/dev/null | awk '{print $12 + $13}' || echo 0))); done
  echo "$t"
}
HZ=$(getconf CLK_TCK)

row() {  # label path: one measured wrk run, after a 2 s warm-up
  local label=$1 path=$2 a0 f0 a1 f1 req rps p50 p99
  wrk -t2 -c"$CONNS" -d2s -H "Host: php.test" "http://127.0.0.1:$PORT$path" > /dev/null 2>&1
  a0=$(ticks "$APID"); f0=$(fpm_ticks "$FPID")
  wrk -t2 -c"$CONNS" -d"${DUR}s" --latency -H "Host: php.test" "http://127.0.0.1:$PORT$path" > "$T/wrk.out" 2>&1
  a1=$(ticks "$APID"); f1=$(fpm_ticks "$FPID")
  req=$(awk '/requests in/ {print $1}' "$T/wrk.out")
  rps=$(awk '/Requests\/sec/ {printf "%.0f", $2}' "$T/wrk.out")
  p50=$(awk '$1 == "50%" {print $2}' "$T/wrk.out"); p99=$(awk '$1 == "99%" {print $2}' "$T/wrk.out")
  local non2xx; non2xx=$(awk '/Non-2xx/ {print $4}' "$T/wrk.out")
  printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' "$label" "$path" "$req" "$rps" "$p50" "$p99" \
    "$(awk -v d=$((a1 - a0)) -v hz="$HZ" -v n="$req" 'BEGIN {printf "%.1f", d * 1000000 / hz / n}')" \
    "$(awk -v d=$((f1 - f0)) -v hz="$HZ" -v n="$req" 'BEGIN {printf "%.1f", d * 1000000 / hz / n}')" "${non2xx:-0}"
  cat "$T/wrk.out" >> "$T/raw.txt"
}

{
  echo "# PHP through a generated pool: $(basename "${BINS[0]}")${BINS[1]:+ vs $(basename "${BINS[1]}")}"
  echo
  echo "- machine: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'), $(nproc) threads; $(. /etc/os-release; echo "$PRETTY_NAME"), kernel $(uname -r)"
  echo "- date: $(date -u '+%Y-%m-%d %H:%M UTC'); commit $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null)$(git -C "$ROOT" diff --quiet 2>/dev/null || echo ' (with uncommitted changes)')"
  echo "- binaries: ${BINS[*]}"
  for b in "${BINS[@]}"; do echo "  - $(basename "$b"): $("$b" --version 2>&1 | head -1), sha256 $(sha256sum "$b" | cut -c1-12)"; done
  echo "- php-fpm: $("$FPM" -v | head -1)"
  echo "- pool: pm = $PM, $CHILDREN children, as agensio pools generates it; agensio one worker, server.user agensio; php read_timeout 5 s${EXTRA:+; php table also: ${EXTRA#, }}"
  echo "- load: wrk -t2 -c$CONNS, ${DUR} s per row after 2 s of warm-up; burst: 30 keep-alive connections x 4 GETs of a 150 ms script at once, on a pool started cold"
  echo "- command: bench/php/pool.sh ${BINS[*]} -r $ROUNDS -d $DUR -c $CONNS -m $PM${EXTRA:+ -o '${EXTRA#, }'}"
  echo "- CPU: utime + stime per request from /proc (agensio's process; php-fpm's master, its children and the children it reaped)"
  echo
  echo "| binary | path | requests | req/s | p50 | p99 | agensio us/req | php-fpm us/req | non-2xx |"
  echo "|---|---|---|---|---|---|---|---|---|"
} > "$OUT"
BURSTS=""
for r in $(seq 1 "$ROUNDS"); do
  for b in "${BINS[@]}"; do
    "$FPM" -y "$T/fpm.conf" -D
    for _ in $(seq 1 50); do [ -S "$T/run/agensio-web1.sock" ] && break; sleep 0.1; done
    FPID=$(cat "$T/fpm.pid")
    "$b" -c "$T/agensio.toml" > "$T/agensio.out" 2>&1 & APID=$!
    for _ in $(seq 1 50); do nc -z 127.0.0.1 $PORT 2> /dev/null && break; sleep 0.1; done
    for _ in 1 2 3; do curl -s -o /dev/null -H "Host: php.test" "http://127.0.0.1:$PORT/hello.php"; done   # the report's warm-up
    read -r ok g504 other secs < <(python3 "$T/burst.py" $PORT 30 4 /slow.php)
    BURSTS+="| $(basename "$b") | $r | $ok | $g504 | $other | $secs |"$'\n'
    row "$(basename "$b")" /hello.php >> "$OUT"
    row "$(basename "$b")" /page.php >> "$OUT"
    kill "$APID"; wait "$APID" 2> /dev/null
    kill "$FPID"; for _ in $(seq 1 50); do kill -0 "$FPID" 2> /dev/null || break; sleep 0.1; done
    rm -f "$T/run/agensio-web1.sock"
  done
done
{
  echo
  echo "Burst (120 requests of /slow.php, 150 ms each, over 30 connections; 504 = waited for read_timeout):"
  echo
  echo "| binary | round | 200 | 504 | other | seconds |"
  echo "|---|---|---|---|---|---|"
  printf '%s' "$BURSTS"
  echo
  echo '```'
  cat "$T/raw.txt"
  echo '```'
} >> "$OUT"
sed -n '/^| binary | path/,/^$/p;/^Burst/,/^```/p' "$OUT" | grep -v '^```'
echo "written: $OUT"
