#!/bin/bash
# One agensio worker under the arena's HTTP/3 load (h2load over QUIC, the h2load-h3:local
# image built from the arena's docker/h2load-h3.Dockerfile), in the perf container: req/s,
# the server's CPU per request, cycles and instructions, syscalls, a flat profile. nginx
# (the devbox's, with its http_v3 module) is profiled on the same box serving a static
# file over h3 with one worker, for the cycles per request of another QUIC stack; the arena's
# nginx entry answers the sum from a module, so its row is not this one's. Usage:
#   bench/httparena/profile-h3.sh                 # both
#   ONLY=agensio|nginx bench/httparena/profile-h3.sh
# The load is `h2load --alpn-list=h3 -c 64 -m 64 -t 4`, the arena's baseline-h3 shape.
set -u
export LC_NUMERIC=C
cd "$(dirname "$0")/../.."
CFG=${CFG:-bench/tmp/perf-h3.toml}   # one worker, 8443 TLS with h2 and h3, handler = "httparena" on /, the localhost cert
BIN=${BIN:-build/agensio}
[ -f "$CFG" ] || sed "s|@ROOT@|$PWD|g; s|protocols = \[\"h2c\", \"h2\", \"h1\"\]|protocols = [\"h2c\", \"h2\", \"h1\", \"h3\"]|" bench/httparena/perf-h2.toml.example > "$CFG"
[ -f bench/tmp/arena-dataset.json ] || cp bench/tmp/httparena/data/dataset.json bench/tmp/arena-dataset.json
docker image inspect h2load-h3:local >/dev/null 2>&1 || { echo "build the load generator first: docker build -t h2load-h3:local -f bench/tmp/httparena/docker/h2load-h3.Dockerfile bench/tmp/httparena/docker"; exit 1; }
docker rm -f perfbox >/dev/null 2>&1
docker run -d --name perfbox --init --cap-add SYS_ADMIN --cap-add PERFMON --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox-perf sleep 3600 >/dev/null
lg() { docker run --rm --network container:perfbox h2load-h3:local "$@"; }
profile() {  # name pid-command url
    local name=$1 pidcmd=$2 url=$3
    echo "== $name: syscalls (3 s under load)"
    lg --alpn-list=h3 -c 64 -m 64 -t 4 -D 6 "$url" > bench/tmp/h2load-h3-$name-st.txt 2>&1 &
    sleep 1.5; docker exec perfbox bash -c "P=\$($pidcmd); timeout -s INT 3 strace -c -f -p \$P -o /tmp/strace.txt >/dev/null 2>&1; awk 'NR<=2 || /total/ || /sendmmsg|recvmmsg|sendmsg|recvmsg|epoll|write|read/' /tmp/strace.txt | head -14"
    wait
    grep -a -E "finished in|requests:|UDP datagram" bench/tmp/h2load-h3-$name-st.txt | head -3
    echo "== $name: CPU per request, cycles and profile"
    local c0; c0=$(docker exec perfbox bash -c "P=\$($pidcmd); awk '{print \$14+\$15}' /proc/\$P/stat")
    lg --alpn-list=h3 -c 64 -m 64 -t 4 -D 8 "$url" > bench/tmp/h2load-h3-$name-c.txt 2>&1 &
    sleep 1.5; docker exec perfbox bash -c "P=\$($pidcmd); perf stat -e cycles:u,cycles:k,instructions:u -p \$P -- sleep 2 2>&1 | grep -E 'cycles|instructions'; perf record -F 1999 -g -p \$P -o /tmp/perf-$name.data -- sleep 3 >/dev/null 2>&1; perf report -i /tmp/perf-$name.data --stdio --no-children --sort dso 2>/dev/null | grep -E '^ +[0-9]' | head -8; perf report -i /tmp/perf-$name.data --stdio --no-children -g none --sort symbol 2>/dev/null | grep -E '^ +[0-9]' | sed 's/ \+- \+-.*$//' | cut -c1-160 | head -50"
    wait
    local c1; c1=$(docker exec perfbox bash -c "P=\$($pidcmd); awk '{print \$14+\$15}' /proc/\$P/stat")
    grep -a -E "finished in|requests:|UDP datagram" bench/tmp/h2load-h3-$name-c.txt | head -3
    local n; n=$(awk '/^requests:/{print $4}' bench/tmp/h2load-h3-$name-c.txt)
    awk -v c0="$c0" -v c1="$c1" -v n="$n" -v hz="$(getconf CLK_TCK)" 'BEGIN{ if (n>0) printf "server CPU: %.2f us per request over the 8 s run (%d ticks, %d requests)\n", (c1-c0)/hz*1e6/n, c1-c0, n }'
    docker exec perfbox bash -c "P=\$($pidcmd); echo \"RSS: \$(awk '/^VmRSS/{print \$2}' /proc/\$P/status) KB\""
}
if [ "${ONLY:-}" != nginx ]; then
    echo "### agensio (one worker, the arena handler)"
    docker exec -d perfbox bash -c "$BIN -c $CFG > /tmp/agensio.err 2>&1"
    sleep 1
    profile agensio "pidof agensio" "https://127.0.0.1:8443/baseline2?a=1&b=1"
    docker exec perfbox bash -c 'kill $(pidof agensio)'
    sleep 0.5
fi
if [ "${ONLY:-}" != agensio ]; then
    echo "### nginx (one worker, a 2-byte static file over h3)"
    printf '3' > bench/www/sum.txt
    sed "s#@WORKERS@#1#g; s#@BENCH@#$PWD/bench#g; s#listen 127.0.0.1:8444 ssl backlog=4096;#listen 127.0.0.1:8444 ssl backlog=4096;\n        listen 127.0.0.1:8444 quic reuseport;\n        http3 on;#" bench/nginx.conf > bench/tmp/nginx-h3-perf.conf
    docker exec -d perfbox bash -c "cd bench && nginx -p $PWD/bench -c $PWD/bench/tmp/nginx-h3-perf.conf -g 'daemon off;' > /tmp/nginx.err 2>&1"
    sleep 1
    profile nginx "pgrep -o -f 'nginx: worker'" "https://127.0.0.1:8444/sum.txt"
    docker exec perfbox bash -c "pkill -f 'nginx: '"
    rm -f bench/www/sum.txt
fi
docker rm -f perfbox >/dev/null
