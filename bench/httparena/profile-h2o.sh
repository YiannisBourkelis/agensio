#!/bin/bash
# h2o's HttpArena entry on one thread against one agensio worker, under the same h2load in
# the same perf container: req/s, syscalls, cycles and instructions, a flat profile of each.
# The arena's h2o app has no thread setting (it starts one loop per online CPU), so its
# main.c in the arena clone gets an H2O_THREADS variable, the image is rebuilt inside the
# Docker-in-Docker container of local.sh (the h2o build layer is cached there), and the
# statically linked app is copied out to bench/tmp/h2o-bin. Needs `local.sh setup` done and
# the agensio-devbox-perf image (perf, strace). Usage:
#   bench/httparena/profile-h2o.sh [build]        # build: (re)make bench/tmp/h2o-bin first
#   ONLY=agensio|h2o bench/httparena/profile-h2o.sh
# Output on stdout; the load is `h2load -c 64 -m 100 -t 4` on the arena's baseline-h2 URL.
set -u
cd "$(dirname "$0")/../.."
URL=${URL:-https://127.0.0.1:8443/baseline2?a=1&b=1}
CFG=${CFG:-bench/tmp/perf-h2.toml}   # one worker, 8443 TLS with h2, handler = "httparena" on /, the localhost cert
ARENA=${ARENA:-bench/tmp/httparena}
[ -f "$CFG" ] || sed "s|@ROOT@|$PWD|g" bench/httparena/perf-h2.toml.example > "$CFG"
[ -f bench/tmp/arena-dataset.json ] || cp "$ARENA/data/dataset.json" bench/tmp/arena-dataset.json
if [ "${1:-}" = build ] || [ ! -x bench/tmp/h2o-bin/server ]; then
    sed -i 's|    int nthreads = sysconf(_SC_NPROCESSORS_ONLN);|    int nthreads = getenv("H2O_THREADS") ? atoi(getenv("H2O_THREADS")) : (int)sysconf(_SC_NPROCESSORS_ONLN);|' "$ARENA/frameworks/h2o/src/main.c"
    docker exec -w /arena httparena-dind docker build -t h2o-one frameworks/h2o >/dev/null || exit 1
    docker exec httparena-dind sh -c 'rm -rf /arena/h2o-bin; mkdir -p /arena/h2o-bin; id=$(docker create h2o-one); docker cp $id:/server /arena/h2o-bin/server; docker rm $id >/dev/null'
    docker run --rm -v "$PWD:$PWD" -w "$PWD" --user root agensio-devbox chown -R "$(id -u):$(id -g)" "$ARENA/h2o-bin"
    rm -rf bench/tmp/h2o-bin && mv "$ARENA/h2o-bin" bench/tmp/h2o-bin
fi
docker rm -f perfbox >/dev/null 2>&1
docker run -d --name perfbox --init --cap-add SYS_ADMIN --cap-add PERFMON --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox-perf sleep 3600 >/dev/null
lg() { docker run --rm --network container:perfbox -v "$PWD:$PWD" -w "$PWD" agensio-devbox "$@"; }
profile() {  # name pid-command
    local name=$1 pidcmd=$2
    echo "== $name: syscalls (3 s under load)"
    lg h2load -c 64 -m 100 -t 4 -D 6 "$URL" > bench/tmp/h2load-$name-st.txt 2>&1 &
    sleep 1.5; docker exec perfbox bash -c "P=\$($pidcmd); timeout -s INT 3 strace -c -f -p \$P -o /tmp/strace.txt >/dev/null 2>&1; awk 'NR<=2 || /total/ || /sendmsg|writev|recvfrom|epoll|write|sendto|read/' /tmp/strace.txt | head -14"
    wait
    grep -a -E "finished in|requests:|status codes" bench/tmp/h2load-$name-st.txt | head -3
    echo "== $name: cycles and profile"
    lg h2load -c 64 -m 100 -t 4 -D 8 "$URL" > bench/tmp/h2load-$name-c.txt 2>&1 &
    sleep 1.5; docker exec perfbox bash -c "P=\$($pidcmd); perf stat -e cycles:u,cycles:k,instructions:u -p \$P -- sleep 2 2>&1 | grep -E 'cycles|instructions'; perf record -F 1999 -g -p \$P -o /tmp/perf-$name.data -- sleep 3 >/dev/null 2>&1; perf report -i /tmp/perf-$name.data --stdio --no-children --sort dso 2>/dev/null | grep -E '^ +[0-9]' | head -8; perf report -i /tmp/perf-$name.data --stdio --no-children -g none --sort symbol 2>/dev/null | grep -E '^ +[0-9]' | sed 's/ \+- \+-.*$//' | cut -c1-160 | head -60"
    wait
    grep -a -E "finished in|status codes" bench/tmp/h2load-$name-c.txt
}
if [ "${ONLY:-}" != agensio ]; then
    echo "### h2o (one thread)"
    docker exec -d perfbox bash -c "cd bench/tmp/h2o-bin && H2O_THREADS=1 TLS_CERT=$PWD/bench/certs/cert.pem TLS_KEY=$PWD/bench/certs/key.pem ./server > /tmp/h2o.out 2>&1"
    sleep 1
    docker exec perfbox bash -c 'cat /tmp/h2o.out; ps -o pid,nlwp,comm -C server'
    profile h2o "pidof server"
    docker exec perfbox bash -c 'ps -o cputime= -p $(pidof server); kill $(pidof server)'
    sleep 1
fi
if [ "${ONLY:-}" != h2o ]; then
    echo "### agensio (one worker)"
    docker exec -d perfbox bash -c "build/agensio -c $CFG > /tmp/agensio.err 2>&1"
    sleep 1
    profile agensio "pidof agensio"
    docker exec perfbox bash -c 'ps -o cputime= -p $(pidof agensio)'
fi
docker rm -f perfbox >/dev/null
