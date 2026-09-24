#!/bin/bash
# Twelve agensio workers, then h2o's arena app with twelve threads, each on cores 0-5 with their SMT
# siblings under h2load with twelve threads on the other six cores; perf over every thread of the
# server: where the per-request cost goes when the workers multiply. Needs profile-h2o.sh's h2o build.
set -u
cd "$(dirname "$0")/../.."
URL="https://127.0.0.1:8443/baseline2?a=1&b=1"
[ -f bench/tmp/perf-h2.toml ] || sed "s|@ROOT@|$PWD|g" bench/httparena/perf-h2.toml.example > bench/tmp/perf-h2.toml
sed 's/^workers = 1/workers = 12/' bench/tmp/perf-h2.toml > bench/tmp/perf-h2-12.toml
[ -x bench/tmp/h2o-bin/server ] || { echo "run bench/httparena/profile-h2o.sh build first"; exit 1; }
docker rm -f perfbox >/dev/null 2>&1
docker run -d --name perfbox --init --cap-add SYS_ADMIN --cap-add PERFMON --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox-perf sleep 3600 >/dev/null
lg() { docker run --rm --network container:perfbox -v "$PWD:$PWD" -w "$PWD" agensio-devbox "$@"; }
profile() {
    local name=$1 pidcmd=$2
    echo "== $name: 12 workers pinned, h2load -c 512 -m 100 -t 12 pinned"
    lg taskset -c 6-11,18-23 h2load -c 512 -m 100 -t 12 -D 8 "$URL" > bench/tmp/h2load-$name-12.txt 2>&1 &
    sleep 2; docker exec perfbox bash -c "P=\$($pidcmd); perf stat -e cycles:u,cycles:k,instructions:u,cache-misses,L1-dcache-load-misses -p \$P -- sleep 2 2>&1 | grep -E 'cycles|instructions|misses'; perf record -F 999 -p \$P -o /tmp/perf-$name-12.data -- sleep 3 >/dev/null 2>&1; perf report -i /tmp/perf-$name-12.data --stdio --no-children --sort dso 2>/dev/null | grep -E '^ +[0-9]' | head -6; perf report -i /tmp/perf-$name-12.data --stdio --no-children --sort symbol 2>/dev/null | grep -E '^ +[0-9]' | sed 's/ \+- \+-.*$//' | cut -c1-150 | head -40"
    wait
    grep -a -E "finished in|status codes" bench/tmp/h2load-$name-12.txt
}
echo "### h2o, 12 threads"
docker exec -d perfbox bash -c "cd bench/tmp/h2o-bin && H2O_THREADS=12 TLS_CERT=$PWD/bench/certs/cert.pem TLS_KEY=$PWD/bench/certs/key.pem taskset -c 0-5,12-17 ./server > /tmp/h2o.out 2>&1"
sleep 1
profile h2o "pidof server"
docker exec perfbox bash -c 'kill $(pidof server)'; sleep 1
echo "### agensio, 12 workers"
docker exec -d perfbox bash -c "taskset -c 0-5,12-17 build/agensio -c bench/tmp/perf-h2-12.toml > /tmp/agensio.err 2>&1"
sleep 1
profile agensio "pidof agensio"
docker exec perfbox bash -c 'kill $(pidof agensio)'
docker rm -f perfbox >/dev/null
