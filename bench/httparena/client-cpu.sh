#!/bin/bash
# h2load's own CPU against each server under the pinned twelve-worker load (profile-12w.sh's setup):
# is the load generator the limit? Needs profile-h2o.sh's h2o build and bench/tmp/perf-h2-12.toml.
set -u
cd "$(dirname "$0")/../.."
URL="https://127.0.0.1:8443/baseline2?a=1&b=1"
docker rm -f perfbox >/dev/null 2>&1
docker run -d --name perfbox --init --cap-add SYS_ADMIN --cap-add PERFMON --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox-perf sleep 3600 >/dev/null
run() {
    local name=$1
    docker run --rm -d --name lg5 --network container:perfbox --pid container:perfbox -v "$PWD:$PWD" -w "$PWD" agensio-devbox taskset -c 6-11,18-23 h2load -c 512 -m 100 -t 12 -D 8 "$URL" >/dev/null
    sleep 3
    docker exec perfbox bash -c "P=\$(pidof h2load); S=\$(pidof $2); a=\$(awk '{print \$14+\$15}' /proc/\$P/stat); b=\$(awk '{print \$14+\$15}' /proc/\$S/stat); sleep 2; a2=\$(awk '{print \$14+\$15}' /proc/\$P/stat); b2=\$(awk '{print \$14+\$15}' /proc/\$S/stat); echo \"$name: h2load \$(( (a2-a) / 2 )) % of CPU, server \$(( (b2-b) / 2 )) %\""
    docker wait lg5 >/dev/null 2>&1
}
docker exec -d perfbox bash -c "cd bench/tmp/h2o-bin && H2O_THREADS=12 TLS_CERT=$PWD/bench/certs/cert.pem TLS_KEY=$PWD/bench/certs/key.pem taskset -c 0-5,12-17 ./server > /tmp/h2o.out 2>&1"; sleep 1
run h2o server
docker exec perfbox bash -c 'kill $(pidof server)'; sleep 1
docker exec -d perfbox bash -c "taskset -c 0-5,12-17 build/agensio -c bench/tmp/perf-h2-12.toml > /tmp/agensio.err 2>&1"; sleep 1
run agensio agensio
docker exec perfbox bash -c 'kill $(pidof agensio)'
docker rm -f perfbox >/dev/null
