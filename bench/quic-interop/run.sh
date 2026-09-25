#!/bin/bash
# The QUIC interop runner against agensio (docs/design-http3.md 9.2).
#   bench/quic-interop/run.sh [-c client,client,...] [-t test,test,...]
# Everything runs inside a Docker-in-Docker daemon (agensio-interop-dind): the runner's
# compose file names interfaces (interface_name), which needs Docker Engine 28.1, and
# the runner creates its temporary directories under /tmp and hands them to compose as
# bind mounts, so the runner container and the daemon must share one filesystem view.
# Inside that daemon: the agensio server image built from a copy of this tree, the
# runner image with tshark, the simulator and the client images the runner pulls.
# Results: bench/tmp/interop/logs-<stamp> (the runner's logs and traces) and a summary
# in bench/results/interop-<stamp>.md.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CLIENTS=${CLIENTS:-quic-go,ngtcp2}
TESTS=${TESTS:-handshake,transfer,longrtt,chacha20,multiplexing,retry,resumption,zerortt,http3,blackhole,keyupdate,ecn,amplificationlimit,handshakeloss,transferloss,handshakecorruption,transfercorruption,ipv6,v2,rebind-port,rebind-addr,connectionmigration}
while getopts "c:t:" o; do case $o in c) CLIENTS=$OPTARG ;; t) TESTS=$OPTARG ;; esac; done
WORK=$ROOT/bench/tmp/interop
DIND=agensio-interop-dind
mkdir -p "$WORK"
[ -d "$WORK/runner" ] || git clone -q --depth 1 https://github.com/quic-interop/quic-interop-runner "$WORK/runner"
# A copy of the tree as the build context (the daemon sees only $WORK).
rsync -a --delete --exclude 'build*' --exclude 'bench/tmp' --exclude '.git' --exclude 'bench/results/raw' "$ROOT/" "$WORK/src/"
if ! docker exec "$DIND" docker info >/dev/null 2>&1; then
  docker rm -f "$DIND" >/dev/null 2>&1 || true
  echo "== starting the Docker-in-Docker daemon ($DIND)"
  docker run -d --privileged --name "$DIND" -v "$WORK:/work" docker:dind >/dev/null
  for _ in $(seq 1 60); do docker exec "$DIND" docker info >/dev/null 2>&1 && break; sleep 1; done
fi
docker exec "$DIND" docker version --format '   engine {{.Server.Version}}'
# Bridged frames must not pass through the daemon's iptables: its rules drop a frame whose
# IP destination is on another bridge, which is every packet the client sends the server
# through the simulator (found with a capture on both sides of the simulator).
docker exec "$DIND" sysctl -q -w net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-ip6tables=0 net.bridge.bridge-nf-call-arptables=0
echo "== building the server image (agensio-interop:local)"
EXTRA=""; [ "${TRACE:-0}" = 1 ] && EXTRA="--build-arg CMAKE_EXTRA=-DAGENSIO_QUIC_TRACE=ON"   # TRACE=1: the server logs every packet into each test's output.txt
docker exec "$DIND" docker build -q $EXTRA -t agensio-interop:local -f /work/src/bench/quic-interop/agensio/Dockerfile /work/src >/dev/null
echo "== building the runner image (agensio-interop-runner:local)"
docker exec "$DIND" docker build -q -t agensio-interop-runner:local -f /work/src/bench/quic-interop/Dockerfile.runner /work/src/bench/quic-interop >/dev/null
# agensio joins the runner's implementation list.
python3 - "$WORK/runner/implementations_quic.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["agensio"] = {"image": "agensio-interop:local", "url": "https://github.com/yiannisbourkelis/agensio", "role": "server"}
json.dump(d, open(p, "w"), indent=2)
PY
STAMP=$(date +%Y%m%d-%H%M%S)
echo "== running: clients $CLIENTS, tests $TESTS"
docker exec "$DIND" docker run --rm --init -v /var/run/docker.sock:/var/run/docker.sock -v /tmp:/tmp -v /work:/work -w /work/runner \
  agensio-interop-runner:local python3 run.py -s agensio -c "$CLIENTS" -t "$TESTS" -l "/work/logs-$STAMP" -j "/work/result-$STAMP.json" 2>&1 | tee "$WORK/run-$STAMP.log" || true  # a failed case is the runner's non-zero exit, not the script's
OUT=$ROOT/bench/results/interop-$STAMP.md
{
  echo "# QUIC interop runner: agensio as server ($STAMP)"
  echo
  echo "Commit $(git -C "$ROOT" rev-parse --short HEAD), $(uname -sr), $(date -u +%Y-%m-%dT%H:%MZ). Command: bench/quic-interop/run.sh -c $CLIENTS -t $TESTS"
  echo
  echo '```'
  sed -n '/^+-/,$p' "$WORK/run-$STAMP.log" | tail -80
  echo '```'
} > "$OUT"
echo "summary written to $OUT"
