#!/usr/bin/env bash
# Runs HttpArena's validator and lite benchmark against agensio and the reference entries on
# this machine, inside Docker-in-Docker: the harness binds 8080-8443 with host networking and
# restarts the Docker daemon in its tuning step, neither of which may touch the host.
#
#   bench/httparena/local.sh setup                    # clone HttpArena into bench/tmp, start dind, copy the entry in
#   bench/httparena/local.sh validate agensio         # scripts/validate.sh
#   bench/httparena/local.sh bench agensio static-h2  # scripts/benchmark-lite.sh (all subscribed profiles without a name)
#   bench/httparena/local.sh bench nginx
#   bench/httparena/local.sh shell                    # a shell in the harness container
#   bench/httparena/local.sh stop                     # remove the dind container (its images go with it)
#
# Environment: ARENA (the clone, default bench/tmp/httparena), DURATION (5s), RUNS (3),
# LOAD_THREADS (the harness default, nproc/2). The lite profile set skips static-tls; setup
# adds it with the static-h2 shape (512 connections) for the local comparison only.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
ARENA=${ARENA:-$ROOT/bench/tmp/httparena}
DIND=httparena-dind
cmd=${1:-}; shift || true

dind_exec() { docker exec -w /arena "$@"; }

case "$cmd" in
  setup)
    mkdir -p "$(dirname "$ARENA")"
    [ -d "$ARENA/.git" ] || git clone --depth 1 https://github.com/MDA2AV/HttpArena.git "$ARENA"
    rsync -a --delete "$HERE/agensio/" "$ARENA/frameworks/agensio/"
    # The lite map lacks static-tls (added to run it here, 512 connections like static-h2) and the
    # h2c and json-tls profiles the nginx and h2o entries subscribe to; the script refuses a
    # meta.json naming a profile it does not know, so those three are declared but never run.
    if ! grep -q '\[static-tls\]' "$ARENA/scripts/benchmark-lite.sh"; then
      sed -i 's/^    \[static-h2\]=\(.*\)$/    [static-h2]=\1\n    [static-tls]="1|0||512|static-tls"\n    [json-tls]="1|0||512|json-tls"\n    [baseline-h2c]="1|0||512|h2c"\n    [json-h2c]="1|0||512|json-h2c"/; s/^    baseline-h2 static-h2$/    baseline-h2 static-h2 static-tls/' "$ARENA/scripts/benchmark-lite.sh"
    fi
    if ! docker inspect "$DIND" >/dev/null 2>&1; then
      docker run -d --privileged --name "$DIND" -v "$ARENA:/arena" -e DOCKER_TLS_CERTDIR= docker:dind >/dev/null
    fi
    for _ in $(seq 1 60); do docker exec "$DIND" docker info >/dev/null 2>&1 && break; sleep 1; done
    docker exec "$DIND" sh -c 'apk add --no-cache bash git python3 curl jq bc openssl coreutils util-linux-misc procps-ng grep sed gawk findutils iproute2 sudo >/dev/null'
    echo "harness at $ARENA, container $DIND ($(docker exec "$DIND" docker info --format '{{.NCPU}} cpus, {{.ServerVersion}}'))"
    ;;
  sync)   # copy the entry again after editing it
    rsync -a --delete "$HERE/agensio/" "$ARENA/frameworks/agensio/"
    ;;
  validate)
    rsync -a --delete "$HERE/agensio/" "$ARENA/frameworks/agensio/"
    dind_exec "$DIND" bash scripts/validate.sh "$@"
    ;;
  bench)
    rsync -a --delete "$HERE/agensio/" "$ARENA/frameworks/agensio/"
    dind_exec -e "DURATION=${DURATION:-5s}" -e "RUNS=${RUNS:-3}" "$DIND" bash scripts/benchmark-lite.sh ${LOAD_THREADS:+--load-threads "$LOAD_THREADS"} "$@"
    ;;
  shell)
    dind_exec -it "$DIND" bash
    ;;
  stop)
    docker rm -f "$DIND" >/dev/null 2>&1 || true
    ;;
  *)
    sed -n 2,16p "$0"; exit 1
    ;;
esac
