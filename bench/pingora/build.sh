#!/usr/bin/env bash
# Builds the Pingora proxy of the comparison (bench/pingora/proxy) into bench/tmp/pingora/target, in
# a Rust container on Debian 13 (bench/pingora/Dockerfile), as the calling user. Run on the host:
#   bench/pingora/build.sh [-j CPUS]
# The crates come from crates.io at the versions Cargo.lock pins; nothing of this repository is sent.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CPUS=12
while getopts 'j:' o; do case $o in j) CPUS=$OPTARG ;; *) exit 2 ;; esac; done
IMAGE=agensio-bench-pingora-build
docker image inspect $IMAGE >/dev/null 2>&1 || docker build -q -t $IMAGE "$ROOT/bench/pingora" >/dev/null
mkdir -p "$ROOT/bench/tmp/pingora/cargo" "$ROOT/bench/tmp/pingora/target"
docker run --rm --cpuset-cpus "0-$((CPUS - 1))" --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -e CARGO_HOME="$ROOT/bench/tmp/pingora/cargo" -v "$ROOT:$ROOT" -w "$ROOT/bench/pingora/proxy" $IMAGE \
  cargo build --release --locked --target-dir "$ROOT/bench/tmp/pingora/target"
ls -la "$ROOT/bench/tmp/pingora/target/release/pingora-bench-proxy"
