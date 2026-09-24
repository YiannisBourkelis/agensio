#!/usr/bin/env bash
# UDP I/O strategies with Asio, measured (docs/design-http3.md 6.1): builds bench/udp/udpbench.cpp
# and runs the matrix of server strategies (asio | spec | wait | wait+gso, each with and without
# UDP_GRO) against a closed-loop client sending plain datagrams or GSO bursts, at two datagram
# sizes, the server pinned to one core and the client to others. Run inside the devbox
# (needs taskset and the fetched Asio under build/_deps).
#
# usage: bench/udp/run.sh [-s SERVER_CPU] [-c CLIENT_CPUS] [-d SECONDS] [-t THREADS] [-f FLOWS] [-w WINDOW]
# Results: bench/results/udp-<stamp>.md, raw output in bench/results/raw/udp-<stamp>/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SERVER_CPU=2; CLIENT_CPUS="6-9"; DURATION=3; THREADS=4; FLOWS=4; WINDOW=8; PORT=9901
while getopts "s:c:d:t:f:w:" opt; do
  case $opt in
    s) SERVER_CPU=$OPTARG ;; c) CLIENT_CPUS=$OPTARG ;; d) DURATION=$OPTARG ;; t) THREADS=$OPTARG ;; f) FLOWS=$OPTARG ;; w) WINDOW=$OPTARG ;; *) exit 2 ;;
  esac
done
ASIO="$ROOT/build/_deps/asio-src/asio/include"
[ -f "$ASIO/asio.hpp" ] || { echo "Asio not found at $ASIO: configure the build first"; exit 1; }
mkdir -p "$ROOT/bench/tmp/udp"
BIN="$ROOT/bench/tmp/udp/udpbench"
if [ ! -x "$BIN" ] || [ "$ROOT/bench/udp/udpbench.cpp" -nt "$BIN" ]; then
  g++ -O2 -std=c++20 -DASIO_STANDALONE -I"$ASIO" -pthread -Wall "$ROOT/bench/udp/udpbench.cpp" -o "$BIN"
fi
STAMP="$(date +%Y%m%d-%H%M%S)"
RAW="$ROOT/bench/results/raw/udp-$STAMP"; mkdir -p "$RAW"
OUT="$ROOT/bench/results/udp-$STAMP.md"
{
  echo "# UDP I/O strategies with Asio, $STAMP"
  echo
  echo "Machine: $(uname -m), $(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //'), kernel $(uname -r); commit $(git -C "$ROOT" rev-parse --short HEAD)."
  echo "Command: bench/udp/run.sh -s $SERVER_CPU -c $CLIENT_CPUS -d $DURATION -t $THREADS -f $FLOWS -w $WINDOW (server pinned to CPU $SERVER_CPU, $THREADS client threads x $FLOWS flows on CPUs $CLIENT_CPUS, $WINDOW datagrams in flight per flow, loopback)."
  echo "Program: bench/udp/udpbench.cpp (an echo server; CPU is the server's user+system time over the datagrams it received)."
  echo
  echo "| server | GRO | client | size | datagrams/s | server CPU us/datagram | per recvmmsg | per sendmmsg | wake-ups/s | lost |"
  echo "|---|---|---|---|---|---|---|---|---|---|"
} > "$OUT"
row() {  # mode gro gso client_gso size
  local mode=$1 gro=$2 gso=$3 cgso=$4 size=$5
  local sflags="" cflags="" name="$mode"
  [ "$gro" = 1 ] && sflags="$sflags --gro"
  [ "$gso" = 1 ] && { sflags="$sflags --gso"; name="$mode+gso"; }
  [ "$cgso" = 1 ] && cflags="--gso"
  local tag="${name}-gro${gro}-cgso${cgso}-${size}"
  taskset -c "$SERVER_CPU" "$BIN" server "$mode" "$PORT" --seconds $((DURATION + 1)) $sflags > "$RAW/$tag.server" 2>&1 &
  local spid=$!
  sleep 0.3
  taskset -c "$CLIENT_CPUS" "$BIN" client 127.0.0.1 "$PORT" --threads "$THREADS" --flows "$FLOWS" --window "$WINDOW" --size "$size" --seconds "$DURATION" $cflags > "$RAW/$tag.client" 2>&1 || true
  wait "$spid" || true
  local s c
  s=$(cat "$RAW/$tag.server"); c=$(cat "$RAW/$tag.client")
  get() { echo "$1" | grep -o "$2=[^ ]*" | head -1 | cut -d= -f2 || true; }
  local rate cpu prc psc wake lost
  rate=$(get "$c" received_per_sec); cpu=$(get "$s" cpu_us_per_datagram); prc=$(get "$s" datagrams_per_recv_call); psc=$(get "$s" datagrams_per_send_call)
  wake=$(awk -v w="$(get "$s" wakeups)" -v d="$DURATION" 'BEGIN{printf "%.0f", w/d}'); lost=$(get "$c" lost)
  printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' "$name" "$([ "$gro" = 1 ] && echo on || echo off)" "$([ "$cgso" = 1 ] && echo 'GSO bursts' || echo plain)" "$size" "$rate" "$cpu" "$prc" "$psc" "$wake" "$lost" | tee -a "$OUT"
  sleep 0.5
}
for size in 100 1200; do
  for cgso in 0 1; do
    row asio 0 0 $cgso $size
    row spec 0 0 $cgso $size
    row wait 0 0 $cgso $size
    row wait 0 1 $cgso $size
    row spec 1 0 $cgso $size
    row wait 1 0 $cgso $size
    row wait 1 1 $cgso $size
  done
done
echo "written $OUT"
