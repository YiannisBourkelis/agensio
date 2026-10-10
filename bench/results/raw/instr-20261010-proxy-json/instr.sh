#!/usr/bin/env bash
# Instructions and cycles per proxied request (/json through 127.0.0.1:8093), base vs new,
# alternated. usage: instr.sh BASE_BIN NEW_BIN ROUNDS
set -u
BASE=$1; NEW=$2; ROUNDS=${3:-2}
CONF=bench/tmp/ab-agensio-proxy.toml
build/agensio_upstream -p 9100 -w 1 > /dev/null 2>&1 &
UP=$!
sleep 0.5
one() {  # label bin
  "$2" -c "$CONF" > /dev/null 2>&1 &
  local pid=$!
  for _ in $(seq 1 50); do nc -z 127.0.0.1 8093 2>/dev/null && break; sleep 0.1; done
  wrk -t4 -c64 -d1s http://127.0.0.1:8093/json > /dev/null 2>&1   # warm up
  wrk -t4 -c64 -d5s http://127.0.0.1:8093/json > /tmp/wrk.out 2>&1 &
  local w=$!
  perf stat -x, -e instructions,cycles -p "$pid" -o /tmp/perf.out -- sleep 5 > /dev/null 2>&1
  wait $w
  kill "$pid"; wait "$pid" 2>/dev/null
  local req ins cyc
  req=$(awk '/requests in/{print $1}' /tmp/wrk.out)
  ins=$(awk -F, '/instructions/{print $1}' /tmp/perf.out)
  cyc=$(awk -F, '/cycles/{print $1}' /tmp/perf.out)
  awk -v l="$1" -v r="$req" -v i="$ins" -v c="$cyc" 'BEGIN{printf "%s requests=%d instructions/req=%.0f cycles/req=%.0f\n", l, r, i/r, c/r}'
  sleep 1
}
for r in $(seq 1 "$ROUNDS"); do
  one "base round $r" "$BASE"
  one "new  round $r" "$NEW"
done
kill $UP
