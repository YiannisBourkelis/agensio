#!/usr/bin/env bash
# Connection churn: wrk with Connection: close, so every request is a new TCP connection and
# the accept path is what is measured (the connection ceiling check lives there). CPU us/req
# from /proc/<pid>/stat ticks (100 Hz). Base and new alternated, two rounds; the summary goes
# to the file named, under bench/results/ by convention.
#   usage: bench/churn.sh <base binary> <new binary> bench/results/churn-<stamp>.md
# Run it where bench/ab.sh runs (the devbox on the Linux box, ports 8080/8443 free); the
# base binary is the one bench/ab.sh built, bench/tmp/ab/<sha>/build/agensio, and the
# configuration is the one bench/ab.sh wrote, bench/tmp/ab-agensio.toml.
set -u
BASE=$(readlink -f "$1"); NEW=$(readlink -f "$2"); OUT=$(readlink -f "$3" 2>/dev/null || echo "$3")  # absolute: run() changes directory
run() {
  local bin=$1 tag=$2
  (cd bench && exec "$bin" -c tmp/ab-agensio.toml) >/dev/null 2>&1 & local pid=$!
  for _ in $(seq 1 50); do nc -z 127.0.0.1 8080 2>/dev/null && break; sleep 0.1; done
  local t0 t1 out reqs rps
  t0=$(awk '{print $14+$15}' /proc/$pid/stat)
  out=$(wrk -t4 -c64 -d5s -H 'Connection: close' http://127.0.0.1:8080/ 2>&1)
  t1=$(awk '{print $14+$15}' /proc/$pid/stat)
  reqs=$(echo "$out" | awk '/requests in/ {print $1}'); rps=$(echo "$out" | awk '/Requests\/sec/ {print $2}')
  kill $pid; wait $pid 2>/dev/null; sleep 0.5
  printf '| %s | %s | %s | %.2f |\n' "$tag" "$reqs" "$rps" "$(awk -v t=$((t1-t0)) -v r=$reqs 'BEGIN{print t*10000/r}')" | tee -a "$OUT"
}
{ echo "# Connection churn $(date +%Y%m%d-%H%M%S): base $(git rev-parse --short v0.1.0-alpha.40) vs new $(git rev-parse --short HEAD)+dirty"; echo; echo "- machine: $(uname -m), $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'), $(uname -sr)"; echo "- command: wrk -t4 -c64 -d5s -H 'Connection: close' http://127.0.0.1:8080/ (plain 1 KB, a new TCP connection per request), agensio workers=1, bench/tmp/ab-agensio.toml; CPU us/req = server CPU ticks x 10,000 / requests"; echo; echo "| side | requests | req/s | CPU us/req |"; echo "|---|---|---|---|"; } > "$OUT"
for r in 1 2; do run "$BASE" "base r$r"; run "$NEW" "new r$r"; done
