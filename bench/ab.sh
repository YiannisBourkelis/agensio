#!/usr/bin/env bash
# A/B checkpoint: the binary in build/ against one built from a base git ref, alternated
# in the same session so that run-to-run drift cancels out. This is the gate for every
# phase checkpoint and every change on the request path (see CLAUDE.md).
#
# usage: bench/ab.sh <base-ref> [-r ROUNDS] [-d DURATION] [-t THREADS] [-w WORKERS] [-P] [-u URLSPEC ...]
#   base-ref  commit, branch or tag to build as the "base" side (worktree under bench/tmp/ab/)
#   -P        proxy gate (phase D): also start the benchmark upstream (build/agensio_upstream on
#             127.0.0.1:9100) and add the proxy rows "proxy:/json:64", "proxy:/big:64" and
#             "proxy:/slow?ms=20:256" through the proxy site of bench/proxy/ab-site.toml, on
#             127.0.0.1:8093. Run it for every change under src/upstream/http*, src/handlers/proxy*.
#             A base that cannot load the proxy site (pre-D1) runs the static rows only.
#   -r        rounds of base/new alternation (default 2)
#   -d        wrk duration per case (default 5s)
#   -t        wrk threads (default 4)
#   -w        agensio workers (default 1: one core saturated, so CPU us/req is exact)
#   -u        "proto:path:conns", repeatable; default: the four small rows plus the two streams
# The metric is server CPU microseconds per request (CPU time of the agensio process over
# wrk's request count). Summary goes to bench/results/ab-<stamp>.md, raw wrk output to
# bench/results/raw/ab-<stamp>/. Paste the summary table into the commit message.
set -euo pipefail

BENCH="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$BENCH")"
[ $# -ge 1 ] || { sed -n '2,16p' "$0"; exit 2; }
BASE_REF="$1"; shift
ROUNDS=2; DURATION=5s; THREADS=4; WORKERS=1; SPECS=(); PROXY=0
while getopts "r:d:t:w:u:P" opt; do
  case $opt in
    r) ROUNDS=$OPTARG ;; d) DURATION=$OPTARG ;; t) THREADS=$OPTARG ;; w) WORKERS=$OPTARG ;;
    u) SPECS+=("$OPTARG") ;; P) PROXY=1 ;; *) exit 2 ;;
  esac
done
[ ${#SPECS[@]} -eq 0 ] && SPECS=("http:/:64" "http:/style.css:64" "https:/:64" "https:/style.css:64" "http:/big.bin:16" "https:/big.bin:16")
if [ $PROXY = 1 ]; then
  [ -x "$ROOT/build/agensio_upstream" ] || { echo "build/agensio_upstream missing: cmake --build build --target agensio_upstream"; exit 1; }
  [ -f "$BENCH/proxy/ab-site.toml" ] || { echo "bench/proxy/ab-site.toml missing (the proxy site for the gate, phase D1)"; exit 1; }
  SPECS+=("proxy:/json:64" "proxy:/big:64" "proxy:/slow?ms=20:256")
fi

for tool in wrk curl nc git cmake; do command -v "$tool" >/dev/null || { echo "missing tool: $tool"; exit 1; }; done
[ -x "$ROOT/build/agensio" ] || { echo "build the new side first: cmake --build build"; exit 1; }
[ -f "$BENCH/www/big.bin" ] || "$BENCH/gen-www.sh" >/dev/null
[ -f "$BENCH/certs/cert.pem" ] || "$BENCH/certs/gen-cert.sh" >/dev/null
ulimit -n 65536 2>/dev/null || true

# ---- base side: worktree + Release build (reuses the fetched asio of the main build) ----
BASE_SHA="$(git -C "$ROOT" rev-parse --short "$BASE_REF")"
BASE_DIR="$BENCH/tmp/ab/$BASE_SHA"
if [ ! -d "$BASE_DIR" ]; then
  git -C "$ROOT" worktree add --detach "$BASE_DIR" "$BASE_SHA" >/dev/null
fi
if [ ! -x "$BASE_DIR/build/agensio" ]; then
  echo "building base $BASE_SHA"
  ASIO_SRC="$ROOT/build/_deps/asio-src"
  extra=""; [ -d "$ASIO_SRC" ] && extra="-DFETCHCONTENT_SOURCE_DIR_ASIO=$ASIO_SRC"
  cmake -S "$BASE_DIR" -B "$BASE_DIR/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DAGENSIO_TESTS=OFF $extra >/dev/null
  cmake --build "$BASE_DIR/build" >/dev/null
fi
NEW_SHA="$(git -C "$ROOT" rev-parse --short HEAD)$(git -C "$ROOT" diff --quiet HEAD -- src CMakeLists.txt || echo '+dirty')"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$BENCH/results/ab-$STAMP.md"
RAW="$BENCH/results/raw/ab-$STAMP"
mkdir -p "$RAW" "$BENCH/tmp"
sed "s#@WORKERS@#$WORKERS#g; s#@BENCH@#$BENCH#g; s#@SENDFILE_MIN@#${SENDFILE_MIN:-48KB}#g; s#@ACCESS_LOG@#${ACCESS_LOG:-off}#g" "$BENCH/agensio.toml" > "$BENCH/tmp/ab-agensio.toml"
# The proxy gate adds a site that forwards 127.0.0.1:8093 to the upstream; a side whose
# binary cannot load it (a base before D1) gets the static-only config and no proxy rows.
UP_PID=""
if [ $PROXY = 1 ]; then
  cat "$BENCH/tmp/ab-agensio.toml" "$BENCH/proxy/ab-site.toml" > "$BENCH/tmp/ab-agensio-proxy.toml"
  nc -z 127.0.0.1 9100 2>/dev/null && { echo "port 9100 is busy; stop the running upstream first"; exit 1; }
  "$ROOT/build/agensio_upstream" -p 9100 -w 1 >>"$RAW/upstream.log" 2>&1 &
  UP_PID=$!
fi

PID=""; SIDE_PROXY=0
start() {  # binary
  for port in 8080 8443 8093; do
    nc -z 127.0.0.1 "$port" 2>/dev/null && { echo "port $port is busy; stop the running server first"; exit 1; }
  done
  local cfg="$BENCH/tmp/ab-agensio.toml"
  SIDE_PROXY=0
  if [ $PROXY = 1 ]; then
    if "$1" -t -c "$BENCH/tmp/ab-agensio-proxy.toml" >/dev/null 2>&1; then cfg="$BENCH/tmp/ab-agensio-proxy.toml"; SIDE_PROXY=1
    else echo "  (this side cannot load the proxy site: static rows only)"; fi
  fi
  (cd "$BENCH" && exec "$1" -c "$cfg") >>"$RAW/server.log" 2>&1 &
  PID=$!
  for _ in $(seq 1 50); do nc -z 127.0.0.1 8080 2>/dev/null && nc -z 127.0.0.1 8443 2>/dev/null && return 0; sleep 0.1; done
  echo "server did not start: $1"; cat "$RAW/server.log"; exit 1
}
stop() { [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true; PID=""; sleep 0.3; }
trap 'stop; [ -n "$UP_PID" ] && kill "$UP_PID" 2>/dev/null; true' EXIT
cpu_seconds() {  # user + system CPU of the server process
  if [ -d /proc ]; then
    awk -v tck="$(getconf CLK_TCK)" '{ printf "%.3f", ($14+$15)/tck }' "/proc/$PID/stat"
  else
    ps -o cputime= -p "$PID" | LC_NUMERIC=C awk -F'[:.]' '{ if (NF==3) s=$1*60+$2+$3/100; else s=$1*3600+$2*60+$3+$4/100 } END{printf "%.3f", s}'
  fi
}

measure() {  # side round -> appends "side round spec cpu_us rps" lines to $RAW/rows
  local side=$1 round=$2 spec proto path conns url t raw c0 c1 n rps
  for spec in "${SPECS[@]}"; do
    proto="${spec%%:*}"; path="${spec#*:}"; conns="${path##*:}"; path="${path%:*}"
    case $proto in
      https) url="https://127.0.0.1:8443$path" ;;
      proxy) [ $SIDE_PROXY = 1 ] || continue; url="http://127.0.0.1:8093$path" ;;
      *) url="http://127.0.0.1:8080$path" ;;
    esac
    curl -sk -o /dev/null "$url"  # warm-up
    t=$THREADS; [ "$conns" -lt "$t" ] && t=$conns
    raw="$RAW/$side-r$round-$proto-$(echo "$path" | tr '/?=' '___')-c$conns.txt"
    c0=$(cpu_seconds)
    wrk -t"$t" -c"$conns" -d"$DURATION" "$url" > "$raw" 2>&1
    c1=$(cpu_seconds)
    n=$(awk '/requests in/{print $1}' "$raw"); rps=$(awk '/^Requests\/sec/{print $2}' "$raw")
    LC_NUMERIC=C awk -v a="$c0" -v b="$c1" -v n="$n" -v s="$side" -v r="$round" -v k="$proto $path $conns" -v q="$rps" \
      'BEGIN{ printf "%s %d %s %.2f %s\n", s, r, k, (n>0 ? (b-a)*1e6/n : -1), q }' >> "$RAW/rows"
    printf '  %-4s r%d %-5s %-11s c=%-3s %8.2f us/req  %s req/s\n' "$side" "$round" "$proto" "$path" "$conns" \
      "$(tail -1 "$RAW/rows" | awk '{print $6}')" "$rps"
  done
}

: > "$RAW/rows"
for round in $(seq 1 "$ROUNDS"); do
  echo "=== round $round: base $BASE_SHA"; start "$BASE_DIR/build/agensio"; measure base "$round"; stop
  echo "=== round $round: new $NEW_SHA";   start "$ROOT/build/agensio";     measure new  "$round"; stop
done

{
  echo "# A/B $STAMP: base $BASE_SHA vs new $NEW_SHA"
  echo
  echo "- machine: $(uname -m), $(sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//'), $(uname -sr)"
  echo "- agensio workers=$WORKERS, wrk threads=$THREADS, duration=$DURATION, rounds=$ROUNDS; CPU us/req = server CPU time / requests"
  echo
  echo "| case | base us/req (per round) | new us/req (per round) | new/base |"
  echo "|---|---|---|---|"
  for spec in "${SPECS[@]}"; do
    proto="${spec%%:*}"; path="${spec#*:}"; conns="${path##*:}"; path="${path%:*}"
    LC_NUMERIC=C awk -v k="$proto $path $conns" -v label="$proto $path c=$conns" '
      $3" "$4" "$5==k { if ($1=="base") { b=b (b?" / ":"") sprintf("%.2f",$6); bs+=$6; bn++ } else { w=w (w?" / ":"") sprintf("%.2f",$6); ws+=$6; wn++ } }
      END { if (bn && wn) printf "| %s | %s | %s | %.3f |\n", label, b, w, (ws/wn)/(bs/bn);
            else if (wn) printf "| %s | n/a (base has no proxy) | %s | n/a |\n", label, w }' "$RAW/rows"
  done
} > "$OUT"
echo; cat "$OUT"; echo; echo "summary written to $OUT"
