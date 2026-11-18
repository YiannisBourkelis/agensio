# The release check's HTTPS 1 KB cost, counted and made cheaper (2026-11-18)

The release check of 0.1.0-alpha.147 (`perfstat-release-147-20261117.md`) found `https /` running
330 to 460 more user instructions a request than alpha.146, bisected to two commits of about 200
each: 8b12bf19 (the TLS coalescing buffer lent per answer) and 800e3356 (F2: HTTP/1.1 over TLS runs
the certificate-name check). This file counts both exactly, and measures the two changes that make
them cheaper without changing what is served: `CertNames::covers` compares the Host in place, eight
bytes at a time, and `SpareBuffers` keeps its spares in fixed slots.

- Machine: AMD Ryzen 9 9900X (12 cores, 24 threads), Debian 13 (trixie), kernel 6.12.116+deb13-amd64,
  GCC 14.2.0, the build's flags (`-O3`, `AGENSIO_HARDEN`: `-ftrivial-auto-var-init=zero`,
  `_GLIBCXX_ASSERTIONS`, `_FORTIFY_SOURCE=2`, `-fstack-protector-strong`).
- Base: b9042a55 (v0.1.0-alpha.147), built as `bench/ab.sh` builds a base (`bench/tmp/ab/b9042a55`).
  New: the working tree on b9042a55 with the two changes (`build/agensio`).
- Tools in `agensio-devbox-perf` (`--network none`, `--cap-add SYS_ADMIN --cap-add PERFMON`):
  valgrind 3.24.0, perf 6.12.107, wrk 4.1.0, h2load 1.64.0.
- Configuration: `bench/tmp/perf-release-147.toml`, the A/B's two configurations joined
  (`bench/tmp/ab-agensio-h3.toml` and `bench/tmp/ab-comp.toml`), one worker, no access log; the
  HTTPS site on 127.0.0.1:8443 with `bench/certs/cert.pem` (DNS:localhost, IP:127.0.0.1).

## 1. Exact counts per commit (callgrind)

The sampled profile of the bisection showed `malloc` +133 instructions a request across 800e3356,
which read as an allocation that commit added. It moved as much between commits that allocate the
same (99.7, 233.1, 128.1, 112.6 on four builds): the allocator's path, not a call. Callgrind counts
every instruction: each binary under `valgrind --tool=callgrind`, 3,000 HTTP/1.1 requests over TLS to
warm it (`h2load --h1 -n 3000 -c 4`), the counts zeroed (`callgrind_control -z`), 20,000 requests
(`h2load --h1 -n 20000 -c 4 https://127.0.0.1:8443/`), dumped (`callgrind_control -d`). The four
handshakes of the second run are in every side alike. Script: section 5.

| build | instructions a request | step |
|---|---|---|
| f5a55b49 (v0.1.0-alpha.146) | 20,050 | |
| 64419def | 20,052 | +2 |
| 37f6e94d (after 8b12bf19, the lent buffers) | 20,229 | **+178** |
| 0293f67a | 20,229 | 0 |
| 800e3356 (F2, the certificate check on HTTP/1.1) | 20,492 | **+263** |
| b9042a55 (v0.1.0-alpha.147) | 20,491 | |
| new | 20,268 | **−223** |

Per function (instructions a request, callgrind):

- 800e3356: `Dispatcher::route` +171 (`covers()` inlined: the Host copied, lowered, into a 256-byte
  buffer the hardened build zeroes), `string_view::compare` +47, `memcmp` +39, `substr` +5. No
  allocation: `malloc` and `free` unchanged.
- 8b12bf19: `SpareBuffers::take` +51 (out of line), `Response::reset` +49 (no longer inlined, −35
  in `route`), the writer's lend and take about +96, inlining moved around them (`on_response_written`
  −51, `finish` and `log_request` out of line). No allocation either.
- new against b9042a55: `route` −72 (`covers()` 99 inline in it, where it was 171 there and 91 in
  `compare`, `memcmp` and `substr`), `SpareBuffers::take` −51 (now inline, a swap), `string_view::compare`
  −47, `memcmp` −39, `write_op` −28, the writer's start +14.

What stays of the two steps: the check 99 of 263 (the F2 fix itself: HTTP/1.1 now checks every
request over TLS, as HTTP/2 and HTTP/3 always did), the lending about 115 of 178 (the lend and the
take, and the inlining they moved: `finish` and `log_request` out of line, `Response::reset` out of
line since 8b12bf19, which moving its rare branch into a `.cpp` of its own did not change; tried and
taken out).

Callgrind's CPU model is not the machine's (glibc picks its string functions by the CPU valgrind
shows), so the real cost is section 2's and 3's.

## 2. covers() alone, on the machine

A loop calling `CertNames::covers` through a `noinline` function, the names `localhost` and
`127.0.0.1` (the benchmark's certificate), compiled with the build's flags, `perf stat -e
instructions:u` over 1 M and 11 M calls, the difference divided by 10 M (the loop's own few
instructions included on both sides):

| Host | alpha.147 | new |
|---|---|---|
| `127.0.0.1:8443` (the A/B's) | 178 | 133 |
| `localhost` | 170 | 127 |
| `www.example.com` (no name of its length) | 250 | 160 |
| `LOCALHOST:443` | 145 | 131 |

On the way: comparing a byte at a time in place cost 215 on the first row, more than the copy and
`memcmp` it replaced (twelve instructions a byte, where glibc's AVX2 `memcmp` and the vector stores of
the zeroing are few). Eight bytes at a time with each byte folded in its own lane, and the fold only
when the raw words differ (a Host is sent in lower case), gives the column above.

## 3. The server, on the machine (perf stat)

`perf stat -e instructions:u,instructions:k,cycles -p PID -- sleep 5` during a 5 s run, after a 2 s
warm-up, the two binaries alternated three times a row; user and kernel instructions a request.

| row | load | b9042a55 user | new user | change | kernel, both |
|---|---|---|---|---|---|
| HTTPS 1 KB, HTTP/1.1 | `wrk -t4 -c64 -d5s https://127.0.0.1:8443/` | 15,658 / 15,695 / 15,694 | 15,503 / 15,489 / 15,477 | **−193** | 14,031 to 14,068 |
| HTTPS 1 KB, HTTP/2 | `h2load -D 5 -c64 -m10 -t4 https://127.0.0.1:8443/` | 6,289 / 6,274 / 6,277 | 6,132 / 6,156 / 6,176 | **−125** | 1,543 to 1,559 |
| HTTP 1 KB | `wrk -t4 -c64 -d5s http://127.0.0.1:8080/` | 4,398 / 4,393 / 4,397 | 4,415 / 4,393 / 4,399 | 0 | 14,121 to 14,194 |

HTTP/2 runs `covers()` too (it always did) and lends no writer buffer: its row is the certificate
check's gain alone. Of the 330 to 460 the release check found on HTTPS 1 KB, about 190 are back.

Run again after the A/B (section 4), on the final build, four rounds, with HTTPS 100 KB added (the
A/B read it 1.049) and L1 instruction-cache misses; another program was taking 40 % of a core then
(load average 3.4 to 4.7):

| row | b9042a55 user (kernel) | new user (kernel) |
|---|---|---|
| HTTPS 100 KB | 108,470 (92,128) / 108,410 (91,964) / 108,472 (92,218) / 108,548 (91,902) | 108,306 (92,219) / 108,662 (92,550) / 108,672 (92,760) / 108,387 (91,485) |
| HTTPS 1 KB | 15,683 (14,040) / 15,691 (14,047) / 15,891 (14,250) / 15,664 (14,027) | 15,696 (14,233) / 15,520 (14,056) / 15,663 (14,197) / 15,490 (14,035) |

HTTPS 100 KB is the same work (108,475 against 108,507 on average, 0.03 %; L1i misses 2,207 to 2,222
against 2,199 to 2,305; cycles a request 109,514 to 114,030 against 106,429 to 110,818 but for one
round of 136,106 under the other load): the A/B's 1.049 is that row's noise. On HTTPS 1 KB the rounds
whose kernel count rose with the other load (above 14,190: one base, two new) count more user
instructions too, the reads and retries of a loaded machine; the others are 15,664 to 15,691 against
15,490 and 15,520, about −175, as in the first run.

## 4. A/B

`bench/ab.sh HEAD -2 -3 -r 3` in `agensio-devbox:latest` (`--network none`, load average 4.7 at the
start, the other program above running), `ab-20261118-005129.md`: HTTPS 1 KB 0.971, HTTP/2 over TLS
0.953 (one stream) and 0.968 (ten), HTTP/3 0.951, 0.932 and 0.917 (one, ten and sixty-four streams:
`covers()` runs there too), h2c 1.036 and 1.030 and plain HTTP 0.954 to 0.998 (neither change is on
those paths: noise), HTTPS 100 KB 1.049 (section 3: the same instructions, noise), the 10 MB streams
0.961 and 0.977. The comments and the tests changed after the A/B's build; the server's code did not.

## 5. Scripts

`cg.sh` (callgrind, section 1), run as
`docker run --rm --init --network none --user root --ulimit nofile=65536:65536 -v $PWD:$PWD -w $PWD
agensio-devbox-perf:latest bash cg.sh OUTDIR f5a55b49 64419def 37f6e94d 0293f67a 800e3356 HEAD`
(each name a worktree `bench/tmp/ab/NAME` with its build, `HEAD` or `NEW` being `build/agensio`):

```bash
#!/usr/bin/env bash
set -u
ROOT=$(pwd); CFG=$ROOT/bench/tmp/perf-release-147.toml; OUT=$1; shift
A=3000; B=20000
for c in "$@"; do
  bin=$ROOT/bench/tmp/ab/$c/build/agensio; case $c in HEAD|NEW*) bin=$ROOT/build/agensio;; esac
  d=$OUT/cg-$c; rm -rf "$d"; mkdir -p "$d"; cd "$d"
  valgrind --tool=callgrind --callgrind-out-file="$d/cg.out" "$bin" -c "$CFG" > "$d/server.log" 2>&1 &
  vpid=$!
  for _ in $(seq 1 300); do curl -sk -o /dev/null https://127.0.0.1:8443/ && break; sleep 0.2; done
  h2load --h1 -n $A -c 4 https://127.0.0.1:8443/ > "$d/warm.txt" 2>&1
  callgrind_control -z $vpid > /dev/null 2>&1
  h2load --h1 -n $B -c 4 https://127.0.0.1:8443/ > "$d/run.txt" 2>&1
  callgrind_control -d run $vpid > /dev/null 2>&1
  sleep 1
  kill $vpid; wait $vpid 2>/dev/null
  callgrind_annotate --threshold=100 --show-percs=no "$d/cg.out.1" > "$d/excl.txt" 2>&1
  echo "$c: $(grep -m1 -E 'PROGRAM TOTALS' "$d/excl.txt")"   # / 20,000 = instructions a request
  cd "$ROOT"
done
```

`pstat.sh BASE_BIN NEW_BIN` (perf stat, section 3), run with
`docker run --rm --init --network none --cap-add SYS_ADMIN --cap-add PERFMON --user root
--ulimit nofile=65536:65536 -v $PWD:$PWD -w $PWD agensio-devbox-perf:latest bash pstat.sh
$PWD/bench/tmp/ab/b9042a55/build/agensio $PWD/build/agensio`:

```bash
#!/usr/bin/env bash
set -u
ROOT=$(pwd); BASE=$1; NEW=$2; ROUNDS=${ROUNDS:-3}
CFG=$ROOT/bench/tmp/perf-release-147.toml
H2LOAD=/opt/nghttp2/bin/h2load; [ -x $H2LOAD ] || H2LOAD=h2load
measure() {  # row side binary loadcmd...
  local row=$1 side=$2 bin=$3; shift 3
  "$bin" -c "$CFG" > /dev/null 2>&1 & local pid=$!
  for _ in $(seq 1 50); do nc -z 127.0.0.1 8443 2>/dev/null && break; sleep 0.1; done
  "$@" > /dev/null 2>&1 & local warm=$!; sleep 2; kill $warm 2>/dev/null; wait $warm 2>/dev/null
  local out lo; out=$(mktemp); lo=$(mktemp)
  perf stat -x, -e instructions:u,instructions:k,cycles -p $pid -o "$out" -- sleep 5 & local ps=$!
  "$@" > "$lo" 2>&1
  wait $ps
  local reqs
  if grep -q "requests in" "$lo"; then reqs=$(awk '/requests in/ {print $1}' "$lo")
  else reqs=$(awk '/^requests:/ {print $8}' "$lo"); fi
  awk -F, -v row="$row" -v s="$side" -v r="$reqs" '
    $3 ~ /^instructions:u/ {u = $1} $3 ~ /^instructions:k/ {k = $1} $3 ~ /^cycles/ {c = $1}
    END {printf "%-9s %-4s reqs %-8d user/req %-7.0f kernel/req %-7.0f cycles/req %.0f\n", row, s, r, u / r, k / r, c / r}' "$out"
  kill $pid; wait $pid 2>/dev/null
  rm -f "$out" "$lo"; sleep 1
}
for row in https_1k h2_1k http_1k; do
  case $row in
    https_1k) cmd=(wrk -t4 -c64 -d5s https://127.0.0.1:8443/) ;;
    h2_1k)    cmd=($H2LOAD -D 5 -c64 -m10 -t4 https://127.0.0.1:8443/) ;;
    http_1k)  cmd=(wrk -t4 -c64 -d5s http://127.0.0.1:8080/) ;;
  esac
  for i in $(seq 1 $ROUNDS); do
    measure "$row" base "$BASE" "${cmd[@]}"
    measure "$row" new "$NEW" "${cmd[@]}"
  done
done
```

The `covers()` loop of section 2:

```cpp
#include "core/host.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>
using namespace agensio;
[[gnu::noinline]] bool one(const CertNames& c, std::string_view h) { return c.covers(h); }
int main(int argc, char** argv) {
    CertNames c;
    c.add("localhost");
    c.add("127.0.0.1");
    const long n = std::atol(argv[1]);
    std::string host = argc > 2 ? argv[2] : "127.0.0.1:8443";
    long hits = 0;
    for (long i = 0; i < n; ++i) {
        asm volatile("" : : "r"(host.data()) : "memory");
        hits += one(c, host);
    }
    std::printf("%ld\n", hits);
}
```

built with `g++ -D_FORTIFY_SOURCE=2 -D_GLIBCXX_ASSERTIONS -DNDEBUG -fPIC -fstack-protector-strong
-ftrivial-auto-var-init=zero -O3 -std=c++20 -Isrc` against each side's `src/core/host.hpp`.
