# HttpArena lite run 20260924-0147: agensio v0.1.0-alpha.20 against the nginx and h2o entries

The first run of agensio through HttpArena's own harness (https://github.com/MDA2AV/HttpArena,
commit 05bff12, 2026-09-23), on this machine, with the entry in `bench/httparena/agensio/`.
`scripts/validate.sh agensio` passed 23 checks, 0 failed, 1 skip (compression: the server
serves no pre-compressed variant). Then `scripts/benchmark-lite.sh` for the three profiles the
entry subscribes to, and the same profiles for the nginx and h2o entries of the repository.

- machine: AMD Ryzen 9 9900X (12 cores, 24 threads), Debian 13, Linux 6.12.107+deb13-amd64
- harness inside Docker-in-Docker (`bench/httparena/local.sh`; the host's 8080-8082 are taken and
  the harness restarts the Docker daemon); Docker 29.8.1 inside; no CPU pinning: server and load
  generator share the 24 threads (the lite mode), 12 load threads
- agensio v0.1.0-alpha.20 (Debian trixie build, `-march=native`, 24 workers per process, two
  processes: h1-only TLS on 8081, h2 on 8443); nginx 1.31.4 from the entry (quictls, brotli,
  custom handler module, `worker_processes auto`); h2o from the entry (libh2o, custom app)
- 512 connections, 5 s, best of 3; pipelined: gcannon 16 deep on `/pipeline`; static-h2: h2load
  32 streams per connection over the 20 files; static-tls: wrk with the 20-file rotation over
  HTTP/1.1 + TLS, `Accept-Encoding: br;q=1, gzip;q=0.8` on every static request
- CPU is the container's cgroup average over the run (percent of one thread); memory the peak
- static-tls was added to the lite profile map for this run (the shipped lite set skips it)

| profile | agensio | nginx | h2o |
|---|---|---|---|
| pipelined, req/s | 4,773,257 | 4,651,758 | 5,645,580 |
| pipelined, CPU / peak memory | 1562 % / 42 MiB | 1351 % / 682 MiB | 1537 % / 20 MiB |
| static-h2, req/s | 304,381 | 845,695 | 289,939 |
| static-h2, payload | 18.7 GB/s, 60.0 KB per response | 13.3 GB/s, 14.9 KB per response | 17.6 GB/s, 57.8 KB per response |
| static-h2, CPU / peak memory | 1247 % / 291 MiB | 1422 % / 962 MiB | 1430 % / 343 MiB |
| static-tls, req/s | 268,642 | 634,561 | not subscribed |
| static-tls, payload | 16.0 GB/s, 58.0 KB per response | 9.7 GB/s, 15.0 KB per response | |
| static-tls, CPU / peak memory | 1216 % / 68 MiB | 1129 % / 708 MiB | |

What the static rows measure: every request carries `Accept-Encoding: br`, and 15 of the 20
files have `.br` and `.gz` twins on disk. nginx serves the twin (`brotli_static`,
`gzip_static`), so its average response is 15 KB; agensio and h2o serve the file as stored,
58 to 60 KB. The rows are bandwidth-bound: agensio moves 16.0 GB/s of TLS payload on HTTP/1.1
and 18.7 GB/s on HTTP/2 against nginx's 9.7 and 13.3 GB/s, at equal or lower CPU, and lands at
0.42 and 0.36 of nginx's request rate only because each of its responses is 3.9 to 4.0 times
larger. h2o, which does not serve the twins either, sits at agensio's rate (0.95). Serving
pre-compressed siblings is therefore the one change that moves these rows; it is roadmap E
material pulled forward, checked once at cache fill, so the hit path pays nothing when no
sibling exists.

Pipelined: 16 requests per connection back to back on plain HTTP/1.1. agensio 1.03 of nginx and
0.85 of h2o; h2o answers `ok` from its handler, agensio serves it as a cached file behind an
exact location with a `try_files` hop (`/pipeline` to `/pipeline.txt`), nginx from its module.
Memory: agensio 42 MiB, nginx 682 MiB (`worker_connections 65536` preallocated per worker), h2o
20 MiB. On static-h2 agensio keeps 291 MiB for 512 connections with 32 streams each, 18 KB per
open stream; the two 100-field header arrays per stream are the known lever (design G2).

## Rerun with pre-compressed twins served (working tree after alpha.20, same session)

The same three profiles with the twins change (`[cache] precompressed`, alpha.21): the
validator now passes the compression check too (24 checks, "15 files compressed, 5 skipped",
the five being the images and fonts that have no twins), and the static rows move as the
byte analysis predicted.

| profile | agensio before | agensio with twins | nginx | h2o |
|---|---|---|---|---|
| pipelined, req/s | 4,773,257 | 4,951,197 | 4,651,758 | 5,645,580 |
| pipelined, CPU / peak memory | 1562 % / 42 MiB | 1535 % / 43 MiB | 1351 % / 682 MiB | 1537 % / 20 MiB |
| static-h2, req/s | 304,381 | 954,688 | 845,695 | 289,939 |
| static-h2, payload | 18.7 GB/s, 60.0 KB per response | 15.1 GB/s, 14.9 KB per response | 13.3 GB/s, 14.9 KB per response | 17.6 GB/s, 57.8 KB per response |
| static-h2, CPU / peak memory | 1247 % / 291 MiB | 1417 % / 178 MiB | 1422 % / 962 MiB | 1430 % / 343 MiB |
| static-tls, req/s | 268,642 | 687,388 | 634,561 | not subscribed |
| static-tls, payload | 16.0 GB/s, 58.0 KB per response | 10.6 GB/s, 15.0 KB per response | 9.7 GB/s, 15.0 KB per response | |
| static-tls, CPU / peak memory | 1216 % / 68 MiB | 1073 % / 70 MiB | 1129 % / 708 MiB | |

With the same bytes per response as nginx, agensio serves 1.13 times nginx's request rate
on static-h2 and 1.08 times on static-tls, at the same or less CPU and a fraction of the
memory (twins are cached beside the file, so the entries grew, and the h2 peak fell because
the responses did). Pipelined is 1.06 times nginx; h2o stays ahead there by 0.88, answering
from its handler where agensio serves a cached file through a `try_files` hop. Raw output
in `raw/httparena-lite-20260924-0147/*-twins.log`.

## Worker count under SMT, server and load generator on disjoint cores

The arena pins the server to 32 cores plus their SMT siblings and the load generators to
the other half. To decide between one worker per thread (what `start.sh` does, like nginx's
`worker_processes auto` and h2o's one thread per processor) and one per physical core, the
same three profiles ran with the server container on CPUs 0-5,12-17 (six cores and their
siblings) and the load generators on 6-11,18-23 with six threads (`SERVER_CPUS`, `LOAD_CPUS`,
`WORKERS` of `bench/httparena/local.sh`; twins served in all three).

| profile | agensio, 12 workers | agensio, 6 workers | nginx, 12 workers |
|---|---|---|---|
| pipelined, req/s | 4,036,962 | 2,643,089 | 3,386,956 |
| pipelined, CPU / peak memory | 1208 % / 35 MiB | 555 % / 36 MiB | 1110 % / 678 MiB |
| static-h2, req/s | 841,051 | 626,873 | 728,665 |
| static-h2, CPU / peak memory | 1199 % / 119 MiB | 604 % / 101 MiB | 1105 % / 942 MiB |
| static-tls, req/s | 461,520 | 438,864 | 451,582 |
| static-tls, CPU / peak memory | 707 % / 68 MiB | 582 % / 65 MiB | 886 % / 702 MiB |

One worker per thread wins on every row: 1.53 times the six-worker rate on pipelined, 1.34
on static-h2, 1.05 on static-tls. The CPU column is thread time, so under SMT it cannot be
read as per-request cost across the two counts. static-tls is bound by the six wrk threads
here (agensio at 707 % of 1200 % available, nginx at the same rate), which is why the
unpinned run above, with twelve wrk threads, shows higher numbers; the arena's load
generators have 64 threads. Against nginx at the same pinning: pipelined 1.19, static-h2
1.15, static-tls level and load-bound. Raw output in `raw/httparena-lite-20260924-0147/*-pinned.log`.

## All nine profiles, with the benchmark handler (working tree after alpha.20, same session)

The handler step (`handler = "httparena"`, `-DAGENSIO_HTTPARENA=ON`; `protocols` per site,
`workers = 0` from the cpuset; one process with the four listeners): the arena's validator
passes 70 checks, and every profile the infrastructure tier scores except the two HTTP/3
rows ran for agensio, with the rows nginx and h2o subscribe to. Same lite setup: 24
threads shared with the load generators, 512 connections, 5 s, best of 3.

| profile | agensio | nginx | h2o | agensio / nginx | agensio / h2o |
|---|---|---|---|---|---|
| baseline | 2,974,438 (1297 %, 38 MiB) | 2,875,625 (1209 %, 676 MiB) | 2,948,866 (1295 %, 19 MiB) | 1.03 | 1.01 |
| pipelined | 5,775,579 (1580 %, 23 MiB) | 4,651,758 (1351 %, 682 MiB) | 5,645,580 (1537 %, 20 MiB) | 1.24 | 1.02 |
| limited-conn | 2,048,426 (1189 %, 44 MiB) | 2,072,407 (1047 %, 686 MiB) | 2,048,322 (1138 %, 28 MiB) | 0.99 | 1.00 |
| json-tls | 1,215,901 (1004 %, 78 MiB) | 1,072,323 (1142 %, 702 MiB) | 866,158 (1257 %, 55 MiB) | 1.13 | 1.40 |
| static-tls | 683,283 (995 %, 67 MiB) | 634,561 (1129 %, 708 MiB) | not subscribed | 1.08 | |
| baseline-h2 | 3,527,827 (1176 %, 63 MiB) | 3,002,565 (1203 %, 755 MiB) | 12,385,544 (931 %, 67 MiB) | 1.18 | 0.28 |
| static-h2 | 951,716 (1397 %, 153 MiB) | 845,695 (1422 %, 962 MiB) | 289,939 (1430 %, 343 MiB) | 1.13 | 3.28 |
| baseline-h2c (reference) | 5,029,619 (1418 %, 49 MiB) | 3,020,093 (1582 %, 801 MiB) | not subscribed | 1.67 | |
| json-h2c (reference) | 2,704,293 (1641 %, 84 MiB) | 1,632,291 (1681 %, 738 MiB) | not subscribed | 1.66 | |

Row by row. baseline is a three-way tie within 3 %: the request path itself, two syscalls
per request, is where all three sit. pipelined moved from 4.95M to 5.78M with the handler
alone (no `try_files` hop, a minimal head) and is now ahead of h2o without response
coalescing. limited-conn is a three-way tie at 2.05M, which is 205k connections a second:
bound outside the servers, by the accept and close churn of the loopback. json-tls: the
pre-rendered item prefixes make the row mostly TLS, where agensio leads nginx by 1.13 and
h2o by 1.40 at less CPU than either. baseline-h2 is the one row h2o owns: 12.4M against our
3.5M, at less CPU. h2load's own accounting shows why in part: h2o's answer is 25 bytes on
the wire (302 MB/s at 12.2M), ours 64 (a literal content-type, content-length, server and
date per response) and nginx's 82; with a hundred streams per connection and the load
generator sharing the cores, bytes per response are segments, syscalls and h2load CPU.
Per request agensio spends 3.3 µs there against h2o's 0.75, so the wire size is not the
whole story; the small-response HTTP/2 path needs a profile before anything is changed.
The h2c rows are reference only (not scored for infrastructure) and sit at 1.67 of nginx.

Against nginx, then: ahead on eight of nine rows and level on the ninth, at a fifth to a
twentieth of the memory. Against h2o: ahead or level on five of its six rows, behind on
baseline-h2. Raw output in `raw/httparena-lite-20260924-0147/*-handler-rows.log` and
`validate-agensio-handler.log`.

## baseline-h2 against h2o: the cause

Pinned like the SMT section (server on six cores plus siblings, load generators on the other
six): agensio 3,263,453 req/s at 1124 % against h2o 11,058,796 at 754 %, and h2o is then
load-bound (7.5 of its 12 threads busy), so its true cost per request is at most 0.68 µs of
thread time against our 3.4. h2c for agensio at the same pinning: 3,649,724 at 1204 %, so
TLS is not where the time goes. One worker under h2load 64 x 100 (`bench/h2/profile.sh`,
raw in `raw/.../profile-baseline-h2-agensio.txt`): 583k req/s on h2c, 516k over TLS.

1. **Writes.** `strace -c` for 3 s under load: 473,309 `sendmsg` against 4,739 `recvfrom`
   for about 1.1M requests, one send per 2.4 answers. A read brings some 240 HEADERS
   frames, and the answer to each is enqueued as soon as the handler returns; the write
   completes inline on loopback, so the next cycle starts with whatever became ready in
   between, two or three streams. h2o answers every frame of a read into its buffer and
   writes once. `perf stat` puts 61 % of our cycles in the kernel (13.2G kernel against
   8.5G user over 4 s): the send path, at 0.42 calls per request, is the largest single cost.
2. **Bytes.** `nghttp -v`: our HEADERS block is 48 bytes on every answer (server and date
   as literals, 33 of them, plus content-type and content-length literals), h2o's is 18 on
   the first answer and 7 after, because it encodes its fields into the dynamic table and
   omits Date. On the wire an answer is 67 bytes from agensio and 26 from h2o: segments,
   TLS records and the client's own parsing scale with it.
3. **User time**, 3.7k cycles per request, is diffuse: HPACK decoding of the request with
   Huffman 7 to 8 %, two clock reads per request 3.5 %, encoding the text head
   (`static_name_index`, `build_head`, `huffman_encode`) about 5 %, target normalisation
   and routing 2.5 %.

The plan that follows from it: batch the answers of one read into one write cycle (the
frame loop enqueues, the cycle starts when the loop ends or the scatter budget fills; no
change for a connection with one stream), encode server, date and content-type through the
HPACK dynamic table (Date stays: RFC 9110 requires it of an origin server; it costs one byte
a response and one insertion a second), one clock read per read, and a prebuilt head for
the handler. Then measure again.

## After write batching (the first of the two fixes)

The writer is held across the frame loop of one read and a cycle of many small pieces is
copied into one buffer (`Writer::Hold`, `kCoalescePieces`; design 6.6). Same one-worker
profile: 67,984 sends for 7.8M requests, one per 57 answers against one per 2.4; 1.30M
req/s on h2c during the syscall count (1.50M in the profile run, from 583k) and 1.61M over
TLS (from 516k). Pinned like the rows above: agensio baseline-h2 7,549,133 req/s at 927 %
against 3,263,453 at 1124 % before, 1.23 µs per request against 3.4; baseline-h2c
8,099,499 at 950 %. h2o's 11,058,796 at 754 % stays the bar, and is load-bound. The A/B
against alpha.20 (`ab-20260924-011552.md`): the multiplexed rows h2c and h2 at ten
streams 0.347 and 0.348 of the base CPU per request, the single-stream rows 0.989 and
1.008, the HTTP/1 rows 0.951 to 1.005. Next: the dynamic-table head.

## After the dynamic-table head (the second fix)

`hpack::Encoder` per connection (design 6.2.1): the handler's answer block went from 48
bytes to 8 (`nghttp -v`: 48, then 8, 8), a static file's from 107 to 56. TLS cycles that
are coalesced before `SSL_write` are capped at 64 KB of body with it (256 KB cycles, full
since the batching, cost the static-h2 row 9 %: 770k against 834k req/s pinned). Pinned
like the rows above: baseline-h2 8,460,254 req/s at 1042 % (7,549,133 at 927 % after the
batching alone; 3,263,453 at 1124 % before it), h2c 9,288,525 at 1177 %, static-h2
834,117 at 1082 % and 232 MiB (841,051 before the batching at 1199 %). One worker: 1.54M
req/s on h2c and 1.62M over TLS, one send per 57 answers. The A/B against alpha.20
(`ab-20260924-075048.md`): the ten-stream rows at 0.387 and 0.373 of the base CPU per
request, the single-stream rows 1.015 and 1.022, the HTTP/1 rows 0.962 to 1.004.

Against h2o on baseline-h2: 8.46M against 11.06M, from 0.29 of it at the start of this
investigation to 0.76; h2o is load-bound there at 754 % of CPU, we are at 1042 % of 1200,
so what is left is our cost per request, 1.23 µs of thread time against h2o's 0.68 at
most. The profile's remaining items are all per-request user time: two clock reads per
stream, the heap-allocated completion of the synchronous handler, HPACK decoding of the
request with Huffman, target normalisation and routing.

## After the per-request steps (three, same session, later the same day)

h2o measured on one thread against one agensio worker under the same `h2load -c 64 -m 100
-t 4` in the same perf container (`bench/httparena/profile-h2o.sh`; the arena's h2o app
rebuilt with an `H2O_THREADS` variable, since it starts a loop per online CPU): h2o 2.60M
req/s on the TLS baseline URL, 2054 cycles per request (10.1G user + 0.56G kernel cycles
over 2 s), IPC 3.89, one `read` and one `sendmsg` per 227 answers, and a profile whose
top items are its Huffman decoder (9 %), malloc (7 %) and request parsing. agensio before
this work, the same way: 1.42M over TLS (the TLS numbers of the two sections above were
invalid: the perf config's certificate did not cover the host and every answer was a 421;
the h2c numbers stood), 3730 cycles per request, of which the clock 11 % (four reads per
request), the stream object's construction and freeing with malloc 23 % (the pool kept
four streams; h2load keeps a hundred in flight), request HPACK 18 %, routing and target
normalisation 12 %, response HPACK 7 %.

Step 1, the clock read once per socket event, the stream pool sized to the concurrency
limit, O(1) stream release and lookups, the writer's in-flight list a flag, the handler's
continuation in the `std::function`'s storage: 2.44M over TLS, 2230 cycles per request.
Step 2, the Huffman decoder writing through a pointer, static-table fields not copied,
one static-name search per encoded field plus a remembered content-type index, the
single-site router shortcut, the plain-target normaliser shortcut, the handler's HTTP/2
tail prebuilt instead of a text block per answer: 3.04M over TLS and 3.37M on h2c, 1775
cycles. Step 3, the write cycle built into one buffer (a read's answers were leaving in
two sends: the 256-piece scatter cap stopped a cycle at 85 small answers): 3.30M over
TLS and 3.97M on h2c, about 1610 cycles per request, 1481 of them user time; one `send`
per read now, the kernel's share per request 129 cycles against h2o's 108. Per core
agensio answers 1.27 times what h2o does on this row. What remains in the profile is
the request side: the Huffman decode of the `:path` literal (15 %, the same automaton
h2o walks), the field checks of request assembly (9 %), routing (6 %) and the
normaliser's scan (6 %). Raw perf output per step in `raw/httparena-lite-20260924-0147/perf/`.

Step 4, after the pinned rows below showed the cost of the pool's memory: requests are
decoded into the connection's scratch (reserved once, hot) and each stream keeps an
exact-size copy instead of reserving the 16 KB header limit for itself: 3.48M req/s over
TLS on one worker, IPC 4.16.

Pinned like the earlier sections (twelve workers on six cores and their siblings, the
load generators on the other six), all nine rows after step 3, six load threads
(`raw/httparena-lite-20260924-0147/pinned-nine-rows-after-step3.log`): baseline 1.83M
req/s at 920 % (h1, gcannon), pipelined 4.16M at 1125 %, limited-conn 1.35M at 844 %,
baseline-h2 9.83M at 714 % (8.46M at 1042 % after the dynamic-table head), static-h2
846k at 1086 %, static-tls 466k at 709 %, json-tls 798k at 642 %, baseline-h2c 10.56M at
680 % (9.29M at 1177 %), json-h2c 2.66M at 1206 %. The h2 baseline rows are load-bound
with six threads now (h2o's 11.06M at 754 % was too), so baseline-h2 was rerun with
twelve load threads for both (`pinned-baseline-h2-12-load-threads.log`): h2o 12.88M at
891 % and 65 MiB, agensio 11.16M at 1142 % and 647 MiB after step 3, 11.12M at 1112 % and
441 MiB after step 4. So on one core agensio answers 1.34 times what h2o does on this row
(3.48M against 2.60M), and with twelve workers on six cores 0.86 of it: the per-request
thread time grows 3.5 times from one worker to twelve for agensio and 1.8 times for h2o.
The memory is the pool of 6.6 keeping as many stream objects as the client had in flight
(a hundred per connection here), 24 KB each before step 4 and about 8 KB after, the two
100-field header arrays; released when the connection idles.

Where the twelve-worker cost goes (`bench/httparena/profile-12w.sh`, perf over every
thread of each server under the pinned twelve-thread load, raw in
`raw/httparena-lite-20260924-0147/perf/twelve-workers-pinned-h2o-and-agensio.txt`):
agensio executes fewer instructions per request than h2o, 5.9k against 7.9k, but at
1.54 instructions per cycle against h2o's 2.73, where one worker ran at 4.16 and h2o's
one thread at 3.89: 3860 cycles per request against 2880, with 31 last-level cache misses
per request against 23. The symbols that grow are the ones that touch the stream object
(`route` from 6 % to 13 %, `begin_request`, `dispatch`, `release`, `open_stream`), not the
decoders. The cause is the working set: a read with a hundred HEADERS frames opens a
hundred streams, every one answered inside the frame loop but kept open until the write
completes, so each burst walks a hundred stream objects per connection, 43 connections
per worker, 8 KB apiece spread over cold cache lines; h2o frees a stream's memory as
soon as its answer is in the connection's output buffer and takes the same hot chunk
back for the next. The fix is the same shape (design 6.6, not built): an answer that is
complete and small is emitted into the cycle's buffer at `respond()` time even while the
writer is held, and its stream closed and pooled at once, so the next HEADERS frame of
the read takes the same object; only asynchronous answers and large bodies keep a
stream open across the write.

Two bugs found by the suites on the way: LeakSanitizer reported, at the end of the
integration suite, 84 control-socket connections with their buffers (15 MB) kept alive by
the control handler's body-reading step, which captured itself strongly; and a build
without OpenSSL had not compiled since the per-site `protocols` change. Both fixed.
The A/B against alpha.20 after step 4 (`ab-20260924-091348.md`): the ten-stream rows at
0.254 and 0.274 of the base CPU per request, the single-stream rows 0.901 and 0.971, the
HTTP/1 rows 0.965 to 1.010.

Not run: the two HTTP/3 rows, which need phase I.

Commands (`bench/httparena/local.sh` wraps them in the Docker-in-Docker container):

```
bench/httparena/local.sh setup
bench/httparena/local.sh validate agensio
bench/httparena/local.sh bench agensio            # pipelined, static-h2, static-tls
bench/httparena/local.sh bench nginx pipelined    # then static-h2, static-tls; h2o: pipelined, static-h2
```

Raw output in `raw/httparena-lite-20260924-0147/` (the validator's checks and every run's
load-generator summary and cgroup stats).
