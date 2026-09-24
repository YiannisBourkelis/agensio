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
