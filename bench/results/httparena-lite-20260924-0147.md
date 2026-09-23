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

Not run: baseline, short-lived and the JSON profiles need the in-process handler (`/baseline11`,
`/baseline2`, `/json/{count}`; the rules forbid proxying them); the two HTTP/3 rows need phase I.

Commands (`bench/httparena/local.sh` wraps them in the Docker-in-Docker container):

```
bench/httparena/local.sh setup
bench/httparena/local.sh validate agensio
bench/httparena/local.sh bench agensio            # pipelined, static-h2, static-tls
bench/httparena/local.sh bench nginx pipelined    # then static-h2, static-tls; h2o: pipelined, static-h2
```

Raw output in `raw/httparena-lite-20260924-0147/` (the validator's checks and every run's
load-generator summary and cgroup stats).
