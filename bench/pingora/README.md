# agensio against Pingora as a reverse proxy

[Pingora](https://github.com/cloudflare/pingora) is Cloudflare's Rust framework for building
proxies. It is a library, not a server: someone writes the proxy program. This directory holds
one, written the way Pingora's own examples are, and a script that runs it and agensio through
the same six groups of tests and writes one report.

Only reverse proxying is compared. Pingora serves no files and runs no PHP, which is most of what
agensio is for, and it has no HTTP/3 towards clients; agensio does not speak HTTP/2 to origins and
has no response cache, which Pingora has. None of that is measured here.

## Running it

```
bench/pingora/build.sh                 # on the host: builds the Pingora proxy in a Rust container
cmake --build build                    # agensio and the benchmark upstream
docker run --rm --init --ulimit nofile=65536:65536 -v $PWD:$PWD -w $PWD --user 1000:1000 \
  -e HOME=/home/dev agensio-devbox:latest bench/pingora/run.sh -r 3
```

The report lands in `bench/results/pingora-<stamp>.md`, the raw tool output beside it under
`raw/`. `run.sh` has the options at its top: `-T` picks groups, `-d` the seconds per row, `-r` the
rounds, `-w` the worker counts, `-n` the number of origins, `-i` the idle connections, `-P`
switches CPU pinning off.

| file | what it is |
|---|---|
| `proxy/` | the Pingora side: `src/main.rs`, Pingora pinned to 0.9.1, `Cargo.lock` |
| `build.sh`, `Dockerfile` | build it on Debian 13, the system the devbox runs |
| `run.sh` | the comparison |
| `mixed.lua`, `origins.lua` | wrk scripts: the request mix, and the many-origins load |
| `hold.py` | opens and holds idle client connections for the memory rows |

## What is equal on both sides

- **The origin.** `build/agensio_upstream` with four workers, which answers 1.3 million small
  requests a second alone, so it is never the limit. Its first two rows in the report are that
  ceiling.
- **What is forwarded.** Host as the client sent it, `X-Forwarded-For`, `X-Forwarded-Proto` and
  `X-Real-IP`. `run.sh` checks before every group that the origin received them, that bodies come
  back byte for byte through both proxies, and that both speak HTTP/2 over TLS.
- **Workers.** agensio `workers = W`, Pingora `threads = W` with work stealing, its default.
- **CPUs.** The proxy runs alone on CPUs 0 to W-1, the origin on 4 to 7, the load generator on 8
  to 11 and their siblings, so the load generator never takes the proxy's time.
- **No access log**, connections to the origin kept, the same certificate.
- **Idle pool sizes.** Each side's pool is set to hold what the row needs: agensio
  `max_idle = 256`, Pingora `upstream_keepalive_pool_size = 1024`, and four per origin in the
  many-origins rows. Pingora's default of 128 for the whole process would close most of 2,000
  origins' connections, which would not be a fair picture of it.

What is not equal: Pingora's `openssl` feature builds and links its own OpenSSL (3.6.3 here);
agensio uses the system's (3.5.7).

## What the numbers mean

**CPU microseconds per request** is the measure to read first: the CPU time of the proxy's
process, all threads, over the requests it answered. It is what a request costs, whatever the
load generator could deliver. Requests per second with one worker is the same fact seen the other
way, since one core is saturated.

The absolute values are higher than those of `bench/proxy/run.sh` and `bench/ab.sh`, which do not
pin: alone on its core, every wake-up of the proxy crosses cores. The same row, the same binary:
5.0 us unpinned, 7.0 to 7.8 us pinned. The second report below is the unpinned cross-check.

## Results, 2026-11-14

Machine: AMD Ryzen 9 9900X (12 cores, 24 threads), Debian 13, kernel 6.12.116, loopback.
agensio 0.1.0-alpha.146, Pingora 0.9.1. Three rounds of 10 s rows, no row with an error.

- [pingora-20261114-002148.md](../results/pingora-20261114-002148.md): the full run, pinned.
- [pingora-20261114-004439.md](../results/pingora-20261114-004439.md): the plain, TLS and mixed
  rows unpinned, one round.

### CPU per request: agensio uses 1.2 to 2.1 times less

| row | workers | agensio us/req | Pingora us/req | Pingora / agensio | agensio req/s | Pingora req/s |
|---|---|---|---|---|---|---|
| small JSON, 64 connections | 1 | 7.75 | 12.88 | 1.66 | 129,320 | 77,518 |
| small JSON, 16 connections | 1 | 7.16 | 13.52 | 1.89 | 139,633 | 74,186 |
| 100 KB body | 1 | 30.25 | 46.43 | 1.54 | 33,072 | 21,539 |
| 20 ms application, 256 connections | 1 | 9.25 | 17.12 | 1.85 | 12,567 | 12,545 |
| HTTPS, small JSON | 1 | 8.98 | 15.37 | 1.71 | 112,241 | 65,241 |
| HTTPS, 100 KB body | 1 | 48.52 | 56.13 | 1.16 | 20,619 | 17,831 |
| HTTP/2, one stream a connection | 1 | 9.36 | 15.53 | 1.66 | 107,219 | 64,479 |
| HTTP/2, ten streams | 1 | 8.17 | 11.83 | 1.45 | 123,107 | 84,396 |
| HTTP/2, 100 KB body, ten streams | 1 | 61.34 | 83.06 | 1.35 | 16,293 | 12,031 |
| mixed traffic over HTTPS | 1 | 16.53 | 24.36 | 1.47 | 60,242 | 40,841 |
| mixed traffic over HTTPS | 4 | 16.25 | 27.75 | 1.71 | 241,791 | 138,613 |
| 2,000 origins, warm | 1 | 9.21 | 19.16 | 2.08 | 108,541 | 52,150 |
| 2,000 origins, warm | 4 | 9.91 | 19.89 | 2.01 | 352,574 | 191,902 |

The smallest lead is the 100 KB body over TLS, where encryption is most of the work and both use
OpenSSL. The 20 ms row has equal throughput because the application sets it; agensio spends half
the CPU doing so. Unpinned, the ratios are 1.07 to 2.15.

Latency follows the CPU: median 441 us against 803 us on small JSON at 64 connections, 3.65 ms
against 5.95 ms on the mix with one worker. The 99th percentiles are close on most rows.

### Idle connections: agensio holds 1.4 to 2.6 times less memory

| 10,000 idle client connections | agensio | Pingora | Pingora / agensio |
|---|---|---|---|
| HTTP/1.1 | 14.0 KB each | 35.9 KB each | 2.56 |
| HTTP/1.1 over TLS | 71.4 KB each | 115.5 KB each | 1.62 |
| HTTP/2 over TLS | 82.2 KB each | 117.0 KB each | 1.42 |

### Memory under load: Pingora uses less

| row | agensio RSS | Pingora RSS |
|---|---|---|
| 100 KB body, plain | 26.8 MB | 20.1 MB |
| 100 KB body over TLS | 32.2 MB | 21.9 MB |
| HTTP/2, 100 KB body, 640 streams | 79.6 MB | 64.0 MB |
| mixed traffic, one worker | 60.0 MB | 37.5 MB |
| mixed traffic, four workers | 64.0 MB | 45.9 MB |

The likely cause is agensio's default of buffering an origin's whole answer before sending it
(`buffering = true`), where Pingora passes it on as it arrives. That was not measured separately.

### Many origins: Pingora's shared pool does what it was built for

2,000 origins, 256 client connections, every request to an origin drawn evenly.

| workers | phase | agensio opened | Pingora opened | agensio RSS | Pingora RSS |
|---|---|---|---|---|---|
| 1 | first 10 s | 5,355 | 4,847 | 149 MB | 41 MB |
| 1 | next 10 s | 485 | 435 | 157 MB | 56 MB |
| 4 | first 10 s | 16,537 | 5,909 | 335 MB | 49 MB |
| 4 | next 10 s | 574 | 292 | 344 MB | 65 MB |

With one worker both open about the same number of connections. With four, agensio opens 2.8
times as many, because each worker keeps its own pool and Pingora's threads share one. agensio
also pays about 17 KB of memory for every connection it keeps to an origin: with the same 2,002
sites loaded and no traffic it holds 54 MB. agensio still spends half the CPU per request here.

This is 2,000 origins with steady traffic to each. With far more origins and little traffic to
each, connections idle out before a worker needs them again, and the gap in connections opened
grows with the worker count. That shape was not measured.

## After the first change it led to (0.1.0-alpha.147)

The 17 KB per kept origin connection was its read buffer, held while idle. It is now the worker's,
lent for an exchange. The rows Pingora was ahead on, run again
([pingora-20261114-010744.md](../results/pingora-20261114-010744.md), one round):

| 2,000 origins | agensio before | agensio now | Pingora |
|---|---|---|---|
| one worker, first 10 s | 149 MB | 69 MB | 41 MB |
| one worker, next 10 s | 157 MB | 69 MB | 56 MB |
| four workers, first 10 s | 335 MB | 79 MB | 50 MB |
| four workers, next 10 s | 344 MB | 79 MB | 64 MB |

About 54 MB of agensio's is the 2,002 configured sites, which the Pingora program does not have:
it computes an origin's address from its name. The connections opened (16,622 against 5,899 with
four workers) and the CPU per request (10.0 against 20.6 us) are as before, and so is the request
mix (59 against 37 MB with one worker).

The 71 KB of an idle TLS client connection was mostly buffers: agensio's staging buffer and
OpenSSL's read and write buffers. They are now given back when the connection goes idle
([pingora-20261114-020730.md](../results/pingora-20261114-020730.md)):

| 10,000 idle client connections | agensio before | agensio now | Pingora |
|---|---|---|---|
| HTTP/1.1 | 14.0 KB each | 14.0 KB each | 35.6 KB each |
| HTTP/1.1 over TLS | 71.4 KB each | 44.6 KB each | 115.4 KB each |
| HTTP/2 over TLS | 82.2 KB each | 66.0 KB each | 111.4 KB each |

## With the shared pool (0.1.0-alpha.147, `run.sh -S`)

The many-origins rows led to `proxy = { pool = "shared" }` (`docs/design-upstream-pool.md`): an
idle connection to an origin a worker asks seldom belongs to no worker, so the workers share it
as Pingora's threads do; an origin asked often keeps its connections in the worker. The whole
comparison again with it on every agensio site, three rounds, no row with an error:
[pingora-20261114-043030.md](../results/pingora-20261114-043030.md).

| 2,000 origins, four workers | agensio, pool per worker | agensio, shared pool | Pingora |
|---|---|---|---|
| connections opened, first 10 s | 16,512 | 6,145 | 5,828 |
| connections opened, next 10 s | 486 | 216 | 315 |
| CPU per request | 10.2 us | 9.9 us | 20.3 us |
| requests per second | 317,000 | 348,600 | 162,000 |
| resident memory, first 10 s | 79 MB | 74.5 MB | 53.5 MB |
| resident memory, next 10 s | 79 MB | 74.9 MB | 69.4 MB |

- agensio now opens within 5 % of Pingora's connections from a cold start and fewer once warm,
  and still spends half the CPU per request. Sharing costs nothing measurable on this row.
- With one worker there is nobody to share with and agensio does not use the store: that row is
  as before (5,308 against 4,792 connections, 10.2 against 20.2 us).
- A busy single origin pays nothing: the same row alternated between the two settings gave
  7.57 us with the pool per worker and 7.40 us shared, on a row that swings from 6.9 to 8.4 by
  itself; the store was touched 45 times in 800,000 requests.
- The memory left on this row is agensio's 54 MB for 2,002 configured sites.

How the rule was found: `pingora-20261114-032818.md` (agensio alone, pool per worker),
`pingora-20261114-033213.md` (shared, an origin called busy after one short gap: 9,585
connections) and `pingora-20261114-033804.md` (shared, busy by the average gap: 6,190).

Every other row of the comparison is where it was: agensio 1.1 to 2.1 times less CPU per
request, 14 against 37 KB per idle plain connection, 45 against 115 KB over TLS. Pingora still
uses less memory under load with large bodies (the request mix: 40 against 60 MB), where agensio
buffers an origin's answer by default.

## What this does and does not show

It shows what each costs per request and per connection on one machine over loopback, with a
synthetic origin and a load generator that asks as fast as it is answered.

It does not show behaviour over a real network, with packet loss, slow clients or TLS to the
origin. The Pingora program is minimal; a production proxy built on Pingora does more per
request. Nobody from the Pingora project has reviewed it, and its settings may not be the ones
they would choose. A newer Pingora, another kernel or another CPU can move every number.
