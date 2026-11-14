# Forwarding a response body: techniques measured, 2026-11-14

- machine: AMD Ryzen 9 9900X, 24 CPUs, Linux 6.12.116+deb13-amd64; commit eca09dbd
- one agensio worker pinned on CPU 0, the benchmark upstream on CPUs 4-7, wrk (4 threads, 64 connections, 6 s) on 8-11 and 20-23; three rounds, the variants alternated in each round; means
- the techniques are a prototype outside the tree (one binary, each technique switched by an environment variable, so the layout is the same for every variant); nothing of it is in the commit
- CPU us/req = the proxy's CPU time over the requests answered; MB = its resident memory at the end of the row

## What is there today

agensio buffers an origin's answer by default (`buffering = true`); `buffering = false` streams it, as Pingora always does. The same binary, both settings (bench/results/pingora-20261114-103322.md buffered, pingora-20261114-103905.md streaming, two rounds each):

| row | buffered | streaming | streaming / buffered |
|---|---|---|---|
| /json, 64 connections | 8.0 us | 9.4 us | 1.17 |
| /big 100 KB | 31.2 us | 41.8 us | 1.34 |
| HTTPS /json | 8.2 us | 11.8 us | 1.44 |
| HTTPS /big 100 KB | 48.6 us | 51.0 us | 1.05 |
| HTTP/2 /json, one stream | 9.5 us | 13.9 us | 1.47 |
| HTTP/2 /json, ten streams | 8.7 us | 14.0 us | 1.62 |
| HTTP/2 /big, ten streams | 64.2 us | 74.8 us | 1.17 |
| request mix, one worker | 17.0 us | 19.3 us | 1.14 |

System calls per request (strace -c): a small streamed answer takes two sends to the client where a buffered one takes one, and one more read of the origin; a streamed 100 KB body takes eight sends and nine reads, each piece copied twice on its way.

## Streaming path: the techniques

| row | buffered today | streaming today | + whole answer in one write | + read on demand into the writer's buffer |
|---|---|---|---|---|
| /json | 7.49 us, 17.5 MB | 9.08 us, 21.6 MB | 7.38 us, 17.6 MB | 6.96 us, 17.4 MB |
| HTTPS /json | 8.12 us, 22.9 MB | 10.57 us, 27.1 MB | 8.21 us, 23.0 MB | 7.89 us, 22.9 MB |
| /big 100 KB | 30.01 us, 25.8 MB | 40.20 us, 21.7 MB | 40.20 us, 21.5 MB | 29.46 us, 21.7 MB |
| HTTPS /big 100 KB | 47.31 us, 32.5 MB | 49.59 us, 27.3 MB | 48.92 us, 27.3 MB | 45.23 us, 27.2 MB |

- whole answer in one write: when the body arrived complete with the head, the exchange answers as a buffered one does (one write, no pull).
- read on demand: a body of known length is read straight into the buffer the client-side writer sends from, when the writer asks; no pass through the connection's buffer and the pending queue. Keeping today's read-ahead for a client that takes the answer slower than the origin gives it costs nothing: 29.8 against 30.0 us plain, 47.2 against 46.6 over TLS (two rounds).

## Buffered path: the techniques (100 KB body)

| variant | plain | HTTPS |
|---|---|---|
| today | 31.42 us | 50.05 us |
| body buffer sized from Content-Length | 30.15 us | 48.20 us |
| body read straight into that buffer | 27.83 us | 45.36 us |
| 64 KB reads in place of 16 KB | 31.56 us | 49.04 us |

## Against Pingora, both streaming

bench/results/pingora-20261114-110107.md (the prototype with both streaming techniques, `buffering = false`, two rounds, Pingora in the same session): agensio 1.17 to 1.81 times less CPU per request on every row. Today's streaming path against the Pingora figures of that run (two sessions, so approximate): 1.04 to 1.5, and Pingora ahead on HTTP/2 small answers at ten streams (14.0 against 11.0 us).

## Memory under load is per active connection, not the body

The request mix over TLS, resident memory while the load runs, less the baseline, over the connections:

| connections | buffered | prototype streaming |
|---|---|---|
| 64 | 214 KB | 216 KB |
| 256 | 177 KB | 192 KB |
| 1,024 | 158 KB | 177 KB |
| 256, plain HTTP | 86 KB | 113 KB |

Four seconds after the load the same connections' memory is back to 17 to 23 MB in all (the idle shed). Pingora on the same mix holds about 100 KB per active TLS connection (40 MB at 256). So what Pingora leads on is the buffers a busy connection keeps between its requests (the writer's 64 KB piece, the receive buffer, the TLS buffers), not the buffering of answers.

## What was built from this, and what it measures

The three path changes (docs/design-proxy-streaming.md 4.1 to 4.3) and the buffers lent per answer
(section 11 there), measured on the commit's code, not the prototype.

A/B against the commit before (`bench/ab.sh HEAD -P`, three rounds), the path changes alone:
ab-20261114-123203.md. The default (buffered) proxy rows: /json 0.996, /big 100 KB 0.788 (18.4 to
14.5 us), the static rows 0.965 to 1.003.

Memory a busy connection holds, the request mix, resident memory during the load less the baseline
over the connections (one worker; `mem.sh` of the session, each binary in turn):

| | HEAD | path changes | + the answer's buffers lent | + OpenSSL releasing its buffers |
|---|---|---|---|---|
| TLS, 256 connections | 173 KB | 166 KB | 128 KB | 97 KB |
| TLS, 1,024 connections | 158 KB | 146 KB | 111 KB | 80 KB |
| plain, 256 connections | 84 KB | | 50 KB | |

What each costs on the static HTTPS rows (one worker pinned, wrk 64 connections, 5 s, four
alternated rounds, CPU us per request):

| | path changes | + buffers lent | + OpenSSL releasing its buffers |
|---|---|---|---|
| HTTPS 1 KB | 4.75 (4.74 to 4.77) | 4.74 (4.72 to 4.79) | 4.86 (4.82 to 4.89) |
| HTTPS 100 KB | 34.32 | 34.28 | 34.35 |

Lending is free. `SSL_MODE_RELEASE_BUFFERS` costs 2.3 % on the small row and was taken out again
(the proxied HTTPS /json row had not shown it: 8.49 against 8.72 us over eight rounds, inside that
row's swing).

## Where a small proxied request's cycles go (perf, one worker)

38,100 cycles: 76 % kernel (four system calls and the loopback's TCP work), 16 % agensio, 5 % libc,
2 % the clock. In agensio the origin's head is parsed twice (2.5 % of the row together), the clock
is read three or four times a request (1.6 %), and the allocator takes about 2 %: what is left to
take in user space is a few percent. On the 100 KB rows 28 % (plain) and 16 % (TLS) of the cycles
are the kernel zeroing the pages a send copies into (`clear_page_erms`: Debian's `init_on_alloc`).

## What 2,000 configured sites cost (massif)

50.1 MB resident against 10.4 MB with none: 19.8 KB a site. The configuration is held twice, once
as the boot configuration (`Server::cfg_`, read for the restart-only keys) and once in the running
generation: 6.5 KB per `SiteConfig` and 2.6 KB per `LocationConfig` in each. Nothing in the server
reads the boot copy's sites; it was not changed in this step.
