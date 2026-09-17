# FastCGI keep-alive and pool transport (C3a), 2026-09-17

Same setup as `laravel-20260917-100530.md` (Ryzen 9 9900X, Debian 13, one web-server
worker, wrk 4 threads, 64 connections, 10 s, the bed's php-fpm with 8 static children,
cookie sessions). Rows are `bench/laravel/bench.sh` runs; the raw wrk output is under
`raw/laravel-<stamp>/`. "web us/req" is the web server's CPU per request.

| pool transport | agensio options | / (78 KB) req/s | / p50 | / web us/req | /json req/s | /json web us/req | file |
|---|---|---|---|---|---|---|---|
| TCP via docker-proxy | defaults (fresh connection per request) | 3384-3407 | 18.6 ms | 85-86 | 3485-3547 | 54-55 | 100530 |
| TCP via docker-proxy | nginx, fresh connections | 3342-3377 | 18.8 ms | 110-111 | 3513-3532 | 58-59 | 100530 |
| unix socket (bind mount) | defaults | 3564 | 17.5 ms | 51.0 | 3743 | 26.2 | 153426 |
| unix socket | nginx | 3465 | 18.1 ms | 74.4 | 3692 | 30.6 | 153426 |
| unix socket | `keep_conn = true, max_connections = 8` | 3743 | 16.9 ms | 45.4 | 3860 | 25.1 | 153525 |
| TCP direct to the container | `keep_conn`, before the fix | 1051 | 59.1 ms | 49.5 | 3835 | 25.8 | 153719 |
| TCP direct to the container | `keep_conn`, with TCP_QUICKACK | 3749 | 16.9 ms | 51.5 | 3847 | 26.0 | 153901 |
| TCP via docker-proxy | `keep_conn`, with TCP_QUICKACK | 1443 | 40.3 ms | 49.9 | 3816 | 30.6 | 153930 |
| TCP direct to the container | defaults (fresh) | 3146 | 18.0 ms | 147 | 1980 | 505 | 153749 |

Findings:

- The 78 KB page collapsing under `keep_conn` on TCP (1.05-1.4k req/s, p50 40-59 ms)
  is Nagle on php-fpm's side meeting the delayed ACK on ours: the child's last partial
  segment waits for the ACK of the previous one, and Linux delays that ACK by up to
  40 ms when nothing else is flowing. A fresh connection never shows it because close()
  flushes the tail. php-fpm does not set TCP_NODELAY. Fix in `FcgiRequest::quick_ack`:
  TCP_QUICKACK before every read on a kept TCP connection (Linux; a no-op elsewhere),
  plus TCP_NODELAY on the upstream socket for our own writes. Direct TCP with keep-alive
  goes from 1051 to 3749 req/s and matches the unix socket.
- Through docker-proxy the collapse remains (1443 req/s): the delayed ACK there is
  between docker-proxy and php-fpm inside the container, out of our reach. A pool
  published with docker-proxy should use fresh connections (the default) or, on Linux,
  the bind-mounted unix socket (`-p unix`).
- Transport matters more than keep-alive: the unix socket alone takes agensio from 85 to
  51 us on the page and from 54 to 26 us on JSON (nginx: 110 to 74, 58 to 31). Keep-alive
  on top of the unix socket saves another 6 us on the page and 1 us on JSON.
- Fresh connections straight to the container IP cost 147-505 us per request in the web
  server's process: every connect goes through the docker bridge's NAT and conntrack.
  Not a server matter; the row is here so nobody benchmarks that path by accident.
- Default stays `keep_conn = false`: with keep-alive every kept connection pins a
  php-fpm child, so `max_connections` per worker times the worker count must not exceed
  `pm.max_children` (here 1 worker x 8 = 8 children). That sizing belongs to the per-site
  pools of C3b, which will turn it on for the pools they generate.

## Rerun after D1 (shared exchange class: per-pool deadline tick instead of a timer per phase, inline completions)

| pool transport | agensio options | / (78 KB) req/s | / web us/req | /json req/s | /json web us/req | file |
|---|---|---|---|---|---|---|
| unix socket | defaults | 3669 | 46.6 (was 51.0) | 3746 | 25.6 (was 26.2) | 181754 |
| unix socket | `keep_conn = true, max_connections = 8` | 3761 | 45.4 (was 45.4) | 3876 | 23.0 (was 25.1) | 181823 |
| TCP via docker-proxy | defaults | 3351 | 86.8 (was 85-86) | 3495 | 56.0 (was 54-55) | 181853 |

The FastCGI path gained 2-9 % on the unix-socket rows and nothing measurable through
docker-proxy: its cost is the connect per request (fresh connections) and the userland
proxy, not the timers. Single rounds; the bench's noise is about 3 %.
