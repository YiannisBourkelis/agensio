# Single worker comparison, 2026-09-15

agensio `workers = 1` vs nginx `worker_processes 1`, same machine (Apple M1 Pro, macOS 26.4),
wrk 4 threads, 64 connections, 5 s, keep-alive. One server core saturated in every row, so
CPU us/req is the true per-request cost (server CPU time divided by requests served).

| case | agensio req/s | agensio us/req | nginx req/s | nginx us/req |
|---|---|---|---|---|
| HTTP 1 KB | 127,756 | 7.8 | 83,812 | 11.6 |
| HTTPS 1 KB | 108,694 | 9.3 | 78,323 | 12.6 |
| HTTP 100 KB | 49,282 | 19.8 | 51,415 | 18.9 |
| HTTPS 100 KB | 18,139 | 55.5 | 14,514 | 67.8 |

Latency p50/p99: agensio 495/825 us, 580/790 us, 1.20/1.61 ms, 3.79/4.35 ms;
nginx 741 us/1.04 ms, 842 us/0.99 ms, 1.22/1.46 ms, 4.42/5.12 ms.

Notes
- With one worker agensio serves as many plain 1 KB requests per second as with ten
  (128k vs 131k): the ten-worker runs are bounded by wrk sharing the cores, not by the server.
- HTTP 100 KB is the one row nginx wins (5 %): sendfile from the page cache avoids the
  100 KB user-to-kernel copy that serving from our in-memory cache costs. Possible future
  experiment: serve cached entries on plain sockets via sendfile from a cached fd.
