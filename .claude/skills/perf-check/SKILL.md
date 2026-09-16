---
name: perf-check
description: Measure agensio performance the way this project trusts (single worker, CPU microseconds per request, sample profiling) before and after any change on the request path, and record the result.
---

# Performance check workflow

The metric is **server CPU microseconds per request** with one worker, not req/s alone:
wrk shares the cores, so req/s can measure the load generator. Details and past numbers:
`CLAUDE.md` "Performance notes".

## Steps
1. Build Release: `cmake --build build`. Run `./build/agensio_tests` and
   `tests/integration.sh build/agensio`; performance work on broken code is wasted.
2. Baseline before the change (stash or use the previous binary):
   `bench/run.sh -s "agensio nginx" -w 1 -t 4` (5 s per case; `-d 15s` for publishable
   numbers). The table has `cpu us/req` and `rss MB` columns. Never run other CPU-heavy
   work while it runs.
3. Apply the change, rebuild, run the same command. Compare `cpu us/req` per case; a
   difference under ~3 % is noise on this machine, repeat twice before believing it.
4. If slower or not faster as expected, profile instead of guessing:
   `sample <pid> 5 -file out.txt` on macOS while wrk runs; read "Sort by top of stack" at
   the end for self time (`kevent` there is blocked time, not CPU). On Linux use
   `perf record -g` / `perf report`. Count syscalls per request; they usually dominate.
5. Check nothing stale is serving: `bench/run.sh` refuses to start if a port is busy;
   nginx is killed with `pkill -f 'nginx: '`.
6. Record: raw output lands in `bench/results/raw/`, the table in `bench/results/`. Put
   the before/after numbers in the commit message and, if a design fact was learned, in
   `CLAUDE.md` "Performance notes" (including negative results, so they are not retried).

## Things already measured (do not retry without new evidence)
Header string assembly (< 0.5 % of a request), cache hit-path refcount traffic,
`SSL_MODE_RELEASE_BUFFERS`, streaming chunk size, memory-BIO reads, `socket.async_wait`
for readiness (re-registers kevent). See `CLAUDE.md`.
