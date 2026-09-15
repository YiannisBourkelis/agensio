# agensio

A very fast, cross-platform web server written in modern C++ on top of standalone
[Asio](https://think-async.com/Asio/) (Christopher Kohlhoff). Successor of
`open-web-server-asio` (2018, Qt + Boost.Asio); see `docs/legacy-analysis.md` for what the
old code did and which ideas carry over.

Phase 1 goal: serve static files fast enough to beat nginx, Apache httpd and Caddy on the
same machine, with the benchmark harness checked in so anyone can reproduce the numbers.

## Status

Phase 1 implemented: static files over HTTP/HTTPS, in-memory cache, benchmark harness.
Everything under "Architecture" below is what the code does now, not a proposal.

## Hard constraints

- **Asio is the foundation.** Standalone header-only Asio (`ASIO_STANDALONE`, `asio::` namespace),
  never Boost.Asio. Every I/O operation is asynchronous through Asio; no blocking socket calls.
- **No Qt. No Boost.** Standard library first. Language standard: C++23 (Apple clang 21,
  GCC 14+, Clang 18+ are the targets).
- **Dependencies must be justified.** Allowed today: Asio (header-only), OpenSSL (TLS phase
  only, optional at build time). Anything else needs a one-line justification in this file
  under "Dependencies". Prefer header-only, vendored under `third_party/` with its license.
- **Performance is the product.** A change on the request hot path is not done until the
  benchmark has been run before and after and the numbers are in the PR/commit message.
  Never trade throughput for convenience on the hot path (no allocations per request that
  the old design avoided, no locks on the cache-hit path, no per-request string formatting
  of constant headers).
- **Correctness bugs of the old code stay fixed**: see `docs/legacy-analysis.md` section 6.
  Do not reintroduce use-after-free on eviction, unbounded request buffers, missing
  timeouts, unnormalised paths, or `delete this` session lifetime.
- Cross-platform: macOS (kqueue) and Linux (epoll) are first-class; Windows should compile
  but is not benchmarked.

## Working agreement with the agent

- Discuss before building anything larger than a bug fix: the owner wants to review the
  design first. Small, reviewable steps; one concern per commit.
- Do not add features outside the current phase (see Roadmap) even if they look easy.
- Comments and identifiers in English.
- When a benchmark result is produced, store the raw tool output under `bench/results/`
  with machine, OS, date, commit hash and the exact command.
- Commit only when asked. Commit messages end with the attribution line the harness
  provides.

## Dependencies

| Dependency | Why | How |
|---|---|---|
| asio (standalone, 1.38+) | The async I/O core | `brew install asio` on macOS; `libasio-dev` on Debian/Ubuntu; or vendored in `third_party/asio` |
| OpenSSL 3 | TLS (later phase) | optional, `-DAGENSIO_TLS=ON` |
| toml++ 3.4.0 | Config parsing | vendored single header in `third_party/tomlplusplus` (MIT) |

## Planned layout

```
CMakeLists.txt
src/            server sources (one component per file pair .hpp/.cpp)
include/        public headers only if the core becomes a library
config/         example configuration files
bench/          benchmark harness: docker compose, server configs, run scripts, results/
docs/           design notes, legacy analysis, benchmark methodology
tests/          unit tests for the parser, path normalisation, cache
third_party/    vendored header-only libraries with licenses
```

## Build and run

Tooling on macOS: `brew install cmake ninja asio openssl@3`. Benchmark: `brew install wrk nginx caddy`.

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/agensio_tests                      # unit tests (parser, path, cache, mime, date)
./build/agensio -c bench/agensio.toml      # http://127.0.0.1:8080 and https://127.0.0.1:8443
./build/agensio -t -c config/agensio.toml  # config check only
bench/run.sh                               # full benchmark, see bench/results/
```

Source map (all in `src/`): `config` (TOML model + loader), `http_parser` (request head),
`path` (target decoding/normalisation), `mime`, `http_date`, `file` (fd wrapper),
`cache` (shared store + per-worker index), `response` (status lines, error pages),
`handler` (request -> ResponsePlan), `connection.hpp` (template over plain/TLS stream),
`server` (workers, listeners, accept loop), `main`. Tests in `tests/tests.cpp`.

## Architecture (as implemented)

- **Threading**: N worker threads, each owning its own `asio::io_context` (concurrency hint 1).
  Linux (`reuse_port = "auto"`): every worker has its own acceptor with `SO_REUSEPORT`.
  Otherwise: one acceptor on worker 0 accepts into the workers' contexts round-robin and
  posts `start()`. A connection never leaves its worker: no strands, no locks on the
  per-connection path.
- **Session**: `std::shared_ptr<Connection>` with `enable_shared_from_this`, handlers as
  lambdas capturing `self`. Receive buffer reused across keep-alive requests; hard cap on
  header size (default 16 KB) and an idle timeout (default 15 s) via `asio::steady_timer`.
- **Parser**: hand-written incremental HTTP/1.1 request parser over `std::string_view`.
  Methods GET and HEAD (others get 405). Headers of interest: Host, Connection,
  If-None-Match, If-Modified-Since, Range, Accept-Encoding. Pipelining supported by leaving
  unconsumed bytes in the buffer.
- **Request target**: percent-decode, reject control characters, normalise (`.`/`..`
  segments, duplicate slashes), then join with the document root and verify the result stays
  under it. Query string is stripped before the cache lookup.
- **Cache**: two layers. `FileCache` is the shared store (mutex taken only on miss, insert,
  evict) owning the bytes as `shared_ptr<CacheEntry>`. `LocalIndex` is a per-worker map of
  key to that same `shared_ptr`, so a hit is lock-free and memory is never duplicated.
  Eviction/invalidation flips an atomic `stale` flag; local indexes drop stale entries lazily;
  a connection mid-write keeps its entry alive through its own `shared_ptr`. Entry carries the
  prebuilt `Content-Type/Content-Length/Last-Modified/ETag` header block; ETag is
  `"hex(mtime)-hex(size)"` like nginx. Revalidation: `stat()` at most once per
  `revalidate_interval` seconds per entry; no filesystem watcher.
- **Response**: prebuilt header fragments; `Date:` refreshed once per second per worker;
  one `async_write` with a `std::array<const_buffer, N>` of header + body. Uncached large
  files stream in 64 KB chunks from an open fd (`sendfile` on Linux later).
- **MIME**: static extension table compiled in (nginx `mime.types` equivalent), overridable
  from config.
- **Config**: TOML (vendored toml++). `[server]`, `[cache]`, `[[site]]` with `server_name`,
  `listen`, `root`, `index`, `tls`, `default`; `include = ["sites.d/*.toml"]` for
  panel-generated per-site files. Loading never creates sockets; `Server` is built from the
  `Config` struct. `agensio -t` validates.
- **Not in phase 1**: Range requests (no `Accept-Ranges` is sent), directory listing,
  request bodies (405 for non-GET/HEAD, 413 if a body is announced), access log, reload.

## Performance notes (measured, keep current)

- `asio::ssl::stream` encrypts only the first buffer of a buffer sequence per `write_some`,
  so a header+body pair becomes two TLS records and two syscalls. `Connection` coalesces
  header and body prefix into one 16 KB record for TLS (`out_`). Plain sockets use
  scatter-gather with no copy.
- `SSL_MODE_RELEASE_BUFFERS` was measured: no gain, so it is not set.
- On macOS, nginx's plain-HTTP path is slower than its TLS path because it uses `sendfile`
  for small files; do not read that as a TLS anomaly in agensio's numbers.
- First full run (`bench/results/20260915-040303.md`, M1 Pro, 15 s): plain HTTP 1 KB agensio
  126-134k req/s vs nginx 106k vs Caddy 33k. 100 KB and 10 MB plain: parity with nginx
  (bandwidth bound). HTTPS 1 KB: parity. **HTTPS 100 KB and 10 MB: agensio is about 33 %
  behind nginx** (24k vs 36k req/s; 2.35 vs 3.57 GB/s).
- Root cause of the HTTPS gap (by construction, not yet profiled): `asio::ssl::stream` uses a
  BIO pair with a 17 KB buffer, so every 16 KB TLS record costs one async socket write and
  one trip through the event loop plus two memcpys. nginx uses a socket BIO and calls
  `SSL_write` directly until `EAGAIN`. Next perf task: a custom TLS stream that puts the
  non-blocking socket in a socket BIO and uses `socket.async_wait(wait_read/wait_write)` for
  readiness, keeping `SSL_read/SSL_write` on the fd. Expected to close the gap.
- HTTPS p99 (1.8-7 ms vs nginx 0.8-4 ms) likely shares the same cause.
- Cache hit path measured (2026-09-15): cutting the per-hit shared-line traffic from two
  refcount inc/dec pairs plus a `last_access` store down to one pair and a once-per-second
  store changed plain HTTP 1 KB throughput by under 2 % (noise). The hit path is not the
  bottleneck on 10 cores; per-request syscalls (writev, read, kevent) are. Kept the change
  because it is correct and will matter on higher core counts; do not spend more time here
  before profiling with `sample`/`perf`.

## Benchmark protocol (phase 1)

- Same static docroot for every server: 1 KB `index.html`, 100 KB CSS/JS-like file,
  10 MB binary, and a 404 URL.
- `bench/run.sh` runs the servers one at a time on native macOS (brew nginx and caddy), plain
  HTTP and HTTPS with the same self-signed cert (`bench/certs/gen-cert.sh`), docroot from
  `bench/gen-www.sh`. Ports: agensio 8080/8443, nginx 8081/8444, caddy 8082/8445.
  Configs: `bench/agensio.toml`, `bench/nginx.conf`, `bench/Caddyfile`.
- Each server tuned sensibly, not crippled: nginx `worker_processes auto; sendfile on;
  open_file_cache; access_log off`; Caddy default `file_server`, admin and auto-https off.
- Default matrix: `/` (1 KB) and `/style.css` (100 KB) at 64 and 256 connections, `/big.bin`
  (10 MB, above the cache limit, streamed) at 16. Body checksums are verified against disk
  before each measurement. Raw wrk output lands in `bench/results/raw/<stamp>/`.
- Later: Docker Compose on Linux (adds Apache httpd event MPM and `SO_REUSEPORT` numbers),
  30 s runs with three repetitions and medians.
- Verify correctness before speed: responses must be byte-identical in body and carry
  `Content-Length`, `Content-Type`, `Date`, `Last-Modified`, `ETag`.

## Decisions

| Topic | Options | Status |
|---|---|---|
| Config format | TOML via vendored toml++ | decided 2026-09-15 |
| Language standard | C++20 (Debian 12 GCC 12 compatibility; no `std::format`) | decided 2026-09-15 |
| Async style | Asio callbacks with lambdas; coroutines may be measured later | decided 2026-09-15 |
| Threading | one `io_context` per worker; `SO_REUSEPORT` on Linux, shared acceptor elsewhere | decided 2026-09-15 |
| Cache sharing | shared store + lock-free per-worker index of `shared_ptr` entries | decided 2026-09-15 |
| License | MIT | decided 2026-09-15 |
| Benchmark host | native macOS via brew (nginx, caddy, wrk), plain and TLS; Docker/httpd later | decided 2026-09-15 |

## Roadmap

1. Static files + benchmark harness (this phase).
2. TLS via `asio::ssl` + OpenSSL, HTTP/1.1 only.
3. Conditional requests and Range done properly; precompressed (`.gz`, `.br`) variants.
4. FastCGI to php-fpm (this is where ddev becomes useful: run agensio inside a ddev project
   as its web server).
5. Reverse proxy, config reload, access log, HTTP/2.
