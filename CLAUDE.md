# agensio

A very fast, cross-platform web server written in modern C++ on top of standalone
[Asio](https://think-async.com/Asio/) (Christopher Kohlhoff). Successor of
`open-web-server-asio` (2018, Qt + Boost.Asio); see `docs/legacy-analysis.md` for what the
old code did and which ideas carry over.

Phase 1 goal: serve static files fast enough to beat nginx, Apache httpd and Caddy on the
same machine, with the benchmark harness checked in so anyone can reproduce the numbers.

## Status

Pre-alpha `0.1.0-alpha.1` (2026-09-19): phases A-D, E1/E9, F0-F7, H1, H3 done; see
`CHANGELOG.md`. Everything under "Architecture" below is what the code does now, not a
proposal. Before every tag: the suites (unit, integration, reload, pools, control, acme),
the sanitizer and fuzz runs listed in `docs/security-control-plane.md`, and
`bench/ab.sh` against the previous tag.

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
  The gate is `bench/ab.sh <base-ref>` on the Linux box (alternates the base and new
  binaries in one session; noise floor about 3 % on the 1 KB rows at 5 s, 2 rounds):
  every phase checkpoint and every performance-sensitive change gets its A/B there before
  it counts. Proxy code (`src/upstream/http*`, `src/handlers/proxy*`, phase D) is gated
  with `bench/ab.sh <base-ref> -P`, which adds the proxy rows through the benchmark
  upstream (`bench/upstream/`, D0); `bench/proxy/run.sh` is the comparison against nginx
  and Caddy. Linux-only work (kTLS, io_uring, Landlock, FUSE behaviour) is developed there.
  Never trade throughput for convenience on the hot path (no allocations per request that
  the old design avoided, no locks on the cache-hit path, no per-request string formatting
  of constant headers).
- **Correctness bugs of the old code stay fixed**: see `docs/legacy-analysis.md` section 6.
  Do not reintroduce use-after-free on eviction, unbounded request buffers, missing
  timeouts, unnormalised paths, or `delete this` session lifetime.
- Cross-platform: macOS (kqueue) and Linux (epoll) are first-class; Windows should compile
  but is not benchmarked.

## Code rules

`docs/CODE_STYLE.md` is binding: RAII everywhere, raw pointers and references are never
owning, no exceptions on the request path, no per-request allocation on the hot path,
`static_cast` only, one worker's state is never touched by another. Enforced by
`.clang-format` / `.clang-tidy` (`scripts/format.sh`, `scripts/lint.sh`). The agent skills
`cpp-guidelines`, `perf-check` and `security-review-cpp` in `.claude/skills/` are the
checklists to apply when writing, measuring and reviewing.

## Working agreement with the agent

- Discuss before building anything larger than a bug fix: the owner wants to review the
  design first. Small, reviewable steps; one concern per commit.
- Do not add features outside the current phase (see Roadmap) even if they look easy.
- Comments and identifiers in English.
- When a benchmark result is produced, store the raw tool output under `bench/results/`
  with machine, OS, date, commit hash and the exact command.
- Commit only when asked. Commit messages end with the attribution line the harness
  provides.
- **The agent interface is part of every change.** Whenever behaviour, a configuration
  key, a control command, a preset or an error answer is added, fixed or changed, check
  whether the MCP tool descriptions, argument descriptions, server instructions and
  prompts in `src/control/mcp.cpp` still describe the truth, and update them in the same
  change; the JSON the tools relay is not enough, the agent acts on the text. The same
  applies to `agensio ctl` help text and `docs/mcp.md`. Lists that come from tables
  (`app_presets()`) need no edit; prose does.

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
(cd build && cpack -G DEB)                 # the .deb (packaging/, tests/package.sh runs it in the root devbox)
bench/run.sh                               # 5 s per case; -d 15s for publishable numbers
scripts/lint.sh && scripts/format.sh       # clang-tidy / clang-format
cmake -B build-fuzz -DAGENSIO_FUZZ=ON -DAGENSIO_TESTS=OFF -DAGENSIO_TLS=OFF \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ && cmake --build build-fuzz
build-fuzz/fuzz_parser corpus -max_len=4096 -max_total_time=60   # and fuzz_path
```

Source map (`src/`, files move into subdirectories as they are touched, see the roadmap):
- `core/`: `result.hpp` (`Result<T>`, to become `std::expected`), `headers.hpp` (fixed-capacity
  name/value views), `request.hpp`, `response.hpp` (status, prebuilt header block, extra
  fields, `Body`), `body.hpp` (`MemoryBody`, `FileBody`, `StreamBody` for later phases),
  `stream.hpp` (one request/response exchange), `worker_state.hpp`, `strings.hpp`,
  `router.hpp/.cpp` (`Router`: site by Host, then `Router::location`: exact before
  prefix, longest prefix first, implicit `/` last; `try_files` fallbacks re-enter it,
  at most 8 hops).
- `http1/`: `parser` (request head into `Request`), `connection.hpp` (`Http1Connection`,
  the I/O loop: reads, parses, drives one `Stream`, keep-alive/pipelining/timer),
  `writer.hpp` (`Http1Writer`: `Response` to bytes, owns the writev/TLS-coalescing/
  sendfile fast paths and the pull path for `StreamBody`), `chunked.hpp` (chunk framing).
  Both are templates over the plain/TLS socket type.
- `handlers/`: `dispatch` (`Dispatcher`: request prologue, site/location routing, method
  policy; the connection drives the hop loop because handlers may finish asynchronously),
  `static` (`StaticHandler`: cache, files, try_files, policies), `fastcgi` (`FcgiHandler`:
  params from a prebuilt per-location block plus a per-request tail), `proxy`
  (`ProxyHandler`: the forwarded head), `upstream_common` (what both share: error page,
  request body collection in memory / temp file / streamed, upstream result to
  `Response`, failure reasons to both logs).
- `upstream/`: `options.hpp` (address, options, failure reasons), `client` (`UpstreamPool`:
  per-worker, bounded, explicit queue with priority reserve, idle keep-alive
  connections; `UpstreamRequest`: one exchange with connect/send/read timeouts, one
  retry for GET/HEAD on a dead reused connection, request body from memory / spill /
  stream, response buffered with temp-file spill or streamed with a high-water mark),
  `fcgi.hpp` (FastCGI record and params codec, CGI head parser; fuzzed), `fcgi_client`
  (`FcgiRequest`, the FastCGI encoding/decoding), `http_head.hpp` (response head parser;
  fuzzed), `http_client` (`HttpRequest`: HTTP/1.1 framing both ways, keep-alive rules).
- top level, not yet moved: `config`, `path`, `mime`, `http_date`, `file`, `cache`,
  `response` (status lines, error pages), `tls_stream.hpp`, `server`, `main`.
Tests in `tests/tests.cpp`, fuzzers in `tests/fuzz/`.

## Architecture (as implemented)

- **Threading**: N worker threads, each owning its own `asio::io_context` (concurrency hint 1).
  Linux (`reuse_port = "auto"`): every worker has its own acceptor with `SO_REUSEPORT`.
  Otherwise: one acceptor on worker 0 accepts into the workers' contexts round-robin and
  posts `start()`. A connection never leaves its worker: no strands, no locks on the
  per-connection path.
- **Session**: `std::shared_ptr<Connection>` with `enable_shared_from_this`, handlers as
  lambdas capturing `self`. Receive buffer reused across keep-alive requests; hard cap on
  header size (default 16 KB) and an idle timeout (default 15 s) via `asio::steady_timer`.
- **Request core (phase A1)**: the unit of work is a `Stream` (`Request` + `Response`);
  HTTP/1 embeds one per connection. Handlers fill a `Response`: status, an optional
  prebuilt header block (the cache entry's, already terminated), extra `Headers`, and a
  `Body` variant (memory, file, or a `StreamBody` pulled with backpressure in later
  phases). The HTTP/1 writer serialises status line + Server + Date, the block, and the
  extra fields into at most three head buffers plus the body: the same zero-concatenation
  write as before, now behind a protocol-independent interface. A/B against the pre-A1
  binary: identical CPU per request.
- **Parser**: hand-written incremental HTTP/1.1 request parser over `std::string_view`.
  All standard methods are recognised (`Method`); each location carries the `MethodSet`
  its handler implements (static: GET, HEAD, OPTIONS; `methods = [...]` narrows it) and
  the matching `Allow` value, so OPTIONS gets 204 + Allow (also `OPTIONS *`) and anything
  else, TRACE and CONNECT included, gets 405 + Allow. Headers of interest: Host, Connection,
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
  `revalidate_interval` seconds per entry; no filesystem watcher. Files above
  `max_file_size` get a *descriptor entry* (`descriptor_only`: open fd + prebuilt headers,
  no bytes, budget `cache.max_open_files`, default 1024, LRU like bytes but a separate
  budget), so streamed responses skip the per-request open/fstat/realpath (A1b).
- **Response**: prebuilt header fragments; `Date:` refreshed once per second per worker;
  one `async_write` with a `std::array<const_buffer, N>` of header + body. Uncached large
  files stream in 64 KB chunks from an open fd (`sendfile` on Linux later).
- **MIME**: static extension table compiled in (nginx `mime.types` equivalent), overridable
  from config.
- **Config**: TOML (vendored toml++). `[server]`, `[cache]`, `[[site]]` with `server_name`,
  `listen`, `root`, `index`, `try_files`, `tls`, `default`, and `[[site.location]]` blocks
  (`path`, `match = "prefix" | "exact"`, per-location `root` or `alias`/`index`/`try_files`/
  `hidden_files`/`symlinks`/`handler`); `include = ["sites.d/*.toml"]` for
  panel-generated per-site files. Loading never creates sockets; `Server` is built from the
  `Config` struct. `agensio -t` validates.
- **Request bodies** (A3): the HTTP/1 connection is the pull source behind
  `Request::body` (`StreamBody`: `async_read` with backpressure), decoding Content-Length
  or chunked (`http1/chunked.hpp`, fuzzed) from its receive buffer and socket.
  `server.max_body_size` (1 MB) gives 413 up front for a declared length and an error
  mid-stream for chunked; `server.body_timeout` (60 s) bounds the wait between reads;
  `Expect: 100-continue` is answered on the first read, or with `Connection: close` when
  the handler answers without reading. A body the handler did not read is drained after
  the response so keep-alive and pipelining survive. Unknown transfer codings get 501,
  unknown expectations 417. HTTP/2 will feed the same interface from DATA frames.
- **FastCGI** (C1): `handler = "fastcgi"` locations talk to php-fpm over a unix or TCP
  socket. Buffering on by default (whole reply in memory, spilled to an unlinked temp
  file above `buffer_max` and then sent with sendfile, fpm child released at once);
  `buffering = false` streams through a `StreamBody`. Request bodies likewise: memory up
  to `request_buffer_max`, then a temp file, or `request_buffering = false` to stream.
  Per-worker pool per upstream: `max_connections`, `queue_depth`, `queue_wait` (503 +
  Retry-After beyond), `priority_reserve` for `priority = true` locations. `keep_conn`
  (FCGI_KEEP_CONN) is off by default: php-fpm binds a child to every open connection, so
  idle keep-alive connections of N workers pin N children and starve the rest (measured in
  the suite: 24 workers, 4 children, every further request a 504). TCP upstreams get
  TCP_NODELAY, and kept TCP connections TCP_QUICKACK before each read (C3a: php-fpm's
  Nagle plus our delayed ACK stalled every large response by 40 ms). Timeouts give
  504, connection and protocol failures 502, each with an `FcgiFailure` reason in the
  error log (with a fix hint: socket owner/mode vs our uid, SCRIPT_FILENAME, bytes seen
  before a close) and in the JSON access log's `upstream` field. `match = "suffix"`
  locations (`.php`) route scripts anywhere under the root, also with PATH_INFO
  (`/index.php/extra`). `server.trusted_proxies` (CIDRs, `net/cidr.hpp`): from those
  peers X-Forwarded-For (rightmost untrusted hop) and X-Forwarded-Proto set the client
  address for the access log and REMOTE_ADDR / HTTPS / REQUEST_SCHEME for FastCGI.
- **Reverse proxy** (D1, `src/upstream/http_client.*`, `src/handlers/proxy.*`):
  `upstream = "http://host:port"` on a location. The FastCGI and HTTP clients share
  `UpstreamRequest` (`src/upstream/client.*`: pool slot, connect, timeouts, one retry,
  request body from memory / spill / stream, response buffering with spill and the
  streaming pull source); each derived class only encodes its request and decodes its
  response (`FcgiRequest`, `HttpRequest`). The HTTP client frames the body it sends
  (Content-Length or chunked), decodes Content-Length, chunked and close-delimited
  bodies, skips 1xx, and keeps the connection when the origin allows. `ProxyHandler`
  builds the forwarded head (hop-by-hop stripped, Host through, X-Forwarded-For/Proto/
  Host) and `handlers/upstream_common.*` holds what both handlers share (error page,
  body collection, result to Response). Response-head parser in
  `src/upstream/http_head.hpp` (fuzzed). Gate: `bench/ab.sh <ref> -P`. Header policy
  (D2, `proxy = { host, forwarded, headers, hide, redirects }`, site table as defaults):
  Host passed through, X-Forwarded-* replaced from untrusted peers and appended behind
  `trusted_proxies`, RFC 7239 on request, `$`-variables in configured fields, hidden
  response fields, origin-pointing Location rewritten; see `docs/configuration.md` 12.
  Upgrades (D3): the origin's 101 hands its connection to `Http1Connection`, which
  tunnels bytes both ways (`start_tunnel`, two pumps, half-close, idle timer reused with
  `tunnel_timeout`, none by default). Groups (D4): `upstream = [...]`, round-robin and
  passive health per worker in `UpstreamPool` (`pick`, `mark_failure`, `mark_success`),
  next-member retry only when nothing binding was sent (`try_next_address`). TLS to the
  origin (D4b): `BasicTlsStream<Socket>` in client mode inside `UpstreamConnection`,
  contexts cached per pool, `https://` in the pool key, `proxy.tls = { verify,
  server_name, ca }`. CGI (D5, `src/upstream/cgi_client.*`, `src/handlers/cgi.*`): the
  exchange's connect step forks the script with a socketpair as stdin/stdout, so the
  shared exchange code does the rest; processes capped and reaped per worker pool.
- **Presets** (C3): `app = "laravel" | "drupal" | "wordpress" | "php" | "static"` on a site expands
  at load into root, index, try_files and locations (Laravel: only `/index.php` is ever
  executed and any other `.php` is refused with 404, never served as source; Drupal: any
  `.php` runs, front controller for the rest, Drupal's `.htaccess` refusals built in;
  the PHP presets are rows of `kPhpPresets` in `config.cpp` (served subdirectory, index,
  front controller, any `.php` or only one, refused suffixes, shielded directories,
  files answered 404) expanded by one shared routine, so a new application is a row, a
  fixture and a docs section; `/build/` gets an immutable Cache-Control via `add_headers`; WordPress: any
  `.php` runs, `wp-content/uploads` and `wp-includes` are `final` prefix locations, nginx
  `^~`, with `deny_suffixes` so PHP there is 404 and never executed); hand-written
  locations win over the preset's. `agensio -t --explain` prints the effective configuration;
  `docs/configuration.md` documents each preset's expansion and every option (keep it
  current when a key or preset changes);
  `-t` connects to every FastCGI upstream once and warns, with the reason, if it cannot.
- **Laravel test bed** (C4): `bench/laravel/` is a ddev project; `bench/laravel/.ddev/setup.sh`
  creates it, `tests/laravel.sh build/agensio` runs the live checks (skips when the project
  is down). php-fpm inside the web container is published on 127.0.0.1:9000 by the ddev
  override files; `php = { ..., remote_root = "/var/www/html/public" }` rewrites the
  script paths into the container's filesystem; a second pool listens on a unix socket
  in the bind-mounted `.ddev/run/` (Linux hosts, `bench.sh -p unix`). `setup.sh` switches the bed to cookie
  sessions and a file cache: Laravel's default sqlite database sessions serialise every
  request (170 req/s), file sessions leave a file per request and their garbage
  collection triples the PHP cost after tens of thousands. `bench/laravel/bench.sh` is
  the C5 benchmark (agensio vs nginx in front of the same pool). `bench/statamic/` is the same setup for
  Statamic (pool on 9001, agensio on 8071, control panel at http://127.0.0.1:8071/cp,
  login admin@admin.com / 4444; a 429 there is Statamic's login throttle, cleared with
  `ddev exec php please cache:clear` in bench/statamic). `bench/wordpress/` is the same
  for WordPress on `app = "php"` (pool on 9002, agensio on 8072, site
  http://wp.agensio.ddev.site:8072, wp-admin admin / 4444).
- **Per-site users** (C3b-1, `src/services/pools.*`, design in
  `docs/design-per-site-users.md`): `user = "web1"` on a site derives a php-fpm pool
  (socket `<pools_run>/agensio-web1.sock`, state dir, `open_basedir`, sizing from
  `php = { children, pm, ... }`), sets `keep_conn = true` with `max_connections =
  children / workers`, and `agensio pools` writes the pool file into the distro's
  directory (exit 3 when php-fpm needs a reload). Sites of one user share a pool and
  must agree on it; different users never share a socket. `check_hosting` (C3b-2) runs
  the ownership rules (roots, secrets, sockets, logs, nothing shared between users) under
  `-t` and before every start, behind an injectable `HostFacts` so the unit tests describe
  a machine. `server.user` (C3b-3, H2 pulled forward): bind and open logs as root, site
  logs `agensio:<site group> 0640`, then drop privileges. `tests/pools.sh` runs the whole
  thing with two real users in a root devbox (`docker run --user root ... agensio-devbox
  tests/pools.sh build/agensio`).
- **Proxy test beds** (D6): `bench/redmine/` (Rails, `docker compose`, admin / admin,
  agensio on 8075) and `bench/uptime-kuma/` (Node, Socket.IO over WebSockets, agensio on
  8076); `setup.sh` starts each, `tests/redmine.sh` and `tests/uptime-kuma.sh` run the
  live checks and skip when the bed is down. `app = "proxy"` with a site-level `upstream`
  is the preset both use; examples for Node, Rails, Rocket.Chat and ThingsBoard in
  `docs/examples/`.
- **Logging** (A5, `src/services/log.*`): access log in Apache/nginx "combined" format
  (same escaping, so fail2ban filters work) or JSON, per site (`access_log`) with the
  `[log] access` default; one descriptor per path opened `O_APPEND`, per-worker buffers
  flushed at 32 KB or by a 1 s timer, `SIGUSR1` reopens every file (the replaced
  descriptor is kept until the next reopen so a racing worker never writes to a recycled
  fd). Error log (`[log] error`, `level`) to stderr or a file. **On by default**
  (`logs/access.log` next to the config file): measured on Linux, one worker, alternated
  off/on twice, plain 1 KB 2.0 -> 2.0-2.1 us, TLS 1 KB 2.8 -> 2.9-3.0 us, 100 KB rows
  within noise, i.e. 0.1-0.2 us per request, under the 1 us bar the roadmap set. Benchmark
  templates: off, like the nginx and Caddy bench configs.
- **Client abort** (E9): one client read in flight per connection, routed by state; an
  upstream exchange older than a pool tick registers a slow callback and the connection
  arms an EOF watch, so an abandoned request is cancelled (slot freed, CGI process
  killed) instead of executed; nothing is armed for fast exchanges.
- **Range requests** (E1, `src/http1/range.hpp`): one `bytes=` range with If-Range; 206
  as a slice of the cache entry or a `FileBody` with an offset (sendfile keeps the fast
  path), 416 past the end, `Accept-Ranges: bytes` prebuilt into the entry block.
- **Reload** (H1): `Generation` = config + routers + TLS contexts; per-worker current
  pointer, per-connection pointer refreshed at each request boundary (one compare);
  `Server::reload` on SIGHUP validates, binds new listeners, then switches; in-flight
  work keeps the old generation alive. `agensio reload` validates and signals
  `server.pid_file`. `tests/reload.sh` proves no request fails across reloads.
- **Automatic certificates** (H3, `src/services/acme.*`, `services/json.hpp`): `tls = "auto"`
  plus `[server] acme = { email }`; ACME v2 with HTTP-01 against any RFC 8555 CA, JWS ES256
  and CSRs through OpenSSL. Placeholder certificate at start, order at once, challenge
  answered by the dispatcher before routing, new certificate swapped in through
  `Server::reload`, hourly renewal check on worker 0 (renew at a third of the lifetime
  left), the network work blocking on the manager's own thread. `tests/acme.sh` runs 17
  checks against Pebble (`bench/acme/docker-compose.yml`, `docker compose` needed).
- **Control socket** (F0/F1, `src/control/`): `[control]` enables a unix socket served by
  `Http1Connection<local socket>` on worker 0 through a synthetic site of kind `control`;
  peer credentials and groups decide the role at accept (`roles.hpp`, root and
  `server.user` admin; `admins`/`operators`/`viewers` groups), refusals and mutations go
  to the audit log, `agensio ctl status` and the future MCP bridge use `control/client.*`.
  `tests/control.sh` runs the role matrix as root in the devbox. Read commands (F2,
  `control/commands.*`): `sites`, `site NAME`, `validate`, `logs` (three log formats parsed
  by hand, files read backwards with caps), `health` (findings with a fix each); all GET,
  viewer role, pure functions over the Config so the unit tests cover them. Mutations
  (F3, `control/sites.*`): POST with `confirm`, audited; `site-create` answers a decision
  form (422) and root prerequisites as commands (409, `waiting`), writes managed
  `sites.d/<domain>.toml` files (spec JSON on line 1), validates through `reload` and
  undoes a refused change; also update/disable/enable/delete, `reload`, `cert-renew`.
  Provisioning helper (F8, `services/provision.*`): a root child forked before the
  privilege drop, socketpair only, five re-validated operations (account, site layout
  with an `O_NOFOLLOW` walk, log ownership, pools + php-fpm reload, rate-limited restart),
  execve by absolute path without a shell; `site-create` applies a problem's `fix`
  through it and reports `done`; `[control] provision = false` hands commands back
  instead. Its threat analysis is in `docs/security-control-plane.md`; every change to it
  updates that section. `tests/provision.sh` runs it as root in the devbox.
  `agensio mcp` (F5, `control/mcp.*`): stdio JSON-RPC MCP server, 15 tools with
  annotations gated by the caller's role, prompts, meant to be spawned over SSH by the
  agent host (`docs/mcp.md`). `agensio ctl` (F6) is the same client for shells.
- **Not yet**: directory listing, TLS-ALPN-01 / DNS-01 (wildcards), OCSP stapling.

## Performance notes (measured, keep current)

Measure **server CPU microseconds per request** (`ps -o cputime` delta divided by wrk's
request count), not only req/s: wrk shares the cores with the server, so req/s hides
CPU efficiency. Numbers below are M1 Pro, 64 connections, 10 s, 2026-09-15.

| case | agensio | nginx 1.31 |
|---|---|---|
| HTTPS 1 KB | 21.8 us | 21.0 us |
| HTTPS 100 KB | 88.5 us | 92.6 us |
| HTTP 1 KB | 18.5 us | 27.1 us (nginx uses sendfile even for small files; slow on macOS) |
| HTTP 10 MB stream | 1.18 ms | 1.21 ms |
| HTTPS 10 MB stream | 10.0 ms | 9.6 ms (AES dominates) |

Latency-bound check (wrk with 2 threads so it cannot starve the server): HTTPS 1 KB
agensio 140.5k req/s at p50 308 us, nginx 140.0k at 320 us. Any remaining gap in the
10-thread runs is CPU competition with wrk, i.e. CPU per request.

Single worker vs single nginx worker process (`bench/results/20260915-single-worker.md`,
one core saturated, so us/req is exact): HTTP 1 KB 7.8 vs 11.6 us, HTTPS 1 KB 9.3 vs 12.6,
HTTPS 100 KB 55.5 vs 67.8, HTTP 100 KB 19.8 vs 18.9 (nginx's sendfile from the page cache
beats our 100 KB memory copy; only row nginx wins). One agensio worker does 128k plain
1 KB req/s, the same as ten workers: multi-worker runs on this laptop are wrk-bound.

Full single-worker run with tuned nginx (`bench/results/20260915-110001.md`, wrk 4
threads): agensio vs nginx req/s: HTTP 1 KB 127k vs 82k, HTTPS 1 KB 107k vs 77k, HTTPS
100 KB 17.9k vs 13.7k, HTTPS 10 MB 182 vs 151, HTTP 10 MB 755 vs 723; HTTP 100 KB 48.0k vs
50.7k was the only loss before item 8 above (sendfile for cached entries >= 48 KB) closed it.

One agensio worker vs nginx `worker_processes auto` (10) and Caddy on all cores
(`bench/results/20260915-114007.md`, wrk 4 threads, CPU us/req = server CPU time over all its
processes / requests): agensio 1 core does 127-132k plain 1 KB req/s at 7.5 us and 7-11 MB
RSS; nginx on 10 cores 112-114k at 27-29 us and 27-103 MB; Caddy 34k at 229 us. Plain
100 KB: 51-54k vs 53-54k (nginx) at 18 vs 39 us. HTTPS 1 KB: 100-104k (1 core, 9.5-9.9 us)
vs nginx 138-143k (10 cores, 18-24 us). HTTPS 100 KB: 16k at 62 us vs 35-37k at 97-106 us.
Streams (10 MB): agensio's single core caps at 760 plain / 160 TLS req/s; nginx and Caddy
win those rows only by using more cores (their CPU per response is 1.4-1.8x higher).
Conclusion: per request agensio costs 2.5-3.5x less CPU than nginx and 20-30x less than
Caddy, and a single worker beats ten nginx workers on plain HTTP; nginx only pulls ahead on
TLS by spending 10 cores. `bench/run.sh` prints the CPU and RSS columns by default now.

Linux container run (`bench/docker/`, Colima VM 4 vCPUs, `bench/results/docker-*.md`):
agensio one worker 238-242k plain 1 KB req/s at 4.1 us, HTTPS 154k at 6.5 us, 100 KB 90k
at 11 us; nginx 130k / 91k / 70k; OpenLiteSpeed 93k / 79k / 9.5k; Caddy 3.4k (GOMAXPROCS=1
pinned to one CPU cripples the Go runtime; not a fair row). Two lessons from that run:
- **Inline completions need a yield budget** (see item 1): the first Linux run timed out
  all 256 HTTPS connections; `kInlineBudget` fixed it.
- **Opening the streamed file per request is expensive on FUSE/network filesystems**: on the
  virtiofs bind mount a 10 MB stream cost 2.8 ms and 218 req/s against nginx's 850, because
  every open invalidates the FUSE page cache; from a container-local ext4 docroot agensio does
  801 req/s at 438 us, nginx 784 at 428 (parity). `sendfile_max_chunk` (1 MB, kept) and
  TCP_CORK around sendfile (kept, nginx's tcp_nopush) were measured on that path: no change.
  The fix is the descriptor cache for streamed files, roadmap A1b, which also matters for
  NFS-backed docroots in hosting.
- Docker's CPU on macOS shows under `com.apple.Virtualization.VirtualMachine` in Activity
  Monitor (231 % of a core during a run), not under docker or colima.

Native Linux run, 2026-09-16 (AMD Ryzen 9 9900X, 12 cores/24 threads, Debian 13 trixie, kernel
6.12.107, GCC 14.2, nginx 1.26.3, Caddy 2.11.4, wrk 4.1 epoll; `bench/results/20260916-1951*`
to `1958*.md` and `docker-20260916-230123.md`). The doc steps ran inside a `debian:trixie`
container with the repo bind-mounted, because the host has other services on ports 8080-8082
and no sudo; Docker shares the kernel, so these are native numbers (loopback, no VM). Stamps
in the native file names are UTC. Single worker each, wrk 4 threads, 5 s, agensio vs nginx CPU
us/req: HTTP 1 KB 1.9-2.0 vs 3.0 (518k vs 329k req/s), HTTP 100 KB 5.5 vs 5.8-5.9 (183k vs
171k), HTTP 10 MB stream 323 vs 302 (3.1k vs 3.3k, nginx's only win), HTTPS 1 KB 2.7-2.8 vs
4.3-4.4 (354-367k vs 229-235k), HTTPS 100 KB 19.7 vs 25 (50.8k vs 39-40k), HTTPS 10 MB 1994
vs 2268 (501 vs 441). Caddy one worker: 17-20 us plain, 44-48 us HTTPS 100 KB, 55k req/s.
Multi-worker with `SO_REUSEPORT` (first time on Linux) works with no errors or timeouts:
plain 1 KB 946-967k req/s at 2.0-2.1 us with 2 workers and 1.43-1.47M at 2.6-2.7 us with 4
(nginx 612k at 3.2-3.3 and 1.0M at 3.9-4.0); HTTPS 1 KB 4 workers 0.98-1.03M vs 738-780k.
Per-request CPU rises with worker count for both servers (cross-core cache traffic on
loopback, not investigated). One agensio worker vs nginx `auto` (24) and Caddy on all cores:
agensio 495-515k plain 1 KB at 2.0 us and 12-15 MB RSS, nginx 1.25-1.27M at 4.9-5.0 us and
247 MB, Caddy 331-354k at 50 us; HTTPS 1 KB 352-356k (2.8 us) vs nginx 781-821k (5.1-5.2 us,
wrk-bound). Container run (`bench/docker/run.sh`, servers pinned to CPU 0, wrk 2 threads on
CPUs 1-3, adds OpenLiteSpeed): plain 1 KB agensio 337k at 2.9 us, nginx 232k at 4.3, OLS
200k at 4.9, Caddy 48k at 20; HTTPS 1 KB 240k/4.2 vs 170k/5.8 vs OLS 150k/6.6; HTTPS 100 KB
is the one row OLS wins (27.3k at 36.7 us vs agensio 20.8k at 47.6, nginx 19.7k at 49.7) and
HTTPS 10 MB too (OLS 324 req/s, nginx 248, agensio 204: the TLS copy path, kTLS is the fix).
Linux differences from macOS: (1) **agensio died with SIGPIPE** (exit 141) the moment wrk
closed its HTTPS connections, in every run: OpenSSL's socket BIO in `TlsStream` and our
`sendfile()` write to the descriptor without `MSG_NOSIGNAL`, and macOS hides this because
Asio sets `SO_NOSIGPIPE` there. `Server::run` now ignores SIGPIPE; peers that vanish surface
as EPIPE and close the connection. Sanitizer build (unit, integration, HTTPS load) and both
fuzzers (2 min each, 41.9M and 13.0M runs) reported nothing else. (2) Linux costs about 4x
less CPU per plain 1 KB request than macOS (1.9 vs 7.5 us) and nginx's sendfile is cheap
here (3.0 us vs 11.6 on macOS), so the agensio advantage is 1.5x on plain and 1.3-1.6x on
TLS instead of 2.5-3.5x. (3) The plain 10 MB stream is the only case where nginx is ahead
(302 vs 323 us; parity on macOS). (4) nginx's plain 100 KB p99 was 39-43 ms with one worker
(p50 235 us); not seen for agensio. (5) `bench/docker/run.sh` printed decimal commas under
the Greek host locale; it now pins `LC_NUMERIC=C` like `bench/run.sh`.

Laravel through FastCGI (C5, `bench/results/laravel-20260917-100530.md`, same Linux box,
one worker each, the bed's php-fpm pool with 8 static children through docker-proxy): both
servers are application-bound at 3.4k req/s on the 78 KB welcome page and 3.5k on a JSON
route (2.2 ms of PHP per request); the web server's own CPU per request is agensio 85-86 us
vs nginx 110-111 us on the page and 54-55 vs 58-59 us on JSON. Most of that is the TCP
connection opened to php-fpm per request: `keep_conn = true` with `max_connections` at the
child count halves it (26.6 us on JSON). The 78 KB page collapsing under keep-alive on
TCP (1.05k req/s, p50 59 ms even without docker-proxy) was Nagle on php-fpm's side
meeting our delayed ACK; `FcgiRequest::quick_ack` (TCP_QUICKACK before each read on a
kept TCP connection, plus TCP_NODELAY on the upstream socket) restores 3.75k req/s
(`bench/results/laravel-keepconn-20260917.md`). Transport matters more than keep-alive:
the bind-mounted unix socket alone is 51 / 26 us (nginx 74 / 31), keep-alive on top 45 /
25. Through docker-proxy keep-alive stays broken (the ACK delay is inside the container)
and fresh connections to the container IP cost 150-500 us in conntrack: benchmark PHP
over the unix socket. php-fpm CPU is read from the container's cgroup
because the children respawn. Two bed findings that would wreck any PHP benchmark: sqlite
database sessions (Laravel's default) serialise requests, file sessions grow a directory
the garbage collector then scans; cookie sessions are stable. And wrk ends a run by
dropping its connections with requests still queued for php-fpm, which agensio only
notices when it writes the response (roadmap E9): wait 2 s between runs.

Reverse proxy (D1, `bench/results/proxy-20260917-181006.md`, one worker each in front of
the D0 upstream which alone does 500k req/s at 2 us): JSON at 64 connections agensio 201k
req/s at 4.98 us per request vs nginx 176k at 5.70 (13 % less CPU), at 16 connections 5.01
vs 5.54; 100 KB body agensio 56k at 17.7 us vs nginx 31k at 32.6 (46 % less); a 20 ms
application at 256 connections 7.5 vs 8.3 us; both reuse upstream connections (1 per run).
Caddy: 40k at 25 us. How it got there, by syscall count (strace -c under wrk, in the
`agensio-devbox-perf` image which adds perf, valgrind and strace; run it with
`--cap-add SYS_ADMIN --cap-add PERFMON --user root` for perf): the static path makes 2
syscalls per request (recvfrom, sendmsg); the first proxy made 7. Two `timerfd_settime`
came from arming an Asio steady_timer per exchange phase: with 64 exchanges in flight the
completing one is always the earliest timer, so every cancel and re-arm reprogrammed the
reactor's timerfd. The pool now runs one 250 ms tick that checks each exchange's recorded
deadline, the same lazy pattern as the connection's idle timer, and no exchange owns a
timer. One `epoll_ctl` came from an `async_wait` for readiness, which asio implements by
re-arming the edge-triggered descriptor; a speculative recv that returns EAGAIN costs the
same, so the simpler read stays. Upstream completions are bound to the immediate executor
like the connection's own (posting them cost a loop trip per step). TCP_QUICKACK is set
only while a body is still arriving (the C3a stall needs a multi-segment response). Result:
4 syscalls per proxied request, the minimum, 6.98 -> 4.98 us. The gate for proxy code is
`bench/ab.sh <ref> -P` (adds the proxy rows; a base that does not proxy gets none).

Behind a real origin (D7): a single Node.js hello-world process tops out at 156-160k
req/s, so with it both proxies sit at the origin's limit and the row measures what each
makes the origin parse. Sending the same fields (Host, X-Forwarded-For, X-Forwarded-Proto)
they tie, nginx 155-157k and agensio 153-158k, agensio at 5-6 % less CPU of its own
(`bench/proxy/run.sh -o node`, `proxy-20260917-210504.md`); forwarding nothing puts agensio
at 164-168k vs 159-164k. Rule learned: every field forwarded costs the origin about 2-3 %
on a hello-world, so agensio sends no `Connection: keep-alive` on kept connections
(HTTP/1.1 is persistent) and `X-Forwarded-Host` only when Host was rewritten or a proxy in
front set it (otherwise it repeats Host). WebSocket-shaped echo through 64 tunnels
(`bench/proxy/ws.sh`, `proxy-ws-20260917-204524.md`): nginx 3.75 us and agensio 3.80 us
of CPU per 1 KB message crossing the proxy twice, parity; the Python load generator
bounds the rate at about 137k msg/s.

Benchmark hygiene: `pkill -x nginx` does not kill nginx (it retitles its processes); a
stale instance keeps the ports and silently serves the next run. `bench/run.sh` now
refuses to start when a port is busy; kill with `pkill -f 'nginx: '`.

What got us there, in order of impact:

1. **Inline completions (biggest win, ~30 %).** Every handler asio *posts* makes the
   scheduler run a non-blocking `kevent` poll before executing it, so a request cost three
   kevent calls instead of one. `Connection` and `TlsStream` bind an immediate executor
   (`asio::bind_immediate_executor(worker.ctx.get_executor(), h)`) so speculative
   completions run inline; `TlsStream::complete` calls the handler directly. Keep every
   new handler on the hot path wrapped in `immediate(...)`. **But bound it**: a connection
   whose client answers instantly can chain request after request inline and starve every
   other connection on the worker (seen on Linux loopback as 2 s timeouts on all 256
   connections). `Connection::finish_response` yields to the loop with `asio::post` every
   `kInlineBudget` (8) responses; measured cost on macOS: none.
2. **Own TLS stream (`src/tls_stream.hpp`) instead of `asio::ssl::stream`.** Writes go
   through a socket BIO: one `SSL_write` pushes all records with back-to-back `send()`
   until EAGAIN. `asio::ssl::stream` uses a 17 KB BIO pair, costing one async write and
   one event-loop trip per 16 KB record (100 KB HTTPS went from 24k to 32k req/s on this
   alone). Reads use the socket's speculative `async_read_some` into a staging buffer that
   a custom zero-copy BIO feeds to OpenSSL; `socket.async_wait()` was rejected because
   asio re-registers the kevent filter on every non-speculative op.
3. `SSL_set_read_ahead(1)` (one read per record), no `ERR_clear_error()` before each call
   (only after an error), `SSL_MODE_RELEASE_BUFFERS` not set (measured: no gain).
4. Header + body prefix coalesced into one 16 KB record for TLS (`Connection::out_`).
5. **sendfile for streamed files on plain sockets** (`Connection::sendfile_step`,
   `send_file` in `file.cpp`; macOS, Linux, FreeBSD). The pread + send path copied every
   byte twice and cost 2.22 ms CPU per 10 MB; sendfile costs 1.18 ms. Chunk size on the
   copy path was measured to make no difference (64 KB vs 256 KB). `server.sendfile = false`
   switches it off. TLS still uses the copy path (kTLS would fix that on Linux).
6. One `steady_clock::now()` per response, not per read: clock reads were 7 % of user time.
8. **sendfile for cached entries on plain sockets** (`cache.sendfile_min_size`, default
   48 KB): the entry keeps its descriptor open and the kernel sends from the page cache,
   headers attached to the same `sendfile` call on macOS/FreeBSD (Linux: writev then
   sendfile). Measured single-worker CPU per request, memory copy vs sendfile: 8 KB 8.2 vs
   10.6-11.3 us, 32 KB 10.6 vs 13.2 us, 64 KB 16.2-17.0 vs 14.7 us, 100 KB 20.0-21.7 vs
   17.6-18.7 us. Crossover about 48 KB; below it the per-call cost of sendfile exceeds the
   copy (which is why nginx, sendfile for everything, does 82k req/s on 1 KB where we do
   128k). The open-file soft limit is raised to the hard limit at startup for this.
7. **Header assembly** (`tests/bench_header.cpp`, run `build/agensio_bench_header`): the old
   server's 11-append concatenation costs 67 ns per header, the prebuilt-entry-block
   version 33 ns, the current zero-concatenation path 4 ns (per-worker cached
   "status + Server + Date" prefix refreshed once per second, the entry's terminated
   header block borrowed, static tail, one writev of up to 4 buffers). End-to-end effect:
   none measurable (a header is <0.5 % of the 18 us a request costs). Kept because it is
   simpler on the hot path, but header building is not where time goes any more.

The remaining 4 % CPU gap to nginx on HTTPS 1 KB is one extra syscall per request: asio's
reactor tries a speculative `recv` (EAGAIN) after every response before waiting in
kevent; nginx knows from the kqueue event that nothing is readable. asio cannot avoid it
without patching the reactor (`socket.async_wait` re-registers the filter instead, same
cost). Accepted.

Things measured with no effect (do not retry without new evidence): cache hit-path
refcount and `last_access` traffic (under 2 %), `SSL_MODE_RELEASE_BUFFERS`, streaming
chunk size, memory-BIO reads.

How to profile on macOS: `sample <pid> 5 -file out.txt` while wrk runs, then read the
"Sort by top of stack" section at the end for self time; `kevent` there is blocked time,
not CPU. CPU per request: `ps -o cputime= -p <pid>` before and after a wrk run (sum over
nginx's worker processes with `pgrep -f nginx`).

Open: HTTPS p99 is noisier than nginx at 256 connections (run-to-run 5-25 ms); likely
CPU contention with wrk on the same 10 cores. Check on a Linux box with a separate load
generator before touching code. kTLS (Linux, `SSL_OP_ENABLE_KTLS`) is the next lever
there: it would allow `sendfile` for streamed files over TLS.

## Security hardening (2026-09-16, measured: no cost)

Each item was benchmarked before and after on the reduced matrix (`bench/run.sh -s agensio
-w 1 -t 4 -u "/:256" -u "/style.css:256"`); CPU per request stayed at 7.5-7.6 / 17.6-18.0 /
9.3-9.6 / 56.6-57.7 us throughout (noise band about 3 %).

1. **Request smuggling / field syntax** (`http_parser.cpp`, 17 unit tests, 3 live checks):
   400 and close for Content-Length together with Transfer-Encoding, duplicate
   Content-Length with different values, Content-Length lists or more than 19 digits,
   Transfer-Encoding on HTTP/1.0, duplicate Host, Host with whitespace or delimiters,
   obs-fold continuation lines, bare CR inside a line, control characters in values,
   non-token characters in names; 431 and close above 100 header fields. Since A3 an
   announced body is consumed by the connection's own decoders (exact Content-Length
   count, chunked state machine), so the boundary to a pipelined request is the framing's
   and never a guess; a declared length above `max_body_size` gets 413 and close.
2. **Path policies** (`handler.cpp`, `path.cpp`): `hidden_files = false` per site (default)
   answers 404 for any dot-segment (`.env`, `.git/`); `symlinks = "deny"` checks the
   realpath stays under the root on each cache miss (default `allow`, like nginx, because
   Laravel's `public/storage` link points outside `public/`); Windows path rules
   (`windows_path_ok`: backslash, `:`/ADS, trailing dot or space, reserved device names)
   applied on Windows and unit-tested everywhere.
3. **Memory safety**: `AGENSIO_HARDEN=ON` (default) adds `-fstack-protector-strong`,
   `-ftrivial-auto-var-init=zero`, `_FORTIFY_SOURCE=2`, hardened libc++ fast mode /
   `_GLIBCXX_ASSERTIONS` (bounds-checked `[]`), RELRO + PIE on Linux, `/GS /guard:cf` on
   MSVC. `AGENSIO_SANITIZE=address,undefined` builds everything with sanitizers.
   `AGENSIO_FUZZ=ON` builds libFuzzer targets (`tests/fuzz/`, brew clang): parser and path
   normaliser ran 16M and 5.7M inputs under ASan+UBSan with no findings. Also fixed: a
   theoretical zero-length-read spin in `TlsStream` when the staging buffer is full, and
   the accept loop now pauses 100 ms on EMFILE/ENFILE instead of spinning at 100 % CPU.
4. **Keep-alive request cap**: `server.max_requests_per_connection` (default 1000, nginx's
   default; 1M in the benchmark template for parity) sends `Connection: close` on the last
   allowed response.

Still to do (roadmap phases E and H): per-IP connection and rate limits, request-body
limits and timeouts once bodies exist, security response headers option (HSTS,
nosniff), TLS ticket key rotation and OCSP, access log with fail2ban-friendly format,
privilege drop, fuzz targets for every new parser (chunked, FastCGI), h1 compliance suite.

## Benchmark protocol (phase 1)

- Same static docroot for every server: 1 KB `index.html`, 100 KB CSS/JS-like file,
  10 MB binary, and a 404 URL.
- `bench/run.sh` runs the servers one at a time on native macOS (brew nginx and caddy), plain
  HTTP and HTTPS with the same self-signed cert (`bench/certs/gen-cert.sh`), docroot from
  `bench/gen-www.sh`. Ports: agensio 8080/8443, nginx 8081/8444, caddy 8082/8445.
- **Single worker by default** (`-w 1`): agensio `workers`, nginx `worker_processes`, Caddy
  `GOMAXPROCS` all get the same count, and wrk runs with 4 threads (`-t`). Workers plus wrk
  threads must stay well under the core count, otherwise wrk steals CPU from the server
  and the run measures the load generator. Configs are generated per run from the
  templates `bench/agensio.toml` and `bench/nginx.conf` (`@WORKERS@`, `@BENCH@`) into
  `bench/tmp/`; `bench/Caddyfile` is used as is.
- nginx is tuned for static files, not crippled: sendfile, tcp_nopush, open_file_cache
  valid 60 s, keepalive_requests 1M, multi_accept, backlog 4096, session cache and tickets,
  access_log off. Caddy: default `file_server`, admin and auto-https off. Note that Caddy
  with GOMAXPROCS=1 still uses extra OS threads for blocking syscalls, so it is not strictly
  one core; it wins the plain 10 MB stream that way.
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

See `docs/ROADMAP.md`, lettered in execution order (renumbered 2026-09-17): A core refactor
(streams, bodies, router; A1-A3 done), B methods beyond GET/HEAD, C PHP/FastCGI (Laravel,
Statamic, WordPress), D reverse proxy (WebSocket, CGI; Rails, Node, Python, Java, Go apps),
E rest of HTTP/1.1 and hardening, F control API and agentic/MCP, G HTTP/2 via nghttp2,
H production hardening, I HTTP/3 via ngtcp2+nghttp3. Real applications come before Range,
compression and the control API so the body model, router and upstream design are validated
first; section 6 of the roadmap lists the application matrix. One step at a time, each gated
by an A/B on the Debian machine and the tests.
