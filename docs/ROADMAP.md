# agensio roadmap

The goal: a super fast, lightweight web server that serves most sites on **one worker
thread**, gentle on VPS CPU and memory, and scales to more workers when asked. Every
feature below is added one at a time, benchmarked when it lands, and must not slow down
what already exists. Architecture rule: protocols, upstreams and services plug into one
request core; nothing pays for a feature it does not use.

Status legend: `[ ]` todo, `[~]` in progress, `[x]` done. Each phase ends with a
benchmark checkpoint recorded in `bench/results/` and a note in `CLAUDE.md`.

---

## 0. Where we are

`[x]` Phase 1 (static files) is done: HTTP/1.1 GET/HEAD, keep-alive, pipelining, conditional
requests, in-memory cache + sendfile, TLS with our own stream, TOML config, benchmark
harness. One worker beats ten nginx workers on plain HTTP; per request agensio uses 2.5-3.5x
less CPU than nginx (`bench/results/20260915-114007.md`).

Current source map (`src/`): `server` (workers, listeners, accept), `connection.hpp`
(one class: reads, parses, writes; HTTP/1.1 only), `handler` (request -> ResponsePlan),
`http_parser`, `path`, `cache`, `tls_stream.hpp`, `file`, `mime`, `http_date`,
`response`, `config`, `main`.

---

## 1. Target architecture

```
                 +-----------------------------------------------------------+
   listeners     |  TCP (plain)   TCP + TlsStream (ALPN: h2, http/1.1)   UDP (QUIC)  |
                 +------+-----------------+-------------------------+--------+
                        |                 |                         |
   protocol       Http1Connection    Http2Connection          Http3Connection
   connections    (1 stream at a time)  (nghttp2 session)    (ngtcp2 + nghttp3)
                        \                |                         /
                         \               v                        /
                          +---------> Stream <--------------------+
                                      | Request  (method, target, headers, body source)
                                      | Response (status, headers, body source)
                                      v
   request core                    Router  (site by Host/SNI -> location -> handler)
                                      |
              +-----------+-----------+-----------+-----------+------------+
              v           v           v           v           v            v
   handlers  Static    FastCGI     Proxy      CGI        Redirect     Control API
             (cache,   (php-fpm)   (HTTP/1.1  (process)  (301/302)    (agentic, JSON
              sendfile)             upstream,                          and text answers)
                                    WebSocket)
              |           |           |           |
   upstreams  file     FcgiClient   HttpClient   ProcessRunner        (per worker,
                       pool        pool          (pipes)              pooled, async)

   services (per process): Config + reload, TLS contexts (SNI, cert reload), Cache,
                           Logging, Metrics, Control socket
   per worker:             io_context, LocalIndex, DateCache, upstream pools
```

Design decisions that make "no protocol pays for another" true:

- **Stream is the unit of work**, not Connection. HTTP/1.1 embeds exactly one Stream in its
  connection (no multiplexing machinery, no extra allocation). HTTP/2 and HTTP/3 own many
  Streams keyed by stream id. The router and every handler see only a Stream.
- **Bodies are sources with backpressure**, both directions. A `BodySource` yields chunks
  on demand (`async_read(chunk, handler)`) and can say "done". Implementations: memory
  (cache entry, static string), file (sendfile or pread), upstream socket, process pipe,
  chunked/framed decoders for request bodies. The connection pulls from the response
  source at the pace the client accepts; an upstream is only read when there is room.
- **Headers are a small flat structure** (vector of name/value views into a per-stream
  arena), shared by all protocols; HPACK/QPACK decode into it, HTTP/1 parses into it.
- **One worker by default**; everything per-worker is lock-free (pools, caches indexes,
  date). Shared state (cache store, config, TLS contexts) is read-mostly with the
  patterns already used. More workers = more of the same, SO_REUSEPORT on Linux.
- **Protocol libraries are allowed** where writing them ourselves would be a project of
  its own: nghttp2 (HTTP/2 framing + HPACK), ngtcp2 + nghttp3 (QUIC + HTTP/3). Both are C,
  callback-driven, own no sockets, and slot into our loop. Everything else stays standard
  library + Asio. (Open question 1 below.)

Target source layout:

```
src/core/        stream.hpp, request.hpp, response.hpp, body_source.hpp, headers.hpp, router.*
src/http1/       parser.*, connection.hpp, chunked.*
src/http2/       connection.hpp (nghttp2 glue)
src/http3/       listener.*, connection.hpp (ngtcp2 + nghttp3 glue)
src/handlers/    static.*, fastcgi.*, proxy.*, cgi.*, redirect.*, control.*
src/upstream/    fcgi_client.*, http_client.*, process.*, pool.hpp
src/services/    config.*, tls.*, cache.*, log.*, metrics.*, control_socket.*
src/net/         tls_stream.hpp, file.*, sendfile
src/main.cpp
```

---

## 2. Phases and steps


**Order (renumbered 2026-09-17 so the letters follow execution):** A core, B methods,
C PHP, D proxy, E rest of HTTP/1.1 and hardening, F control API and agentic, G HTTP/2,
H production hardening, I HTTP/3. Real
applications (Laravel, Statamic, WordPress through FastCGI; Rails, Node and others through
the proxy) test the architecture's central bets, the pull-based body model in both
directions, the stream as unit of work, the router and per-site configuration, upstream
backpressure and buffering, before more code is built on them. Range and compression are
body transformations and are designed against real producers; the control API generates
site presets and is built after those presets exist. See section 6 for the application
matrix. (Earlier documents and commits before 2026-09-17 used the previous lettering:
old B2-B9 are now E1-E8, old C is F, old D is C, old E is D, old F is G, old G is H, old H is I.)

### Phase A. Core refactor: streams, bodies, router  `[ ]`
Prerequisite for everything else. No new features; the static path must benchmark the
same after it (that is the checkpoint).

- [x] A1 (2026-09-17) `Stream`, `Request`, `Response`, `Headers`, `Body` (`MemoryBody`,
      `FileBody`, `StreamBody` interface), `Result<T>`, `WorkerState` in `src/core/`; parser
      in `src/http1/`, static handler in `src/handlers/` producing a `Response`; the HTTP/1
      connection serialises it. A/B vs the pre-A1 binary: equal CPU per request on all
      four rows. Files moved as touched.
- [x] A1b (2026-09-17) Descriptor cache for streamed files: entries above `max_file_size`
      hold an open fd and the prebuilt headers, no bytes (`CacheEntry::descriptor_only`,
      budget `cache.max_open_files`), so a 10 MB stream no longer costs an `openat` +
      `fstat` + `close` (+ `realpath` with `symlinks = "deny"`) per request (measured on
      Linux/virtiofs: 467 us per open, 8 % of the response; on local ext4 about 1 us, within
      noise). nginx's `open_file_cache` equivalent. A/B on Linux: see the commit.
- [x] A2 (2026-09-17) `Connection` split into `Http1Connection` (`src/http1/connection.hpp`:
      I/O loop, parser, keep-alive, pipelining, idle timer, inline budget; drives one
      `Stream`) and `Http1Writer` (`src/http1/writer.hpp`: `Response` to bytes; the writev /
      TLS-coalescing / sendfile paths unchanged, plus the pull path for `StreamBody` with
      Content-Length, chunked or close-delimited framing, `src/http1/chunked.hpp`). The
      `StreamBody` path is exercised end to end from A3/C1 on; only the framing has unit
      tests today. A/B on Linux: see the commit.
- [x] A3 (2026-09-17) Request bodies: `Request::body` is a `StreamBody` pull source the
      HTTP/1 connection implements (Content-Length and chunked decoders,
      `http1/chunked.hpp`, fuzzed with `fuzz_chunked`); `server.max_body_size` (413 up
      front, error mid-stream for chunked), `server.body_timeout`, `Expect: 100-continue`
      (100 sent on first read; `Connection: close` when answered unread), unread bodies
      drained after the response, 501 for other transfer codings, 417 for other
      expectations. No handler reads a body yet (B1/C1); the drain path exercises the
      decoders end to end in `tests/integration.sh`. A/B on Linux: see the commit.
- [x] A4 (2026-09-17) `Router` (`src/core/router.*`): site by Host, then
      `[[site.location]]` blocks (`path`, `match = "prefix" | "exact"`; regex later) with
      per-location `root` or `alias`, `index`, `try_files`, `hidden_files`, `symlinks`, `handler`
      (static only until C). Exact before prefix, longest prefix first, implicit `/` from
      the site's settings. `try_files`: `$uri`, `$uri/`, `=403`/`=404`, `/fallback`
      (internal redirect routed again, 8 hops max). Cache keys are location + path. A/B on
      Linux: see the commit.
- [x] A5 (2026-09-17) Access and error logs (`src/services/log.*`): "combined" (byte-
      compatible with nginx/Apache, fail2ban filters unchanged) or JSON, per site
      (`access_log`) with a `[log] access` default, per-worker buffers flushed at 32 KB
      or each second, `SIGUSR1` reopens every file (`ctl reopen` comes with F). Error log
      to stderr or a file with `level`. Benchmark templates off. Measured on Linux (one
      worker, off/on alternated twice): 0.1-0.2 us per request, so the default is **on**
      (`logs/access.log` next to the config file).
- [x] Checkpoint (2026-09-17): every step A1-A5 was gated by `bench/ab.sh` on Linux, CPU
      per request equal within noise on all six rows; unit tests cover the chunked decoder,
      the router, try_files, the config schema and the log formatters.

### Phase B. Methods beyond GET/HEAD  `[ ]`
Small on purpose: the first real applications need forms, logins and uploads; the rest of HTTP/1.1 is phase E.
- [x] B1 (2026-09-17) Methods: the parser knows every standard method; a location carries
      the `MethodSet` its handler implements (static: GET/HEAD/OPTIONS, `methods = [...]`
      narrows) and its `Allow`; OPTIONS answers 204 + Allow (also `OPTIONS *`), everything
      else 405 + Allow, TRACE and CONNECT always. POST/PUT/DELETE/PATCH reach the handler
      with their body (A3); the static handler declines them, FastCGI (C1) will accept.

### Phase C. PHP by design (FastCGI to php-fpm), Laravel first  `[ ]`
- [x] C1 (2026-09-17) `FcgiClient` (`src/upstream/`, `src/handlers/fastcgi.*`): async
      FastCGI/1.1 over unix or TCP, per-worker bounded pool with an explicit queue
      (`max_connections`, `queue_depth`, `queue_wait` -> 503 + Retry-After, `priority_reserve`
      for `priority` locations), `FCGI_KEEP_CONN` available but **off by default** (php-fpm
      pins a child per idle connection; on with a pool sized for it), one retry on a fresh
      connection for GET/HEAD when a reused one dies before the head, request body in memory
      / temp file / streamed per location, prebuilt per-location params block + per-request
      tail, growable response head up to `head_max`, `Status:`/`Location:` parsing, response
      buffered (memory, temp-file spill, sendfile) or streamed as a `StreamBody`, timeouts to
      504, `FcgiFailure` reasons with fix hints in the error log and the JSON access log.
      `match = "suffix"` locations. Live tests against php-fpm in `tests/integration.sh`
      (skipped when php-fpm is absent). Not here: `-t` socket check and presets (C3).
- [x] C2 (2026-09-17) nginx's `fastcgi_params` set (plus `REDIRECT_STATUS`), `PATH_INFO` /
      `PATH_TRANSLATED` split at the first `.php/` (suffix locations match there too),
      `HTTPS` / `REQUEST_SCHEME` / `REMOTE_ADDR` from `X-Forwarded-Proto` / `X-Forwarded-For`
      when the peer is in `server.trusted_proxies` (`src/net/cidr.hpp`); the access log
      shows that client address as well. From the C1 review: a sized `StreamBody` is held
      to its Content-Length (surplus cut, short body closes), `Proxy` never forwarded
      (httpoxy), header names with `_` dropped and repeats joined like nginx, temp-file
      cap `buffer_file_max` (1 GB) switching to streaming, pool bounds validated per
      upstream, fewer copies in the client.
- [x] C3 (2026-09-17) `php = { socket = ... }` at site level (C1) and presets:
      `app = "laravel"` (root/public, index.php, `try_files $uri $uri/ /index.php?$query_string`,
      exact `/index.php` fastcgi location so no other script ever runs, dotfiles hidden,
      `/build/` with a one-year immutable Cache-Control), `app = "php"` (`.php` suffix
      location, index.php/index.html, `=404`), `app = "static"`. A preset never overrides
      a location the site defines. `add_headers` per location. `agensio -t --explain`
      prints the expansion; `-t` also warns about unreachable FastCGI upstreams.
      `app = "wordpress"` (added with the C4 bed): `.php` suffix location, permalink
      `try_files`, `wp-content/uploads` and `wp-includes` as `final` prefix locations
      (nginx `^~`, new in the router) with `deny_suffixes` for PHP sources and
      Cache-Control. `app = "proxy"` comes with phase D.
- [x] C3a (2026-09-17) FastCGI keep-alive: the 78 KB page collapsing under `keep_conn`
      on TCP was Nagle on php-fpm's side meeting our delayed ACK (a fresh connection's
      close() flushes the tail; a kept one waits up to 40 ms). Fixed with TCP_QUICKACK
      before each read on kept TCP connections and TCP_NODELAY on the upstream socket:
      direct TCP with keep-alive 1051 -> 3749 req/s, level with the unix socket.
      Measured the transports too (`bench/results/laravel-keepconn-20260917.md`): the
      bed now has a unix-socket pool in a bind mount (`bench.sh -p unix`, Linux hosts);
      the socket alone takes agensio from 85 to 51 us per page request (nginx 110 to 74),
      keep-alive on top saves 6 us more. Through docker-proxy keep-alive stays broken
      (the delayed ACK is inside the container) and fresh connections straight to the
      container IP cost 150-500 us in conntrack, so the TCP pool keeps fresh connections.
      Default stays off: the pool must be sized so kept connections cannot pin every
      child (`max_connections` x workers <= `pm.max_children`), which C3b's generated
      pools will do.
- [x] C3b (2026-09-17) **Per-site users (ISPConfig / IIS app-pool model, made native)**: `user = "web1"`
      on a site; agensio generates the php-fpm pool for it (user/group, socket owned by the
      site user with group-only access for agensio, private tmp and session dirs,
      `open_basedir`, child limits, timeouts), writes per-site logs owned by that user, and
      refuses at validation any pool socket, docroot or `.env` whose ownership or mode would
      let sites read each other. `sites/create` in the control API does all of it.
      Design `docs/design-per-site-users.md` (accepted 2026-09-17, all five questions as
      proposed). C3b-1 done 2026-09-17: `user`/`group` on a site, pool keys in `php`,
      derived socket and keep-alive sizing, `src/services/pools.*` rendering the pool
      file, `agensio pools` (writes, prunes, exit 3 on change), `-t --explain` shows the
      pool, unit tests. C3b-2 the same day: `check_hosting` (`src/services/pools.*`)
      runs the six ownership rules of the design behind an injectable `HostFacts`
      (unit-tested over a described machine), under `-t` and before every start.
      C3b-3: `server.user` (H2 pulled forward): bind and open logs as root, per-site
      access logs `agensio:<site group> 0640`, then `initgroups/setgid/setuid`; started
      as that user it just runs. `tests/pools.sh` (root devbox, two real users, the
      distro php-fpm) proves the isolation end to end: PHP runs as each site's user,
      `open_basedir` blocks the other site's `.env`, sessions land in the private
      directory, `-t` refuses a world-readable `.env` and a socket with the wrong group.
- [x] C4 (2026-09-17) Test bed: `bench/laravel/` is a ddev Laravel project
      (`setup.sh` creates it once: `ddev config`, `ddev start`, `composer create-project`,
      test routes). `.ddev/web-build/Dockerfile.agensio` adds a second php-fpm pool on
      TCP 9000 and `.ddev/docker-compose.agensio.yaml` publishes it to 127.0.0.1:9000;
      agensio runs natively with `bench/laravel/.ddev/agensio.toml` (`app = "laravel"`,
      `php = { socket = "127.0.0.1:9000", remote_root = "/var/www/html/public" }`). The
      new `remote_root` maps SCRIPT_FILENAME/DOCUMENT_ROOT/PATH_TRANSLATED into the
      container. `tests/laravel.sh`: welcome, JSON, POST, 300 KB upload, client IP,
      mapped script path, static asset, Laravel's 404, dotfile, keep-alive; skips when
      the project is not running. Same files work on macOS (ddev + Docker Desktop/Colima).
      `bench/statamic/` is a second bed of the same shape (Statamic on the laravel preset,
      flat-file, pool published on 9001, agensio on 8071, control panel for uploads and
      PUT/PATCH/DELETE by hand: `bench/statamic/.ddev/setup.sh`, login admin@admin.com / 4444).
      `bench/wordpress/` is the third: WordPress on `app = "php"` with the permalink
      `try_files`, MariaDB from ddev, pool on 9002, agensio on 8072, reachable as
      http://wp.agensio.ddev.site:8072 (wp-admin admin / 4444); the bed for the
      `app = "wordpress"` preset and the page cache later.
- [x] C5 (2026-09-17) Benchmark: `bench/laravel/bench.sh` runs agensio and nginx (one
      worker each, nginx from the devbox image on the host network when the host has none)
      in front of the same php-fpm pool (the bed's, 8 static children) and records req/s,
      latency, CPU per request of the web server's processes and of the container's
      cgroup (the application). `bench/results/laravel-20260917-100530.md`: both servers
      are application-bound at 3.4k (78 KB welcome page) and 3.5k (`/json`) req/s, 2.2 ms
      of PHP per request; web-server CPU per request agensio 85-86 us vs nginx 110-111 us
      on the page, 54-55 vs 58-59 us on JSON, dominated by the per-request TCP connection
      to php-fpm. `keep_conn = true, max_connections = 8` halves agensio's cost on JSON
      (26.6 us, 3840 req/s) but the 78 KB page dropped to 1354 req/s through docker-proxy,
      not understood yet (C3b). Found and recorded on the way: sqlite database sessions
      and file sessions both make the bed unusable for load (setup.sh sets cookie
      sessions), and abandoned client requests keep their pool slots (E9).
- [x] Checkpoint (2026-09-17): Laravel welcome page served with one worker; table above.

### Phase D. Reverse proxy  `[ ]`
- [x] D0 (2026-09-17) Benchmark upstream and baseline before the first line of proxy code:
      `bench/upstream/upstream.cpp` (target `agensio_upstream`, Asio, shares nothing with
      agensio) answers 500k+ req/s on one core so the proxy in front of it is the
      bottleneck and its CPU per request is what a run reads, as with static files and
      Laravel. Modes by path: `/json`, `/big` (100 KB), `/slow?ms=N` (a working
      application: connection pools and concurrency under a delayed answer), `/chunked`,
      `/close` (reconnects), `/stats` (connections accepted, so a test can prove the pool
      reuses them). `bench/proxy/run.sh` runs the upstream direct, nginx (`upstream`
      keepalive, `proxy_http_version 1.1`) and Caddy one worker each, later agensio, and
      records req/s, latency, proxy CPU per request and the upstream connections each
      proxy opened. The baseline rows are the targets for D1-D4.
- [x] D1 (2026-09-17) HTTP/1.1 upstream client: `UpstreamRequest` (`src/upstream/client.*`)
      now holds what FastCGI and HTTP share (pool slot, connect, timeouts, one retry,
      request body from memory / spill / stream, response buffering with spill, the
      streaming pull source); `FcgiRequest` and `HttpRequest` only encode and decode
      their protocol. `HttpRequest` frames the body it sends (Content-Length or chunked),
      decodes Content-Length, chunked and close-delimited bodies, skips 1xx, keeps the
      connection when the origin allows. `ProxyHandler` + `handlers/upstream_common.*`
      (shared with FastCGI). Config: `upstream = "http://host:port[/prefix/]"` on a
      location, `proxy = { ... }` with proxy-sized pool defaults (256 in flight, 1024
      queued, 64 idle per worker). Profiled with strace inside the perf devbox
      (`agensio-devbox-perf`, perf + valgrind + strace): the static path makes 2 syscalls
      per request, the first proxy did 7, three of them overhead: two timerfd_settime
      from arming an Asio timer per phase and an epoll_ctl from a readiness wait. Fixed
      by giving the pool one 250 ms tick that checks each exchange's deadline (the idle
      timer's lazy pattern) and by running upstream completions inline (immediate
      executor); TCP_QUICKACK only while a body is still arriving. Now 4 syscalls per
      proxied request (send and receive each way), the minimum.
      `bench/results/proxy-20260917-181006.md` (one worker each, D0 upstream): JSON at
      64 connections agensio 201k req/s at 4.98 us per request vs nginx 176k at 5.70
      (13 % less CPU), at 16 connections 5.01 vs 5.54, 100 KB body 17.7 vs 32.6 us
      (46 % less), 20 ms application at 256 connections 7.5 vs 8.3; connection reuse
      like nginx's. Integration suite: 22 proxy checks (framings, streaming both ways,
      spilled and chunked request bodies, 502/504, reuse, logs); fuzz target
      `fuzz_http_head`, 23M runs clean. `bench/ab.sh <ref> -P` is the gate from here on.
      The FastCGI path shares the change: Laravel over the unix socket went from 51.0 to
      46.6 us per page request (fresh connections) and 25.1 to 23.0 us per JSON request
      (keep-alive); TCP through docker-proxy unchanged (`laravel-keepconn-20260917.md`).
- [x] D2 (2026-09-17) Header policy, designed around what nginx gets criticised for:
      Host passed through by default (`host = "pass" | "upstream" | "name"`),
      X-Forwarded-For/Proto/Host always set and, from a peer that is not a trusted proxy,
      replaced rather than appended (nothing a client sends is believed); `forwarded =
      "x-forwarded" | "forwarded" | "both" | "off"` (RFC 7239 with bracketed IPv6);
      `headers = { name = "value" }` toward the origin with `$host`, `$remote_addr`,
      `$scheme`, `$server_name`, `$server_port`, `""` removing, site and location tables
      merged per field (no `proxy_set_header` reset trap); `hide = [...]` on the way back;
      `redirects = "rewrite"` (a Location naming the origin becomes this site and location)
      or `"pass"`; the location's `add_headers` on 2xx/3xx for proxied and PHP answers
      alike; a site-level `proxy = { ... }` as the default for its locations. Documented
      as the complete proxy reference in `docs/configuration.md` section 12, with the
      nginx knobs left out on purpose. 18 integration checks against the upstream's new
      `/headers` and `/redirect` modes. Gate (`ab-20260917-184508.md`, 3 rounds): proxy
      JSON 4.38 -> 4.49 us, the untouched static row moved the same 2.6 %, so noise.
- [x] D3 (2026-09-17) WebSocket / `Upgrade` tunnelling: a request with `Connection:
      Upgrade` and an `Upgrade` field (and no body) is forwarded as one (`Connection:
      Upgrade` to the origin, the field passed through); a 101 ends the exchange
      (`finish_upgraded`: slot back, connection kept) and `Http1Connection` takes the
      origin connection as the peer of a tunnel: two byte pumps with their own buffers,
      bytes that followed either head forwarded first, a side's EOF half-closing the
      other (TLS clients: close), the idle timer reused with `tunnel_timeout` (0 = none
      by default). `upgrade = false` per location refuses. Integration: 101 with
      Upgrade/Connection and no Content-Length, early bytes, 100 KB both ways, close
      propagation, a 101 logged with `upstream=upgrade`. HTTP/2-to-HTTP/1.1 downgrade
      for upstreams moves to phase G where it belongs.
- [x] D4 (2026-09-17) Upstream groups: `upstream = ["http://a:3000", "http://b:3000"]`,
      round-robin per worker (`UpstreamPool::pick`), passive health per worker
      (`max_fails` consecutive failures mark a member down for `fail_timeout`, a success
      clears; all down: the one marked longest ago), and moving to the next member on a
      failure before any response byte: any request after a connect failure (nothing was
      sent), GET/HEAD only after bytes went out (`UpstreamRequest::try_next_address`,
      the slot of the failed member released, the head buffer kept). Every member is a
      pool of its own; `-t` probes all; the error log carries "marked down" and "is
      back". Integration: alternation on one connection, failover with a dead member,
      the dead member marked down after max_fails, a POST retried after a refused
      connection. No weights or active checks.
- [x] D4b (2026-09-17) TLS to the origin: `TlsStream` became `BasicTlsStream<Socket>`
      with a client mode (`set_client`: connect state, SNI, `SSL_set1_host` verification);
      `UpstreamConnection` carries an optional TLS layer behind `async_read_some` /
      `async_write` / `sock()`, so the exchange, the tunnel and the pool never know which;
      `UpstreamPool::tls_context` builds one client context per verify/CA setup on first
      use. `https://` upstreams get their own pool key; `proxy = { tls = { verify,
      server_name, ca } }`. Integration against the suite's own HTTPS site: verify off,
      verified with the bench CA and name, system-store verification failing with a 502
      `tls_error`, keep-alive across requests.
- [ ] D5 CGI handler: spawn a process per request with CGI/1.1 env and pipes, for legacy
      applications; async pipes via Asio; concurrency cap.
- [ ] D6 Presets: `app = "proxy"` with `upstream = "http://127.0.0.1:3000"`; examples for
      Node, Rails, Rocket.Chat, ThingsBoard in `docs/examples/`.
- [ ] D7 Benchmark: hello-world Node upstream through agensio vs nginx; WebSocket echo.
      Left on the table from D1 if ever needed: per-exchange allocations (Exchange,
      HttpRequest, std::function, the forwarded head string) and the pool's string-keyed
      lookup; the syscalls are already at the minimum.
- [ ] Checkpoint: Rocket.Chat or a Node app fully usable behind agensio.

### Phase E. Complete HTTP/1.1 and hardening  `[ ]`
- [ ] E1 Range requests (single range, `206`, `416`, `If-Range`) on memory and file sources.
- [ ] E2 Compression, off by default, per site/location: `compression = "precompressed"`
      serves `.br`/`.gz` siblings by `Accept-Encoding` (no CPU); `compression = "on-the-fly"`
      gzip/brotli for dynamic responses with level setting; measure and document the
      CPU and latency cost of each.
- [~] E3 Request-smuggling and parser hardening: **done 2026-09-16** for the request head
      (CL vs TE rules, duplicate CL/Host, obs-fold, bare CR, CTLs, header count limit,
      `Host` validation; libFuzzer targets for the parser and path normaliser). Remaining:
      chunked decoder fuzzing once bodies exist (A3), running fuzzers in CI.
- [~] E4 Timeouts everywhere: header read, body read, write stall, keep-alive idle,
      per-connection request cap (**done 2026-09-16**: `max_requests_per_connection`; idle
      timeout also bounds slow header sends); `Connection: close` on shutdown; graceful drain.
- [ ] E5 IPv6 listeners tested; `SO_REUSEPORT` path tested on Linux (Docker).
- [x] E6 Path policies (2026-09-16): `hidden_files`, `symlinks = "deny"`, Windows path rules.
- [x] E7 Hardened build flags, sanitizer and fuzz build options, accept-loop EMFILE backoff
      (2026-09-16).
- [ ] E8 103 Early Hints for static and proxied responses (asked of nginx; cheap once
      bodies are sources).
- [ ] E9 Client abort while an upstream request is pending (found with C5): the HTTP/1
      connection has no read in flight while its FastCGI request waits in the pool queue
      or runs, so a client that goes away (wrk closing 64 connections, a browser
      navigating on) is noticed only when the response is written. Until then the request
      keeps its queue slot and php-fpm executes it; after a burst that is up to
      `queue_depth` wasted requests and a 503 storm for the next 0.5 s. nginx aborts the
      upstream request on client EOF (`fastcgi_ignore_client_abort off`). Fix: a
      zero-byte read for EOF on the client socket while `upstream_` is set (FastCGI and
      proxy paths only, nothing on the static path), cancelling the exchange; measure.
- [ ] Checkpoint: h1 compliance run (a scripted curl/python suite in `tests/`), fuzzers
      clean for 1h, benchmark unchanged.

### Phase F. Control API and agentic interface  `[ ]`
Independent of the other phases and useful for all of them (inspect cache, reload config).
**Security is the first requirement here**: a compromised control interface owns the
server and every site on it. The rules below are binding for every step in this phase.

Threat model (what the interface must resist):
- a local unprivileged user, or a compromised PHP/Node app running as its own user
- a browser on the administrator's machine (CSRF, DNS rebinding against loopback)
- anything on the network (the interface must never be reachable from it by default)
- an AI agent or a script misusing the interface, by mistake or through prompt injection
- an attacker who obtained a token or a config file backup

Rules:
- [ ] F0 Security design, implemented before any command exists:
  - **Off the data plane.** The control API is a separate listener with its own code path;
    no site listener can ever route to it, no shared port, no path-prefix trick.
  - **Unix socket by default**, mode `0600` owned by the server's user, optional admin
    group at `0660`. Peer credentials (`SO_PEERCRED` / `LOCAL_PEERCRED`) are checked on
    every connection regardless of file permissions, and the peer uid/gid is written to
    the audit log with every mutating command. The PHP/proxy app users are never in the
    admin group.
  - **Loopback TCP is opt-in**, `127.0.0.1`/`::1` only; binding to any other address is
    refused unless `remote = { tls = ..., client_ca = ... }` is set, i.e. remote access
    requires mutual TLS with client certificates, never a token alone.
  - **Token auth for TCP**: 32 random bytes generated at first start, stored `0600`,
    rotated with `ctl token rotate`, compared in constant time, failures rate-limited and
    logged. Tokens are never printed by any command.
  - **Browser defences on TCP**: requests must carry `Host: localhost|127.0.0.1|[::1]`
    (DNS rebinding), must not carry an `Origin` header (no browser is a client), must
    carry a custom header (`X-Agensio-Control: 1`), no CORS ever.
  - **Roles**: `viewer` (read-only), `operator` (reload, purge, reopen logs), `admin`
    (create/disable sites, edit config, token rotate). Role comes from peer uid/group on
    the socket or from the token on TCP; default: socket owner = admin, admin group =
    operator, everything else refused.
  - **Mutations are safe by construction**: validate the resulting config before
    applying; atomic file writes with a `.bak` of anything overwritten; `sites/create`
    accepts only syntactically valid domains and paths under a configured `sites_root`
    (no symlink escape, checked after canonicalisation); generated TOML comes from
    templates, never string concatenation; the API never executes shell commands.
  - **Audit log**: every mutating command appended as one line (time, peer, role, command,
    arguments, result), separate from the access log, rotated with it.
  - **Kill switch**: `control.enabled = false` removes the listener entirely; the
    interface is also absent when the config does not mention it.
  - Same fuzzed HTTP/1.1 parser as the data plane; JSON parsing with size limits.
- [ ] F1 Control socket: unix domain socket (`/run/agensio.sock`) speaking HTTP/1.1 + JSON
      through the same core; optional loopback TCP listener with the token; remote only
      with mTLS. One API, several transports, one permission model.
- [ ] F2 Read-only commands, JSON and plain text (`Accept: text/plain` gives a human answer):
      `status`, `cache` (count, bytes, hit ratio) and `cache/entries` (path, size, age,
      hits), `sites`, `config` (effective, with sources), `connections`, `metrics`
      (Prometheus text as well; per upstream and per certificate metrics from phases D/G,
      the top metrics requests on the Caddy and nginx trackers).
- [ ] F3 Mutating commands: `config/validate`, `reload` (SIGHUP equivalent, atomic swap of
      config + listeners), `cache/purge` (all or by path), `sites/create` (writes
      `sites.d/<domain>.toml` from a preset: static, laravel, php, proxy; validates;
      reloads), `sites/disable`.
- [ ] F4 Natural-language front: a small intent matcher for the questions in the brief
      ("how many files are in cache?", "create a website in /var/www/x for x.com") mapping
      to F2/C3 commands, answering in text. No model inside the server.
- [ ] F5 MCP server (decided 2026-09-16, first-class feature): expose the same commands as
      **Model Context Protocol** tools so agentic OS tooling (e.g. Omarchy) and
      administrators' assistants can inspect and configure the server.
  - `agensio mcp` runs as a stdio MCP server that connects to the control socket **as the
    invoking user**: it inherits the OS permission model and needs no secret of its own.
  - MCP over streamable HTTP is available only on the loopback listener, with the token,
    and validates `Origin` as the MCP spec requires.
  - Tools carry the MCP annotations (`readOnlyHint`, `destructiveHint`) so agent hosts ask
    the user before mutations; mutating tools additionally require `confirm: true` and a
    short `reason` string that is written to the audit log.
  - The tool set is the role's command set: a viewer's MCP session cannot see mutating
    tools at all.
  - The server never embeds a model and never fetches anything from the network on behalf
    of an agent; it offers precise, auditable tools and nothing else.
- [ ] F6 CLI: `agensio ctl <command>` wrapping the socket, so shell scripts and panels
      (ISPConfig style) get the same interface.
- [ ] F7 Security review of the phase: a written checklist against the threat model above,
      tests for each rule (wrong uid refused, `Origin` refused, non-loopback bind refused,
      token rate limit, symlink escape in `sites/create` refused, viewer cannot mutate),
      and a fuzz target for the JSON command parser.
- [ ] Checkpoint: control traffic measured to add zero cost to data-plane workers (runs on
      worker 0's loop but only when called); docs page with every command, every role and
      the threat model.

### Phase G. HTTP/2  `[ ]`
- [ ] G1 ALPN in `TlsStream` (`h2`, `http/1.1`); `Http2Connection` around an nghttp2
      session: our socket I/O feeds nghttp2, callbacks create/complete `Stream`s, response
      `BodySource`s become DATA frames with flow control honoured.
- [ ] G2 Settings and limits: max concurrent streams, window sizes, header list size,
      priority ignored (RFC 9113), PING/GOAWAY, graceful close.
- [ ] G3 h2c (cleartext upgrade / prior knowledge) optional, off by default.
- [ ] G4 Benchmark with `h2load` (nghttp2) vs nginx `http2 on`: static, Laravel, proxy.
- [ ] Checkpoint: h2spec passes; HTTP/1.1 numbers unchanged (no cost when h2 is idle).

### Phase H. Production hardening  `[ ]`
- [ ] H1 Zero-downtime reload: new config applied by worker 0 atomically; listeners added
      or removed; **TLS certificates watched and reloaded automatically when the files
      change** (the request nginx and Caddy users share most) as well as via `ctl reload`;
      reload must not stall new QUIC connections (nginx's known weakness).
- [~] H2 Start as root, bind, drop privileges (`user =`): **done 2026-09-17 with C3b-3**
      (`server.user`); log rotation via `SIGUSR1`/reopen done with A5. Remaining: systemd
      unit, pid file.
- [ ] H3 Certificates: built-in ACME client (HTTP-01, TLS-ALPN-01 **and DNS-01 with a
      provider interface**: HTTP-01-only is the main criticism of nginx's 2025 module and
      DNS challenges are Caddy's second most upvoted request), any RFC 8555 CA, short-lived
      certificate profiles, automatic renewal, cross-platform; until then documented reload
      hooks for certbot / win-acme / acme.sh. OCSP stapling.
- [ ] H3b **Kernel-enforced containment of the web server itself** (Linux, FreeBSD): open
      files relative to a per-site root descriptor with `openat2(RESOLVE_BENEATH)` (and
      `RESOLVE_NO_SYMLINKS` for `symlinks = "deny"`), so containment does not depend on path
      code; Landlock rules at startup restricting each worker to reading the docroots and
      connecting to upstream sockets; a seccomp filter for the request-path syscalls.
      macOS/Windows keep the path checks (fuzzed). Closes the gap in the ISPConfig model,
      where PHP is isolated but the shared web server user can read every site.
- [ ] H4 Rate limiting and connection limits per IP; request id header; error pages
      configurable.
- [ ] H5 Metrics endpoint scraped by Prometheus; structured JSON logs option with a
      request id that also appears in the error log; W3C `traceparent` passthrough for
      OpenTelemetry.
- [ ] H6 Memory/CPU profile under 10k idle keep-alive connections; per-connection memory
      budget documented (target: < 8 KB idle h1 connection).
- [ ] H7 Packaging: Debian/Arch packages, Docker image, Homebrew formula; CI on Linux and
      macOS with ASan/UBSan builds and the fuzzers.
- [ ] Checkpoint: runs a real site for a week; documented ops guide.

### Phase I. HTTP/3  `[ ]`
- [ ] I1 UDP listener per worker (one worker first); ngtcp2 with OpenSSL 3.5+ QUIC TLS
      API; connection ids, retry tokens, timers on our loop.
- [ ] I2 nghttp3 session per connection creating `Stream`s exactly like h2.
- [ ] I3 `Alt-Svc` advertising from h1/h2; 0-RTT policy (only idempotent GET);
      connection migration; multi-worker via SO_REUSEPORT + connection-id routing (Linux
      eBPF) later.
- [ ] I4 Benchmark with `h2load --npn-list h3` or `quiche` client vs nginx `quic`.
- [ ] Checkpoint: browsers connect over h3; h1/h2 numbers unchanged.

### Principles confirmed by user research (`docs/web-server-feedback.md`)
- Everything ships in the one open build; no feature is held back for a paid tier. The
  nginx Plus and OpenLiteSpeed/Enterprise gaps are the most repeated complaints about
  those servers.
- Presets and a validator that explains beat more directives; "if is evil" and `.htaccess`
  migrations are the configuration complaints that never go away.
- Memory and CPU per request stay published numbers; Caddy's OOM reports and Apache's
  footprint are why people look for alternatives.

### Later / ideas
- Shared-dictionary compression (RFC 9842) once compression exists.
- Asynchronous cold-cache file reads: a slow disk stalls the worker's loop for
  milliseconds today. Use Asio's own async file I/O (`asio::random_access_file`,
  `async_read_some_at`) on the worker's loop: io_uring on Linux (`ASIO_HAS_IO_URING`,
  files only, sockets stay on epoll) and IOCP on Windows. macOS/FreeBSD have no async file
  backend in Asio, so there a small `asio::thread_pool` does the read and posts the
  completion back to the worker. Only the miss path is affected; warm the page cache the
  same way before `sendfile` of a cold streamed file (nginx's `aio threads` trick).
  Moving sockets to io_uring as well (`ASIO_HAS_IO_URING_AS_DEFAULT`, nginx's most upvoted
  request) is a separate measurement.
- io_uring backend for Linux (Asio supports it; measure).
- kTLS on Linux: sendfile over TLS.
- Brotli precompression at cache load time.
- Static site presets (Hugo/Astro output), SPA fallback.
- **Hosting mode: one process per site user.** A front process accepts, reads SNI/Host,
  and passes the descriptor (SCM_RIGHTS) to the site's own agensio process running as the
  site user, so even a web-server exploit is confined to that user; per-site cgroups give
  CPU, memory and connection limits panels ask for. Affordable because a process is
  7-11 MB. Needs the proxy and control API first.

---

## 3. Suggestions

1. **Order: A to I as lettered** (renumbered 2026-09-17, see section 2). Real
   applications first, because they validate the body model, router and upstream design
   before Range, compression and the control API are built on top of them. HTTP/3 last:
   it is the largest dependency and browsers fall back gracefully.
2. **Presets over knobs.** `app = "laravel"` should be the whole config for a Laravel site.
   Panels and agents generate presets far more reliably than nginx location blocks.
3. **Keep the one-worker promise measurable.** Every phase's checkpoint runs with
   `-w 1`; the CPU-per-request column is the number to protect.
4. **Agentic = tools, not a model.** The server exposes precise, auditable commands (JSON
   + MCP). Any language model lives outside, in the OS's agent. That keeps the server
   small and the security story simple (unix socket, owner-only, explicit mutating
   commands, every change written to a TOML file you can read).
5. **Testing per phase**: unit tests for pure code, `tests/integration.sh` grows a section
   per phase, fuzzers for every parser (h1, chunked, FastCGI records, HPACK is nghttp2's).

---

## 4. Decisions (2026-09-16)

1. **HTTP/2 and HTTP/3 libraries.** Start with nghttp2 and ngtcp2 + nghttp3. Benchmark h2
   and h3 against nginx and Caddy; if the numbers disappoint, write HTTP/2 framing + HPACK
   ourselves (QUIC stays a library either way).
2. **Control interface: security first, MCP built in** (reaffirmed 2026-09-16). HTTP + JSON
   API over a unix domain socket by default with peer-credential checks; an optional
   loopback TCP listener with a bearer token (off by default on POSIX, the default on
   Windows); remote access only with mutual TLS. Roles viewer/operator/admin, audit log
   for every mutation, kill switch. The MCP server (stdio bridge and loopback HTTP) and the
   `agensio ctl` CLI are thin adapters over the same API and the same permission model.
   Created sites are written to `sites.d/`. Full threat model and rules: phase F0.
3. **PHP test bed: ddev** (present on both macOS and Linux dev machines). php-fpm only;
   Octane out of scope.
4. **Proxy: upstream groups from the first cut**, kept simple: list of backends,
   round-robin, passive health marking (N failures -> down for T seconds), retries on
   idempotent requests only. No active health checks, no weights, until asked for.
   General rule: take the good parts of nginx and other servers, keep it simple and stable.
5. **Compression is a per-site/location setting, off by default.** Precompressed siblings
   (`.br`, `.gz`) cost nothing and are served when present and enabled; on-the-fly
   gzip/brotli is a separate switch with a measured CPU/latency cost documented.
6. **Certificates: later (phase H), automatic once set up, cross-platform.** Built-in ACME
   (HTTP-01 and TLS-ALPN-01, keys and JWS via OpenSSL) is the only option that works the
   same on Linux, macOS and Windows; external clients (certbot, win-acme, acme.sh) get a
   reload hook meanwhile.
7. **Windows stays supported** as a compile-and-run target with CI, best-effort performance.
   All OS-specific code lives behind a small `src/os/` interface (see below); if it starts
   to bend the core design, revisit.
8. **Access logging is a configuration option** with a human-readable, fail2ban-friendly
   format (Apache/nginx "combined" so existing fail2ban filters work unchanged), buffered
   and written off the hot path. Default: see the note in phase A5 (recommendation: on,
   measured cost must stay under 1 us/request).

### Phase A start decisions (2026-09-16)
- Source layout moves file by file as each is touched (`src/core`, `src/http1`, `src/handlers`,
  `src/services`, `src/net`, `src/os`), no single big rename.
- Data-plane errors use a small in-house `Result<T>` (about 60 lines). **When the project
  moves to a standard that has `std::expected` (C++23; needs GCC 13+, i.e. after Debian 12
  is dropped), replace it with the standard type.**
- Limits: 100 header fields, 16 KB head, 8 KB per field; request body 1 MB default with
  per-site override (PHP presets raise it). Timeouts: header read 10 s, body read 30 s
  between chunks, write stall 30 s, keep-alive idle 15 s; all configurable.
- Access log: on by default in combined format if measured under 1 us/request, else off;
  **always off in the benchmark templates**, matching the nginx and Caddy bench configs.
- Names: `Stream`, `Request`, `Response`, `Headers`, `BodySource`; conventions per
  `docs/CODE_STYLE.md`.
- One commit per step A1-A5 with before/after numbers; the owner commits.
- **OpenLiteSpeed joins the benchmark** via the Linux container harness (`bench/docker/`),
  since it has no macOS build; that harness runs agensio, nginx, Caddy and OpenLiteSpeed
  with wrk on one Docker network, one worker each.

## 5. Platform layer (Windows and POSIX)

Everything that differs by OS goes behind `src/os/` with one header per concern and a
`posix/` and `win32/` implementation; the core never includes OS headers.

| concern | POSIX | Windows | notes |
|---|---|---|---|
| sockets, timers, TLS | Asio (kqueue/epoll) + OpenSSL | Asio (IOCP) + OpenSSL | same code; speculative-read tuning is POSIX-only |
| zero-copy send | `sendfile` | `TransmitFile` | both behind `send_file()`; copy path fallback everywhere |
| files, stat, pread | POSIX | `_sopen_s`, `_fstat64` | already shimmed in `file.cpp` |
| multi-worker accept | `SO_REUSEPORT` (Linux) | shared acceptor | shared acceptor path exists |
| control socket | unix domain socket | AF_UNIX (Win10 1803+) or loopback + token | Asio `local::stream_protocol` on both |
| signals / reload / stop | SIGHUP, SIGTERM, SIGUSR1 | console ctrl handler, service control | `os::on_reload()`, `os::on_stop()` |
| privilege drop | `setuid/setgid` after bind | run as a service account | `os::drop_privileges()` no-op on Windows |
| daemon / service | systemd unit | Windows service (`agensio --service`) | phase H |
| process spawn (CGI, php-cgi) | `posix_spawn` + pipes | `CreateProcess` + pipes | `os::Process` |
| paths | case-sensitive, `/` | case-insensitive, `\`, reserved names (`CON`, `NUL`), trailing dots/spaces, `::$DATA` streams | path normaliser gets a Windows mode; deny-rules compare case-insensitively |
| PHP | php-fpm (unix socket / TCP) | `php-cgi.exe -b 127.0.0.1:9000` (FastCGI over TCP) | same FastCGI client |
| kTLS, io_uring | Linux only | n/a | optional accelerators, never required |

Estimated share of OS-specific code: under 10 %, all in `src/os/`. A GitHub Actions matrix
(Linux, macOS, Windows) builds and runs the unit tests from phase A on; the integration
suite runs on Linux and macOS.

## 6. Real-world application matrix

Each application is a standing integration test from the step that enables it, run on
the Debian machine (ddev for PHP, Docker for the rest) and kept green from then on.
"Exercises" says what part of agensio the application stresses that synthetic tests do not.

| application | stack | enabled by | exercises |
|---|---|---|---|
| **Laravel** (skeleton + Breeze auth) | PHP, php-fpm | C4 | front controller `try_files`, sessions and cookies, POST forms, CSRF, JSON APIs, file uploads (A3 bodies), `public/storage` symlink policy |
| **Statamic** | PHP (Laravel), flat files | C4 | control panel (long admin sessions, many XHR), glide image resizing (large responses), static caching output |
| **WordPress** | PHP, php-fpm, MySQL | C4 | the most deployed target: pretty permalinks, admin, media uploads (multipart bodies), plugins expecting `.htaccess` rules, `wp-cron`, REST API; `wordpress` preset |
| **Nextcloud** | PHP | C4 + B1 (+ E1 for video) | WebDAV methods (PROPFIND, MKCOL, PUT, MOVE), very large and chunked uploads, Range requests, long-running PHP requests, strict forwarded-header handling |
| **Redmine** | Ruby on Rails, Puma | E | classic Rails app behind a proxy: sessions, attachments, no WebSockets; the simplest Rails baseline |
| **Discourse** | Rails, Puma, Redis, Sidekiq | D3 | demanding Rails: long polling message bus, uploads, strict `X-Forwarded-*`/`Host` handling, heavy asset serving; the Rails stress test |
| **Ghost** | Node.js | E | the most used Node CMS: proxy plus static assets, admin SPA, image uploads |
| **Rocket.Chat** | Node.js (Meteor) | D3 | WebSockets (DDP) at scale, large file uploads, many concurrent long-lived connections |
| **Next.js starter** (App Router) | Node.js | E | modern SSR with streaming responses (chunked, no Content-Length), backpressure to the client |
| **Django + Wagtail** | Python, Gunicorn/Uvicorn | E | the common Python CMS: proxy, static/media split, CSRF with forwarded scheme |
| **FastAPI** demo with SSE | Python, Uvicorn | D1 | server-sent events: buffering off, streaming that never ends, idle handling |
| **Gitea** | Go | E + A3 | git smart HTTP: large chunked request bodies, `git push` over HTTPS, long responses, Basic auth passthrough |
| **Keycloak** | Java | D2 | the strictest consumer of `X-Forwarded-Proto/Host/Port` and `Forwarded`; a proxy-correctness oracle for redirects and cookies |
| **ThingsBoard** | Java, Spring | D3 | dashboards over WebSockets plus REST; long sessions |
| **Jellyfin** | .NET | E + E1 | media: Range requests and seeking on multi-GB streams through the proxy, many parallel large transfers |
| **cgit** | C, CGI | D5 | a real CGI program for the legacy CGI handler |
| **Hugo / Astro static site**, **SPA with history fallback** | static | now / A4 | phase 1 serving, precompressed assets (E2), `try_files ... /index.html` |

Order of first light: Laravel first (C4, the acceptance test of phase C), then WordPress
and Statamic, then Redmine and Ghost as the first proxy targets (E), then the real-time
ones (Rocket.Chat, Discourse, FastAPI SSE, ThingsBoard) with WebSocket/SSE support (D3),
then Keycloak and Gitea as correctness oracles, Nextcloud and Jellyfin when Range (E1) lands.
