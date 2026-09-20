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
- [x] D5 (2026-09-17) CGI handler: `CgiRequest` is an `UpstreamRequest` whose connect
      step forks and execs the script with a socketpair as its stdin/stdout (the parent
      end is the exchange's connection, so body sending, the CGI head, buffering, spill
      and streaming are the shared code; the body ends with the process's EOF like an
      HTTP close-delimited one) and a pipe for stderr (captured for the log). The pool
      caps processes per worker (`max_connections`, 8) and queues the rest; `read_timeout`
      kills a silent script; children are reaped by the pool's tick. `CgiHandler` resolves
      the script by Apache's longest-file rule with `PATH_INFO`, builds the environment
      from the FastCGI parameter builders (`fcgi::for_each_param` decodes them) plus
      `cgi.env`, runs an `interpreter` when given. Every other descriptor is closed in the
      child (`close_range`). 13 integration checks with shell scripts in `tests/cgi/`.
- [x] D6 (2026-09-17) Presets: `app = "proxy"` with a site-level `upstream` (string or
      list) and `proxy = { ... }` defaults, `root` optional, hand-written locations
      coexisting (a location's own `upstream` or `handler = "proxy"` decides; static
      otherwise). Examples in `docs/examples/` for Node, Rails, Rocket.Chat and
      ThingsBoard. Two real-world beds with live checks that skip when down:
      `bench/redmine/` (Redmine 6, Rails, official image with SQLite, `tests/redmine.sh`:
      page, stylesheet, login with CSRF token and session cookie, redirect kept on this
      host, Rails 404, keep-alive) and `bench/uptime-kuma/` (Uptime Kuma, Node, `tests/
      uptime-kuma.sh`: app shell, bundle, Socket.IO long-polling handshake and a real
      Socket.IO session over a WebSocket through the tunnel, connect acknowledged).
- [x] D7 (2026-09-17) Benchmarks: `bench/proxy/run.sh -o node` puts a Node.js
      hello-world (node:22-alpine, one process) behind each proxy: Node is the bottleneck
      at 156-160k req/s, so the row measures what each proxy makes the origin parse. With
      both forwarding Host, X-Forwarded-For and X-Forwarded-Proto they tie (nginx 155-157k,
      agensio 153-158k, `proxy-20260917-210504.md`) with agensio at 5-6 % less CPU of its
      own; forwarding nothing puts agensio at 164-168k against nginx's 159-164k. Two
      changes came out of it: no `Connection: keep-alive` on kept origin connections
      (HTTP/1.1 is persistent) and `X-Forwarded-Host` only when Host was rewritten or a
      trusted proxy sent one (otherwise it repeats Host and costs the origin a field).
      `bench/proxy/ws.sh`: 64 echo
      tunnels, 1 KB messages, client-bound at 135-138k msg/s for everyone; per message
      nginx 3.75 us, agensio 3.80 us (`proxy-ws-20260917-204524.md`); Caddy tunnels only
      `Upgrade: websocket` so its row needs a framed client. Left on the table from D1 if
      ever needed: per-exchange allocations (Exchange, HttpRequest, std::function, the
      forwarded head string) and the pool's string-keyed lookup; the syscalls are at the
      minimum.
- [x] Checkpoint (2026-09-17): Uptime Kuma (Node, WebSocket UI) and Redmine (Rails) fully
      usable behind agensio; Rocket.Chat has its example config, a bed can follow when a
      MongoDB-backed setup is wanted.

### Phase E. Complete HTTP/1.1 and hardening  `[ ]`
- [x] E1 (2026-09-18) Range requests: `http1/range.hpp` parses one `bytes=` range
      (first-last, first-, -suffix; lists and malformed values mean the whole body, 200)
      and If-Range (strong ETag or exact Last-Modified); the static handler answers 206
      with `Content-Range` and the slice as a memory view or a `FileBody` with an offset
      (sendfile and the copy path honour it, also from a cached descriptor), 416 with
      `Content-Range: bytes */size` past the end; 200 answers carry `Accept-Ranges:
      bytes` in the entry's prebuilt block. One empty-view test on the plain path.
      Integration: slices from the memory cache, the sendfile-from-descriptor path, a
      streamed 10 MB file and over TLS, suffix and open ranges, 416, If-Range both ways,
      several ranges, HEAD, keep-alive after a 206. Gate (`ab-20260917-213829.md`, 3
      rounds): 1 KB rows 1.020 / 1.022, 100 KB 0.995, inside the 3 % noise band.
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
- [ ] E8b The tunnel integration check ("101, fields, early bytes, 100 KB both ways")
      failed once with an empty result on 2026-09-17 (the D6 gate) and passed on every
      other run before and after; the Python client prints nothing when its 5 s recv
      times out, so the cause is unknown. Capture the client's exception in the check
      and, if it repeats, trace the tunnel's first reads.
- [x] E9 (2026-09-18) Client abort while an upstream request is pending (found with C5).
      The connection now has at most one client read in flight, routed by state
      (`arm_read` / `on_read`: next request head, abort watch, tunnel client side). An
      exchange that has run for one pool tick (250 ms) tells its connection
      (`UpstreamRequest::on_slow`, a raw callback set at dispatch, no allocation), which
      arms a read: EOF cancels the exchange, freeing the pool slot and, for CGI, killing
      the process; bytes are a pipelined request and are kept for after the response.
      Fast exchanges never arm it, so the proxy and FastCGI hot paths gain no syscall
      (a speculative recv costs an EAGAIN, an async_wait an epoll_ctl: both measured in
      D1). Applies to FastCGI, proxy and CGI alike; a body still being read keeps the
      body reader as the watch. Integration: with one slot and no queue, a client that
      leaves after 100 ms of a 1.5 s request lets the next client in within 600 ms
      instead of a 503. The C5 burst (wrk dropping 64 queued requests on the Laravel
      pool, then a strict client) now yields 7154 x 200 and no 503 where it gave 30k
      503s; gate `ab-20260918-003305.md` flat (proxy JSON 1.010, static 0.96-1.00).
- [ ] Checkpoint: h1 compliance run (a scripted curl/python suite in `tests/`), fuzzers
      clean for 1h, benchmark unchanged.

### Phase F. Control API and agentic interface  `[ ]`
Independent of the other phases and useful for all of them (inspect cache, reload config).

**Pulled before the pre-alpha (decided 2026-09-18)**: the owner and early adopters set up
and maintain VPS servers with a local LLM agent over SSH, so the guided setup is the
deliverable, not a bare command set. Scope and rules agreed that day:
- F4 (intent matcher) is dropped: the agent is the intent matcher. TCP, token and mTLS
  transports are deferred to after the alpha; the alpha has the unix socket, peer
  credentials, roles, the audit log and the stdio bridge spawned over SSH.
- **The guidance lives in the tool schemas, not in dialogue code.** `site_create` refuses
  to act until `user`, `https` and `php` are decided explicitly and answers with the
  missing decisions and a suggestion for each (a username derived from the domain,
  `https = "auto"`, the preset matching the files under the root); the agent turns that
  into questions and the MCP host asks for confirmation before the mutation. A new site
  defaults to HTTPS-only: `tls = "auto"` on 443 and `redirect = "https"` on 80; plain
  HTTP needs an explicit `https = "none"`.
- **Root-only work is never executed by agensio or the bridge.** Creating the OS user,
  stopping or restarting the service, reloading php-fpm: the tool answers with the exact
  commands to run as root and states that it waits for them; the agent shows them, the
  administrator runs them, the agent continues. Nothing on the socket can spawn a
  process, and the bridge exposes no tool that does.
- `health_check` plus an MCP prompt give newcomers the greeting and the list of things
  to look at on an existing server (certificates, missing port-80 redirect, sites
  without a user, recent errors, settings waiting for a restart, pools needing a
  php-fpm reload). `logs_query` answers "errors in the last 3 hours" for one site or all,
  bounded in lines and bytes, read backwards from the end of the file; summarising is
  the agent's job.
- Order: F0+F1 (socket, credentials, roles, audit, one read command), F2 (read tools),
  F3 (site_create/update/disable, reload, pools_apply, certificates), F5 (stdio bridge,
  tested through `ssh localhost`) with F6 (CLI on the same client), F7 tests alongside.
**Security is the first requirement here**: a compromised control interface owns the
server and every site on it. The rules below are binding for every step in this phase.

Threat model (what the interface must resist):
- a local unprivileged user, or a compromised PHP/Node app running as its own user
- a browser on the administrator's machine (CSRF, DNS rebinding against loopback)
- anything on the network (the interface must never be reachable from it by default)
- an AI agent or a script misusing the interface, by mistake or through prompt injection
- an attacker who obtained a token or a config file backup

Rules:
- [x] F0 (2026-09-18, the alpha subset: socket, directory, credentials, roles, audit, kill switch, parser; the TCP-only rules and the isolation warning are deferred) Security design, implemented before any command exists:
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
  - **The socket's directory is part of the boundary** (agreed 2026-09-18): `/run/agensio/`
    is created by the server, owned by its user, mode `0750`, never world-writable, so a
    site user cannot replace the socket path; the token file lives there too.
  - **Isolation warning at validation**: `agensio -t` reports, as a misconfiguration, a
    control interface enabled while any php-fpm pool, proxy upstream process or CGI
    location runs as the server's own user or as a member of the admin group. With every
    site under `www-data` the peer-credential check cannot tell sites apart, and the
    socket is only as safe as that one user; per-site users (C3b) are what makes the
    control plane safe on a shared host. The warning names the offending site.
  - Same fuzzed HTTP/1.1 parser as the data plane; JSON parsing with size limits.
- [x] F0/F1 (2026-09-18) Control socket: `[control]` table, unix domain socket
      (`/run/agensio/control.sock`, directory created 0755 owned by the server, socket
      0660 for a single admin group else 0666), HTTP/1.1 + JSON through the same core:
      `Http1Connection<asio::local::stream_protocol::socket>` on worker 0 routed to a
      synthetic site whose one location is `HandlerKind::control`. Peer credentials
      (`SO_PEERCRED` / `getpeereid`) plus the account's groups decide the role at accept
      (`control/roles.hpp`, pure); root and `server.user` are admin, `admins` /
      `operators` / `viewers` groups map to the roles, anyone else is closed before a
      byte is read and written to the audit log (`control.audit`, one line per refusal or
      mutating command). First command `GET /v1/status` (viewer); `agensio ctl status`
      client (`control/client.*`, also the bridge's transport). `tests/control.sh`
      (root devbox, real accounts, 14 checks), integration checks, unit tests for the
      role rule and the parsing. The server's own logs are handed to `server.user` at
      start so rotation works after the drop. Deferred to after the alpha: loopback TCP
      with the token, mTLS, the `-t` isolation warning (F0 last bullet).
- [x] F2 (2026-09-18) Read commands (`src/control/commands.*`, pure functions over the
      configuration and the files on disk, unit tested): `sites`, `site NAME` (effective
      locations after presets, certificate state through `acme::certificate_info`),
      `validate` (file on disk, hosting rules, restart-only diff), `logs` (error log and
      access logs in combined or JSON form, parsed by a hand-written reader for the three
      formats, read backwards from the end of each file with byte and line caps, `since`
      in `3h` form or a local timestamp, level and status-class filters, a site's error
      lines picked by name), `health` (findings with a fix per finding, the list in
      `docs/configuration.md` 15). All GET, viewer role. Not done: `cache`,
      `connections`, `metrics`/Prometheus and per-upstream pool state (per-worker, needs a
      cross-worker collection step); they follow after the alpha.
- [ ] F2b Read-only commands, remaining (`Accept: text/plain` gives a human answer):
      `status`, `cache` (count, bytes, hit ratio) and `cache/entries` (path, size, age,
      hits), `sites`, `config` (effective, with sources), `connections`, `metrics`
      (Prometheus text as well; per upstream and per certificate metrics from phases D/G,
      the top metrics requests on the Caddy and nginx trackers). The upstream diagnostics
      the FastCGI and proxy clients already compute are exposed as they are: per upstream
      the pool state (in flight, queued, idle), the last failure reasons with their fix
      hints, retry counts, queue timeouts and the slowest scripts and routes. Those are
      the first answers an administrator or an agent asks for ("why is this site 502?")
      and cost nothing new.
- [x] F3 (2026-09-18) Mutating commands (POST, `confirm` required, `reason` audited):
      `reload` (`Server::reload` now returns the refusal), `logs-reopen`, `site-create`
      / `site-update NAME` / `site-disable` / `site-enable` / `site-delete`, `cert-renew`
      (`AcmeManager::renew_now`). `src/control/sites.*`: the `SiteSpec`, its TOML rendering
      (HTTPS-only by default: redirect site on 80, TLS site on 443, optional HSTS
      location), the decision form (`apply_request` lists what is still open with a
      suggestion each: user from the domain, app from the files under root), the
      prerequisites answered as root commands (useradd, mkdir/chown, certificate files)
      with `waiting: true`, next steps (`agensio pools`, port 80 for ACME). Managed files
      carry their spec as JSON on the first line (`# agensio:managed {...}`), so an update
      merges into it and a hand-written file is refused. Every change validates through
      the reload and is undone when refused. Request bodies read on the control
      connection (256 KB cap). `agensio ctl` grew the matching subcommands (`--yes`,
      `--reason`). Not done: `cache/purge` (needs the cache invalidation API, F2b).
- [-] F4 Natural-language front: dropped 2026-09-18, the agent is the intent matcher.
- [x] F5 (2026-09-18) `agensio mcp` (`src/control/mcp.*`): newline-delimited JSON-RPC on
      stdin/stdout, protocol 2025-06-18, `initialize` / `ping` / `tools/list` /
      `tools/call` / `prompts/list` / `prompts/get`; 14 tools mapped one to one onto the
      control commands with input schemas, titles and the MCP annotations; the tool list
      is the caller's role's (learned from `status` at start; read tools listed when the
      socket is down so the agent can retry); mutating tools require `confirm` and
      `reason`; results carry the API's JSON as text and `structuredContent`, `isError`
      on any 4xx/5xx; two prompts (`getting_started`, `new_site`); server instructions
      explain the root-commands protocol. `docs/mcp.md`: wiring over SSH for Claude Code
      and Claude Desktop, tool table, a sample session. Tested in the integration suite
      (driven by a Python client) and per role in `tests/control.sh`; the `ssh localhost`
      check runs when an sshd is present (skipped on the dev box, which has none).
- [x] F6 (2026-09-18, with F1-F3) CLI: `agensio ctl <command>` wrapping the socket
      (`control/client.*`, shared with the bridge): every read and change command, `--yes`
      and `--reason` for changes, exit 1 on any 4xx/5xx with the JSON answer printed.
- [x] F7 (2026-09-19) Security review: `docs/security-control-plane.md` maps the five
      threats to 18 rules, each with the code that enforces it and the test that proves
      it. Added for it: static checks (no process spawning, no TCP acceptor under
      `src/control/`), the kill switch (no `[control]`, no socket), a 1 MB body refused
      with 413, a site name with a slash never reaching a file, `fuzz_json`
      (5.83 M runs in 121 s, no finding). Sanitizer run (`-fsanitize=address,undefined`)
      of the unit, integration, root-role, reload and Pebble suites found one real bug:
      `AcmeManager::stop()` cancelled its timer a second time from the destructor after
      worker 0's io_context was gone (heap-use-after-free at every shutdown of a server
      with `tls = "auto"`); fixed, all suites clean. The `Origin` / non-loopback / token
      rules belong to the deferred TCP transport and come with it.
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
- [x] H1 (2026-09-18) Zero-downtime reload: a `Generation` owns a loaded `Config` with
      its routers and TLS contexts; workers hold the current one and connections the one
      they started a request from (`refresh_generation`, one pointer compare per request),
      so anything in flight keeps its configuration alive and keep-alive connections
      switch at the next request boundary. `Server::reload` (SIGHUP, or `agensio reload`
      which validates first and signals `server.pid_file`) loads, runs the hosting rules,
      builds listeners and certificates, opens new log sinks, binds new addresses, then
      posts the generation to every worker, starts the new acceptors and closes the
      removed ones (their connections finish and get Connection: close). Any failure
      before the switch refuses the reload with the old configuration untouched.
      `tests/reload.sh`: 14 checks including a keep-alive connection served across the
      switch without reconnecting, a 1.5 s upstream request finishing through a reload
      that removed its location, and wrk at 750k req/s across six reloads with no error.
      Restart-only: workers, reuse_port, user/group, sendfile, cache sizes (warned).
- [x] H1a (2026-09-18) Stale document root after reloads, found through the reload test
      flaking one run in three: the file cache keyed entries by the location's *pointer*
      plus the path, and after a few reloads a new generation's `LocationConfig` landed
      on the address of a freed one whose entries were still cached and still passing
      revalidation (same size and second), so the old root's file was served. Entries
      are now keyed by `LocationConfig::id`, unique for the process's life (assigned in
      `finalize_site`); a reload therefore starts with a cold cache for the reloaded
      locations, like nginx's new workers. Reproduced with `wrk` across six reloads in
      1 of 8 rounds before, 0 of 40 after. Two acceptor bookkeeping bugs fixed on the
      way: a listener that failed to bind stayed in the table as open, and a removed
      acceptor's slot could be reused before its posted close had run (the close
      lambda held a raw pointer). The other symptom seen once (a raw connection to a
      new listener waiting 5 s) was not reproduced in 35 rounds of that sequence and
      is left under watch.
- [x] H2b (2026-09-19) Hosting rules made consistent, from a live VPS report: the
      "server's group" every rule compares against came from the process running the
      check, so `-t` as root, the dropped server and `agensio pools` disagreed and no
      socket ownership satisfied all of them; a site could reload and then fail to boot
      25 minutes later. Now one helper (`server_account`) derives it from `server.user` /
      `server.group`. Added rule 2b (the server's account can read the root, fix printed),
      the socket message says which side connects, EACCES on a root is reported as such,
      log files are created 0640, a redirect or proxy site has no root at all (the
      static handler answers 404 for an empty root; before, the configuration directory
      was the root), `site NAME` returns the content site rather than its redirect stub,
      `site-create` prescribes `useradd --no-create-home` with the home in the state
      directory and `chown user:<server group> && chmod 2750`, names the real php-fpm
      unit, and gives a user site its own access log. `tests/site-user.sh` (root devbox,
      17 checks) runs the prescribed commands verbatim and asserts `-t`, a restart, a
      clean health check, PHP and static content together.
- [x] H2c (2026-09-19) **Security**: the Laravel preset let an existing second `.php` under
      `public/` fall through to the static handler and served its source as a download
      (found on a live server running Drupal under `app = "laravel"`: `core/install.php`,
      `sites/default/default.settings.php` disclosed; `settings.php` with the database
      password would have followed the install). The preset's "only index.php runs" rule
      now refuses every other `.php` (403 from the static handler before any read), on
      `/` and `/build/`. New `app = "drupal"` for multi-entry-point applications: any
      `.php` runs, front controller for the rest, and Drupal's `.htaccess` protections
      built in natively (source spellings `.inc/.module/.install/...`, dumps, backups,
      library/vendor/upload directories, `settings.php` and friends as 404). WordPress:
      `wp-config.php` answered 404. Unit test asserts that every PHP preset either runs
      `.php` through FastCGI or refuses it on every location it creates; integration
      fixtures for Laravel (second entry point), Drupal (13 checks) and WordPress (4)
      assert on the absence of `<?php` in bodies, not only on status codes.
      Documented: `.htaccess` is never read (section 4c).
- [x] C6 (2026-09-19) PHP presets as data: `kPhpPresets` rows (subdir, index, front
      controller, any-php or front-only, refused suffixes, shields with cache headers,
      404 files) and one expansion; the four existing presets expand identically (diffed
      through `-t --explain`) except that WordPress shields now also refuse `.php8`.
      Next rows, in this order, each with a fixture and a docs section: `symfony`,
      `joomla`, `phpbb`, `nextcloud`, `mediawiki`; test beds for Joomla and Nextcloud.
- [x] H2d (2026-09-19, third live report) A log file added by a reload received nothing:
      every worker sized its per-sink buffers at start and dropped lines for sinks added
      later (silent for five hours on the reporting server; the file existed at 0 bytes and
      health saw nothing). Buffers now grow per worker, the flush timer always runs, and
      `tests/reload.sh` asserts a reload-added log receives the next request. State
      directory parent `/var/lib/agensio` is 0751 (packages, `agensio pools`, install
      guide) with a hosting rule that names the fix, since at 0750 the site user could not
      reach its own tmp/ and PHP reported a misleading open_basedir error; the site-user
      test now writes to `sys_get_temp_dir()` as the pool user. Refused endings answer
      404 like hidden files (one policy, existence never confirmed). `agensio ctl` has a
      help page, `--help` on any subcommand, and a CLI-shaped hint instead of the API's
      JSON when a change lacks `--yes`. Not bugs: the WordPress preset already runs every
      `.php` (fixtures now list seven real entry points); the Drupal preset already exists
      (`site-update NAME --app drupal`).
- [x] H2e (2026-09-19, fourth live report) **Strict host matching and SNI.** A listener's
      first site had been its implicit catch-all, so a named site served every Host
      (forged Host headers reached the application). Now only `server_name = ["*"]` or
      `default = true` is a catch-all; a Host no site lists answers 421 Misdirected
      Request (`Cache-Control: no-store`, constant body) on HTTP/1.1 already, so nothing
      changes when HTTP/2 coalesces connections. Found on the way, and bigger: a TLS
      listener had one OpenSSL context built from its first site and no SNI callback, so
      two HTTPS sites on one address shared the first one's certificate. Each certificate
      now has its own context on the listener and an SNI callback selects the site's;
      a name no site lists is refused with `unrecognized_name`, no SNI gets the
      catch-all's certificate or a refusal. Catch-all visible in `status` and `sites`,
      `site-create` warns when a listener has none. **Breaking**: a single named site no
      longer answers by IP address; the changelog says so. Integration: 15 checks
      (strict listener, two-certificate listener, 8443 catch-all), unit test locks the
      router rule; the HTTP/2 coalescing retry is written as a skipped check.
- [x] H2f (2026-09-20, fifth report) `user: "null"` from an agent that could not send JSON
      null was accepted as an account name and turned into `useradd null` and a recursive
      `chown` of the supplied root. Now every value that reaches a root command is
      validated before any command exists (`valid_account`: pattern, sentinel words,
      system accounts; `safe_path`: absolute, normalised, shell-safe), `prerequisites`
      refuses to assemble a command from a value that would not pass again, `no_user:
      true` is the always-expressible way to say "no account" (JSON null still works,
      both together are refused), the MCP schema types `user` and `group` with the
      pattern, and the decision text names the boolean. Unit test feeds hostile values.
- [x] H2g (2026-09-20, sixth report) `preflight` returns every problem at once with a code
      (`missing_account`, `root_missing`, `root_unreadable`, `certificate_missing`,
      `needs_restart`) and its command; `dry_run` on create/update; a privileged port the
      dropped server cannot bind answers 202 `needs_restart` with the file written and
      validated instead of a failed reload; `next_steps` split into separate commands
      (`agensio pools && systemctl reload` skipped the reload on exit 3); refusals report
      as handler `deny` and locations list what they `refuse`; `health` finds a per-site
      log the site user cannot read (a restart hands it over); the MCP `app` enum was
      already table-driven, now asserted equal to `presets_list` by a test.
- [x] F8 (2026-09-20) Provisioning helper: `services/provision.*`, forked before the drop,
      socketpair only, five validated operations (`account_add`, `site_layout` with an
      `O_NOFOLLOW` walk and the "never another site's directory" rule, `log_own`,
      `pools_apply`, rate-limited `service_restart`), execve by absolute path with a fixed
      argv and empty environment, audited. `Problem.fix` carries the request that resolves
      a prerequisite; `site-create` / `site-update` apply the fixes and report `done`, the
      pool and the log follow, `needs_restart` restarts after the reply. Default on
      (`[control] provision = false` to opt out). `tests/provision.sh` (root devbox): the
      one-call path and the refusals. Security page section written.
- [x] F9 (2026-09-20) `site-install`: `services/archive.*` (own tar/tar.gz/zip extractor,
      Source/Sink, fenced and fuzzed), `services/fetch.*` (blocking https GET with the
      private-address fence on every hop, verified certificate, caps), `services/install.*`
      (target owned by the executing account and empty, download to an unlinked temp file,
      sha256, extract with modes from the target, unwrap a single top directory, empty the
      directory on any failure); helper op `app_install` (child becomes the site account),
      server-side thread when there is no helper; `PUT /v1/uploads/NAME` streamed to
      `<state_dir>/uploads` (0700, `upload_max`), `uploads`, `uploads-delete`; presets carry
      their official `source`; MCP `site_install`, `uploads_list`, `upload_delete`.
      `[control] install`, `install_private`, `install_ca`, `upload_max`. zlib added as a
      dependency. `tests/install.sh` (root devbox), unit, fuzz and integration checks;
      security page rows 19-22.
- [ ] H1b Certificates watched and reloaded when the files change (manual `tls = { cert,
      key }` sites; automatic ones already reload themselves); reload must not stall new
      QUIC connections (nginx's known weakness).
- [~] H2 Start as root, bind, drop privileges (`user =`): **done 2026-09-17 with C3b-3**
      (`server.user`); log rotation via `SIGUSR1`/reopen done with A5; pid file with H1.
      `docs/install.md` (2026-09-18) fixes the directory layout per platform (Linux FHS,
      Homebrew prefix on macOS, ProgramData on Windows), the recommended per-domain site
      tree with its owners, and the Linux steps (service user, directories, unit file,
      first site with `-t`, pools, certificates, logrotate, reload, upgrade/rollback).
      Remaining: ship the unit file and logrotate snippet in the repository, make the
      macOS defaults (`$PREFIX/var/log`, `$PREFIX/var/lib`) and the Windows defaults the
      binary's own, complete the macOS and Windows steps with the release, packages (H7).
- [x] H3 (2026-09-18) Automatic certificates: built-in ACME v2 client (RFC 8555) with
      HTTP-01 (`src/services/acme.*`, JSON in `src/services/json.hpp`, JWS ES256 and CSRs
      through OpenSSL, no new dependency). `tls = "auto"` on a site plus
      `[server] acme = { email, directory, storage, ca }`; any RFC 8555 CA, Let's Encrypt
      by default. Start: placeholder self-signed certificate so the listener is up at
      once, order right away; the dispatcher answers `/.well-known/acme-challenge/<token>`
      before routing on any plain listener (one prefix compare per request); a fresh
      P-256 key per issuance, files written atomically, the new certificate picked up
      through `Server::reload` (H1) so no request is interrupted. Renewal check hourly on
      worker 0, renew at a third of the lifetime left (short-lived profiles work), failed
      orders retried after an hour with the CA's reason in the error log; names added to
      `server_name` reorder. Network work is blocking on the manager's own thread (a few
      requests a year, never on the request path). Storage handed to `server.user` when
      started as root. `tests/acme.sh`: 17 checks against Pebble (`bench/acme/`),
      including chain verification against Pebble's root and a restart keeping the
      certificate. Unit tests: JSON, base64url, JWS sign/verify, renewal rule, config rules.
      Same day: `redirect = "https"` (or an `https://host:port` prefix) on the plain site
      for HTTPS-only setups: 301 to the same host and target, no root needed, the
      challenge still answered first; HSTS stays an explicit `add_headers`.
- [ ] H3a Certificates, next: TLS-ALPN-01 (no port 80), **DNS-01 with a provider
      interface** (HTTP-01-only is the main criticism of nginx's 2025 module and DNS
      challenges are Caddy's second most upvoted request; wildcards need it), external
      account binding (ZeroSSL), OCSP stapling / ARI renewal hints, a stop flag for an
      order in flight at shutdown.
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
- [~] H7 (2026-09-19, first part) Packaging: `packaging/` holds the systemd unit, the
      logrotate file, the packaged `/etc/agensio` (main file plus a default site on
      `/var/www/html`), the Debian maintainer scripts (account, groups, directories,
      conffiles, start when port 80 is free, purge keeps certificates and content), the
      RPM scripts and a COPR spec, and an AUR `PKGBUILD`. CMake gained install rules and
      CPack for DEB and RPM (`cpack -G DEB` in `build/`; Debian version `0.1.0~alpha.1`).
      `tests/package.sh` installs, runs, reinstalls, removes and purges the `.deb` as
      root in the devbox (13 checks). `.github/workflows/release.yml` builds both
      packages on every `v*` tag, checks the binary's version against the tag,
      smoke-installs the `.deb`, attaches both to the release, and publishes a signed
      APT repository to GitHub Pages when the `APT_GPG_PRIVATE_KEY` secret exists;
      `ci.yml` builds and tests on Ubuntu and macOS on a pull request or a manual run
      (`workflow_dispatch`; since 2026-09-20 no longer on every push: the release job
      tests the tagged commit). An `arch` job builds the binary pacman package
      from the `PKGBUILD` in an Arch container and attaches it too (`pacman -U`). First
      release with all three packages: `v0.1.0-alpha.3` (2026-09-19). Lessons from the
      runners: Ubuntu 22.04 needs CMake from an action, GCC 12 and a fetched asio; the
      `runner` account cannot read `/etc/agensio` (0750) and has no `/usr/sbin` on PATH;
      `secrets` is not readable in a step `if`; `gh` inside a container must be told the
      repository because the checkout belongs to another uid; libc++ has no `std::jthread`.
      Remaining: the GPG key and Pages setup for the APT repository, the COPR project and
      the AUR submission (need accounts), Docker image, Homebrew formula, aarch64 builds.
- [ ] H7b CI additions: ASan/UBSan builds and the fuzzers on a schedule; Docker image;
      Homebrew formula; aarch64 packages.
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
