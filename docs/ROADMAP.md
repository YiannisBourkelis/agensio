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

### Phase A. Core refactor: streams, bodies, router  `[ ]`
Prerequisite for everything else. No new features; the static path must benchmark the
same after it (that is the checkpoint).

- [ ] A1 Introduce `Stream`, `Request`, `Response`, `Headers`, `BodySource`; port the static
      handler to produce a `Response` with a memory/file `BodySource`.
- [ ] A2 Split `Connection` into `Http1Connection` (I/O + parser) that drives one `Stream`;
      response writing consumes a `BodySource` (keeps the writev / TLS-coalescing /
      sendfile fast paths exactly as they are today).
- [ ] A3 Request bodies: `Content-Length` and `chunked` decoders as `BodySource`s, size
      limits, `Expect: 100-continue`, body timeouts, `413`.
- [ ] A4 `Router`: sites (Host/SNI) -> ordered `[[site.location]]` blocks (prefix, exact,
      regex later) -> handler; `try_files`; per-location settings. Config schema for it.
- [ ] A5 Access log and error log services (async, per worker buffers, off by default in
      the benchmark config; measured cost when on).
- [ ] Checkpoint: static benchmark equal to phase 1 within noise; new unit tests for body
      decoders and router.

### Phase B. Complete HTTP/1.1 and hardening  `[ ]`
- [ ] B1 Methods: OPTIONS, POST/PUT/DELETE/PATCH passed to handlers; `405` with `Allow`
      per location; `TRACE` rejected.
- [ ] B2 Range requests (single range, `206`, `416`, `If-Range`) on memory and file sources.
- [ ] B3 Compression: serve precompressed `.br`/`.gz` siblings by `Accept-Encoding`; on-the-
      fly gzip/brotli for dynamic responses as an option (measure CPU; off by default).
- [ ] B4 Request-smuggling and parser hardening: CL vs TE rules, obs-fold rejected, header
      count/size limits, URI normalisation edge cases, `Host` validation; libFuzzer target
      for the parser and the chunked decoder run in CI.
- [ ] B5 Timeouts everywhere: header read, body read, write stall, keep-alive idle,
      per-connection request cap; `Connection: close` on shutdown; graceful drain.
- [ ] B6 IPv6 listeners tested; `SO_REUSEPORT` path tested on Linux (Docker).
- [ ] Checkpoint: h1 compliance run (a scripted curl/python suite in `tests/`), fuzzers
      clean for 1h, benchmark unchanged.

### Phase C. Control API and agentic interface  `[ ]`
Cheap, independent, and useful for every later phase (inspect cache, reload config).
- [ ] C1 Control socket: unix domain socket (`/run/agensio.sock`, owner-only) speaking HTTP/1.1
      through the same core; optional loopback TCP listener; token auth for TCP.
- [ ] C2 Read-only commands, JSON and plain text (`Accept: text/plain` gives a human answer):
      `status`, `cache` (count, bytes, hit ratio) and `cache/entries` (path, size, age,
      hits), `sites`, `config` (effective, with sources), `connections`, `metrics`
      (Prometheus text as well).
- [ ] C3 Mutating commands: `config/validate`, `reload` (SIGHUP equivalent, atomic swap of
      config + listeners), `cache/purge` (all or by path), `sites/create` (writes
      `sites.d/<domain>.toml` from a preset: static, laravel, php, proxy; validates;
      reloads), `sites/disable`.
- [ ] C4 Natural-language front: a small intent matcher for the questions in the brief
      ("how many files are in cache?", "create a website in /var/www/x for x.com") mapping
      to C2/C3 commands, answering in text. No model inside the server.
- [ ] C5 Agent integration: expose the same commands as an **MCP server** (Model Context
      Protocol) over the control socket so agentic OS tooling (e.g. Omarchy's Claude/Codex
      setup) can call them as tools; `agensio mcp` subcommand as stdio bridge.
- [ ] C6 CLI: `agensio ctl <command>` wrapping the socket, so shell scripts and panels
      (ISPConfig style) get the same interface.
- [ ] Checkpoint: control traffic measured to add zero cost to data-plane workers (runs on
      worker 0's loop but only when called); docs page with every command.

### Phase D. PHP by design (FastCGI to php-fpm), Laravel first  `[ ]`
- [ ] D1 `FcgiClient`: async FastCGI/1.1 over unix socket or TCP, per-worker connection
      pool with keep-alive (`FCGI_KEEP_CONN`), request body streaming to fpm, response
      header parsing (`Status:`, `Location:`), body streaming back as a `BodySource`,
      timeouts, `502`/`504` mapping, buffering on/off.
- [ ] D2 Parameter set matching nginx's `fastcgi_params` plus `PATH_INFO` splitting,
      `HTTPS`, `REMOTE_ADDR`, `SERVER_PORT`, `REQUEST_SCHEME`, forwarded headers.
- [ ] D3 Config: `php = { socket = "unix:/run/php/php-fpm.sock" }` at site level and
      **presets**: `app = "laravel"` expands to root `public/`, `try_files $uri
      /index.php?$query_string`, deny `.env`/dotfiles, static caching rules; `app = "php"`
      plain; `app = "wordpress"` later.
- [ ] D4 Test bed: Laravel skeleton in `bench/laravel/` served by brew php-fpm (macOS) and
      by ddev's php-fpm in Docker (Linux); integration test hits the welcome route, a JSON
      route, a POST with body, a file upload.
- [ ] D5 Benchmark: Laravel `GET /` and a JSON route through agensio vs nginx (same php-fpm,
      same pool size). Record req/s, CPU per request on the *web server* processes only.
- [ ] Checkpoint: Laravel welcome page served with one worker; benchmark table.

### Phase E. Reverse proxy  `[ ]`
- [ ] E1 `HttpClient`: async HTTP/1.1 upstream, per-worker keep-alive pool, request body
      forwarding, response `BodySource` (chunked/length/close-delimited), streaming
      (SSE) with buffering off, timeouts (connect/read/write), `502`/`504`.
- [ ] E2 Header handling: hop-by-hop stripping, `X-Forwarded-For/Proto/Host`,
      `Forwarded`, `Host` passthrough or rewrite, `proxy_set_header` equivalent.
- [ ] E3 WebSocket / `Upgrade` tunnelling (Rocket.Chat, ThingsBoard need it), plus
      HTTP/2-to-HTTP/1.1 downgrade for upstreams once phase F exists.
- [ ] E4 Upstream groups: several backends, round-robin, passive health marking, retries on
      idempotent requests; TLS to upstream (verify on/off).
- [ ] E5 CGI handler: spawn a process per request with CGI/1.1 env and pipes, for legacy
      applications; async pipes via Asio; concurrency cap.
- [ ] E6 Presets: `app = "proxy"` with `upstream = "http://127.0.0.1:3000"`; examples for
      Node, Rails, Rocket.Chat, ThingsBoard in `docs/examples/`.
- [ ] E7 Benchmark: hello-world Node upstream through agensio vs nginx; WebSocket echo.
- [ ] Checkpoint: Rocket.Chat or a Node app fully usable behind agensio.

### Phase F. HTTP/2  `[ ]`
- [ ] F1 ALPN in `TlsStream` (`h2`, `http/1.1`); `Http2Connection` around an nghttp2
      session: our socket I/O feeds nghttp2, callbacks create/complete `Stream`s, response
      `BodySource`s become DATA frames with flow control honoured.
- [ ] F2 Settings and limits: max concurrent streams, window sizes, header list size,
      priority ignored (RFC 9113), PING/GOAWAY, graceful close.
- [ ] F3 h2c (cleartext upgrade / prior knowledge) optional, off by default.
- [ ] F4 Benchmark with `h2load` (nghttp2) vs nginx `http2 on`: static, Laravel, proxy.
- [ ] Checkpoint: h2spec passes; HTTP/1.1 numbers unchanged (no cost when h2 is idle).

### Phase G. Production hardening  `[ ]`
- [ ] G1 Zero-downtime reload: new config applied by worker 0 atomically; listeners added
      or removed; TLS certs reloaded on change (file watch or `ctl reload`).
- [ ] G2 Start as root, bind, drop privileges (`user =`); systemd unit; pid file; log
      rotation via `SIGUSR1`/reopen.
- [ ] G3 ACME (Let's Encrypt) HTTP-01 and TLS-ALPN-01 built in, or documented certbot
      hooks (open question 6). OCSP stapling.
- [ ] G4 Rate limiting and connection limits per IP; request id header; error pages
      configurable.
- [ ] G5 Metrics endpoint scraped by Prometheus; structured JSON logs option.
- [ ] G6 Memory/CPU profile under 10k idle keep-alive connections; per-connection memory
      budget documented (target: < 8 KB idle h1 connection).
- [ ] G7 Packaging: Debian/Arch packages, Docker image, Homebrew formula; CI on Linux and
      macOS with ASan/UBSan builds and the fuzzers.
- [ ] Checkpoint: runs a real site for a week; documented ops guide.

### Phase H. HTTP/3  `[ ]`
- [ ] H1 UDP listener per worker (one worker first); ngtcp2 with OpenSSL 3.5+ QUIC TLS
      API; connection ids, retry tokens, timers on our loop.
- [ ] H2 nghttp3 session per connection creating `Stream`s exactly like h2.
- [ ] H3 `Alt-Svc` advertising from h1/h2; 0-RTT policy (only idempotent GET);
      connection migration; multi-worker via SO_REUSEPORT + connection-id routing (Linux
      eBPF) later.
- [ ] H4 Benchmark with `h2load --npn-list h3` or `quiche` client vs nginx `quic`.
- [ ] Checkpoint: browsers connect over h3; h1/h2 numbers unchanged.

### Later / ideas
- io_uring backend for Linux (Asio supports it; measure).
- kTLS on Linux: sendfile over TLS.
- Brotli precompression at cache load time.
- Static site presets (Hugo/Astro output), SPA fallback.
- Per-site resource limits (CPU time, memory) for shared hosting panels.

---

## 3. Suggestions

1. **Order: A, B, C, D, E, F, G, H.** PHP and proxy before HTTP/2 because they need the
   async-body core (A) and prove it; HTTP/2 then reuses proven handlers. HTTP/3 last: it
   is the largest dependency and browsers fall back gracefully. Control/agentic early
   (C) because it makes every later phase easier to test and demo.
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

## 4. Open questions (answer before phase A starts)

1. **HTTP/2 and HTTP/3 libraries.** Accept nghttp2 and ngtcp2+nghttp3 as dependencies, or
   write HTTP/2 framing + HPACK ourselves (feasible, ~5k lines, more control, more risk)
   and still use ngtcp2 for QUIC (writing QUIC ourselves is not reasonable)?
2. **Control interface reach.** Unix socket only, or also a loopback HTTP listener with a
   token? Should mutating commands (create site, reload) be on by default or opt-in?
   Where should `sites/create` write: `sites.d/` next to the main config?
3. **PHP test environment.** Local brew `php-fpm` + a Laravel skeleton (fast, macOS), or
   ddev in Docker (closer to production Linux), or both? Is Laravel Octane
   (FrankenPHP/Swoole) in scope, or classic php-fpm only?
4. **Proxy scope for the first cut.** Single upstream per location with WebSocket support,
   or upstream groups with balancing from the start?
5. **Compression policy.** Precompressed files only (zero CPU), or on-the-fly gzip/brotli
   for PHP/proxy responses too?
6. **Certificates.** Built-in ACME like Caddy (big convenience, a few thousand lines), or
   rely on certbot/acme.sh with a reload hook?
7. **Platforms.** Linux (Debian/Arch) production and macOS development are given. Does
   Windows need to keep compiling, or can it be dropped to simplify the network code?
8. **Logging default.** Access log off by default (fastest) or on with a cheap format?
