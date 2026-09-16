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
- [ ] A5 Access log and error log services: "combined" format (fail2ban filters for
      nginx/apache work unchanged), optional JSON, per-worker buffers flushed by a timer or
      size, reopen on `SIGUSR1`/`ctl reopen` for rotation. Configurable per site; the
      benchmark config turns it off. Decide the default after measuring: nginx and Apache
      log by default, Caddy does not; recommendation is on if the cost is < 1 us/request.
- [ ] Checkpoint: static benchmark equal to phase 1 within noise; new unit tests for body
      decoders and router.

### Phase B. Complete HTTP/1.1 and hardening  `[ ]`
- [ ] B1 Methods: OPTIONS, POST/PUT/DELETE/PATCH passed to handlers; `405` with `Allow`
      per location; `TRACE` rejected.
- [ ] B2 Range requests (single range, `206`, `416`, `If-Range`) on memory and file sources.
- [ ] B3 Compression, off by default, per site/location: `compression = "precompressed"`
      serves `.br`/`.gz` siblings by `Accept-Encoding` (no CPU); `compression = "on-the-fly"`
      gzip/brotli for dynamic responses with level setting; measure and document the
      CPU and latency cost of each.
- [ ] B4 Request-smuggling and parser hardening: CL vs TE rules, obs-fold rejected, header
      count/size limits, URI normalisation edge cases, `Host` validation; libFuzzer target
      for the parser and the chunked decoder run in CI.
- [ ] B5 Timeouts everywhere: header read, body read, write stall, keep-alive idle,
      per-connection request cap; `Connection: close` on shutdown; graceful drain.
- [ ] B6 IPv6 listeners tested; `SO_REUSEPORT` path tested on Linux (Docker).
- [ ] Checkpoint: h1 compliance run (a scripted curl/python suite in `tests/`), fuzzers
      clean for 1h, benchmark unchanged.

### Phase C. Control API and agentic interface  `[ ]`
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
- [ ] C0 Security design, implemented before any command exists:
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
- [ ] C1 Control socket: unix domain socket (`/run/agensio.sock`) speaking HTTP/1.1 + JSON
      through the same core; optional loopback TCP listener with the token; remote only
      with mTLS. One API, several transports, one permission model.
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
- [ ] C5 MCP server (decided 2026-09-16, first-class feature): expose the same commands as
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
- [ ] C6 CLI: `agensio ctl <command>` wrapping the socket, so shell scripts and panels
      (ISPConfig style) get the same interface.
- [ ] C7 Security review of the phase: a written checklist against the threat model above,
      tests for each rule (wrong uid refused, `Origin` refused, non-loopback bind refused,
      token rate limit, symlink escape in `sites/create` refused, viewer cannot mutate),
      and a fuzz target for the JSON command parser.
- [ ] Checkpoint: control traffic measured to add zero cost to data-plane workers (runs on
      worker 0's loop but only when called); docs page with every command, every role and
      the threat model.

### Phase D. PHP by design (FastCGI to php-fpm), Laravel first  `[ ]`
- [ ] D1 `FcgiClient`: async FastCGI/1.1 over unix socket or TCP, per-worker connection
      pool with keep-alive (`FCGI_KEEP_CONN`), request body streaming to fpm, response
      header parsing (`Status:`, `Location:`), body streaming back as a `BodySource`,
      timeouts, `502`/`504` mapping, buffering on/off.
- [ ] D2 Parameter set matching nginx's `fastcgi_params` plus `PATH_INFO` splitting,
      `HTTPS`, `REMOTE_ADDR`, `SERVER_PORT`, `REQUEST_SCHEME`, forwarded headers.
- [ ] D3 Config: `php = { socket = "unix:/run/php/php-fpm.sock" }` at site level and
      **presets** (future todo, agreed 2026-09-16): `app = "laravel"` expands to root
      `public/`, `try_files $uri /index.php?$query_string`, deny `.env`/dotfiles, static
      caching rules; `app = "php"` plain; `app = "wordpress"`, `app = "proxy"`,
      `app = "static"` later. A preset is the whole config for a common site; every
      expansion is printable with `agensio -t --explain` so nothing is hidden.
- [ ] D4 Test bed: Laravel skeleton as a ddev project (`bench/laravel/` with `.ddev/`),
      agensio connecting to ddev's php-fpm (expose port 9000 from the web container via a
      `docker-compose.agensio.yaml` override, or run agensio inside the container as a
      custom webserver); integration test hits the welcome route, a JSON route, a POST
      with body, a file upload. Same setup on macOS and Linux.
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
- [ ] E4 Upstream groups from the start: `upstream = ["http://a:3000", "http://b:3000"]`,
      round-robin, passive health marking (N failures -> down for T seconds), retries on
      idempotent requests only; TLS to upstream (verify on/off). No active checks or
      weights until needed.
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
- [ ] G3 Certificates: built-in ACME client (HTTP-01 and TLS-ALPN-01, Let's Encrypt and any
      RFC 8555 CA), automatic renewal, cross-platform; until then documented reload hooks
      for certbot / win-acme / acme.sh. OCSP stapling.
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
   Created sites are written to `sites.d/`. Full threat model and rules: phase C0.
3. **PHP test bed: ddev** (present on both macOS and Linux dev machines). php-fpm only;
   Octane out of scope.
4. **Proxy: upstream groups from the first cut**, kept simple: list of backends,
   round-robin, passive health marking (N failures -> down for T seconds), retries on
   idempotent requests only. No active health checks, no weights, until asked for.
   General rule: take the good parts of nginx and other servers, keep it simple and stable.
5. **Compression is a per-site/location setting, off by default.** Precompressed siblings
   (`.br`, `.gz`) cost nothing and are served when present and enabled; on-the-fly
   gzip/brotli is a separate switch with a measured CPU/latency cost documented.
6. **Certificates: later (phase G), automatic once set up, cross-platform.** Built-in ACME
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
| daemon / service | systemd unit | Windows service (`agensio --service`) | phase G |
| process spawn (CGI, php-cgi) | `posix_spawn` + pipes | `CreateProcess` + pipes | `os::Process` |
| paths | case-sensitive, `/` | case-insensitive, `\`, reserved names (`CON`, `NUL`), trailing dots/spaces, `::$DATA` streams | path normaliser gets a Windows mode; deny-rules compare case-insensitively |
| PHP | php-fpm (unix socket / TCP) | `php-cgi.exe -b 127.0.0.1:9000` (FastCGI over TCP) | same FastCGI client |
| kTLS, io_uring | Linux only | n/a | optional accelerators, never required |

Estimated share of OS-specific code: under 10 %, all in `src/os/`. A GitHub Actions matrix
(Linux, macOS, Windows) builds and runs the unit tests from phase A on; the integration
suite runs on Linux and macOS.
