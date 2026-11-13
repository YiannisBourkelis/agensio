# Feature set of a "feature complete" general-purpose web server, November 2026: matrix of the established servers

Researcher's notes, written 2026-11-13. Reading conventions used throughout:

- **[F]** = the fact was read on the cited page in this session (WebFetch or a search result quoting it).
- **[K]** = the fact is from my knowledge of the cited documentation page (training data up to mid-2026), the page was **not** re-fetched in this session. Treat as "very likely, verify before quoting a default".
- Abbreviations in matrices: **N** nginx open source, **N+** NGINX Plus only, **A** Apache httpd 2.4, **C** Caddy 2.x (core build; "plugin" = needs an xcaddy build), **LSWS** LiteSpeed Enterprise, **OLS** OpenLiteSpeed, **H** h2o, **HAP** HAProxy, **T** Traefik (OSS; "Hub" = paid).
- "Use" column (high / medium / low for PHP-and-app hosting on a VPS) is my judgement, not a measured statistic, unless a source is given.
- Version context: nginx mainline is 1.31.8 (21 Oct 2026) [F]; Caddy is in the 2.11.x line (2.11.8 seen) [F]; Angie 1.12.4 (16 Oct 2026) [F]; HAProxy 3.4 is "the latest version" per haproxy.com [F]; Apache is 2.4.x; h2o has no tagged releases since 2019 [F].
- Injection check: none of the fetched pages or search results contained text that tried to give me instructions. (The only imperative text was the search tool's own "include the sources" reminder, which is tool boilerplate, not page content.)
- Search queries used only generic terms; no workspace, project or personal names were sent anywhere.

---

## 0. Objective: usage, the condensed matrix, and the judgement for a 1.0 (table stakes / differentiators / niche)

### Takeaway
Five things are universal across every server that serves sites directly (nginx, Apache, Caddy, LiteSpeed/OLS, h2o) and are the hard floor of a 1.0: name-based virtual hosts with TLS/HTTP/2 (HTTP/3 now in all of them), static serving with index/fallback/error pages/Range/conditional requests/compression, FastCGI to PHP, a reverse proxy with WebSocket and timeouts, and reload-without-drop plus a config test. What divides them, and what users argue about, is everything one level up: automatic certificates (now in all, including nginx since 2025), response caching for PHP (nginx and LiteSpeed have it built in and WordPress hosts rely on it; Caddy does not and is criticised for it), per-IP rate limiting (nginx/LiteSpeed/HAProxy/Traefik built in; Apache and Caddy not in core), active health checks (everyone but nginx open source), and `.htaccess` (Apache and LiteSpeed only).

### Cited Findings

**Usage (who the market actually runs)**
- W3Techs, 13 Nov 2026, share of websites whose server is known (a site can count twice): Cloudflare Server 33.8 %, Nginx 30.0 %, Apache 20.9 %, LiteSpeed 13.4 %, Node.js 7.5 %, Microsoft-IIS 2.9 %, Caddy 1.2 %, Google Servers 1.1 %, Envoy 0.5 %; Tengine 0.1 %; Lighttpd and about 90 others under 0.1 % each. h2o, OpenResty and Traefik are not listed separately. [F] — [W3Techs](https://w3techs.com/technologies/overview/web_server)
- Netcraft July 2026: all hostnames nginx 20.37 % (21.10 % in June, 22.58 % in March), Cloudflare 16.67 %, Apache 11.50 %, OpenResty 8.02 %; busiest million sites Cloudflare 28.29 %, nginx 20.02 %, Apache 15.56 %, LiteSpeed 3.88 %; web-facing computers nginx 43.92 %, Apache 18.82 %, Microsoft 5.73 %. [F, via search result quoting the survey] — [Netcraft July 2026](https://www.netcraft.com/blog/july-2026-web-server-survey)
- A newer Netcraft survey than July 2026 was not found in the search results; the November figure is a gap.

**The 2025–2026 shift that changes the baseline: nginx open source absorbed a list of former Plus features**
- DNS re-resolution of upstream names (`resolve`, `resolver` in `upstream`, `service`): open source since 1.27.3 (26 Nov 2024); "Prior to version 1.27.3, this parameter was available only as part of our commercial subscription." [F] — [ngx_http_upstream_module](https://nginx.org/en/docs/http/ngx_http_upstream_module.html), [CHANGES](https://nginx.org/en/CHANGES)
- Early hints (103) from proxy and gRPC backends, `early_hints`: 1.29.0 (24 Jun 2025). [F] — [CHANGES](https://nginx.org/en/CHANGES)
- HTTP/2 to backends in `ngx_http_proxy_module` (`proxy_http_version 2`): 1.29.4 (9 Dec 2025). [F] — [CHANGES](https://nginx.org/en/CHANGES), [ngx_http_proxy_module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- Session affinity (`sticky`, `route`, `drain`): open source since 1.29.6 (10 Mar 2026); "Prior to version 1.29.6, this directive was available only as part of our commercial subscription." [F] — [ngx_http_upstream_module](https://nginx.org/en/docs/http/ngx_http_upstream_module.html)
- Upstream keep-alive on by default (`keepalive 32 local;`), `proxy_http_version` default 1.1, `Connection` header no longer sent by default: 1.29.7 (24 Mar 2026). Before that every nginx proxy needed three lines of boilerplate to reuse upstream connections. [F] — [CHANGES](https://nginx.org/en/CHANGES), [ngx_http_upstream_module](https://nginx.org/en/docs/http/ngx_http_upstream_module.html)
- `least_time` balancing: open source since 1.31.0 (13 May 2026). [F] — [ngx_http_upstream_module](https://nginx.org/en/docs/http/ngx_http_upstream_module.html)
- ACME: `ngx_http_acme_module`, a separate dynamic module (`nginx-module-acme` package, source at github.com/nginx/nginx-acme), HTTP-01 (default) and TLS-ALPN-01; DNS-01 not mentioned; also packaged for Plus "since 1.29.0". [F] — [ngx_http_acme_module](https://nginx.org/en/docs/http/ngx_http_acme_module.html)
- Control API (`/1/control/processes`, `/1/control/config`; a PATCH reloads and returns the result as JSON): open source in 1.31.5 (2 Sep 2026), "first shipped in NGINX Plus R37.0"; built only with `--with-control-api`; meant for a UNIX socket (`nginx -l unix:...`), described as an "open unauthenticated interface to NGINX internals". [F] — [NGINX blog, 1.31.5](https://blog.nginx.org/?p=75128), [configure options](https://nginx.org/en/docs/configure.html)
- Predicate locations (`location $variable`), `client_body_early_read`, `ngx_http_json_module`: 1.31.5. [F] — [NGINX blog, 1.31.5](https://blog.nginx.org/?p=75128)
- MaxMind MMDB support in the geoip modules, QUIC reconfiguration and binary upgrade with `quic_bpf`, RFC 9218 priorities for HTTP/2 (RFC 7540 priority ignored): 1.31.7 (14 Oct 2026). [F] — [CHANGES](https://nginx.org/en/CHANGES)
- PROXY protocol v2 output in stream and mail: 1.31.4. [F] — [CHANGES](https://nginx.org/en/CHANGES)
- HTTP/2 server push removed from nginx in 1.25.1 (2023); TLSv1 and 1.1 disabled by default in 1.27.3. [F] — [CHANGES](https://nginx.org/en/CHANGES)
- **Still commercial-only on nginx.org's own pages** (checked this session): active health checks (`ngx_http_upstream_hc_module`: "This module is available as part of our commercial subscription"), the statistics/dynamic-upstream REST API (`ngx_http_api_module`, same sentence), `proxy_cache_purge` and the cache `purger`, upstream `queue`, `slow_start`, `ntlm`, `state`, `sticky learn ... sync`, resolver `status_zone`, `proxy_next_upstream denied`. [F] — [upstream_hc](https://nginx.org/en/docs/http/ngx_http_upstream_hc_module.html), [api](https://nginx.org/en/docs/http/ngx_http_api_module.html), [proxy](https://nginx.org/en/docs/http/ngx_http_proxy_module.html), [upstream](https://nginx.org/en/docs/http/ngx_http_upstream_module.html)
- The nginx.org module index now lists `auth_jwt`, `oidc`, `keyval`, `status`, `session_log`, `f4f`, `hls`, `internal_redirect`, `num_map`, `auth_require`, `proxy_protocol_vendor`, `zone_sync`, `mgmt` alongside the open-source modules with no marker on the index page; the per-module pages for these were not opened in this session, so their commercial status is not verified here (they have historically been Plus-only). [F for the listing] — [nginx documentation index](https://nginx.org/en/docs/)

**Condensed matrix (detail and sources in sections 1–6)**

| Feature | N | A | C | LSWS / OLS | H | Default on? | Use |
|---|---|---|---|---|---|---|---|
| Name-based vhosts, SNI | yes | yes | yes | yes / yes | yes | n/a | high |
| HTTP/2 | yes (`--with-http_v2_module`, in packages) | mod_http2 (2.4.17) | yes | yes / yes | yes | C: on. N, A: per-site switch | high |
| HTTP/3 | yes (`--with-http_v3_module`; experimental 1.25.0, 0-RTT 1.29.1) | no module in the 2.4 index | yes | yes / yes | yes | C: on. N: off | medium, rising |
| Automatic certificates (ACME) | separate dynamic module (HTTP-01, TLS-ALPN-01) | mod_md (2.4.30) | built in, default, all three challenges, on-demand | [K] built-in ACME in recent LSWS/OLS not verified | no | C only | high |
| index / try_files-style fallback / error pages | yes | yes | yes | yes | yes (fallback via internal redirect) | index on | high |
| Directory listing | autoindex | mod_autoindex | `file_server browse` | yes | `file.dirlisting` | off everywhere (Apache: on where `Options Indexes`) | low on app hosting |
| gzip / brotli / zstd on the fly | gzip built in; brotli, zstd third-party | deflate, brotli (2.4.26); no zstd module in index | gzip + zstd in core (`encode`), brotli plugin | gzip + brotli / same | gzip + brotli | off in N source, C, H until configured | high |
| Precompressed siblings | `gzip_static` (not built by default) | by rewrite/negotiation recipe | `precompressed` | static gzip/br cache [K] | `file.send-compressed` [K] | off | medium |
| Rewrite with regex | rewrite module | mod_rewrite | `rewrite`, `uri`, regexp matchers (RE2) | Apache-compatible | redirect + mruby | n/a | high |
| `.htaccess` | no | yes (`AllowOverride None` default) | no | full / rewrite rules only, restart needed | no | — | high among shared hosts |
| FastCGI (PHP-FPM) | yes | mod_proxy_fcgi | `php_fastcgi` | LSAPI (+FastCGI) | yes | n/a | high |
| Response cache for PHP/proxy | proxy/fastcgi cache; purge is Plus | mod_cache | plugin only | LSCache built in (ESI: LSWS only) | none [K] | off | high for WordPress |
| Reverse proxy + WebSocket | yes (manual Upgrade headers [K]) | mod_proxy (+wstunnel) | yes, automatic | yes | yes | n/a | high |
| Active health checks | **N+ only** | mod_proxy_hcheck (2.4.21) | yes | not found | no [K] | off | medium |
| Per-IP request rate limit | limit_req / limit_conn | not in core (mod_ratelimit is bandwidth) | plugin only | per-client throttling built in | mruby DoS detector | off | medium-high |
| Basic auth, allow/deny | yes | yes | yes | yes | yes | n/a | high |
| Config test, graceful reload | `-t`, HUP, USR2 upgrade | configtest, graceful | `validate`, API reload | yes | `-t`, start_server | n/a | high |
| Metrics endpoint | stub_status (not built by default) | mod_status | Prometheus `metrics` | Prometheus exporter | status handler | off | medium |
| Runtime config API | control API (1.31.5, reload only); rich API is N+ | no | admin API, full config | WebAdmin GUI | no | C: on (localhost) | low-medium |

### Inferences

**Table stakes for a 1.0 aimed at PHP and application hosting on a VPS** (present in every one of nginx, Apache, Caddy, LiteSpeed; absence would be the first thing a migrating administrator hits):
1. Virtual hosts by name with SNI; TLS 1.2/1.3; HTTP/2; automatic certificates by HTTP-01. Automatic HTTPS stopped being a Caddy differentiator in 2025 when nginx shipped an official ACME module; Apache has had mod_md since 2018 and HAProxy has experimental ACME since 3.2. A 1.0 without wildcard (DNS-01) support is in the company of nginx's and HAProxy's ACME, which also lack it.
2. Static serving: index files, a `try_files` equivalent, custom error pages, MIME table with overrides, Range, ETag/Last-Modified/conditional requests, gzip and brotli (zstd is in Caddy core and arriving elsewhere), precompressed siblings, per-path response headers and cache lifetimes, redirects.
3. PHP through FastCGI with correct script/path-info handling, plus whatever isolates sites from each other (the panels all do per-site PHP-FPM pools and users).
4. Reverse proxy: HTTP/1.1 keep-alive to origins, WebSocket upgrade, `X-Forwarded-*`, connect/read/send timeouts, request and response buffering switches, body size limit, passive failure detection and retry to the next origin, round-robin over a group. All seven products have these.
5. Regex-capable rewrite and redirect rules. Every server has them and every migration guide is written in them; the one server that tried to be minimal here (h2o) pushes users to mruby.
6. Limits: header/body size, header/body/idle timeouts (slowloris), a connection ceiling. Per-IP request limiting is built into nginx, LiteSpeed, HAProxy and Traefik and missing from Apache's and Caddy's cores, so it is "expected by nginx users" rather than universal; Caddy's lack of it is a standing complaint (section 8).
7. Basic auth and IP allow/deny; client IP from trusted proxies (`realip`/`trusted_proxies`).
8. Access log in combined format (what fail2ban, GoAccess, AWStats and panels parse) and JSON; error log with levels; reopen-on-signal for logrotate.
9. Operations: config test with usable messages, reload without dropping connections, systemd unit, privilege drop, distribution packages with a repository, a container image, complete reference documentation.
10. HTTP/3: all five web servers now have it. It is still off by default in nginx and absent from Apache 2.4, so it is expected-but-not-yet-floor.

**Expected by the WordPress hosting segment specifically, not universal:**
- A response cache for FastCGI/proxied answers with cache key control, bypass on cookies, lock, stale-on-error and purge. nginx (`fastcgi_cache`, purge through the third-party module because the official one is Plus) and LiteSpeed (LSCache with the WordPress plugin) are the two servers that dominate WordPress hosting, and both sell on this. Caddy has it only as a plugin and reviewers call that less mature.
- `.htaccess` compatibility: only Apache and LiteSpeed have it; LiteSpeed's 13.4 % share rests largely on being a drop-in for Apache on cPanel-style hosts. nginx reached 30 % without it, with panels covering the gap by templates, a hybrid nginx+Apache stack, or app-specific presets. A new server does not need `.htaccess`, but it needs an answer to "my plugin wrote rules into `.htaccess`".
- Directory listing: all five have it, off by default; low use on application sites but its absence is noticed for download/mirror sites.

**Differentiators (some have them; users choose a server for them):**
- Zero-config HTTPS with on-demand certificates and DNS-01 (Caddy).
- Built-in page cache with tag-based purge and ESI, and a managed PHP runtime (LiteSpeed LSCache + LSAPI; FrankenPHP for Caddy).
- Full runtime configuration API (Caddy admin API; NGINX Plus API; Traefik providers; HAProxy runtime API).
- Active health checks, slow start, queueing, sticky sessions, least-time balancing (HAProxy has all in open source; nginx keeps health checks, slow start and queue in Plus).
- Native Prometheus metrics and OpenTelemetry tracing (Caddy, Traefik, HAProxy; nginx through separate modules).
- JWT/OIDC at the edge (NGINX Plus, Traefik Hub; HAProxy has JWT verification in open source [K]).
- WAF integration (ModSecurity with Apache/nginx/OLS; Coraza with Caddy/Traefik).
- Anti-DDoS built into the server with CAPTCHA challenge (LiteSpeed).
- Memory safety (Caddy/Go; the Rust entrants) is used as a headline by every new server.

**Niche (present in one or two servers, low use for the target audience; safe to leave out of a 1.0):** SSI, ESI, WebDAV, image filter, XSLT, mp4/flv pseudo-streaming, slice, secure links (signed URLs), random index, userid/usertrack, memcached pass, SCGI and uwsgi protocols, plain CGI, digest auth, LDAP/DBD auth, mail proxy, TCP/UDP stream proxy (core for a load balancer, niche for a site host), request mirroring, split-clients A/B, embedded scripting (njs/Lua/mruby/perl), forward-proxy CONNECT, gRPC-Web bridging, content negotiation/MultiViews, mod_speling, per-user directories.

### Gaps
- No source gives measured adoption of individual directives (how many sites use autoindex, limit_req, fastcgi_cache, ...). All "Use" ratings are judgement.
- LiteSpeed's 13.4 % is not split between Enterprise and OpenLiteSpeed by W3Techs.
- The November 2026 Netcraft survey was not retrieved.
- Whether a stable nginx 1.30 branch exists was not verified; it is implied by the numbering (mainline 1.31 began 13 May 2026 after 1.29.8 on 7 Apr 2026) but the stable release notes were not read.

---

## 1. Static serving

### Takeaway
Index, fallback, error pages, MIME, Range and validators are identical everywhere and on by default; compression and directory listing exist everywhere but are off until configured; the long tail (X-Accel-Redirect, bandwidth limits, signed links, media seeking, slice, WebDAV, SSI, image filter) is where nginx and Apache are broad and Caddy/h2o deliberately narrow, with Caddy pushing the tail to plugins.

### Cited Findings

| Feature | Who has it, and how | Default | Use |
|---|---|---|---|
| Directory listing | N `ngx_http_autoindex_module` (built by default: it is in the `--without-` list) [F] — [configure](https://nginx.org/en/docs/configure.html). A `mod_autoindex` [F] — [Apache module index](https://httpd.apache.org/docs/2.4/mod/). C `file_server browse` with sorting, filter, grid, JSON API, custom template [F] — [Caddy features](https://caddyserver.com/features). H `file.dirlisting` [K] — [h2o file directives](https://h2o.examp1e.net/configure/file_directives.html). Ferron: "Directory listing is optional" [F] — [Ferron README](https://github.com/ferronweb/ferron) | Off in N, C, H; Apache lists when `Options Indexes` is set (built-in `Options` default is `FollowSymLinks` [K, WebFetch model's recollection] — [core](https://httpd.apache.org/docs/2.4/mod/core.html)) | low |
| Index files | N `ngx_http_index_module`, A `mod_dir` ("trailing slash redirects and serving directory index files"), C index files, H File group [F] — [nginx index](https://nginx.org/en/docs/), [Apache module index](https://httpd.apache.org/docs/2.4/mod/), [Caddy features](https://caddyserver.com/features), [h2o configure](https://h2o.examp1e.net/configure.html) | on | high |
| Fallback to a front controller | N `try_files` [K] — [ngx_http_core_module](https://nginx.org/en/docs/http/ngx_http_core_module.html). C `try_files` "Rewrite that depends on file existence" [F] — [Caddyfile directives](https://caddyserver.com/docs/caddyfile/directives). A `FallbackResource` (mod_dir) or `RewriteCond -f` [K] — [mod_dir](https://httpd.apache.org/docs/2.4/mod/mod_dir.html). H: internal redirect (`redirect` with `internal: YES`) [K] — [h2o redirect directives](https://h2o.examp1e.net/configure/redirect_directives.html) | n/a | high |
| Custom error pages | N `error_page` [K]; A `ErrorDocument` (no default; local path, text or URL; 401 must be local) [F] — [core](https://httpd.apache.org/docs/2.4/mod/core.html); C `handle_errors` "Defines routes for handling errors" [F] — [Caddyfile directives](https://caddyserver.com/docs/caddyfile/directives); H Errordoc group [F] — [h2o configure](https://h2o.examp1e.net/configure.html); T `Errors` middleware [F] — [Traefik middlewares](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | built-in pages | high |
| MIME handling | N `types`/`default_type` [K]; A `mod_mime`, plus `mod_mime_magic` (content sniffing) [F] — [Apache module index](https://httpd.apache.org/docs/2.4/mod/) | on | high |
| Range, ETag, Last-Modified, conditional | C: "conditional requests (ETag, Last-Modified...), range requests" [F] — [Caddy features](https://caddyserver.com/features). A `FileETag` default `MTime Size` (was `INode MTime Size` before 2.3.14) [F] — [core](https://httpd.apache.org/docs/2.4/mod/core.html). N `etag on` default [K] | on | high |
| sendfile | C uses sendfile [F] — [Caddy features](https://caddyserver.com/features). A `EnableSendfile` default **Off** since 2.3.9 (platform and network-filesystem bugs) [F] — [core](https://httpd.apache.org/docs/2.4/mod/core.html). N `sendfile off` in source default, `on` in the shipped nginx.conf [K] | mixed | high |
| On-the-fly compression | N `ngx_http_gzip_module` built by default; no brotli/zstd module in the official index [F] — [nginx index](https://nginx.org/en/docs/), [configure](https://nginx.org/en/docs/configure.html). A `mod_deflate`, `mod_brotli` (2.4.26); no zstd module in the 2.4 index [F] — [Apache module index](https://httpd.apache.org/docs/2.4/mod/), [new features](https://httpd.apache.org/docs/2.4/new_features_2_4.html). C `encode`: "gzip, zstd, brotli" listed [F] — [Caddy features](https://caddyserver.com/features) (brotli encoding is a plugin in practice [K]). LSWS and OLS: "GZIP and Brotli compression" in both [F] — [OLS: should you upgrade](https://openlitespeed.org/?p=8058). H Compress group [F] — [h2o configure](https://h2o.examp1e.net/configure.html). T `Compress` middleware [F]. HAP "HTTP compression offload" [F] — [HAProxy intro](https://docs.haproxy.org/3.2/intro.html) | off until a directive in N (source), C, H, T | high |
| Precompressed files | N `gzip_static` needs `--with-http_gzip_static_module`; `gunzip` likewise [F] — [configure](https://nginx.org/en/docs/configure.html). C "Precompressed files (brotli, zstd, gzip)" [F] — [Caddy features](https://caddyserver.com/features) | off | medium |
| X-Accel-Redirect / X-Sendfile | N honours `X-Accel-Redirect`, `X-Accel-Expires`, `X-Accel-Limit-Rate`, `X-Accel-Buffering`, `X-Accel-Charset` from origins unless listed in `proxy_ignore_headers` [F] — [proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html). C: "The X-Accel-Redirect pattern is supported this way" through `handle_response` (a recipe, not a switch) [F] — [reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy); `intercept` directive "Intercept responses written by other handlers" [F] — [Caddyfile directives](https://caddyserver.com/docs/caddyfile/directives). H Reproxy group (`X-Reproxy-URL`) [F for the group] — [h2o configure](https://h2o.examp1e.net/configure.html). A: third-party mod_xsendfile [K, no official page] | N: on for proxied answers | medium (Laravel, Rails, Nextcloud, download sites) |
| Bandwidth throttling | N `limit_rate`, `limit_rate_after`; `proxy_limit_rate` etc. take variables since 1.27.0 [F for the latter] — [CHANGES](https://nginx.org/en/CHANGES). A `mod_ratelimit` "Bandwidth Rate Limiting for Clients" [F] — [Apache module index](https://httpd.apache.org/docs/2.4/mod/). H "Throttle Response" group [F] — [h2o configure](https://h2o.examp1e.net/configure.html). LSWS per-client inbound/outbound bandwidth throttling, and per-vhost throttling since 5.0 [F] — [LiteSpeed anti-DDoS](https://docs.litespeedtech.com/lsws/cp/cpanel/antiddos/) | off | low |
| Signed URLs | N `ngx_http_secure_link_module`, not built by default [F] — [configure](https://nginx.org/en/docs/configure.html). T: HMAC middleware is Hub-only [F] — [Traefik middlewares](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/) | off | low |
| mp4 / flv seeking, HLS, slice | N `mp4`, `flv`, `slice` exist but are `--with-` (not default) [F] — [configure](https://nginx.org/en/docs/configure.html); `hls`, `f4f` are in the index (historically Plus) [F] — [nginx index](https://nginx.org/en/docs/) | off | low |
| charset | N `ngx_http_charset_module` (default build) [F]; A `mod_charset_lite` [F] | off | low |
| WebDAV | N `ngx_http_dav_module` (`--with-`; 1.31.0 tightened COPY/MOVE) [F] — [configure](https://nginx.org/en/docs/configure.html), [CHANGES](https://nginx.org/en/CHANGES). A `mod_dav`, `mod_dav_fs`, `mod_dav_lock` [F]. C: WebDAV listed among handlers [F] — [Caddy features](https://caddyserver.com/features) (a plugin [K]) | off | low |
| SSI | N `ngx_http_ssi_module` (default build) [F]; A `mod_include` [F]; C `templates` "Execute templates on the response" (different language, same job) [F] | off | low |
| Image filter | N `image_filter` (`--with-`, dynamic) [F]; C image filtering listed [F] (plugin [K]) | off | low |
| Response body substitution | N `sub` (`--with-`) [F]; A `mod_substitute`, `mod_sed` [F] | off | low |

### Inferences
- The universally present, default-on set is small: index, validators, Range, MIME, built-in error pages. Everything else is opt-in everywhere, so "has it, off by default" is the normal state, not a weakness.
- nginx's packaging hides how much is optional at build time: `gzip_static`, `auth_request`, `realip`, `stub_status`, `secure_link`, `mp4`, `slice`, `dav`, `sub`, even `ssl`, `v2` and `v3` are all `--with-` options. Distribution packages turn nearly all of them on, so users perceive them as core.
- A server that has index, fallback, error pages, validators, Range, gzip+brotli(+zstd), precompressed twins, header rules, and X-Accel-Redirect-style internal redirect covers what PHP and proxied applications need; directory listing is the one remaining static feature all five incumbents ship.
- zstd as a content coding is ahead in Caddy (core) and behind in nginx and Apache (no official module in either index as of Nov 2026).

### Gaps
- Not verified this session: h2o's `file.send-compressed` and `file.dirlisting` defaults, OLS static compression cache behaviour, LiteSpeed's `X-LiteSpeed-Location` internal redirect, LiteSpeed media seeking. The OLS knowledge-base comparison page returned HTTP 403.
- Whether Caddy core has any bandwidth throttle was not confirmed (I believe it does not).
- No usage numbers for X-Accel-Redirect or directory listing.

---

## 2. Routing and rewriting

### Takeaway
Regex rewrite/redirect and a map-like lookup exist in all the web servers; `.htaccess` is Apache/LiteSpeed-only and is the single most consequential routing difference for PHP hosting. nginx's 2026 "predicate locations" and Caddy's matchers/CEL show the direction: routing on arbitrary request properties rather than only on the path.

### Cited Findings
- **nginx**: `ngx_http_rewrite_module`, `map`, `geo`, `split_clients`, `referer`, `browser`, `mirror` are all built by default; `auth_request` and `realip` are not (`--with-`). [F] — [configure](https://nginx.org/en/docs/configure.html)
- **nginx predicate locations** (1.31.5): "any variable can now be used as a predicate in a location definition", e.g. `location $is_ai_scraper`; checked after regex locations; `client_body_early_read` lets nginx read and parse the body before choosing a location, and `json_set` extracts JSON fields into variables. [F] — [NGINX blog](https://blog.nginx.org/?p=75128); ordering detail from a secondary write-up [F] — [pbxscience](https://pbxscience.com/nginx-1-31-5-released-predicate-locations-let-routing-decisions-follow-variables-not-just-uris/)
- **nginx** startup with many locations was sped up in 1.25.3; `add_header_inherit` (1.29.3) addresses the long-criticised rule that an `add_header` in a location discards the parent's. [F] — [CHANGES](https://nginx.org/en/CHANGES)
- **Apache**: `mod_rewrite` ("rule-based rewriting engine"), `mod_alias` (Redirect, RedirectMatch, Alias), `mod_setenvif`, `mod_macro` (2.4.5), `<If>/<ElseIf>/<Else>` and a general expression parser, `Define` variables, `AllowOverrideList` for fine-grained `.htaccess` control. [F] — [Apache module index](https://httpd.apache.org/docs/2.4/mod/), [new features 2.4](https://httpd.apache.org/docs/2.4/new_features_2_4.html)
- **Apache `.htaccess`**: `AllowOverride` default is `None` [F] — [core](https://httpd.apache.org/docs/2.4/mod/core.html) (the change from `All` to `None` at 2.3.9 is from the fetch model's memory, not on the page excerpt read). So `.htaccess` is off in a bare install and on in every shared-hosting configuration.
- **Caddy**: directives `rewrite`, `uri`, `redir`, `map`, `vars`, `handle`, `handle_path`, `route`, `invoke` ("Invoke a named route"), `method`, `intercept`; a hard-coded directive order that `order` or `route` overrides; plugin directives have no default order. Matchers: host, path, method, headers, protocol, remote IP, CEL expressions, file checks, variables; AND/OR/NOT; regular expressions are RE2 (linear time). [F] — [Caddyfile directives](https://caddyserver.com/docs/caddyfile/directives), [Caddy features](https://caddyserver.com/features)
- **Caddy 2.11.6** added URL-pattern captures as placeholders. [F, via release mirror] — [newreleases.io v2.11.6](https://newreleases.io/project/github/caddyserver/caddy/release/v2.11.6)
- **LiteSpeed**: Enterprise "supports Apache rewrite rules and most Apache directives. Detects .htaccess changes automatically, with no restart"; OpenLiteSpeed "supports rewrite rules but not Apache directives. A restart is required to load a new .htaccess file." [F] — [openlitespeed.org](https://openlitespeed.org/?p=8058); OLS front page: "mod_rewrite compatibility with no new syntax". [F] — [openlitespeed.org](https://openlitespeed.org/)
- **h2o**: Redirect and Mruby groups; no rewrite language; "Using Mruby", "Access Control" how-tos. [F] — [h2o configure](https://h2o.examp1e.net/configure.html)
- **Sub-request authentication**: N `auth_request` (not built by default) [F] — [configure](https://nginx.org/en/docs/configure.html); C `forward_auth` in core [F] — [Caddyfile directives](https://caddyserver.com/docs/caddyfile/directives) (a 2.11.2 CVE fix was in `forward_auth`: identity injection [F, via release mirror] — [newreleases.io](https://newreleases.io/project/github/caddyserver/caddy/release/v2.11.2)); T `ForwardAuth` [F]; A `mod_authnz_fcgi` (FastCGI authorizer) [F].
- **Mirror**: N `ngx_http_mirror_module` built by default [F] — [configure](https://nginx.org/en/docs/configure.html).
- **How servers without `.htaccess` cope** (hosting practice):
  - RunCloud offers three stacks: "Native NGINX" (PHP-FPM, "no .htaccess support", rules go into custom nginx config), "NGINX + Apache2 Hybrid" (nginx serves static files and proxies PHP to Apache, "aimed at users who rely on .htaccess"), and OpenLiteSpeed ("supports .htaccess files"); the stack cannot be changed after the server is connected. [F, via search result quoting the docs] — [RunCloud OLS FAQ](https://runcloud.io/docs/openlitespeed-faq), [RunCloud nginx config](https://runcloud.io/blog/nginx-config)
  - Plesk runs nginx in front of Apache with templates for both; forum users report "upon moving to nginx, all sub-pages throw 404 errors if WordPress permalinks are active" and that the htaccess-to-nginx extension "does no magic with existing htaccess files". [F, via search] — [Plesk forum](https://talk.plesk.com/threads/htaccess-to-nginx-not-working-wordpress-404s.346655), [Plesk forum](https://talk.plesk.com/threads/nginx-config-for-wordpress-rewrite-rules.339284/)
  - CloudPanel is nginx-only: "uses the Nginx server instead of Apache, so .htaccess files are not read"; it ships per-application vhost templates and a vhost editor. [F, third-party] — [underhost docs](https://docs.underhost.com/article/cloudpanel-vhost/), [CloudPanel tutorial](https://www.cloudpanel.io/tutorial/nginx-rewrite-rules)
  - Security plugins must special-case it: WP Ghost writes its rules to `.htaccess` on the hybrid stack and says native nginx "requires manual configuration because NGINX doesn't process .htaccess". [F, via search] — [WP Ghost KB](https://wpghost.com/kb/runcloud-wp-ghost-setup/amp/)
  - Ferron ships a migration guide "from Apache .htaccess" and from NGINX. [F] — [Ferron docs](https://ferron.sh/docs)

### Inferences
- Three coping strategies exist for no-`.htaccess` servers: (a) per-application templates/presets maintained by the panel or the server (CloudPanel, Forge-style, Caddy's `php_fastcgi`), (b) keep Apache behind nginx (Plesk, RunCloud hybrid, cPanel's optional nginx proxy), (c) partial compatibility (OLS: rewrite rules only). Strategy (a) is the only one available to a new server that does not embed an Apache-compatible parser, and it is what the fastest-growing panels do.
- Regex locations/rewrites are table stakes; nginx-style `if`, named locations and internal redirects are implementation details that Caddy replaced with matchers and `handle` blocks without user revolt.
- Routing on non-path properties (headers, client address sets, JSON body fields) is becoming a headline feature (nginx 1.31.5 explicitly for API/MCP traffic); for site hosting it is a differentiator, not a requirement.

### Gaps
- No official statement from cPanel, HestiaCP, Forge or Ploi documentation was retrieved on which rewrite features their templates depend on. HestiaCP's nginx-only and nginx+Apache modes are known to me but only a roundup ("nginx/Apache sites") was seen.
- Did not retrieve user-sentiment data on nginx `if` or on Caddy directive ordering beyond comparison blogs.

---

## 3. Dynamic content and caching

### Takeaway
FastCGI to PHP-FPM is universal; the differences are in who manages PHP processes (LiteSpeed's LSAPI and FrankenPHP embed it, the rest delegate to php-fpm) and in response caching, where nginx and LiteSpeed have mature built-in caches, Apache has mod_cache, and Caddy, h2o and Traefik OSS have none in core.

### Cited Findings
- **nginx**: `fastcgi`, `uwsgi`, `scgi`, `grpc`, `memcached` built by default; no CGI. [F] — [configure](https://nginx.org/en/docs/configure.html)
- **nginx cache** (proxy module; the fastcgi/uwsgi/scgi modules mirror it): `proxy_cache` off by default; `proxy_cache_key` default `$scheme$proxy_host$request_uri`; `proxy_cache_lock` (1.1.12) off; `proxy_cache_use_stale` parameters `error`, `timeout`, `invalid_header`, `updating`, `http_500/502/503/504/403/404/429`; `proxy_cache_background_update` (1.11.10); `proxy_cache_revalidate`; `proxy_cache_min_uses 1`; `proxy_cache_bypass` / `proxy_no_cache`. nginx honours `stale-while-revalidate` and `stale-if-error` in `Cache-Control` since **1.11.10** (2017; still holds), with lower priority than the directive. **`proxy_cache_purge` is commercial-only**, as are the `purger*` parameters of `proxy_cache_path`. [F] — [ngx_http_proxy_module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- **Apache**: `mod_proxy_fcgi`, `mod_proxy_scgi`, `mod_proxy_uwsgi` (2.4.30), `mod_proxy_ajp`, `mod_cgi`/`mod_cgid`, `mod_suexec`, `mod_actions`; `mod_cache` ("RFC 2616 compliant HTTP caching filter") with `mod_cache_disk`, `mod_cache_socache`; `mod_file_cache`; mod_cache can serve stale content when the backend returns 5xx and exposes `X-Cache` HIT/MISS/REVALIDATE; `htcacheclean` deletes individual URLs. [F] — [Apache module index](https://httpd.apache.org/docs/2.4/mod/), [new features 2.4](https://httpd.apache.org/docs/2.4/new_features_2_4.html)
- **Caddy**: `php_fastcgi` ("Serve PHP sites over FastCGI"), FastCGI transport with path splitting, env, timeouts, stderr capture. Caching is listed on the features page ("RFC 7234-compliant, tag-based purge" with Badger, Etcd, NutsDB, Olric, Redis backends) but is not among the 41 standard directives, i.e. it is a plugin. [F] — [Caddyfile directives](https://caddyserver.com/docs/caddyfile/directives), [Caddy features](https://caddyserver.com/features). Reviewers: "Caddy — Souin caching plugin, less mature than Nginx's". [F, comparison blog] — [privatedevops.com](https://privatedevops.com/articles/nginx-vs-caddy-2026-reverse-proxy-comparison)
- **Caddy app modules** listed include "PHP" and "Process supervision" (FrankenPHP and a supervisor plugin). [F] — [Caddy features](https://caddyserver.com/features)
- **LiteSpeed**: LSCache engine is in both editions; ESI only in Enterprise ("OpenLiteSpeed does not include ESI support"; LiteMage for Magento and the PrestaShop cache module need ESI, so Enterprise only). OLS: "PHP LiteSpeed SAPI ... up to 50 % faster" (vendor claim). [F] — [openlitespeed.org](https://openlitespeed.org/?p=8058), [openlitespeed.org](https://openlitespeed.org/)
- **h2o**: FastCGI group (connect to or spawn a FastCGI process), "Using CGI" how-to (through a FastCGI-to-CGI wrapper), Mruby handlers; no response cache group in the directive list. [F] — [h2o configure](https://h2o.examp1e.net/configure.html)
- **HAProxy**: FastCGI supported; "RAM-only response caching". [F] — [HAProxy intro](https://docs.haproxy.org/3.2/intro.html)
- **Ferron** documents "HTTP caching, edge caching (CDN), CGI, PHP hosting, PHP edge caching (LSCache), FastCGI, SCGI". [F] — [Ferron docs](https://ferron.sh/docs)
- **Early hints**: nginx 1.29.0; Ferron documents them. [F] — [CHANGES](https://nginx.org/en/CHANGES), [Ferron docs](https://ferron.sh/docs)

### Inferences
- For WordPress hosting, a FastCGI response cache with purge is the feature with the largest gap between "who has it" and "who needs it": the two servers with the biggest PHP hosting footprint build it in, panels expose it as a checkbox, and the nginx community works around the Plus-only purge with a third-party module. A new server can ship 1.0 without it only if it is honest that page caching is delegated to the application (cache plugins writing static files that `try_files` serves) or to a CDN.
- RFC 5861 (`stale-while-revalidate`, `stale-if-error`) and cache lock are refinements that only matter once a cache exists.
- SCGI, uwsgi and CGI are legacy for this audience: Python apps now speak HTTP (Gunicorn/Uvicorn), so proxying covers them. Ferron shipping CGI and SCGI shows new entrants still tick these boxes, but nothing in the panel documentation seen depends on them.
- ESI is niche outside Magento/PrestaShop-style commerce and is a paid LiteSpeed feature.

### Gaps
- LiteSpeed's PHP process modes (suEXEC daemon, ProcessGroup, worker) and CloudLinux integration were not on any page retrieved.
- FrankenPHP's 2026 status (worker mode, adoption) was not researched this session.
- Whether Traefik has gained FastCGI was not checked (it had none as of my knowledge).
- nginx `fastcgi_cache` adoption numbers: none found.

---

## 4. Reverse proxy and load balancing

### Takeaway
By late 2026 open-source nginx closed most of its historical proxy gaps (keep-alive by default, HTTP/2 to origins, sticky, least_time, DNS re-resolution), leaving active health checks, slow start, queueing and the dynamic-upstream API as the paid remainder; Caddy, Apache, HAProxy and Traefik all have active health checks for free. Passive failure detection plus next-origin retry is the common floor.

### Cited Findings

| Feature | nginx | Apache | Caddy | HAProxy | Traefik |
|---|---|---|---|---|---|
| Algorithms | round robin (default), `least_conn`, `ip_hash`, `hash` (consistent), `random` (two choices), `least_time` (OSS since 1.31.0) [F] | byrequests, bytraffic, bybusyness, heartbeat [F] | default **random**; `random_choose`, `first`, `round_robin`, `weighted_round_robin`, `least_conn`, `ip_hash`, `client_ip_hash`, `uri_hash`, `query`, `header`, `cookie` [F] | "10+ algorithms", weights, consistent hashing [F] | weighted round robin [K] |
| Sticky sessions | `sticky` OSS since 1.29.6 [F] | `stickysession` in mod_proxy_balancer [K] | `cookie` policy [F] | cookies, stick-tables replicated across peers [F] | sticky cookie [K] |
| Active health checks | **Plus only** [F] | `mod_proxy_hcheck` (2.4.21) [F] | yes: `health_uri`/`health_port`, interval 30 s, timeout 5 s, passes/fails 1, expects 200 [F] | TCP, HTTP, SSL, SMTP, LDAP, SQL, Redis, agent checks [F] | yes [K] |
| Passive checks | `max_fails=1`, `fail_timeout=10s` by default (on) [F] | worker error state with `retry` [K] | off until `fail_duration` set; `max_fails 1`, `unhealthy_status`, `unhealthy_latency` [F] | from production traffic [F] | — |
| Retries | `proxy_next_upstream error timeout` default; `non_idempotent` opt-in; `proxy_next_upstream_tries 0` (unlimited) [F] | — | off by default (`lb_retries 0`, `lb_try_duration 0`); retries only GET by default (`lb_retry_match`) [F] | redispatch of queued requests [F] | `Retry` middleware [F] |
| Circuit breaking / concurrency cap | `max_conns` (OSS since 1.11.5); `queue` is Plus [F] | — | `unhealthy_request_count`; "latency-based circuit breaking" [F] | per-server limits with queueing [F] | `CircuitBreaker`, `InFlightReq` [F] |
| Slow start | `slow_start` **Plus only** [F] | — | — | yes [F] | — |
| Upstream keep-alive | default since 1.29.7: `keepalive 32 local` [F] | pooled by default [K] | default: keep-alive 2 m, 32 idle per host [F] | yes [K] | yes [K] |
| HTTP/2 to origin | since 1.29.4 (`proxy_http_version 2`); gRPC module earlier [F] | `mod_proxy_http2` (2.4.19) [F] | default versions "1.1 and 2"; `h2c://`; HTTP/3 to upstream experimental [F] | "HTTP/2 on either side" [F] | yes [K] |
| WebSocket | by forwarding Upgrade headers by hand [K] | `mod_proxy_wstunnel` (2.4.5) [F] | automatic; connections closed on config reload unless `stream_close_delay` [F] | yes [K] | yes [K] |
| Buffering | `proxy_buffering on`, `proxy_request_buffering on`, `proxy_max_temp_file_size 1024m` [F] | `mod_buffer`, `mod_request` [F] | streams by default; `request_buffers`, `response_buffers`, `flush_interval` opt-in [F] | — | `Buffering` middleware [F] |
| Timeouts | connect/read/send 60 s each [F] | `TimeOut` 60 s [K] | dial 3 s; no read/write timeout by default [F] | — | — |
| PROXY protocol | in on `listen`; out in stream/mail, v2 out since 1.31.4 [F] | in via `mod_remoteip` [K] | in (listener wrapper) and out (`proxy_protocol v1|v2`, off by default) [F] | in and out [F] | in [K] |
| TCP/UDP proxy | `stream` (`--with-stream`, not default; virtual servers in stream since 1.25.5) [F] | no | "raw TCP/UDP" app (plugin) [F] | TCP mode [F] | TCP and UDP routers [K] |
| DNS / service discovery | `resolve`, `service` (SRV) OSS since 1.27.3 [F] | — | dynamic upstreams from SRV, A/AAAA, `multi`, refresh 1 m [F] | DNS resolution not covered in the intro read | providers (Docker, Kubernetes, file...) [K] |

Sources for the table: [nginx upstream module](https://nginx.org/en/docs/http/ngx_http_upstream_module.html), [nginx proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html), [nginx upstream_hc](https://nginx.org/en/docs/http/ngx_http_upstream_hc_module.html), [nginx CHANGES](https://nginx.org/en/CHANGES), [nginx configure](https://nginx.org/en/docs/configure.html), [Apache module index](https://httpd.apache.org/docs/2.4/mod/), [Apache 2.4 new features](https://httpd.apache.org/docs/2.4/new_features_2_4.html), [Caddy reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy), [Caddy features](https://caddyserver.com/features), [HAProxy intro 3.2](https://docs.haproxy.org/3.2/intro.html), [Traefik middlewares](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/).

Further findings:
- Caddy's defaults for forwarded headers: `Host` passed through; sets `X-Forwarded-For`, `-Proto`, `-Host`; incoming `X-Forwarded-*` ignored unless the peer is in `trusted_proxies`; since 2.11.0 `Host` is set automatically for HTTPS upstreams; adds `Accept-Encoding: gzip` to the origin unless `compression off`. [F] — [reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
- Caddy 2.11.7+: a request or response marked `Incremental: ?1` is streamed, and if buffering would prevent it Caddy answers 501. [F] — [reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
- Caddy 2.0.0 (2020; still relevant as history) removed its reverse-proxy circuit-breaker module at release. [F] — [Caddy v2.0.0 release](https://github.com/caddyserver/caddy/releases/tag/v2.0.0)
- nginx 1.31.4: requests to HTTP/2 and gRPC backends always send `:authority`. 1.31.7: backend certificates can be verified by IP address. [F] — [CHANGES](https://nginx.org/en/CHANGES)
- Apache mod_proxy_balancer: runtime member changes through balancer-manager, a "Drain" state, settings persisted across restarts. [F] — [new features 2.4](https://httpd.apache.org/docs/2.4/new_features_2_4.html)
- HAProxy 3.2 (28 May 2025): QUIC faster and pacing automatic; thread limit 256 → 1024; `strict-maxconn`; HTTP/2 `idle-ping`. HAProxy 3.3 (Nov 2025) brought official downloadable packages. [F] — [haproxy.com 3.2 announcement](https://www.haproxy.com/blog/announcing-haproxy-3-2)
- Angie (nginx fork) has in open source: `slow_start`, sticky sessions, HTTP/3 to upstreams, Docker-label upstream discovery, a JSON statistics API and Prometheus output. [F] — [Angie](https://en.angie.software/angie/)
- Sōzu 2.0 (29 May 2026): H1/H2 in every combination to backends, RFC 9218 priorities, active HTTP/1.1 and HTTP/2 health checks, splice(2) forwarding for TCP. [F] — [Clever Cloud blog](https://www.clever.cloud/blog/engineering/2026/05/29/sozu-2-0-reverse-proxy-programmable-edge/)

### Inferences
- For "Rails, Django, Node behind it" on one VPS the origin is one local process, so the realistic proxy floor is: keep-alive, WebSocket, timeouts, buffering switch, body limit, forwarded headers with a trust list, graceful handling of a dead origin (502/504 pages, retry of idempotent requests). Groups, algorithms and health checks matter only when there is more than one origin.
- Active health checks are the one proxy feature where a new server can be measured against nginx and win on paper, since every other open-source server has them. Whether hosting users need them is doubtful for single-origin sites.
- Defaults differ sharply and are worth deciding consciously: nginx buffers both directions and retries on error/timeout by default; Caddy streams and does not retry by default; nginx passive checks are on, Caddy's off.
- WebSocket surviving a reload is not solved everywhere: Caddy closes proxied WebSockets on reload unless told otherwise.

### Gaps
- Traefik and HAProxy cells marked [K] were not verified against their docs this session (only the Traefik middleware list and the HAProxy introduction were read).
- HAProxy HTTP/3 to backends and its DNS service discovery were not confirmed from a page.
- Apache mod_proxy's default connection reuse and WebSocket-in-mod_proxy_http (2.4.47+) are from memory.

---

## 5. Limits and protection

### Takeaway
Request-size limits and timeouts are universal; per-IP request and connection limiting is built into nginx, LiteSpeed, HAProxy and Traefik but not into Apache's or Caddy's core; WAF, bot defence and identity (JWT/OIDC) are integrations or paid tiers almost everywhere.

### Cited Findings
- **nginx**: `limit_conn` and `limit_req` modules are built by default (not configured by default); `access` (allow/deny), `auth_basic`, `geo`, `referer` built by default; `auth_request`, `realip`, `geoip`, `secure_link` are `--with-`. `max_headers` directive added in 1.29.8 (Apr 2026); `keepalive_min_timeout` 1.27.4. [F] — [configure](https://nginx.org/en/docs/configure.html), [CHANGES](https://nginx.org/en/CHANGES)
- **nginx Plus identity**: `ngx_http_auth_jwt_module`, `ngx_http_oidc_module`, `ngx_http_auth_require_module`, `ngx_http_keyval_module` appear in the module index. [F for listing; commercial status not re-verified] — [nginx index](https://nginx.org/en/docs/)
- **Apache**: `mod_reqtimeout` ("Set timeout and minimum data rate for receiving requests" — the slowloris defence), `mod_ratelimit` (bandwidth, not request rate), `mod_auth_basic`, `mod_auth_digest`, `mod_auth_form`, `mod_authnz_ldap`, `mod_authn_dbd`, `mod_authn_socache`, `mod_authz_host`, `mod_allowmethods`, `mod_remoteip`, `mod_ssl` client certificates with OCSP. No per-IP request-rate module in the 2.4 index. [F] — [Apache module index](https://httpd.apache.org/docs/2.4/mod/), [new features 2.4](https://httpd.apache.org/docs/2.4/new_features_2_4.html)
- **Apache defaults** (from the fetch model's memory of the core page, not in the excerpt read): `LimitRequestFields 100`, `LimitRequestFieldSize 8190`, `LimitRequestLine 8190`, `TimeOut 60`, `KeepAliveTimeout 5`, `MaxKeepAliveRequests 100`, `LimitRequestBody` 1 GiB (earlier unlimited). [K] — [core](https://httpd.apache.org/docs/2.4/mod/core.html)
- **Caddy**: `basic_auth`, `forward_auth`, `request_body` (size limit), `timeouts` ("Set idle read and write timeouts"; 2.11.6 release notes describe it as slowloris mitigation) are core. Rate limiting is listed on the features page ("local or distributed, sliding window") but is the third-party `caddy-ratelimit` module that must be compiled in with xcaddy; a stock build fails with "unrecognized directive: rate_limit". JWT, forms, SAML, Authelia come via the caddy-security plugin. [F] — [Caddyfile directives](https://caddyserver.com/docs/caddyfile/directives), [Caddy features](https://caddyserver.com/features), [Caddy forum: unrecognized directive](https://caddy.community/t/unrecognized-directive-rate-limit/30359), [Caddy forum: rate limiting as a default module](https://caddy.community/t/adding-rate-limiting-as-a-default-module/23871), [newreleases.io v2.11.6](https://newreleases.io/project/github/caddyserver/caddy/release/v2.11.6)
- **LiteSpeed Enterprise**: per-client throttling at server level (static requests/s and dynamic requests/s limited separately, example 40 and 2; inbound/outbound bandwidth), connection soft limit and hard limit (recommended hard limit 4–10 per IP for most sites), grace period, banned period (default 300 s), reCAPTCHA challenge (5.4+), SSL renegotiation protection, "bot detected" log reasons (OverConnHardLimit, OverConnSoftLimit, DetectByWAF), "Block Bad Request". Enterprise has built-in WordPress brute-force protection; OLS has "no native protection". OLS front page lists "Anti-DDoS: connection and bandwidth throttling". [F] — [LiteSpeed anti-DDoS docs](https://docs.litespeedtech.com/lsws/cp/cpanel/antiddos/), [openlitespeed.org](https://openlitespeed.org/?p=8058), [openlitespeed.org](https://openlitespeed.org/)
- **WAF**: OLS "includes a standard ModSecurity v3 engine, which uses the same library as open source nginx"; Enterprise "a proprietary ModSecurity engine". Traefik: WAF, JWT, OIDC, LDAP, API key, HMAC, OPA and distributed rate limit are Traefik Hub (paid) middlewares; OSS has `RateLimit`, `InFlightReq`, `IPAllowList`, `BasicAuth`, `DigestAuth`, `ForwardAuth`, `PassTLSClientCert`. [F] — [openlitespeed.org](https://openlitespeed.org/?p=8058), [Traefik middlewares](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/)
- **HAProxy**: stick-tables with up to 8 tracked keys, "rate limiting at various points", per-server connection limits with queueing. [F] — [HAProxy intro](https://docs.haproxy.org/3.2/intro.html)
- **h2o**: "Using DoS Detection" (an mruby handler), "Access Control", "Using Basic Authentication" how-tos. [F] — [h2o configure](https://h2o.examp1e.net/configure.html)
- **Geo/IP**: nginx geoip modules read MaxMind MMDB natively since 1.31.7 (before that the legacy database format, or a third-party module). Caddy lists a geolocation matcher. [F] — [CHANGES](https://nginx.org/en/CHANGES), [Caddy features](https://caddyserver.com/features)
- **Ferron** documents "rate limiting, abuse protection, security headers, access control, Fail2ban integration, HTTP basic auth, forwarded auth". [F] — [Ferron docs](https://ferron.sh/docs)
- **Sōzu 2.0** ships a per-IP connection cap, DoS mitigations, an audit log, HSTS and Basic auth. [F] — [Clever Cloud blog](https://www.clever.cloud/blog/engineering/2026/05/29/sozu-2-0-reverse-proxy-programmable-edge/)
- **Recent protocol hardening as a baseline signal**: nginx 1.31.0 rejects HTTP/2 and HTTP/3 requests carrying connection-specific headers; 1.29.4 treats a bare LF chunk terminator as an error and validates host/port per RFC 3986; 1.29.6 limits QUIC stateless resets. Apache 2.4 no longer converts header names containing underscores into CGI variables. [F] — [CHANGES](https://nginx.org/en/CHANGES), [new features 2.4](https://httpd.apache.org/docs/2.4/new_features_2_4.html)

### Inferences
- The floor: header count/size limits, body size limit, header/body/idle timeouts, a global connection ceiling, basic auth, IP allow/deny, trusted-proxy handling, TLS client certificates (present in all, used by few).
- Per-IP rate limiting: a server without it is in Apache's and Caddy's company, and both are criticised or patched for it (mod_evasive/mod_qos for Apache, the xcaddy plugin for Caddy). On a hosting server the same job is commonly done by fail2ban and the firewall, which only requires a parseable log; documenting that division is an acceptable 1.0 position, but reviewers will list "no built-in rate limit" as a gap, as they do for Caddy.
- LiteSpeed is the only web server that bundles a full anti-abuse suite (per-client throttle, ban periods, CAPTCHA, WordPress login protection); that is a differentiator and a reason hosts pay for it.
- Digest auth, LDAP/DB-backed auth and form auth are Apache-only legacy; JWT/OIDC is paid or plugin everywhere except HAProxy; none are 1.0 material for site hosting.
- Fail2ban compatibility is a property of the log format rather than a feature; Ferron documenting it explicitly shows new entrants treat it as a checklist item.

### Gaps
- No page read states mod_reqtimeout's default values; ModSecurity/Coraza/CrowdSec integration pages were not read (the OLS statement is the only sourced WAF fact). CrowdSec bouncer availability per server is from memory and not cited.
- HAProxy's JWT verification in open source is from memory.
- LiteSpeed defaults for throttling were only in a screenshot; whether each anti-DDoS control exists in OLS was not stated on the page.

---

## 6. Observability and operations

### Takeaway
Combined-format access logs, leveled error logs, a config test and a graceful reload are universal; structured JSON logs, Prometheus metrics, OpenTelemetry and a runtime API are native in the newer servers (Caddy, Traefik, HAProxy, the Rust entrants) and bolted on or paid in nginx, which only in 2026 gained a minimal control API.

### Cited Findings
- **Logging**: N `ngx_http_log_module`; `$request_id` now SipHash-2-4 (1.31.2). A `mod_log_config`, `mod_logio`, `mod_log_forensic`, `mod_log_debug`, `mod_unique_id`, per-module and per-directory `LogLevel` with `trace1`–`trace8`, `ErrorLogFormat`, `rotatelogs` with post-rotate script. C: "leveled, structured, zero-allocation" logs with field deletion, IP masking, hashing, regex redaction; directives `log`, `log_append`, `log_skip`, `log_name`, `log_level` (per-matcher access log level, new in 2.11.8). H Access Log group. HAP: "syslog, UDP, JSON, stdout, ring buffers". [F] — [nginx CHANGES](https://nginx.org/en/CHANGES), [Apache module index](https://httpd.apache.org/docs/2.4/mod/), [new features 2.4](https://httpd.apache.org/docs/2.4/new_features_2_4.html), [Caddy features](https://caddyserver.com/features), [Caddyfile directives](https://caddyserver.com/docs/caddyfile/directives), [h2o configure](https://h2o.examp1e.net/configure.html), [HAProxy intro](https://docs.haproxy.org/3.2/intro.html)
- **Status and metrics**: N `stub_status` is `--with-` (not built by default); the rich status API is Plus. A `mod_status`, `mod_info`. C `metrics` directive ("Prometheus metrics exposition endpoint"). OLS "LiteSpeed Prometheus Exporter". H Status group and Server Timing. HAP stats page and Prometheus exporter. Angie: JSON API plus Prometheus with templates plus a web console. [F] — [configure](https://nginx.org/en/docs/configure.html), [nginx api module](https://nginx.org/en/docs/http/ngx_http_api_module.html), [Apache module index](https://httpd.apache.org/docs/2.4/mod/), [Caddyfile directives](https://caddyserver.com/docs/caddyfile/directives), [openlitespeed.org](https://openlitespeed.org/), [h2o configure](https://h2o.examp1e.net/configure.html), [HAProxy intro](https://docs.haproxy.org/3.2/intro.html), [Angie](https://en.angie.software/angie/)
- **Tracing**: nginx `ngx_otel_module` listed under "Other" (a separate module). Caddy `tracing` directive "Integration with OpenTelemetry tracing" in core; 2.11.1 "expanded tracing". Ferron: logging, metrics, tracing, OTLP, Prometheus, StatsD, a Grafana dashboard, trace IDs searchable in logs. h2o: "Using h2olog for Tracing". [F] — [nginx index](https://nginx.org/en/docs/), [Caddyfile directives](https://caddyserver.com/docs/caddyfile/directives), [linuxiac on 2.11.1](https://linuxiac.com/caddy-2-11-1-web-server-released-with-automatic-ech-key-rotation/), [Ferron docs](https://ferron.sh/docs), [h2o configure](https://h2o.examp1e.net/configure.html)
- **Runtime configuration**:
  - Caddy: "Config via RESTful API, config files, or secure remote access"; export of the running config; "zero-downtime graceful reloads and runtime config changes". [F] — [Caddy features](https://caddyserver.com/features)
  - NGINX Plus API: read status of everything; with `api write=on` add/modify/remove upstream servers and key-value pairs without reload. [F] — [nginx api module](https://nginx.org/en/docs/http/ngx_http_api_module.html)
  - nginx control API (1.31.5, opt-in build flag): inspect processes and config, trigger a reload over HTTP and get the result as JSON. A trade article headline from Sept 2026: "ask nginx which config it is running: not every build will answer". [F] — [NGINX blog](https://blog.nginx.org/?p=75128), [webhosting.today](https://webhosting.today/2026/09/23/ask-nginx-which-config-it-is-running-not-every-build-will-answer/)
  - HAProxy: CLI/runtime API; "seamless reload (old and new processes coexist)". [F] — [HAProxy intro](https://docs.haproxy.org/3.2/intro.html)
  - Sōzu: configuration changes at runtime over a UNIX socket, `listener update` without rebinding, hot upgrade, systemd `Type=notify` with MAINPID kept across upgrades. [F] — [Clever Cloud blog](https://www.clever.cloud/blog/engineering/2026/05/29/sozu-2-0-reverse-proxy-programmable-edge/)
  - Ferron: Admin API, `validate`, `adapt` (config to JSON), a config "doctor", formatter, editor support. [F] — [Ferron docs](https://ferron.sh/docs), [Ferron README](https://github.com/ferronweb/ferron)
  - OLS: WebAdmin GUI. [F] — [openlitespeed.org](https://openlitespeed.org/)
- **Reload and upgrade**: nginx 1.31.7 added "QUIC supports reconfiguration and binary upgrade with quic_bpf" — i.e. until Oct 2026 HTTP/3 connections did not survive nginx's own reload/upgrade cleanly. Caddy closes proxied WebSocket connections on reload unless `stream_close_delay` is set. [F] — [CHANGES](https://nginx.org/en/CHANGES), [reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
- **systemd**: Apache `mod_systemd` (2.4.42) gives `Type=notify`. [F] — [new features 2.4](https://httpd.apache.org/docs/2.4/new_features_2_4.html)
- **Certificates in operation**: Caddy renews at two thirds of lifetime, exponential backoff, OCSP stapling with caching, ARI, EAB, falls back to the CA's staging endpoint after failures, cluster coordination through shared storage, automatic ECH key rotation (2.11.1), `tls_resolvers` (2.11.2). nginx: certificates cached at start/reconfiguration (1.27.2), ECH with the OpenSSL ECH branch (1.29.4), certificate compression (1.29.1), OpenSSL 4.0 compatibility (1.29.8), AWS-LC build (1.29.2). HAProxy 3.2 ACME: experimental, HTTP-01 only, single node, renews 7 days before expiry. [F] — [Caddy features](https://caddyserver.com/features), [linuxiac](https://linuxiac.com/caddy-2-11-1-web-server-released-with-automatic-ech-key-rotation/), [CHANGES](https://nginx.org/en/CHANGES), [haproxy.com](https://www.haproxy.com/blog/announcing-haproxy-3-2)
- **Platforms and distribution**: Caddy runs on Linux, Windows, macOS, FreeBSD, OpenBSD, NetBSD, Android as a static binary with signed releases and self-upgrade. nginx ships a Windows binary (built with Windows SDK 10 since 1.29.0) and Homebrew on Apple Silicon is a supported build. nginx offers prebuilt dynamic-module packages (`nginx-module-acme`). HAProxy 3.3 added official vendor-built packages. Angie advertises ready-made packages for its own and third-party modules. OLS: one-click installers and cloud images. Ferron: Linux, Windows, Docker installers. [F] — [Caddy features](https://caddyserver.com/features), [CHANGES](https://nginx.org/en/CHANGES), [acme module](https://nginx.org/en/docs/http/ngx_http_acme_module.html), [haproxy.com](https://www.haproxy.com/blog/announcing-haproxy-3-2), [Angie](https://en.angie.software/angie/), [openlitespeed.org](https://openlitespeed.org/), [Ferron docs](https://ferron.sh/docs)

### Inferences
- Floor for 1.0: combined and JSON access logs, conditional/skip logging, error log levels, reopen on signal, a config test, graceful reload, a status endpoint, systemd unit with notify, privilege drop, packages and a container image.
- Native Prometheus and OpenTelemetry are present in every server designed after 2015 and absent from the cores of nginx and Apache; a new server will be compared to Caddy/Traefik here, not to nginx.
- A runtime API is now mainstream enough that nginx added one to open source in 2026; but nginx's is deliberately tiny (inspect, reload), which sets a low bar for "has an API".
- Graceful reload quality is uneven even among incumbents (nginx+QUIC until 1.31.7; Caddy+WebSocket), so "no request fails across a reload, including long-lived connections" is a claim few can make in full.
- Built-in log rotation exists in Caddy [K]; nginx and Apache rely on logrotate/rotatelogs. Either is accepted.

### Gaps
- Not verified this session: Caddy's access log being off until `log` is configured, Caddy's log roll defaults, systemd socket activation support in Caddy, nginx's lack of sd_notify, HAProxy's notify mode; chroot/seccomp/Landlock use inside any of these servers (I found no page showing a mainstream web server applying seccomp or Landlock to itself; systemd unit hardening is the common practice, unverified here).
- No source compared documentation quality; opinions on that are anecdotal.
- journald-native logging support per server was not checked.

---

## 7. Configuration model: what users praise and criticise

### Takeaway
Users praise Caddy's short config with safe defaults and nginx's predictability and performance, and criticise nginx's boilerplate and surprising inheritance, Apache's per-request `.htaccess` cost and sprawl, and Caddy's plugin-means-custom-binary model; the incumbents have been fixing their best-known complaints in 2025–2026.

### Cited Findings
- **Caddy**: native JSON config with adapters (Caddyfile, JSON5, YAML, TOML, NGINX conf, CUE, HCL...), `import` for snippets and files, `caddy validate` and `caddy fmt`, config export from the running server. [F] — [Caddy features](https://caddyserver.com/features), [Caddyfile directives](https://caddyserver.com/docs/caddyfile/directives)
- **Caddy criticism**: directive order is hard-coded and must be overridden with `order` or `route`; plugin directives have no default order. [F] — [Caddyfile directives](https://caddyserver.com/docs/caddyfile/directives). "If you have compiled plugins in via xcaddy, you are the distributor of your own binary and patching means rebuilding"; the plugin ecosystem "is much smaller" and rate-limit/WAF modules "do not have the decades of battle-testing that Nginx modules have"; Caddy "uses more RAM than nginx (Go runtime + GC)"; "the example rate_limit config in many comparison articles does not work in a stock Caddy build". [F, comparison blogs — secondary, treat as opinion] — [privatedevops.com](https://privatedevops.com/articles/nginx-vs-caddy-2026-reverse-proxy-comparison), [dev.to](https://dev.to/pickuma/caddy-vs-nginx-in-2026-which-reverse-proxy-should-you-run-4h9i), [techplained](https://www.techplained.com/caddy-vs-nginx)
- **Caddy forum**: `caddy validate` fails on a config that uses a plugin the binary lacks (thread "Ignoring plugins configuration when running caddy validate?"). [F, title only] — [Caddy forum](https://caddy.community/t/ignoring-plugins-configuration-when-running-caddy-validate/33949)
- **nginx fixing old complaints**: `add_header_inherit` / `add_trailer_inherit` (1.29.3) for the header-inheritance trap; keep-alive to upstreams by default (1.29.7) removing three lines of boilerplate per proxy; wildcard `include` inside `geo` (1.29.8); `http2` as a directive instead of a `listen` parameter (1.25.1). [F] — [CHANGES](https://nginx.org/en/CHANGES)
- **Apache**: variables with `Define`, macros with `mod_macro`, `<If>` expressions, `mod_info` dumps the parsed configuration, `mod_vhost_alias` for mass virtual hosting, `AllowOverrideList`. [F] — [new features 2.4](https://httpd.apache.org/docs/2.4/new_features_2_4.html), [Apache module index](https://httpd.apache.org/docs/2.4/mod/)
- **LiteSpeed**: Enterprise reads Apache's configuration and is "a drop-in Apache replacement, so any Apache-compatible panel works (cPanel, Plesk, DirectAdmin)"; OLS is "not a direct Apache replacement", configured through its WebAdmin GUI, and supported by CyberPanel, DirectAdmin, CloudPages, RunCloud, GridPane. [F] — [openlitespeed.org](https://openlitespeed.org/?p=8058)
- **Panels and per-site isolation**: CloudPanel validates and reloads nginx on saving a vhost; HestiaCP uses per-domain templates (`/usr/local/hestia/data/templates/web/nginx`); Plesk has default/custom template trees for nginx and Apache. [F, via search] — [underhost docs](https://docs.underhost.com/article/cloudpanel-vhost/), [HestiaCP forum](https://forum.hestiacp.com/t/how-to-edit-the-domain-config-from-the-panel/157), [Plesk docs](https://plesk.com/?p=136)
- **Ferron** (newest entrant) ships config validation, a "doctor", a formatter, conditionals and editor support as documented features. [F] — [Ferron docs](https://ferron.sh/docs)
- **River** chose KDL as its configuration language; **Sōzu** is configured at runtime through commands. [F] — [River repository](https://github.com/memorysafety/river), [Clever Cloud blog](https://www.clever.cloud/blog/engineering/2026/05/29/sozu-2-0-reverse-proxy-programmable-edge/)

### Inferences
- Common model everywhere: one main file, per-site included files, variables, a syntax check. Per-site failure isolation (one broken site file not stopping the others) is not something any of the incumbents' documentation claims; nginx and Apache refuse the whole configuration. This is a possible differentiator but I found no source measuring demand for it beyond panels wrapping every save in a validate-then-reload.
- Templating is the panels' job in the nginx world; Caddy's snippets and Apache's macros bring it into the server. Application presets (`php_fastcgi` expanding to the canonical PHP routing) are Caddy's most-praised simplification.
- Good error messages and a formatter/doctor are being used as selling points by new entrants.

### Gaps
- User sentiment is sourced only from comparison blogs and forum thread titles; no survey data. No retrieved source on what users criticise about Apache or nginx configuration specifically (the well-known "if is evil" and `.htaccess` performance points are from memory and uncited).
- HestiaCP, cPanel, Forge and Ploi official documentation was not read.

---

## 8. What each server deliberately does not do, and how users react

### Takeaway
Every server has a deliberate hole, and the market tolerates each as long as there is a documented way around it: nginx without `.htaccess` and with paid health checks and purge, Caddy without rate limiting and caching in core, OpenLiteSpeed without live `.htaccess` and ESI, h2o without releases, HAProxy and Traefik without file serving.

### Cited Findings
- **nginx**: no `.htaccess` ("there is no per-directory .htaccess-equivalent that Nginx reads, and WordPress cannot modify Nginx's server configuration automatically"); Apache's protective rules for `wp-config.php` or PHP in uploads "have to become explicit nginx location blocks". Reactions: panels add a hybrid Apache backend or templates; forum threads on 404s after migration. [F, via search] — [jorijn.com](https://jorijn.com/en/knowledge-base/wordpress/setup/wordpress-nginx-server-block-configuration/), [Plesk forum](https://talk.plesk.com/threads/htaccess-to-nginx-not-working-wordpress-404s.346655)
- **nginx**: no CGI and no PHP process management (no such module in the index); active health checks, cache purge, the statistics API, queue and slow start are reserved for Plus. [F] — [nginx index](https://nginx.org/en/docs/), [upstream_hc](https://nginx.org/en/docs/http/ngx_http_upstream_hc_module.html), [proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- **nginx** removed HTTP/2 server push (1.25.1) while Caddy still lists a `push` directive. [F] — [CHANGES](https://nginx.org/en/CHANGES), [Caddyfile directives](https://caddyserver.com/docs/caddyfile/directives)
- **Caddy**: no rate limiting, response cache, WAF, brotli encoder, WebDAV, layer-4 proxy or DNS-provider modules in the standard build; all are plugins requiring an xcaddy rebuild. Forum threads asking for rate limiting as a default module go back to 2020 ("Rate limiting for v2") and continue ("Adding rate limiting as a default module", "Unrecognized directive: rate_limit"). No maintainer statement of the reason was found; a third-party blog suggests policy and storage choices vary too much. [F] — [Caddy forum 2020](https://caddy.community/t/rate-limiting-for-v2/6990), [Caddy forum](https://caddy.community/t/adding-rate-limiting-as-a-default-module/23871), [Caddy forum](https://caddy.community/t/unrecognized-directive-rate-limit/30359)
- **OpenLiteSpeed**: no Apache directives in `.htaccess` (rewrite rules only), restart needed to pick up changes, no ESI, no asynchronous TLS handshake offload, no built-in WordPress brute-force protection, not usable under cPanel/Plesk as an Apache replacement. Community reaction is a steady stream of "OLS or go straight to Enterprise?" threads. [F] — [openlitespeed.org](https://openlitespeed.org/?p=8058), [DirectAdmin forum](https://forum.directadmin.com/goto/post?id=324376), [OLS forum](https://forum.openlitespeed.org/threads/what-is-the-complete-difference-beetwen-openlitespeed-litespeed-enterprise-ols-vs-lsws.4123)
- **h2o**: "we no longer tag versions!" — the project stopped tagging in 2019 because backporting was a burden; "Users are advised to use the up-to-date commit of the master branch." Last tagged stable 2.2.6 (Aug 2019). Its directive groups have no response cache, no rewrite language, no ACME. [F] — [h2o releases](https://github.com/h2o/h2o/releases), [h2o configure](https://h2o.examp1e.net/configure.html). W3Techs does not list h2o at or above 0.1 %. [F] — [W3Techs](https://w3techs.com/technologies/overview/web_server). A wiki claims Debian removed h2o in May 2025; unverified. [F, low-quality source] — [linux-server-admin wiki](https://wiki.linux-server-admin.com/software/webserver/h2o/history)
- **HAProxy** says what it is not: not a forward proxy, "not a static web server: it has no file-system access after startup", not a data scrubber, not a packet-level balancer. [F] — [HAProxy intro](https://docs.haproxy.org/3.2/intro.html)
- **Traefik** OSS has no file-serving middleware in its list, and puts WAF, JWT, OIDC, LDAP and distributed rate limiting in the paid Hub. [F] — [Traefik middlewares](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/)
- **Apache**: sendfile off by default; `.htaccess` off by default (`AllowOverride None`); no HTTP/3 module in 2.4's index. [F] — [core](https://httpd.apache.org/docs/2.4/mod/core.html), [Apache module index](https://httpd.apache.org/docs/2.4/mod/)

### Inferences
- A deliberate omission is tolerated when (a) the server says so plainly, and (b) there is a working, documented path: nginx's PHP via php-fpm, Caddy's plugins, HAProxy pointing to nginx for files. It becomes a reputational problem when the path is fragile (Caddy's custom binaries) or paid (nginx health checks and purge are the most-cited reasons people look at Angie, Caddy or HAProxy).
- h2o demonstrates that performance alone does not create adoption: fastest in benchmarks, no releases, no packaging, under 0.1 % of sites.
- "Not a web server" proxies (HAProxy, Traefik, Sōzu, Pingora-based) are not competitors for PHP hosting; they set expectations only for the proxy area.

### Gaps
- No official Caddy maintainer explanation for keeping rate limiting out of core was retrieved.
- h2o's current commit activity and distribution status in 2026 were not verified from a primary source.
- Apache HTTP/3 status (trunk/2.5) was not checked.

---

## 9. Newer entrants and their scope at first stable release

### Takeaway
New servers reach "1.0" with a narrow core — static files, reverse proxy, automatic TLS, HTTP/2, a clear config and a reload story — and add caching, rate limiting and protocol breadth afterwards; the ones that stalled (River) or stayed marginal (h2o) lacked releases and packaging, not features.

### Cited Findings
- **Caddy 1.0.0** (24 Apr; the year, 2019, is from memory): a stability milestone ("future work on the 1.0 line will focus on stability and bug fixes"), removal of the binary EULA; the release notes list no features. [F] — [Caddy v1.0.0 release](https://github.com/caddyserver/caddy/releases/tag/v1.0.0)
- **Caddy 2.0.0** (4 May; year 2020 from memory): "Caddy 2 is ready for production"; "2.0 means the software is stable, not perfect"; 2.1 already planned with 30+ improvements; DNS challenge moved to libdns provider plugins; reverse proxy sets `X-Forwarded-Proto`; the reverse-proxy circuit-breaker module was **removed** at release. Rate limiting was not in 2.0 (forum thread "Rate limiting for v2", 2020). [F] — [Caddy v2.0.0 release](https://github.com/caddyserver/caddy/releases/tag/v2.0.0), [Caddy forum](https://caddy.community/t/rate-limiting-for-v2/6990)
- **Caddy today** (2.11.x, 41 standard directives) still has no cache or rate limit in the standard directive list, six years after 2.0. [F] — [Caddyfile directives](https://caddyserver.com/docs/caddyfile/directives)
- **River** (Prossimo/ISRG, on Pingora): v0.5.0, 30 Aug 2024; "Until further notice, there is no expectation of stability"; the initiative page says development is "currently paused while we focus resources on other projects". Feature set at pause: load balancing, rate limiting, KDL configuration, static file serving, graceful reloads, CIDR blocking. Never reached 1.0. [F] — [River repository](https://github.com/memorysafety/river), [Prossimo reverse proxy initiative](https://www.memorysafety.org/initiative/reverse-proxy)
- **Pingora** is a Rust framework for building proxies, open-sourced by Cloudflare in 2024, and the base of several 2026 projects (e.g. a dashboard-first proxy with a WAF); it is not itself a configurable server. [F, secondary] — [youngju.dev 2026 overview](https://www.youngju.dev/blog/culture/2026-05-16-reverse-proxy-edge-servers-2026-nginx-caddy-traefik-haproxy-envoy-openresty-pingora-frankenphp-deep-dive.en), [ecosyste.ms listing](https://awesome.ecosyste.ms/projects/github.com%2FRwx-G%2FLorica)
- **Ferron** (Rust): 1.x is end-of-life; "First stable release of Ferron 2" dated 4 Nov (year not shown; 2.1–2.5 followed); Ferron 3 is at release-candidate stage in Nov 2026. Scope documented for 3: static files, directory listing, compression, HTTP caching and "PHP edge caching (LSCache)", CGI/FastCGI/SCGI, reverse and forward proxy, load balancing with health checks and HTTP/2 backends (third-party listing), URL rewriting, maps, variables, canary routing, error pages, early hints, automatic TLS with DNS providers and OCSP stapling, mTLS, rate limiting, "abuse protection", Fail2ban integration, basic and forwarded auth, logs/metrics/traces (OTLP, Prometheus, StatsD), an Admin API, config validate/doctor/format, migration guides from `.htaccess` and nginx. Three major versions in roughly two years. [F] — [Ferron docs](https://ferron.sh/docs), [Ferron README](https://github.com/ferronweb/ferron), [Ferron releases mirror](https://newreleases.io/project/github/ferronweb/ferron/release/2.1.0), [selfhostyourself listing](https://selfhostyourself.com/services/ferron)
- **Angie** (nginx fork by former nginx developers): 1.12.4 on 16 Oct 2026; positions as a drop-in replacement; adds to open source what nginx kept paid or lacked: JSON statistics API, Prometheus, console, built-in ACME (`acme_client`, certificates API in 1.12.0), HTTP/3 to upstreams, Docker upstream discovery, `slow_start`, sticky, `mqtt_preread`, DNS over HTTPS; a commercial Angie PRO exists. [F] — [Angie](https://en.angie.software/angie/), [Angie 1.12.0 release](https://en.angie.software/news/releases/angie-1-12-0/), [dev.to migration account](https://dev.to/stan-breaks/migrating-from-nginx-to-angie-a-real-world-journey-from-certbot-to-built-in-acme-7a3)
- **Sōzu**: 1.0.x through 2024 (1.0.6 Dec 2024 per a mirror); **2.0.0 on 29 May 2026** with a new H1/H2 multiplexer, active health checks, runtime listener updates, hot upgrade, URL/header rewriting, redirects, Basic auth, HSTS, per-IP connection cap, post-quantum key exchange by default. HTTP/3 is "a future step". No mention of static files, caching, compression or FastCGI: it is a proxy only. [F] — [Clever Cloud blog](https://www.clever.cloud/blog/engineering/2026/05/29/sozu-2-0-reverse-proxy-programmable-edge/), [Sōzu mirror](https://sourceforge.net/projects/s-zu.mirror)
- **nginx's own 2025–2026 additions** (section 0) are partly a response to this field: ACME, sticky, least_time, resolve, keep-alive defaults, control API all appeared in open source after Angie and Caddy had them. This causal reading is mine; the dates are sourced in section 0.

### Inferences
- First-stable scope across Caddy 2.0, Ferron 2, Sōzu 1.0, River's target: static files (not Sōzu), reverse proxy with basic balancing, TLS with automation, HTTP/2, access logs, config reload. Left out at first stable and still survivable: response caching, rate limiting (Caddy), HTTP/3 (Sōzu even at 2.0), WAF, scripting, `.htaccess`.
- Caddy shows the risk of leaving something out "for plugins": six years later the omission (rate limit, cache) is still the first line of every comparison.
- Ferron shows the opposite strategy: tick every box quickly (CGI, SCGI, forward proxy, LSCache-style PHP caching, Fail2ban, StatsD) at the price of three majors in two years; I found no evidence of resulting adoption (not in W3Techs' list).
- Forks (Angie) compete by un-paywalling features rather than by new architecture.
- What correlates with staying power in this set is release cadence, packaging and documentation (Caddy, Angie, Sōzu), not breadth at 1.0.

### Gaps
- **freenginx** was not researched (no query run); nothing about it is asserted here.
- Caddy 1.0's feature list at release was not on the release page; the year of both Caddy releases is from memory.
- Ferron 2.0's release year and its exact feature list at 2.0 were not confirmed (the "04 Nov" date lacked a year; context suggests 2025).
- Pingora's own release state in 2026 was only seen through secondary sources.
- No adoption numbers for Angie, Ferron or Sōzu.
