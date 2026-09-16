# What users ask for, and complain about, in the popular web servers

Compiled 2026-09-16 from issue trackers (GitHub reactions for nginx and Caddy), vendor
forums, community threads and comparison articles, to check agensio's roadmap against real
demand. Items marked (T) come from tracker data sorted by 👍 reactions; the rest is the
recurring theme in community discussion. Sources at the end.

## Cross-cutting: the ten things people keep asking every server for

1. **HTTPS that needs no thought**: built-in ACME including DNS challenges for hosts that
   are not reachable from the internet, certificate hot-reload when files change, short-lived
   certificate profiles. Caddy set the bar; nginx only got a (HTTP-01-only, Rust module)
   ACME in 1.29 in 2025; Apache has mod_md but not by default; IIS needs win-acme.
2. **Configuration without footguns**: nginx's "if is evil" and location precedence,
   Apache's directive sprawl and 2.2 to 2.4 `.htaccess` breakage, IIS's XML, Caddy's two
   config models. Users want presets for common apps and a validator that explains.
3. **Observability built in**: Prometheus metrics (per upstream, per certificate),
   structured JSON logs, a request id in error logs, OpenTelemetry hooks. nginx open source
   has only `stub_status`; the metrics API is a Plus feature.
4. **Reload without dropping anything**: config, certificates and upstreams changed at
   runtime; nginx needs a full reload and blocks new QUIC connections during it; Apache and
   OpenLiteSpeed need restarts for parts of their config.
5. **HTTP/3 as a first-class protocol** with congestion control, proxy-protocol support and
   HTTP/3 to backends. Apache has none and no roadmap.
6. **Dynamic upstreams and health checks in the free version**: DNS re-resolution without
   reload, active health checks, sticky sessions, load-balancing methods.
7. **No feature gating between free and paid**: the nginx Plus gap and the OpenLiteSpeed
   versus Enterprise gap are the two most repeated complaints; both spawned forks or
   alternatives (freenginx, Angie).
8. **Predictable, low resource use**: Caddy OOM reports and Go GC memory, Apache's
   process-per-connection footprint.
9. **Extending without rebuilding**: nginx third-party modules must be compiled in,
   Caddy plugins are compile-time via xcaddy, IIS relies on separate installer add-ons.
10. **Security posture as a feature**: rate limiting, basic WAF, hidden-file and header
    defaults, and memory-safety confidence in the protocol code (nginx's 2026 advisory
    spike in HTTP/2 and HTTP/3 code is cited widely).

## nginx

Top requests
1. (T) io_uring support: the most upvoted open issue.
2. (T) BBR congestion control for QUIC; `ssl_preread` on QUIC; `listen quic` with
   `proxy_protocol`; new QUIC connections blocked during reload.
3. (T) Prometheus metrics module and the upstream API in open source (Plus-only today).
4. (T) Monitor certificate files and reload automatically.
5. (T) Error log customisation: format, request id, structured (JSON) logs, syslog RFC 5424,
   configurable log file permissions.
6. (T) HTTP/3 to backends; 103 Early Hints without upstream support.
7. ACME with DNS-01 challenge (the 1.29 module is HTTP-01 only; Angie's supports DNS).
8. Dynamic upstreams and DNS re-resolution without reload (third-party dyups/upsync exist).
9. Active health checks and session persistence in open source.
10. Brotli and other common modules built in rather than compiled by the user.

Top criticisms
1. `if` semantics, location precedence and rewrite-outside-location pitfalls.
2. Open source versus Plus gating (API, health checks, sticky sessions, metrics).
3. F5 stewardship: the original authors forked to Angie, freenginx exists, and the
   community Ingress NGINX retirement (Dec 2025) left Kubernetes users scrambling.
4. Reload model: full reload for everything; QUIC connections stalled by it.
5. Late and partial ACME; certbot cron jobs as the norm for a decade.
6. Module ecosystem requires source builds and breaks across versions.
7. Observability is thin without Plus.
8. Memory-safety advisories concentrated in HTTP/2 and HTTP/3 code.
9. Text configuration with `-t` as the only validation; cryptic error messages.
10. Rate limiting and WAF are basic or third-party.

## Caddy

Top requests
1. (T, 38) Use Let's Encrypt's short-lived certificate profile by default.
2. (T, 21) DNS-PERSIST challenge type.
3. (T, 17/14) Prometheus metrics for reverse-proxy upstreams and for certificates.
4. (T, 13) Bind to an interface name rather than an IP.
5. (T, 12) Caddyfile placeholders with default values (expressiveness).
6. (T, 9) `Forwarded` header (RFC 7239).
7. (T, 8) Shared-dictionary compression; embedded ACME proxy.
8. (T, 7/6) Per-site ECH; automatic reload of TLS certificates from the filesystem;
   certificate pinning for insecure upstreams.
9. (T, 5) Per-log filtering; OTEL exporter protocol env var.
10. Runtime plugin loading instead of xcaddy rebuilds (community, long-standing).

Top criticisms
1. Memory: OOM kills and multi-gigabyte RSS reported in proxy and file-server setups.
2. Throughput and CPU per request well below nginx (our benchmark: 3 to 4x fewer req/s,
   20 to 30x the CPU per request on small files).
3. Plugins are compile-time only; the add-package flow is flaky.
4. Caddyfile hits limits on complex setups; the JSON model is verbose; two mental models.
5. Admin API on localhost with no auth by default; CVE-2026-27589 cross-origin bypass.
6. Conservative defaults that need tuning for production.
7. ACME surprises: CA rate limits, on-demand TLS abuse, DNS provider plugins required.
8. (T) Random 502 state across all domains (SSE-related) in recent versions.
9. Smaller operations mindshare and fewer battle-tested recipes than nginx.
10. Behavioural changes between versions breaking plugins and configs.

## LiteSpeed (Enterprise) and OpenLiteSpeed

Top requests
1. Live `.htaccess` reload in OpenLiteSpeed (the single most repeated forum ask).
2. Configuration changes without a graceful restart in OpenLiteSpeed.
3. Better documentation and community support for OpenLiteSpeed.
4. More Enterprise features in the open edition (full cache, ESI).
5. Cheaper or per-site pricing tiers.
6. Panel integrations beyond cPanel, DirectAdmin and CyberPanel.
7. Cache modules for applications other than WordPress.
8. A public issue tracker and roadmap for Enterprise.
9. Full Apache rewrite-rule parity in OpenLiteSpeed.
10. Windows support.

Top criticisms
1. OpenLiteSpeed is deliberately limited (`.htaccess`, restarts) to upsell Enterprise.
2. Enterprise is closed source with lock-in and "very high" pricing in reviews.
3. Forum moderation deleting criticism (reported in vendor forums).
4. LSCache breaking WordPress sites through caching conflicts.
5. Small community; support is commercial.
6. WebAdmin console on port 7080 as an extra attack surface.
7. Partial Apache compatibility in the open edition.
8. A PHP and WordPress hosting story more than a general-purpose server.
9. Vendor-published benchmarks lack independent confirmation.
10. Linux only.

## Apache httpd

Top requests
1. HTTP/3: none exists and there is no roadmap; retrofitting UDP means a core rewrite.
2. A release after 2.4 (2012); trunk 2.5 has been unreleased for years.
3. Simpler configuration and modern defaults out of the box.
4. mod_http2 stability and performance.
5. Structured logging and a metrics endpoint beyond mod_status.
6. `.htaccess` flexibility without the per-directory lookup cost.
7. ACME by default (mod_md exists but is rarely enabled).
8. Reverse-proxy ergonomics comparable to nginx.
9. Hot reload or a runtime API.
10. Clearer documentation for the event MPM plus PHP-FPM as the standard setup.

Top criticisms
1. Memory and concurrency under prefork with mod_php; benchmarks show several times
   the memory of nginx for a fraction of the throughput.
2. Configuration complexity; the 2.2 to 2.4 access-control change broke countless
   `.htaccess` files.
3. `.htaccess` lookups on every path component.
4. No HTTP/3.
5. Fourteen years on the 2.4 line.
6. Weak as an edge proxy.
7. Little observability.
8. Module sprawl and defaults that leak information.
9. Dense documentation.
10. Steady CVE volume across modules.

## IIS

Top requests
1. Built-in ACME; today win-acme plus a web.config workaround because IIS refuses to serve
   the extensionless ACME challenge file by default.
2. HTTP/3 on more than Windows Server 2022+ with registry toggles.
3. ARR and URL Rewrite as first-class parts rather than separate installers.
4. JSON or structured logging beyond W3C format.
5. Configuration as code that is not XML in two places (web.config, applicationHost).
6. TLS cipher and protocol management without Schannel registry edits.
7. CLI and PowerShell parity with the GUI.
8. Built-in rate limiting and WAF beyond dynamic IP restrictions.
9. A container and cross-platform story (Microsoft points to Kestrel and YARP instead).
10. Open source or at least a public tracker.

Top criticisms
1. Windows only, with licensing cost.
2. XML configuration and GUI-centric administration with hidden inherited settings.
3. Performance overhead and a reputation for struggling under high load.
4. ARR reverse-proxy troubleshooting is notoriously painful.
5. Let's Encrypt friction.
6. Small community; Microsoft's own investment moved to Kestrel and YARP.
7. Schannel TLS configuration via the registry.
8. Limited logging.
9. Historic security reputation.
10. Slow feature evolution.

## What this means for agensio's roadmap

Already covered: presets over knobs (D3), control API and hot reload (C, G1), reverse proxy
with `Forwarded` (E2), HTTP/3 (H), no paid tier, low memory by design, hidden-file defaults.

Added to the roadmap on 2026-09-16 because of this research:
- certificate file watching with automatic reload (G1), the one request nginx and Caddy
  users share most;
- ACME with DNS-01 as well as HTTP-01 and TLS-ALPN-01 (G3), since HTTP-01-only is the
  main criticism of nginx's new module;
- Prometheus metrics per upstream and per certificate, structured JSON logs with a
  request id, OpenTelemetry-compatible trace headers (C2, G5);
- 103 Early Hints (B), shared-dictionary compression noted for later;
- reload semantics must keep QUIC connections alive (H3);
- a public principle: every feature is in the open build, nothing is gated.

## Sources

nginx: https://github.com/nginx/nginx/issues (reactions sort),
https://blog.nginx.org/blog/native-support-for-acme-protocol,
https://algustionesa.com/nginxs-native-acme-a-welcome-complicated-step/,
https://dev.to/stan-breaks/migrating-from-nginx-to-angie-a-real-world-journey-from-certbot-to-built-in-acme-7a3,
https://www.theregister.com/2025/12/02/ingress_nginx_opinion/,
https://gixy.org/guides/if-is-evil, https://braindumpk.substack.com/p/nginx-config-pitfalls,
https://gpt-lab.eu/nginx-vulnerabilities/,
https://www.managedserver.eu/nginx-vs-nginx-plus-why-upgrade-from-open-source-to-commercial-version/
Caddy: https://github.com/caddyserver/caddy/issues (reactions sort),
https://github.com/caddyserver/caddy/issues/6751, https://github.com/caddyserver/caddy/issues/5366,
https://caddy.community/t/cpu-and-memory-usage-are-very-high/24754,
https://caddy.community/t/state-of-add-packages-and-xcaddy/30846,
https://adhdecode.com/articles/caddy/caddy-performance-tuning/
LiteSpeed: https://forum.openlitespeed.org/threads/htaccess-support.58/,
https://forum.directadmin.com/threads/openlitespeed-v-litespeed-plugin.70085/,
https://www.capterra.com/p/186217/LiteSpeed-Web-Server/reviews/,
https://www.litespeedtech.com/support/forum/threads/litespeed-censors-all-criticism-and-deletes-posts.23369/,
https://www.litespeedtech.com/products/litespeed-web-server/editions
Apache: https://sumguy.com/apache-vs-nginx-vs-caddy-2026/, https://sa.net/blog/nginx-vs-apache-vs-caddy/,
https://httpd.apache.org/docs/2.4/misc/perf-tuning.html, https://www.php.net/manual/en/install.unix.apache2.php,
https://gist.github.com/ernolf/00cd9b7a12e333dd8aac8bed2379937d
IIS: https://www.xeams.com/letsenc-with-iis.htm,
https://community.letsencrypt.org/t/letsencrypt-for-iis-web-server-install/108183,
https://www.coryretherford.com/Lists/Posts/Post.aspx?ID=444,
https://techcommunity.microsoft.com/t5/iis-support-blog/application-request-routing-part-2-reverse-proxy-and/ba-p/347937,
https://g2.com/products/internet-information-services-iis-for-windows-server/reviews
Cross-cutting: https://colonelserver.com/blog/best-open-source-web-servers-in-2026/,
https://community.f5.com/kb/technicalarticles/f5-nginx-plus-r35-release-now-available/342962
