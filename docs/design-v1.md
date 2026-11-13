# Version 1: scope, readiness and stages (draft)

Status: **draft for the owner's review, 2026-11-13. Nothing here is decided.** Every row carries a
recommendation ("1.0", "after", "no") that the owner confirms or changes; section 7 lists the
questions only the owner can answer. Written at 0.1.0-alpha.145, after the roadmap was held to the
code (`docs/ROADMAP.md`, the lines starting "Audit 2026-11-13").

What it rests on:

- `reports/Web server v1 readiness 2026.md`: the research of 2026-11-13 (129 sources) and its
  notes in `research_notes/Web server v1 readiness 2026/`. Six notes are web research: the HTTP
  standards a server is expected to implement in 2026, TLS and certificates, the feature matrix
  of nginx, Apache, Caddy, LiteSpeed, h2o, HAProxy and Traefik, what administrators ask for and
  complain about, what some forty applications require of the server, and what a stable release
  needs beyond features. Four are readings of agensio's code against the RFC texts in
  `docs/rfc/`, requirement by requirement: `audit_http1_semantics.md` (about 185 requirements),
  `audit_http2.md` (132), `audit_http3_quic.md` (about 275), `audit_tls_acme.md`.
- Two limits of that evidence. The audits were made by reading, not by running: a row is a
  fact here only where it says "seen" (the owner's agent read the code path afterwards) or
  "reproduced"; every other row is the audit's reading and gets its failing test before it is
  called a bug. And the administrators' ranking could not read Server Fault, Stack Overflow or
  Reddit (they refuse automated readers): it is a judgement from GitHub trackers, the nginx and
  Caddy forums and Hacker News, not a count of votes.

The rule the owner set for this plan: the RFCs come first. agensio 1.0 does what RFC 9110, 9112,
9113, 9114, 9000 to 9002, 7541 and 9204 require of a server and of a gateway, and says in
writing where it deliberately does not; then what every established server offers; then what
administrators and applications need.

## 1. What the reading found, in short

- The protocol cores are sound: 52 of 69 requirements of RFC 9112, 78 of 109 of RFC 9113 and 70
  of 107 of RFC 9000 are met in full, HPACK and HSTS without a gap, and no defect was found in
  agensio's own TLS code that a remote client can use.
- 121 rows are partly met or unmet. Most are edges no well-behaved client reaches. About a dozen
  matter, and one was a security defect, reproduced and fixed the same day (1.1).
- They share a pattern: agensio is careful with the bytes it means to use and loose with the
  bytes it has decided not to use. An unread body's window credit, a HEADERS frame after its 431,
  CRYPTO data after the handshake, an upload cut by an early answer: each is a discard path. A
  review organised around "what happens to input after the answer is decided" finds the rest of
  that family faster than another pass through the RFCs.
- The design documents run ahead of the code in nearly twenty places (`docs/design-http2.md`,
  `docs/design-http3.md`, `docs/tls.md`). An outside reviewer reads their threat tables as
  claims, so they are brought in step as each row is fixed.
- Against the incumbents the feature gaps are short lists (sections 3 and 4). The long pole is
  not a feature: every comparable project ran about six months with its feature set frozen, in
  other people's production, before it called a release stable (section 5).

### 1.1 Fixed while this was written

Over HTTP/2 and HTTP/3 the values of `:method`, `:path` and `:authority` were stored unchecked and
a request target was examined only up to its `?`, so bytes HTTP/1 can never carry reached a
proxied origin's request head (RFC 9113 8.2.1 and 10.3, RFC 9114 4.2 and 10.3). Reproduced on
0.1.0-alpha.145, fixed in the working tree for 0.1.0-alpha.146: the HTTP/1 parser's own rule for a
request line and a Host field, byte for byte, once per table entry (`core/fields.hpp`,
`http/request_assembly.hpp`; the unit test, `tests/pseudo-header-bytes.py`;
`bench/results/ab-20261113-192601.md`). PHP and CGI sites were not exposed to the framing
problem; proxied sites reached over HTTP/2 or HTTP/3 were.

## 2. Conformance and security: all of it is 1.0

The first block of work, before any feature: one row, one failing test, one commit, in this
order (what a client can reach from outside first). "Seen" and "audit" are explained above.

### 2.1 Reachable by a hostile client

| # | What | Where | State | Rec. |
|---|---|---|---|---|
| S1 | Pseudo-header values validated | `http/request_assembly.hpp` | reproduced, fixed (1.1) | 1.0, done |
| S2 | HTTP/3: `content-length` held to the DATA bytes (RFC 9114 4.1.2). The design says it is; the code checks only the body limit. Matters on a proxy location with `request_buffering = false` | `http3/connection.hpp` | seen | 1.0 |
| S3 | QUIC: CRYPTO data after the handshake is kept without a bound, because nothing consumes it once the handshake is done (RFC 9001 4.1.3, 6) | `quic/tls.cpp`, `quic/connection.hpp` | seen | 1.0 |
| S4 | HTTP/3: a HEADERS frame over `max_header_size` is answered 431 and its remaining bytes still stored | `http3/connection.hpp` | seen | 1.0 |
| S5 | HTTP/2: connection window credit not returned for a body that arrived whole and no handler read (a POST answered 401, 403, 404, 405): uploads on that connection stall after about 1 MB of such bodies. The same for QUIC's connection credit on reset or abandoned bodies | `http2/connection.hpp`, `quic/` | audit, the line seen | 1.0 |
| S6 | QUIC: a connection id entry can be displaced by an Initial whose id starts with a live connection's, which then draws a stateless reset (RFC 9000 21.11) | `quic/udp.hpp` | audit | 1.0 |
| S7 | QUIC: the three-times limit does not hold in the closing state (RFC 9000 8.1); this is the attack suite's missing amplification row | `quic/connection.hpp` | audit | 1.0 |
| S8 | HTTP/2: a header block for a refused stream is decoded with the result ignored (RFC 9113 4.3) | `http2/connection.hpp` | audit | 1.0 |
| S9 | The decoded size of a field section: the running total with 32 bytes a field is in both decoders (seen: the October 2026 disclosure that hit seven of ten HTTP/3 stacks does not apply); what is missing is the suite row and the fuzz invariant that hold it | `http2/hpack.cpp`, `http3/qpack.cpp` | seen: met | 1.0 (the test) |

### 2.2 RFC requirements of an origin server and a gateway

| # | What | State | Rec. |
|---|---|---|---|
| C1 | `If-Match` and `If-Unmodified-Since` evaluated, 412 (RFC 9110 13.1.1, 13.1.4): a resumed download guarded by either gets a 206 of a changed file today | seen | 1.0 |
| C2 | The absolute-form request target accepted, the host taken from it (RFC 9112 3.2.2) | seen | 1.0 |
| C3 | An origin's interim 1xx on a streamed proxy location is delivered as the final answer; the decoded path goes to an origin whose upstream has a URI part. Both read, not run: the test first | audit (medium), the lines seen | 1.0 |
| C4 | A gateway forwards 1xx (RFC 9110 15.2): 103 Early Hints relayed from an origin, over all three protocols (ROADMAP E8) | not built | 1.0 |
| C5 | Gateway duties in one change: `Host` on a forwarded HTTP/1.0 request, `Upgrade` ignored on HTTP/1.0, fields named by an origin's `Connection` and `Proxy-Connection`, `Trailer`, a non-101 `Upgrade` removed from responses, differing `Content-Length` lines from an origin refused, and a written decision on `Via` and `Max-Forwards` | audit | 1.0 |
| C6 | Small origin answers: 414 for an over-long request line (431 today), a page of its own for 416, `Last-Modified` never in the future, an invalid `Host` refused with 400, 501 or 405 for an unknown method decided and documented | audit | 1.0 |
| C7 | A lingering close after an early error answer (a 413 during an upload can be lost to a reset today) | audit | 1.0 |
| C8 | HTTP/2 stream-state edges: the 413 on a body of unknown length, frames in flight after the server's own reset, idle against closed streams, a PRIORITY frame of the wrong length, trailers validated, `Expect: 100-continue` answered, budgets not charged for frames the RFC says to ignore | audit | 1.0 |
| C9 | The small QUIC, HTTP/3 and QPACK MUSTs in one pass (duplicate suppression floor, idle period of three PTOs, the old path probed on migration, reserved frame types, frames after trailers, GOAWAY and push ids checked, QPACK references bounded by the Required Insert Count) | audit | 1.0 |
| C10 | QUIC congestion control: pace or limit bursts (RFC 9002 7.7 is a MUST), the application-limited rule, every in-flight packet gated by the window; CUBIC beside NewReno while it is open (nginx has it since 1.27.5) | audit; ROADMAP I3 | 1.0 |
| C11 | TLS: a handshake whose ALPN list has nothing in common refused with the alert (RFC 7301 3.2; it continues as HTTP/1.1 today) | seen | 1.0 |
| C12 | TLS to origins: `close_notify` sent, a close-delimited body that ends without one treated as incomplete | audit | 1.0 |
| C13 | The deviations kept on purpose, each with its reason, in one page (`docs/conformance.md`): what agensio does not implement of the optional parts (multiple ranges, trailers passed through, TRACE, forward-proxy CONNECT, server push, 0-RTT) and where it is stricter than the RFC | not written | 1.0 |

### 2.3 Hardening

| # | What | State | Rec. |
|---|---|---|---|
| H1 | **A stop that drains.** SIGTERM ends HTTP/1 and HTTP/2 requests in flight at once; only HTTP/3 gets a GOAWAY, with the close in the same call. `Connection: close`, GOAWAY in two steps, a deadline. Every upgrade is a restart, so every upgrade cuts requests today (ROADMAP E4) | seen | 1.0 |
| H2 | TLS policy: an ECDHE AEAD suite list for TLS 1.2 by default so HTTP/2 never runs on a suite RFC 9113 9.2.2 lists, `SSL_OP_NO_RENEGOTIATION` set and not left to the library, and keys for the minimum version and a profile (the Mozilla guideline's modern and intermediate, version 6.0). Today only the TLS 1.2 floor and no-compression are set; the rest is each distribution's OpenSSL default | seen | 1.0 (the default is a behaviour change: section 7) |
| H3 | Session ticket keys rotated on a schedule with a key ring (they change only at a reload or restart today; RFC 9325 3.4) | audit | 1.0 |
| H4 | ACME robustness: key and chain replaced as one checked unit (the key is written first today), `Retry-After` honoured, back-off kept across restarts, the downloaded chain checked | seen (write order), audit | 1.0 |
| H5 | HTTP/3 request timers per stream (a request body's own timer; deferred 2026-10-26) | known | 1.0 |
| H6 | The attack suites still open: `tests/h2-attacks.py` with memory sampled (rapid reset, MadeYouReset, CONTINUATION, HPACK bomb, floods), the QUIC amplification row, HTTP/2 counters in status and health (ROADMAP G3, I2) | not built | 1.0 |
| H7 | A health finding for a private key readable by others; handshake failures counted by reason in status | audit | 1.0 |
| H8 | Build flags against the OpenSSF hardening guide of 2026-08 (`_FORTIFY_SOURCE=3`, stack-clash, CET, strict flex arrays), each through the A/B gate; the systemd unit tightened (`NoNewPrivileges` is false today) and its `systemd-analyze security` score published | own check | 1.0 |
| H9 | Kernel containment of the server itself: `openat2(RESOLVE_BENEATH)`, Landlock, seccomp (ROADMAP H3b). No mainstream server applies these to itself; unit hardening (H8) is the common practice | not built | after |

## 3. What every established server has and agensio lacks

Present in nginx, Apache, Caddy and LiteSpeed alike. The floor is small and agensio is five items
short of it.

| # | What | Rec. |
|---|---|---|
| F1 | Custom error pages per site (ROADMAP H4) | 1.0 |
| F2 | Directory listing, off by default | 1.0 |
| F3 | A status or metrics endpoint a monitoring system scrapes over HTTP (Prometheus text), with per-upstream and per-certificate figures; a request id in the access and error logs (ROADMAP F2b, H5) | 1.0 |
| F4 | TLS policy keys | 1.0, with H2 |
| F5 | Rewrites with captures | no regex engine; see A6 to A8 for what replaces it (section 7) |
| F6 | TLS client certificates. The feature notes infer all five have them; a hosting server rarely needs them, and since Let's Encrypt dropped client authentication from its certificates in 2026 they need a private CA | after |

## 4. What applications and administrators expect

| # | What | Who needs it | Rec. |
|---|---|---|---|
| A1 | **Extension methods passed to applications**: PROPFIND, REPORT, MKCOL, the QUERY method (RFC 10008). Only seven methods reach an application today, so no WebDAV or CalDAV application works | Nextcloud and every DAV application (seen) | 1.0 |
| A2 | `X-Accel-Buffering: no`, `text/event-stream` and `Incremental: ?1` (RFC 10036) honoured on a buffered location (compression plan, step 8) | Next.js, Drupal BigPipe, Nextcloud, Mercure, Discourse | 1.0, next |
| A3 | The rest of the compression plan's step 7 (`path_check`'s reasons, health, the log fields) | the agent | 1.0 |
| A4 | Internal redirect for protected downloads, both dialects: the `X-Accel-Redirect` answer and the negotiated `X-Sendfile-Type` request field | Moodle, WooCommerce, Rails, Discourse, Symfony | 1.0 |
| A5 | Managed application processes (F14: the unit installed by the helper, start, stop, restart) and "static first, else the upstream" (design-site-operations 5 and 7) | Laravel queues, Octane and Reverb, Rails, Django, Node | 1.0 |
| A6 | Wildcard `server_name` routed (a certificate's wildcard is matched today; a site is found by one hash lookup of the exact name) | WordPress multisite in subdomain mode, SaaS sites | 1.0 |
| A7 | One leading path segment stripped before routing | WordPress multisite in subdirectory mode | section 7 |
| A8 | A `try_files` target built from host, path and query with method and cookie conditions; capture and substitute | file-based page caches (WP Super Cache, W3 Total Cache, Statamic full measure; each also works through PHP), Magento, PrestaShop | after |
| A9 | ACME Renewal Information (RFC 9773). Let's Encrypt's default goes to 64 days in February 2027 and 45 in February 2028, with renewals expected by ARI | every site with `tls = "auto"` | 1.0 |
| A10 | TLS-ALPN-01 (no port 80), external account binding and a second CA as fallback; `docs/tls.md` corrected meanwhile (it names CAs that need the binding) | hosts without port 80; ZeroSSL, Google | 1.0 for TLS-ALPN-01, after for the rest |
| A11 | Wildcard certificates through DNS-01 with a hook (ROADMAP H3a) | wildcard sites | after |
| A12 | Upstream pool state in status (in flight, queued, idle, last failures): the first answer to "why is this site 502?" (ROADMAP F2b) | every PHP host | 1.0 |
| A13 | Presets for Symfony, Joomla, Nextcloud and Moodle (the two panels read both ship them); Matomo, MediaWiki, CodeIgniter, phpBB by the documented way (`app = "php"` with rules) | hosts | 1.0 for the four |
| A14 | A container image and aarch64 packages (ROADMAP H7) | ARM servers, containers | 1.0 |
| A15 | The upstream prober: `upstream_unreachable`, `upstream_exposed` (design-site-operations 6) | proxied sites | 1.0 |
| A16 | HTTP/2 to origins (in nginx since 1.29.4, HAProxy, Apache, Caddy) | gRPC; the 2025 desync research's "upstream HTTP/2" advice | after |
| A17 | RFC 9218 priorities for HTTP/2 and HTTP/3 (nginx 1.31.7) | browsers | after |
| A18 | A response cache for PHP and proxied answers with purge | WordPress hosts (built into nginx and LiteSpeed, not into Caddy) | after; the position stated (section 7) |
| A19 | A one-line block by user agent or network list (AI crawlers); request limits per address stay the firewall's and fail2ban's (decided 2026-10-02), the position documented | administrators | section 7 |
| A20 | PROXY protocol on a listener; upstream host names resolved again | hosts behind a load balancer | after |
| A21 | Active health checks, sticky sessions, more balancing algorithms | load balancers | after |
| A22 | WebSocket over HTTP/2 and HTTP/3, HTTP/3 to origins, 0-RTT, ECN, NEW_TOKEN, active migration, QUIC v2, datagrams, ECH (needs OpenSSL 4), OCSP stapling (Let's Encrypt ended OCSP in 2025), DNS-PERSIST-01, on-demand issuance | | after or no |
| A23 | `.htaccess` emulation; a web UI; Windows and macOS as production platforms | | no: a migration guide, the agent interface, a statement |

## 5. Readiness that is not a feature

What a stranger needs before trusting a young server, in the order the research found it asked
for: benchmarks against nginx with a standard tool (built), packages and an upgrade path
(built), proof for security claims, a visible feature list and working documentation, signs of
commitment, and since 2026 evidence that code and documentation are reviewed and not unreviewed
AI output.

| # | What | Rec. |
|---|---|---|
| R1 | This scope, with its "not in 1.0" list and the rule for an experimental feature inside a stable release (it is in scope for security fixes unless the policy says otherwise) | 1.0 |
| R2 | "Stable" defined in writing: what is frozen, how long a release is maintained, how deprecations are announced | 1.0 |
| R3 | The freeze at beta: configuration keys, the command line, the control API and MCP tools, log formats. From then a change needs a deprecation; the configuration migration mechanism is built and exercised once before 1.0 (the owner's rule of 2026-10-19: none until then) | 1.0 |
| R4 | `SECURITY.md`: a private channel, a response time, the supported versions, GitHub advisories as the route to a CVE. None exists today | 1.0, now |
| R5 | Run what the audits only read: every row marked medium or low, and the four "could not determine" tables (several depend on OpenSSL's QUIC API) | 1.0 |
| R6 | Outside checks made public: a row in the QUIC interop matrix with the declined cases named, an HTTP/1 differential run (HTTP Garden or Http11Probe) with each deliberate deviation, a TLS scanner run per target distribution, h2spec | 1.0 |
| R7 | An independent audit, staged: the network surface before authentication and the root helper first. Published audits of comparable code ran 25 person-days to 9.5 weeks | section 7 |
| R8 | Continuous fuzzing with coverage published (ClusterFuzzLite or the like; OSS-Fuzz asks for a user base first); soak and fault-injection runs with memory, descriptors and errors recorded; memory per HTTP/3 connection measured (ROADMAP H6, I3) | 1.0 |
| R9 | Documentation: migration guides from nginx and Apache, an upgrade and rollback guide, `docs/install.md` 4.2 and 4.3 written or macOS and Windows stated as unsupported for production, the design documents and `docs/tls.md` in step with the code | 1.0 |
| R10 | Signed release artefacts, a bill of materials, provenance from the release job; the OpenSSF Best Practices badge | 1.0 |
| R11 | A statement on continuity (one maintainer) and one on AI-assisted development and how it is reviewed | 1.0 |
| R12 | The checkpoints that need only a record: a browser's HTTP/3 connection, control traffic beside a data-plane load, "a real site for a week with an ops guide" | 1.0 |

## 6. Stages

1. **Alpha, as now.** Section 2 first, a row at a time; then sections 3 and 4 in the order the
   owner sets; R4 at once. Releases as today, the configuration still free to change.
2. **Beta: the feature freeze.** Everything marked 1.0 in sections 2 to 4 is built. R1 to R3
   are written, the migration mechanism exists, R6's results are public. From here only fixes.
   Operators other than the owner run it on distinct workloads; the comparable projects needed
   about six months at this stage (HAProxy's stable branch about six, Caddy 2 eight, Traefik 3
   sixteen), and the clock starts only when keys stop changing.
3. **Release candidate.** The audit's findings (if R7 is taken) and the beta's reports are
   fixed, R9 is complete, no open row of section 2.
4. **1.0.**

## 7. Questions for the owner

1. **The 1.0 line.** Are the recommendations of sections 2 to 5 the scope? In particular the
   larger ones marked 1.0: managed processes (A5), four presets (A13), aarch64 and a container
   image (A14), CUBIC with pacing (C10), 103 relayed (C4), directory listing (F2).
2. **The TLS default (H2).** Restricting TLS 1.2 to ECDHE AEAD suites refuses the clients that
   offer none, those older than the Mozilla intermediate profile's list (roughly from before
   2014). It is what that profile and every scanner ask for; it is also a change of behaviour,
   so it waits for a yes.
3. **Rewrites (F5, A7, A8).** No regex engine in 1.0, and typed primitives for the cases
   applications really need? If so, is WordPress multisite in subdirectory mode in 1.0 (one
   primitive, A7), and are Magento and PrestaShop named as not supported from their official
   configuration?
4. **The response cache (A18).** After 1.0 as recommended, with the position written down, or
   in? It is the one feature WordPress hosts will name first.
5. **Bots (A19).** A user-agent block inside the server is a test on the request path for every
   request of a site that sets it. Build it as a site key that costs nothing when unset, or keep
   the position that this is the firewall's and fail2ban's?
6. **The audit (R7).** Seek one before 1.0 (a funded programme, or paid), or call 1.0 without and
   say so?
7. **The beta's length and its operators.** Six months, or a count of sites and weeks? Who
   besides the test VPS?
8. **Platforms.** Linux only for production in 1.0, macOS and Windows "builds, unsupported"?
9. **HTTP/3's timers (H5).** Deferred on 2026-10-26; this plan puts them back in 1.0.

## 8. The preset reviews

The owner will ask the WordPress, Laravel and Drupal communities whether the presets are
complete. The report's section "Asking the WordPress, Laravel and Drupal communities" has the
venues and a checklist per application drawn from each project's own files. In short:

- **WordPress** is where a listing is realistic: the Hosting Team (`#hosting` on the WordPress
  Slack; the server-environment page and the Advanced Administration handbook are edited on
  GitHub, and the first already lists Angie and OpenLiteSpeed beside Apache and nginx).
- **Laravel** documents nginx and FrankenPHP only: a review goes through the framework's GitHub
  Discussions or `#internals` on its Discord; Laracasts and r/laravel for users.
- **Drupal** ships no nginx file and says administrators recreate the `.htaccess` protections
  themselves: a preset is reviewed against `.htaccess`, in Drupal Slack or the forum.
- A review is easiest to pass as a line-by-line mapping of the project's own file to the preset.
- For proxied applications each project keeps a community list of proxy examples (Vaultwarden,
  Uptime Kuma, Gitea, Forgejo, Synapse, Jellyfin, Grafana, Nextcloud) that takes a snippet.

Before the first post, the cells the report marks "to verify" are checked on a live site, since
a reviewer will ask: `wp-admin/includes/` and the top-level `wp-includes/*.php`, the multisite
`ms-files.php` exception, Drupal's private files directory and `update.php/selection`, the
`Proxy` request header over FastCGI, `Authorization` passed to PHP, Livewire's
`/livewire/livewire.js`, `SCRIPT_FILENAME` from the real path, and the default lifetime of
static files. What a preset refuses beyond the project's own documentation (backups of
`wp-config.php`, for one) is said so in the mapping.
