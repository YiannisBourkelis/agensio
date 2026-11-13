# HTTP standards landscape for a production web server, November 2026

Researcher notes. State of the world as of 2026-11-13. Reading conventions:

- Classification letters used throughout: **(a)** required for conformance, **(b)** expected in practice (browsers, CDNs, clients, administrators), **(c)** optional but commonly shipped by competitors, **(d)** emerging, **(e)** deprecated / avoid.
- Classifications are my judgement (they sit under "Inferences"); the facts they rest on are under "Cited Findings" with a source each.
- **[PK]** marks a statement from prior knowledge that I did not re-verify against a page fetched in this session. Treat [PK] items as leads to confirm, not as findings.
- "Older than 2024" items are marked **[pre-2024, still holds]** or **[pre-2024, changed]**.
- Prompt-injection log: no fetched page or search result contained text that tried to instruct me. The only instruction-like strings seen were tool-generated ("REMINDER: You MUST include the sources…" appended by the search tool, and redirect notices from the fetch tool); they were treated as tool mechanics. Several search hits were auto-generated or low-quality aggregator pages (starlog.pages.dev, cavac.at, unseel.pages.dev, dev.to posts, wiki.linux-server-admin.com, technologychecker.io); where I use one it is flagged as secondary.
- Version oddity to keep in mind: the nginx changelog fetched today shows mainline **1.31.8 (21 Oct 2026)**; the brief's "1.28/1.29+" therefore means "the 2025 stable/mainline pair and later". Features below carry the nginx version that introduced them.

---

## 1. HTTP semantics, HTTP/1.1 and what remains of HTTP/1.0: which optional parts do production servers ship?

### Takeaway
The conformance core is small (GET/HEAD, strict message framing, Host handling, absolute-form acceptance, Date, conditional requests, correct 1xx/Expect behaviour); almost everything else in RFC 9110 is optional, and the competitive baseline in 2026 is set less by the RFC than by what nginx added in 2025-2026: 103 Early Hints from backends (1.29.0), trailers pass-through (1.27.2), HTTP/1.1 keep-alive to upstreams by default (1.29.7), HTTP/2 to backends (1.29.4), a header-count limit (1.29.8) and a CONNECT tunnel module (1.31.0). Three new RFCs since mid-2025 touch a server directly: RFC 9931 (close on rejected CONNECT), RFC 10008 (the QUERY method) and RFC 10036 (the `Incremental` field for proxies).

### Cited Findings

**New and current documents (httpbis)**
- RFCs published by the HTTP WG since 2024: RFC 9421 HTTP Message Signatures (2024-02), RFC 9530 Digest Fields (2024-02), RFC 9532 Proxy-Status next-hop aliases (2024-01), RFC 9651 Structured Field Values (2024-09, replaces 8941), RFC 9659 zstd window sizing (2024-09), RFC 9729 Concealed auth scheme (2025-02), RFC 9842 Compression Dictionary Transport (2025-09), RFC 9875 HTTP Cache Groups (2025-10), RFC 9931 Security Considerations for Optimistic Protocol Transitions in HTTP/1.1 (2026-03), RFC 10008 The HTTP QUERY Method (2026-06), RFC 10036 Incremental Forwarding of HTTP Messages (2026-08). — [IETF datatracker, httpbis documents](https://datatracker.ietf.org/wg/httpbis/documents/)
- In the RFC Editor queue (approved, not yet published): `draft-ietf-httpbis-rfc6265bis-22` (Cookies; "RFC Editor blocked: Final Approval Pending"), `draft-ietf-httpbis-connect-tcp-18` (template-driven CONNECT for TCP), `draft-ietf-httpbis-no-vary-search-10`, `draft-ietf-httpbis-unencoded-digest-05`. — [IETF datatracker, httpbis documents](https://datatracker.ietf.org/wg/httpbis/documents/)
- Active WG drafts: `draft-ietf-httpbis-resumable-upload-15` (2026-11-02, still a WG document), `draft-ietf-httpbis-layered-cookies-02`, `draft-ietf-httpbis-pre-denied-01` ("Purpose Declined" status code), `draft-ietf-httpbis-secondary-server-certs-03` (in WG Last Call). Expired/parked: `retrofit` structured fields (expired 2023), `rfc7838bis` Alt-Svc revision (parked since 2021), `variants` (parked), `wrap-up` capsule (expired 2025). — [IETF datatracker, httpbis documents](https://datatracker.ietf.org/wg/httpbis/documents/)
- RFC 10008 (QUERY) is a Proposed Standard dated June 2026 (authors Reschke, Snell, Bishop); ecosystem adoption was described as early in July 2026, with an open Jetty pull request the most concrete server-side implementation found. — [RFC 10008](https://www.rfc-editor.org/rfc/rfc10008.html); [datatracker draft history](https://datatracker.ietf.org/doc/draft-ietf-httpbis-safe-method-w-body/14/)
- Resumable uploads: still an Internet-Draft at -15 (November 2026); it defines the 104 (Upload Resumption Supported) interim status code and the `application/partial-upload` media type, with a temporary "upload resource" separate from the target. — [draft-ietf-httpbis-resumable-upload-15](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-resumable-upload-15)
- RFC 9931 updates RFC 9112: a proxy server "MUST close the underlying connection when rejecting a CONNECT request" without processing further requests on it; proxy clients acting for untrusted TCP clients must wait for the 2xx before forwarding payload or send `Connection: close`. For a rejected Upgrade the server simply keeps parsing HTTP/1.1; RFC 2817 "Upgrade: TLS" gets no new requirement. — [RFC 9931](https://www.rfc-editor.org/rfc/rfc9931.html)
- RFC 10036 defines `Incremental` (a Structured Field Boolean, `?1`): an intermediary that receives it "SHOULD NOT buffer the entire message before forwarding it"; one that refuses "MUST generate an error response rather than buffering" (501 with Proxy-Status `incremental_refused`, or 429 with `connection_limit_reached` when a concurrency limit for incremental requests is hit). Server-Sent Events are the named motivating case. — [RFC 10036](https://www.rfc-editor.org/rfc/rfc10036.html)
- Caddy already implements RFC 10036: messages with `Incremental: ?1` are forwarded as they arrive, a 501 is returned if buffering would prevent that ("requires Caddy 2.11.7 or newer"), and `proxy_status_name` sets the name used in the `Proxy-Status` header for these refusals. — [Caddy reverse_proxy docs](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)

**What the HTTP/1.1 text requires (verified against the RFC text kept locally, same as rfc-editor.org)**
- RFC 9112 2.2: "a recipient MAY recognize a single LF as a line terminator"; a sender "MUST NOT generate a bare CR", and a recipient of a bare CR "MUST consider that element to be invalid or replace each bare CR with SP". — [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)
- RFC 9112 3.2.2: "A server MUST accept the absolute-form in requests even though most HTTP/1.1 clients will only send the absolute-form to a proxy." — [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)
- RFC 9112 7.1.1: "A recipient MUST ignore unrecognized chunk extensions. A server ought to limit the total length of chunk extensions received in a request". — [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)
- RFC 9112 9.3 and appendix C.2.2 still describe the HTTP/1.0 `Connection: keep-alive` mechanism (a connection persists for an HTTP/1.0 request only when the keep-alive option is present). — [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)
- RFC 9110 6.5: trailers are only possible when the HTTP version supports them; "A recipient MUST NOT merge a trailer field into a header section unless…" the field definition permits it; `TE: trailers` is how a client says trailers will not be dropped; a server "SHOULD NOT generate trailer fields that it believes are necessary for the user agent to receive". — [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html)
- RFC 9112 errata as of today: five, two verified and editorial (7744 cross-reference; 8284, verified 2025, a note that origin servers give the absolute-form request URI priority over the Host header) and three rejected, including 7633 (a proposal to allow bare LF line endings in chunked encoding, rejected because chunk parsing is intentionally stricter) and 9284 (reported 2026-11-05, about an invalid Host not falling back to a default authority). — [RFC Editor errata search, RFC 9112](https://errata.rfc-editor.org/search/?rfc_number=9112)

**What competitors shipped, 2024-2026 (nginx changelog, primary)**
- nginx 1.27.2 (2024-10): `proxy_pass_trailers` directive. — [nginx CHANGES](https://nginx.org/en/CHANGES)
- nginx 1.29.0 (2025-06): 103 Early Hints from proxy and gRPC backends, `early_hints` directive; fixes in 1.29.1 (103 buffered over HTTP/2) and 1.29.8 (processing of 103 from proxied backends). — [nginx CHANGES](https://nginx.org/en/CHANGES)
- nginx 1.29.4 (2025-12): `ngx_http_proxy_module` supports HTTP/2 to backends; host and port validation in the request line, `Host` and `:authority` follows RFC 3986; Encrypted ClientHello (`ssl_ech_file`). — [nginx CHANGES](https://nginx.org/en/CHANGES)
- nginx 1.29.7 (2026-03): `keepalive` in the upstream block enabled by default; `proxy_http_version` defaults to 1.1; the `Connection` proxy header is no longer sent by default. — [nginx CHANGES](https://nginx.org/en/CHANGES)
- nginx 1.29.8 (2026-04): `max_headers` directive limits the number of request header fields. — [nginx CHANGES](https://nginx.org/en/CHANGES)
- nginx 1.31.0 (2026-05) ships a tunnel module that handles HTTP/1.1 CONNECT (forward proxying; F5 says it first appeared in NGINX Plus R36 in 2025 and that an unrestricted config "literally allow[s] any traffic through the tunnel"). — [nginx CHANGES](https://nginx.org/en/CHANGES); [F5 community: forward proxies in NGINX Plus](https://community.f5.com/t/secure-and-harden-forward-proxies-in-nginx-plus/76806)
- Apache httpd: newest changelog heading is 2.4.71; 2.4.58 added `H2EarlyHint`, RFC 8441 WebSockets (`H2WebSockets`) and `H2ProxyRequests`; 2.4.64 **removed** TLS upgrade (RFC 2817 `Upgrade: TLS`) after CVE-2025-49812 "HTTP desync via TLS upgrade"; 2.4.59 stopped CGI-like scripts setting Transfer-Encoding or Content-Length (response splitting, CVE-2024-24795); 2.4.69 rejects control characters in interim-response reason phrases; 2.4.71 "correctly handles asterisk-form OPTIONS" in mod_http2. — [Apache httpd CHANGES_2.4](https://downloads.apache.org/httpd/CHANGES_2.4)
- Caddy `reverse_proxy`: upstream `versions` are `1.1`, `2`, `h2c`, `3` (default `1.1 2`); responses are flushed immediately for `text/event-stream`, `Incremental: ?1`, unknown Content-Length and some HTTP/2 cases; `expect_continue_timeout` governs `Expect: 100-continue` to the upstream; `X-Forwarded-For/Proto/Host` are set and incoming values ignored unless `trusted_proxies` names the peer; the FastCGI transport never passes the client's `Proxy` header as `HTTP_PROXY` (httpoxy). — [Caddy reverse_proxy docs](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
- HAProxy has a dedicated `http-request early-hint` action for 103 responses, and `option accept-invalid-http-request` as the switch that relaxes its default rejection of ambiguous requests. — [HAProxy mailing list / source references found by search](https://www.mail-archive.com/haproxy@formilux.org/msg42494.html); [AlmaLinux packaging of the HAProxy fix for CVE-2023-45539](https://git.almalinux.org/rpms/haproxy/src/branch/c8s/CVE-2023-45539-pass-accept-invalid-http-request-parser.patch)

**Which RFC texts the project keeps locally**
- The local index lists RFC 7617, 9111, 6797, 8246, 5861, 9213, 9110, 9112, 9113, 7541, 8999, 9000, 9001, 9002, 9114, 9204, 9438 and 8899. — local file `/home/yiannis/projects/agensio/docs/rfc/README.md`

### Inferences

Classified inventory for this question. Server-support cells marked [PK] are from prior knowledge.

| Item | Spec | Class | Notes and who ships it |
|---|---|---|---|
| GET and HEAD; strict framing (CL vs TE, one Host, 400 on ambiguity); Date; absolute-form accepted; 1xx handling | RFC 9110 9.1, RFC 9112 3, 6 | (a) | Universal. Errata 8284 (2025): absolute-form wins over Host. |
| Conditional requests in full (If-Match, If-None-Match, If-Modified-Since, If-Unmodified-Since, precedence order) and If-Range | RFC 9110 13 | (a) for the ones a server evaluates; (b) to do all five | All six competitors' static handlers do ETag/Last-Modified validators [PK]. |
| Single byte range, 206/416, `Accept-Ranges` | RFC 9110 14 | (b) | Range support itself is optional in the RFC ("A server MAY ignore the Range header field" [PK, RFC 9110 14.2]) but video, download managers and PDF viewers expect it. |
| Multiple ranges, `multipart/byteranges` | RFC 9110 14.6 | (c) | nginx (`max_ranges`), Apache (`MaxRanges`), Go/Caddy and h2o serve multipart [PK]. The RFC lets a server ignore or coalesce range sets, so a single-range server is conformant. A cap on range count is the hardening lesson (Apache "Range header DoS" CVE-2011-3192, pre-2024, still holds [PK]). |
| `Expect: 100-continue`; 417 for unknown expectations | RFC 9110 10.1.1 | (a) | Now also a desync surface: see question 2. A proxy must decide deliberately whether it answers 100 itself or forwards Expect. |
| 103 Early Hints | RFC 8297 (2017, pre-2024, still holds) | (b) for a reverse proxy, (c) for an origin | nginx 1.29.0+, Apache (`H2EarlyHints`/`H2EarlyHint`), HAProxy (`early-hint`), Caddy/Go and h2o [PK for the last two]. Since browsers dropped server push, 103 is the surviving "think-time" mechanism. |
| Trailers (send, receive, pass through) | RFC 9110 6.5 | (b) for a proxy that carries gRPC; (c) otherwise | nginx `proxy_pass_trailers` 1.27.2, `add_trailer` [PK]; Apache, Caddy, HAProxy pass them [PK]. Never merge into headers. |
| `OPTIONS *` | RFC 9110 9.3.7, RFC 9112 3.2.4 | (a) to parse, (b) to answer | Apache fixed asterisk-form OPTIONS over h2 in 2.4.71. |
| TRACE | RFC 9110 9.3.8 | (e) to enable by default | Optional method; nginx answers 405, Apache has `TraceEnable` [PK]. Refuse (405/501). |
| CONNECT (forward proxying) | RFC 9110 9.3.6, RFC 9931 | (c) and out of scope for an origin/reverse proxy | nginx gained it only in 1.31.0. If ever answered: close the connection on rejection (RFC 9931). |
| `Upgrade` (WebSocket) | RFC 9110 7.8, RFC 6455 | (b) | See question 6. `Upgrade: TLS` is (e) (Apache removed it in 2.4.64); `Upgrade: h2c` is (e) (RFC 9113). |
| HTTP/1.0 requests, `Connection: keep-alive` for 1.0 | RFC 1945 (informational, 1996), RFC 9112 9.3 / C.2.2 | (b) accept 1.0, (c) 1.0 keep-alive | Health checkers, `ab`, old proxies and some monitoring still speak 1.0. No Host required, no chunked to a 1.0 client, `Expect` ignored in 1.0 [PK, RFC 9110 10.1.1]. HTTP/0.9 is (e). |
| `Max-Forwards` | RFC 9110 7.6.2 | (c) | Only meaningful with TRACE/OPTIONS through proxies; with TRACE refused, decrement-on-OPTIONS is the whole feature. |
| `Via` | RFC 9110 7.6.3 | (a) on paper for a gateway's forwarded requests, widely ignored | nginx and Caddy do not add Via by default; Apache has `ProxyVia Off` by default; HAProxy does not [all PK]. An option is enough; RFC 8586 `CDN-Loop` is the modern loop guard. |
| `Content-Location`, `Content-Language` etc. | RFC 9110 8 | pass-through | Nothing for the server to do except not mangle them. |
| Digest fields (`Content-Digest`, `Repr-Digest`, `Want-*`) | RFC 9530 (2024) | (d) | Pass through; no general-purpose server computes them by default. `unencoded-digest` is about to become an RFC. |
| Structured Fields | RFC 9651 (2024) | (b) as a parser dependency | Needed to parse `Priority`, `Incremental`, `Cache-Status`, `Proxy-Status`, `Signature`, client hints correctly. |
| `Cache-Status` | RFC 9211 | (c), only if the server caches upstream responses | |
| `Proxy-Status` | RFC 9209, 9532 | (c) trending (b) | Caddy emits it for RFC 10036 refusals; RFC 10036 names two parameters. A cheap way to make 502/504 causes machine-readable. |
| `Forwarded` | RFC 7239 (2014, pre-2024, still holds) | (c) | `X-Forwarded-*` remains the de facto contract (Caddy's defaults above); `Forwarded` as an option. |
| `Prefer` / `Preference-Applied` | RFC 7240 | pass-through | Application-level. |
| 421 Misdirected Request | RFC 9110 15.5.20 | (a) for any server with connection reuse across names (h2/h3) | |
| 425 Too Early, `Early-Data: 1` | RFC 8470 (2018, pre-2024, still holds) | (a) **if** TLS 1.3 or QUIC 0-RTT is enabled | A proxy adds `Early-Data: 1` when forwarding before the handshake completes; an origin may answer 425. |
| 451 | RFC 7725 | configuration, nothing to implement | |
| QUERY method | RFC 10008 (2026-06) | (d) moving to (b) for proxies | A server must not reject or mis-frame an unknown-to-it method with a body; safe + idempotent, so it may be retried and its responses cached keyed on the body. FastCGI and proxy paths should pass it. |
| Resumable uploads (104, upload resources) | draft -15 | (d) | Application or dedicated-endpoint feature (tus lineage); the server-side duty today is to forward 1xx interim responses, including unknown ones such as 104, intact. |
| `Incremental` | RFC 10036 (2026-08) | (d) moving to (b) for reverse proxies | Caddy 2.11.7 has it. A proxy that buffers responses by default should honour it or answer 501. |
| Cookies | RFC 6265, 6265bis (RFC Editor queue) | pass-through | A server touches cookies only when it sets its own, must not fold `Set-Cookie` lines, and must rejoin HTTP/2 and HTTP/3 cookie crumbs with "; " before passing to HTTP/1.1 or CGI (RFC 9113 8.2.3). |
| Compression dictionaries (`dcb`, `dcz`), zstd | RFC 9842 (2025), RFC 8878/9659 | (d) | Chromium-driven; a static server would only need to serve pre-built dictionary-compressed variants. |
| Message Signatures | RFC 9421 (2024) | (d), application/edge | Relevant to bot authentication proposals; not a web-server core feature. |

- The gap between "conformant" and "feature complete" is mostly on the proxy side: Early Hints forwarding, trailers, unbuffered streaming with `Incremental`, 1xx pass-through and Proxy-Status are where nginx and Caddy moved in 2025-2026.
- Texts the inventory relies on that are absent from the local `docs/rfc/` index: RFC 1945, 3986, 6455, 6265(bis), 7239, 7838, 8297, 8441, 8470, 9209, 9211, 9218, 9220, 9221, 9287, 9297, 9368, 9369, 9460, 9530, 9651, 9931, 10008, 10036.

### Gaps
- I did not fetch per-server documentation for multi-range, Max-Forwards, Via, TRACE and HTTP/1.0 keep-alive behaviour; those cells are [PK].
- RFC 9110 and 9111 errata lists were not fetched (only RFC 9112's). Whether any verified 9110 erratum since 2024 changes server behaviour is unconfirmed.
- No source found for any of the six servers implementing QUERY-specific handling or resumable uploads natively as of November 2026.
- The Apache changelog headings show 2.4.71 while a vendor blog found by search says the vote for 2.4.70-rc1 started 3 November 2026; I could not determine which 2.4.x is the latest *released* version.

---

## 2. What changed in 2024-2026: errata, new RFCs, and the HTTP/1.1 desynchronisation research

### Takeaway
The standards themselves barely moved (no revision of RFC 9110-9114; a handful of errata; RFC 9931 as the one normative HTTP/1.1 update), but the security consensus did: Kettle's August 2025 research argues that HTTP/1.1 between proxies and origins cannot be made safe by parser fixes and that "the only viable long-term solution is upstream HTTP/2", and the 2025 "funky chunks" work turned lenient line-terminator and chunk-extension parsing into CVEs across Go, Netty, Jetty and Kestrel. For a new server this demands strict, reject-don't-repair HTTP/1.1 parsing as an origin, careful Expect handling, and HTTP/2 to origins as a first-class proxy feature.

### Cited Findings

**"HTTP/1.1 must die: the desync endgame" (PortSwigger, Black Hat USA / DEF CON, August 2025)**
- Core claim: "Requests are simply concatenated on the underlying TCP/TLS socket with no delimiters, and there are multiple ways to specify their length." Classes: CL.TE, TE.CL, **0.CL** (front-end ignores Content-Length, back-end honours it; "widely regarded as unexploitable" until early-response gadgets broke the upstream deadlock), **CL.0** (back-end ignores Content-Length), H2.0/H2.CL/H2.TE from HTTP/2 downgrade, TE.0 and TE.TE. — [PortSwigger research](https://portswigger.net/research/http1-must-die)
- Expect-based desync: front-ends may not support, see or correctly parse `Expect`; back-ends may answer early or with a non-100 status; `Expect` creates a second header block that breaks response-header handling. Obfuscated values such as `Expect: y 100-continue` trigger it on servers that accept them. Case studies: vanilla-Expect 0.CL against T-Mobile, obfuscated-Expect 0.CL against GitLab, vanilla-Expect CL.0 against Netlify's CDN, obfuscated-Expect CL.0 against Akamai's CDN (**CVE-2025-32094**). — [PortSwigger research](https://portswigger.net/research/http1-must-die); [Black Hat whitepaper](https://i.blackhat.com/BH-USA-25/Presentations/US-25-Kettle-HTTP1-Must-Die-The-Desync-Endgame-wp.pdf)
- Parser discrepancies named: hidden-versus-visible headers (space before the colon, leading space, e.g. `Host : foo/bar`), duplicate Host headers, a server that did not treat a double LF as ending the header block (RFC 9112 allows recognising a single LF), a server mishandling HEAD after Expect. — [PortSwigger research](https://portswigger.net/research/http1-must-die)
- Early-response gadgets (what turns 0.CL into an attack): reserved device names on IIS (`/con`), server-level redirects, and **static files on nginx**, i.e. any path where the back-end answers before reading the body. Apache yielded no viable gadget "because it closes connections on error". — [PortSwigger research](https://portswigger.net/research/http1-must-die)
- Recommended defences: enable upstream HTTP/2; enable every normalisation and validation option on the front-end and validation on the back-end; disable upstream connection reuse (at a performance cost); reject requests with a body on methods that do not need one (GET, HEAD, OPTIONS); prefer mainstream servers (Apache and nginx called "lower-risk"). — [PortSwigger research](https://portswigger.net/research/http1-must-die)
- On downgrade: "Downgrading incoming HTTP/2 messages is even more dangerous than using HTTP/1.1 end to end." Upstream HTTP/2 was confirmed available in HAProxy, F5 BIG-IP, Google Cloud, Imperva and Apache (experimental); not available at the time in nginx, Akamai, CloudFront or Fastly. — [PortSwigger research](https://portswigger.net/research/http1-must-die)
- nginx closed that gap four months later: HTTP/2 to backends in 1.29.4 (2025-12). — [nginx CHANGES](https://nginx.org/en/CHANGES)
- Reported scale (the researcher's figures, not verified against vendor statements): a Cloudflare-internal H2.0 desync exposing over 24 million sites, patched within hours; Akamai's fix took 65 days. — [PortSwigger research](https://portswigger.net/research/http1-must-die)

**Chunk-extension and bare-LF parsing ("funky chunks", June and October 2025)**
- The mechanism: one parser treats a bare LF inside a chunk extension as part of the extension, another treats it as the end of the chunk-size line, so one request becomes two. Go `net/http` (CVE-2025-22871: accepted a bare LF as line terminator in chunk-size lines; fixed in Go 1.23.8 and 1.24.2), Netty (CVE-2025-58056; quoted-string follow-up CVE-2026-33870), Jetty (CVE-2026-2332) and ASP.NET Kestrel (CVE-2025-55315) were all affected. — [Go vulnerability report GO-2025-3563](https://pkg.go.dev/vuln/GO-2025-3563); [Netty CVE-2025-58056 advisory summary](https://corgea.com/advisories/vulnerabilities/CVE-2025-58056); [F5 on CVE-2025-55315](https://community.f5.com/t/http-request-smuggling-using-chunk-extensions-cve-2025-55315/76631)
- A related variant ends the chunk-size line with a bare semicolon and no extension name. — [Imperva](https://www.imperva.com/blog/smuggling-requests-with-chunked-extensions-a-new-http-desync-trick/)
- nginx 1.29.4: "a single LF used as a line terminator in a chunked request or response body is now an error". — [nginx CHANGES](https://nginx.org/en/CHANGES)
- The RFC Editor rejected erratum 7633, which asked to allow bare LF in chunked encoding, on the grounds that chunk parsing is intentionally stricter than header-line parsing. — [RFC Editor errata, RFC 9112](https://errata.rfc-editor.org/search/?rfc_number=9112)

**Other strictness changes vendors made in 2025-2026**
- nginx 1.31.0: HTTP/2 and HTTP/3 requests carrying `Connection`, `Proxy-Connection`, `Keep-Alive`, `Transfer-Encoding` or `Upgrade`, or `TE` with any value other than `trailers`, are rejected; 1.31.3: out-of-order pseudo-headers rejected and `Upgrade` no longer sent in h2/h3 responses; 1.31.4: h2/gRPC requests to backends always carry `:authority`, and an incomplete gRPC response with non-zero Content-Length is malformed. — [nginx CHANGES](https://nginx.org/en/CHANGES)
- nginx 2026 CVEs on the proxy/h3 side: CVE-2026-1642 (plain-text injection in a response from an SSL backend), CVE-2026-42926 (data injection into requests to HTTP/2 backends with `proxy_set_body`), CVE-2026-42055 (heap overflow proxying to an h2/gRPC backend), CVE-2026-40460 (HTTP/3 migration letting streams use an unvalidated address), CVE-2026-95101 (part of an unknown HTTP/3 frame treated as request body, bypassing `client_max_body_size` or injecting into the proxied request). — [nginx CHANGES](https://nginx.org/en/CHANGES)
- Apache 2.4.64 removed TLS upgrade after CVE-2025-49812 (desync via TLS upgrade); 2.4.67 fixed response splitting via a malicious backend status line (CVE-2026-33523); 2.4.69 fixed Transfer-Encoding response smuggling in mod_proxy_uwsgi (CVE-2026-63718). — [Apache httpd CHANGES_2.4](https://downloads.apache.org/httpd/CHANGES_2.4)
- RFC 9931 (March 2026) is the IETF's answer to one desync family: data sent optimistically after an Upgrade or CONNECT that the server rejects gets parsed as HTTP/1.1 requests. — [RFC 9931](https://www.rfc-editor.org/rfc/rfc9931.html)
- An individual draft proposes a cryptographic defence for HTTP/1.1 hops: `draft-nygren-httpbis-http11-request-binding-01` (2026-07), "HTTP/1.1 Request Smuggling Defense using Cryptographic Message Binding". Not adopted by the WG. — [IETF datatracker, httpbis related drafts](https://datatracker.ietf.org/wg/httpbis/documents/)

**New QUIC-side RFCs and drafts 2024-2026** (detail in question 4)
- RFC 10069 "Managing Multiple Paths for a QUIC Connection" (multipath) published 2026-11; `draft-ietf-quic-reliable-stream-reset-11` is in the RFC Editor queue; qlog (three drafts, -14/-15, revised 2026-11-02), QMux (-02), load balancers (-22), address discovery, extended key update and receive timestamps remain WG drafts. — [IETF datatracker, quic documents](https://datatracker.ietf.org/wg/quic/documents/)

### Inferences
- What the research demands of an **origin-facing parser** (reject and close, never repair): exactly one framing signal (CL together with TE is a 400); a single syntactically exact Content-Length; `Transfer-Encoding` only as the exact token `chunked` on HTTP/1.1; no whitespace between field name and colon; no obs-fold; CRLF only in chunk-size lines and chunk extensions (bare LF or CR is an error); chunk-extension length bounded and quoted-strings parsed or refused; `Expect` accepted only as exactly `100-continue` (anything else 417 and close); after any 4xx generated before the body was read, either drain the declared body or close the connection (the "early response gadget" lesson, and the reason Apache was hard to exploit); a body on GET/HEAD/OPTIONS is at least framed correctly and at most refused.
- A server that answers **static files without reading a request body** is exactly the nginx gadget named in the paper. Draining or closing after such an answer removes the gadget; this matters when the server sits *behind* another proxy or CDN that reuses connections.
- What it demands of a **proxy talking HTTP/1.1 to origins**: regenerate the request head from the parsed form (never forward raw bytes of framing headers); send exactly one of CL or chunked; decide Expect locally (either absorb it and send 100 itself, or forward it and wait, with a timeout) and never forward an Expect value it would not itself accept; treat an early upstream response as poisoning the connection (do not reuse it); never reuse an upstream connection after any parse irregularity; offer per-upstream "no connection reuse" as a hardening switch; and offer HTTP/2 to origins.
- The field has moved from "HTTP/2 to origins is exotic" to "expected": HAProxy (since 1.9 [PK]), Apache mod_proxy_http2, Caddy (default `1.1 2`), and nginx since 1.29.4 all have it. Class **(b)** for a 2026 reverse proxy; the project lists it as "not yet".
- The RFC's permission to accept a bare LF as a line terminator in the *header* section (RFC 9112 2.2) is still there, but the direction of every 2025 fix is to stop using that permission. A new server loses nothing by requiring CRLF everywhere.

### Gaps
- I did not read the whitepaper PDF itself beyond its table of contents; vendor remediation details for Netlify, T-Mobile, GitLab and LastPass were not found.
- I did not open the original "funky chunks" posts (w4ke.info); the mechanism is taken from the Go, Netty and F5 advisories.
- No authoritative list found of which of nginx, Apache, HAProxy, h2o, OpenLiteSpeed accept bare LF in header lines today; Http11Probe (question 5) tests it but its results page returned 404 when fetched.
- RFC 9110, 9111, 9113, 9114 errata were not enumerated.

---

## 3. HTTP/2 (RFC 9113, HPACK RFC 7541): required versus optional, and the attack classes

### Takeaway
Server push is dead in practice (Chrome disabled it in version 106 in 2022 and nginx removed its implementation in 2023), the RFC 7540 priority tree is deprecated and nginx stopped honouring it in October 2026 in favour of RFC 9218, and the h2c `Upgrade` path is deprecated while prior-knowledge h2c survives. What a server must get right in 2026 is the denial-of-service surface: Rapid Reset (2023), CONTINUATION flood (2024) and MadeYouReset (2025) all turn on the server doing work for streams the protocol no longer counts, and vendors answered with per-connection budgets for resets, protocol errors and header-block size.

### Cited Findings

**Required versus deprecated in the RFC text (verified against the local copy of RFC 9113)**
- RFC 9113 "deprecates the priority signaling defined in RFC 7540" (5.3.2; "The PRIORITY frame (type=0x02) is deprecated"); the HTTP/1.1 Upgrade mechanism to h2c "is deprecated and no longer specified" and the `HTTP2-Settings` field is obsolete; section 3.3 keeps "Starting HTTP/2 with Prior Knowledge"; connection-specific header fields are prohibited (8.2.2) and a message containing them is malformed; `SETTINGS_ENABLE_PUSH` remains with initial value 1, and PUSH_PROMISE "MUST NOT be sent" when the peer set it to 0; section 10.5 tells implementations to bound SETTINGS, PING, empty frames, small WINDOW_UPDATEs, priority changes and field-block size (10.5.1). — [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html)

**Server push**
- Chrome announced HTTP/2 Server Push "will be disabled by default in Chrome 106 and other Chromium-based browsers"; its data showed 1.25 % of HTTP/2 sites using push, later 0.7 %; 103 Early Hints was the recommended replacement [2022, pre-2024, still holds]. — [Chrome for Developers: Removing HTTP/2 Server Push](https://developer.chrome.com/blog/removing-push)
- nginx removed HTTP/2 server push in 2023, the patch citing Chrome 106 [pre-2024, still holds]. — [nginx-devel: "HTTP/2: removed server push"](https://mailman.nginx.org/pipermail/nginx-devel/2023-June/GF5EDSAA5TDY3W3QU345QIOMVAN32O2L.html)
- Apache still carries push code and directives (a 2.4.71 fix concerns a crash with `H2PushDiarySize 0`). — [Apache httpd CHANGES_2.4](https://downloads.apache.org/httpd/CHANGES_2.4)

**Priorities**
- RFC 9218 (June 2022, Oku and Pardue) replaces the tree with two parameters, urgency and incremental, carried in the version-independent `Priority` header field and in PRIORITY_UPDATE frames. — [RFC 9218](https://www.rfc-editor.org/rfc/rfc9218)
- nginx 1.31.7 (2026-10-14): "the `ngx_http_v2_module` now uses the RFC 9218 prioritization scheme; RFC 7540 priority signals are ignored." — [nginx CHANGES](https://nginx.org/en/CHANGES)
- Chrome and Safari send the `priority` request header, deferring to an application-set value when one exists; Cloudflare supports HTTP/3 extensible priorities; a 2024 academic comparison of twelve HTTP/3 endpoints found support for the scheme's sub-features varies, e.g. Cloudflare ignoring PRIORITY_UPDATE frames. — [Chromium intent: 'priority' HTTP request header](https://groups.google.com/a/chromium.org/g/blink-dev/c/Do3kwLuf02c); [Cloudflare blog](https://blog.cloudflare.com/better-http-3-prioritization-for-a-faster-web); [Herbots et al., ANRW 2024](https://research.edm.uhasselt.be/~mwijnants/pdf/herbotsANRW2024.pdf)
- lsquic (LiteSpeed) lists RFC 9218 among its supported extensions. — [lsquic README](https://github.com/litespeedtech/lsquic)

**Extended CONNECT / WebSockets over HTTP/2 (RFC 8441, 2018, pre-2024, still holds)**
- Apache: RFC 8441 via `H2WebSockets` since 2.4.58 (a null-pointer DoS in it fixed in 2.4.60, CVE-2024-36387). — [Apache httpd CHANGES_2.4](https://downloads.apache.org/httpd/CHANGES_2.4)
- HAProxy: "supports the WebSocket protocol over HTTP/2 through the extended CONNECT HTTP method" since 2.4. — [Announcing HAProxy 2.4](https://www.haproxy.com/blog/announcing-haproxy-2-4)
- nginx: an nginx trac ticket for RFC 8441 exists (#1992), and no entry from 1.27.0 through 1.31.8 in the changelog mentions extended CONNECT; the new tunnel module is documented as handling HTTP/1.1 CONNECT. — [nginx trac #1992](https://trac.nginx.org/nginx/ticket/1992); [nginx CHANGES](https://nginx.org/en/CHANGES)
- Browsers: Firefox implemented RFC 8441 under a bug closed as fixed in 2018-2019; a third-party guide lists Chrome 67+, Firefox 65+ and Safari 14.1+, while a GitHub comment says Chrome sends WebSocket over HTTP/2 from 121 (the sources conflict on Chrome's version). — [Mozilla bug 1434137](https://bugzilla.mozilla.org/show_bug.cgi?id=1434137); [websocket.org guide](https://websocket.org/guides/future-of-websockets/)

**Attack classes and what vendors did**
- **Rapid Reset, CVE-2023-44487** [2023, pre-2024, still holds]: client opens streams and resets them at once; exploited in the wild August to October 2023; reported peaks 398 million requests per second (Google), 201 million (Cloudflare), 155 million (Amazon); nghttp2 fixed in 1.57.0, Tomcat in 8.5.94; HAProxy published that it was not affected. — [CISA alert](https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487); [Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/10/cve-2023-44487-http-2-rapid-reset-attack); [CERT-EU advisory 2023-074](https://cert.europa.eu/publications/security-advisories/2023-074/)
- Apache 2.4.58 fixed two related h2 flaws: CVE-2023-45802 (stream memory not reclaimed on RST) and CVE-2023-43622 (DoS with initial window size 0, a window stall). — [Apache httpd CHANGES_2.4](https://downloads.apache.org/httpd/CHANGES_2.4)
- **CONTINUATION flood, April 2024 (CERT/CC VU#421644)**: endless CONTINUATION frames without END_HEADERS exhaust memory or CPU from a single connection. Apache httpd 2.4.17-2.4.58 (CVE-2024-27316, fixed 2.4.59), Envoy (CVE-2024-30255, CVE-2024-27919; fixed 1.26.8/1.27.4/1.28.2/1.29.3), Go net/http and x/net/http2 (CVE-2023-45288), Apache Traffic Server, Tomcat, Node.js, hyper/h2 and others were affected. — [CERT/CC VU#421644](https://kb.cert.org/vuls/id/421644); [discoverer's write-up](https://nowotarski.info/http2-continuation-flood); [Apache httpd CHANGES_2.4](https://downloads.apache.org/httpd/CHANGES_2.4)
- Apache follow-ups: `H2MaxHeaderBlockLen` and a memory-retention DoS fix (CVE-2025-53020) in 2.4.64; `H2MaxStreamErrors` in 2.4.66 "to limit client misbehavior before the connection closes". — [Apache httpd CHANGES_2.4](https://downloads.apache.org/httpd/CHANGES_2.4)
- **MadeYouReset, CVE-2025-8671, August 2025 (CERT/CC VU#767506)**: the client provokes *server-sent* RST_STREAM with malformed frames or flow-control errors; the protocol then counts the stream closed (not against `SETTINGS_MAX_CONCURRENT_STREAMS`) while the back end keeps working, so one connection drives unbounded concurrent work. Recommended mitigation: limit the number or rate of RST_STREAM frames the server sends. — [CERT/CC VU#767506](https://kb.cert.org/vuls/id/767506)
- MadeYouReset vendor status: affected — Apache Tomcat (CVE-2025-48989; fixed 11.0.10, 10.1.44, 9.0.108), Fastly's h2o fork (fixed in release 25.17, deployed 2 June 2025), Varnish, Netty, Jetty/Eclipse, gRPC; not affected — Apache HTTP Server, Apache Traffic Server, Envoy (its Rapid Reset mitigation covers it), Go net/http and therefore Traefik (the cap on concurrent handlers does not depend on how a reset is issued), HAProxy ("streams are counted and closed on any RST; limits are enforced on allocated streams"), LiteSpeed, lighttpd, Node.js; no statement — nginx, Cloudflare, F5, nghttp2. The IETF HTTP WG called it an implementation issue, not a protocol flaw. — [CERT/CC VU#767506](https://kb.cert.org/vuls/id/767506)
- Debian's tracker listed upstream h2o as unfixed for CVE-2025-8671 (upstream advisory GHSA-mrjm-qq9m-9mjq). — [Debian security tracker](https://security-tracker.debian.org/tracker/CVE-2025-8671)
- 2026 shows the HTTP/2 code of mature servers is still producing memory-safety bugs: Apache mod_http2 CVE-2026-23918 (double free on early reset, 2.4.67), CVE-2026-49975 and CVE-2026-48913 (2.4.68), CVE-2026-57941 (use-after-free, 2.4.69), CVE-2026-119618 (heap corruption in `assign_headers`, 2.4.71); nginx fixed an h2 flow-control bug and proxy_v2 header-size limits in 1.31.3. — [Apache httpd CHANGES_2.4](https://downloads.apache.org/httpd/CHANGES_2.4); [nginx CHANGES](https://nginx.org/en/CHANGES)

### Inferences

| Item | Spec | Class | Notes |
|---|---|---|---|
| Framing, stream states, flow control, SETTINGS, PING, GOAWAY, HPACK decode with dynamic table, field validation (pseudo-header order, no connection-specific fields, lowercase names), cookie-crumb rejoin, 421 | RFC 9113, 7541 | (a) | nginx tightened two of these only in 2026 (1.31.0, 1.31.3), so strictness here is still a differentiator. |
| ALPN `h2` over TLS 1.2+ with the cipher rules, TLS 1.3 | RFC 9113 9.2, RFC 8740 | (a) | |
| h2c by prior knowledge | RFC 9113 3.3 | (c) | Used by gRPC and internal meshes, not browsers. nginx, HAProxy, Caddy, Envoy accept it [PK]. |
| h2c via `Upgrade` | RFC 7540 3.2 | (e) | Deprecated by RFC 9113; also the vector of "h2c smuggling" through proxies that forward Upgrade (2020 research, pre-2024, still holds [PK]). |
| Server push (PUSH_PROMISE) | RFC 9113 8.4 | (e) | No browser accepts it; nginx removed it; Apache keeps legacy code. Do not build. |
| RFC 7540 stream dependency tree | RFC 7540 5.3 | (e) | Parse and ignore PRIORITY frames (still required to tolerate them). |
| RFC 9218 priorities: `Priority` header, PRIORITY_UPDATE, `SETTINGS_NO_RFC7540_PRIORITIES` | RFC 9218 | (b) | nginx 1.31.7, h2o (its author co-wrote the RFC [PK]), lsquic/LiteSpeed, Cloudflare. The minimum useful form: honour urgency and incremental from the header when scheduling DATA; send `SETTINGS_NO_RFC7540_PRIORITIES = 1`. |
| Extended CONNECT + `SETTINGS_ENABLE_CONNECT_PROTOCOL` (WebSocket over h2) | RFC 8441 | (b) trending; (c) today | Apache 2.4.58+, HAProxy 2.4+, Envoy, Caddy via Go [PK]; nginx still without. Browsers use it when the server advertises the setting, otherwise they open a separate HTTP/1.1 connection, so absence costs a connection, not correctness. |
| ORIGIN frame | RFC 8336, RFC 9412 (h3) | (c)/(d) | Firefox honours it; Chromium does not [PK]. Mostly a CDN connection-coalescing tool. |
| ALTSVC frame | RFC 7838 4 | (e) in effect | Chrome and Firefox ignore the frame and use the `Alt-Svc` header field [PK]; the rfc7838bis revision is parked (question 1 findings). |
| GREASE (unknown frame types and settings must be ignored) | RFC 9113 4.1, 6.5.2 | (a) to tolerate | Chrome sends greased settings/frames [PK]. |
| `SETTINGS_MAX_HEADER_LIST_SIZE`, header count limit | RFC 9113 10.5.1 | (b) | nginx `max_headers` (1.29.8), Apache `H2MaxHeaderBlockLen` (2.4.64). |

DoS budget checklist a 2026 server is expected to have (each maps to a cited incident above):
1. A cap on streams the server is *still working on*, independent of protocol stream state (MadeYouReset; Go's and HAProxy's reason for being unaffected).
2. A budget for client RST_STREAM per connection/time (Rapid Reset) and for server-sent RST_STREAM / stream errors (MadeYouReset; Apache `H2MaxStreamErrors`), closing with ENHANCE_YOUR_CALM past it.
3. A bound on total header-block bytes across HEADERS + CONTINUATION, and on the number of CONTINUATION frames, enforced before decoding completes (CONTINUATION flood).
4. HPACK decoded-size and dynamic-table-size bounds (HPACK bomb, 2016 CVE-2016-6581 class, pre-2024, still holds [PK]).
5. Rate limits for SETTINGS, PING, PRIORITY/PRIORITY_UPDATE, empty DATA/HEADERS/CONTINUATION frames and zero-increment or tiny WINDOW_UPDATEs (the 2019 Netflix set, CVE-2019-9511 to 9518, pre-2024, still holds [PK]; RFC 9113 10.5).
6. A write-progress timeout so a client that never opens its window cannot pin responses in memory (Apache CVE-2023-43622; "window stall").
7. Cancel upstream work when the stream is reset, in either direction (lighttpd's statement in VU#767506).

- For an HTTP/2 implementation written in-house, MadeYouReset is the most relevant of the three: it is a property of how the server accounts for work after *its own* resets, and conformance suites such as h2spec do not test for it.

### Gaps
- Firefox's removal of server push (a search result claimed October 2024 / Firefox 132) was not confirmed from a Mozilla source.
- nginx's own Rapid Reset and CONTINUATION-flood changes (believed: 1.25.3 limits in October 2023 [PK]) were not found in the fetched part of the changelog; nginx gave CERT/CC no statement for MadeYouReset.
- No primary source fetched for Caddy/Go, h2o and OpenLiteSpeed support of RFC 8441, RFC 9218 over h2, or ORIGIN.
- Browser-by-browser status of `SETTINGS_NO_RFC7540_PRIORITIES` and PRIORITY_UPDATE was not found; MDN's compatibility table for `Priority` was not captured.

---

## 4. HTTP/3 and QUIC: table stakes, what browsers use, and traffic share

### Takeaway
HTTP/3 carries about a fifth of requests seen by Cloudflare (21 % in 2025, flat year on year) and is offered by about 40 % of websites (W3Techs, July 2026), so a 2026 server needs it, but with a narrow core: QUIC v1 with Retry, stateless reset, path validation for NAT rebinding, key update, 0-RTT with RFC 8470, Alt-Svc advertisement and a modern congestion controller. QUIC v2, datagrams, extended CONNECT over h3, WebTransport, multipath (an RFC only this month), ack frequency and qlog remain optional or emerging, and no browser ships WebSocket over HTTP/3.

### Cited Findings

**Adoption**
- Cloudflare Radar 2025 Year in Review: "50% of requests to Cloudflare were made over HTTP/2", "HTTP/1.x accounted for 29%", "the remaining 21% were made via HTTP/3"; shares "largely unchanged" from 2024; HTTP/3 was below 10 % in seven countries "due to high levels of bot-originated HTTP/1.x traffic". — [Cloudflare Radar 2025 Year in Review](https://blog.cloudflare.com/radar-2025-year-in-review/)
- W3Techs: HTTP/3 used by 40.0 % of all websites (page dated 26 July 2026); 38.6 % on a page dated 14 March 2026. — [W3Techs HTTP/3 breakdown](https://w3techs.com/technologies/breakdown/ce-http3/dns_server)
- A secondary analysis of Cloudflare Radar data puts HTTP/3 at 20.17 % of requests in Q3 2026 (provisional), down from 21.91 % in Q2 2026 and 22.98 % in Q3 2025. Not confirmed on radar.cloudflare.com. — [technologychecker.io (secondary)](https://technologychecker.io/blog/http-protocol-adoption)
- Firefox telemetry presented at IETF 126 maprg puts HTTP/3 nearer 17 % of requests, a figure affected by ad and tracker subresources (as summarised by search; slides not read in full). — [IETF 126 maprg slides](https://datatracker.ietf.org/meeting/126/materials/slides-126-maprg-a-browsers-perspective-surprises-and-insights-from-firefox-networking-telemetry-00)

**QUIC WG document status (datatracker, today)**
- RFCs: 8999, 9000, 9001, 9002 (2021); 9114, 9204 (2022-06); 9221 datagrams (2022-03); 9287 greasing the QUIC bit (2022-08); 9308 applicability, 9312 manageability (2022-09); 9368 compatible version negotiation, 9369 QUIC v2 (2023-05); **RFC 10069 Managing Multiple Paths for a QUIC Connection (2026-11)**. — [IETF datatracker, quic documents](https://datatracker.ietf.org/wg/quic/documents/)
- Drafts: reliable stream reset -11 (RFC Editor queue); qlog main schema -15, QUIC events -14, HTTP/3 events -14 (all revised 2026-11-02, still WG documents); QMux -02 (QUIC semantics over TCP/TLS); load balancers -22; address discovery -01; extended key update -03; receive timestamps -03. — [IETF datatracker, quic documents](https://datatracker.ietf.org/wg/quic/documents/)
- Acknowledgement frequency: latest found is draft-14 (February 2026), shown as an expired Internet-Draft with intended status Proposed Standard; no RFC number found. — [datatracker: draft-ietf-quic-ack-frequency](https://datatracker.ietf.org/doc/draft-ietf-quic-ack-frequency/)
- WebTransport over HTTP/3: still an Internet-Draft, -17 dated November 2026 (a March 2026 secondary source said -15 was in WG Last Call). — [draft-ietf-webtrans-http3-17](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-17.html); [datatracker](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)
- Individual drafts worth knowing: `draft-kazuho-httpbis-http3-over-qmux-00` (HTTP/3 over QMux, 2026-06), `draft-seemann-httpbis-reset-stream-at-00` (using reliable resets in HTTP/3), `draft-rajappa-httpbis-connection-contamination-06` (HTTP/3 connection contamination in multi-tenant deployments). — [IETF datatracker, httpbis related drafts](https://datatracker.ietf.org/wg/httpbis/documents/)

**Server implementations**
- nginx: `ngx_http_v3_module` appeared in 1.25.0, is not built by default and is still documented as experimental ("caveat emptor applies"). Directives: `quic_retry` (address validation by Retry packets or NEW_TOKEN frames), `quic_gso`, `quic_host_key` (stateless reset and token key), `quic_bpf` (eBPF routing "to support connection migration"; connections preserved across reloads since 1.31.7), `quic_active_connection_id_limit` (default 2), `http3_max_concurrent_streams` (128), `http3_hq`. 0-RTT needs OpenSSL 3.5.1+, BoringSSL, LibreSSL or QuicTLS and could not be enabled with OpenSSL before 1.29.1. — [nginx ngx_http_v3_module docs](https://nginx.org/en/docs/http/ngx_http_v3_module.html)
- nginx QUIC timeline: CUBIC congestion control in 1.27.5 (2025-04); 0-RTT with OpenSSL 3.5.1+ in 1.29.1 (2025-08); limits on size and rate of stateless resets in 1.29.6 (2026-03); "ignores QUIC version negotiation packets from clients" in 1.27.4; HTTP/3 security fixes in 1.27.0 (four CVEs), 1.31.0, 1.31.2, 1.31.6, 1.31.7. — [nginx CHANGES](https://nginx.org/en/CHANGES)
- nginx advertises HTTP/3 only through an administrator-written `add_header Alt-Svc 'h3=":8443"; ma=86400'`. — [nginx ngx_http_v3_module docs](https://nginx.org/en/docs/http/ngx_http_v3_module.html)
- Apache httpd: no released version has HTTP/3; a packaging vendor reports that mod_http3 (a Google Summer of Code project) was merged into httpd trunk on 30 October 2026 and builds with `--enable-http3`, with known gaps. Vendor-sourced, not confirmed from Apache's own lists. — [CodeIT blog (vendor)](https://codeit.guru/tag/httpd/)
- Caddy: HTTP/3 enabled by default since v2.6 (September 2022) per a third-party write-up; 2.10 (April 2025) added automated Encrypted ClientHello published via DNS HTTPS records and post-quantum key exchange; 2.11.1 updated quic-go to v0.56.0 and enabled qlog for HTTP/3; HTTP/3 to upstreams exists as `versions 3`, marked experimental ("VERY EXPERIMENTAL" in the pull request). — [ma.ttias.be (secondary)](https://ma.ttias.be/running-http3-with-caddy-2026/); [AlternativeTo on Caddy 2.10](https://alternativeto.net/news/2025/4/web-server-caddy-2-10-released-with-ech-post-quantum-key-exchange-and-more-enhancements); [Linuxiac on Caddy 2.11.1](https://linuxiac.com/caddy-2-11-1-web-server-released-with-automatic-ech-key-rotation/); [Caddy PR #6312](https://github.com/caddyserver/caddy/pull/6312); [Caddy reverse_proxy docs](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
- HAProxy 3.3 (2025-11-26): "You can now connect to backend servers with HTTP/3 over QUIC", experimental (`expose-experimental-directives`); also kernel TLS and experimental ECH. BBR was added to `quic-cc-algo` as experimental. HAProxy 3.4 is reported (third-party version page) to add QMux and reuse of NEW_TOKEN tokens toward servers. — [Announcing HAProxy 3.3](https://www.haproxy.com/blog/announcing-haproxy-3-3); [HAProxy commit adding bbr (mirror)](https://git.redxen.eu/RepoMirrors/haproxy/commits/commit/349954601f5d13351f0ed4a6bfbdd90de01717ab); [versionlog.com HAProxy 3.4 (third party)](https://versionlog.com/haproxy/3.4/)
- LiteSpeed/OpenLiteSpeed (lsquic): QUIC v1, v2 and draft-29 enabled by default; lists RFC 9000, 9001, 9002, 9114, 9204, 9368, 9369, 9218, 9221, 9287, the ACK Frequency draft and the WebTransport draft. OpenLiteSpeed 1.9.0 (April 2026) dropped SPDY; 1.9.3 stable dated 2026-09-29 per a third-party wiki. — [lsquic README](https://github.com/litespeedtech/lsquic); [OpenLiteSpeed 1.9.0 announcement](https://groups.google.com/g/openlitespeed-development/c/pOgIZ4KFxoY); [third-party wiki](https://wiki.linux-server-admin.com/software/webserver/openlitespeed)
- h2o: README still says "support for HTTP/1.x, HTTP/2 and HTTP/3 (experimental)"; the project has stopped versioned releases and treats master as stable (secondary sources); Fastly runs it in production as its HTTP/3 implementation (quicly). — [h2o README](https://github.com/h2o/h2o); [Wikipedia: H2O (web server)](https://en.wikipedia.org/wiki/H2O_(web_server)); [Fastly: state of QUIC and HTTP/3 2020 (pre-2024)](https://www.fastly.com/blog/state-of-quic-and-http3-2020)

**What clients do**
- Discovery: Safari queries the DNS HTTPS record and opens QUIC at once when `alpn` lists h3; Apple recommends an HTTPS record with `alpn="h3,h2"`; Firefox has done HTTPS lookups since 2020 (with DNS over HTTPS); Chrome published an intent to prototype HTTP/3 upgrade from HTTPS records with an h3 alpn parameter. `Alt-Svc` remains the mechanism that works without DNS support. — [APNIC: Triggering QUIC (2025-07)](https://blog.apnic.net/2025/07/15/triggering-quic/); [Peakhour: how browsers decide to use HTTP/3](https://www.peakhour.io/blog/how-browsers-decide-to-use-http3/); [Chromium intent to prototype](https://groups.google.com/a/chromium.org/g/blink-dev/c/hqvk-XxBIN0)
- QUIC v2: Firefox 154 Nightly can offer QUIC v2 through compatible version negotiation, Nightly-only with telemetry (secondary source, August 2026). — [PiunikaWeb (secondary)](https://piunikaweb.com/2026/08/03/firefox-nightly-quic-v2-http3-support/)
- WebSocket over HTTP/3 (RFC 9220, 2022): Chromium has an "Intent to Prototype"; an early-2026 secondary article says no major browser ships it in stable or experimental builds. — [Chromium intent to prototype: WebSockets over HTTP/3](https://groups.google.com/a/chromium.org/g/blink-dev/c/KOupRe29WhY); [dev.to article (secondary)](https://dev.to/instatunnel/scaling-real-time-ingress-tunneling-websockets-via-http3-extended-connect-1i5o)
- WebTransport: one secondary source says Safari 26.4 (March 2026) shipped it on by default. — [forasoft.com (secondary, unverified)](https://www.forasoft.com/learn/video-streaming/articles-streaming/webtransport-whip)
- 0-RTT: a proxy that forwards early data must mark it and an origin may refuse with 425 (RFC 8470). — [RFC 8470](https://www.rfc-editor.org/rfc/rfc8470.html)

**Interop test cases that define "works" among implementers**
- The QUIC interop runner's fourteen test cases: `versionnegotiation` (currently disabled), `handshake`, `transfer`, `chacha20`, `keyupdate`, `retry`, `resumption`, `zerortt`, `http3`, `multiconnect` (handshake under loss), `v2`, `rebind-port`, `rebind-addr`, `connectionmigration` (to the server's preferred address). An implementation that does not support a case exits 127. — [quic-interop-runner quic.md](https://github.com/quic-interop/quic-interop-runner/blob/master/quic.md)

### Inferences

| Item | Spec | Class | Notes |
|---|---|---|---|
| QUIC v1 transport, TLS 1.3 handshake, loss recovery; HTTP/3 framing, control and QPACK streams, GOAWAY; QPACK decoder (dynamic table may be 0) | RFC 8999, 9000, 9001, 9002, 9114, 9204 | (a) | |
| Version Negotiation for unknown versions; stateless reset; amplification limit; Retry / address validation tokens; path validation on peer address change (NAT rebinding); connection-ID issuing and retirement; key update | RFC 9000, 9001 | (a) | Rebinding is passive migration and unavoidable on mobile networks; the interop runner tests it (`rebind-port`, `rebind-addr`). |
| `Alt-Svc: h3=…` on HTTP/1.1 and HTTP/2 answers | RFC 7838 (2016, pre-2024, still holds), RFC 9114 3.1 | (b), effectively required to be reachable over h3 | nginx leaves it to the administrator; Caddy sends it automatically [PK]. |
| HTTPS/SVCB DNS records | RFC 9460 (2023) | (b) as documentation and tooling; the server cannot publish DNS itself | Safari relies on it; Caddy generates the records' ECH content. A server should at least tell the administrator the record to publish. |
| 0-RTT + `Early-Data` / 425 | RFC 9001 4.6, RFC 8470 | (b) | nginx 1.29.1+, HAProxy, LiteSpeed, Caddy/quic-go [PK for the last three]. Needs anti-replay policy (safe methods only, or pass `Early-Data: 1` to the application). Listed by the project as not yet built. |
| NEW_TOKEN | RFC 9000 8.1.3 | (c) | nginx bundles it with `quic_retry`. Saves a round trip when Retry is on. |
| CUBIC (or better) congestion control, pacing, GSO | RFC 9438 (2023), RFC 9002 | (b) | nginx moved from NewReno to CUBIC in 1.27.5; HAProxy offers cubic/newreno/bbr. |
| BBR | no RFC (CCWG draft [PK]) | (c)/(d) | HAProxy experimental; Google's and LiteSpeed's stacks use it [PK]. |
| DPLPMTUD | RFC 8899, RFC 9000 14.3 | (b) | |
| ECN | RFC 9000 13.4, RFC 9002 | (c) | Was in the interop runner's list historically [PK]; not among today's fourteen cases. Marking and validation are cheap; reacting needs the congestion controller. |
| Active connection migration, server preferred address | RFC 9000 9 | (c) | Chrome and Safari use client migration in some configurations [PK]; needs connection-ID-aware routing across workers (nginx `quic_bpf`). nginx had a 2026 CVE here (CVE-2026-40460). |
| Greasing the QUIC bit | RFC 9287 | (c) | lsquic, quic-go [PK]. |
| Compatible version negotiation + QUIC v2 | RFC 9368, 9369 | (d)/(c) | lsquic default-on; Firefox Nightly experimenting; interop `v2` case. No user-visible benefit; ossification defence. |
| RFC 9218 priorities over h3 (`Priority`, PRIORITY_UPDATE) | RFC 9218 | (b) | h3 has no other priority scheme; Chrome and Safari send it. |
| QUIC DATAGRAM, HTTP Datagrams and capsules | RFC 9221, RFC 9297 | (c) | Only needed for MASQUE (CONNECT-UDP, RFC 9298) and WebTransport. |
| Extended CONNECT over h3 (WebSocket) | RFC 9220 | (d) | No browser ships it; server side exists in Envoy, Caddy/quic-go, lsquic [PK]. |
| WebTransport over h3 | draft -17 | (d) | Chrome and Firefox ship the API, Safari reportedly from 26.4; still not an RFC; among the six servers only lsquic lists it. |
| Reliable stream reset (RESET_STREAM_AT) | RFC Editor queue | (d) | A WebTransport dependency. |
| ACK frequency | draft -14 (expired) | (d) | lsquic implements. |
| Multipath QUIC | RFC 10069 (2026-11) | (d) | Brand new; no browser use found. |
| qlog | drafts -14/-15 | (c) for debugging | De facto format (qvis, quic-go, Caddy 2.11.1); schema still changing. |
| QMux / HTTP/3 over TCP | drafts | (d) | HAProxy 3.4 reportedly experiments. Worth watching: it would give HTTP/3 semantics on TCP paths and to origins. |
| QUIC to origins (HTTP/3 upstream) | — | (d) | HAProxy 3.3 and Caddy both "experimental". Not expected. |

- nginx's HTTP/3 module being formally experimental and not built by default four years after RFC 9114, Apache having none in a release, and h2o's still labelled experimental means the practical competitive bar is set by Caddy (quic-go), LiteSpeed (lsquic) and HAProxy. An own QUIC stack that passes the interop runner against quic-go and ngtcp2 is already at or above the nginx level in protocol coverage; 0-RTT is the visible gap versus nginx 1.29.1+.
- HTTP/3 share has plateaued at about 20-21 % of requests while site support keeps rising, so HTTP/2 over TCP remains the majority path for years; h3 cannot be the only well-tuned protocol.

### Gaps
- No primary-source confirmation of browser defaults for 0-RTT, active connection migration or ECN in Chrome, Firefox and Safari.
- Chrome's current default for HTTPS-record-driven h3 (prototype versus shipped) is unclear from the sources found.
- BBR standardisation status (CCWG draft) not checked.
- Whether nginx implements RFC 9218 for HTTP/3 (the 1.31.7 entry names only the HTTP/2 module) was not established.
- The W3Techs page that carried the 38.6 % (14 March 2026) figure was identified only through the search summary; the linked breakdown page is the July one.
- OpenLiteSpeed-specific (as opposed to lsquic library) feature status was not found in project documentation.

---

## 5. Conformance and interoperability test suites in 2026

### Takeaway
There is no single authoritative HTTP conformance suite; each protocol has a de facto tool (h2spec, h3spec, the QUIC interop runner) and HTTP/1.1 now has two differential or probing projects aimed at smuggling (HTTP Garden, Http11Probe) beside PortSwigger's scanner. Passing them shows protocol-level interoperability and absence of known parser discrepancies; none of them tests resource-exhaustion behaviour such as Rapid Reset or MadeYouReset.

### Cited Findings
- **QUIC interop runner** (Seemann and Iyengar, SIGCOMM EPIQ workshop 2020; results matrix at interop.seemann.io): automated interop matrix across QUIC implementations in Docker with a network simulator; fourteen test cases listed in question 4; unsupported cases exit 127; a separate WebTransport test set exists (`webtransport.md`, `implementations_webtransport.json`). — [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner); [test case definitions](https://github.com/quic-interop/quic-interop-runner/blob/master/quic.md); [paper page](https://research.protocol.ai/publications/automating-quic-interoperability-testing/)
- **h3spec**: an HTTP/3 and QUIC server conformance tester from the Haskell `http3`/`quic` ecosystem; that library's own server tests run it. — [Hackage: http3 ServerSpec](https://hackage.haskell.org/package/http3-0.1.2/src/test/HTTP3/ServerSpec.hs)
- **HTTP Garden** (Dartmouth and Narf Industries; arXiv May 2024): a coverage-guided differential fuzzer for HTTP/1.1 origin servers plus a REPL that sends one payload through many servers and proxies and compares interpretations; it argues most significant parsing anomalies are in origin servers, which earlier gateway-only black-box testing missed; examples include chunk-size parsing and whitespace in header names. — [arXiv 2405.17737](https://arxiv.org/abs/2405.17737); [GitHub narfindustries/http-garden](https://github.com/narfindustries/http-garden)
- **Http11Probe** (2026, open source): probes HTTP/1.1 servers against RFC 9110/9112 requirements, smuggling vectors and malformed input; the README describes 215 tests across six categories, 76 of them compliance tests; documentation pages exist per test (e.g. obs-fold, chunk-extension LF, header normalisation). CI snapshots in February 2026 pull requests: Apache 107/135 (79 %), HAProxy 98/135 (73 %), Caddy 78/135 (58 %) on one run; 101/127, 95/127, 74/127 on an earlier one with a smaller test count. — [Http11Probe](https://github.com/MDA2AV/Http11Probe); [PR #61 comment](https://github.com/MDA2AV/Http11Probe/pull/61); [chunk-ext LF test page](https://mda2av.github.io/Http11Probe/docs/smuggling/chunk-ext-lf)
- **HTTP Request Smuggler** (PortSwigger, Burp extension): the tool the 2025 research recommends for regular scanning; the 2025 release added detection of parser discrepancies (hidden/visible headers, Expect). — [PortSwigger research](https://portswigger.net/research/http1-must-die)
- The RFC Editor's stance on chunk parsing strictness (erratum 7633 rejected) is the reference point these HTTP/1.1 testers use when they treat bare LF in chunk lines as a failure. — [RFC Editor errata, RFC 9112](https://errata.rfc-editor.org/search/?rfc_number=9112)
- CERT/CC points implementers to the MadeYouReset reporters' supplemental material for testing; no conformance suite is named. — [CERT/CC VU#767506](https://kb.cert.org/vuls/id/767506)

### Inferences
- What "passing" is taken to mean, per tool:
  - **h2spec** [PK: summerwind/h2spec, tests written against RFC 7540 and 7541 sections; last release 2020]: every MUST-level error condition is answered with the right connection or stream error. It predates RFC 9113, so it still exercises the deprecated priority frames (tolerating them is required anyway) and says nothing about RFC 9218, RFC 8441 or DoS budgets. Vendors cite a full h2spec pass as the baseline.
  - **h3spec**: the equivalent for QUIC transport errors and HTTP/3 frame/stream errors; small (tens of cases) and server-only.
  - **QUIC interop runner**: the QUIC community's shared definition of "interoperable"; a green row against several independent stacks (quic-go, ngtcp2, quiche, picoquic, lsquic, neqo) is stronger evidence than any spec suite, because it covers loss, Retry, resumption, 0-RTT, key update and rebinding under a simulated network.
  - **HTTP Garden / Http11Probe / HTTP Request Smuggler**: absence of *known* parsing discrepancies. Scores are not conformance certificates: several probes test stricter-than-RFC behaviour (rejecting what the RFC lets a recipient tolerate), so "failures" of nginx or Caddy can be RFC-permitted leniency. They are best used as a list of decisions to make deliberately.
  - **REDbot** [PK: redbot.org, Mark Nottingham; lints a live resource's responses for caching, validators, ranges, content negotiation] and **cache-tests.fyi** [PK: http-tests/cache-tests; conformance of HTTP caches, relevant only if the server caches upstream responses, plus a Structured Fields test suite at httpwg/structured-field-tests] are response-quality tools, not parsers' conformance.
  - **nghttp2 tools** (`nghttp`, `h2load`) and **curl** are interoperability clients; `h2load` is also the standard HTTP/2 and HTTP/3 load generator. [PK]
  - **T-Reqs** [PK: CCS 2021 differential fuzzer for request smuggling, grammar-based] and **h2csmuggler** [PK: 2020 tool for smuggling through proxies that forward `Upgrade: h2c`] are research tools for specific classes; the second is moot for a server that never honours `Upgrade: h2c`.
- A defensible v1.0 claim would be: h2spec clean on TLS and h2c listeners; h3spec clean; interop-runner matrix published against at least two stacks; Http11Probe/HTTP Garden results published with each deliberate deviation explained; plus the server's own attack suite for the DoS classes that no public suite covers.

### Gaps
- No source fetched for h2spec, REDbot, cache-tests, T-Reqs, h2csmuggler (all [PK] above); the search calls returned nothing on them.
- Http11Probe's live results page (moved to http-probe.com) returned 404, so there are no current per-server, per-category scores, and nothing for nginx, h2o or OpenLiteSpeed.
- Whether h2spec has a maintained successor covering RFC 9113 was not established.
- The interop runner's list of registered server implementations (whether nginx, HAProxy, lsquic are in it today) was not retrieved.

---

## 6. Application-level protocols a web server is expected to carry

### Takeaway
WebSocket over HTTP/1.1 Upgrade and unbuffered streaming for Server-Sent Events are table stakes; WebSocket over HTTP/2 (RFC 8441) is shipped by Apache and HAProxy and used by browsers but still absent from nginx; gRPC proxying needs HTTP/2 to the origin and trailers end to end, which every competitor now has (nginx's general HTTP/2 upstream arrived in December 2025); HTTP/3 to origins is experimental everywhere and not expected.

### Cited Findings
- WebSocket over HTTP/2: Apache `H2WebSockets` since 2.4.58; HAProxy since 2.4 via extended CONNECT (one forum post of unclear date disputes how complete HAProxy's handling is); Firefox implements RFC 8441; nginx has an open ticket and no changelog entry through 1.31.8. — [Apache httpd CHANGES_2.4](https://downloads.apache.org/httpd/CHANGES_2.4); [Announcing HAProxy 2.4](https://www.haproxy.com/blog/announcing-haproxy-2-4); [Mozilla bug 1434137](https://bugzilla.mozilla.org/show_bug.cgi?id=1434137); [nginx trac #1992](https://trac.nginx.org/nginx/ticket/1992)
- WebSocket over HTTP/3 (RFC 9220): no browser ships it (secondary source, early 2026); Chromium has only an intent to prototype. — [Chromium intent](https://groups.google.com/a/chromium.org/g/blink-dev/c/KOupRe29WhY); [dev.to (secondary)](https://dev.to/instatunnel/scaling-real-time-ingress-tunneling-websockets-via-http3-extended-connect-1i5o)
- RFC 9931 restates that WebSocket clients must wait for the server's 101 before sending data, and advises that upgrade tokens be restricted to GET requests without content. — [RFC 9931](https://www.rfc-editor.org/rfc/rfc9931.html)
- Caddy's proxy performs the HTTP upgrade and then switches to a bidirectional tunnel; WebSocket connections are closed on config reload by default, with `stream_timeout` and `stream_close_delay` to tune it. — [Caddy reverse_proxy docs](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
- Server-Sent Events: RFC 10036 names SSE as the case where a buffering intermediary leaves the client with nothing, and says for bidirectional protocols extended CONNECT "is generally more consistent with HTTP's architecture"; Caddy flushes immediately for `text/event-stream`. — [RFC 10036](https://www.rfc-editor.org/rfc/rfc10036.html); [Caddy reverse_proxy docs](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
- gRPC: nginx has a separate gRPC proxy module, received Early Hints support for it in 1.29.0 and several 2026 fixes (1.29.5, 1.29.7, 1.31.3, 1.31.4: incomplete gRPC responses with non-zero Content-Length are malformed; h2/gRPC requests to backends always carry `:authority`); trailers pass through `proxy_pass_trailers` since 1.27.2. — [nginx CHANGES](https://nginx.org/en/CHANGES)
- HTTP/2 to origins: nginx `ngx_http_proxy_module` since 1.29.4 (2025-12), with upstream keep-alive and HTTP/1.1 by default since 1.29.7; Apache `mod_proxy_http2` (received `ProxyErrorOverride` support in 2.4.66; PortSwigger calls Apache's upstream h2 experimental); Caddy default `versions 1.1 2`, plus `h2c`; HAProxy confirmed by PortSwigger. — [nginx CHANGES](https://nginx.org/en/CHANGES); [Apache httpd CHANGES_2.4](https://downloads.apache.org/httpd/CHANGES_2.4); [Caddy reverse_proxy docs](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy); [PortSwigger research](https://portswigger.net/research/http1-must-die)
- HTTP/3 to origins: HAProxy 3.3 experimental; Caddy `versions 3` experimental, exclusive of other versions and requiring TLS to the upstream. — [Announcing HAProxy 3.3](https://www.haproxy.com/blog/announcing-haproxy-3-3); [Caddy reverse_proxy docs](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
- FastCGI: Caddy's FastCGI transport sets the standard CGI variables and `HTTP_*` headers, never passes the client's `Proxy` header as `HTTP_PROXY`, and offers `php_fastcgi` as the PHP shortcut; nginx fixed SCGI proxying with chunked request bodies in 1.29.6 and Apache fixed Transfer-Encoding response smuggling in mod_proxy_uwsgi (2.4.69) and several AJP flaws (2.4.67), showing gateway protocols remain a live attack surface. — [Caddy reverse_proxy docs](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy); [nginx CHANGES](https://nginx.org/en/CHANGES); [Apache httpd CHANGES_2.4](https://downloads.apache.org/httpd/CHANGES_2.4)
- CONNECT-based tunnelling is expanding at the standards level: template-driven CONNECT for TCP is in the RFC Editor queue, and QUIC datagram/capsule RFCs (9221, 9297) underpin CONNECT-UDP. — [IETF datatracker, httpbis documents](https://datatracker.ietf.org/wg/httpbis/documents/); [IETF datatracker, quic documents](https://datatracker.ietf.org/wg/quic/documents/)

### Inferences

| Protocol | Class | What the server must do | Competitor status |
|---|---|---|---|
| WebSocket over HTTP/1.1 (RFC 6455, 2011, pre-2024, still holds) | (b) | Forward `Upgrade`/`Connection` hop-by-hop on request, hand over on 101, tunnel with half-close and idle limits; survive reloads | All six [PK for LiteSpeed, h2o] |
| WebSocket over HTTP/2 (RFC 8441) | (c) trending (b) | Advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL`, accept `:protocol = websocket`, translate to an HTTP/1.1 Upgrade toward the origin | Apache 2.4.58+, HAProxy 2.4+, Envoy, Caddy [PK]; not nginx |
| WebSocket over HTTP/3 (RFC 9220) | (d) | Same over h3 | No browser demand yet |
| Server-Sent Events | (b) | No response buffering for `text/event-stream`, no compression buffering, idle timers that do not cut quiet streams, client-abort detection; honour `Incremental: ?1` | nginx needs `proxy_buffering off` or `X-Accel-Buffering: no` [PK]; Caddy automatic |
| gRPC (HTTP/2 end to end, `application/grpc`, trailers carry `grpc-status`) | (b) for a general reverse proxy | HTTP/2 to the origin (h2c prior knowledge and TLS), trailers both ways, no buffering of streaming calls, per-stream flow control across the hop | nginx `grpc_pass` (2018) and now `proxy_pass` over h2; Apache mod_proxy_http2; Caddy; HAProxy |
| gRPC-Web | (c) | Either plain pass-through (it is ordinary HTTP/1.1 or h2 with trailers encoded in the body) or translation to gRPC, which only Envoy does natively [PK] | Pass-through everywhere |
| FastCGI (no RFC; the 1996 specification) | (b) for PHP hosting | Responder role, params, stdin streaming, keep-conn optional; httpoxy guard; never trust CGI `Status`/`Location` framing blindly | nginx, Apache mod_proxy_fcgi, Caddy, LiteSpeed (LSAPI preferred), h2o; HAProxy has `fcgi-app` [PK] |
| HTTP/2 to origins | (b) since 2025 | See question 2: it is the recommended desync defence | HAProxy, Apache, Caddy, nginx 1.29.4+ |
| HTTP/3 to origins | (d) | — | HAProxy 3.3 and Caddy, both experimental |
| CONNECT-UDP / MASQUE, WebTransport | (d), out of scope for an origin/reverse proxy | — | h2o and Envoy for MASQUE [PK]; lsquic lists WebTransport |

- For the stated scope (static origin, PHP over FastCGI, reverse proxy to application servers) the two gaps against November 2026 competitors are RFC 8441 (shipped by two, absent from nginx, so defensible to defer) and HTTP/2 to origins (now shipped by all four proxies including nginx, and the security community's headline recommendation, so hard to call a v1.0 "feature complete" without it or without a clearly stated position).

### Gaps
- No primary source fetched for gRPC-Web handling in any of the six servers, nor for Caddy's or h2o's extended CONNECT support.
- LiteSpeed/OpenLiteSpeed and h2o proxy capabilities (h2 upstream, WebSocket over h2) were not found in project documentation during this session.
- No measurement found of how much browser WebSocket traffic actually uses RFC 8441 versus HTTP/1.1 Upgrade.
