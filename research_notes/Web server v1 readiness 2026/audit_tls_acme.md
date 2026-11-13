# Audit: TLS termination, TLS to origins, and the ACME client

Read-only source audit of agensio at commit `bf67e7ac` (0.1.0-alpha.145), 2026-11-13. Nothing was
built or run. Paths are relative to the repository root. Statements about OpenSSL's defaults are
from memory and marked **(M)**; the machine's library is OpenSSL 3.5.7, Asio is 1.38.2
(`build/_deps/asio-src`). The RFCs other than 9001 and 6797 were not in `docs/rfc/` and are quoted
from memory; section numbers should be checked before they are cited elsewhere.

## Summary

The TLS layer is small and sound in what it does itself: TLS 1.2 minimum, no compression, no early
data, client renegotiation refused, SNI that never shows another site's certificate, a 421 rule
tied to the certificate actually presented, bounded handshakes, QUIC on TLS 1.3 with h3-only ALPN,
origin verification on by default with name or IP checks, and an ACME client that covers the
RFC 8555 happy path with HTTP-01.

What stands out is how much is left to OpenSSL's defaults and how little is configurable. agensio
sets exactly four things on a server context: the protocol floor, `SSL_OP_NO_COMPRESSION`, the SNI
callback and the ALPN callback. Cipher suites, groups, signature algorithms, session cache,
ticket keys and ticket count are all the library's (or the distribution's `openssl.cnf`). There is
no configuration key for any of them. The consequences that matter:

1. **TLS 1.2 cipher list is OpenSSL's `DEFAULT`**, client order: CBC and static-RSA suites can be
   negotiated, including with HTTP/2 (RFC 9113 9.2.2 blocklist). BCP 195 recommends ECDHE + AEAD only.
2. **Session ticket keys are never rotated** inside a generation; they change only when a reload,
   certificate refresh or restart builds new contexts. BCP 195 asks for regular rotation.
3. **ALPN with no overlap falls back to HTTP/1.1** instead of the `no_application_protocol` alert
   RFC 7301 3.2 requires.
4. **ACME**: no ARI (RFC 9773), `Retry-After` parsed and ignored, fixed one-hour retry with the
   back-off state lost at restart, no external account binding (yet `docs/tls.md` 2.4 names
   ZeroSSL and Google, which need it), one CA with no fallback, the key file replaced before the
   certificate file (a failed second write leaves a mismatched pair on disk).
5. **TLS client to origins** sends no `close_notify` and accepts a close-delimited body that ends
   without one (truncation not detected); no session reuse, no client certificate.
6. Known and documented as missing: OCSP stapling, TLS-ALPN-01, DNS-01 and wildcards for `auto`,
   wildcard `server_name` routing, kTLS, 0-RTT.

Nothing found is a remotely exploitable defect in agensio's own code. The gaps are policy
defaults, missing features and a few SHOULD-level deviations.

## Section 1. What the TLS layer does today

### 1.1 Server side over TCP (HTTP/1.1 and HTTP/2)

| Topic | What the code does | Where |
|---|---|---|
| Library object | One `SSL_CTX` per certificate file per listener, built for each `Generation` (start, reload, certificate refresh that changed something); shared by all workers. The pair is loaded once into a holder context and its certificate, chain and key are shared by reference into the listener context | `src/server.cpp:659-686`, `src/services/certificates.cpp:24-42` |
| Minimum version | TLS 1.2: Asio options `no_sslv2/3`, `no_tlsv1`, `no_tlsv1_1`, then `SSL_CTX_set_min_proto_version(TLS1_2_VERSION)`. Not configurable | `src/server.cpp:663-666`, `:680` |
| Maximum version | Not set: the library's highest (TLS 1.3). Not configurable | (no call) |
| Cipher suites, TLS 1.2 | Not set: OpenSSL `DEFAULT` filtered by the security level, or the system `openssl.cnf`. No key | no `SSL_CTX_set_cipher_list` anywhere in `src/` |
| Cipher suites, TLS 1.3 | Not set: library default (AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM) **(M)** | no `SSL_CTX_set_ciphersuites` |
| Groups / curves | Not set: library default. OpenSSL 3.0 to 3.4: X25519, P-256, X448, P-521, P-384, ffdhe (no ML-KEM without an extra provider). OpenSSL 3.5 and 4.x: `X25519MLKEM768` is in the default list and preferred, so the hybrid is negotiated with a client that offers it, with no configuration **(M)** | no `SSL_CTX_set1_groups*` |
| Signature algorithms | Not set: library default; SHA-1 signatures are below security level 1 since OpenSSL 3.0 **(M)** | no `SSL_CTX_set1_sigalgs*` |
| Security level | Not set: 1 upstream in 3.0/3.1, 2 from 3.2; Debian and Ubuntu build with 2 **(M)** | (no call) |
| Server cipher preference | Not set (`SSL_OP_CIPHER_SERVER_PREFERENCE` absent): the client's order decides | `src/server.cpp:664-666`, `:682` |
| Compression | Off: `SSL_OP_NO_COMPRESSION` set explicitly, and Asio's constructor sets it too | `src/server.cpp:682`; asio `ssl/impl/context.ipp:371` |
| Renegotiation | Nothing set. OpenSSL 3.0+ refuses client-initiated renegotiation by default **(M)**; the integration suite holds it | `tests/integration.sh:716-719` |
| `SSL_OP_ALL` | Set through Asio's `default_workarounds` (four legacy bug workarounds in 3.5; harmless at TLS 1.2+) | `src/server.cpp:664` |
| `single_dh_use` | Passed, a no-op since OpenSSL 1.1.0 (`SSL_OP_SINGLE_DH_USE` is 0) | `src/server.cpp:666`; `/usr/include/openssl/ssl.h:482` |
| DH parameters | None set (no `SSL_CTX_set_dh_auto`, no tmp DH): DHE suites cannot be chosen in TLS 1.2 **(M)**; TLS 1.3 ffdhe groups are the library's | (no call) |
| Session cache | Not set: library default, server-side internal cache, 20,000 sessions, on the listener's first context **(M)**. No session id context set (harmless without client certificates) | (no call) |
| Session tickets | Not set: enabled, 2 tickets per full TLS 1.3 handshake **(M)**. Ticket key: random, made by OpenSSL when the context is created, in memory only | (no call) |
| Ticket key sharing | Across workers: yes (one context). Across sites of a listener: yes (OpenSSL keeps using the context the handshake started on, `l->ssl`, for tickets after the SNI switch **(M)**). Across listeners: no. Across reload, certificate refresh, restart: no (new contexts) | `src/server.cpp:683`, `:1727` |
| Ticket key rotation | None within a generation | (no call) |
| Early data (0-RTT) | Never: `max_early_data` stays 0, `SSL_read_early_data` is never called | (no call) |
| Read-ahead | On (`SSL_set_read_ahead(ssl, 1)`) with a 17 KB staging buffer | `src/tls_stream.hpp:55`, `:312` |
| Modes | `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER`, `SSL_MODE_AUTO_RETRY`; no partial write; `SSL_MODE_RELEASE_BUFFERS` deliberately off | `src/tls_stream.hpp:54`, `src/server.cpp:681` |
| kTLS | Not enabled | (no `SSL_OP_ENABLE_KTLS`) |
| ALPN | List from `protocols` (`h2`, `http/1.1`) in the configured order; the first of ours the client offers wins. No overlap, or no ALPN extension: no protocol selected, the connection speaks HTTP/1.1 | `src/server.cpp:499-530`, `src/config.cpp:1496-1510` |
| h2 selection | After the handshake, `SSL_get0_alpn_selected == "h2"` hands the socket to `Http2Connection`. No check of TLS version or cipher for h2 | `src/http1/connection.hpp:150-157` |
| SNI: known name | The site's context is swapped in (`SSL_set_SSL_CTX`) | `src/server.cpp:464-480` |
| SNI: unknown name | The listener's catch-all site's certificate if there is one; otherwise fatal `unrecognized_name`, counted (`tls_handshakes_refused`) | `src/server.cpp:467-472`, `src/core/router.cpp:34-51`, `src/http1/connection.hpp:100-108` |
| SNI: none | Same rule: catch-all's certificate, or fatal `unrecognized_name` | same; `tests/integration.sh:632-633` |
| TLS listener with no site | Closed before any handshake, counted | `src/server.cpp:1717-1725` |
| Site names | Exact names only, plus `*` as catch-all. `*.example.com` is accepted in `server_name` but never routed (documented) | `src/core/router.cpp:20-51`, `docs/redirects.md:305-306` |
| 421 rule | Names of the certificate the handshake ended with (subject CN, DNS and IP SANs; wildcard = exactly one leftmost label) fixed for the connection's life; a Host outside them, or no site for it, is 421 with `Cache-Control: no-store`. HTTP/2 and HTTP/3 use the same names | `src/server.cpp:434-458`, `src/core/host.hpp:35-63`, `src/handlers/dispatch.cpp:573-579`, `:594-598`, `:633-636`, `src/http3/connection.hpp:226` |
| Certificates per site | One pair (`tls = { cert, key }` or `"auto"`). No second certificate (ECDSA + RSA) | `src/config.hpp:38-42`, `src/config.cpp:2892-2916` |
| Chain | Whatever follows the leaf in the PEM file is sent as the chain (`SSL_CTX_use_certificate_chain_file`, then `SSL_CTX_set1_chain`). No chain building, no completeness or order check | `src/services/certificates.cpp:27`, `src/server.cpp:672-676` |
| Key types | Whatever OpenSSL loads from PEM (RSA, ECDSA, Ed25519); the key must match the certificate. No passphrase callback | `src/services/certificates.cpp:30` |
| Key file permissions | Checked only for "the server's account can read it" (`tls_key_unreadable`). No check that the key is not group- or world-readable | `src/services/pools.cpp:502-524` |
| Loading and isolation | A pair that fails sets its site aside; a serving site keeps the pair in memory; hourly stat-based watch, `cert-renew`, refresh without reading configuration | `src/services/certificates.cpp:44-79`, `src/server.cpp:2442-2520`, `:2527` |
| OCSP stapling, must-staple, SCT/CT | None | (no code) |
| Client certificates (mTLS) | None | (no `SSL_VERIFY_PEER` on server contexts) |
| Handshake timeout | The connection's timer runs from accept; the handshake must finish within `idle_timeout` (15 s default) or the connection is closed | `src/http1/connection.hpp:133-144`, `:424-457` |
| Handshake limits | None of its own beyond the per-worker connection ceiling (a TLS client above it is closed before the handshake) | `src/server.cpp:1714-1715` |
| Handshake failure | Connection closed; no log line; only SNI refusals are counted | `src/http1/connection.hpp:139-144` |
| Alerts | OpenSSL's. agensio chooses two itself: `unrecognized_name` and `internal_error` in the SNI callback | `src/server.cpp:470`, `:475` |
| close_notify sent | Yes, best effort: one non-blocking `SSL_shutdown` before the TCP close, HTTP/1 and HTTP/2 | `src/tls_stream.hpp:97-102`, `src/http1/connection.hpp:260`, `src/http2/connection.hpp:229` |
| close_notify on receipt | Not required: EOF without it (`SSL_R_UNEXPECTED_EOF_WHILE_READING`) is mapped to a clean EOF. Harmless for requests, which are length- or chunk-delimited | `src/tls_stream.hpp:166-170` |
| Error queue | Cleared after an error only (measured choice), and after `SSL_shutdown` | `src/tls_stream.hpp:11-12`, `:191`, `:211`, `:234`, `:100` |
| Secrets | Key log callback exists only in `-DAGENSIO_INTEROP=ON` builds and only with `SSLKEYLOGFILE` set | `src/server.cpp:487-497`, `:741-745` |
| Record size / coalescing | Default 16 KB records; header and body prefix coalesced into one record; HTTP/2 DATA sized to one record. No security effect found | `src/tls_stream.hpp:216-236` |
| Non-blocking | Every accepted socket is set non-blocking before OpenSSL's socket BIO writes to it | `src/server.cpp:1706-1707` |
| Configuration keys | `tls` (`"auto"` or `{cert, key}`), `protocols`, `hsts`, `http`, `[server] acme {email, directory, ca, storage}`, `proxy.tls {verify, ca, server_name}`. No key for versions, ciphers, groups, tickets, session cache, client certificates or OCSP | `src/control/reference.cpp:22-23`, `:36-39`, `:106-111`, `:183`, `:223-227` |

### 1.2 QUIC TLS (HTTP/3)

| Topic | What the code does | Where |
|---|---|---|
| API | OpenSSL 3.5 third-party QUIC TLS callbacks (`SSL_set_quic_tls_cbs`); agensio carries CRYPTO bytes and installs the yielded secrets | `src/quic/tls.cpp:38-59`, `:105-151` |
| Context | The listener's first TCP context (`lst->ssl`): same certificates, same SNI callback, same ticket keys as TCP | `src/server.cpp:932-933` |
| Version | TLS 1.3 only (`SSL_set_min_proto_version(ssl, TLS1_3_VERSION)`) | `src/quic/tls.cpp:52` |
| ALPN | `h3` only (plus `hq-interop` in interop builds); a client that offers ALPN without `h3` gets a fatal alert from the callback. A client with no ALPN extension is caught after the handshake: connection closed with an HTTP/3 code | `src/server.cpp:502-517`, `src/http3/connection.hpp:234` |
| Transport parameters | Ours passed to OpenSSL before the handshake (original DCID, initial SCID, retry SCID, reset token and limits); the client's decoded when OpenSSL reports them, server-only parameters refused, `initial_source_connection_id` compared with the packet's | `src/quic/connection.hpp:97-120`, `:912-917`, `src/quic/transport_params.hpp:86-141` |
| Early data | Refused: 0-RTT packets are skipped, early secrets ignored, `max_early_data` 0 so tickets do not advertise it | `src/quic/connection.hpp:292-295`, `:905-906` |
| Session tickets | OpenSSL's default tickets go out as 1-RTT CRYPTO data; the `SSL` object is freed once they are acknowledged. Resumption without 0-RTT should work; not verified by a test I found | `src/quic/connection.hpp:1210-1216` |
| Suites | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305; any other suite fails the handshake | `src/quic/tls.cpp:99-103`, `:139-140` |
| Alerts | A TLS alert becomes `CONNECTION_CLOSE` with `crypto_base + alert`; a failure without an alert is reported as 80 | `src/quic/tls.cpp:84-88`, `src/quic/connection.hpp:926` |
| Key update, AEAD limits | Implemented in the transport (confidentiality and integrity limits) | `src/quic/crypto.hpp:23-25`, `src/quic/connection.hpp:338`, `:999-1005` |
| Handshake bound | A handshake finishes within `idle_timeout` or the connection is dropped; Retry above 512 handshakes in progress per worker | CLAUDE.md "HTTP/3"; not re-read line by line |
| 421 | Same certificate names as TCP, taken when the handshake completes | `src/http3/connection.hpp:226` |

### 1.3 TLS as a client

| Use | Verification | Name check | SNI | CA store | Min version | ALPN | Session reuse | Where |
|---|---|---|---|---|---|---|---|---|
| Reverse proxy to `https://` origins | On by default (`verify = true`) | `proxy.tls.server_name` if set; otherwise the certificate must carry the upstream's IP address as an IP SAN | Sent only when `server_name` is set (origins are IP literals) | System store, or `proxy.tls.ca` | TLS 1.2 | None sent (HTTP/1.1 only) | None; kept connections are reused instead | `src/upstream/client.cpp:432-453`, `:688-712`, `src/tls_stream.hpp:77-89`, `src/upstream/options.hpp:86-94`, `src/upstream/client.cpp:139-143` |
| `verify = false` | `SSL_VERIFY_NONE`: any certificate, any name, expired or self-signed | none | as above | none | TLS 1.2 | | | `src/upstream/client.cpp:448-449` |
| ACME directory | Always on | Host name of the URL (`expect_peer_name`, return value ignored) | Yes | System store, or `acme.ca` | TLS 1.2 | None | None; one connection per request | `src/services/acme.cpp:344-360` |
| `site-install` downloads | Always on | Host name of the URL (return value ignored) | Yes | System store, or `install_ca` | TLS 1.2 | None | None | `src/services/fetch.cpp:175-189` |
| Health's own probe | None (loopback to its own listener, by design) | none | Yes | none | library default | None | None | `src/control/probe.cpp:94-98` |

Common to all: no revocation checking (no CRL, no OCSP), no client certificate, library default
cipher suites and groups. The proxy client sends no `close_notify` when it closes
(`shutdown_notify` has no caller under `src/upstream/`) and accepts EOF without one as the end of
a close-delimited body (`src/tls_stream.hpp:169`, `src/upstream/http_client.cpp:170-176`). The
handshake to an origin is bounded by `send_timeout` (`src/upstream/client.cpp:702-703`).

### 1.4 ACME client

| Topic | What the code does | Where |
|---|---|---|
| Protocol | RFC 8555, HTTP-01 only, JWS ES256, POST-as-GET | `src/services/acme.cpp:1`, `:473-497` |
| Account key | ECDSA P-256, `<storage>/account.key`, mode 0600 in a 0700 directory owned by the server's account; created on first use; one key whatever the directory URL | `src/services/acme.cpp:65`, `:419-434`, `:636-668` |
| Account | `newAccount` with `termsOfServiceAgreed: true` and `mailto:<email>` on every order (finds the existing account by key). `email` is required by the configuration. No contact update, no deactivation, no `onlyReturnExisting` | `src/services/acme.cpp:452-466`, `src/config.cpp:5154-5156` |
| Directory | Fetched on every order; `newNonce`, `newAccount`, `newOrder` used. `meta` (terms of service, `externalAccountRequired`, profiles), `renewalInfo`, `revokeCert`, `keyChange` not read | `src/services/acme.cpp:437-450` |
| CA | One directory, Let's Encrypt production by default; no fallback CA | `src/config.hpp:48` |
| Nonce | From `newNonce` (HEAD), then from each reply; one retry on `badNonce` using the error reply's nonce | `src/services/acme.cpp:473-497`, `:509-518` |
| Order | All of the site's `server_name` entries as `dns` identifiers in one order (one certificate per site, shared when two sites name the same certificate path) | `src/services/acme.cpp:621-634`, `:758-771` |
| Challenges | `http-01` only; a CA offering none fails the order. Authorizations already `valid` are skipped | `src/services/acme.cpp:789-800` |
| Polling | Authorization and order polled once a second, at most 60 times; `Retry-After` is parsed but never used | `src/services/acme.cpp:531-548`, `:300`, `:400` |
| CSR | New P-256 key per issuance (key rotated at every renewal); CN = first name, SAN = all names; signed with SHA-256; no must-staple, no other extensions | `src/services/acme.cpp:226-258`, `:834-835` |
| Certificate download | The order's `certificate` URL, body accepted if it contains `-----BEGIN CERTIFICATE-----`; alternate chains (`Link: rel="alternate"`) ignored | `src/services/acme.cpp:856-861` |
| Writing | `key.pem` (0600) is renamed into place first, then `fullchain.pem` (0644), each through a `.tmp` sibling | `src/services/acme.cpp:862`, `:89-115` |
| Renewal rule | Hourly check; renew when the certificate is missing, unreadable, the placeholder, does not cover a name, or has less than a third of its lifetime left. No ARI | `src/services/acme.cpp:670-674`, `:729-751`, `:914-931` |
| Renewal timing by lifetime | 90 days: day 60. 45 days: day 30. 6 days (160 h): about hour 107, 53 h before expiry | arithmetic on `renewal_due` |
| Failure | Logged with the CA's problem text; that certificate is skipped for one hour, then tried again, indefinitely, at a constant interval. The skip list is in memory: a restart orders at once | `src/services/acme.cpp:918-920`, `:942`, `:954-955` |
| Rate limits | No awareness: `rateLimited` problems and `Retry-After` are treated like any failure | `src/services/acme.cpp:499-506` |
| While an order fails | A new site serves a self-signed placeholder (P-256, 7 days, CN `agensio placeholder`); a renewing site keeps its current certificate, also past expiry. Health: `certificate_not_issued`, `acme_renewal_failed`, `acme_renewal_overdue` | `src/services/acme.cpp:261-284`, `:652-661`, `docs/tls.md` section 5 |
| After success | The certificate refresh loads the pair (no configuration read); new connections get it | `src/server.cpp:1803-1810`, `:2442-2520` |
| Wildcards | Refused at load for `tls = "auto"` | `src/config.cpp:2894-2897` |
| IP identifiers | Not supported: identifiers are always `dns`; an IP literal in `server_name` is not refused at load | `src/services/acme.cpp:760` |
| EAB, revocation, key rollover, profiles, TLS-ALPN-01, DNS-01 | Not implemented | (no code) |
| Clock | System clock against notBefore/notAfter; no skew handling | `src/services/acme.cpp:670-674` |
| HTTP client | Blocking, one TLS connection per request, 30 s socket timeouts after connect, reply capped at 1 MB, read to EOF | `src/services/acme.cpp:335-412` |
| HTTP-01 responder | Before site routing, redirects, access rules and the 421 test; exact lookup of the normalised path's last part in the map of tokens of orders in flight; answers `text/plain` with `token.thumbprint`. Served on every listener (plain or TLS, any port), any Host, any method. An unknown token falls through to normal routing (404 or 421) | `src/handlers/dispatch.cpp:619-630`, `src/services/acme.hpp:24-47` |
| Token validation | The token is taken from the CA's JSON as is; the base64url alphabet is not checked. A token with other characters would simply never match a request path | `src/services/acme.cpp:793-801` |
| Port 80 | A TLS site on 443 opens port 80 by itself; health warns `acme_needs_port_80` otherwise | `src/control/commands.cpp:1977-1980` |

### 1.5 HSTS and the plain-HTTP redirect

| Topic | What the code does | Where |
|---|---|---|
| Where the field is sent | Only on answers over TLS, or over a connection a trusted proxy marked `https`; never on a plain answer (RFC 6797 7.2) | `src/handlers/dispatch.cpp:641-644` |
| Which answers | Every answer once the site is known: files, PHP, proxied answers, redirects, error pages. Not on a 421 or an answer given before a site is found | same |
| Value | `max-age=N` and optionally `; includeSubDomains`, built at load. `preload` is deliberately not offered (`docs/redirects.md` 4.6) | `src/config.cpp:2238-2240` |
| max-age validation | Integer seconds or a duration, 0 to ten years; `hsts = true` and `false` are refused; 0 is allowed (forget) | `src/config.cpp:2190-2237` |
| One field only | With `hsts` on, the application's own field is dropped; with `"application"` it passes; with `"none"` it is removed. `add_headers` refuses the field | CLAUDE.md "Response"; `src/control/reference.cpp:216` |
| Default | Off; health suggests it after a week of a real certificate | `docs/tls.md` 2.7 |
| Plain HTTP | `http = "redirect"` by default for a TLS site on 443: 308 to `https://`, same host and path, a day (`no-store` for a name only a catch-all took); certificate validation paths served first | `src/handlers/dispatch.cpp:520-523`, `:654-666` |

No deviation from RFC 6797 was found on the server side.

## Table 2. Gaps against the standards and good practice

Confidence is about the description of what agensio does. Classification: **C** conformance bug,
**H** security hardening, **F** expected feature, **O** optional.

| # | Reference | Required or recommended | What the code does | Practical consequence | Conf. | Class |
|---|---|---|---|---|---|---|
| 1 | RFC 9325 4.1, 4.2 (BCP 195); RFC 9113 9.2.2 and Appendix A | TLS 1.2: forward-secret AEAD suites; SHOULD NOT negotiate static RSA key transport; HTTP/2 over TLS 1.2 SHOULD NOT use blocklisted suites | No cipher list is set (`src/server.cpp:663-682`); OpenSSL's `DEFAULT` with the client's order applies, which includes CBC and static-RSA suites **(M)**; nothing ties `h2` to the suite (`src/http1/connection.hpp:150-157`) | A TLS 1.2 client that prefers such a suite gets it, also with HTTP/2. Modern clients put ECDHE+AEAD first, so in practice it is scanners (SSL Labs style grades, compliance checklists) that notice. The host's `openssl.cnf` is the only lever today | high (no call); medium (exact default list) | H |
| 2 | RFC 9325 3.4 | Ticket keys changed regularly (weekly is the example), ticket lifetime bounded | No ticket handling at all; OpenSSL's per-context random key lives as long as the generation: until the next reload, certificate refresh or restart (`src/server.cpp:659-686`, `:2326`) | On a quiet host one key can protect months of TLS 1.2 sessions: a later memory disclosure decrypts recorded TLS 1.2 traffic that used tickets. TLS 1.3 resumption keeps forward secrecy through (EC)DHE **(M)**. Side effect in the other direction: every reload invalidates all tickets | high | H |
| 3 | RFC 7301 3.2; RFC 9325 3.8 | A server with no protocol in common with the client's ALPN list SHALL answer `no_application_protocol` | `select_protocol` returns `SSL_TLSEXT_ERR_NOACK` on no overlap and the connection proceeds as HTTP/1.1 (`src/server.cpp:521-526`) | A client offering only an unknown protocol (or only `h2` on an h1-only listener) is served HTTP/1.1 instead of being refused; strict ALPN is also the recommended defence against cross-protocol (ALPACA) attacks. nginx and others refuse | high | C |
| 4 | RFC 8446 9.2 | A server that requires SNI SHOULD answer a ClientHello without it with `missing_extension` | No SNI on a listener without a catch-all gets `unrecognized_name` (`src/server.cpp:467-471`) | Cosmetic: the alert name differs | high | O |
| 5 | RFC 9001 8.1 | No ALPN negotiated: close with `no_application_protocol` (0x0178) | A QUIC client that sends no ALPN extension is not seen by the ALPN callback; agensio closes after the handshake with an HTTP/3 application code (`src/http3/connection.hpp:234`), unless OpenSSL refuses first (not determined) | Wrong error code at most; no request is served | medium | C (minor) |
| 6 | RFC 8446 6.1 | Each side sends `close_notify` before closing its write side | The proxy's TLS client never calls `shutdown_notify` (`src/upstream/`: no caller) | Origins that log unclean TLS shutdowns will log them; no data loss | high | C (minor) |
| 7 | RFC 8446 6.1; RFC 9112 9.8 | A close-delimited message that ends without `close_notify` is incomplete | EOF without `close_notify` is mapped to a clean EOF (`src/tls_stream.hpp:169`) and ends a close-delimited origin body normally (`src/upstream/http_client.cpp:170-176`). The ACME and download clients read to EOF the same way (`src/services/acme.cpp:372-378`) | An attacker on the path between agensio and a TLS origin can truncate a close-delimited response undetected. Bodies with Content-Length or chunked framing are not affected | high | H (low) |
| 8 | RFC 8555 7.5.1, 6.6 | Honour `Retry-After` when polling and on rate limits | Parsed into `HttpReply::retry_after`, never read; polls every second, 60 times (`src/services/acme.cpp:400`, `:531-548`) | A slow CA (or one asking for longer waits) sees 60 requests a minute per pending object, and an order that needs more than about a minute fails and is retried an hour later | high | C (SHOULD) |
| 9 | RFC 9773 | Ask the CA when to renew; renew early when it says so; mark the replaced certificate | Not implemented; fixed rule of a third of the lifetime left (`src/services/acme.cpp:670-674`) | A mass revocation or a CA-suggested early window is not noticed until health or a browser shows it; no rate-limit exemption for ARI renewals at Let's Encrypt **(M)**. The fixed rule itself is sane for 90, 45 and 6 day certificates | high | F |
| 10 | Good practice (Let's Encrypt integration guide) | Back off on repeated failures; persist the state; respect rate limits | Constant one-hour retry forever; skip list in memory, so each restart orders at once (`src/services/acme.cpp:918-920`, `:954`) | A host restarted in a loop, or with a permanently failing name, keeps ordering; Let's Encrypt's failed-validation limit (5 per name per hour **(M)**) is not hit by the hourly rhythm but is by restarts | high | H |
| 11 | RFC 8555 7.3.4 | External account binding where the CA requires it | Not implemented; `meta.externalAccountRequired` not read | CAs that require EAB (ZeroSSL, Google Trust Services **(M)**) cannot be used, although `docs/tls.md` 2.4 names them as usable while 2.5 lists EAB as missing | high (code); medium (which CAs) | F, and a documentation error |
| 12 | Robustness | Replace key and certificate as a unit | `write_file(key) && write_file(cert)` (`src/services/acme.cpp:862`): if the second write fails (disk full) the new key is already in place beside the old certificate | The pair on disk no longer matches. The running server keeps the pair in memory and the hourly retry repairs it, but a restart in between sets the site aside (or refuses the start for a site in the main file) | high (order of writes); medium (the chain of consequences) | H |
| 13 | RFC 8555 7.4.2 | The client should check what it downloads | The chain is written if it contains a PEM certificate marker; it is not parsed, matched to the new key or to the names first (`src/services/acme.cpp:858-862`) | A CA or path error is only found when the pair is loaded, after the old files were replaced (same repair path as row 12) | high | H (low) |
| 14 | Single CA | (Caddy's practice: fall back to a second CA) | One directory, no fallback (`src/config.hpp:48`) | A CA outage near expiry has no second route; with 6-day certificates the margin is 53 hours | high | O |
| 15 | RFC 8555 8.3 | Token is base64url only | Not checked by the client (`src/services/acme.cpp:793-801`) | None found: an odd token never matches a request path, and the body is `text/plain` | high | O |
| 16 | RFC 6066 3; RFC 9525 | SNI carries host names only; verify the name asked for | The ACME and download clients pass the URL's host to SNI even if it is an IP literal, and ignore the return of `expect_peer_name` (`src/services/acme.cpp:358-359`, `src/services/fetch.cpp:186-187`) | The call fails only on allocation failure; then the chain would be verified without a name. Checking the return closes it | high | H (low) |
| 17 | Common practice (a private key readable by its owner, or one group, only) | Private keys readable by their owner only | No test of the key file's mode beyond "the server can read it" (`src/services/pools.cpp:502-524`); the reference says "0600, root's or the server's" (`src/control/reference.cpp:224`) but nothing enforces or reports it | A world-readable key goes unnoticed (site credentials elsewhere do get `credential_exposed`) | medium (I looked for a check and found none) | H |
| 18 | RFC 9525 (the subject CN is no longer an identity) | Do not use the subject CN for identity when a SAN is present | The 421 rule adds the CN to the SAN names (`src/server.cpp:438`) | Slightly more permissive than clients are; a client would not have accepted the certificate for that name anyway | high | O |
| 19 | RFC 9325 7.5; RFC 6066 8 | Servers SHOULD support OCSP stapling | None | Known gap. Weight reduced since Let's Encrypt ended OCSP in 2025 **(M)**; still asked for by other CAs' customers and by checklists | high | F / O |
| 20 | Operability | See why handshakes fail | A failed handshake closes silently; only SNI refusals are counted (`src/http1/connection.hpp:139-144`) | "Old client cannot connect" (protocol or cipher mismatch) leaves no trace on the server | high | O |
| 21 | Listener scope | (none) | Ticket keys and the TLS 1.2 session cache belong to the listener's first context (`src/server.cpp:683`) | No resumption between two listeners of one host (an IPv4 and an IPv6 address listed separately, two ports); performance only | medium | O |

## Table 3. Features not implemented

| Feature | What it is for | Status |
|---|---|---|
| OCSP stapling (RFC 6066 8, RFC 6961) and must-staple | Revocation status delivered by the server | Known ("Not yet") |
| TLS-ALPN-01 (RFC 8737) | ACME validation on port 443 for hosts without port 80 | Known |
| DNS-01, wildcard certificates with `tls = "auto"` | Wildcards, hosts not reachable from the CA | Known |
| ACME Renewal Information (RFC 9773) | The CA tells when to renew (revocation events, load spreading) | New |
| External account binding (RFC 8555 7.3.4) | CAs that tie ACME accounts to a customer account | Known (`docs/tls.md` 2.5) |
| ACME IP identifiers (RFC 8738) | Certificates for IP addresses (Let's Encrypt issues them on short-lived profiles **(M)**) | New |
| ACME profiles (draft, Let's Encrypt) | Choosing the 6-day or the `tlsserver` profile | New |
| ACME revocation, account key rollover, account deactivation, contact update | Key compromise handling, account hygiene | New |
| Alternate chain selection, a second CA as fallback | Choosing a root, surviving a CA outage | New |
| Honouring `Retry-After`, exponential back-off, persisted failure state | Rate-limit friendliness | New |
| TLS policy keys: minimum version (TLS 1.3 only), cipher suites, groups, signature algorithms | Compliance profiles (PCI, BSI, Mozilla modern/intermediate), post-quantum only or classical only | New |
| Server cipher preference | Enforcing the server's order | New |
| Session ticket key rotation, ticket and cache settings (count, lifetime, off), keys shared across hosts | Forward secrecy hygiene; resumption behind a load balancer | New |
| Strict ALPN (`no_application_protocol`) | RFC 7301 conformance, ALPACA defence | New |
| Client certificates (mutual TLS), per site or per path, with CRL | Authenticating clients, Cloudflare authenticated origin pulls | New |
| Two certificates per site (ECDSA and RSA) | Old clients without ECDSA | New |
| Wildcard `server_name` routing (`*.example.com`) | Using a wildcard certificate without listing every name | Known (`docs/redirects.md` 3.2) |
| Chain building or checking (missing or misordered intermediates), key-size and expiry-of-intermediate findings | Catching a broken chain before clients do | New |
| Passphrase-protected private keys | Keys encrypted at rest | New |
| Private-key file mode finding | Catching a readable key | New |
| kTLS (`SSL_OP_ENABLE_KTLS`) | sendfile over TLS, less copying | Known ("Open") |
| 0-RTT (TCP and QUIC), QUIC NEW_TOKEN, ECN, QUIC v2 | Faster resumption | Known |
| Encrypted Client Hello | Hiding the site name | New (needs OpenSSL 4.x **(M)**) |
| Certificate compression (RFC 8879), delegated credentials, raw public keys, record size limit extension | Smaller handshakes and niche uses | New, optional |
| Handshake failure log or counters by reason | Diagnosing client incompatibility | New |
| TLS to origins: client certificate, session resumption, ALPN / HTTP/2 to origins, host names as upstreams, revocation checks | mTLS backends, cheaper reconnects | Partly known (HTTP/2 to origins, names) |
| HSTS `preload` directive | Browser preload lists | Known, declined (`docs/redirects.md` 4.6) |
| TLS session and key export for debugging in release builds | Wireshark decryption | Declined by design (interop builds only) |

## Table 4. Could not determine

| Question | What I looked at | Why it stays open |
|---|---|---|
| The exact TLS 1.2 cipher list a given install offers | No cipher call in `src/`; OpenSSL defaults from memory | Depends on the OpenSSL version, its security level and the distribution's `openssl.cnf`; needs `openssl s_client` or a scanner against a running server on each target (Debian 12 and 13, Ubuntu 24.04, Arch with 4.1) |
| Whether X25519MLKEM768 is really chosen on 3.5 and 4.1, over TCP and over QUIC | Defaults from memory; `src/quic/connection.hpp` CRYPTO reassembly not read line by line | A hybrid ClientHello spans two QUIC Initial packets; the interop runs with quic-go and ngtcp2 suggest multi-packet ClientHellos work, a browser test would confirm |
| Default session lifetime and ticket lifetime | OpenSSL from memory: 7,200 s in the code, 300 s in one man page | Not verifiable without the library source or a test |
| Resumption across sites of one listener (a ticket from site A used with SNI B) | `src/server.cpp:464-480`; OpenSSL behaviour from memory | I believe TLS 1.3 resumes and the SNI callback then switches to B's context, so the 421 rule follows B's certificate; TLS 1.2 reports the original name. No server-side harm seen without client certificates, but it matters the day mutual TLS is added (the nginx issue of 2025) |
| Whether OpenSSL's third-party QUIC TLS API itself enforces ALPN, the presence of the peer's transport parameters, and no middlebox compatibility mode | `src/quic/tls.cpp`, `src/quic/connection.hpp:902-927` | agensio's code does not check that transport parameters arrived (`peer_params_ok_` is only set, never required); if OpenSSL does not either, a client without them completes the handshake with zero credit and can do nothing. Needs a test with a hand-built ClientHello (`tests/h3-attacks.py` style) |
| Automatic TLS 1.3 KeyUpdate at the AES-GCM limit over TCP | No call in `src/`; OpenSSL from memory | About 380 GB on one connection before it matters; QUIC has its own limits implemented |
| Behaviour with a passphrase-protected key | `src/services/certificates.cpp:30` (no password callback) | OpenSSL's default callback may prompt on a terminal; under systemd it should fail. Not run |
| SHA-1 and weak-key refusal at load | Left to the security level | Depends on the level of the install |
| What `-t` and health say about a chain without intermediates or with an expired intermediate | `src/services/acme.cpp:691-727` reads the leaf only | I found no chain inspection; I did not read all of `src/control/commands.cpp` |
| Windows and macOS paths of the TLS code | Not examined | Out of the time available; the code is shared |
| RFC wording quoted from memory (RFC 9325 3.4, 3.8, 4.1, 7.5; RFC 7301 3.2; RFC 8446 9.2; RFC 8555 7.5.1; RFC 9773) | Not in `docs/rfc/` | Section numbers and MUST/SHOULD levels should be checked against the texts before the scope document cites them |
