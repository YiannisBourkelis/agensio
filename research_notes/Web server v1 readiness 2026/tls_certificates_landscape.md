# TLS, certificates and transport security: what a production web server must and should implement (state of November 2026)

Method notes for the report writer:

- Research date 2026-11-13. About 50 search and fetch calls. Items marked **[verified]** were read from the cited page in this session. Items marked **[RFC text, not re-fetched]** come from a stable RFC whose content is well known and whose URL is given, but the page was not opened in this session. Items marked **[secondary]** come from a search summary or a non-primary page and should be treated with more caution.
- Classification labels used throughout: **REQUIRED** (a standard or a browser/CA rule makes it mandatory, or a server without it is broken or unsafe), **EXPECTED** (not mandatory, but every serious competitor ships it and administrators and scanners assume it), **OPTIONAL**, **EMERGING**, **DEPRECATED**.
- Untrusted content: no fetched page contained text addressed to an automated reader or asking for an action (three pages were explicitly checked for it: the Cloudflare PQ post, the Let's Encrypt forum announcement and the CaptainDNS article; none). The search tool itself appends a standard reminder to cite sources to every result; that is tool boilerplate, not page content, and was followed only in the sense that sources are cited here.
- Several facts postdate mid-2026 (RFC 9846, RFC 9851, RFC 9852, RFC 10024, OpenSSL 3.5.9, dns-persist draft -02). They come from search results pointing at rfc-editor.org, datatracker.ietf.org and openssl-library.org and are flagged where only a search summary was seen.

---

## 1. Protocol and cipher baseline

### Takeaway
The baseline in late 2026 is TLS 1.3 plus TLS 1.2 with only ECDHE AEAD suites, TLS 1.0/1.1 and SSLv3 never negotiated, client-chosen cipher order, and X25519MLKEM768 first in the group list; the reference "Mozilla" profiles are now version 6.0 at docs.tlsref.org, which dropped the Old profile and all DHE suites. TLS 1.3 was republished as RFC 9846 (July 2026, backward compatible), TLS 1.2 is formally in feature freeze (RFC 9851), and scanners cap a server without TLS 1.3 at A-.

### Cited Findings

**Standards**
- RFC 9846, "The Transport Layer Security (TLS) Protocol Version 1.3", published July 2026 (datatracker history: 2026-07-11), obsoletes RFC 8446; it is "a minor update" that keeps the version number and is backward compatible **[verified, first 100k characters of the RFC]** — [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html), [datatracker history](https://datatracker.ietf.org/doc/rfc9846/history/)
- Changes in RFC 9846 against RFC 8446 that touch a server: KeyShare values must not be reused between connections; TLS 1.0 and 1.1 must not be negotiated (RFC 8996); starting a key update before the key usage limit is now a MUST; the number of permitted KeyUpdate messages is limited; a new `general_error` alert; `close_notify` back to warning level; the RSA-PSS requirement text removed; language generalised to cover KEM-based key exchange **[verified]** — [RFC 9846 section 1.2](https://www.rfc-editor.org/rfc/rfc9846.html)
- RFC 9846 states that TLS 1.3 forbids renegotiation (a second ClientHello gets `unexpected_message`), that the compression field must be exactly one zero byte, and that 0-RTT data has "no guarantees of non-replay between connections" **[verified]** — [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html)
- RFC 9851 "TLS 1.2 is in Feature Freeze" (July 2026, Proposed Standard): apart from urgent security fixes, new exporter labels and new ALPN ids, no changes will be approved for TLS 1.2. In practice: post-quantum key exchange will never come to TLS 1.2 **[secondary: search summary of rfc-editor.org]** — [RFC 9851](https://www.rfc-editor.org/info/rfc9851/)
- RFC 9852 "New Protocols Using TLS Must Require TLS 1.3" (July 2026, BCP, updates RFC 9325) **[secondary: search summary]** — [RFC 9852](https://www.rfc-editor.org/rfc/rfc9852.txt)
- RFC 9325 (BCP 195, November 2022; older than 2024, still the current BCP, updated by RFC 9852) **[verified]** — [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html):
  - 3.1.1: MUST NOT negotiate SSL 2, SSL 3, TLS 1.0, TLS 1.1; MUST support TLS 1.2; SHOULD support TLS 1.3 and MUST prefer it when supported.
  - 3.2: web servers MUST support HSTS and SHOULD use it.
  - 3.3: TLS-level compression SHOULD NOT be supported in TLS 1.2.
  - 3.4: resumption information MUST be authenticated and encrypted; ticket-encryption keys MUST be rotated regularly ("e.g., weekly") and old keys destroyed; ticket validity MUST be limited; TLS 1.3 servers SHOULD use `psk_dhe_ke`.
  - 3.5: TLS 1.2 MUST implement `renegotiation_info` (RFC 5746) and `extended_master_secret` (RFC 7627).
  - 3.6: multiplexed protocols (HTTP/2) should not use post-handshake authentication.
  - 3.7: SNI MUST be supported; a server that does not recognise the name SHOULD NOT continue the handshake and SHOULD send `unrecognized_name`.
  - 3.8: ALPN MUST be supported by both sides; when no protocol matches the server "SHALL respond with a fatal" `no_application_protocol` alert.
  - 3.10: 0-RTT must be avoided unless the application protocol has an explicit profile (RFC 8470 for HTTP, RFC 9001 9.2 for QUIC).
  - 4.1/4.2: MUST NOT negotiate NULL or RC4; SHOULD NOT negotiate static RSA key transport, static DH/ECDH, or (in TLS 1.2) ephemeral finite-field DHE; CBC suites SHOULD NOT be used without encrypt-then-MAC; recommended TLS 1.2 suites are ECDHE-RSA/ECDSA with AES-128/256-GCM.
  - 4.5: RSA certificates at least 2048 bits; SHOULD support P-256 and X25519.
  - 4.6: Truncated HMAC MUST NOT be used.
- RFC 8996 (March 2021; older than 2024, still holds and is now restated inside RFC 9846) deprecates TLS 1.0 and 1.1 — [RFC 9846 section 1.2](https://www.rfc-editor.org/rfc/rfc9846.html)
- OpenSSL 4.0.0 (released 14 April 2026, not an LTS, supported until 14 May 2027) removed SSLv3 and the engine API; OpenSSL 3.5 is the current LTS, supported until 8 April 2030, latest patch 3.5.9 of 29 September 2026 **[4.0: secondary search summary of the release announcement; 3.5.9: verified]** — [OpenSSL 4.0 final release](https://openssl-library.org/post/2026-04-14-openssl-40-final-release/), [OpenSSL 3.5 release notes](https://openssl-library.org/news/openssl-3.5-notes/)

**The reference server profiles (formerly Mozilla Server Side TLS)**
- The Mozilla wiki page now only says the public guidelines "have been moved to a community working group managed project outside of Mozilla" at docs.tlsref.org (wiki page last edited 11 June 2026) **[verified]** — [Mozilla wiki](https://wiki.mozilla.org/Security/Server_Side_TLS)
- TLSRef Server-Side TLS, version 6.0 **[verified]** — [docs.tlsref.org/server-side-tls](https://docs.tlsref.org/server-side-tls.html):
  - **Modern**: TLS 1.3 only; suites TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256; ECDSA P-256 certificate; lifespan 90 days.
  - **Intermediate (recommended)**: TLS 1.2 and 1.3; TLS 1.2 suites ECDHE-ECDSA/RSA with AES128-GCM-SHA256, AES256-GCM-SHA384, CHACHA20-POLY1305 only; ECDSA P-256 (recommended) or RSA 2048; lifespan 90 days recommended, up to 366.
  - Both: groups **X25519MLKEM768, X25519, prime256v1, secp384r1** in that order; HSTS `max-age=63072000`; **client chooses** the cipher (no server preference).
  - Version history: 5.8 "removed kDHE ciphers from Intermediate and Old ... prepended the X25519MLKEM768 PQC hybrid KEM to recommended groups"; 6.0 "Removed the Old configuration".
  - The 6.0 page no longer mentions OCSP stapling or session tickets at all (the 5.x Mozilla text recommended stapling).
  - Oldest clients for Intermediate: Firefox 31.3, Android 4.4.2, Chrome 49, IE 11 on Windows 10, Java 8u161, OpenSSL 1.0.1l, Safari 9.

**Scanners**
- SSL Labs (Qualys notice, February 2025): a server without TLS 1.3 gets a warning and is capped at A-; missing TLS_FALLBACK_SCSV no longer affects the grade; proper HSTS matters for the higher grades **[secondary: search summary of the Qualys notice]** — [Qualys notice 2025-02-26](https://notifications.qualys.com/product/2025/02/26/key-changes-in-ssl-labs-grading-and-qualys-certview)
- SSL Labs caps a server that offers TLS 1.0 or 1.1 at B (live since January 2020; older than 2024, still in force) and caps at B when forward secrecy is not negotiated with the reference browsers **[secondary]** — [Qualys TLS 1.0/1.1 grade change](https://blog.qualys.com/ssllabs/2018/11/19/grade-change-for-tls-1-0-and-tls-1-1-protocols), [Qualys CertView grading](https://docs.qualys.com/en/certview/latest/scans/ssl_grading.htm)

**Session tickets, resumption, 0-RTT, SNI, ALPN, kTLS**
- TLS 1.3 ticket lifetime is at most 7 days (604,800 s) **[RFC text, not re-fetched]** — [RFC 9846 section 4.6.1](https://www.rfc-editor.org/rfc/rfc9846.html)
- 0-RTT over HTTP needs the RFC 8470 profile (the `Early-Data` request field and `425 Too Early`), and replay protection is the server's job **[RFC text, not re-fetched; requirement to use it verified in RFC 9325 3.10]** — [RFC 8470](https://www.rfc-editor.org/rfc/rfc8470.html), [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html)
- The 421 rule: a server that receives a request for an authority it is not configured to answer on that connection (connection reuse across names in HTTP/2 and HTTP/3, or a Host that differs from the SNI's site) answers `421 Misdirected Request` **[RFC text, not re-fetched]** — [RFC 9110 section 15.5.20](https://www.rfc-editor.org/rfc/rfc9110.html#name-421-misdirected-request)
- nginx has `ssl_reject_handshake` (1.19.4, 2020) to refuse a handshake with `unrecognized_name` for an unknown name, and since 2021 rejects connections whose ALPN does not match, "a recommended behavior by RFC 7301 and ... useful for mitigation of protocol confusion attacks" **[secondary: search summary of the nginx commits]** — [nginx commit, ALPN mismatch](https://mailman.nginx.org/pipermail/nginx-devel/2021-October/014434.html)
- kTLS: nginx has used it for `SSL_sendfile()` since 1.21.4 (2021; needs a kernel and OpenSSL 3 built with kTLS); HAProxy 3.3 (released 26 November 2025) added a `ktls` option for bind and server lines with OpenSSL and AWS-LC **[secondary]** — [F5/nginx kTLS post](https://www.f5.com/company/blog/nginx/improving-nginx-performance-with-kernel-tls.html), [Announcing HAProxy 3.3](https://www.haproxy.com/blog/announcing-haproxy-3-3)

### Inferences

Classification for a 1.0 scope:

| Item | Class | Note |
|---|---|---|
| TLS 1.3 (RFC 9846 semantics) | REQUIRED | SSL Labs caps at A- without it; HTTP/3 needs it; PQ key exchange exists only here |
| TLS 1.2 with ECDHE + AEAD only | EXPECTED (on by default) | RFC 9325 still says MUST support; the Intermediate profile is the recommended default; frozen by RFC 9851 |
| A "modern" switch (TLS 1.3 only) per server or site | EXPECTED | The two-profile model is what administrators and generators know |
| TLS 1.0/1.1, SSLv3, RC4, 3DES, static RSA, DHE, CBC | DEPRECATED, must not be offered | RFC 9325, RFC 9846, tlsref 6.0; OpenSSL 4 removed SSLv3 |
| Client cipher preference | EXPECTED | tlsref 6.0 says the client chooses; server preference is the old advice |
| TLS compression off, renegotiation refused | REQUIRED | Both are library defaults today; a server must only make sure nothing re-enables them |
| `renegotiation_info` and extended master secret on TLS 1.2 | REQUIRED | Library-provided |
| SNI with refusal of unknown names; 421 for a mismatched authority | REQUIRED (421), EXPECTED (handshake refusal as an option) | RFC 9325 3.7 is a SHOULD; many servers serve a default certificate instead |
| ALPN with strict no-match alert | REQUIRED | RFC 7301 / RFC 9325 3.8; also the ALPACA mitigation |
| Session tickets with key rotation | EXPECTED | RFC 9325 3.4 makes rotation a MUST when tickets are used; a server that keeps one key for the process lifetime breaks forward secrecy for as long as it runs |
| Stateless resumption shared across workers | EXPECTED | Otherwise resumption fails whenever a connection lands on another worker or after a reload |
| 0-RTT (TLS and QUIC) | OPTIONAL, off by default | Needs RFC 8470 handling and anti-replay; nginx, HAProxy and Caddy keep it opt-in |
| kTLS | OPTIONAL (performance) | Linux only; matters for large files over TLS |
| Dynamic TLS record sizing | OPTIONAL | No source found this session that makes it an expectation |

- With TLS 1.3 only in the Modern profile and DHE removed from Intermediate, a server needs no DH parameter handling at all in 2026.
- The scanner-relevant defaults are: TLS 1.3 on, no TLS 1.0/1.1, forward secrecy with every reference client, HSTS available, a complete chain. Everything else on a scanner's vulnerability list (Heartbleed, CCS, ROBOT, POODLE, FREAK, Logjam, DROWN, SWEET32, BEAST, Lucky13) is answered by "OpenSSL 3.x or later and the Intermediate suite list".
- OpenSSL's built-in ticket handling generates a key per `SSL_CTX` and does not rotate it on its own, so "rotation" in a server means either rebuilding contexts periodically or installing a ticket key callback with a key ring (current plus previous). A reload that rebuilds the contexts gives rotation as a side effect but also invalidates every ticket.

### Gaps
- The full RFC 9846 text past section 4.3 was not read (page is 362k characters); the mandatory-to-implement suite, group and signature lists of its section 9 are assumed unchanged from RFC 8446 apart from the RSA-PSS and KEM wording.
- Qualys lists a post "SSL Labs Grade Change for TLS 1.0 and TLS 1.1 Protocols" dated 16 March 2026; its content could not be retrieved, so whether the cap moved from B to something lower in 2026 is unknown.
- The current SSL Labs rating guide document itself and the testssl.sh 3.2 documentation were not fetched. From general knowledge testssl.sh checks protocols, cipher categories, forward secrecy, server preference, certificate and chain, OCSP stapling, session ticket lifetime, HSTS and other headers, a list of named vulnerabilities (including client-initiated renegotiation and CRIME/BREACH) and client simulations; this is unverified for the 2026 release.
- No current authoritative source was found on TLS 1.3 kTLS coverage across distributions' OpenSSL builds or on dynamic record sizing as an expectation.
- OpenSSL 4.1 release notes were not found by search; only 4.0 was confirmed.

---

## 2. Post-quantum

### Takeaway
Hybrid key exchange X25519MLKEM768 is the deployed norm in 2026: over half of human traffic to Cloudflare by October 2025 and over 60 % by February 2026, default in all major browsers and in OpenSSL 3.5+, standardised as RFC 10024 (August 2026). A server only has to offer the group first in its list and cope with a ClientHello that no longer fits one packet; post-quantum certificates (ML-DSA or Merkle Tree Certificates) are not something a 1.0 server can deploy yet.

### Cited Findings
- "In the last week of October 2025, the majority of human-initiated traffic with Cloudflare" used post-quantum key agreement ("over 50% (and rising!)") **[verified]** — [Cloudflare, State of the post-quantum Internet in 2025](https://blog.cloudflare.com/pq-2025)
- Over 60 % of human-generated TLS traffic to Cloudflare used hybrid ML-KEM in February 2026, up from under 3 % at the start of 2024 **[secondary: InfoQ citing Cloudflare Radar]** — [InfoQ, March 2026](https://www.infoq.com/news/2026/03/cloudflare-post-quantum-ipsec)
- Client timeline: Chrome desktop default March 2024; Go default August 2024; Chrome on Android and Firefox desktop November 2024; OpenSSL default April 2025; Apple with iOS/iPadOS/macOS 26 in October 2025 **[verified]** — [Cloudflare pq-2025](https://blog.cloudflare.com/pq-2025)
- Server side: a September 2025 scan of the top 100k domains found 39 % supporting PQ key agreement (28 % six months earlier); origin servers behind Cloudflare 3.7 % in 2025 (0.5 % in 2023) **[verified]** — [Cloudflare pq-2025](https://blog.cloudflare.com/pq-2025)
- Cloudflare Radar added origin-side PQ tracking on 27 February 2026 **[secondary]** — [Cloudflare changelog](https://developers.cloudflare.com/changelog/post/2026-02-27-radar-pq-key-transparency/index.md)
- OpenSSL 3.5 (April 2025, LTS): "The default TLS supported groups list has been changed to include and prefer hybrid PQC KEM groups"; "The default TLS keyshares have been changed to offer X25519MLKEM768 and X25519"; adds ML-KEM, ML-DSA, SLH-DSA, server-side QUIC and support for third-party QUIC stacks **[verified]** — [OpenSSL 3.5 release notes](https://openssl-library.org/news/openssl-3.5-notes/)
- RFC 10024 "Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3" (August 2026) defines X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024; the server share is the ML-KEM ciphertext concatenated with the ephemeral X25519 share **[secondary: search summary of rfc-editor.org]** — [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html)
- TLSRef 5.8/6.0 put X25519MLKEM768 first in the recommended group list for both profiles **[verified]** — [docs.tlsref.org](https://docs.tlsref.org/server-side-tls.html)
- Size: the X25519MLKEM768 client key share is about 1,216 bytes (X25519 alone: 32), which can split the ClientHello across two TCP segments **[secondary]** — [dev.to article](https://dev.to/indra_gustiprasetya_a80a/post-quantum-tls-is-already-on-and-it-broke-your-router-3hpc); ML-KEM-512 already needs 1,568 bytes on the wire against 64 for X25519 **[verified]** — [Cloudflare pq-2025](https://blog.cloudflare.com/pq-2025)
- Failure modes seen in the field: servers that "don't call read() more than once" for the ClientHello (catalogued at tldr.fail); about 0.02 % of origins reset a fragmented ClientHello but accept one that fits a packet; overall incompatibility with PQ key shares about 0.34 % **[secondary: search summary of the PKI Consortium slides]** — [PKIC 2025 talk](https://pkic.org/events/2025/pqc-conference-austin-us/THU_BREAKOUT_1100_Syed-Suleman-Ahmad_Lessons-Learned-from-Testing-Millions-of-Servers-for-PQ-Compatibility.pdf)
- A reverse proxy doing SNI routing from the first segment broke when curl/OpenSSL began sending PQ shares by default (user report against Traefik) **[secondary: forum report]** — [CachyOS forum](https://discuss.cachyos.org/t/compatibility-upstream-default-pqc-ml-kem-in-curl-openssl-breaks-sni-routing-in-traefik-due-to-clienthello-bloat/24331)
- Two ways a client can offer PQ: send the PQ key share at once (all major browsers) or advertise it and wait for a HelloRetryRequest (one more round trip); Cloudflare found the fast method breaks about 0.05 % of origin connections **[verified]** — [Cloudflare pq-2025](https://blog.cloudflare.com/pq-2025)
- Post-quantum authentication: replacing every signature in a handshake with ML-DSA-44 adds about 15 kB; the median compressed chain today is 3.2 kB and chains above about 10 kB hit the initial congestion window; "The first PQ certificates may appear in 2026, but broad availability and browser trust are unlikely before 2027" **[verified]** — [Cloudflare pq-2025](https://blog.cloudflare.com/pq-2025)
- Let's Encrypt (3 June 2026) will pursue Merkle Tree Certificates, with a staging environment targeted for late 2026 and production in 2027, while tracking ML-DSA in X.509 (RFC 9881) and in TLS (draft-ietf-tls-mldsa); its advice to operators is to enable X25519MLKEM768 now because key exchange is the urgent half **[secondary: search summary of the Let's Encrypt post]** — [Let's Encrypt, PQ certs](https://letsencrypt.org/2026/06/03/pq-certs.html)
- Chrome reportedly will not accept post-quantum signatures in classical X.509 chains and is building a separate quantum-resistant root store for MTCs, CA onboarding targeted around Q3 2027 **[secondary, not confirmed against a Google source]** — [postquantum.com](https://postquantum.com/security-pqc/googles-merkle-tree-mtc-https/)
- OpenSSL 4.0 added the SM2MLKEM768 hybrid **[secondary]** — [Help Net Security](https://www.helpnetsecurity.com/2026/04/14/openssl-4-0-0-released/)

### Inferences

| Item | Class | Note |
|---|---|---|
| Offer X25519MLKEM768, preferred, with X25519 / P-256 / P-384 behind it | EXPECTED (close to REQUIRED for a 2026 release) | It is the OpenSSL 3.5+ default; a server must only not override the default group list with a classical-only one, and should expose a `groups` key that defaults to the tlsref order |
| Read a ClientHello that spans several TCP segments | REQUIRED | Any library-driven handshake does; a hand-written SNI peek or protocol sniff on the first read does not |
| Reassemble a ClientHello spanning several QUIC Initial packets | REQUIRED for HTTP/3 | See below |
| Report the negotiated group in logs or status | OPTIONAL | Useful for administrators asked "are we PQ" |
| ML-DSA or MTC certificates | EMERGING, not for 1.0 | No public CA issues them for the web; design the certificate store so more than one certificate per name is possible |
| Pure ML-KEM groups | EMERGING / OPTIONAL | The IETF last call concluded in 2026 per the mailing list; browsers use the hybrid |

- QUIC effect (inference from the sizes plus RFC 9000, no measurement source found): with a 1,216-byte key share the ClientHello is about 1.4 to 1.8 kB, more than one 1,200-byte Initial datagram, so every browser's first flight is now two Initial packets with the CRYPTO stream split across them, possibly out of order. A QUIC server must buffer out-of-order CRYPTO data (RFC 9000 7.5 requires at least 4,096 bytes), must not derive routing or Retry decisions from "the ClientHello in the first packet", and its anti-amplification budget (three times the bytes received, RFC 9000 8.1) is counted over both datagrams. The server's first flight also grows by the 1,120-byte server share, which makes the certificate chain size plus share more likely to exceed the 3x budget on a single client datagram; certificate compression (RFC 8879) and an ECDSA chain help — [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) **[RFC text, not re-fetched]**
- Any code path that looks at a new TCP connection's first bytes before the TLS library does (protocol detection, a PROXY header check, an SNI peek for passthrough) must tolerate a ClientHello longer than one read.
- A server on a distribution's OpenSSL older than 3.5 (Debian 12: 3.0, Ubuntu 24.04: 3.0) cannot offer the hybrid at all; this is a packaging fact to state in documentation and in a health finding rather than something to work around.

### Gaps
- No primary measurement was found for the share of QUIC handshakes whose ClientHello spans two Initial packets, or for server failures caused by it.
- The live Cloudflare Radar figure for November 2026 was not read; the latest number seen is "over 60 %" for February 2026.
- The Chrome MTC root-store timeline rests on a secondary source.
- Whether RFC 10024's final text differs from the deployed draft codepoint (0x11EC) was not checked; no source suggests it does.

---

## 3. Encrypted Client Hello (ECH)

### Takeaway
ECH became RFC 9849 in March 2026 (with RFC 9848 for the DNS bootstrap), OpenSSL 4.0 (April 2026) is the first OpenSSL release that carries it, and nginx 1.29.4, HAProxy 3.3 (experimental) and Caddy 2.10 (fully automated, including DNS publication) ship server support. For a server on OpenSSL 3.5 LTS it is not available without a patched library, and its value depends on the operator being able to publish HTTPS records and on many sites sharing one public name, so it is an emerging, optional feature for 1.0.

### Cited Findings
- "RFC 9849 was published this month" (post dated 11 March 2026); the OpenSSL implementation supports shared mode only, "Split mode is not implemented"; it was prototyped with curl, Apache2, lighttpd, nginx, freenginx and HAProxy and interoperates with NSS, BoringSSL, Cloudflare's test server, wolfSSL and Rustls **[verified]** — [OpenSSL blog, ECH](https://openssl-library.org/post/2026-03-11-ech/)
- RFC 9849 came "after eight years in development and testing, alongside RFC 9848 for DNS bootstrapping" **[secondary]** — [Feisty Duck newsletter 136](https://feistyduck.com/newsletter/issue_136_ech_is_done_but_can_we_make_it_work)
- OpenSSL 4.0.0 (14 April 2026) includes ECH conforming to RFC 9849; 4.0 is not an LTS and ends support 14 May 2027 **[secondary: search summary of the release announcement]** — [OpenSSL 4.0 final release](https://openssl-library.org/post/2026-04-14-openssl-40-final-release/)
- nginx 1.29.4 adds ECH with the `ssl_ech_file` directive (one or more ECH PEM files holding the private key and the ECHConfig, generated with `openssl ech`); "the first PEM file configured is used as the retry configuration"; the configuration needs a virtual server matching the ECH `public_name`; the ECHConfig is published in the `ech` parameter of an HTTPS resource record; at the time of the post (19 February 2026) it required building against OpenSSL's `feature/ech` branch **[verified]** — [nginx blog](https://blog.nginx.org/blog/encrypted-client-hello-comes-to-nginx)
- HAProxy 3.3 has "a new, experimental bind argument, ech", gated by `expose-experimental-directives`, with runtime commands `add ssl ech`, `set ssl ech`, `show ssl ech` taking the ECH PEM format **[secondary: search summary of haproxy.com]** — [Announcing HAProxy 3.3](https://www.haproxy.com/blog/announcing-haproxy-3-3), [add ssl ech](https://www.haproxy.com/documentation/haproxy-runtime-api/reference/add-ssl-ech)
- Caddy 2.10 (April 2025) ships "fully automated support for Encrypted ClientHello", generating keys and publishing ECH configs into HTTPS DNS records when a DNS provider module is configured (PR #6862 merged 6 March 2025) **[secondary]** — [Linuxiac on Caddy 2.10](https://linuxiac.com/caddy-2-10-web-server-debuts-enhanced-tls-privacy/)
- Browsers: Firefox and Chrome have had ECH on since October 2023; Safari's status is unconfirmed (older sources say still in development); Android 17 adds platform support **[secondary]** — [CDT](https://cdt.org/insights/encrypted-client-hello-closing-the-sni-metadata-gap/), [Zscaler, September 2026](https://www.zscaler.com/de/blogs/product-insights/encrypted-client-hello-ech-here-stay)
- A 2026 measurement paper describes server-side availability as fragmented by TLS library, "with OpenSSL notably lacking support as of early 2026", and a "Cloudflare monoculture" in deployment **[secondary]** — [IFIP Networking 2026 paper](https://dl.ifip.org/db/conf/networking/networking2026/1571261276.pdf)
- A third-party nginx packager backports ECH onto OpenSSL 3.5 LTS rather than moving to 4.0 because 4.0 is not an LTS **[secondary: vendor view]** — [GetPageSpeed](https://www.getpagespeed.com/server-setup/nginx/nginx-encrypted-client-hello)
- Operational friction: ECH with split-horizon or internal networks produces failures that users report against the server (Caddy forum thread on ECH and internal networks) **[secondary: thread title and context only]** — [Caddy community](https://caddy.community/t/encrypted-client-hello-ech-issues-with-internal-network/31138/17)

### Inferences

What a server must implement to claim ECH (from RFC 9849's model and the three shipped designs):

1. An HPKE key pair and an ECHConfigList naming a `public_name`, loaded from files (the OpenSSL "ECH PEM" format is the de facto interchange format: nginx and HAProxy both take it).
2. Decryption of the inner ClientHello in the TLS library (shared mode), then ordinary SNI selection on the inner name.
3. The rejection path: when decryption fails (stale key), finish the handshake as the `public_name` with its certificate and send `retry_configs`; this is why nginx requires a virtual server for the public name and names the first file as the retry configuration.
4. Key rotation with overlap (several keys loaded, newest published), and tolerance of GREASE ECH extensions, which browsers send to every server.
5. Publication: the operator, or the server through a DNS provider API (Caddy), puts the ECHConfigList in the `ech` parameter of the HTTPS record (RFC 9460 for the record, RFC 9848 for the parameter). Without the record no client uses ECH.

| Item | Class | Note |
|---|---|---|
| ECH server support | EMERGING / OPTIONAL for 1.0 | Standard is final; library support exists only in OpenSSL 4.0+ and BoringSSL-family; the LTS most distributions ship (3.5) has none |
| Ignoring GREASE ECH without failing | REQUIRED | Automatic in the library |
| HTTPS/SVCB record awareness | OPTIONAL | The server cannot publish DNS without a provider integration; at most it can print the record to publish |
| Split mode (a front that only decrypts and forwards) | OPTIONAL | Not in OpenSSL |

- For a hosting server the privacy gain of ECH comes from many sites sharing one public name on one address; a host with a handful of sites hides little. The feature is a credible "after 1.0, once the LTS OpenSSL has it" item, with the certificate and key store designed so an ECH key ring fits beside it.
- ECH in QUIC uses the same ClientHello extension, so a QUIC stack that hands the handshake to OpenSSL gets it from the library, but no source read this session states that the OpenSSL QUIC TLS API paths were tested with ECH.

### Gaps
- Apache httpd: OpenSSL says ECH was prototyped with Apache2, but no released httpd version or directive could be confirmed.
- No figure was found for the share of connections that use ECH in 2026, or for how many servers outside Cloudflare publish ECH configs.
- Safari's ECH status in 2026 is unconfirmed.
- Whether ECH works through OpenSSL's third-party QUIC TLS API (OpenSSL 4.x) was not documented in anything read.
- nginx's own blog says ECH is in 1.29.4; a forum comment claims 1.30; the stable-branch version carrying it was not confirmed.

---

## 4. Certificates and revocation

### Takeaway
OCSP is finished as a web mechanism: Let's Encrypt stopped putting OCSP URLs in certificates on 7 May 2025 and shut its responders on 6 August 2025, browsers check revocation from pushed sets (CRLite, CRLSets), and the answer to revocation is lifetime: CA/Browser Forum maximums of 200 days (since 15 March 2026), 100 days (March 2027) and 47 days (March 2029), Let's Encrypt at 45 days by February 2028, and 160-hour certificates generally available since January 2026. A 1.0 server needs flawless unattended renewal and hot reload far more than it needs OCSP stapling, which is not worth building for Let's Encrypt users and is at most a low-priority option for commercial-CA certificates.

### Cited Findings

**End of OCSP**
- Let's Encrypt: OCSP URL removed from certificates on 7 May 2025, certificates now carry a CRL Distribution Point URL instead **[verified]** — [Let's Encrypt upcoming features, updated 22 July 2026](https://letsencrypt.org/upcoming-features)
- The OCSP service was turned off on 6 August 2025; by then every certificate that contained an OCSP URL had expired **[secondary: search summary of the Let's Encrypt post]** — [Let's Encrypt, OCSP end of life](https://letsencrypt.org/2025/08/06/ocsp-service-has-reached-end-of-life.html)
- Must-Staple: requests for the extension began to fail on 30 January 2025 for accounts that had not used it, and were rejected for everyone from 7 May 2025 **[secondary]** — [Let's Encrypt, Ending OCSP](https://www.abetterinternet.org/post/ending-ocsp), [Feisty Duck 121](https://www.feistyduck.com/newsletter/issue_121_the_slow_death_of_ocsp)
- CA/Browser Forum ballot SC-063 (2023; older than 2024, in force) made OCSP optional for public CAs and CRLs mandatory **[secondary]** — [Ascertia summary](https://blog.ascertia.com/ocsp-and-the-web-pki-whats-changing)
- Chrome has not done online OCSP checks by default since 2012 and uses CRLSets; it never enforced Must-Staple **[secondary]** — [Wikipedia, OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol)
- Firefox ships CRLite (a compact encoding of all revoked certificates seen in CT logs, pushed to the browser) **[secondary: search summary of the Mozilla post]** — [Mozilla Hacks, August 2025](https://hacks.mozilla.org/2025/08/crlite-fast-private-and-comprehensive-certificate-revocation-checking-in-firefox/)
- Other CAs are following: HARICA announced the end of its OCSP service (notice of 29 January 2026) **[secondary]** — [RedIRIS notice](https://rediris.es/tcs/news/2026/20260129-ocsp-end.html)
- A managed host removed stapling from its platform in May 2025 because of the Let's Encrypt change **[secondary]** — [WordPress VIP notice](https://customerhub.wpvip.com/lobby/2025/05/29/ending-ocsp-stapling-support/)
- A configuration linter now flags `ssl_stapling on` with a Let's Encrypt certificate as a misconfiguration (it only produces warnings) **[secondary]** — [gixy check](https://gixy.getpagespeed.com/checks/ssl-stapling-letsencrypt/)
- RFC 9325 7.5 (2022; older than 2024, overtaken by practice): "Servers SHOULD support OCSP and OCSP stapling"; operators MAY request must-staple **[verified]** — [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html)
- The current reference profile (TLSRef 6.0) does not mention OCSP stapling at all **[verified]** — [docs.tlsref.org](https://docs.tlsref.org/server-side-tls.html)

**Lifetimes**
- CA/Browser Forum ballot SC-081v3 (approved 11 April 2025): maximum validity 200 days from 15 March 2026, 100 days from 15 March 2027, 47 days from 15 March 2029; domain validation reuse falls to 10 days by 2029 **[secondary: several summaries agree; ballot page metadata only]** — [CA/B Forum ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/), [DNSimple summary](https://support.dnsimple.com/articles/announcement-ssl-certificate-validity-changes/)
- Let's Encrypt schedule **[verified]** — [From 90 to 45](https://letsencrypt.org/2025/12/02/from-90-to-45), [upcoming features](https://letsencrypt.org/upcoming-features):
  - 13 May 2026: the opt-in `tlsserver` profile issues 45-day certificates.
  - 10 February 2027: the default `classic` profile moves to 64 days and a 10-day authorization reuse period (30 days today).
  - 16 February 2028: `classic` moves to 45 days and a 7-hour authorization reuse period.
  - The `shortlived` profile is unaffected.
- Let's Encrypt's guidance to clients: use ARI; without ARI renew "at about two-thirds of the way through the current certificate's lifetime"; "a hardcoded interval of 60 days will no longer be sufficient"; set up monitoring for failed renewals **[verified]** — [From 90 to 45](https://letsencrypt.org/2025/12/02/from-90-to-45)
- Short-lived certificates (160 hours, "just over six days") and IP address certificates became generally available on 15 January 2026; IP certificates are issued only on the short-lived profile; 90-day certificates continue beside them **[secondary: search summary of the Let's Encrypt post]** — [Let's Encrypt, 6-day and IP GA](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)
- Short-lived certificates carry neither OCSP nor CRL URLs (2025 description) **[secondary]** — [Let's Encrypt, 6-day and IP certs, January 2025](https://letsencrypt.org/2025/01/16/6-day-and-ip-certs)
- TLSRef 6.0 recommends a 90-day certificate lifespan in both profiles **[verified]** — [docs.tlsref.org](https://docs.tlsref.org/server-side-tls.html)

**Key types, chains, client-auth EKU**
- TLSRef 6.0: ECDSA P-256 for Modern; ECDSA P-256 recommended or RSA 2048 for Intermediate **[verified]** — [docs.tlsref.org](https://docs.tlsref.org/server-side-tls.html)
- nginx's ACME module defaults to `ecdsa:256` certificate keys and offers ecdsa 384/521 and rsa 2048/3072/4096 **[verified]** — [nginx-acme README](https://github.com/nginx/nginx-acme)
- TLS Client Authentication EKU: Let's Encrypt removed it from the default profile on 11 February 2026 and retired the temporary `tlsclient` profile on 8 July 2026 **[verified]** — [Let's Encrypt upcoming features](https://letsencrypt.org/upcoming-features)
- Chrome Root Program policy requires publicly trusted TLS server certificates to be serverAuth-only; sources give 15 June 2026 for CA hierarchies and 15 March 2027 as the cutoff for subscriber certificates; client certificates for mTLS must come from a private CA **[secondary, vendor blogs that disagree on the scope of the June date]** — [The SSL Store](https://www.thesslstore.com/blog/chrome-ssl-certificate-client-authentication-ends-june-2026/), [WorkOS](https://workos.com/blog/public-tls-certificates-client-authentication-mtls)
- Cloudflare's advice to operators for the PQ transition: "automate certificate issuance, and make sure you can install multiple certificates" **[verified]** — [Cloudflare pq-2025](https://blog.cloudflare.com/pq-2025)
- Let's Encrypt launched a new hierarchy ("Generation Y") together with the lifetime changes **[secondary: headline only]** — [Neowin](https://www.neowin.net/news/lets-encrypt-launches-generation-y-shortens-cert-lifetimes-to-45-days/)

### Inferences

| Item | Class | Note |
|---|---|---|
| Unattended renewal that survives 45-day and 6-day lifetimes | REQUIRED | With 6-day certificates a renewal outage of three days is an outage of the site |
| Certificate hot reload without dropping connections or restarting | REQUIRED | Renewal every few days makes restart-to-reload unacceptable; also needed for certificates maintained by an external client |
| Watching externally managed certificate files for change | EXPECTED | certbot/acme.sh/panel users expect the new file to be picked up without a manual reload |
| Full chain served as given by the CA, no intermediate pinned or cached across renewals | REQUIRED | Hierarchies change (Generation Y); the ACME response is the chain |
| ECDSA P-256 as the default key type, RSA 2048+ selectable | EXPECTED | tlsref, nginx-acme and Caddy all default to ECDSA |
| Two certificates per name (ECDSA and RSA), chosen by the client's signature algorithms | OPTIONAL now, EXPECTED later | Needed only for very old clients today; the same mechanism is what a PQ transition will need |
| Expiry and renewal-failure visibility (status, health finding, log) | EXPECTED | Let's Encrypt ended expiry e-mails on 4 June 2025, so the server is the only thing that knows |
| OCSP stapling | OPTIONAL, low value; not for 1.0 | Does nothing for Let's Encrypt and, increasingly, other CAs; browsers do not need it; one scanner line at most |
| OCSP Must-Staple handling | DEPRECATED | Not issuable at Let's Encrypt; never enforced by Chrome |
| CRL fetching by the server | Not needed | Revocation of server certificates is a client concern; relevant only if client certificates are verified |
| Support for requesting a certificate profile (`shortlived`, `tlsserver`) | EXPECTED (see ACME) | It is how an administrator opts into 6-day or 45-day certificates |

- Whether to build OCSP stapling in 2026: the costs are a background fetcher, a cache, error handling and a failure mode (a stale staple is worse than none); the benefit is limited to certificates from CAs that still run OCSP and to clients that still look at a staple. Nothing read this session names stapling as an expectation of a new server in 2026, and the reference profile dropped it. Recommendation for the report: classify as optional and defer; state the reason in the documentation so a scanner's "OCSP stapling: not offered" line is explained.
- Authorization reuse falling to 7 hours (February 2028) means every renewal performs a fresh validation. For HTTP-01 the challenge path on port 80 must stay reachable for the life of the site, including behind redirects-to-HTTPS, access rules, password rules and a CDN; a site that closed port 80 after its first issuance will stop renewing.
- Renewing at two thirds of the lifetime (equivalently, with a third left) matches Let's Encrypt's fallback advice; with ARI the CA's suggested window takes precedence.
- Short-lived certificates change the placeholder and failure story: a self-signed placeholder at first start is still fine, but a server should keep serving the last good certificate and escalate loudly well before expiry, since "expired in two days" is the normal state of a 6-day certificate.

### Gaps
- The intermediate values of the CA/B domain-validation reuse schedule (200 days in 2026, 100 days in 2027 from memory of the ballot) were not confirmed from the ballot text.
- Firefox's exact OCSP default in 2026 (a forum comment says OCSP is off for DV certificates from Firefox 142) was not confirmed from a Mozilla source.
- Which large commercial CAs still operate OCSP responders at the end of 2026, and whether Microsoft's or Apple's root programs still require them, was not researched.
- Details of Let's Encrypt's Generation Y hierarchy (new roots, intermediates, cross-signing) were not read.
- No data was found on how many sites actually use the `shortlived` profile.

---

## 5. ACME

### Takeaway
RFC 8555 with HTTP-01 covers single-name sites; what a built-in client is now expected to add is ARI (RFC 9773; ARI renewals are exempt from all Let's Encrypt rate limits), profile selection, TLS-ALPN-01 as a second challenge, external account binding and a second CA as fallback. Wildcards still need DNS-01 (and therefore DNS provider integrations or a hook), DNS-PERSIST-01 is the coming alternative but is not usable at Let's Encrypt as of autumn 2026, and on-demand issuance is a known abuse vector that Let's Encrypt began blocking in 2026.

### Cited Findings

**Protocol pieces**
- ARI: enabled at Let's Encrypt since 23 March 2023; published as RFC 9773; clients query a suggested renewal window **[verified for the date; RFC number verified through the nginx-acme README]** — [Let's Encrypt upcoming features](https://letsencrypt.org/upcoming-features), [nginx-acme README](https://github.com/nginx/nginx-acme)
- ARI renewals are "exempt from all rate limits" at Let's Encrypt (the new order must include at least one identifier of the certificate it replaces, which must not already have been replaced through ARI); non-ARI renewals of the same identifier set are exempt only from the new-orders and per-registered-domain limits **[verified, page updated 5 August 2026]** — [Let's Encrypt rate limits](https://letsencrypt.org/docs/rate-limits/)
- Let's Encrypt rate limits **[verified]** — [rate limits](https://letsencrypt.org/docs/rate-limits/):
  - 300 new orders per account per 3 hours
  - 50 certificates per registered domain (or IPv4 address, or IPv6 /64) per 7 days
  - 5 certificates per exact identifier set per 7 days (no override)
  - 5 authorization failures per identifier per account per hour
  - 1,152 consecutive authorization failures per identifier pause that identifier for the account until unpaused through a self-service portal
  - 10 new accounts per IPv4 address per 3 hours
  - Every rate-limit error carries `Retry-After`; per-IP request limits answer 503 with `Retry-After`
- ACME profiles: enabled at Let's Encrypt on 9 January 2025; still an Internet-Draft (`draft-ietf-acme-profiles-02`, August 2026, working-group last call pending); implemented by Boulder and Pebble and by at least seven clients including Certbot, lego, Caddy and dehydrated **[secondary for the draft status; date verified]** — [draft-ietf-acme-profiles](https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/), [Let's Encrypt upcoming features](https://letsencrypt.org/upcoming-features)
- TLS-ALPN-01 (RFC 8737, 2020; older than 2024, in force): validation on port 443 through the ALPN id `acme-tls/1` and a self-signed certificate carrying the key authorization digest; no port 80 needed **[RFC text, not re-fetched]** — [RFC 8737](https://www.rfc-editor.org/rfc/rfc8737.html)
- Wildcards: "Let's Encrypt requires the dns-01 challenge verification for wildcards" **[secondary: search summary of the mod_md manual]** — [Apache mod_md](https://httpd.apache.org/docs/current/mod/mod_md.html)
- IP address certificates (RFC 8738): generally available at Let's Encrypt since 15 January 2026, short-lived profile only **[secondary]** — [Let's Encrypt, 6-day and IP GA](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)
- DNS-PERSIST-01 **[verified against the article; the article is third-party]** — [CaptainDNS, updated 11 October 2026](https://www.captaindns.com/en/blog/dns-persist-01-tls-certificate-domain-validation); announcement **[secondary]** — [Let's Encrypt, 18 February 2026](https://letsencrypt.org/2026/02/18/dns-persist-01.html):
  - Permitted by the TLS Baseline Requirements (method 3.2.2.4.22; ballot SC-088v3, October 2025).
  - A standing TXT record at `_validation-persist.<name>` holding the issuer domain and the ACME account URI, optional `persistUntil`; set once, no DNS write at renewal.
  - `draft-ietf-acme-dns-persist-02` (20 September 2026) changed the record to a SHA-256-hashed account URI; the -01 plain form "is no longer accepted" by the draft, while Google Trust Services (support since 28 September 2026) still documents the -01 format.
  - Let's Encrypt announced it in February 2026 targeting Q2 2026, then held the rollout until IETF ACME issue #64 was resolved (closed 23 September 2026); as of 11 October 2026 no date is announced and the method is not on its challenge-types page.
  - Clients: lego 5.0.0 and acme.sh 3.1.4 implement draft -01; Certbot's PR was closed unmerged on 3 August 2026 with others open.
- External account binding is part of RFC 8555 and is supported by nginx's module (`external_account_key`) **[verified for nginx]** — [nginx-acme README](https://github.com/nginx/nginx-acme)
- Caddy's defaults: Let's Encrypt and ZeroSSL as issuers with fallback between them (ZeroSSL as second default only when an e-mail is configured, per a 2.11.4-era article); other compatible ACME CAs named on its features page include Google Trust Services, BuyPass, DigiCert, GlobalSign, SSL.com and Smallstep **[secondary]** — [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https), [Caddy features](https://caddyserver.com/features)
- Certbot gained ARI support in 4.1.0 (June 2025) **[secondary, single source]** — [Let's Encrypt, ARI post, 17 March 2026](https://letsencrypt.org/2026/03/17/acme-renewal-information-ari)

**Built-in clients in other servers**
- nginx `ngx_http_acme_module` (announced August 2025 as a preview, written in Rust, packaged at 0.4.1 in Alpine and Arch) **[verified README]** — [nginx-acme README](https://github.com/nginx/nginx-acme), [nginx ACME announcement](https://blog.nginx.org/?p=74612):
  - Challenges: `http-01` (default) and `tls-alpn-01` (since 0.2.0); no DNS-01, so no wildcards ("wildcards in `server_name` are ignored for identifiers").
  - Supports ARI (RFC 9773), IP identifiers (RFC 8738), profiles (draft -03), EAB.
  - Needs a `resolver` in the `http` block; keeps certificates in a shared memory zone (default 256k, "about 50 ECDSA P-256 keys or 35 RSA 2048"); `state_path` persists account key, certificates and keys, and without it the account key is lost on restart.
  - Must be built against the same TLS library as nginx or it can crash.
- Apache mod_md: picks challenges from the listeners (port 80: http-01; port 443 with `Protocols ... acme-tls/1`: tls-alpn-01); dns-01 only through an external script (`MDChallengeDns01`) **[secondary: search summary of the manual]** — [Apache mod_md](https://httpd.apache.org/docs/current/mod/mod_md.html)
- Caddy on-demand TLS: a certificate is requested during the first handshake for a name; Caddy refuses to enable it without an `ask` endpoint or permission module, added after "a number of negligence cases causing abuse"; its documentation says to "reject domains you don't recognize" **[secondary]** — [Caddy on-demand TLS](https://caddyserver.com/on-demand-tls)
- Let's Encrypt, 25 February 2026: a surge of requests for very long hostnames (repeated labels such as `update.update.update.example.com`) caused by "unintended feedback loops" between on-demand issuance (Caddy, Go autocert) and Internet scanners that derive names from CT logs; Let's Encrypt blocks such requests and "may pause accounts"; its recommendation: disable on-demand TLS or have the `ask` endpoint approve only pre-approved names, or use a wildcard **[verified]** — [Let's Encrypt community announcement](https://community.letsencrypt.org/t/blocking-some-on-demand-issuance-caused-by-internet-scanning/245553)
- An operator on Caddy reported hitting Let's Encrypt and ZeroSSL rate limits because wildcard DNS sent every subdomain to the server **[secondary]** — [Caddy community](https://caddy.community/t/provisioning-wildcard-on-demand-tls-records/23846)

### Inferences

| Item | Class | Note |
|---|---|---|
| RFC 8555 with HTTP-01 | REQUIRED (present) | |
| ARI (RFC 9773), including `replaces` in the new order | EXPECTED | Rate-limit exemption, CA-directed early renewal on mass revocation, and Let's Encrypt's first recommendation for short lifetimes; nginx's young module has it |
| Profile selection (`classic`, `tlsserver`, `shortlived`) | EXPECTED | A single string in the new-order request; the only way to 6-day and IP certificates; still a draft, so tolerate a CA without profiles |
| Honouring `Retry-After`, backing off after failures, never looping | REQUIRED | The 1,152-failure pause and the 5-failures-per-hour limit punish a client that retries blindly; a server restarts and reloads often, so state (account, orders, last failure) must persist |
| TLS-ALPN-01 | EXPECTED | The fallback when port 80 is closed or redirected elsewhere; nginx, Apache and Caddy have it; it lives in the TLS accept path (ALPN `acme-tls/1`) |
| DNS-01 | EXPECTED for wildcard users; OPTIONAL for 1.0 | Needs provider plugins or an exec hook; the complaint surface is large (provider APIs, propagation waits, credentials on the web server) |
| DNS-PERSIST-01 | EMERGING | The clean wildcard answer for a server without DNS plugins (one TXT record set by a person once); format unstable between draft -01 and -02 and not offered by Let's Encrypt yet |
| DNS-ACCOUNT-01 | EMERGING | Not researched to a conclusion |
| External account binding | EXPECTED | Needed for ZeroSSL, Google Trust Services and most commercial ACME CAs |
| A configurable directory URL and a second CA as fallback | EXPECTED | Caddy made multi-issuer fallback the norm; a single-CA client turns a CA outage into expiry risk at 6-day lifetimes |
| IP address certificates | OPTIONAL | Follows from profiles plus IP identifiers; HTTP-01 and TLS-ALPN-01 only |
| On-demand TLS | OPTIONAL, deliberately not default | Abuse history at Let's Encrypt in 2026; a hosting server that knows its site list does not need it |
| Staging / test-CA switch and a dry run | EXPECTED | Every guide tells users to test against staging to save rate limits |

Complaints and failure patterns visible in the sources, as design input:
- State loss: nginx's module loses its account key on restart without `state_path`, and its fixed-size shared zone (about 50 certificates by default) is a silent capacity limit. Persistent state and no fixed ceiling are the expectations.
- Missing DNS-01 and wildcard support is the first limitation named for nginx's module; Apache covers it only through an external script.
- Extra required configuration (nginx needs a `resolver`) and library coupling (module and server must share one TLS library).
- On-demand issuance without a strict allow list leads to rate-limit exhaustion and, since 2026, CA-side blocking.
- Hardcoded renewal intervals (60 days) break under 45-day certificates; clients without ARI need lifetime-relative scheduling.
- Certbot's slow adoption of new challenge types (dns-persist PR closed unmerged) shows external clients lag; a built-in client is judged on how fast it follows Let's Encrypt's changes.

### Gaps
- Traefik's ACME complaints (single `acme.json`, clustering, ARI status) and certbot's nginx-installer complaints were searched twice without usable results; nothing is claimed about them.
- mod_md's ARI and profile support in 2026 was not confirmed.
- DNS-ACCOUNT-01's draft status in 2026 was not found.
- Caddy's current ARI behaviour and its default challenge order were not confirmed from Caddy's documentation in this session (Caddy is listed as a profiles implementer in the IETF draft).
- Rate limits and EAB requirements of ZeroSSL and Google Trust Services were not read from their own pages.
- The exact resolution of IETF ACME issue #64 and Let's Encrypt's present dns-persist date rest on one third-party article.

---

## 6. Security headers and policies a server offers natively

### Takeaway
HSTS is the one policy with normative weight for a web server (RFC 9325: implementations MUST support it, servers SHOULD use it; reference value two years), with `preload` strictly opt-in by the preload list's own rules. Verified TLS to upstreams is expected; client-certificate authentication is a niche need for hosting and now requires a private CA because public CAs no longer issue client-auth certificates; security.txt, CAA awareness, SNI passthrough and PROXY protocol are optional conveniences.

### Cited Findings
- RFC 9325 3.2: "Web HTTP implementations MUST support HSTS (RFC 6797). Web servers SHOULD use HSTS unless it would weaken overall security" **[verified]** — [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html)
- TLSRef 6.0: HSTS `max-age=63072000` (two years) in both profiles **[verified]** — [docs.tlsref.org](https://docs.tlsref.org/server-side-tls.html)
- SSL Labs: proper HSTS matters for the top grades since the February 2025 grading change **[secondary]** — [Qualys notice](https://notifications.qualys.com/product/2025/02/26/key-changes-in-ssl-labs-grading-and-qualys-certview)
- HSTS preload list requirements **[verified]** — [hstspreload.org](https://hstspreload.org/):
  - a valid certificate; redirect HTTP to HTTPS on the same host when port 80 is open; all subdomains over HTTPS;
  - the header on the base domain with `max-age` of at least 31536000, `includeSubDomains` and `preload`; a redirect from the HTTPS site must carry the header too;
  - removal takes months to reach Chrome users;
  - "Software and projects that offer HSTS configuration or HTTPS advice should not include `preload` by default"; HSTS itself is recommended, preloading is not.
- Public certificates can no longer be used as client certificates: Let's Encrypt removed the clientAuth EKU from its default profile on 11 February 2026 and retired the `tlsclient` profile on 8 July 2026 **[verified]** — [Let's Encrypt upcoming features](https://letsencrypt.org/upcoming-features); the Chrome Root Program requires serverAuth-only server certificates, and mTLS deployments must move client certificates to a private CA **[secondary]** — [WorkOS](https://workos.com/blog/public-tls-certificates-client-authentication-mtls)
- RFC 9325 3.6: post-handshake client authentication has the problems of renegotiation and should not be used with multiplexed protocols such as HTTP/2 **[verified]** — [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html)
- RFC 9325 3.9: services sharing a name across protocols SHOULD deploy ALPN and equivalent TLS configurations (cross-protocol and DROWN-style exposure) **[verified]** — [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html)
- SNI-based routing of raw TLS reads the name from the ClientHello before any handshake; larger PQ ClientHellos broke at least one such router that read only the first segment **[secondary]** — [CachyOS forum report](https://discuss.cachyos.org/t/compatibility-upstream-default-pqc-ml-kem-in-curl-openssl-breaks-sni-routing-in-traefik-due-to-clienthello-bloat/24331)
- Cloudflare enabled automatic post-quantum key exchange towards origins for 45 billion daily connections (September 2026), with 99.2 % of PQ origin handshakes completing without a HelloRetryRequest **[secondary]** — [InfoQ, September 2026](https://www.infoq.com/news/2026/09/cloudflare-automatic-key-exchang/)
- security.txt is RFC 9116 (April 2022; older than 2024, in force): a file at `/.well-known/security.txt` with `Contact` and a required `Expires` field **[RFC text, not re-fetched]** — [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html)
- CAA (RFC 8659, 2019; in force): the CA checks it at issuance; RFC 8657 adds `accounturi` and `validationmethods` parameters that bind issuance to one ACME account or method **[RFC text, not re-fetched]** — [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659.html), [RFC 8657](https://www.rfc-editor.org/rfc/rfc8657.html)
- PROXY protocol (HAProxy specification, versions 1 and 2; older than 2024, in wide use by load balancers and CDNs' L4 products) carries the client address ahead of the TLS bytes **[specification, not re-fetched]** — [PROXY protocol specification](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)

### Inferences

| Item | Class | Note |
|---|---|---|
| HSTS as a per-site setting, sent on every answer over TLS including errors and redirects | REQUIRED to support, EXPECTED to be easy | RFC 9325; value two years in the reference profile |
| `includeSubDomains` and `preload` as explicit opt-ins, never defaults | REQUIRED behaviour | hstspreload.org says software must not default to preload |
| Suggesting HSTS only once a real certificate has been served for a while | Good practice | HSTS on a site whose renewal then fails locks users out; ties HSTS to renewal health |
| HTTP to HTTPS redirect on the same host, with the ACME challenge path exempt | REQUIRED | Preload rule and HTTP-01 both depend on it |
| TLS to upstreams with verification on by default (chain, name or IP SAN, optional private CA, SNI) | EXPECTED | Unverified upstream TLS is a recurring audit finding; PQ groups towards origins come free with OpenSSL 3.5 |
| Client certificate verification (mTLS) per site or location | OPTIONAL for hosting | Typical users: API endpoints, admin areas, Cloudflare "authenticated origin pulls"; since 2026 always with a private CA, so the server needs only a CA file, optional CRL, and to pass the subject to the application; must be handshake-time authentication, not post-handshake, to work with HTTP/2 and HTTP/3 |
| security.txt | OPTIONAL | It is a static file under `/.well-known/`; a server needs only to not hide `/.well-known/` and perhaps a cookbook recipe; an expired `Expires` is the common fault |
| CAA awareness | OPTIONAL | The server cannot enforce CAA; useful form: a health note when the site's CAA record forbids the configured CA, and documentation of `accounturi` binding as hardening against HTTP-01 hijack |
| SNI passthrough / L4 routing | OPTIONAL, outside a web server's 1.0 | A separate product surface (nginx stream, HAProxy tcp mode); must reassemble multi-segment ClientHellos; ECH hides the inner name from it by design |
| PROXY protocol (accept, v1 and v2) from trusted addresses | OPTIONAL, EXPECTED by users behind L4 load balancers | Hosting on a single box does not need it; cloud load balancers and HAProxy fronts do; must be per listener and trusted-peer gated, never auto-detected |

- How common is mTLS for a hosting server: no survey was found. The evidence is indirect: the public-CA client-auth removal produced a wave of migration notices in 2026 aimed at API, VPN, Wi-Fi and workload-identity users rather than at web hosting, which suggests the hosted-website audience rarely depends on it. Classify as optional and post-1.0 unless a concrete user needs CDN-to-origin authentication.

### Gaps
- No data on how many hosted sites use client certificates, PROXY protocol or SNI passthrough.
- The RFC 9116, RFC 8659/8657 and PROXY protocol texts were cited from prior knowledge, not re-read.
- Whether any mainstream server serves or validates security.txt natively in 2026 was not researched.

---

## 7. TLS-related attack classes still relevant in 2026 and expected mitigations

### Takeaway
With TLS 1.3 plus an ECDHE-AEAD-only TLS 1.2, the classical protocol attacks are closed by configuration and library defaults; what remains for the server's own code is resource exhaustion (handshake floods, KeyUpdate and renegotiation abuse, slow handshakes), forward secrecy of ticket keys, cross-protocol confusion (ALPACA, answered by strict ALPN and SNI), 0-RTT replay, and compression side channels at the HTTP layer. Opossum (2025) targets servers that offer opportunistic TLS upgrade beside implicit TLS, which a server that never implements RFC 2817 `Upgrade: TLS` does not have.

### Cited Findings
- **Opossum** (CVE-2025-49812, IACR ePrint 2025/1260, USENIX Security 2026): a man-in-the-middle desynchronises a client using implicit TLS from a server that also supports opportunistic TLS on the same service, exploiting that in implicit TLS the client speaks first and in the upgrade the server does; over 3 million servers support both modes; for HTTP it needs RFC 2817 upgrade support, which is rare (CUPS, Icecast, Apache's `SSLEngine optional`); mitigation is to disable opportunistic TLS; Apache plans to deprecate RFC 2817 support **[secondary: search summary of the paper's pages]** — [USENIX Security 2026](https://www.usenix.org/conference/usenixsecurity26/presentation/merget), [ePrint 2025/1260](https://eprint.iacr.org/2025/1260), [TII summary](https://www.tii.ae/node/3747)
- RFC 9325 3.2 already requires the TLS-only method to be preferred over dynamic upgrade wherever both exist **[verified]** — [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html)
- **ALPACA** (CVE-2021-3618; older than 2024, still relevant): cross-protocol confusion when several TLS services share a certificate or hostname (multi-domain or wildcard certificates make it easier); nginx's mitigation was to reject connections with a mismatched ALPN and to cap errors before closing **[secondary]** — [Wiz CVE-2021-3618](https://www.wiz.io/vulnerability-database/cve/cve-2021-3618), [nginx-devel](https://mailman.nginx.org/pipermail/nginx-devel/2021-October/014434.html)
- RFC 9325 3.8/3.9: strict ALPN (fatal `no_application_protocol`) and SNI refusal are the standard's mitigations for cross-protocol attacks **[verified]** — [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html)
- **Renegotiation**: forbidden in TLS 1.3 (RFC 9846); in TLS 1.2 secure renegotiation indication and extended master secret are mandatory (RFC 9325 3.5); HTTP/2 forbids it **[verified for RFC 9846 and RFC 9325]** — [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html), [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html)
- OpenSSL 3.0 and later disable client-initiated renegotiation by default (re-enabled only with `SSL_OP_ALLOW_CLIENT_RENEGOTIATION`) **[from OpenSSL's change log as remembered, not re-fetched]** — [OpenSSL CHANGES](https://github.com/openssl/openssl/blob/master/CHANGES.md)
- **KeyUpdate abuse**: RFC 9846 "limits the number of permitted KeyUpdate messages" **[verified]** — [RFC 9846 section 1.2](https://www.rfc-editor.org/rfc/rfc9846.html)
- **Ticket key reuse / forward secrecy**: ticket-encryption keys MUST be rotated (for example weekly), old keys destroyed, ticket validity limited; TLS 1.3 resumption SHOULD use `psk_dhe_ke` so resumed sessions get a fresh key exchange **[verified]** — [RFC 9325 section 3.4](https://www.rfc-editor.org/rfc/rfc9325.html)
- **Compression side channels** (CRIME at the TLS layer): TLS-level compression SHOULD NOT be supported in TLS 1.2 and does not exist in TLS 1.3 **[verified]** — [RFC 9325 section 3.3](https://www.rfc-editor.org/rfc/rfc9325.html), [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html)
- **Raccoon** (2020; older than 2024, still holds): a timing side channel on the premaster secret of finite-field DH(E) in TLS 1.2 and earlier when the server reuses DH keys; TLS 1.3 is not affected **[from the attack's site as remembered, not re-fetched]** — [raccoon-attack.com](https://raccoon-attack.com/); the current guidance removes DHE altogether: RFC 9325 says TLS 1.2 SHOULD NOT negotiate DHE suites and TLSRef 5.8 "removed kDHE ciphers from Intermediate" **[verified]** — [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html), [docs.tlsref.org](https://docs.tlsref.org/server-side-tls.html)
- **KeyShare reuse**: RFC 9846 forbids reusing KeyShare values between connections **[verified]** — [RFC 9846 section 1.2](https://www.rfc-editor.org/rfc/rfc9846.html)
- **0-RTT replay**: "There are no guarantees of non-replay between connections"; applications must not use 0-RTT without a profile (RFC 8470 for HTTP) **[verified]** — [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html), [RFC 9325 section 3.10](https://www.rfc-editor.org/rfc/rfc9325.html)
- **AEAD key usage limits**: RFC 9325 4.4 recommends rekeying before 2^24.5 records with AES-GCM; RFC 9846 makes initiating a key update before the limit a MUST **[verified]** — [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html), [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html)
- **Large-ClientHello handling bugs**: servers that read the ClientHello with a single `read()` fail with post-quantum key shares (about 0.02 % of scanned origins reset fragmented ClientHellos) **[secondary]** — [PKIC 2025 talk](https://pkic.org/events/2025/pqc-conference-austin-us/THU_BREAKOUT_1100_Syed-Suleman-Ahmad_Lessons-Learned-from-Testing-Millions-of-Servers-for-PQ-Compatibility.pdf)
- **On-demand issuance abuse**: third parties trigger certificate requests by naming arbitrary hosts in handshakes; Let's Encrypt blocks patterns and may pause accounts **[verified]** — [Let's Encrypt community](https://community.letsencrypt.org/t/blocking-some-on-demand-issuance-caused-by-internet-scanning/245553)
- **Certificate chain size and amplification**: chains above about 10 kB cause a steep performance drop from the initial congestion window, and some clients and middleboxes reject them **[verified]** — [Cloudflare pq-2025](https://blog.cloudflare.com/pq-2025)

### Inferences

Expected mitigations, by where they live:

| Attack class | Status in 2026 | Mitigation a server ships | Class |
|---|---|---|---|
| Downgrade, POODLE, BEAST, Lucky13, SWEET32, RC4, FREAK, Logjam, DROWN, ROBOT | Closed by configuration | TLS 1.2+ only, ECDHE AEAD suites only, no static RSA, no export, no SSLv2/3 | REQUIRED defaults |
| Raccoon, small-subgroup and DH parameter issues | Closed by removal | No DHE suites at all | REQUIRED default |
| CRIME | Closed | TLS compression never enabled | REQUIRED |
| BREACH (HTTP compression of secrets beside attacker-controlled input) | Still open in principle | Not a TLS-layer fix; the server's response-compression design decides (no compression of answers to credentialed cross-site requests is the application's job; a server documents it) | EXPECTED to be documented |
| Renegotiation DoS and injection | Closed in TLS 1.3; TLS 1.2 by default-off client renegotiation | Keep client-initiated renegotiation off; never offer it on HTTP/2 | REQUIRED |
| KeyUpdate flood (TLS 1.3) | Addressed in RFC 9846 | Library limit; a server should treat excess as a protocol-budget violation | REQUIRED via library version |
| Handshake floods (cheap ClientHello, costly server signature) | Open | Handshake timeout, a ceiling on connections and on handshakes in progress, ECDSA certificates (cheaper signatures than RSA), per-source rate limits at the firewall, QUIC Retry under load | EXPECTED |
| Slow or stalled handshakes holding slots | Open | A deadline from accept to handshake completion, counted separately from request idle time | REQUIRED |
| Ticket key compromise breaking forward secrecy | Open if keys are static | Rotation (daily to weekly), keys in memory only, `psk_dhe_ke`; ticket lifetime no longer than the key's | EXPECTED |
| Session ticket sharing across virtual hosts (resumption confusion) | Open by misconfiguration | Bind tickets to the context of the site (session id context), never accept a ticket for a different certificate set | REQUIRED |
| ALPACA cross-protocol | Open where one certificate serves several protocols | Strict ALPN alert on no match, refusal of unknown SNI as an option, error budget per connection | REQUIRED (ALPN), EXPECTED (SNI option) |
| Opossum | Not applicable without opportunistic TLS | Never implement `Upgrade: TLS/1.0` (RFC 2817) on HTTP; nothing else to ship | Not applicable / DEPRECATED feature |
| 0-RTT replay | Open when enabled | Off by default; if ever on: single-use tickets or a strike register, `Early-Data` to the application, 425 handling, safe methods only | OPTIONAL feature, REQUIRED safeguards with it |
| Virtual-host confusion (SNI differs from Host) | Open | 421 when the request's authority is not served by the connection's certificate set and site | REQUIRED |
| ClientHello size assumptions | New with PQ | Reassembly across segments and Initial packets; no first-read parsing | REQUIRED |
| QUIC amplification with large certificate chains | Open | 3x limit before address validation, Retry under load, small ECDSA chain, certificate compression where the library has it | REQUIRED (limit), OPTIONAL (compression) |
| On-demand issuance abuse | Open for servers with on-demand TLS | Do not issue for names that are not configured sites | REQUIRED if the feature exists |

- The mitigations that require the server's own code rather than a library default are: handshake deadlines and ceilings, ticket key rotation and scoping, the 421 rule, strict ALPN selection in the ALPN callback, connection error budgets, QUIC address validation, and refusal to issue certificates for unconfigured names.
- Certificates with SHA-1 or RSA below 2048 bits are refused by current libraries at the default security level; a server only needs to say so clearly at load time.

### Gaps
- No 2025 or 2026 source on TLS handshake-flood mitigations in servers was retrieved; the handshake-flood rows above are inference from general practice.
- OpenSSL's default for client-initiated renegotiation and the Raccoon details were cited from memory of primary pages that were not re-opened.
- No new TLS-layer attack of 2026 was found by the searches run; that is absence of evidence from a limited search, not a survey of the year's CVEs. OpenSSL published a security advisory on 29 September 2026 (3.5.9, 4.0.3) whose content was not read.
- Whether testssl.sh or SSL Labs test for Opossum, KeyUpdate limits or multi-segment ClientHello handling in their 2026 versions is unknown.
