# The protocol specifications, as text

The RFCs the protocol layers implement, fetched from https://www.rfc-editor.org/rfc/ as
plain text so that a section number in a comment, a design document or a commit message
can be read here without a browser. Cite them by number and section (`RFC 9000 8.1`).
Keep this list in step with the code: a new protocol feature adds its RFC here first.

| File | Title | Implemented by |
|---|---|---|
| `rfc7617.txt` | The 'Basic' HTTP Authentication Scheme | `[[site.auth]]` (`docs/configuration.md` 19b): the credentials' syntax and the UTF-8 `charset` (2, 2.1, 3) in `src/core/auth.*` (`parse_basic`), the challenge in `src/handlers/dispatch.cpp` (`auth_challenge`); the reuse of credentials below a challenged path (2.2) is why `agensio-auth` counts the error log's failures and not 401s (`docs/fail2ban.md` 2c) |
| `rfc9111.txt` | HTTP Caching | what a password-protected answer may say to caches (3.5: a shared cache may reuse a response to a request with `Authorization` only when it says `public`, `s-maxage` or `must-revalidate`; 5.2.2.7: `private`): `src/core/private_cache.hpp`, used by `handlers/upstream_common.cpp` and `handlers/static.cpp`; what a response-header rule may change in an application's answer (`docs/headers.md` 2.4): its `no-store`, `private` and `no-cache` (5.2.2.5, 5.2.2.7, 5.2.2.4) stand over a rule's value that drops them and over a rule's `Expires` (5.3), and an answer with `Set-Cookie`, which does not stop a cache (7.3), or a `Vary` naming `Cookie` or `*` (4.1) gets no shared lifetime from a rule, nor is left without `Cache-Control` (heuristic freshness, 4.2.2): `src/core/private_cache.hpp` (`restrictions`, `covers`, `shared_lifetime`) and `src/core/response_fields.hpp` |
| `rfc6797.txt` | HTTP Strict Transport Security | the site key `hsts` (`parse_hsts` in `src/config.cpp`, the managed field in `src/control/sites.cpp`): the field sent over HTTPS only (7.2, 8.1), its value written once at load (`SiteConfig::tls_fields`) with `max-age` (6.1.1, `0` to make browsers forget the host) and `includeSubDomains` (6.1.2), the lifetime the administrator writes and never a default (11.2), the certificate findings raised to errors while it holds (12.1: no recourse for the user); health's `hsts_suggested`, `hsts_from_application` and `hsts_narrows_application` (`src/control/commands.cpp`; which value is stronger, by 6.1, in `hsts_stronger`, `src/core/site_fields.hpp`); `docs/redirects.md` 4 |
| `rfc8246.txt` | HTTP Immutable Responses | `immutable` (2, 3): `rules.cache`'s `immutable: true` on a managed site (`src/control/sites.cpp`, refused without a lifetime, the one time it holds), and the recipes for fingerprinted assets (`docs/headers.md` 3.5) |
| `rfc5861.txt` | HTTP Cache-Control Extensions for Stale Content | `stale-while-revalidate` and `stale-if-error` (3, 4), which let a cache serve a stored answer past its lifetime, so `shared_lifetime` counts them: `src/core/private_cache.hpp` |
| `rfc9213.txt` | Targeted HTTP Cache Control | `CDN-Cache-Control` and its vendor forms, which a CDN follows over `Cache-Control` and `Expires` (2.2): dropped from a password-protected answer, `src/core/private_cache.hpp`; each CDN reads the first field of its own list (2.2), so an application's restriction in any of them holds for every CDN field a response-header rule adds (`src/core/response_fields.hpp`, `settle`) |
| `rfc9110.txt` | HTTP Semantics | every protocol layer: methods, status codes, fields, conditionals, ranges (`src/core/`, `src/handlers/`) |
| `rfc9112.txt` | HTTP/1.1 | `src/http1/` (parser, connection, chunked coding) |
| `rfc9113.txt` | HTTP/2 | `src/http2/` (`docs/design-http2.md`) |
| `rfc7541.txt` | HPACK: Header Compression for HTTP/2 | `src/http2/hpack.*`, the Huffman and integer codec shared with QPACK (`src/http/field_codec.*`) |
| `rfc8999.txt` | Version-Independent Properties of QUIC | `src/quic/packet.hpp` (the invariants every version keeps) |
| `rfc9000.txt` | QUIC: A UDP-Based Multiplexed and Secure Transport | `src/quic/` (`docs/design-http3.md` section 6); the stateless answers of 8.1.2 and 10.3 in `src/quic/stateless.hpp`, connection ids (5.1) and migration (9) in `src/quic/connection.hpp` |
| `rfc9001.txt` | Using TLS to Secure QUIC | `src/quic/crypto.*`, `src/quic/tls.*` |
| `rfc9002.txt` | QUIC Loss Detection and Congestion Control | `src/quic/recovery.*`, `src/quic/ack.hpp` |
| `rfc9114.txt` | HTTP/3 | `src/http3/` (`docs/design-http3.md` section 7) |
| `rfc9204.txt` | QPACK: Field Compression for HTTP/3 | `src/http3/qpack.*` |
| `rfc9438.txt` | CUBIC for Fast and Long-Distance Networks | `src/quic/recovery.*` (phase I3) |
| `rfc8899.txt` | Packetization Layer Path MTU Discovery for Datagram Transports | `src/quic/connection.*` (the MTU probe, phase I1b) |
