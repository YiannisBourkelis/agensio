# Audit: HTTP semantics and HTTP/1.x conformance of agensio

Date: 2026-11-13. Tree: `main` at `bf67e7ac` (0.1.0-alpha.145). Read-only audit of the source
against the RFC texts in `docs/rfc/`: nothing was built, run or changed. Every row of Table 1
was confirmed by reading the code path named in it; where the effect on the wire depends on
something that was not executed (kernel behaviour, an origin's reaction), the confidence says so.

Roles. agensio is an **origin server** (static files, FastCGI/PHP, CGI) and a **gateway**
("reverse proxy", RFC 9110 3.7) to HTTP/1.1 origins, plus a tunnel after a 101. RFC 9110 3.7
makes a gateway an origin server towards the client and a user agent towards the origin, so
requirements written for "a proxy" (forward proxy) do not bind it; requirements written for
"an intermediary", "a gateway", "a sender" or "a recipient" do. Rows say which role is bound.

Out of scope here: HTTP/2 and HTTP/3 framing (`src/http2`, `src/http3`, `src/quic`), the
control socket's API, the benchmark handler (`handlers/httparena.*`).

## 1. Summary

Requirements examined (distinct normative statements that bind a server or an intermediary,
grouped as the RFC states them; counts are approximate because some statements repeat across
sections):

| RFC | Examined | Met | Partly met | Not met | Not applicable |
|---|---|---|---|---|---|
| RFC 9112 (HTTP/1.1) | 69 | 52 | 9 | 4 | 4 |
| RFC 9110 (semantics, sections 2 to 18) | 96 | 71 | 6 | 11 | 8 |
| RFC 9111 (caching: origin and non-caching gateway only) | 11 | 11 | 0 | 0 | 0 |
| RFC 7617 (Basic) | 4 | 4 | 0 | 0 | 0 |
| RFC 6797 (HSTS) | 4 | 4 | 0 | 0 | 0 |
| RFC 8246 (immutable), RFC 5861 (stale content) | 2 | 1 | 0 | 0 | 1 |

Not applicable means: CONNECT and forward-proxy rules, 407, rules for caches, rules for a
"proxy" that a gateway is exempt from (persistent connections to HTTP/1.0 clients, 100-continue
relaying, 1xx relaying). Table 1 has 27 rows for the 30 statements counted as partly met or not
met, because a few rows cover two statements (rows 3, 5, 12, 20).

The picture in one paragraph: request parsing, message framing, smuggling defences, connection
management, HEAD, 1xx/204/304 framing, Expect, Range (single), If-None-Match, content codings and
Vary, 421, HSTS and Basic are in good order, several of them stricter than the RFC asks. The
gaps cluster in four places: (1) the conditional requests an origin server MUST evaluate and
does not (`If-Match`, `If-Unmodified-Since`); (2) the absolute-form request target, which a
server MUST accept and agensio answers with 400; (3) the gateway duties nginx also skips but the
RFC states as MUST (`Via`, `Max-Forwards`, `Connection`-nominated fields in responses); (4) two
defects found on the way that are worth a test each: an interim 1xx from an origin on a
location with `buffering = false`, and the decoded path sent un-encoded to an origin when the
upstream has a URI part.

## 2. Table 1: not met or partly met

Level is the RFC's keyword. Class: **bug** = conformance bug worth fixing for 1.0;
**hardening** = safe today, but a robustness or security margin is missing; **optional** =
a deviation that is defensible to keep (say so in the documentation).

### 2.1 Origin server and request parsing

| # | RFC, section | Requirement (level) | Role | What the code does today | What a client observes | Confidence | Class |
|---|---|---|---|---|---|---|---|
| 1 | 9110 13.1.1, 13.2.1, 13.2.2 step 1 | An origin server MUST evaluate `If-Match` before performing the method; false is 412 | origin | Never read. The parser extracts only `If-None-Match`, `If-Modified-Since`, `If-Range` (`src/http1/parser.cpp:185-187`); `StaticHandler::not_modified` knows only those two (`src/handlers/static.cpp:70-91`). No `if-match` anywhere in `src/` outside the HPACK table. | `GET` with `Range` and `If-Match: "old"` on a file that changed gets 206 of the new file (a resumed download is spliced from two versions) where 412 is required. `If-Match: *` on a missing file is 404 either way (correct). | high | bug |
| 2 | 9110 13.1.4, 13.2.2 step 2 | An origin server MUST evaluate `If-Unmodified-Since` when no `If-Match` is present; false is 412 | origin | Never read (same places as row 1). | Same as row 1 for clients that resume with `If-Unmodified-Since` instead of `If-Range`. | high | bug |
| 3 | 9112 3.2.2 | A server MUST accept the absolute-form request target; an origin server MUST then ignore `Host` and use the target's host | origin, gateway | `normalize_target` returns false unless the target starts with `/` (`src/path.cpp:33`); `Dispatcher::route` answers 400 (`src/handlers/dispatch.cpp:609-612`). The parser passes the target through (`src/http1/parser.cpp:108-110`). | `GET http://example.com/ HTTP/1.1` is 400 and close. nginx and httpd serve it. Sent by some HTTP libraries behind a forward proxy setting, and by conformance suites. | high | bug |
| 4 | 9112 3 | A request target longer than the server parses MUST get 414 | origin | One limit for the whole head: when the receive buffer (`max_header_size`, 16 KB) fills without a complete head the answer is 431 (`src/http1/connection.hpp:509-514`), whether the request line or the fields filled it. 414 has no canned page (`src/response.cpp:63`). | A 20 KB URL gets `431 Request Header Fields Too Large` instead of `414 URI Too Long`. | high | bug (small) |
| 5 | 9110 9.1; 9112 3 | An unrecognised or unimplemented method SHOULD get 501 (405 is for a known method the resource does not allow); a method longer than any implemented SHOULD get 501 | origin | Every token that is not one of the nine methods is `Method::other` and answered 405 with `Allow`, by design (`src/handlers/dispatch.cpp:727-765`, comment at 745); so are TRACE and CONNECT ("in no set", line 730). `CONNECT host:443` fails `normalize_target` first and is 400. | `PROPFIND /` is `405` + `Allow: GET, HEAD, OPTIONS` where the RFC recommends 501. Harmless to clients; see also Table 2 row 1 (such methods cannot reach an application either). | high | optional |
| 6 | 9110 6.2 (also 2.5) | A message with a higher minor version than implemented SHOULD be processed as the highest implemented minor version | origin | Only `HTTP/1.0` and `HTTP/1.1` parse; `HTTP/1.2` to `HTTP/1.9` return `version_not_supported` and are answered 505 (`src/http1/parser.cpp:114-117`, `src/http1/connection.hpp:652-655`). | `GET / HTTP/1.2` is 505. No such client exists today. | high | optional |
| 7 | 9112 3.2 | 400 for a `Host` with an invalid field value (MUST) | origin | Missing Host on 1.1 and a second Host line are 400 (`dispatch.cpp:590-593`, `parser.cpp:149`). The value is checked against a short list of bytes only: control and space, `/`, `\`, `"`, `<`, `>` (`parser.cpp:151-153`). `user@host`, `a,b`, `host:abc`, `host?x`, `host#x`, `[::1` (unclosed) pass. | On a listener without a catch-all such a name matches no site and is 421. With a catch-all site it is served, and the raw value reaches PHP (`HTTP_HOST`, `SERVER_NAME` for a `*` site, `src/handlers/fastcgi.cpp:132`), a proxied origin (`Host`, `X-Forwarded-Host`) and the `Location` of the HTTPS redirect (`dispatch.cpp:503-522`, never cacheable for such a name). | high | hardening |
| 8 | 9110 5.3 | Repeated field lines of one name are one comma-separated list | origin, gateway | The parser keeps the **last** line of `Connection`, `Accept-Encoding`, `If-None-Match`, `Range` (`parser.cpp:145, 158, 185, 190`); the proxy reads the **first** `Connection` line for the fields it nominates (`src/handlers/proxy.cpp:109`). Fields handed to PHP and origins are joined or forwarded in order correctly (`fastcgi.cpp:63-85`, `proxy.cpp:133-174`). | `Connection: close` followed by a second `Connection: x` line keeps the connection open (9112 9.6: MUST close). An `Accept-Encoding` split over two lines is judged by the second only. Clients do not send these. | high | hardening |
| 9 | 9112 6.3 rule 4 | A request whose `Transfer-Encoding` does not end in `chunked`: MUST answer 400 and close | origin | Any value other than a lone `chunked` is 501 and close (`parser.cpp:193-201`, `connection.hpp:659-661`). For `gzip, chunked` 501 is what 6.1 recommends; for `gzip` alone or `chunked, gzip` the RFC says 400. | 501 instead of 400; the connection is closed either way, so there is no framing risk. | high | optional |
| 10 | 9110 14.2 | A server MUST ignore `Range` on a method for which range handling is not defined; GET is the only one | origin | `apply_range` has no method test (`src/handlers/static.cpp:96-104`); a HEAD with `Range` gets the 206 head. The integration suite asserts it (`tests/integration.sh:3642`). | `HEAD` + `Range: bytes=0-9` answers `206` with `Content-Range` and `Content-Length: 10`; the RFC wants the 200 head. Harmless: it is what the GET would answer. | high | optional |
| 11 | 9110 8.8.2.1 | An origin server MUST NOT send a `Last-Modified` later than `Date`; a future mtime MUST be replaced by the origination date | origin | `Last-Modified` is the file's mtime as it is (`static.cpp:207-209`, `385-387`); `file_settled` treats an mtime more than a second ahead as settled and cacheable (`src/handlers/static.hpp:36-39`). | A file with a future mtime (clock skew on an upload host, an archive's timestamps) is served with `Last-Modified` in the future; caches then compute odd heuristic lifetimes. | high (code), effect small | bug (small) |
| 12 | 9110 13.1.3; 5.6.7 | `If-Modified-Since`: condition is false (304) when the file's date is earlier **or equal**; a recipient that parses a timestamp MUST accept all three HTTP-date formats | origin | No HTTP-date parser exists (`src/http_date.hpp` only formats). `If-Modified-Since` and a date in `If-Range` are compared as strings with the `Last-Modified` text (`static.cpp:89`, `src/http1/range.hpp:74`). | Correct whenever the client echoes `Last-Modified` (every browser and cache). A later date, or the same instant in RFC 850 or asctime form, gets 200 with the body instead of 304: wasteful, never wrong. nginx's default (`if_modified_since exact`) is the same. | high | optional |
| 13 | 9110 15.3.7 | A 206 answering a request with `If-Range` SHOULD NOT carry representation fields beyond those required | origin | The 206 block always has `Content-Type`, `Last-Modified`, `ETag`, `Accept-Ranges` (`static.cpp:113-132`). | A few redundant fields. Every server sends them. | high | optional |
| 14 | 9110 5.6.3; 9112 7.1.1 | Bad whitespace (BWS) before `;` of a chunk extension MUST be parsed and removed | origin, gateway (decoding) | After the hex digits only `;` or CR is accepted (`src/http1/chunked.hpp:66-74`); `5 ;ext` is a framing error. | 400 and close for a chunked body written that way (client), 502 (origin). Rejecting is the safer reading: whitespace here is a known parser-discrepancy vector. Listed for completeness. | high | optional (keep) |
| 15 | 9112 9.6 | Not a keyword: "servers typically close a connection in stages" (half-close, read until the client closes) because an immediate close with unread data risks a TCP reset that destroys the last response | origin | `close()` does `shutdown(both)` then `close()` at once (`connection.hpp:240-265`). Error answers that leave request bytes unread go straight there: 400/431/501/417 (`fail_request`, 1062-1072, drops the buffer and closes after the write), 413 up front while the client may still be uploading (674-682), a final answer to a client that was waiting for 100 (929). | A client still sending a large body when the 413 goes out can receive RST before it reads the answer, and reports a broken connection instead of "too large". No lingering close exists (`grep -i linger src/` finds nothing). | medium (kernel behaviour not observed here) | hardening |

### 2.2 Gateway (reverse proxy) and tunnel

| # | RFC, section | Requirement (level) | Role | What the code does today | What an origin or client observes | Confidence | Class |
|---|---|---|---|---|---|---|---|
| 16 | 9110 15.2; 9112 6.3 | An interim 1xx from the origin is not the final response | gateway | Buffered answers (the default) skip a 1xx correctly (`src/upstream/http_client.cpp:68-71`). With `buffering = false`, `UpstreamRequest::feed_head` delivers the head to the handler as soon as it parses (`src/upstream/client.cpp:918-922`), **before** `HttpRequest::on_head_complete` sees that it is interim (`http_client.cpp:122`). `apply_upstream_result` then builds a response with status 1xx and no body (`src/handlers/upstream_common.cpp:186, 374-377`), the dropped `Source` ends the exchange (`client.cpp:480-483`, `reader_gone` 579-582, `bodiless_` is only HEAD/204/304 at 600), and the later real head finds `head_delivered_` set (`client.cpp:1010-1012`). | As traced: an origin that sends `103 Early Hints` (Puma with early hints, Node) or `102`, on a location that streams, has its 103 written to the client as agensio's whole answer; the exchange is cancelled; an HTTP/1.1 client keeps waiting for the final response until the idle timeout. No test covers an interim response from an origin. Needs a test before it is called a bug. | medium (read end to end, not run) | bug |
| 17 | 9112 3.2; 9110 7.7 | The request target sent to the origin has no whitespace and keeps the client's path and query | gateway | With a URI part on the upstream (`upstream = "http://host:port/base/"`, `src/config.cpp:624-633`) and a raw target that does not literally begin with the location's path (`//app/x`, `/x/../app/y`, `/%61pp/z`), the forwarded target is built from `ws.path`, the percent-**decoded** normalised path, with no re-encoding (`src/handlers/proxy.cpp:238-249`). | `GET //app/a%20b` goes to the origin as `GET /base/a b HTTP/1.1`: a malformed request line; `%3F` or `%23` in such a path become a real `?` or `#`, `%25xx` a second decoding. CR and LF cannot appear (`path.cpp:58`), so no field injection, but the origin sees a different resource than the access and refuse rules judged. Without a URI part the raw target is forwarded untouched (correct). | medium (not run) | bug |
| 18 | 9110 7.6.3 | An HTTP-to-HTTP gateway MUST send `Via` in each inbound request (MAY in responses) | gateway | Never generated (no `Via` in `src/`). A client's `Via` is forwarded unchanged. | The origin cannot see agensio in the chain; loop detection by `Via` is impossible. A common deviation: nginx never adds it, and Apache's `ProxyVia` is off by default. | high | bug (small) or documented deviation |
| 19 | 9110 7.6.2 | An intermediary that forwards OPTIONS or TRACE with `Max-Forwards` MUST check and decrement it, and answer itself at 0 | gateway | Not read (`max-forwards` appears only in the HPACK table). OPTIONS on a proxy or FastCGI location is forwarded as it came; TRACE is 405 everywhere. | `OPTIONS /api` with `Max-Forwards: 0` reaches the origin. Diagnostic use only. | high | optional |
| 20 | 9110 7.6.1 | An intermediary MUST remove the fields named in a received `Connection` field, and SHOULD remove `Proxy-Connection`, `Keep-Alive`, `TE`, `Transfer-Encoding`, `Upgrade`, before forwarding | gateway | Request direction: done (`proxy.cpp:134-136`, `src/upstream/http_head.hpp:73-78`). Response direction: `apply_upstream_result` drops `Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Server`, `Date` only (`upstream_common.cpp:268-275`); the fields the origin's `Connection` names, `Proxy-Connection`, `Trailer` (while trailers are discarded) and `Upgrade` on a non-101 answer go to the client. | An origin's hop-by-hop extension field (rare) leaks to the client; a `Trailer` field announces trailers that never arrive; `Upgrade: h2c` from an origin reaches the client without its `Connection: Upgrade`. | high | hardening |
| 21 | 9112 6.3 rule 5 | A response with an invalid `Content-Length` (or several differing ones) is an unrecoverable error: close the origin connection, answer 502 | gateway | The first `Content-Length` is parsed with `from_chars`; a non-number is 502 (`http_client.cpp:96-106`). A second line with another value is not compared (`Headers::get` returns the first), and an empty value falls through to close-delimited framing (`!cl.empty()`). | The client is safe (agensio re-frames every answer). The risk is on the kept origin connection: two differing lengths desynchronise it for the next request that reuses it. Requires a broken or hostile origin. | high (code), medium (effect) | hardening |
| 22 | 9112 6.1 | The gateway sends no `TE`, so an origin may apply only `chunked`; a coding the recipient cannot decode must not be passed on unlabelled | gateway | `Transfer-Encoding` ending in `chunked` is de-chunked whatever precedes it (`gzip, chunked`), anything else is read to the close (`http_client.cpp:84-95`); the field is then dropped (`upstream_common.cpp:273`), so the still-gzipped bytes reach the client with no coding named. | Only with an origin that violates 7.4 (uses a coding nobody asked for). A 502 would be the clean answer. | medium | hardening |
| 23 | 9112 6.1 | An HTTP/1.0 message with `Transfer-Encoding` MUST be treated as faulty framing and the connection closed after it | gateway | Enforced on requests (`parser.cpp:194`, 400). On an origin's HTTP/1.0 response the coding is decoded as on 1.1 and the connection is kept if the origin said `Connection: keep-alive` (`http_client.cpp:57, 66-67, 84-90`). | None with a real origin; a hardening margin on kept origin connections. | medium | hardening |
| 24 | 9112 3.2 (client side, by 9110 3.7) | Every HTTP/1.1 request sent MUST carry `Host` | gateway | With `proxy.host = "pass"` (the default) an HTTP/1.0 request that had no `Host` is forwarded as HTTP/1.1 without one (`proxy.cpp:158-161, 177-181`: the fallback line needs `req.host`, which is empty then). | The origin answers 400 to such a client. Only HTTP/1.0 clients without Host reach this (old monitors, `nc` checks) and only on proxied sites that are the listener's catch-all. | high (code) | bug (small) |
| 25 | 9110 7.8 | A server MUST ignore `Upgrade` in an HTTP/1.0 request (and 15.2: no 1xx to an HTTP/1.0 client) | gateway, tunnel | `ProxyHandler::build_head` decides to upgrade from `policy.upgrade`, the `Upgrade` field, no body and `Connection: upgrade`; the version is not looked at (`proxy.cpp:112-115`). | An HTTP/1.0 request with those fields is forwarded as an upgrade and the origin's 101 is relayed. No WebSocket client speaks 1.0. | high (code) | bug (small) |
| 26 | 9112 5.1 | Whitespace between a field name and the colon in a **response**: a proxy MUST remove it before forwarding | gateway | The response-head parser refuses such a line and the exchange fails with 502 (`http_head.hpp:58-62`). Obs-fold in a response is 502 too, which 5.2 allows. | 502 for an origin that writes `Name : value`. Stricter than asked; listed because the keyword is MUST. | high | optional (keep) |

### 2.3 Found on the way

| # | RFC, section | Requirement (level) | Role | What the code does today | What a client observes | Confidence | Class |
|---|---|---|---|---|---|---|---|
| 27 | 9110 15.5 | A 4xx answer SHOULD carry a representation that explains the error | origin | 416 has no canned page: `kPageCodes` (`src/response.cpp:63`) lacks it, `error_page` falls back to the 500 page (`response.cpp:99-104`), and `apply_range` answers through it (`src/handlers/static.cpp:107`). The suite checks the status and `Content-Range` only (`tests/integration.sh:3636`). | `416 Range Not Satisfiable` with the correct `Content-Range: bytes */N`, and a body that reads "500 Internal Server Error". 416 is the only status agensio generates itself without its own page. | high (code) | bug (cosmetic) |

Rows 16 and 17 are the two I would test first; rows 1 to 3 are the conformance items a
checker (h1spec-style suites, REDbot) will flag first.

## 3. Table 2: optional features not implemented

MAY-level behaviour and whole optional mechanisms. "Pass-through" means an application behind
FastCGI or the proxy can still use it; agensio itself does not.

| # | Feature (RFC, section) | What it is for | Today |
|---|---|---|---|
| 1 | Extension methods to applications (9110 9.1, 16.1) | WebDAV/CalDAV (`PROPFIND`, `REPORT`, `MKCOL`, `MOVE`, `LOCK`), `PURGE`, `QUERY`: needed by Nextcloud, SabreDAV, Radicale, Subversion | Not possible: an application location takes GET, HEAD, OPTIONS, POST, PUT, DELETE, PATCH only (`kFcgiMethods`, `src/config.hpp:142-143`) and `methods = [...]` accepts only those (`src/config.cpp:841-858`). Anything else is 405 before the handler. The largest functional gap of this audit; the roadmap's Nextcloud row already names it. |
| 2 | TRACE (9110 9.3.8) | loop-back diagnostics | 405. Most servers disable it. |
| 3 | CONNECT, forward proxying, authority-form (9110 9.3.6; 9112 3.2.3) | tunnels through a forward proxy | Not a forward proxy; CONNECT is 400. |
| 4 | Multiple ranges, `multipart/byteranges` (9110 14.6) | several slices in one response (PDF readers, some video clients) | A list of ranges is ignored and the whole file sent with 200 (`src/http1/range.hpp:31`), which 14.2 allows. |
| 5 | Range on generated answers | slices of a buffered PHP or proxied answer | Pass-through only: the application's own 206 is forwarded; agensio does not slice. |
| 6 | Proactive negotiation on `Accept`, `Accept-Language`, `Accept-Charset`; 406; 300; `Content-Location`, `Content-Language` (9110 12.5.1, 12.5.2, 12.5.4) | one URL, several representations (Apache MultiViews) | Not implemented; only `Accept-Encoding` is negotiated (twins, copies, `response_compression`). The fields pass to applications. |
| 7 | Request content codings, 415 with `Accept-Encoding` (9110 8.4, 12.5.3) | gzip-compressed uploads decoded by the server | Not decoded; `Content-Encoding` on a request passes to the application. |
| 8 | Transfer codings other than `chunked`; `TE` negotiation (9112 7.2, 7.4) | compression at the transfer layer | Not implemented; such a request coding is 501. |
| 9 | Trailer fields: generating them, `TE: trailers`, forwarding them either way (9110 6.5; 9112 7.1.2) | checksums or status after a streamed body (gRPC-style) | Request trailers and an origin's trailers are read, bounded and discarded (`src/http1/chunked.hpp:115-132`), which the RFC allows. |
| 10 | Relaying 1xx from an origin, `103 Early Hints` (9110 15.2; RFC 8297) | preload hints before the final answer | Dropped on buffered answers; see Table 1 row 16 for streamed ones. (MUST for a "proxy", optional for a gateway.) |
| 11 | Relaying `Expect: 100-continue` to the origin (9110 10.1.1) | let the origin refuse a large upload before it is sent | `Expect` is not forwarded (`proxy.cpp:134`); agensio answers 100 itself when the body is first read, i.e. as the origin server it is to the client. |
| 12 | `408 Request Timeout` (9110 15.5.9), `411 Length Required` (15.5.12) | tell a slow or length-less client why | A head that does not arrive within `idle_timeout` is closed without an answer; a body that stalls is closed and logged as 408; a request without length has no body (correct per 9112 6.3). |
| 13 | `Keep-Alive` response field with `timeout`/`max` (9112 appendix C.2.2) | tell clients the idle limit | Not sent; only `Connection: keep-alive` to HTTP/1.0 clients. |
| 14 | Upgrade to other protocols by the server itself: `h2c` by `Upgrade` (obsolete), TLS by RFC 2817; `426` | protocol switch on one connection | Not implemented (h2c by prior knowledge only). `Upgrade` is relayed to origins for WebSocket. |
| 15 | Authentication beyond Basic: Digest (RFC 7616), `Authentication-Info`, proxy authentication (407, `Proxy-Authenticate`) (9110 11.6, 11.7) | stronger schemes; authenticating to a proxy | Basic only; the proxy fields pass through untouched. |
| 16 | An HTTP cache in the gateway (RFC 9111 whole; RFC 5861) | store and reuse origin answers, `Age`, serve stale | Not a cache: no `Age` is generated, nothing stored, cache directives pass through. |
| 17 | Weak comparison helpers for unsafe methods on static resources: PUT, DELETE, partial PUT (9110 9.3.4, 9.3.5, 14.5) | writing files over HTTP | The static handler is read-only (GET, HEAD, OPTIONS). |
| 18 | `203 Non-Authoritative Information` on transformed answers (9110 15.3.4) | flag that the gateway changed the content | Not used; compression is marked by `Content-Encoding`, `Vary` and a weakened ETag instead. |
| 19 | `Via` in responses, `Server` of the origin kept | show the chain to clients | The origin's `Server` and `Date` are replaced by agensio's (`upstream_common.cpp:273-275`), as nginx does. No keyword forbids it for a gateway. |
| 20 | Parallel processing of pipelined safe requests (9112 9.3.2) | throughput on pipelined connections | Sequential, in order. |
| 21 | Media types `message/http`, `application/http` (9112 10) | messages as content | Not used. |

## 4. Table 3: could not determine

| # | Question | What I looked at | Why it stays open |
|---|---|---|---|
| 1 | Whether the immediate close of Table 1 row 15 actually costs clients the 413/400 | `Http1Connection::close`, `fail_request`, the 413 branch | Depends on timing and the kernel (RST on close with unread data); needs a run with a slow uploader. |
| 2 | The exact failure a client sees in Table 1 row 16 | `feed_head`, `deliver_head`, `Source::~Source`, `reader_gone`, `apply_upstream_result`, the HTTP/1 writer | Traced by reading only. A fixture origin that writes `103` then `200` on a `buffering = false` location settles it. HTTP/2 and HTTP/3 clients go through the same exchange code and were not traced. |
| 3 | TLS closure rules (9112 9.8: close_notify sent, a truncated close not taken for a complete message) | call sites only (`socket_.shutdown_notify()` in `close()`); `src/tls_stream.hpp` was not read line by line | Outside the files this audit covered in depth. Request bodies are length- or chunk-delimited, so a truncated close cannot end one silently. |
| 4 | Whether a date in `If-Range` is always a strong validator in the sense of 9110 8.8.2.2 | `if_range_matches`, `file_settled` | Cached files are at least a second old when cached; a file streamed uncached within its first seconds is served `no-store` but still honours a date `If-Range`. Edge of an edge. |
| 5 | Correctness of the `Cache-Control` directive parsing used by the password guard and the response-header rules (quoted-string arguments, RFC 9111 5.2) | call sites in `upstream_common.cpp`, not `src/core/private_cache.hpp` and `response_fields.hpp` in full | Skimmed only; counted as met on the strength of their unit tests' existence, not verified here. |
| 6 | CGI and FastCGI specifics that touch HTTP semantics (local `Location` redirects of RFC 3875 6.2.2, a `Status:` below 200, NPH scripts) | `parse_cgi_head` (`src/upstream/fcgi.hpp:196-237`), `handlers/fastcgi.cpp`, the first half of `handlers/cgi.cpp` | RFC 3875 is not in the repository and was not the subject; a `Location` with a local path is sent to the client as a 302, not re-dispatched. |
| 7 | How the same semantics hold over HTTP/2 and HTTP/3 (Range, conditionals, Expect, the field rules of `http/request_assembly.hpp`) | not examined | Out of scope; the dispatcher and handlers are shared, so Table 1 rows 1, 2, 10 to 13 and 16 to 22 apply there too in all likelihood. |
| 8 | What an invalid `Host` (row 7) becomes in every consumer | parser, `normalize_host`, the redirect writers, FastCGI params | The log formats, `X-Forwarded-Host` consumers and `$host` expansion in `proxy.request_headers` were not each traced. |

## 5. HTTP/1.0 interoperability (the rules 9110 and 9112 state themselves)

| Rule | Verdict | Where |
|---|---|---|
| Response version is the server's own (`HTTP/1.1`) whatever the request's minor version | met | `src/response.cpp:54` |
| No chunked coding to an HTTP/1.0 client: close-delimited body, connection closed | met | `src/http1/writer.hpp:151-154` |
| No `Transfer-Encoding` accepted from HTTP/1.0 (400, close) | met | `parser.cpp:194` |
| No 100 Continue to HTTP/1.0; `Expect` ignored there | met | `parser.cpp:179` |
| Persistence only with `Connection: keep-alive`, echoed in the response | met | `parser.cpp:212`, `writer.hpp:157, 199` |
| Request without `Host` accepted on 1.0, routed to the listener's default site | met | `dispatch.cpp:590-598`; the HTTPS redirect uses the site's first name (`dispatch.cpp:503`) |
| A 1.0 request forwarded to an origin goes out as HTTP/1.1 with the gateway's own framing | met, except `Host` | Table 1 row 24 |
| `Upgrade` in a 1.0 request ignored | not met | Table 1 row 25 |
| "A proxy server MUST NOT maintain a persistent connection with an HTTP/1.0 client" (9112 9.3) | not applicable | binds forward proxies; agensio keeps such a connection only when the client asked, as an origin server may |

## 6. Stricter or better than the RFC requires (notable only)

- `Content-Length` together with `Transfer-Encoding` is 400 and close; the RFC would let the
  server process it by the transfer coding (`parser.cpp:209`). A second `Transfer-Encoding`
  line, a `Content-Length` list or more than 19 digits are refused too.
- Chunked framing takes CRLF only, sizes of at most 16 hex digits, bounded extensions (4 KB a
  line) and trailers (8 KB), and never reads past the body's last byte, so a pipelined request
  is safe (`src/http1/chunked.hpp`). Bare LF and obs-fold are refused in requests, in chunked
  framing and in an origin's response head.
- Fields with `_` in the name never reach PHP or an origin (`fastcgi.cpp:66`,
  `proxy.cpp:142`), closing the `Client_IP` / `HTTP_CLIENT_IP` confusion; `Proxy` is dropped
  for CGI (httpoxy).
- A streamed answer is held to the length it declared: never more bytes, and a short one
  closes the connection so the client sees the truncation (`writer.hpp:349-386`).
- 421 for a `Host` the TLS connection's certificate does not cover, on HTTP/1.1 as well
  (9110 7.4), with `no-store`.
- `100 Continue` only when the client is really waiting (nothing of the body arrived with the
  head), and `Connection: close` on a final answer given without it (`connection.hpp:278-294,
  929`).
- Retries towards an origin only for GET and HEAD without a body, only on a reused connection,
  only before any response byte (`client.cpp:516, 862-863`): narrower than "idempotent".
- Validators: a distinct strong ETag per coded representation (twin, made copy), a weakened
  ETag and merged `Vary` when agensio compresses an application's answer, `no-transform`
  honoured from the request and the response (`handlers/compress_answer.hpp:196`), a file
  still being written served `no-store` and not cached, so the mtime-and-size ETag is not
  reused across two writes in one second.
- A password-protected answer is never left storable by a shared cache (RFC 9111 3.5), and
  HSTS is sent on secure transport only and replaces an application's copy (RFC 6797 7.2).
- Encoded path separators (`%2F`, `%5C`) are 404 on every handler that resolves a path on disk;
  dot segments are resolved before any rule or location is chosen.
- The status line always has the space before an empty reason phrase (9112 4), and every
  code 100 to 599 an application may answer has a line.

## 7. Suggested order for the 1.0 scope

1. Test and fix rows 16 (interim response while streaming) and 17 (decoded path to the origin).
2. Conformance items a public checker will report: rows 1, 2 (`If-Match`,
   `If-Unmodified-Since`: one function beside `not_modified`), 3 (absolute-form: strip
   `scheme://authority`, take the authority as the host), 4 (414), 11 (future `Last-Modified`),
   27 (the 416 page).
3. Gateway hygiene in one change: rows 20, 21, 24, 25, and a decision on `Via` (row 18).
4. Decide and document the deviations kept on purpose: rows 5, 6, 9, 10, 12, 13, 14, 26.
5. Extension methods to applications (Table 2 row 1) if Nextcloud or any DAV application is
   in the 1.0 application matrix; lingering close (row 15) with it, since DAV clients upload.
