# HTTP/2 conformance audit: RFC 9113 and RFC 7541

Date: 2026-11-13. Tree: `bf67e7ac` (v0.1.0-alpha.145). Scope: agensio as an HTTP/2 server
endpoint (`src/http2/`, `src/http/`, `src/core/fields.hpp`, the hand-over in
`src/http1/connection.hpp`, the TLS context in `src/server.cpp`), and where a requirement
only shows once a request is forwarded, the proxy and FastCGI heads.

Method: the RFC texts in `docs/rfc/` read section by section, each requirement that binds
a server traced to its code path. This was a read-only audit: nothing was built or run,
no h2spec, no fuzzers, no live requests. Every row of Table 1 was confirmed by reading the
code path end to end; "confidence" says how sure the reading is and, separately, how sure
the effect on a real peer is. The h2spec result (146/146 over TLS, 145/146 plain) is the
design document's, not re-run here; h2spec does not cover most rows below.

## Summary

| RFC | Items examined | Met | Partly met | Not met | Not applicable | Could not determine | Optional (MAY), not implemented |
|---|---|---|---|---|---|---|---|
| RFC 9113 (HTTP/2), sections 3 to 10 | 109 | 78 | 16 | 6 | 4 | 3 | 2 |
| RFC 7541 (HPACK), all sections | 23 | 22 | 0 | 0 | 1 | 0 | 0 |

The HPACK codec itself (`http2/hpack.*`, `http/field_codec.*`) has no gap that I could
find: integer and string limits, index 0 and out-of-range indexes, size updates (ceiling,
position, several at the block's start), eviction, an entry larger than the table, a name
taken from an entry the insertion evicts, Huffman EOS and padding rules, never-indexed
literals for sensitive response fields, the encoder's own size updates. The one HPACK
problem is in the connection, which in one path ignores the decoder's result (row 5).

The frame layer is in good shape: frame sizes, padding, CONTINUATION sequencing, SETTINGS
validation and acknowledgement, window arithmetic on the sending side, overflow and zero
increments, GOAWAY's last-stream-id discipline, unknown frames and settings. The gaps
cluster in four places: what is done with pseudo-header values, the receive-side window
bookkeeping, how connections are ended (GOAWAY), and the edges of the stream state machine
after a reset.

Most important, in order:

1. Pseudo-header values (`:path`, `:authority`) are not validated and reach an origin's
   HTTP/1.1 request line and `Host` line verbatim (row 1). This is the request-smuggling
   class RFC 9113 10.3 warns about, and the design's threat table claims it closed.
2. The connection-level receive window is not given back for request bodies that arrived
   complete but were never read by a handler, and on four stream-error paths (row 2).
3. No GOAWAY before an idle close or at shutdown, and the graceful GOAWAY is one deferred
   frame instead of the two-step form (rows 3 and 4).
4. A header block for a refused stream is decoded with its result ignored (row 5).
5. Stream state edges: a body over the limit, frames in flight after the server's own
   reset, late WINDOW_UPDATE and RST_STREAM (rows 6 to 8).

## Table 1: not met or partly met

Classification: **conformance bug** (the RFC's MUST or SHOULD is not done and a peer can
see it), **hardening** (within the letter, or a MAY, but a risk), **optional**.

| # | RFC, section | Requirement (level) | What the code does today | What a peer observes | Confidence | Class |
|---|---|---|---|---|---|---|
| 1 | 9113 8.2.1 (MUST: no NUL, CR, LF in a field value; malformed otherwise), 10.3 (MUST validate before translating to another HTTP version; pseudo-header values need additional validation; "simple concatenation is not secure") | Field values, pseudo-header values included, are validated before a request is used or forwarded | `http::sink_field` returns for a pseudo-header before `fields::valid_value` runs (`src/http/request_assembly.hpp:41-50`; the value checks are lines 55-63, regular fields only). `finish_request` checks only that `:path` starts with `/` (line 108). `normalize_target` stops at `?` and never looks at the query (`src/path.cpp:19-27`, 34-41), and its path part accepts SP and bytes above 0x7f. The proxy writes `method SP target SP HTTP/1.1` from `req.target` as received (`src/handlers/proxy.cpp:108`, 236) and the `Host` line from the synthetic `host` field made of `:authority` (`request_assembly.hpp:123`, `proxy.cpp:159`, 180). `CertNames::covers` and `Router::site` cut the host at the last `:` (`src/core/host.hpp:21-24`, `src/core/router.cpp:40-43`), so text after a port is not looked at. `:method` is safe: an unknown token is 405 in every location (`src/handlers/dispatch.cpp:731`). | A client can send `:path: /app?x HTTP/1.1\r\nHost: h\r\n\r\nGET /other HTTP/1.1\r\n...` and the origin behind a proxy location receives two requests on a kept connection (request smuggling, then the next client's exchange on that connection reads the wrong answer). The same through `:authority` with CR LF after a port. FastCGI is length-prefixed, so php-fpm only sees odd bytes in `REQUEST_URI`. HTTP/3 uses the same assembly code. | High for the code path (read from the HPACK decoder to the proxy's head; no check found anywhere between). Not exercised. | Conformance bug, security |
| 2 | 9113 5.2, 6.9 (flow control: the receiver returns window as it consumes data; 6.9: every flow-controlled frame is accounted against the connection window "even if the frame is in error") | Bytes counted against the connection window come back to the peer once consumed or discarded | The decrement is always done (`src/http2/connection.hpp:963-964`), the return is not: (a) `close_stream` returns a stream's buffered bytes only `if (!s.body_done ...)` (line 728), so a body that arrived whole (END_STREAM seen) and was never read by the handler, a POST answered 405, 404, 401, 403 or by a redirect, is never returned; (b) DATA beyond the stream window returns nothing (lines 978-979, 1000-1001); (c) "more DATA than content-length" drops the current frame's bytes (1008-1009); (d) `end_of_body` sets `body_done` before its content-length error (1047-1050), so the buffered bytes are lost as in (a); (e) the over-limit path sets `body_done` with earlier frames still buffered (1016). | The connection's receive window shrinks for good by those bytes. After about 1 MB in total (`kConnectionWindow`) the client can send no DATA on that connection: uploads hang until `body_timeout` cancels them, until the connection reaches `max_requests_per_connection` or goes idle. Small on a browser connection; real on a long-lived connection from a CDN or proxy that multiplexes many users. | High for the code; medium for how often it bites (needs the body to arrive before the answer's write completes, which a small POST sent with its HEADERS does) | Conformance bug |
| 3 | 9113 6.8, 9.1 (SHOULD: "always send a GOAWAY frame before closing a connection") | GOAWAY before the server closes | The idle close calls `close()` directly (`connection.hpp:1310-1313`; `close()` at 209-233 writes nothing), as does the close after the client's own GOAWAY. `Server::stop` ends every worker's loop with no HTTP/2 frame (`src/server.cpp:2300-2315`; `docs/ROADMAP.md` E4 already records the shutdown half). Design 6.8 says GOAWAY "at shutdown". | At `idle_timeout` (15 s) and at every restart the TCP connection just ends. A client whose request crossed the close cannot tell whether it was processed, so it may not retry a POST; with a GOAWAY naming the last stream it could. Streams in flight at a restart are cut. | High | Conformance bug (SHOULD) |
| 4 | 9113 6.8 (SHOULD: graceful shutdown sends a first GOAWAY with last stream 2^31-1 and NO_ERROR, then a second with the real id) | The client is told at once that no new streams will be taken | `leave_after_streams` (`connection.hpp:1189-1194`, called at `max_requests_per_connection` and when the listener left the configuration, 704-706) only sets `going_away_`; the one GOAWAY goes out in `maybe_finish` when no stream is active (1219-1233). Until then every new stream is answered `RST_STREAM(REFUSED_STREAM)` (671-674). | While any stream stays open (an event stream, a long download) the client keeps opening streams on the connection and each is refused; it is never told to move. DATA frames sent for the refused streams each cost a glitch point (row 7), and at 100 the connection is closed with `ENHANCE_YOUR_CALM`, cutting the streams that were to finish. | High for the code; medium for the effect (depends on how a client retries REFUSED_STREAM) | Conformance bug (SHOULD) |
| 5 | 9113 4.3 (MUST: a decoding error is a connection error COMPRESSION_ERROR; every field block is processed to keep the compression state) and 6.8 (HEADERS after GOAWAY "MUST be minimally processed") | The decoder's result is acted on for every block | For a request block whose stream was refused (over `max_concurrent_streams`, or going away) the block is decoded and the result thrown away (`connection.hpp:621-626`). `malformed` goes unanswered; `too_large` means the decoder stopped mid-block, so later insertions of that block are missing from the table. The other two paths (`begin_request` 759-764, trailers and discard 633-635) do act on it. | Nothing at once. After a `too_large` block the server's dynamic table differs from the client's encoder: later requests on the connection decode to wrong fields or fail with COMPRESSION_ERROR. Needs a refused stream and a block over the limits together. | High | Conformance bug |
| 6 | 9113 5.1 (a stream becomes half-closed (remote) only by a received END_STREAM), 8.1.1 (an early complete response may be followed by `RST_STREAM(NO_ERROR)`) | State follows the frames; an early answer ends the upload without an error | A body of unknown length that passes `max_body_size` gets the 413 queued and the stream is then marked `half_closed_remote` by the server itself (`connection.hpp:1010-1021`). The next DATA frame is "DATA after END_STREAM": `RST_STREAM(STREAM_CLOSED)` (966-975), and if the 413 was still queued (two DATA frames in one read) it is dequeued and never sent. Once the 413 is written the stream is closed and every further DATA frame gets `RST_STREAM(STREAM_CLOSED)` and a glitch point. The known-length path is right (`fail_stream` then `on_stream_written`, 137-155: drain or `NO_ERROR`). | The client sees the 413 followed by `RST_STREAM(STREAM_CLOSED)`, or only the reset. RFC 8.1.1 obliges clients to keep the response only when the code is NO_ERROR, so some will report a stream error instead of the 413. | High for the code; medium for the outcome (timing decides which of the two) | Conformance bug |
| 7 | 9113 5.1 closed (MUST: after sending RST_STREAM on an open or half-closed (local) stream "minimally process and then discard any frames"), 5.4.2 (SHOULD NOT send more than one RST_STREAM per stream) | Frames the peer had in flight when the server reset a stream are discarded | DATA: the connection window is accounted and returned, then a second `RST_STREAM(STREAM_CLOSED)` and a glitch point for every frame (`connection.hpp:968-972`); the ring of recently closed ids is not consulted for DATA. HEADERS (the request's trailers still in flight): the stream is no longer in the table, so "stream id lower than one already used", a connection error PROTOCOL_ERROR (572-575). | After the server ends an upload early (`RST_STREAM(NO_ERROR)`, lines 151, 994) each DATA frame already on the wire draws another RST_STREAM and a point; a 1 MB window is 64 frames, the soft limit 75. A client whose trailers cross the reset loses the whole connection. | High for the code; medium for the effect | Conformance bug (HEADERS case), hardening (DATA case) |
| 8 | 9113 5.1 closed, 6.9 (WINDOW_UPDATE on a closed stream: "MUST NOT treat this as an error"; RST_STREAM likewise for a short period) | Late WINDOW_UPDATE and RST_STREAM for a stream the server has finished are ignored | Ignored without cost only for the last 8 closed stream ids (`kRecentClosed`, `connection.hpp:56`, 660-666); older ones cost a glitch point (502-503, 528). Points never expire; 75 send `GOAWAY(ENHANCE_YOUR_CALM)`, 100 close (1236-1243). The window is a count of streams, not a time: a cycle that finishes twenty answers pushes twelve of them out of the ring at once. | No frame in reply, but a busy connection whose client cancels requests or acknowledges data just after the answers completed collects points and is told to go away after 75. | High for the code; low to medium for how often real clients reach 75 | Hardening |
| 9 | 9110 10.1.1 (MUST: on `Expect: 100-continue` send a final status or an immediate 100; "MUST NOT wait for the content"), mapped by 9113 8.1 (interim responses as HEADERS frames) | A 100-continue expectation is answered | Only the HTTP/1 parser knows the field (`src/http1/parser.cpp:179-181`, `src/core/request.hpp:48` "HTTP/1.1 only"). Over HTTP/2 it is an ordinary field; the writer never emits a 1xx HEADERS frame (`src/http2/writer.hpp:632-672`), the proxy drops the field (`proxy.cpp:134`). An unknown expectation gets no 417 either (a MAY). | A client that waits for the 100 before sending DATA waits out its own timer (about a second in the common libraries), then sends. curl does not send the field over HTTP/2; some other stacks do. | High | Conformance bug, small |
| 10 | 9113 8.1 (MUST: pseudo-header fields in trailers make the request malformed), 8.2.1 | Trailers are validated | The trailers block is decoded with a sink that accepts everything (`connection.hpp:630-648`): no pseudo-header, name or value rule runs. Design 6.4 says "validated, and dropped". Trailers are never handed to a handler, so nothing invalid is forwarded. | A request with `:path` in its trailers is served instead of reset. | High | Conformance bug, harmless today |
| 11 | 9113 5.1 idle (MUST: any frame but HEADERS or PRIORITY on an idle stream is a connection error PROTOCOL_ERROR), 6.4 (RST_STREAM on an idle stream) | Idle streams are told from closed ones | "Idle" is tested as `id > last_stream_id_` only (`connection.hpp:969`, 497, 527). An even id below the highest client id is idle (the server never opens streams) but is treated as closed: DATA draws `RST_STREAM(STREAM_CLOSED)`, RST_STREAM and WINDOW_UPDATE a glitch point. HEADERS on an even id is a connection error, as required (573). | A stream error or nothing where the RFC asks for a connection error. Only a broken or hostile client sends such frames. | High | Conformance bug, minor |
| 12 | 9113 6.5, 5.1.2 (limits are what the endpoint advertised) | The server enforces what it announced | SETTINGS are sent once, at the start (`connection.hpp:101-109`). After a reload a connection enforces the new generation's `http2.max_concurrent_streams` and `max_header_size` (`refresh_generation` 935-948; used at 675, 683, 607, 755) without a new SETTINGS frame. | Only after a reload that lowers one of the two: a client within the announced limit gets REFUSED_STREAM with glitch and reset points, or `ENHANCE_YOUR_CALM` for a header list the old value allowed. Ends with the connection (idle 15 s, 1,000 requests). | High | Hardening |
| 13 | 9113 8.2.1 (SHOULD: a request that violates the field rules gets a 400) | 400 for an invalid field | Every malformed request is `RST_STREAM(PROTOCOL_ERROR)` with no response (`connection.hpp:771`), which 8.1.1 requires and allows; the 400 is not sent. The access log records 400 (`unsent_status`, 1146). | A reset instead of a 400 page. | High | Optional (SHOULD) |
| 14 | 9113 6.3 (MUST: a PRIORITY frame whose length is not 5 is a stream error FRAME_SIZE_ERROR) | Stream error | Connection error FRAME_SIZE_ERROR (`connection.hpp:402`). | GOAWAY where a RST_STREAM is asked for. | High | Conformance bug, minor |
| 15 | 9113 5.3.2, 6.3 (PRIORITY "can be sent on a stream in any state"; the fields are kept so implementations "remain interoperable with implementations that use the priority signaling described in RFC 7540") | PRIORITY frames are tolerated | Accepted and ignored, but each is a glitch point (`connection.hpp:417`), from the same lifetime budget as row 8. The server announces `SETTINGS_NO_RFC7540_PRIORITIES = 1` (line 107), which newer clients take as "stop sending them". | A client that still signals RFC 7540 priorities and sends more than 75 PRIORITY frames on one connection is sent `GOAWAY(ENHANCE_YOUR_CALM)`; at 100 the connection closes. | High for the code; low for whether a current browser gets there | Hardening |
| 16 | 9113 8.3 (MUST: the same pseudo-header twice makes the request malformed) | Duplicates detected | A duplicate is detected by the slot being non-empty (`request_assembly.hpp:46`; `:authority` also by its bit). `:method`, `:scheme` or `:path` sent first with an empty value and then again is accepted. | A malformed request is served. No known use. | High | Conformance bug, minor |
| 17 | 9113 8.1.1 (a request is malformed when Content-Length does not equal the DATA total), 9110 8.6 | Every Content-Length value agrees with the body | The loop keeps the last `content-length` field (`request_assembly.hpp:130-147`); two fields with different values pass when the DATA matches the last. The proxy drops the field and writes its own (`src/upstream/http_head.hpp:73-78`, `src/upstream/http_client.cpp:15-21`), FastCGI's `CONTENT_LENGTH` is the real count, so nothing wrong is forwarded as framing. | A request that should be reset is served; PHP sees `HTTP_CONTENT_LENGTH` as "5, 10". | High | Conformance bug, minor |
| 18 | 9113 8.3.1 (SHOULD: malformed when Host and `:authority` name different entities; "values need to be normalized to compare them") | Compared after normalisation | Byte comparison (`request_assembly.hpp:110`): `Example.com` against `example.com`, or a default port on one side, is "differ". | A reset for a request the RFC accepts. Clients that send both normally send them identical. | High | Hardening (stricter than asked) |
| 19 | 9113 8.2.2 (MUST NOT generate connection-specific fields; an intermediary "MUST remove" them as in 9110 7.6.1), 8.2.1 (no 0x7f-0xff in a field name) | Responses carry no connection-specific field and only valid names | The fixed names are dropped (`src/handlers/upstream_common.cpp:273-275`, `writer.hpp:621-626`). Fields an origin's own `Connection` field nominates are not (the request side does this, `proxy.cpp:134-136`; the response side has no such test). The upstream head parser accepts bytes above 0x7f in a field name (`src/upstream/http_head.hpp:58-62`), which then go into the HPACK block. | Only behind an origin that sends `Connection: x-something` or non-ASCII field names: the client receives a field it should not, or a name it may reject as malformed. | Medium (the response path was read in `upstream_common.cpp` and the writer, not every handler) | Conformance bug, minor |
| 20 | 9113 9.2.1 (MUST disable renegotiation; MUST treat one as a connection error PROTOCOL_ERROR) | Renegotiation refused and treated as an error | Refused by OpenSSL 3's default, held by a test (`tests/integration.sh:716`; `docs/security-audit-2026-10-07.md` 2.6). `SSL_OP_NO_RENEGOTIATION` is not set (`src/server.cpp:664-682`) and the attempt is not turned into a GOAWAY. | A TLS 1.2 client that tries gets a `no_renegotiation` alert and the connection goes on. | Medium (OpenSSL's behaviour taken from the audit note and the test, not re-run) | Hardening |
| 21 | 9113 9.2.2 (SHOULD NOT use the Appendix A cipher suites with HTTP/2 over TLS 1.2; MAY answer INADEQUATE_SECURITY) | No prohibited suite with `h2` | No cipher list, no server preference, no check after the handshake (`src/server.cpp:664-682`; `src/http1/connection.hpp:150-157` looks at ALPN only). With OpenSSL's default list a TLS 1.2 client that offers only CBC or static-RSA suites together with `h2` gets HTTP/2 on one. `INADEQUATE_SECURITY` is defined and never sent. | Browsers offer AEAD suites first, so this needs an unusual client; a strict client may itself close with INADEQUATE_SECURITY. | Medium (OpenSSL's default list not inspected on the target systems) | Hardening |
| 22 | 9113 3.4 (the connection preface and the frames after it are processed) | The h2c hand-over keeps what was read | `Http2Connection` copies the bytes HTTP/1 had read only when they fit its 16,393-byte buffer and otherwise drops all of them silently (`connection.hpp:83-86`). HTTP/1's buffer is `max_header_size` (`src/http1/connection.hpp:72`). | Only with `h2c` on and `max_header_size` above 16,393: a client whose first read carried more than that (preface, SETTINGS and many requests) loses them; the server then answers PROTOCOL_ERROR to the next bytes or waits for a preface until the idle timeout. | High for the code; the configuration is unusual | Conformance bug, edge |
| 23 | Design 8.1 threat table, row "Slow read ... data dribble" (not an RFC requirement; RFC 9113 10.5) | "no DATA frame smaller than 1 KB unless it ends the body" | No such floor in the writer: a frame is `min(data, quantum, frame size, stream window, connection window)` (`writer.hpp:510-515`, 432-436), so a window of 1 gives a 1-byte frame. What bounds the dribble is that every WINDOW_UPDATE below 1 KB is a glitch point (`connection.hpp:490`, 518) and that such an update does not restart the stream's idle clock (517). | A client can draw up to about 100 tiny DATA frames per connection before the budget closes it. | High | Hardening (the document claims more than the code does) |

### Design document statements the code does not match

Found while checking the threat table and section 6; not RFC gaps, listed so the document
and the code can be brought together.

- 6.4 "trailers are accepted ..., validated, and dropped": not validated (row 10).
- 6.8 "GOAWAY ... at shutdown": not for HTTP/2 (row 3).
- 6.3 "a frame for a closed stream within the last few ids is tolerated": true for
  RST_STREAM and WINDOW_UPDATE, not for DATA (row 7).
- 6.9 "a WINDOW_UPDATE below 1 KB while more than 1 KB is pending" is a glitch: the code
  counts every stream or connection WINDOW_UPDATE below 1,024 whatever is pending
  (`connection.hpp:490`, 518), so a client that acknowledges each small DATA frame as it
  arrives loses a point per frame.
- 6.9 "an empty HEADERS" is a glitch: an empty HEADERS frame without END_HEADERS is not
  counted by itself (`on_headers`, 539-594); the block is still bounded by eight
  CONTINUATION frames and the header deadline.
- 8.1 "none reaches php-fpm or an origin" (smuggling row): see row 1.
- 8.1 "we never use the peer's table for encoding": superseded by 6.2.1 (the encoder has
  a 1 KB dynamic table); the row was not updated.
- 8.1 CONTINUATION row, "the buffer is the 16 KB receive buffer, not a growing string":
  the block is a `std::string` grown to at most `max_header_size`
  (`connection.hpp:606-613`); bounded, but not as described.

## Table 2: optional features and extensions not implemented

| Feature | What it is for | Defined by | Note |
|---|---|---|---|
| Server push (PUSH_PROMISE) | The server sends responses the client did not ask for | RFC 9113 8.4 | Never sent; a client's PUSH_PROMISE is a connection error as required. Removed from Chrome and nginx. |
| Extensible priorities: the `priority` field and the PRIORITY_UPDATE frame | Urgency and incremental delivery chosen by the client | RFC 9218 | Known ("Not yet"). The frame is ignored as unknown, the field is passed on unread; the writer is round robin. `SETTINGS_NO_RFC7540_PRIORITIES = 1` is announced all the same. |
| RFC 7540 priority tree | Dependency and weight scheduling | RFC 7540 5.3, deprecated by RFC 9113 5.3.2 | Not built by decision; see row 15 for how the frames are counted. |
| CONNECT | Tunnels through the server | RFC 9113 8.5 | Known. A CONNECT request without `:scheme` and `:path` is reset as malformed (`request_assembly.hpp:107`) where a 405 or 501 would be the HTTP answer. |
| Extended CONNECT (`:protocol`, `SETTINGS_ENABLE_CONNECT_PROTOCOL`) | WebSockets over an HTTP/2 stream | RFC 8441 | Known. The setting is not sent, so browsers open WebSockets on a separate HTTP/1.1 connection, which works. |
| HTTP/2 to origins (h2, h2c, gRPC) | Multiplexed upstream connections, gRPC backends | RFC 9113 as a client | Known. The proxy speaks HTTP/1.1 to origins. |
| Request trailers delivered to the application; response trailers | gRPC status, checksums after a body | RFC 9113 8.1, RFC 9110 6.5 | Request trailers are decoded and dropped; no response path can send a trailers HEADERS frame. Needed for gRPC together with the previous row. |
| Interim responses: 100 (Continue), 103 (Early Hints), passing an origin's 1xx on | Early hints for preloading; the 100-continue handshake | RFC 9113 8.1, RFC 9110 15.2, RFC 8297 | No 1xx is ever sent over HTTP/2; the proxy skips an origin's 1xx. Row 9 is the part that is a requirement. |
| ORIGIN frame | Tells the client which other origins the connection may be used for | RFC 8336 | Not sent. Coalescing is bounded by the certificate and answered with 421 where it does not hold (`src/handlers/dispatch.cpp:577-580`, 598). |
| ALTSVC frame | Alternative services at the frame level | RFC 7838 | Not sent; the `alt-svc` response field does the job for HTTP/3. |
| `Upgrade: h2c` from HTTP/1.1 | Starting HTTP/2 on a plain connection without prior knowledge | RFC 7540 3.2, removed by RFC 9113 | Not built by decision; prior knowledge (`h2c` in `protocols`) is. |
| Padding of DATA and HEADERS frames sent | Hiding the size of responses | RFC 9113 6.1, 6.2, 10.7 | Never used; padding received is validated and its window returned at once. |
| SETTINGS_TIMEOUT | Closing when the peer never acknowledges SETTINGS | RFC 9113 6.5.3 (MAY) | The acknowledgement is recorded (`settings_acked_`) and not used. |
| INADEQUATE_SECURITY | Refusing HTTP/2 on a weak TLS 1.2 handshake | RFC 9113 9.2 (MAY) | Never sent; see row 21. |
| PING from the server | Liveness and round-trip measurement, the "other signals" of 5.1 | RFC 9113 6.7 | The server only answers PINGs. |
| New SETTINGS during a connection | Changing limits on a live connection, a reload's values among them | RFC 9113 6.5 | One SETTINGS frame per connection; see row 12. |
| The client's `SETTINGS_MAX_HEADER_LIST_SIZE` | Not sending a response head the client said it will refuse | RFC 9113 6.5.2 (advisory) | Stored (`src/http2/settings.hpp:34`), never consulted. |
| TLS-ALPN-01, per-connection client certificates, secondary certificates | Outside HTTP/2 proper | RFC 8737 and others | Not built ("Not yet" lists TLS-ALPN-01). |

## Table 3: could not determine

| Item | What I looked at | Why it stays open |
|---|---|---|
| 9113 9.2.1 key-exchange sizes (ECDHE at least 224 bits, DHE at least 2048) and 9.2.2 "MUST support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 with P-256" | `src/server.cpp:664-682`: no groups, no DH parameters, no cipher list set | All of it is OpenSSL's defaults and the distribution's security level; right in practice on OpenSSL 3, but nothing in the tree states or tests it. |
| 9113 10.6 (no compression of secret and attacker-controlled data under one dictionary) for response bodies | HPACK side only: sensitive response fields are never indexed (`hpack.cpp` `Encoder::policy`) | `response_compression` (the content codings) was outside this audit. |
| What clients do with the reset after a 413 (row 6) and with repeated RST_STREAM (row 7) | The server side only | Needs a run with curl, a browser and an nghttp2 client. |
| Whether a current browser sends enough PRIORITY frames, small WINDOW_UPDATEs or late frames on closed streams to reach 75 glitch points (rows 8, 15) | The counters and their thresholds | Needs captures of real sessions; RFC 9218 (not in `docs/rfc/`) says clients stop RFC 7540 signals after the setting, from memory. |
| Field names and values in prebuilt HPACK blocks (cache entries, error pages, redirects) | `writer.hpp` `build_head`, which appends `prebuilt_h2` as it is | `cache.cpp` and `response.cpp`, where the blocks are built, were not read; the fuzzer is said to decode every block. |
| No content on 204, 304 and HEAD answers, and Content-Length agreeing with the DATA sent, for every handler | The writer: END_STREAM on HEADERS for `head` or no body (`writer.hpp:401-406`), a sized source checked against its length (540-563) | The handlers that fill the Response were not read; `fuzz_h2_conn` is said to check this for the static handler. |
| The h2spec and fuzzer results the design quotes | `tests/integration.sh:3310-3318` runs h2spec on both listeners | Nothing was run. |
| TLS with ALPN offered but no protocol in common | `select_protocol` returns NOACK and the handshake goes on as HTTP/1.1 (`src/server.cpp:521-526`) | RFC 7301 3.2 asks for a fatal `no_application_protocol` alert; that RFC is not in scope and not in `docs/rfc/`. Noted, not judged. |

## Stricter or better than the RFC asks

- One misbehaviour budget and one reset budget per connection, with resets the server was
  provoked into counted like the client's own (`stream_error`, `count_reset`): Rapid
  Reset and MadeYouReset meet the same counter. The RFC only says "SHOULD track".
- A header block is bounded three ways before a stream exists: compressed bytes, eight
  CONTINUATION frames, and the decoded list size counted field by field while decoding,
  cookie crumbs included; the deadline for an unfinished block holds with no stream open.
- Every frame-size error is a connection error, checked before a byte of the frame is
  buffered; the receive buffer is exactly one frame.
- Field rules beyond the minimum: names must be tokens (the RFC's minimum only excludes
  ranges), a second `host` field is malformed, a request with neither `:authority` nor
  `host` is malformed, `te` must be exactly `trailers`, and the rules run once per
  dynamic-table entry without weakening them.
- GOAWAY discipline: the last stream id never rises across frames, an error GOAWAY is
  followed by a half-close and a one-second linger so that it arrives, and every GOAWAY
  and RST_STREAM sent is a log line.
- Sending: a response head larger than the client's SETTINGS_MAX_FRAME_SIZE is split into
  HEADERS and CONTINUATION; the encoder announces its table size, sends the floor and
  then the current size when the limit dipped, never indexes `set-cookie`,
  `www-authenticate` and the authorization fields, and keeps its table at
  min(peer, 1 KB).
- Padding received is returned to both windows at once; a body nobody reads is drained
  up to 64 KB after the answer and then ended with `RST_STREAM(NO_ERROR)`, as 8.1.1
  suggests (the known-length case).
- HPACK: the Huffman automaton is generated from the RFC's table and rejects EOS,
  padding of eight bits or more and padding that is not all ones; integers stop at 32
  bits and five continuation bytes; a size update after the first field is an error.

Three places where "stricter" can cost a well-behaved client, to weigh when the budgets
are reviewed: every WINDOW_UPDATE below 1 KB and every PRIORITY frame is a point (rows 15
and 23, and the list above Table 2); a decoded header list over `max_header_size` is a
connection error `ENHANCE_YOUR_CALM` rather than a 431 on the stream (allowed by 10.5.1,
but a browser with large cookies loses the connection on every request where HTTP/1.1
gets a 431 page); and glitch points never expire over a connection's life.
