# QUIC and HTTP/3 conformance audit: RFC 9000, 9001, 9002, 9114, 9204 (8999, 8899, 9438)

Date: 2026-11-13. Tree: `bf67e7ac` (v0.1.0-alpha.145). Scope: agensio as a QUIC server
endpoint and an HTTP/3 server: `src/quic/`, `src/http3/`, `src/http/request_assembly.hpp`,
`src/http/stream_pool.hpp`, `src/core/fields.hpp`, the accept path and ALPN callback in
`src/server.cpp`, and, where a requirement only shows once a request is forwarded, the
proxy head and the upstream client.

Method: `docs/rfc/README.md`, `docs/design-http3.md` and the HTTP/3 part of `CLAUDE.md` first,
then the sources read in full (`connection.hpp`, `recovery.hpp`, `udp.hpp`, `frames.hpp`,
`packet.hpp`, `crypto.*`, `tls.*`, `transport_params.hpp`, `stream.hpp`, `stateless.hpp`,
`range_set.hpp`, `http3/connection.hpp`, `qpack.*`, `frame.hpp`, `http3/stream.hpp`), each
requirement that binds a server traced to its code path, the RFC wording checked in
`docs/rfc/`. This was a read-only audit: nothing was built or run, no interop runner, no
fuzzers, no live connection. Every row of Table 1 was confirmed by reading the code path;
"confidence" says how sure the reading is, and where the effect on a real peer is less sure
than the reading the row says so. Line numbers are of this tree.

## Summary

Counts are of the requirements I traced, grouped the way the RFC states them (one MUST or
SHOULD, or one tight group of them, per count). They are approximate: a tally kept while
reading, not a generated checklist.

| RFC | Examined | Met | Partly met | Not met | Not applicable (client-only, or a feature not offered) | Could not determine |
|---|---|---|---|---|---|---|
| 9000 transport | 107 | 70 | 13 | 11 | 12 | 1 |
| 9001 TLS | 35 | 23 | 1 | 2 | 5 | 4 |
| 9002 recovery | 32 | 22 | 4 | 3 | 3 | 0 |
| 9114 HTTP/3 | 58 | 36 | 4 | 10 | 8 | 0 |
| 9204 QPACK | 32 | 25 | 1 | 3 | 3 | 0 |
| 8999 invariants | 5 | 4 | 0 | 1 | 0 | 0 |
| 8899 DPLPMTUD | 6 | 3 | 1 | 1 | 1 | 0 |
| 9438 CUBIC | 0 | | | | CUBIC is not implemented (NewReno only), Table 2 | |

What stands out, in order of weight:

1. Five findings are about what a hostile client can make the server do, and I would look at
   them before anything else: CRYPTO data after the handshake is buffered without bound (row 1),
   an oversized HEADERS frame is buffered without bound after its 431 (row 5), `content-length`
   is not held to the DATA bytes over HTTP/3, which with `request_buffering = false` reaches an
   origin as a mis-framed HTTP/1.1 request (row 3), pseudo-header values are not validated (row
   4, the same finding as row 1 of `audit_http2.md`), and a connection in the closing state
   answers small datagrams with CONNECTION_CLOSE packets outside the 3x limit (row 6).
2. Congestion control is NewReno without pacing, without a burst limit worth the name, and
   without the application-limited rule (rows 9 to 11). The design document describes a pacer
   and packet-number skipping that the code does not have.
3. A group of small MUST-level misses in frame and packet handling that no well-behaved client
   triggers (rows 12 to 27, 38 to 48): they matter for a conformance claim, not for users.
4. Known and listed, not rediscovered: 0-RTT, ECN, NEW_TOKEN, active migration and
   preferred address, QUIC v2, the amplification row of the attack suite (Table 2).

Not reached, or reached only in part:

- `src/http/field_codec.*` (Huffman and prefix integers, shared with HPACK) was not read; the
  QPACK rows assume it is right, as the HTTP/2 suites and `fuzz_qpack` hold it (Table 3).
- `src/quic/send_blocks.hpp` and `src/quic/timer_heap.hpp` were read for interfaces only.
- The tests (`tests/h3-attacks.py`, `tests/quic-lossy.py`, the fuzzers, `bench/quic-interop/`)
  were listed, not audited: I did not check which rows of Table 1 a test already covers.
- RFC 9000 sections 2.3 (prioritisation), 13.4 (ECN) and 21.5 (request forgery) only to the
  point of establishing that the feature is not offered; RFC 9002 appendix A was compared
  with the code function by function but not line by line; RFC 9114 section 4.6 and 7.2.5
  (push) only as "never sent".
- Everything that OpenSSL decides inside the handshake (Table 3).
- HTTP semantics (RFC 9110) beyond what RFC 9114 itself requires: see `audit_http1_semantics.md`.

## Table 1. Not met or partly met

Classification: **bug** = conformance bug (the RFC says otherwise and a peer can observe it),
**hardening** = a security consideration or a robustness rule, **optional** = a SHOULD or
RECOMMENDED whose absence costs little.

| # | RFC, section | Requirement (level) | What the code does today | What a peer observes | Confidence | Class |
|---|---|---|---|---|---|---|
| 1 | 9001 6 (MUST: a TLS KeyUpdate message is a connection error 0x010a); 9000 7.5 (CRYPTO buffering is bounded) | Post-handshake CRYPTO data is processed by TLS or refused | Once the handshake is done `TlsSession::advance` returns at once (`quic/tls.cpp:72-74`) and never calls OpenSSL again, but `on_crypto` still accepts CRYPTO frames in 1-RTT packets and appends every in-order byte to the level's input string (`quic/connection.hpp:871-900`, `quic/tls.cpp:66-69`). The 16 KB limit of line 875 is relative to the bytes already delivered, so it never trips for in-order data, and nothing consumes or frees the string (also after `free_ssl`) | A KeyUpdate (or any bytes) in CRYPTO frames is silently swallowed instead of closing with 0x010a. A client that keeps sending in-order CRYPTO frames grows the connection's memory at its send rate for as long as it likes: CRYPTO is not flow-controlled and the packets keep the idle timer alive | High (read end to end; not run) | bug + hardening |
| 2 | 9001 4.1.3 (MUST: data on a previous encryption level beyond what was received is PROTOCOL_VIOLATION) | New CRYPTO data at an old level is an error | Same path: Initial-level CRYPTO bytes after the ClientHello was consumed are appended to `in_[initial]`; OpenSSL only reads the current level (`tls.cpp:113-121`), so they stay there until the Initial keys are dropped or the handshake deadline | No error; memory grows for up to `idle_timeout` per half-open connection | High | bug |
| 3 | 9114 4.1.2 (MUST: a request whose Content-Length differs from the sum of DATA lengths is malformed; MUST NOT forward it; stream error H3_MESSAGE_ERROR) | Content-Length is held to the DATA bytes | The DATA path counts `body_received` against the body limit only (`http3/connection.hpp:374-398`), and the end of the stream delivers the end without a comparison (`:424-434`). HTTP/2 has both checks (`http2/connection.hpp:984-987`, `:1048`). The only length check is "declared, non-zero, and no body at all" (`:470`) | A request with `content-length: 10` and 5 or 20 bytes of DATA is served. Buffered (the default) the origin gets the real size. With `request_buffering = false` the proxy writes `Content-Length: <declared>` and then whatever the stream delivers (`handlers/proxy.cpp:268-275`, `upstream/http_client.cpp:15-20`, `upstream/client.cpp:784-803`): surplus bytes are read by the origin as the next request on a kept connection, missing bytes leave it waiting | High for the missing check; medium for the effect at an origin (not run) | bug (smuggling class with streamed bodies) |
| 4 | 9114 10.3, 4.1.2 (MUST: a message with a character not permitted in a field value is malformed; MUST NOT forward) | Pseudo-header values are validated before they become an HTTP/1.1 request line | `sink_field` returns for a pseudo-header before the value rules run (`http/request_assembly.hpp:41-50`); `normalize_target` checks control characters only before the `?` (`path.cpp:40-43`); the proxy writes the raw target into the request line (`handlers/proxy.cpp:108`). `:method` is saved by the 405 for unknown methods, `:authority` on TLS by the certificate-name check | CR, LF, NUL or a space in the query of `:path` reaches the origin's request line verbatim. Shared with HTTP/2: see row 1 of `audit_http2.md` | High for the missing check (same reading as the HTTP/2 audit); not run | bug (smuggling class) |
| 5 | 9114 10.5.1, 4.2.2 (a server bounds the field section it buffers) | A HEADERS frame over the limit is not buffered | A first HEADERS frame longer than `max_header_size` is answered 431 with the parser left inside that frame (`http3/connection.hpp:341-346`); every later byte of the frame is appended to `s.section` and credited back to the client (`:361-366`), up to the declared length, which is a 62-bit number. The stream stays open for receiving after the answer | The 431 arrives; the client can then keep sending the "frame" and the server stores all of it. Bounded only by the client's bandwidth (16 KB a round trip per stream, 128 streams, 1 MB a round trip per connection) | High (read end to end; not run) | hardening |
| 6 | 9000 8.1 (MUST NOT send more than three times the bytes received before the address is validated) | The limit holds in every state | In the closing state every third datagram routed to the connection sets `close_due_` (`quic/connection.hpp:282-285`) and `send_close` sends without consulting the limit or counting `bytes_sent_` (`:1632-1679`); an Initial-level close is padded to 1,200 bytes (`:1668-1672`). The endpoint routes any datagram of 9 bytes or more by its first 8 id bytes (`quic/udp.hpp:560`, `:616-626`) | A spoofed Initial that fails in TLS (one 1,200-byte datagram) puts the connection in closing for three PTOs (about 3 s); 9-byte datagrams with that id then draw a 1,200-byte packet per three, to the spoofed address | High for the code path; the factor is my arithmetic | bug + hardening (the design's missing `amplification` test row would have met it) |
| 7 | 9000 21.11, 10.3.2 (MUST NOT generate a stateless reset for an id that could be active on an endpoint sharing the key) | A reset is never produced for a live connection | (a) `add_cid` overwrites a table entry (`quic/udp.hpp:462`, called from `server.cpp:936`), and the lookup key is the first 8 bytes: an Initial whose client-chosen destination id is longer than 8 bytes and starts with a live connection's id passes the `owns` test as "unknown" (`udp.hpp:570-575`), gets a connection, and takes the entry; the victim's next short-header packet fails `owns` and is answered with a valid reset (`:619-622`). (b) Where the reuseport program is not attached, a packet that the kernel's hash hands to another worker after a NAT rebinding gets a valid reset instead of the forwarding design 6.1 describes; no forwarding exists | (a) An observer who has seen a connection's server id (it is in clear in every short header) can have the server reset that connection. (b) Without steering, a rebinding ends the connection | Medium (read; (a) needs the id, so on-path only) | hardening |
| 8 | 9000 12.3 (MUST discard a packet unless certain its number was not processed; a floor below which all are dropped) | Duplicate suppression has a floor | Received numbers are a range set cut to the 33 highest ranges (`quic/recovery.hpp:168-169`); a duplicate is "contained in a range" (`quic/connection.hpp:358`). A number below the lowest kept range is treated as new | After 34 gaps in the client's packet numbers over a connection's life (34 lost client packets), a replayed copy of an old packet is opened and its frames processed again. Stream data is idempotent; resets, credit frames and the budgets are counted again | High | bug |
| 9 | 9002 7.7 (MUST either pace or limit bursts; SHOULD limit bursts to the initial window) | Pacing or a burst limit | No pacer exists (no code; design 6.5 describes a token bucket). The only bound is the 128-datagram loop of one `produce` call (`quic/connection.hpp:414`), each datagram up to the probed size | After an idle period or on a large window the server sends up to 128 datagrams back to back | High | bug (SHOULD part), hardening for real paths |
| 10 | 9002 7.8 (SHOULD NOT increase the window while it is underused) | No growth when application-limited | `cc_on_acked` grows the window on every acknowledged packet (`quic/recovery.hpp:399-402`, `:222`) | A connection of small answers accumulates a window it never tested, then bursts (row 9) | High | bug (SHOULD) |
| 11 | 9002 7 (MUST NOT send a packet that takes bytes in flight over the window, except probes) | The window gates every in-flight packet | Only STREAM frames ask `cwnd_room` (`quic/connection.hpp:1247`, `:1422`); CRYPTO, HANDSHAKE_DONE, MAX_*, RESET_STREAM, STOP_SENDING, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID and PATH_* make `wants_to_send` true and go out, counted in flight, whatever the window (`:1239-1248`, `:426`, `:1330-1420`) | Small ack-eliciting packets beyond the window | High | bug (small) |
| 12 | 9000 10.1 (MUST raise the idle timeout to at least three PTOs) | Idle period is max(negotiated, 3 PTO) | `idle_` is the smaller of ours and the peer's and nothing else (`quic/connection.hpp:923`, `:472`, `:533`) | With a small `max_idle_timeout` from the client or a small `idle_timeout`, or a very slow path, the connection ends before loss recovery could act | High | bug |
| 13 | 9000 9.3.3 (MUST validate the previously active path with PATH_CHALLENGE on an apparent migration) | The old path is probed too | `migrate` challenges the new path only (`quic/connection.hpp:1016-1039`) | An off-path attacker that forwards a packet from its own address moves the connection until the challenge fails three times; the original path is not exercised meanwhile | High | bug (the passive side of migration) |
| 14 | 9000 19.5, 19.10 (MUST: STOP_SENDING or MAX_STREAM_DATA for a locally initiated stream not yet created is STREAM_STATE_ERROR) | Error for our streams that do not exist | A server-initiated id that `find_stream` does not know returns silently (`quic/connection.hpp:656-661`, `:676-680`; `http3/connection.hpp:111-117`) | No error for stream 15, 19, or any server-bidirectional id | High | bug |
| 15 | 9000 4.1 (MUST close with FLOW_CONTROL_ERROR when the connection limit is exceeded) | The connection limit is checked for every source of final size | RESET_STREAM adds its final size to `data_received_` without the comparison (`quic/connection.hpp:641-649`); only STREAM frames compare (`:845-847`) | A client can pass `initial_max_data` in accounting through resets; no memory is involved | High | bug (small) |
| 16 | 9000 4.5 (MUST use the final size to account for all bytes of a stream at the connection level) | Accounting and credit survive a stream's end | A RESET_STREAM or late STREAM frame for a stream already closed here is dropped before any accounting (`quic/connection.hpp:639-640`, `:810-813`). And connection credit is only ever returned through `stream_consumed` (`:172-180`): bytes of a stream that was reset, or abandoned after STOP_SENDING (`http3/connection.hpp:405-411`), are never credited back | The two sides' counts drift; after about 1 MB of request-body bytes abandoned or reset on one connection the client is left without connection credit (DATA_BLOCKED) for uploads | Medium (read; the stall itself not run) | bug (functional) |
| 17 | 9000 4.1, 4.6 (MUST ignore MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS that do not raise a limit) | Ignored | Each is a "glitch" (`quic/connection.hpp:668-697`); the budget is 100 for the connection's whole life, never reset (`:1051-1054`), and the hundredth closes with PROTOCOL_VIOLATION | A long connection on a path that reorders or duplicates, or a client that repeats a credit frame in probes, can be closed for frames the RFC says to ignore | High for the code; low for how often a real client reaches 100 | bug (risk) |
| 18 | 9000 12.4 (MUST: a packet with no frames is PROTOCOL_VIOLATION) | Error | `process_frames` loops over nothing and returns (`quic/connection.hpp:599-618`); a 4-byte packet number with an empty payload passes the sample-length test | Accepted, acknowledged never, no error | High | bug (trivial) |
| 19 | 9000 6.1 (MUST NOT send Version Negotiation in response to Version Negotiation) | No answer to version 0 | Any long-header datagram of 1,200 bytes or more with a version other than 1 is answered, version 0 included (`quic/udp.hpp:566-569`) | A VN-shaped datagram draws a VN packet (15 to 55 bytes; no loop, the answer is under 1,200) | High | bug (trivial) |
| 20 | 9000 14.1 (MUST discard an Initial packet in a datagram under 1,200 bytes) | Every Initial, not only the first | The size test is only on the path that creates a connection (`quic/udp.hpp:575`); an Initial for a known connection is handed to `receive`, which has no size test (`quic/connection.hpp:273-300`) | A client's later Initials in short datagrams are processed (the 3x count uses real bytes, so nothing is gained) | High | bug (small) |
| 21 | 9000 10.3.1 (MUST enter draining when a datagram ends in a stateless reset token) | Resets from the peer are detected | The peer's tokens are stored with its ids (`quic/connection.hpp:738-743`) and never compared; a packet that does not open is dropped (`:336-341`) | After a client's stateless reset the server retransmits until its idle timeout | High | bug (clients rarely send resets) |
| 22 | 9000 10.2.3 (SHOULD send CONNECTION_CLOSE in Handshake and 1-RTT, and Initial, before the handshake is confirmed) | Close at each level the peer may hold | `send_close` picks one level; its test `state_ != State::handshaking` is always true there because `fail` and `close` set the state to closing first (`quic/connection.hpp:1634`, `:1618`, `:260`), so once 1-RTT send keys exist (after our first flight) a handshake failure is sent in a 1-RTT packet only | A client that has not processed our Handshake flight cannot read the close and waits for its timeout. A failure on the ClientHello (the common case, only Initial keys exist) is sent correctly | High for the dead test; medium for how often it matters | bug (SHOULD) |
| 23 | 9000 12.2 (SHOULD ignore coalesced packets with a different destination id) | Ignored | No comparison in the datagram loop (`quic/connection.hpp:287-300`, `:364`) | None in practice: such a packet must still open | High | optional |
| 24 | 9000 19.14 (MUST: STREAMS_BLOCKED above 2^60 is an error) | Error | Read and ignored (`quic/frames.hpp:286-289`, `quic/connection.hpp:698-702`) | No error | High | bug (trivial) |
| 25 | 9000 17.2 (SHOULD read connection ids over 20 bytes of other versions to answer with VN); 8999 5.1 | VN for any future version | `parse_header` refuses an id length over 20 before it looks at the version (`quic/packet.hpp:83-90`) | A future version with long ids gets no Version Negotiation | High | optional |
| 26 | 9000 8.2.2 (MUST send PATH_RESPONSE on the path the challenge came from) | Response to the challenge's source | Responses are queued without their source and sent to the current peer address (`quic/connection.hpp:769-773`, `:1339-1346`, `:457`) | A probe from a new address that carries only probing frames is answered on the old path. Clients are told not to migrate (`disable_active_migration`), so this needs a non-conforming or rebinding client | High for the code; low impact | bug (passive migration) |
| 27 | 9000 8.1.3 (SHOULD treat an unusable NEW_TOKEN token as "address not validated") | Unknown token: proceed, perhaps with Retry | Every non-empty token must open as one of our Retry tokens or the client gets INVALID_TOKEN (`quic/udp.hpp:588-600`). We never issue NEW_TOKEN, so a token can only be a stale Retry token or one another server gave for this name | A client that kept a NEW_TOKEN token from a previous server behind the same name (a migration to agensio, a mixed fleet) is refused once instead of served | Medium | optional (becomes a bug when NEW_TOKEN is added) |
| 28 | 9000 14.1 (MUST expand a datagram with an ack-eliciting Initial to 1,200 bytes) | Always padded | Padding is asked of the last packet that wants to send (`quic/connection.hpp:447-455`); when that packet then builds nothing (no room left for its header, a seal failure) the datagram goes out as built | In a narrow size coincidence (an Initial that ends 30 to 40 bytes short of the datagram, with a Handshake packet wanted) an Initial datagram under 1,200 bytes | Low (constructed from the code, not seen) | hardening |
| 29 | 9000 17.4 (RECOMMENDED: a random spin bit when the spin bit is not used) | Random | Always 0 (`quic/connection.hpp:1264`) | The connection is recognisable as "spin disabled" | High | optional |
| 30 | 9000 14.3, 8899 4.3 and 5.1.2 (black hole detection; MAX_PROBES 3; raising again later) | The datagram size can come back down, a lost probe is retried | A probe goes once per step; one lost probe ends the search for the path (`quic/connection.hpp:1175-1177`); nothing lowers `max_datagram_` except an address change (`:1027`); no confirmation or raise timer | A random loss of the first probe leaves the connection at 1,200 bytes. A path whose MTU drops later (a route change) loses every full datagram until the idle timeout | High | hardening |
| 31 | 9000 21.6, 9114 10.5 (SHOULD mitigate slow clients) | Per-stream receive timers | None over HTTP/3: no header or body timeout between frames (design 9.1 says "planned and not built"; the owner deferred it 2026-10-26). Only the connection's idle timeout and the no-progress check on answers | 128 streams per connection can each be held open by a byte now and then | High (known) | hardening |
| 32 | 9000 15, 6.3 (reserved versions are 0x?a?a?a?a) | The greased version in VN is reserved | `0x0a0a0a0a | (rnd << 4)` also sets bits 8 to 11, the low nibble of the second byte (`quic/udp.hpp:638`) | Three times in four the list holds a version like 0x0a0a0e0a, which is not a reserved one | High | bug (cosmetic) |
| 33 | 9001 6.6 (MUST count failed packets across all keys of the connection) | One counter | `failures` lives in each `Keys` object and starts at zero with every key generation and for the previous and next keys (`quic/crypto.cpp:68-93`, `quic/connection.hpp:338`, `:346-347`) | None reachable (the limits are 2^52 and 2^36) | High | bug (letter only) |
| 34 | 9001 8.1 (MUST close with no_application_protocol, 0x0178, when no protocol is negotiated) | 0x0178 | With an ALPN extension that lacks `h3` the callback returns a fatal alert (`server.cpp:505-517`): met. With no ALPN extension at all the callback is not called; the code's own net is an application close H3_NO_ERROR after the handshake (`http3/connection.hpp:234`) unless OpenSSL refuses earlier | Depends on OpenSSL (Table 3); at worst a completed handshake closed with the wrong code | Low | bug (if OpenSSL lets it through) |
| 35 | 9002 7.6.1, 7.6.2 (persistent congestion: no acknowledged packet between the two lost ones; SHOULD NOT start before the first RTT sample) | Both conditions | The span of the packets declared lost in one pass is compared with the threshold (`quic/recovery.hpp:404-418`); nothing checks for an acknowledged packet in between, and `has_rtt` is read when the loss is declared, not for when the packets were sent | The window collapses to two datagrams in cases the RFC does not count (losses on both sides of an acknowledged packet; handshake losses before the first sample) | High for the code; the effect is conservative | bug (small) |
| 36 | 9002 5.1 (an RTT sample when the largest acknowledged is new and any newly acknowledged packet was ack-eliciting); 5.2 (SHOULD reset min_rtt after persistent congestion) | As written | The sample is taken only when the largest acknowledged packet itself was ack-eliciting (`quic/recovery.hpp:233`); `min_rtt` is never reset (`:391`, `:416`) | Fewer samples; a stale minimum after a path change without an address change | High | optional |
| 37 | 9002 7.2 (SHOULD recompute the initial window when the datagram size changes) | Recomputed | The window keeps its bytes when the probe raises the size (`quic/connection.hpp:1138-1142`); the minimum window follows it | None of note | High | optional |
| 38 | 9114 7.2.8 (MUST: frame types HTTP/2 used and HTTP/3 does not, 0x02, 0x06, 0x08, 0x09, are H3_FRAME_UNEXPECTED) | Error | Skipped like unknown types on request streams (`http3/connection.hpp:351-358`) and on the control stream (`:1048-1056`) | No error | High | bug |
| 39 | 9114 4.1 (MUST: an invalid sequence of frames is H3_FRAME_UNEXPECTED) | HEADERS, DATA*, optional trailers, nothing more | After a trailer section another HEADERS frame is taken as trailers again and DATA as body (`http3/connection.hpp:344-352`, `:514-525`) | No error for HEADERS or DATA after trailers | High | bug |
| 40 | 9114 4.3, 4.1.2 (MUST: pseudo-header fields in trailers, invalid names or values make the message malformed) | Trailers are validated | Trailers are decoded with a sink that accepts everything and are then discarded (`http3/connection.hpp:518-519`) | A malformed trailer section is accepted (it reaches no handler) | High | bug (small; row 10 of `audit_http2.md` is the same) |
| 41 | 9114 5.2 and 7.2.6 (MUST: a GOAWAY with a larger id than before is H3_ID_ERROR), 7.2.7 (MUST: a smaller MAX_PUSH_ID is H3_ID_ERROR), 7.2.3 (MUST: CANCEL_PUSH for an id never promised is H3_ID_ERROR), 7.1 (frame payloads of the wrong length are H3_FRAME_ERROR) | The control stream's frames are checked | After SETTINGS, every frame that is not SETTINGS, DATA, HEADERS or PUSH_PROMISE is consumed unread (`http3/connection.hpp:1048-1071`); the design document says CANCEL_PUSH is an error | No error for any of the four | High | bug (the server never pushes, so nothing depends on the values) |
| 42 | 9114 7.2.4.1 (SHOULD include a reserved setting) | One greased setting | Three settings, none reserved (`http3/connection.hpp:239-247`); the design document says one is sent | Nothing | High | optional |
| 43 | 9114 4.2.2 (SHOULD NOT send a field section over the peer's SETTINGS_MAX_FIELD_SECTION_SIZE) | The peer's limit is respected | Stored and never read (`http3/connection.hpp:1130`, `:709-746`) | An application's very large response head is sent to a client that said it would not take it | High | optional |
| 44 | 9114 4.4 (a CONNECT request has no `:scheme` and `:path`) | A well-formed CONNECT is recognised | Missing `:scheme` or `:path` is malformed whatever the method (`http/request_assembly.hpp:107`) | H3_MESSAGE_ERROR where 405 or 501 is the HTTP answer | High | bug (small; CONNECT itself is Table 2) |
| 45 | 9114 4.3.1 (MUST NOT be empty: `:authority`, Host; exactly one of each pseudo-header) | Empty values and repeats are malformed | An empty `:authority` beside a Host is accepted (`request_assembly.hpp:109`); a pseudo-header first sent empty and then again is not seen as a duplicate (`:46`, except `:authority`) | Lenient | High | bug (small; row 16 of `audit_http2.md`) |
| 46 | 9114 5.2 (graceful shutdown: GOAWAY, then the requests in progress complete) | Requests below the GOAWAY id finish | `Endpoint::shutdown` sends GOAWAY and the close in the same call (`quic/udp.hpp:433-451`); a reload that drops the listener uses it too. GOAWAY is sent nowhere else: `max_requests_per_connection` is not applied over HTTP/3 and no stream is refused with H3_REQUEST_REJECTED, both of which design 7.3 describes | Requests in flight at a shutdown or a listener's removal are cut; the RFC allows an immediate close (5.3), so this is quality, not a violation | High | hardening |
| 47 | 9204 2.2.3 (MUST: a reference at or above the declared Required Insert Count is QPACK_DECOMPRESSION_FAILED) | Checked for every reference | Post-base references are bounded by the count (`http3/qpack.cpp:253`, `:258`); a relative reference is bounded by the base and by the entry's existence only (`:231-232`, `:242-243`), and the base may be above the count | A section that declares too small a count (or zero) and references existing entries is decoded | High | bug (lenient) |
| 48 | 9204 4.4.1 (MUST: a Section Acknowledgment for a stream with nothing to acknowledge is QPACK_DECODER_STREAM_ERROR) | Error | An acknowledgement for an unknown stream or a stream whose section is not pending is ignored (`http3/connection.hpp:1090-1098`, `http3/qpack.cpp:513-514`); the code cannot tell it from one for a stream closed meanwhile | No error | High | bug (lenient) |
| 49 | 9204 2.2.2.2 (a Stream Cancellation when a stream is reset or abandoned with a section unprocessed) | Sent in every such case | Sent only for a stream that was blocked (`http3/connection.hpp:1160-1165`). Not sent when a section was given up: the 431 for a list over the limit (`:451`), oversized trailers skipped (`:345-347`), a reset or STOP_SENDING while a HEADERS frame is half received (`:182-201`, `:405-411`) | The client's encoder keeps the entries those sections referenced pinned until the connection ends | Medium | bug (small) |
| 50 | 9204 2.1.3 (SHOULD NOT write an encoder instruction without flow-control credit for all of it) | Credit checked before an insert | Inserts are appended to the encoder stream and the section that needs them is sent (`http3/connection.hpp:747-756`) whatever the stream's credit | If the client grants the encoder stream little credit, an answer can wait blocked at the client | Medium | optional |

Notes that are not a requirement of the RFCs but came out of the same reading:

- The first Initial of an unknown id creates the connection, its `SSL` and its keys before
  the packet is opened (`quic/udp.hpp:609`, `quic/connection.hpp:71-124`); a datagram of 1,200
  bytes of noise with a long header holds a half-open slot for `idle_timeout`. The budget
  (1,024 per worker) and Retry bound it.
- Every packet sent, ACK-only ones too, is recorded in the sent-packet ring until an ACK frame
  passes it (`quic/recovery.hpp:81-94`); a client that sends ack-eliciting packets and never an
  ACK grows the ring by one record per two of its packets. Roughly one byte held per byte sent,
  so a weak lever; medium confidence.
- The process secret is made at each start (`quic/crypto.cpp:226-233`), so after a restart a
  stateless reset carries a token the client never saw and does nothing; the comment "a restart
  forgets nothing it needs" (`crypto.hpp:88-90`) and design 6.4 say otherwise. nginx has
  `quic_host_key` for this.
- The design document describes things the code does not do: a pacer and packet-number
  skipping (6.5), forwarding of a misrouted packet (6.1), a Retry key per hour (6.3), a closing
  rate that halves (6.9; the code answers one in three), a greased setting and CANCEL_PUSH as an
  error (7.1), a 400 before the reset of a malformed request, GOAWAY at
  `max_requests_per_connection` and H3_REQUEST_REJECTED above it (7.3), a shutdown that waits
  for the streams (6.9).

## Table 2. Optional features and extensions not implemented

| Feature | RFC | What it is for |
|---|---|---|
| 0-RTT | 9000 7.4.1, 9001 4.6 | A returning client's first request with no round trip; replayable, so GET and HEAD only when it comes (design I4). Known |
| ECN | 9000 13.4, 9002 7.1, B.7 | Congestion signalled by marks instead of loss. Neither marking nor feedback: the socket does not ask for the TOS byte, so 13.4.1's "MUST provide feedback ... if accessible" is read as not accessible. Known |
| NEW_TOKEN | 9000 8.1.3, 19.7 | Address validation for a client's next connection without a Retry round trip. Known; row 27 changes with it |
| Active migration, `preferred_address` | 9000 9, 9.6 | A client that moves networks on purpose; a server that moves the client to another address. `disable_active_migration` is sent; only rebinding is followed. Known |
| QUIC version 2, compatible version negotiation | 9369, 9368 | A second version to keep middleboxes honest; choosing a version without a round trip. Known |
| Greasing the QUIC bit | 9287 | Lets the fixed bit vary so that nothing ossifies on it |
| Spin bit | 9000 17.4 | Passive RTT measurement by the network (row 29) |
| CUBIC | 9438 | Window growth for fast, long paths; what browsers and most servers use. NewReno only |
| Pacing | 9002 7.7 | Spreads a window over the round trip (row 9; required unless bursts are limited) |
| HyStart++, BBR | 9406, drafts | Leaving slow start before loss; rate-based control |
| Packet-number skipping | 9000 21.4, 9002 | Catches a client that acknowledges packets it did not receive. An ACK of a number never sent is detected; no numbers are skipped |
| Persistent stateless-reset and token key | 9000 10.3.2 | Resets and tokens that outlive a restart and work across a fleet |
| ACK frequency | draft-ietf-quic-ack-frequency | The sender tunes how often it is acknowledged |
| Datagrams | 9221, 9297 | Unreliable messages; HTTP Datagrams and the Capsule Protocol |
| Extended CONNECT, WebSocket over HTTP/3 | 9220 | WebSockets on an HTTP/3 connection. A WebSocket today needs HTTP/1.1 |
| CONNECT, CONNECT-UDP | 9114 4.4, 9298 | Tunnels (row 44) |
| WebTransport | drafts | Not in scope of phase I |
| Priorities | 9218 | The `priority` field and PRIORITY_UPDATE; answers are round-robin. Listed in "Not yet" |
| Server push | 9114 4.6 | Never sent; MAX_PUSH_ID is ignored. Browsers have dropped it |
| Request trailers | 9114 4.1, 9110 6.5 | Decoded and discarded; handlers and origins see none |
| Response trailers, 1xx (103 Early Hints) | 9114 4.1, 8297 | Not sent |
| HTTP/3 to origins | | The proxy speaks HTTP/1.1 upstream |
| GREASE of frames, streams, settings, transport parameters | 9114 7.2.8, 6.2.3, 7.2.4.1; 9000 18.1 | Keeps peers tolerant; received ones are tolerated (row 42 for the setting) |
| QPACK encoder beyond four fields | 9204 | Only `server`, `date`, `content-type`, `strict-transport-security` go through the dynamic table; no literal-name inserts, no Duplicate, no never-indexed marking |
| qlog | drafts | Structured traces other tools read; the tracing build prints its own lines |
| Key update on a schedule | 9001 6 | Only at the confidentiality limit (2^23 packets) or when the peer asks |
| HTTPS/SVCB records, Alt-Svc beyond `h3` | 9460 | The operator's; `alt-svc` is sent |
| Interop runner cases `zerortt`, `ecn`, `v2`, `connectionmigration` | | Not claimed, as the design says |
| The `amplification` row of the attack suite | design 9.1 | A spoofed-source test; row 6 is what it would exercise. Known |

## Table 3. Could not determine

| Question | What I looked at | Why it stays open |
|---|---|---|
| A ClientHello with no ALPN extension over QUIC (9001 8.1) | `server.cpp:499-517`, `http3/connection.hpp:234` | Whether OpenSSL's QUIC TLS API aborts such a handshake itself. If not, row 34 applies |
| A ClientHello without `quic_transport_parameters` (9001 8.2: missing_extension) | `quic/connection.hpp:912-929`, `quic/tls.cpp:153-158` | The code never tests `peer_params_ok_` when the handshake completes; it relies on OpenSSL to refuse. If OpenSSL does not, the connection runs with every peer limit at zero |
| 1-RTT packets processed before the handshake is complete (9001 5.7, MUST NOT) | `quic/connection.hpp:300-306`, `:902-929` | `receive` only asks whether read keys exist. It is safe if OpenSSL yields the application read secret only after the client's Finished, which I believe but could not check here |
| A non-empty `legacy_session_id` (9001 8.4, SHOULD be PROTOCOL_VIOLATION) | `quic/tls.cpp` | Decided inside OpenSSL |
| NewSessionTicket contents and early data (9001 4.6.1) | `quic/tls.cpp:38-59`; no call of `SSL_set_quic_tls_early_data_enabled` or `max_early_data` in `src/` | Off by OpenSSL's default as far as the code shows; the tickets themselves were not inspected |
| Huffman and prefix-integer rules (7541 5.1, 5.2, by reference from 9204 4.1) | Not read: `src/http/field_codec.*` | Shared with HPACK; covered by the HTTP/2 suites and `fuzz_qpack` |
| Whether row 16's stall and row 5's growth show as described | The code paths cited | Not run |
| Which Table 1 rows an existing test already holds | Test names only | The suites were not audited |
| Behaviour against real client stacks | `bench/quic-interop/` exists; CLAUDE.md records 18 cases passing with quic-go and ngtcp2 | Not run in this audit |

## Stricter or better than the RFCs require

- Every datagram that carries an Initial is padded to 1,200 bytes, not only those with
  ack-eliciting Initials (9000 14.1), with the edge of row 28.
- A handshake has an absolute deadline of `idle_timeout` from the connection's creation, and
  only a packet that opens restarts the idle timer, while every datagram still counts for the
  3x allowance (`quic/connection.hpp:277-281`, `:469-473`).
- A worker at its connection ceiling answers CONNECTION_REFUSED in one stateless Initial
  packet, before Retry; an unusable Retry token gets INVALID_TOKEN the same way.
- Retry tokens are AEAD-sealed, bound to address and port and the original id, valid ten
  seconds; stateless resets are always smaller than the packet answered and rate-limited.
- Transport parameters: every bound of 18.2 is checked, duplicates and the four server-only
  parameters are refused (`quic/transport_params.hpp:87-147`); MAX_STREAMS above 2^60 is refused.
- An ACK of a packet never sent closes the connection (a SHOULD in 9000 13.1); reserved header
  bits are checked after the AEAD opens, as 17.2 asks.
- CRYPTO reassembly holds 16 KB per level where 4 KB is required; ACK frames are processed for
  32 ranges at most; the peer's ids are held to four with CONNECTION_ID_LIMIT_ERROR.
- PTO probes carry the oldest unacknowledged data, not a PING (9002 6.2.4); MTU probes are
  outside the congestion window and their loss is not a congestion signal (9000 14.4); don't
  fragment is set for both families; a port-only rebinding keeps the congestion state (9.4).
- A reset budget (H3_EXCESSIVE_LOAD past the stream limit per second) and a no-progress check
  on answers, neither asked for by the RFCs.
- HTTP/3: duplicate settings and the HTTP/2 setting identifiers are refused, connection-specific
  fields are dropped from every answer, the QPACK static table is held byte for byte to the
  RFC's XML by a unit test, blocked streams are capped on both sides, and the encoder never
  evicts an entry a pending section references.
