# Changelog

## 0.1.0-alpha.22 (unreleased)

- **HTTP/3 over our own QUIC transport, the first slice** (phase I, `docs/design-http3.md`,
  accepted 2026-09-24): `src/quic/` (packets, frames, transport parameters, the keys and
  the AEAD over OpenSSL 3.5's QUIC TLS API and EVP, RFC 9002 loss detection and NewReno,
  streams with flow control, the packetiser that fills a worker-wide send batch, idle and
  close) and `src/http3/` (QPACK over the static table, the frames, the control and QPACK
  streams, request streams turned into `Stream`s through the same request assembler,
  dispatcher and pool as HTTP/2, answers as HEADERS and DATA frames with memory and file
  bodies, request bodies as the pull source with the bytes waiting in the QUIC stream's
  buffer until the handler takes them). `"h3"` in `protocols` opens QUIC on every TLS
  listener's port over UDP, on worker 0 in this slice; the UDP endpoint reads with
  `recvmmsg` after `async_wait` with GRO on and sends the wake-up's answers of every
  connection with one `sendmmsg`, consecutive datagrams to a peer folded into GSO
  messages. Measured first (`bench/udp/run.sh`, `bench/results/udp-20260924-140715.md`):
  the textbook one-datagram-per-completion Asio loop costs 1.45 to 1.60 us per datagram,
  batching the syscalls a tenth less, GRO in and GSO out 0.55 to 0.64 us, and Asio's own
  receive cannot see the GRO segment size, which decides the loop. Under the arena's
  `baseline-h3` load (the arena's own h2load over QUIC, 64 connections with 64 streams
  each, `bench/httparena/profile-h3.sh`): 1.22 to 1.25M req/s on one worker at 0.61 us of
  server CPU per request, about 3,100 cycles at 3.19 instructions per cycle, twenty-one
  answers per datagram, the kernel 4.2 % of the cycles and libcrypto 3.5 %; the devbox's
  nginx 1.26 with its http_v3 module does 402 to 433k req/s at 2.32 us on the same load
  serving a two-byte file with one worker. In the arena's own harness (`local.sh`, twelve
  workers pinned, one of them serving QUIC in this slice): `baseline-h3` 1.77 to 1.81M
  req/s and `static-h3` 98 to 108k on that one core, no failed request; the board's nginx
  entry does 4.85M and 361k on 31 and 50 cores. Three servers with one worker each on
  this box (`bench/h3/run.sh`, `h3-20260924-162836.md`): the 1 KB file at 64 connections
  and 64 streams agensio 0.90 us and 1.03M req/s, nginx 3.27 us and 305k, Caddy 26.6 us
  and 38k; at ten streams 1.05 / 2.70 / 26.8 us; the 100 KB file at ten streams 24.8 /
  31.0 / 121 us; the 10 MB stream is nginx's row (1.95 ms against our 2.72 ms per
  response: the file's 64 KB windows are read and copied per packet). `ab.sh
  v0.1.0-alpha.21 -2 -3` (`ab-20260924-162251.md`): every h1 and h2 row 0.92 to 1.01,
  the h3 rows 4.4 us at one stream per connection, 1.05 at ten, 0.88 at sixty-four,
  24.7 for the 100 KB file at ten. Open: two of 4.5 million requests stalled at 256
  connections with ten streams (the client saw a few of its own packets lost; the
  next step's loss injection on the receive side targets it). The profile's top item is the Huffman decoding of the
  request's literals (23 %): with the dynamic table at capacity 0 a client sends `:path`,
  `:authority` and `user-agent` as Huffman literals on every request where HPACK indexed
  them after the first, which is the QPACK step of the design's I3. Tests: the RFC 9001
  appendix A vectors (the client Initial opened, the server Initial and the ChaCha20
  packet sealed byte for byte), varints, ranges, frames, transport parameters, the
  deadline heap, the recovery's loss and RTT arithmetic, QPACK's static encoding and
  decoding; in the integration suite a curl over HTTP/3 through every static answer
  (bodies, the streamed 10 MB file, HEAD, 404, 405 with a body, 301, 304, 206, the
  pre-compressed twin, one connection for several requests, the access log's
  `HTTP/3.0`) when the binary and curl have it; the sanitizer suite, run over the same
  rows and under the QUIC load, caught the endpoint freeing a connection while it still
  walked that connection's own id list (every idle timeout; the release build survived
  it silently), fixed before the slice was measured again. Two more findings from the
  first rows: a response packet carried no acknowledgement of the request it answered
  (the delayed-ACK rule waited for a second packet or 25 ms), so at one stream per
  connection the client's stream could not close until an ACK-only packet followed and
  the row ran at 2,575 req/s over 64 connections; the pending acknowledgement now rides
  on any packet sent for another reason (RFC 9000 13.2.1) and the row does 212k, with
  the 100 KB row's failures partly with it. And the arena's harness resolves `localhost`
  to `::1`, which QUIC cannot fall back from the way TCP does: the endpoint on a `[::]`
  address is dual-stack like the acceptors, and the entry's TLS site listens there. Two
  more came from the 100 KB row at ten streams, whose bursts overflow the client's
  receive buffer, the loss loopback does have: a response whose last packet is lost is
  recovered only by a probe, and our probe was a one-byte PING behind a one-byte packet
  number, shorter than header protection can sample (RFC 9001 5.4.2), so the client
  could not unprotect it and never acknowledged; such packets are padded to the minimum
  now, and the tracing build (`-DAGENSIO_QUIC_TRACE=ON`) can lose every Nth datagram or
  one final packet on purpose (`AGENSIO_QUIC_DROP=N`, `AGENSIO_QUIC_DROP_TAIL=1`) to
  exercise loss detection, probes and retransmission on loopback; and a send batch that
  filled during a wake-up left the connections behind it without a send until their idle
  timeout, so it goes out when full and fills again. The arena entry subscribes
  `baseline-h3` and `static-h3`. Not in this slice (I1b to I4 of the design): streamed upstream bodies
  over h3, Retry, stateless reset, key update, path validation, path MTU discovery,
  0-RTT, ECN, `alt-svc`, the per-worker sockets.
- **HTTP/3 on every worker**: with `reuse_port` each worker opens its own UDP socket on the
  h3 listener's port and a classic BPF program attached to the group (six instructions,
  no privilege, `SO_ATTACH_REUSEPORT_CBPF`) delivers a packet to the socket whose index
  the first byte of its destination connection id names, which is the worker that issued
  the id; a client-chosen id falls back to the kernel's 4-tuple hash, so a connection
  never changes worker (design 6.1). Where the attach is refused the hash routes alone. The per-worker buffers are 1 MB in
  and 1 MB out. On the arena's rows in its harness (twelve workers pinned, twelve load
  threads): `baseline-h3` 3.86 to 3.89M req/s at 2.6 cores of server CPU (the load
  generator is the limit; one worker did 1.8M at one core), `static-h3` 541k at 8.3
  cores (one worker 98 to 108k), no failed request, 83 and 92 MiB resident; the board's
  nginx entry does 4.85M and 361k on 31 and 50 cores.
- **QPACK's dynamic table on the decoding side** (RFC 9204 sections 3, 4.3 to 4.5; design
  7.2's first step): the connection advertises a 4 KB table and 16 blocked streams, the
  client's encoder stream (set capacity, insert with a name reference, insert with a
  literal name, duplicate) fills the table, a field section's prefix names the insert
  count it needs and its base, a section ahead of the table waits and is decoded when
  the inserts arrive (a seventeenth waiting stream is QPACK_DECOMPRESSION_FAILED), and
  the decoder stream carries the section acknowledgements, stream cancellations and
  insert count increments the encoder needs. Dynamic entries keep the rules-once mark
  of HTTP/2's HPACK, so a request's field rules run once per entry. Trailers are
  decoded and discarded to keep the acknowledgements in step. The control streams' send
  buffers drop what is acknowledged in order, so a long connection's decoder stream
  stays small. Unit tests: RFC 9204 appendix B (B.1 to B.5) on the encoder stream, the
  blocked section, the decoder stream's bytes, the eviction, and the errors. Measured
  under the arena load (`profile-qpack.txt`): the Huffman share of the profile 21 % to
  7.9 %, 0.61 to 0.56 us of server CPU per request, a request's field section seven
  bytes with two dynamic references; A/B `ab-20260924-172435.md` h1 and h2 flat.
- **A stream whose id arrives after a higher one is a new stream, not a closed one**: the
  transport took a lower id for a stream it had already closed, so a client that opened
  its unidirectional streams 2, 10 and then 6 lost its QPACK encoder stream, and a
  request stream whose first packet landed after a later stream's did too (the likely
  cause of the two stalled requests in 4.5 million at 256 connections). Closed ids are
  now recorded (the last 64, as HTTP/2 keeps them) and only those are refused.
- **Larger datagrams and fewer packets per HTTP/3 request** (design 6.7): one path MTU
  probe after the handshake (a PING padded to 1,472 bytes over IPv4, 1,452 over IPv6, or
  what the client announces; acknowledged, every datagram is that size; lost, 1,200 stays;
  probed again when the client's address changes), so a 1 KB answer with its head is one
  datagram and the 10 MB stream costs 2.37 ms per response instead of 2.72 (nginx 1.95;
  `h3-20260924-174006.md`). And MAX_STREAMS no longer goes out in a datagram of its own
  after every closed stream: the trace of a client with one request at a time showed a
  31-byte packet per request that the client then acknowledged; the credit rides on the
  next packet sent for another reason and goes alone only when the peer's room is under
  a quarter of the limit. Measured with the transport step below in one A/B
  (`ab-20260924-181813.md`, every h1 row 0.99 to 1.01, the h2 rows 0.94 to 0.98): the h3
  rows against the first slice's 4.4 / 1.05 / 0.88 / 24.7 us are now 3.8 us at one
  stream per connection, 0.90 at ten, 0.80 at sixty-four and 21.7 to 22.0 for the 100 KB
  file at ten; one worker on this box (`h3-20260924-182224.md`): 1 KB at 64 connections
  and 64 streams 0.78 us and 1.08M req/s, at ten streams 0.90 us and 664k, at 256
  connections with ten 0.97 us and 546k (the row that stalled two requests in the first
  slice: none now), the 100 KB file 21.8 us and 46.0k (nginx 31.0 and 32.1k), the 10 MB
  stream 2.40 ms and 417 req/s (nginx 1.95 and 512), the one-stream row 3.78 us at 54.3k
  where nginx costs 7.57 us for 57.4k (the row is bound by h2load's per-request work,
  about a millisecond per connection in this shape: agensio, nginx and the previous
  build all sit at 52 to 57k; the same client with one connection does a request every
  148 us); in the arena's harness with twelve workers `baseline-h3` 3.85 to 3.88M req/s
  at 2.35 cores and `static-h3` 618 to 622k at 8.9 cores (541k before the datagram work).
- **The transport rows of HTTP/3's I1b** (RFC 9000 5.1, 8.1, 9, 10.3; RFC 9001 6; design
  6.3, 6.4, 6.9): address validation with Retry (`http3 = { retry = "auto" | "always" |
  "never" }`, the one HTTP/3 key: tokens sealed under a per-hour key from a per-process
  secret, bound to the client's address, the original connection id and the time, valid
  ten seconds; an Initial whose token does not open is answered with an INVALID_TOKEN
  close under the client's Initial keys and forgotten; "auto" sends Retry once a worker
  has 512 handshakes in progress and drops Initials at 1,024, "always" is for a host
  under a handshake flood, "never" for a benchmark); stateless resets for a packet whose
  id nobody knows (a server that restarted), the token of every id HMAC of the id under
  the process secret so nothing is stored and any worker can answer, the reset one byte
  shorter than the packet, none under 22 bytes, at most 1,000 per second per worker; four
  connection ids issued to the peer at the handshake and one more for each it retires
  (at most 64 per connection), the peer's own ids bounded at four; key update both ways
  (the peer's followed before its packet is acknowledged, ours at the AEAD's
  confidentiality limit; the previous keys kept three PTOs for reordered packets; a
  second update before the first is acknowledged is KEY_UPDATE_ERROR; the
  header-protection key never changes across updates, RFC 9001 6.1, which the first
  version got wrong); a client whose address changes (a NAT rebinding) keeps its
  connection: its new path is validated with PATH_CHALLENGE, sending to it is capped at
  three times what arrived on it until PATH_RESPONSE (the cap is a byte allowance, so
  the challenge goes out after a small packet), the congestion state starts over unless
  only the port changed, and the previous address is used again when the validation
  fails; the reset budget (RESET_STREAM and STOP_SENDING past `http2.max_concurrent_streams`
  in one second close with H3_EXCESSIVE_LOAD) and the glitch budget (100 credit updates
  that raise nothing). `tests/h3-attacks.py` on aioquic (now in the devbox image) drives
  thirteen rows of the design's threat table by hand over its own sockets: handshake,
  retry in both modes, invalid-token, key-update, key-update-twice, rebind, cid-retire,
  stateless-reset, forged-flood, rapid-reset, stream-flood, control-stream,
  handshake-flood (1,500 Initials in 1.1 s); the integration suite runs it where aioquic
  is installed and adds a curl through a `retry = "always"` instance. Unit tests for the
  tokens, the Retry packet and its tag, the stateless reset and the INVALID_TOKEN close.
  Two bugs the suite found before the step was measured: the header-protection key was
  re-derived at a key update (every packet after it failed to open), and the
  amplification check counted whole datagrams, so a client that had just changed its
  address could not be sent the PATH_CHALLENGE that validates it. No cost on the request
  path: the profile after the step 1.14 to 1.15M req/s on one worker at 0.58 us per
  request (`profile-transport.txt`).
- **HTTP/3 stability and the transport's remaining per-request costs** (2026-09-25).
  The path MTU search goes on upward (RFC 8899): after 1,472 bytes each acknowledged
  probe doubles the next, up to what the client announces, so loopback and jumbo-frame
  paths carry tens of KB per datagram (the trace: 1,472, 2,944, 5,888, 11,776, 23,552,
  47,104 bytes in five round trips) and a 1,500-byte path stops at 1,472; probes are
  outside the congestion window (their loss is the path's answer, not congestion) and
  a datagram larger than the window's room shrinks to it instead of waiting. Closed
  streams are a bitmap over the 64 indices below the highest opened (a bit test per new
  stream instead of a scan of 64 ids, 7.4 % of the profile). At shutdown every HTTP/3
  connection gets a GOAWAY naming the first request id it will not process and a close
  with H3_NO_ERROR, in the datagrams that go out before the workers' loops stop, so a
  client retries at once instead of waiting for its idle timeout. Stability tests: the
  loss proxy `tests/quic-lossy.py` (3 % of the datagrams dropped and 5 % delayed up to
  3 ms, both ways) sits between curl and the server in the integration suite, and the
  1 KB page and the 10 MB file arrive through it; six attack rows written as raw frames
  into aioquic's packets (101 credit updates that raise nothing, an acknowledgement of a
  packet never sent, a fifth connection id, retiring an unissued and the in-use id, data
  beyond a stream's window) and the shutdown row; the fuzzers `fuzz_quic_packet`,
  `fuzz_transport_params` and `fuzz_qpack` (20.6 M, 121 M and 11.7 M runs in two minutes
  each, no findings). Measured (`ab-20260925-013754.md` against the previous commit, h1
  and h2 rows 0.97 to 1.05): the h3 rows on loopback, where the search reaches 47 KB
  datagrams, 1.00 at one stream per connection, 0.83 at ten, 0.76 at sixty-four and 0.53
  for the 100 KB file at ten (21.2 to 11.2 us); one worker (`h3-20260925-014251.md`) 1.23M
  req/s at sixty-four streams (0.62 us), 1.09M at 256 connections with ten (0.87 us), the
  100 KB file 85k req/s at 11.7 us (nginx 32k at 31.0), and the 10 MB stream 1.44 ms per
  response against nginx's 1.95, the last row nginx held (2.72 ms in the first slice;
  the profile's datagrams there average 42 KB now); under the arena load 0.54 us per
  request (0.58 before, the closed-stream scan gone); the arena's rows, on a 1,500-byte
  path, within noise (`baseline-h3` 3.70 to 3.72M at 2.0 cores, `static-h3` 610 to
  614k). The tree as committed, with the interop fixes below, measured again
  (`ab-20260925-031102.md`, `h3-20260925-031559.md`, the interop matrix running on the
  same box): the h3 rows 1.00 / 0.84 / 0.80 / 0.55 of the previous commit, h1 and h2
  within noise. A finding for the next step: h2load, the arena's client, announces a 4 KB QPACK
  table (curl announces none), so the encoder-side dynamic head will shorten every answer
  it sends there. And the QUIC
  interop runner (`bench/quic-interop/`, design 9.2): agensio as a server implementation
  in a Debian trixie image with the runner's endpoint setup, the runner in its own image
  with tshark, `run.sh` driving both through the host's docker; the runner's `hq-interop`
  protocol (a `GET /path` line per stream, the file raw) and the `SSLKEYLOGFILE` export
  exist only in `-DAGENSIO_INTEROP=ON` builds, and `zerortt`, `ecn`, `v2` and
  `connectionmigration` exit 127 as unsupported. Its first finding, before any test
  case ran: the simulator's readiness probe is a packet with an unknown QUIC version
  expecting Version Negotiation, and the header parser read the rest of such a packet
  by version 1's rules (RFC 8999 5.1 makes everything after the ids opaque), so no
  Version Negotiation was ever sent; fixed, with a unit test. The harness runs inside a
  Docker-in-Docker daemon (the runner's compose file needs Engine 28.1 and the host has
  26.1) with the bridge netfilter hook off, because the daemon's iptables rules dropped
  every bridged frame whose IP destination lay on the other bridge, which is what the
  client's packets to the server through the simulator are. Two bugs the first matrix
  found: a request retransmitted after loss was refused as a stale stream when the
  client had opened more than 64 streams since (the closed-stream window is 1,024
  indices now; 24 of 2,000 requests of the multiplexing case), and the `[::]` socket set
  don't-fragment for IPv4 peers only, so on the simulator's 1,500-byte link the MTU
  probes went through as fragments, the search reached 11 KB datagrams, and a transfer
  crawled under fragment loss (DF is set for both families now, and a probe beyond the
  path fails at once). And a third from the multi-connection cases under 30 % loss and
  corruption: a probe timeout sent a bare PING, so a lost Handshake flight or a lost
  response was repaired only after the probe's acknowledgement declared the old packets
  lost, two or three round trips instead of one; a probe now carries the oldest
  unacknowledged data of its space again (RFC 9002 6.2.4), the original packet staying in
  the ring for its own acknowledgement. The matrix after the three fixes
  (`bench/results/interop-20260925-061102.md`): every supported case passes with quic-go
  (18 of 18) and ngtcp2 (17, plus one run of handshakeloss where the client restarted an
  attempt under the 30 % burst loss and the runner counted 51 handshakes for 50);
  `zerortt`, `ecn`, `v2` and `connectionmigration` exit 127 by choice. The results table
  is in the security page.
- **The code HTTP/2 and HTTP/3 share lifted into `src/http/`** first, as a pure refactor
  (design-http3 section 4): the Huffman code, the prefixed integers and the dynamic
  table with its rules-once marks (`field_codec`), the request assembler (`request_assembly`),
  the stream table and pool (`stream_pool`); HTTP/2 rebuilt on them, `ab.sh v0.1.0-alpha.21 -2`
  0.96 to 1.04 on every row (`ab-20260924-142634.md`), the suites unchanged. The table
  generator also emits QPACK's 99-entry static table.
- **The RFCs the protocol layers implement are in `docs/rfc/`** as text (HTTP semantics
  and HTTP/1.1, HTTP/2 and HPACK, QUIC with its TLS and recovery documents, HTTP/3 and
  QPACK, CUBIC, DPLPMTUD), with an index mapping each to the code; CLAUDE.md asks for the
  section to be read and cited.
- Benchmarks: `bench/h3/run.sh` (the HTTP/3 rows against nginx and Caddy with an h2load
  built with QUIC; `bench/docker/Dockerfile.devbox` now carries the devbox recipe with
  one under `/opt/nghttp2`), `bench/ab.sh -3` (four h3 rows; a base without h3 gets
  none), `bench/httparena/profile-h3.sh`, `bench/udp/`.

## 0.1.0-alpha.21 (2026-09-24)

- **HTTP/2 per-request cost, in three measured steps** on the arena's HTTP/2 baseline
  row (one worker, `h2load -c 64 -m 100`; the same load against h2o's arena entry on one
  thread in the same container does 2.60M req/s over TLS, `bench/httparena/profile-h2o.sh`):
  the clock read once per socket event instead of four times per request, released
  streams pooled up to the concurrency limit (a client with a hundred streams in flight
  constructed and freed a stream object with its two hundred header views per request),
  stream lookups and the writer's in-flight bookkeeping without scans, and the benchmark
  handler's continuation in the `std::function`'s own storage, 1.42M to 2.44M req/s over
  TLS; the Huffman decoder writing through a pointer, static-table fields viewed in place,
  one static-name search per encoded field and a remembered content-type index, the
  router's single-site shortcut, the normaliser's plain-target shortcut and the handler's
  HTTP/2 tail prebuilt, to 3.04M over TLS and 3.37M on h2c; and the write cycle built into
  one buffer, large payloads on plain sockets as scatter entries between its runs, so the
  answers of one read leave in one send instead of two, to 3.30M over TLS and 3.97M on h2c,
  1.27 times h2o on one core; and, once the pinned rows showed the pool's memory
  (647 MiB resident for 512 connections with a hundred streams each, h2o 65), requests
  decoded into the connection's scratch with each stream keeping an exact-size copy
  instead of a 16 KB reservation, to 3.48M and 441 MiB; and emit at respond: inside a
  read's frame loop a complete small answer goes into the cycle's buffer at once and its
  stream is closed and pooled, so a read of a hundred requests reuses one or two hot
  stream objects instead of holding a hundred cold ones until the write completes.
  Twelve workers pinned to six cores with their siblings: 2030 cycles per request
  against h2o's 3100 (instructions per cycle 3.20 against 2.74, cache misses per request
  6 against 24, 68 MiB resident against the pool's 441), one worker 3.60M req/s. On this
  box the pinned row is 12.0M against h2o's 12.4-12.9M with half of agensio's CPU idle:
  the twelve-thread load generator is the limit there. Then the request side: the field
  rules run once per dynamic-table entry (the decoder reports each field's origin and
  the entry carries a mark; a static pair skips the syntax rules; a literal is checked
  every time), the fields of interest are found by length first, and the benchmark
  handler builds only the head of the protocol in use: one worker 3.99M req/s, 1315
  cycles per request against h2o's 2054, twelve workers 1905 against 3210. In the
  arena's own harness, all rows: level with h2o on baseline-h2 (12.39M against 12.29M at
  776 % against 1001 % CPU) and on the HTTP/1 rows, ahead on json-tls (1.40) and
  static-h2 (3.22), 4.2 to 4.4 times nginx on the HTTP/2 baselines. The router and
  normaliser shortcuts and the continuation reach HTTP/1 as well. Details and the
  profiles in `docs/design-http2.md` 6.2.1, 6.4, 6.6 and 7.3 and
  `bench/results/httparena-lite-20260924-0147.md`.
- **Fixed: a control-socket request with a body leaked its connection.** The body-reading
  step of the control handler (mutations, uploads) captured itself strongly, a reference
  cycle that kept the connection, its receive buffer and the request's state alive for
  the life of the process, once per such request; LeakSanitizer found it at the end of
  the integration suite (84 connections, 15 MB). The step refers to itself weakly now and
  the read in flight keeps the chain alive.
- **Fixed: a build without OpenSSL did not compile** since `protocols` per site (the
  listener's ALPN field exists only with TLS).
- **HTTP/2 response heads through a dynamic table** (design 6.2.1): `server`, `date`,
  `content-type`, `vary`, `content-encoding` and whatever a handler's or an upstream's
  block repeats are inserted once per connection (date once per second) and cost one byte
  after; `content-length`, the validators and everything that changes per answer stay
  literal, `set-cookie` and the authorization fields are never indexed. A cache entry's
  block is now the tail of literals, still built once at insert. The table is at most 1 KB
  and never above the peer's SETTINGS_HEADER_TABLE_SIZE, shrinks with it and stops at
  zero; encoder and decoder share one table implementation, so both sides evict by the
  same code, and unit tests, a fuzz target and nghttp2's decoder hold them in step. The
  arena's HTTP/2 baseline answer went from a 48-byte HEADERS block to 8, and the row
  from 7.55M to 8.46M req/s pinned (h2o 11.06M, load-bound; agensio was at 3.26M before
  the write batching). With it, TLS
  write cycles that are coalesced before `SSL_write` are capped at 64 KB of body: once
  the write batching filled every cycle, 256 KB cycles copied and encrypted outside the
  cache and cost the arena's static-h2 row 9 %.
- **HTTP/2 answers of one read go out in one write.** The writer is held while the
  connection runs the frames of a read, so the answers to a hundred HEADERS frames leave
  in one cycle instead of one every two or three streams (the write completed inline and
  the next cycle started with whatever was ready), and a cycle of many small pieces is
  copied into one buffer, since asio hands the kernel at most 64 scatter entries per
  call. Measured on the arena's HTTP/2 baseline, one worker: sends per answer from one in
  2.4 to one in 57, 583k to 1.50M req/s on h2c and 516k to 1.61M over TLS; pinned to six
  cores plus siblings, 3.26M to 7.55M req/s at less CPU. The A/B against alpha.20 puts the
  ten-stream rows at 0.35 of the base CPU per request and every single-stream and HTTP/1
  row inside the noise band.
- **Fixed: a HEADERS frame on a stream the client had already ended was reset with
  PROTOCOL_ERROR** where RFC 9113 5.1 requires STREAM_CLOSED. Rarely visible before, since
  the answer had usually gone out inline and the frame then met a closed stream; with the
  answers of a read written after its frames, h2spec 5.1/6 caught it under the sanitizer
  build.
- **`protocols` per site**: a `[[site]]` may name its own list (`["h1"]` keeps a TLS port at
  HTTP/1.1 while another offers h2; `["h2c", "h1"]` accepts the preface on one plain
  listener), inherited from `[server]` otherwise; sites sharing an address must agree.
  `status` names each listener's own protocols.
- **`workers = 0` counts the CPUs the process may run on** (the affinity mask: a
  container's cpuset, a `taskset`) instead of every hardware thread, like nginx's
  `worker_processes auto`.
- **HttpArena benchmark handler** behind `-DAGENSIO_HTTPARENA=ON`: `handler = "httparena"`
  answers the arena's `/baseline11`, `/baseline2`, `/json/{count}?m=` and `/pipeline`
  in-process from a dataset given as `httparena = { dataset }`, as the arena's rules
  require of an infrastructure entry; a release build refuses the handler. The entry in
  `bench/httparena/` is one process with the four listeners and subscribes to every
  profile the infrastructure tier scores except the two HTTP/3 rows. The arena's validator
  passes 70 checks; in its harness on the bench box agensio is ahead of nginx on eight of
  the nine rows and level on the ninth, and ahead of or level with h2o on five of its six,
  behind only on the HTTP/2 baseline (`bench/results/httparena-lite-20260924-0147.md`).
- **Pre-compressed files are served**: a `name.br` or `name.gz` beside a cached file goes
  out with `Content-Encoding` and `Vary: Accept-Encoding` to a client whose
  `Accept-Encoding` takes it (q-values, `q=0` and `*` honoured, `br` on a tie), the file
  itself to any other; the twin is cached beside the file with its own ETag and
  Last-Modified, counts in the byte budget with it, is revalidated with it, and an older
  twin than its file is ignored as a build not redone. Conditional and Range requests work
  per representation on both protocols. `[cache] precompressed = false` turns it off.
  Motivated by HttpArena's static rows, where every request asks for `br` and nginx served
  the twins at a quarter of our bytes per response: in the arena's own harness on the
  bench box (`bench/results/httparena-lite-20260924-0147.md`, rerun section) static-h2 went
  from 304k to 955k req/s against nginx's 846k and static-tls from 269k to 687k against
  635k; the A/B against alpha.20 is flat on every HTTP/1 and HTTP/2 row.
- **Fixed: a heap use-after-free in the upstream streaming path** (FastCGI and proxy
  responses streamed to the client, `buffering = false` or past the temp-file cap): when a
  body ended short, the writer's inline completion closed the connection, dropped the body
  source and with it the last reference to the exchange while its own `pull` was still on
  the stack. Found by the sanitizer build under the integration suite; the exchange now
  holds itself alive for the length of the call.
- **HttpArena entry** (`bench/httparena/`): agensio packaged for the public HttpArena board
  (Dockerfile from the tag, the arena's port layout, `meta.json` subscribing to the pipelined,
  static-tls and static-h2 profiles) and a driver that runs the arena's own validator and lite
  benchmark on a developer machine inside Docker-in-Docker. First run against the nginx and
  h2o entries in `bench/results/httparena-lite-20260924-0147.md`: the validator passes, the
  pipelined row is level with nginx, and the static rows show the next step, pre-compressed
  `.br`/`.gz` siblings, since the arena asks for `br` on every static request.

## 0.1.0-alpha.20 (2026-09-24)

- **Fixed: a Grav site on the borrowed drupal preset served its backup** (2026-09-23,
  a live host): `logs/grav.log` was served and named the `backup/*.zip` next to it, which
  was served too, with the admin account and the signing salt inside. Three changes.
  **`app = "grav"`**, a preset from Grav's own nginx recipe: only `index.php` runs;
  `logs/`, `backup/`, `cache/`, `bin/`, `tests/` and `tmp/` are never answered, whatever
  they hold (the preset table gained whole-directory refusals, `never_served_directories`
  in the catalogue); `system/` and `vendor/` serve assets only; `user/` serves images,
  css, js and uploads while pages, accounts and configuration stay private (per-shield
  endings); the version fingerprints and composer files are 404; `site-install` fetches
  the `grav-admin` release; `site-create` detects Grav from `bin/grav` and
  `system/defines.php`. **`.log` and `.sql` are refused on every PHP preset's root and
  shields**, like `.inc` and editor backups (WordPress's `wp-content/debug.log` too).
  **`health` reports `preset_mismatch`**, a site whose files belong to another
  application than its `app` says, with the marker found and the `app` to set (the
  borrowed preset's refusals do not fit), and `site-create` warns the same way on a
  directory that already holds files; and **`archives_in_root`**, backup archives and
  database dumps under a served tree, the directories a preset never answers excepted.
  The integration suite serves a Grav fixture through both presets.
- **Fixed: `php_pool_resident` stayed silent for a pool left `static` on disk** after
  the configuration changed to `ondemand` (the same host: two such pools held 16 PHP
  processes and 681 MB). The finding now judges the pool file php-fpm runs and names a
  stale one as a warning with `agensio pools` plus a php-fpm reload as the fix; the root
  suite makes a file stale behind the configuration's back and checks both.
- HTTP/2 across a reload: a connection whose listener left the configuration, or that
  reached `max_requests_per_connection`, serves the stream in flight and only then sends
  its GOAWAY and closes, so no client has to read an answer behind a GOAWAY; a stream
  opened while the connection is leaving is refused (`REFUSED_STREAM`) so the client
  retries on a new connection. `tests/reload.sh` now drives both cases over HTTP/2 with an
  h2-library client: a connection that picks up the new generation at its next stream
  without a GOAWAY, and one on a removed listener that is served once more, told GOAWAY
  and closed.
- HTTP/2 performance pass (phase G, step G2): the four-worker comparison
  (`bench/results/h2-20260923-201044.md`: 1.59M req/s on h2c and 1.28M over TLS at ten
  streams per connection against nginx's 665k and 559k, every row ahead). **Idle
  connections cost less**, on both protocols: two seconds after its last request a
  connection sheds its buffers (the pooled HTTP/2 streams, the writer's buffers, and the
  receive buffer, whose pending read is cancelled and replaced by a readiness wait; the
  buffer comes back with the next bytes), the HPACK ring is made on a client's first
  insertion, at most four released streams stay pooled, and each worker trims the heap
  once a second after sheds or closes, since glibc keeps freed chunks mapped. Measured
  with 10,000 idle and 1,000 busy connections (`bench/h2/memory.sh`,
  `h2-memory-20260923-204605.md`): an idle HTTP/2 connection 19 KB (40 before; nginx 7.5,
  Caddy 35), an idle HTTP/1 connection 13 KB (25 before); busy, 90 MB against nginx's
  93 MB. The integration suite checks that a connection idle past the shed point still
  serves its next request on every protocol. Uploads through the WordPress and Drupal
  presets are exercised over HTTP/2 in the root suite.
- **Fixed: a heap read past the HTTP/2 receive buffer** after a connection error decided
  inside a frame handler (found by the sanitizer build under h2spec, which the release
  build survived by luck): the lingering close reset the buffer while the frame loop went
  on with its old position. The loop now stops the moment a close is decided. The
  integration harness keeps the server's stderr in `bench/tmp/server.err` so a sanitizer
  report is never discarded again.

## 0.1.0-alpha.19 (2026-09-23)

- **Generated pools default to `pm = "ondemand"`** with `pm.process_idle_timeout = 60s`
  (live host: every site with its own account kept 8 PHP processes resident around the
  clock, 150 to 200 MB per idle site). A child starts on the first request and exits after
  a quiet minute; `static` and `dynamic` stay available per site (`settings: {pm:
  "static"}`), and `static` is what a PHP benchmark should use. Existing pool files
  differ from the configuration until `agensio pools` rewrites them; `health` says so
  (`pools_stale`).
- **Kept upstream connections are closed after `idle_timeout`** (new option of `php = {}`
  and `proxy = {}`, default 30 s, 0 = never) from the pool's existing tick, so an
  `ondemand` child is not held open by an idle server and an origin with a short
  keep-alive timeout is never met dead.
- `health` `php_pool_resident`: every `static` or `dynamic` pool with the PHP processes
  it keeps and their memory (RSS and private, read from `/proc` on Linux), with the
  setting that frees it, so an agent asked why the machine is full has the number.

- **HTTP/2** (phase G, step G0; design in `docs/design-http2.md`): RFC 9113 with HPACK
  (RFC 7541) in agensio's own protocol layer, `src/http2/`, on every TLS listener through
  ALPN and, with `"h2c"` in the new `[server] protocols` key (`["h2", "h1"]` by default,
  Caddy's names; `"http/1.1"` accepted for `"h1"`), by prior knowledge on plain listeners. Every handler serves it: static files from the cache and disk, conditional
  and range answers, FastCGI, proxy, CGI, redirects, request bodies through DATA frames
  with windows that follow the site's body limit (uploads at the consumer's pace, not
  64 KB per round trip). The encoder uses static indexes and literals only, so a cache
  entry's headers are one HPACK block built at insert and copied per response; a
  worker's server and date pair is re-encoded once per second. Limits and defences
  built in from the first line: frame size, header list and compressed block sizes from
  `max_header_size`, CONTINUATION count, a glitch budget (PING, SETTINGS, empty frames,
  window-update dribbles, PRIORITY, frames on closed streams) with a graceful GOAWAY at
  three quarters, a reset counter that counts server-provoked resets too (Rapid Reset,
  MadeYouReset), no priority tree (RFC 9218 announced), stream and connection memory
  bounded by the windows and `max_header_size`. Every GOAWAY and RST_STREAM the server
  sends is an info line in the error log. `http2 = { max_concurrent_streams = 128 }`,
  `agensio ctl status` names each listener's protocols, requests log as `HTTP/2.0`,
  PHP sees `SERVER_PROTOCOL=HTTP/2.0`. HTTP/1.1 pays nothing: the hand-over sits behind
  the TLS handshake and the parser's 505 branch. Tests: RFC 7541's vectors and error
  cases, a Huffman table generated from the RFC text, `fuzz_hpack`, h2spec against both
  listeners (146 of 146 over TLS; on h2c the one case where an invalid preface is an
  HTTP/1 400), curl and an h2-library client in the integration run (the H2h coalescing
  check is live now), `bench/h2/run.sh` and `bench/ab.sh -2` (h2load). Measured, one
  worker on the Linux box: the HTTP/1 rows unchanged; HTTP/2 1 KB at 2.3 us plain and
  3.1 to 3.4 us TLS with one stream per connection, 1.6 to 1.8 and 2.0 to 2.1 us with ten
  (below HTTP/1); nginx 3.5 to 4.7 us on the same rows, Caddy 30 us. Large bodies over
  TLS: a DATA frame is exactly one record (16,375-byte payloads) and a file's frames are
  read with one preadv into a pre-framed chunk that is written as is, so the 10 MB stream
  costs 2017 us against nginx's 2771 and 100 KB at ten streams 20.5 against 28.4.

## 0.1.0-alpha.18 (2026-09-20)

- **Fixed, wordpress preset: backups of `wp-config.php` were served** (live report:
  `wp-config.php~`, `.bak`, `.save`, `.orig` and `.txt` answered 200 with the database
  password and the salts; the exact name was 404). Every name a preset never serves is
  now refused in every backup spelling within its directory, anchored on the name rather
  than on an ending: `name.bak`, `name~`, `name.txt`, `name-old`, `stem.bak`
  (`wp-config.bak`), `.name.swp`, `#name#`, in any case, whatever `hidden_files` says;
  `ads.txt` and the `/readme`, `/license` permalinks are untouched. `agensio -t
  --explain` and the presets catalogue state the rule; the MCP `presets_list` text too.
- **Fixed, every PHP preset: one shared refusal list.** WordPress's shields lacked `.inc`
  and the `~` backup form Drupal's had (live report: `x.inc`, `x.php~` under
  `wp-content/uploads` served as source). Every preset's root and shields now refuse
  `.inc` and editor backups (`.bak`, `.orig`, `.save`, `.swp`, `.swo`, `~`), and the
  root refuses the PHP spellings the `.php` suffix location does not take (`x.PHP`,
  `x.phtml` were served as source at a drupal or wordpress root; `x.php` still runs).
  The integration suite plants one table of spellings under every preset's shields and
  roots, and the backups of `wp-config.php`, `db.php` and `settings.php` in their
  directories, and asserts each is refused without a byte leaking.

## 0.1.0-alpha.17 (2026-09-20)

- MCP instructions: rule one, stated first: whatever a tool can do is done through the
  tool over the connection; a terminal command or a file edit is offered only when no tool
  covers the change (root's main file, a hand-written site file, root work handed back
  without the helper), with the reason and what follows. `config_reference`'s `via` is
  read as which tool does it.
- **Configuration reference for agents and administrators** (F11; live: the agent could
  not say how to change `workers`): one table of every key agensio reads, with type,
  default, meaning, whether a change applies on reload or needs a restart, who changes it
  (root in the main file, a site file, `site-create`, `settings`) and the section that
  explains it; `agensio keys [--markdown]`, `agensio ctl reference`, `GET
  /v1/config/reference` (with running values and the file they come from), MCP
  `config_reference`. `docs/keys.md` is generated from it and the integration suite
  fails when the file and the binary differ; the unit test fails when the parser reads a
  key the table lacks or a row names a section that does not exist. The bridge's
  instructions tell the agent to hand root's edits back as the exact line plus the
  reload or restart command, never claiming to have made them.

## 0.1.0-alpha.16 (2026-09-20)

- **Fixed: refused endings were matched case-sensitively and a trailing dot escaped
  them**, so `x.PHP`, `x.PhP` and `x.php.` under a shielded directory (Drupal's
  `files/`, WordPress's `uploads/`) were served as source (live report; nothing
  executed). The rule now ignores case and trailing dots on every shield and root, the
  PHP spellings gained `.pht`, `.phtm`, `.php3`, `.php4`, `.php6`, and the drupal preset
  refuses `~` backups too. Unit test of the rule and integration checks that plant every
  spelling under both presets and assert not a byte leaks.
- `health` `files_unreadable` picks its remedy from the example's defect: `chgrp` for a
  wrong group, `chmod -R g+r` for a right group without group read, both when both.

## 0.1.0-alpha.15 (2026-09-20)

- **Fixed, drupal preset: a missing file below `sites/default/files/` now reaches
  `index.php`** with its query string, so Drupal generates image-style derivatives
  (`?itok=`) and rebuilds aggregated css/js on first request; an existing file still
  serves statically, and PHP-like endings below `files/` stay refused (live report: a
  deleted derivative was a 404 from the server for ever, and every newly uploaded image
  would have been). The preset table's shield gained a fallback flag; `presets` lists
  the directory under `missing_reaches_front_controller`. The regression test deletes a
  derivative and an aggregate and asserts the front controller gets the URL.
- `site-create`: the log hand-over under `done` is now verified on disk (group and
  mode) and otherwise reported under `warnings` with the command; the server no longer
  logs "cannot chown" on every reload for a log that already has the right group, nor
  when the helper is the one handing it over (live report: a claimed step next to a
  warning that it failed).
- `health` `files_unreadable` names the owner and group instead of numeric ids.

## 0.1.0-alpha.14 (2026-09-20)

- **Fixed: uploaded files were unservable on every site with a site user** (live report:
  a WordPress video answered 404, no log line, no finding). PHP creates an upload in the
  pool's `tmp/`, which was `0700 user:user`, and `move_uploaded_file()` renames it into
  the document root; rename keeps the group, and a set-gid directory stamps only files
  created in it, so every upload arrived `0640 user:user`, unreadable by the server.
  `tmp/` is now `2750 user:<server group>`, like the document root, so an upload is born
  with the server's group. `agensio pools` (and the helper's pool apply) repairs an
  existing `tmp/` when run as root. **Existing uploads need one command per site**,
  e.g. `chgrp -R agensio /var/www/example.com/wp-content/uploads` (Drupal:
  `sites/default/files`); `health` now reports them as `files_unreadable` with that
  fix until it is done, sampling the preset's upload directory first. The root suite
  uploads through the php, wordpress and drupal presets and asserts the moved file's
  group and that it is served.
- **Fixed: the first POST after a php-fpm reload on a kept connection answered 502**
  (`closed_early`; a GET was retried on a fresh connection, a POST or an upload was not).
  A kept connection idle for longer than a pool tick (250 ms) is now checked with one
  non-blocking peek before a request is written to it, and a dead one is dropped for a
  fresh connection; a connection reused at once is not peeked, so the benchmark path pays
  nothing. Found by the new
  upload test in the root suite: the first upload after the pool was rewritten and
  php-fpm restarted failed exactly as the live report's upload did minutes after a
  settings change had reloaded php-fpm.
- `health`: `php_tmp_missing` / `php_tmp_not_owned` when a generated pool's private
  `tmp` or `sessions` directory is absent or not the user's: PHP then fails every upload
  and session silently, with nothing in the server's logs (live report). The root suite
  now uploads real files through a generated pool, in-memory and spilled bodies, and
  asserts `$_FILES` lands in the private tmp inside `open_basedir`, the moved file is
  byte-identical and the response after a large multipart body is complete; the docs say
  which directories the pool gives PHP.
- **Fixed: a request after a slow exchange could be parsed from stale bytes** (live
  report: one Firefox asset request logged as `GETGET /wp-admin/js/...` and answered
  405). The client-abort watch of a slow FastCGI or proxy exchange (E9) arms a read at
  the end of the request being served; the response then compacts the receive buffer,
  and when that read completed with the next request its bytes sat past the old offset
  while the count was added at the new one, so the parser saw the previous request's
  bytes first (a silent replay of a GET) and the new request's tail after. The read's
  landing offset is now tracked and its bytes moved to the buffer's end, with the
  invariant asserted in debug builds. Diagnostics: an unrecognised method token and a
  request line that does not parse are logged at warn level, hex-escaped. Tests: every
  split point of a request line on plain and TLS, 240 varied requests on one connection,
  two requests in one write, the exact trigger, a parser prefix test, the line in the
  fuzz corpus.

## 0.1.0-alpha.13 (2026-09-20)

- **Per-site limits through the control plane** (F10, live request: "raise the WordPress
  upload limit to 200 MB" could not be done without a terminal): `site-create` and
  `site-update` take `settings = {key: value}` (CLI `--set KEY=VALUE`, MCP `settings`)
  for `max_body_size` (now a site key too, driving the pool's `upload_max_filesize` and
  `post_max_size`; `[server] max_body_size` stays the default), `memory_limit`,
  `max_execution_time`, `max_input_time` (new pool key), `children`, `pm` and
  `max_requests`. Every value moves within the ceilings `[control] site_limits` sets
  (defaults 512MB, 512M, 300 s, 300 s, 32 children) and is refused above them naming the
  key, the value and the ceiling; every other ini name is refused as unknown, so
  `extra`, `open_basedir`, `sendmail_path` and the like stay in the file. `agensio ctl
  settings [NAME]`, `GET /v1/settings`, MCP `site_settings_list` publish the table with
  units, defaults, minimum, ceiling, cost and derivations, plus current values per site;
  `site NAME` reports each setting's value and source; the MCP `settings` schema is
  generated from the same table and a test asserts the three cannot drift. Answers list
  under `done` what was written and reloaded; `site-update` now applies the pool through
  the helper like `site-create` does.
- **A TLS connection serves only the names its certificate covers** (live report: with
  three sites and three certificates on one listener, a connection made with site B's
  certificate served site A's pages for `Host: A`). Host matching on a TLS connection is
  now bounded by the certificate presented at the handshake (CN, SAN DNS and IP entries,
  RFC 6125 wildcards): a Host outside it answers `421` with `Cache-Control: no-store`
  exactly like an unknown Host, a SAN or wildcard certificate covering several sites
  keeps them all reachable on one connection (the HTTP/2 coalescing case), a catch-all
  on TLS is bounded the same way, and a renewal or reload never changes what an open
  connection may serve. Plain listeners, unknown Hosts, missing Host and HTTP/1.0
  without Host are unchanged. Twelve integration checks, including the renewal-during-
  a-connection case; the HTTP/2 coalescing retry stays a written, skipped check.
- **Credential files are `0600` on every write path, and a writer validates before it
  answers** (live report: five ok answers produced a server `agensio -t` refused to start,
  because a `2750` site directory hands the server's group to every file, including the
  `wp-config.php` a `site-copy` had just written). The preset table now names each
  preset's `secrets` (`wp-config.php`; Drupal's `settings.php`, `settings.local.php`,
  `services.yml`), the hosting rule reads that list (Drupal was not covered before),
  `site-install` and `site-copy` create those files `0600` and report them under
  `secured`, check the rule on what they wrote, and compare the configuration's
  validation before and after: a new error answers `409` with `written: true` and the
  validator's message instead of ok. `presets` shows `secrets`.
- `health`: `php_fpm_hard_reload` when php-fpm.conf sets no `process_control_timeout`:
  the reload `site-create` and `agensio pools` trigger then kills PHP requests in flight
  on every site (live report: 502s on another site while a site was created); the fix
  is one line in php-fpm.conf, and `site-create`'s `done` entry says so.
- WordPress preset: the `wp-content` drop-ins `db.php`, `advanced-cache.php` and
  `object-cache.php` are answered 404 like `wp-config.php`; they run only inside
  WordPress's bootstrap and answered 500 when fetched directly (live report).

## 0.1.0-alpha.12 (2026-09-20)

- `site-copy NAME --from SUB --to SUB [--overwrite]` (MCP `site_copy`, `POST
  /v1/sites/NAME/copy`): one regular file of a site copied to another path of the same
  site as the site's account, for the drop-ins applications ship as templates
  (WordPress's `wp-content/db.php` from the SQLite plugin's `db.copy`, caching plugins'
  `advanced-cache.php`, Drupal's `settings.php`). Both paths take the install's walk
  (no `..`, no symlink on the way, no other account's directory); the destination's
  directory must exist; an existing destination needs `--overwrite` and its old size and
  mtime are reported; the new file gets the directory's pattern; written under a
  temporary name, so a refusal leaves nothing. Never across sites, never caller content,
  never a directory, no chmod or chown, and no option to relax any of that. With
  `site-create`, `site-install` and `--create-path` the WordPress-on-SQLite path now
  completes with zero terminal commands (the request that prompted it).

## 0.1.0-alpha.11 (2026-09-20)

- `site-install --path SUB --create-path` (MCP `create_path: true`): a plugin, theme or
  module goes into its own new directory below the site (`wp-content/plugins/NAME`,
  `web/modules/contrib/NAME`), created as the site's account with the parent's pattern,
  reached by a walk that refuses symlinks, `..` and another account's directories; a
  refusal removes what the call created; the answer lists `created`. `dry_run` now takes
  the same walk and reports `would_create` or the refusal instead of an unconditional ok
  (live report: the first plugin after a one-call site).
- WordPress preset: `readme.html` and `license.txt`, which name the installed version,
  are answered 404 like `wp-config.php` (from a live report: the first thing a
  vulnerability scanner reads).

## 0.1.0-alpha.10 (2026-09-20)

- **`site-install`** (F9): puts an application's files into a site's empty directory as
  the site's own account, from the preset's official archive (WordPress, Drupal;
  `--version`), any https URL, or an archive uploaded with the new `agensio ctl upload
  NAME [FILE]` (`uploads`, `uploads-delete`); MCP tools `site_install`, `uploads_list`,
  `upload_delete`. agensio's own extractor handles `.tar`, `.tar.gz` and `.zip` and
  refuses symlinks, hard links, devices, `..`, absolute paths, encrypted and zip64
  entries, bad checksums and oversize archives; the download is https only with every
  hop checked against a private-address fence; `--sha256` gates the whole thing; a
  refusal leaves the directory empty. Modes follow the target directory's own
  (`2750` gives `0640`/`2750`). `[control] install = false` turns downloads off and keeps
  uploads; `install_private` and `install_ca` are for internal mirrors and test beds;
  `upload_max` caps uploads (512 MB). The helper gained `app_install` (the child drops to
  the site's account before it reads a byte); without the helper the server installs as
  its own account into directories it owns. New dependency: zlib. Tests:
  `tests/install.sh` (root devbox, 22 checks), unit tests of the extractor and the fence,
  `fuzz_archive`, 17 integration checks.
- **Provisioning helper** (`[control] provision = true`, the default): a server started
  as root forks a small root helper before the privilege drop, and `site-create` then
  creates the account, lays out the directories, hands the site its log, writes the
  php-fpm pool and reloads php-fpm in one call, listing it under `done`; a change that
  needs a restart restarts the service after answering. The helper does exactly those
  five things, re-validates every argument, runs programs by absolute path without a
  shell, and refuses another site's directory, a symlink on the way, a system account.
  `docs/security-control-plane.md` states what a compromised server could and could not
  do through it; `provision = false` or a server not started as root keeps the previous
  behaviour of handing commands back.

## 0.1.0-alpha.9 (2026-09-20)

Sixth live report, all five items, on the way from a bare server to a working Drupal site.

- `site-create` and `site-update` report every prerequisite at once: `problems`, each
  with a `code` (`missing_account`, `missing_group`, `root_missing`, `root_unreadable`,
  `certificate_missing`) and its command, so one round of root work suffices.
- `dry_run: true` (`--dry-run` on the CLI) runs every check and returns the file that
  would be written, without writing or reloading.
- A site that adds a privileged port to a server that has dropped root answers
  `202 needs_restart`: the file is written and validated, `systemctl restart agensio`
  serves it. Before, the reload failed with what looked like a permission error.
- `next_steps` are separate commands: `agensio pools` exits 3 when it wrote files, and
  the `&&` that followed skipped the php-fpm reload exactly when it mattered.
- `site NAME` and `-t --explain` report a path answered 404 whatever exists on disk as
  handler `deny`, and a location lists the endings it `refuses`. Before, `settings.php`
  showed as `static`.
- `health` reports `log_not_readable_by_user` while a per-site log created by a reload
  is not owned by the site's group; a restart hands it over.
- The MCP `site_create` `app` options are asserted equal to what `presets_list` returns,
  so a new preset cannot ship unadvertised; the `app` description points at `presets_list`.

## 0.1.0-alpha.8 (2026-09-20)

- `presets`: `agensio ctl presets`, `GET /v1/presets` and the MCP tool `presets_list`
  describe every `app` value from the preset table (served root, which `.php` runs,
  refusals, directories that never run PHP, files never served).
- Every value that can reach a root command is validated first: account names must match
  `^[a-z_][a-z0-9_-]{0,31}$` and may not be a system account or a word for "none"; paths
  must be absolute and shell-safe. `user: "null"` is refused with the way to say "no
  account": `no_user: true` (JSON `null` still works; both together are refused). The MCP
  schema types `user` and `group`.

## 0.1.0-alpha.7 (2026-09-19)

- chore: update changelog for version 0.1.0-alpha.7
- feat!: strict host matching with 421, and SNI certificate selection per site
- fix: log sinks added by a reload, state directory access, 404 for refused paths, ctl help

**Breaking: strict host matching.** A site answers only the names in its `server_name`.
A request with any other Host, including the server's IP address, answers `421
Misdirected Request` unless the listener has a catch-all site (`server_name = ["*"]` or
`default = true`). Before, the first site on a listener silently served everything. If
your monitor checks the IP address, point it at the hostname or add a catch-all site.
The packaged default site on port 80 is a catch-all; port 443 has none unless you add one.

- TLS: each site on a listener gets its own certificate, selected by SNI (before, all
  sites shared the first site's certificate). A name no site lists is refused at the
  handshake; a client sending no name gets the catch-all's certificate or is refused.
- `status` names each listener's catch-all; `sites` marks catch-all sites; `site-create`
  warns when a listener has none.
- A log file added by a reload received nothing (per-worker buffers); fixed.
- `/var/lib/agensio` is 0751 so site users reach their own tmp/ and sessions/.
- Refused endings (`deny_suffixes`) answer 404 like hidden files.
- `agensio ctl --help`, and `--help` on every subcommand.

## 0.1.0-alpha.6 (2026-09-19)

- feat: implement PHP presets as data structure and enhance application routing

## 0.1.0-alpha.5 (2026-09-19)

- feat: enhance PHP presets for Laravel, Drupal, and WordPress
- Add A/B benchmark results and acceptance test for site creation
- docs: update installation instructions for Debian, Ubuntu, Fedora, and Arch

## 0.1.0-alpha.4 (2026-09-19)

- feat: enhance release workflow to upload RPM artifacts and add Fedora smoke tests

## 0.1.0-alpha.3 (2026-09-19)

- fix: update release workflow to use secrets for APT GPG key and enhance Arch package build process

## 0.1.0-alpha.2 (2026-09-19)

Packages and release automation; no change to the server itself.

- Debian package (`.deb`) and RPM built by CPack: binary in `/usr/sbin`, systemd unit,
  log rotation, `/etc/agensio` with a default site serving `/var/www/html`, the
  `agensio` service account and the `agensio-admin` group, start on first install when
  port 80 is free. Upgrades keep edited configuration files; purge keeps certificates
  and content. `tests/package.sh` exercises the whole cycle in a container.
- `packaging/rpm/agensio.spec` for COPR and `packaging/arch/PKGBUILD` for the AUR.
- GitHub Actions: `ci.yml` builds and tests on Ubuntu and macOS; `release.yml` builds
  both packages on every `v*` tag, checks the version against the tag, attaches the
  packages to the release and publishes a signed APT repository to GitHub Pages when the
  signing key secret is present.
- `scripts/release.sh` bumps the version everywhere, tags and pushes.
- `docs/install.md`: the package routes for Debian/Ubuntu, Fedora and Arch.

## 0.1.0-alpha.1 (2026-09-19)

First pre-alpha. Everything below is implemented and tested on Linux (Debian 13) and
macOS; Windows compiles but is not tested. Read `docs/install.md` before installing and
`README.md` for the known limitations.

### Serving
- Static files over HTTP/1.1 and HTTPS with an in-memory cache, sendfile, Range requests,
  conditional requests, per-site locations, `try_files`, path policies.
- PHP through FastCGI with presets for Laravel, Statamic (`laravel`), WordPress and plain
  PHP; per-site users with generated php-fpm pools and ownership rules checked by `-t`.
- Reverse proxy with WebSockets, upstream groups with passive health checks, TLS to the
  origin, header policy, CGI; presets and examples for Node, Rails, Rocket.Chat,
  ThingsBoard.
- Access log in combined or JSON format, error log, `SIGUSR1` reopen.

### Operating
- `agensio reload` (or `SIGHUP`): configuration switched between requests, nothing in
  flight interrupted, a bad file refused with the old configuration kept.
- `tls = "auto"`: built-in ACME client (HTTP-01) for Let's Encrypt or any RFC 8555 CA,
  renewal at a third of the lifetime left, the new certificate picked up through the
  reload path.
- `redirect = "https"` or `redirect = "https://www.example.com"` for HTTPS-only and
  canonical-host setups.
- Start as root, bind, then drop to `server.user`; per-site logs owned for the customer.

### Control plane
- `[control]`: a unix socket with peer-credential roles (admin, operator, viewer) and an
  audit log. Read commands: status, sites, site, validate, logs, health. Changes:
  reload, logs-reopen, site-create/update/disable/enable/delete, cert-renew, every one
  behind an explicit confirmation and a reason.
- `agensio ctl` for shells and panels.
- `agensio mcp`: a Model Context Protocol server on stdio for AI agent hosts, locally
  or over SSH, with the same tools gated by role; a guided site creation that asks for
  the decisions it needs and hands root work back as commands.
- Security review of the control plane in `docs/security-control-plane.md`.

### Performance
Single worker on Linux against nginx: about 1.5x less CPU per plain request, 1.3-1.6x
on TLS, proxying 13-46 % cheaper; numbers and method in `CLAUDE.md` and `bench/results/`.
