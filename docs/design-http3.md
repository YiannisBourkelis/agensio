# Design: HTTP/3 and QUIC (phase I)

Status: accepted 2026-09-24 as proposed (every decision of section 12); built the same
day: the UDP measurement of 6.1, the lifts of I0 (the codec, the assembler, the pool;
`ab.sh -2` 0.96 to 1.04) and the first slice of I1, a GET over HTTP/3 on one worker with
memory and file bodies and request bodies, so that the benchmark and the profile ran
early (8.5): 1.22 to 1.25M req/s on one worker under the arena's `baseline-h3` load at
0.61 us of CPU per request, the devbox's nginx 402 to 433k at 2.32 us on the same load;
1.77 to 1.81M and 98 to 108k on the arena's two rows in its own harness.
What the slice leaves for I1b, I1c, I2 and I3 is listed at the end of section 11.
It replaces the roadmap's phase I text (ngtcp2 + nghttp3 glue) with a transport of our
own, for the reasons of section 3, and reuses the HTTP/2 layer where the two protocols
are the same protocol (section 4). The RFCs it cites are in `docs/rfc/`.

## 1. Goals

- Serve HTTP/3 (RFC 9114) over QUIC version 1 (RFC 9000, 9001, 9002) with QPACK (RFC 9204)
  on every TLS listener whose `protocols` name `h3`, over UDP on the listener's port
  number, for every handler agensio has (static files from the cache and disk, FastCGI,
  proxy, CGI, redirects, error pages, the ACME challenge), and advertise it with `alt-svc`
  from the HTTP/1.1 and HTTP/2 answers of that port. The control socket stays HTTP/1.
- The fastest and cheapest of its kind: CPU per request and memory per connection below
  nginx's and Caddy's HTTP/3 on the same box, with one worker and with several, measured
  with h2load over QUIC the way phase G measured HTTP/2. On the arena, whose two HTTP/3
  rows are h2load at 64 connections with 64 streams each (`baseline-h3`, `static-h3`), the
  board today reads nginx 4.85M and 361k req/s, Caddy 361k and 22k; h2o's entry has no
  HTTP/3. Both rows above nginx's is the target.
- HTTP/1.1 and HTTP/2 unchanged: the A/B gate on every step, and the code the two
  protocols share lifted out of `src/http2/` first as a pure refactor, flat on the h2 rows.
- One transport written once, the way phase G made a protocol layer: the same `Stream`
  contract (design-http2 5.1), the same field rules and request assembly, the same pooled
  streams, budgets and timeouts, the same prebuilt-block pattern with a QPACK twin, so that
  HTTP/3 is a third protocol directory and QUIC a fourth, not a second server.
- Correct on real networks, not only on loopback: loss, reordering, path MTU, an address
  that changes under a NAT, amplification. Proven by the QUIC interop runner and a
  loss-injecting harness in the suite, not by the benchmark.
- Secure against the published QUIC and HTTP/3 attack classes, every limit a number in
  this document and a test in the suite, as phase G did (section 9).

Not in phase I: 0-RTT (replayable; an opt-in later, for GET and HEAD), active migration
and `preferred_address`, ECN, server push, QUIC datagrams (RFC 9221) and WebTransport,
CONNECT over HTTP/3, HTTP/3 to origins, QUIC version 2 (RFC 9369, a relabelling of
version 1, cheap once version 1 is right), the arena's `gateway-h3` row (our proxy over
HTTP/3 works the day HTTP/3 does, since the proxy handler consumes a `Stream`; the row
needs the gateway tier's compose file, a separate entry).

## 2. What the other servers do

| Server | Transport | Where it spends | Several workers | What it teaches |
|---|---|---|---|---|
| nginx 1.25+ | its own (`src/event/quic/`), the OpenSSL 3.5 QUIC TLS API in recent releases or a hook into older OpenSSL's message callbacks | one `sendmsg` per packet unless `quic_gso on` (off by default); EVP per packet; the `SSL` object kept for the connection's life; `http3_stream_buffer_size` 64 KB per stream | `reuseport` sockets, one per worker, the kernel's 4-tuple hash; an address change reaches the wrong worker unless `quic_bpf on`, an eBPF program loaded as root with a map of connection ids | the arena's entry runs the defaults plus `Alt-Svc`: 4.85M and 361k on the board, at 31 and 50 cores |
| Caddy 2 (quic-go) | quic-go, Go's `crypto/tls` | GSO and ECN on by default; per-packet allocations and the collector | one socket, goroutines | 361k and 22k on the board: a transport in a managed language costs thirteen times nginx's on the same row |
| h2o (quicly) | quicly over picotls; "fusion", an AES-GCM in AVX2/VAES that encrypts the payload and computes the header-protection mask in one pass | GSO; the cheapest per packet of the C servers | one socket per thread; the thread's number inside the connection id; a packet that lands on the wrong thread is forwarded | the arena entry does not wire QUIC up, so the HTTP/3 rows have no h2o number |
| HAProxy 2.6+ | its own | GSO in the 3.x releases, CUBIC by default, BBR optional | a connected UDP socket per connection by default (`tune.quic.socket-owner connection`), so the kernel demultiplexes; per-thread listener sockets otherwise | congestion control is a table, not an architecture |

Measurements published since 2020 (Fastly's, the EPIQ workshops') put QUIC at two to
three times the CPU of TLS over TCP per byte when the server sends one packet per
syscall and encrypts one packet at a time: the kernel does segmentation, checksums and
retransmission for TCP, and userspace does them for QUIC. The rows above say the same:
the servers that win use GSO and one crypto pass per packet. Our HTTP/2 result came from
owning the byte path end to end (one buffer per write cycle, the answer built at respond,
prebuilt blocks, the request's rules once per table entry); for QUIC the byte path also
contains the packets, the acknowledgements and the retransmissions, so owning it matters
more, not less.

## 3. Library or our own code

| Option | What it gives | What it costs | Verdict |
|---|---|---|---|
| A. Own QUIC, HTTP/3 and QPACK; OpenSSL 3.5 for the TLS 1.3 handshake through its QUIC TLS API (`SSL_set_quic_tls_cbs`) and for the primitives (HKDF, AES-GCM, ChaCha20-Poly1305, AES-ECB and ChaCha20 for header protection) | the packet is built in the datagram buffer and encrypted from the response's bytes in one pass; every buffer, limit and timer ours; batching across connections per worker; the pool, the budgets and the request assembler of HTTP/2 reused; no new dependency (OpenSSL is already the TLS library; 3.5 is trixie's, brew's and the devbox's) | about 5,000 lines for the transport and 1,800 for HTTP/3 and QPACK, plus tests; the correctness of loss recovery and congestion control is ours to prove, on networks the benchmark never sees | **proposed** |
| B. ngtcp2 + nghttp3, the roadmap's plan | ten years of interop, the crypto helper for the same OpenSSL API, curl's stack | two libraries of about 50,000 lines of C to vendor and build (Debian ships `libngtcp2-crypto-gnutls`, not the OpenSSL backend); packets written one at a time into our buffer (`ngtcp2_conn_writev_stream`) but stream data copied into the library's buffers and headers delivered per callback and copied again, allocations per stream and packet through `ngtcp2_mem`, an HTTP/3 encoder that runs per response with no prebuilt sections: the same costs section 4 of the HTTP/2 design measured and rejected, now on the packet path too | rejected for the runtime; nghttp3 kept in the test bed as the QPACK oracle, as nghttp2 is for HPACK |
| C. OpenSSL 3.5's own QUIC server (`SSL_new_listener`, `SSL_accept_stream`) | already linked, Apache 2.0 | a complete stack that wants the socket (a datagram BIO), its own polling and timing (`SSL_handle_events`, `SSL_poll`), an `SSL` object per stream, no GSO, no control of packetisation or acknowledgements; OpenSSL's own release notes present the server side as new in 3.5 with performance work to follow | rejected for the runtime; it is the QUIC client inside the devbox's curl, so it is in the test bed anyway |
| D. msquic | production-grade, OpenSSL-based | its own worker threads and datapath beside ours: a connection's state touched by two threads, which the code rules forbid; the HTTP/3 layer would still be ours | rejected |
| E. quiche (Rust, BoringSSL), lsquic (BoringSSL), quicly (picotls) | fast | a second TLS library or a second toolchain in the build | rejected |

Proposal: **A**. Three reasons beyond the table. First, the design of A is the design of
phase G continued: the transport is a writer that produces datagrams instead of `writev`
buffers, the acknowledgement state is what the kernel kept for TCP, and everything above
it is the code we have. Second, the OpenSSL 3.5 QUIC TLS API is exactly the seam the
other stacks use (ngtcp2's `crypto_ossl`, recent nginx, curl) and it is small: six
callbacks (handshake bytes out, handshake bytes in, a secret per level and direction, the
peer's transport parameters, an alert) and two setters. Third, a third of the transport
is RFC 9002's pseudocode transcribed (loss detection, PTO, NewReno), which is the
part that looks large and is not.

The risk is correctness on real networks, and the mitigations are section 9.2: the QUIC
interop runner, which is the industry's conformance harness for exactly this (our server
against five client stacks under simulated loss and reordering), a loss-injecting proxy in
the integration suite, five fuzzers, one of them differential against nghttp3, an attack
suite, sanitizer runs and the `security-review-cpp` checklist on every file.

Cost estimate, lines of C++: UDP I/O, steering and the send batch 500; packets, varints,
transport parameters, frames 700; keys and the TLS glue 600; acknowledgements, loss
recovery, congestion control, pacing 900; connection (handshake, ids, close, timers,
address change) 1,500; streams and flow control 600; HTTP/3 framing and control streams
400; QPACK 900; `Http3Connection` 700. About 6,800, against 4,300 in `src/http2/`
today; tests, fuzzers, the loss proxy and the attack suite about half as much again.

## 4. What is reused and what moves

The rule is the one phase G set: the request core sees a `Stream`, nothing else. The
table says what HTTP/3 takes as is, what is lifted out of `src/http2/` so both protocols
call one copy, and what gets a twin.

| Part | Today | Phase I | Why |
|---|---|---|---|
| `core/stream.hpp`, `request.hpp`, `response.hpp`, `body.hpp`, `headers.hpp`, `Dispatcher`, `Router`, every handler, the access log, `ConnectionInfo`, `trusted_proxies` | protocol-independent | unchanged | the contract of design-http2 5.1 |
| `core/fields.hpp` | the RFC 9113 / 9114 field rules, written for both | unchanged | RFC 9114 4.2 has the same rules by reference |
| Huffman coding, prefix integers, `DynamicTable` with its `checked` marks (`http2/hpack.*`) | HPACK's | lifted to `src/http/field_codec.hpp/.cpp`; `hpack.*` keeps the 61-entry static table, the representations, `Encoder` and `Decoder` | QPACK uses HPACK's Huffman code and integer form (RFC 9204 4.1); the table ring and the rules-once mark are the same object with another index rule |
| Request assembly: the decode sink (pseudo-headers, the rules once per entry, `host`, cookies), the post-decode checks, the fields of interest by length, `content-length` (`Http2Connection::begin_request`) | inside the HTTP/2 connection | lifted to `src/http/request_assembly.hpp` as a struct fed by either decoder, each connection mapping its outcome to its own error codes | one copy of the 2021 smuggling defences, one set of tests |
| The pooled stream table (`open_stream`, O(1) `release` by slot, the pool up to the concurrency limit, the idle shed) | `Http2Connection` | `src/http/stream_pool.hpp`, a template over the stream type | measured shape (design-http2 7.3); the same numbers for HTTP/3 |
| The body source behind `Request::body` (`H2Stream::BodySource`, `BodyOwner`) | HTTP/2's DATA frames | a template whose owner returns credit its own way (WINDOW_UPDATE there, MAX_STREAM_DATA and MAX_DATA here) | one pull path for handlers |
| The budgets (glitches, resets, rates) and the timeouts (`since` per phase, the tick, the write-stall rule) | constants and members of `Http2Connection` | `src/http/budgets.hpp`, the same constants | the attacks are the same attacks over another transport |
| `CacheEntry::h2_block`, `ErrorPage::h2_headers`, `Response::prebuilt_h2` and the sites that fill them (`handlers/static.cpp`, `response.cpp`, `upstream_common.cpp`) | HPACK tails | an `h3_block` / `h3_headers` / `prebuilt_h3` twin at each site, one line each; the writer picks by protocol | a QPACK section built from the static table alone is as state-independent as the HPACK one (RFC 9204 3.1) |
| `hpack::Encoder` (design-http2 6.2.1: server, date, content-type through a small dynamic table) | HTTP/2's head | `qpack::Encoder` with the same interface and memo logic, over the encoder stream (7.2) | the head from 40 bytes to 8 is the same win as in HTTP/2 |
| TLS contexts, the SNI callback, `CertNames` per context (`server.cpp`) | per listener | the UDP listener uses the TLS listener's contexts and names; its ALPN offers `h3` only | one certificate store |
| `http2/frame.hpp`, `writer.hpp`, `settings.hpp`, `tls_stream.hpp` | HTTP/2 over TCP | not reused: QUIC's framing, packetisation and TLS integration are different in kind | |

Gate for the lifts (step I0): `bench/ab.sh <tag> -2` flat on every row, the unit and
integration suites and h2spec unchanged. The lifts are pure refactors and come first, on
their own, so that any movement on the h2 rows has one possible cause.

## 5. The layers

### 5.1 The contract, fulfilled by `Http3Connection`

The eight items of design-http2 5.1, in HTTP/3 terms:

1. It owns the transport: a `QuicConnection` (6), whose datagrams arrive through the
   worker's UDP socket (6.1); it counts itself in `Worker::connections`.
2. It produces `Stream`s: a `Request` whose views point into the stream's arena (decoded
   into the connection's scratch first, copied at its exact size, as HTTP/2 does since
   2026-09-24), the request body as a `StreamBody` fed by the QUIC stream's ordered data,
   `ConnectionInfo` filled once (the peer's address, `HTTP/3.0` as the protocol).
3. It drives the dispatcher exactly as `Http2Connection::dispatch` does.
4. It writes a `Response` in its framing: a HEADERS frame whose QPACK section is the
   status, the worker's server and date pair, the response's `prebuilt_h3` tail and the
   extra fields, then DATA frames, FIN on the QUIC stream; the body from memory, a file
   or a `StreamBody` pulled one chunk at a time within the stream's send credit.
5. It applies the server's limits in its terms: `max_header_size` is the field section
   limit and the stream's first receive window, `max_body_size` the window raised for a
   declared body, `idle_timeout` the QUIC idle timeout, `body_timeout` the wait between
   DATA, `max_requests_per_connection` the GOAWAY, `max_concurrent_streams` the
   bidirectional stream limit.
6. It refreshes its generation at each new stream and retires (GOAWAY, then
   CONNECTION_CLOSE when the streams are done) when its listener leaves the configuration.
7. It logs each request through `WorkerLogs` with `HTTP/3.0`.
8. It reports a client abort (RESET_STREAM or STOP_SENDING) to the exchange in flight.

### 5.2 Source layout

```
src/http/                 shared by HTTP/2 and HTTP/3 (step I0)
  field_codec.hpp/.cpp    Huffman, prefix integers, DynamicTable (with the rules-once marks)
  request_assembly.hpp    the field sink and the post-decode rules, the fields of interest
  stream_pool.hpp         the active table, the pool, the slot release, the shed
  body_source.hpp         the pulled request body over an owner that returns credit
  budgets.hpp             the glitch and reset counters, the rate windows, the constants
src/quic/                 the transport (RFC 8999, 9000, 9001, 9002)
  varint.hpp              variable-length integers (fuzzed with the packet parser)
  packet.hpp              long and short headers, packet numbers, coalescing, Version Negotiation, Retry
  frames.hpp              the 22 frame types: encode, decode, which level may carry which (fuzzed)
  transport_params.hpp    RFC 9000 section 18 (fuzzed)
  crypto.hpp/.cpp         initial secrets, the key schedule, AEAD seal and open, header protection,
                          key update, the Retry integrity tag, the AEAD limits
  tls.hpp/.cpp            the OpenSSL 3.5 QUIC TLS API glue: the six callbacks, ALPN, SNI
  ack.hpp                 received ranges, ACK frame generation and its timer
  recovery.hpp/.cpp       sent-packet records per space, RTT, loss detection, PTO, NewReno (CUBIC later), pacing
  stream.hpp              a QUIC stream's send and receive state, the gap map, credits
  cid.hpp                 connection ids (the worker byte), the stateless reset tokens, the per-worker table
  udp.hpp/.cpp            the per-worker socket, recvmmsg with GRO, sendmmsg with GSO, the reuseport program
  connection.hpp/.cpp     QuicConnection: handshake, packets in, frames, the packetiser, timers, close
  timer_heap.hpp          the worker's deadline heap (6.8)
src/http3/                the application protocol (RFC 9114, 9204)
  frame.hpp               HTTP/3 frames, incremental per stream (fuzzed)
  qpack.hpp/.cpp          the 99-entry static table (generated), decoder with the dynamic table and
                          both instruction streams, the encoder (static first, dynamic in I3)
  stream.hpp              H3Stream: the embedded Stream, the arena, the request body, the response progress
  connection.hpp          Http3Connection: control streams and SETTINGS, request streams, responses, GOAWAY
tools/gen-hpack-tables.py extended for the QPACK static table
tests/fuzz/fuzz_quic_packet.cpp, fuzz_transport_params.cpp, fuzz_qpack.cpp (differential), fuzz_h3_frame.cpp, fuzz_quic_conn.cpp
tests/quic-lossy.py       the loss, reorder and delay proxy for the integration suite
tests/h3-attacks.py       the attack suite of section 9 (aioquic)
bench/h3/run.sh, profile.sh, memory rows; bench/quic-interop/ (the interop runner, Docker)
```

### 5.3 What changes outside the new directories

| Where | Change | Cost to HTTP/1 and HTTP/2 |
|---|---|---|
| `server.hpp/.cpp` | `Listener::h3`; a UDP socket per worker per h3 listener (6.1), opened where the acceptors are, kept across reloads like them; the reuseport program on Linux | none on the TCP paths |
| `config.*`, `control/reference.cpp`, `docs/keys.md` | `h3` in `protocols`; the `http3` table (section 10) | none |
| `http1/writer.hpp`, `http2/writer.hpp`, `http2/hpack.*` | the listener's prebuilt `alt-svc` line inside the HTTP/1 writer's fast path and an HPACK encoder memo for HTTP/2 on TLS listeners that also speak h3 (7.4) | one more head buffer on those listeners' HTTP/1 answers, one index byte on their HTTP/2 answers; listeners without h3 pay two empty tests |
| `cache.hpp`, `response.hpp/.cpp`, `core/response.hpp`, `handlers/static.cpp`, `upstream_common.cpp` | the QPACK twins (section 4) | the miss path and startup only |
| `core/request.hpp` | `Request::protocol` takes `HTTP/3.0` | none |
| `CMakeLists.txt` | `AGENSIO_HAS_QUIC` when OpenSSL has `SSL_set_quic_tls_cbs` (3.5+); without it the build has no `h3` and says so at `-t` | none |
| the MCP texts, `docs/configuration.md` (section 17), `docs/security-control-plane.md` | as section 10 | none |

## 6. QUIC (`src/quic/`)

### 6.1 UDP I/O and worker steering

**Sockets.** On Linux every worker opens its own UDP socket per h3 listener, bound with
`SO_REUSEPORT` (the group's index is the worker's number, because the workers bind in
order and a listener's sockets are only ever closed together), `UDP_GRO` on, `IP_PKTINFO`
/ `IPV6_RECVPKTINFO` so a wildcard bind answers from the address the packet came to,
`IP_MTU_DISCOVER = IP_PMTUDISC_PROBE` (the DF bit, no kernel fragmentation: 6.7 does path
MTU discovery), receive and send buffers raised to 4 MB. Elsewhere (macOS, BSD, Windows:
no kernel steering for UDP groups) one socket per listener on worker 0 serves every
HTTP/3 connection of that listener on worker 0, the control socket's precedent; the
platform is not benchmarked and the note stays in the docs until someone measures it.

**Receiving.** One `async_wait(wait_read)` per wake-up, then a `recvmmsg` loop into the
worker's 32 slots of 64 KB until EAGAIN (a GRO message holds several datagrams of one
size, the size in its control message); one re-arm per wake-up, amortised over the batch
(the D1 finding that a wait costs an
`epoll_ctl` holds; a speculative
`async_receive_from` costs one `recvmsg` returning EAGAIN instead, and I3 measures both).
Each datagram is split into its coalesced packets; each packet's destination connection
id is looked up in the worker's table (6.4); a packet for a connection of this worker is
handed to it; an Initial for an unknown id may create a connection (6.3); a short-header
packet for an unknown id gets a stateless reset (rate-limited, 6.4); everything else is
dropped. The connections touched by the batch are noted in a list.

**Sending.** After the batch, each touched connection produces its datagrams (6.7) into
the worker's send batch: an array of `mmsghdr` over one buffer, consecutive datagrams of
one size to one peer folded into one message with a `UDP_SEGMENT` control message (the
kernel splits it: one syscall for a 64 KB burst), then one `sendmmsg`. A kernel or
interface that refuses GSO (EIO on some virtual interfaces) turns it off for that socket
after the first refusal, with a log line, and the batch is resent one datagram per
message. EAGAIN keeps the rest of the batch and arms `async_wait(wait_write)`; a
connection whose datagrams wait is not asked for more until the socket drains. This is
the HTTP/2 rule "a read's answers are one send" (design-http2 6.6) at the worker level:
a wake-up's answers for every connection are one syscall.

**Measured (2026-09-24, `bench/udp/run.sh`, `bench/results/udp-20260924-140715.md`, an
echo server on one core against a closed-loop client on four, loopback, sixteen flows
with eight datagrams in flight each; CPU is the server's user and system time per
datagram received):**

| server loop | client | 100-byte datagrams | 1,200-byte datagrams | datagrams per syscall |
|---|---|---|---|---|
| `async_receive_from` per datagram, `send_to` per reply (the textbook loop) | plain | 1.45 us, 691k/s | 1.60 us, 626k/s | 1 |
| Asio's speculative read for the first datagram, `recvmmsg` for the rest, `sendmmsg` | plain | 1.32 us | 1.43 us | 63 |
| `async_wait`, `recvmmsg`, `sendmmsg` | plain | 1.30 us | 1.42 us | 64 |
| the same with UDP_GRO | GSO bursts | 0.98 us, 1.02M/s | 1.08 us, 928k/s | 128 |
| the same with UDP_GRO, replies as GSO messages | GSO bursts | **0.55 us, 1.81M/s** | **0.64 us, 1.55M/s** | 128 |

Three findings. (1) Batching the syscalls alone saves a tenth: the kernel's per-datagram
path (socket lookup, skb, the loopback transmit, the softirq) is the cost, not the
syscall. (2) GRO and GSO are what remove it, because the kernel then pays that path
once per coalesced message: receiving with GRO takes 1.30 to 0.98 us, sending the
replies as GSO messages takes it to 0.55, 2.6 times cheaper than the textbook loop;
h2load sends its bursts with GSO (`--no-udp-gso` switches it off), so the arena's
traffic has this shape. (3) Asio's receive operations cannot return the GRO control
message (the segment size), so a socket with GRO on must be read with `recvmmsg` after
`async_wait`: the speculative variant answered a coalesced message as one datagram and
collapsed (1,160 datagrams per second, every burst timed out). The textbook loop also
showed the inline-completion hazard of every speculative Asio read: with an immediate
executor and a client that never lets the queue empty, each completion re-arms and
completes inline until the stack overflows; the bench needed the yield budget of
`Connection::finish_response` (a post every 64 completions) to run at all. Decision:
`async_wait`, `recvmmsg` with GRO, `sendmmsg` with GSO, a bound per wake-up, the
send batch per worker.

**Steering by connection id** (built 2026-09-24 as described: `quic::Endpoint::attach_steering`,
six classic BPF instructions; a 4-worker run spread 64 connections 14, 20, 16 and 14). Our connection ids carry the worker: byte 0 is the
worker's index, bytes 1 to 7 are random (6.4). A classic BPF program attached with
`SO_ATTACH_REUSEPORT_CBPF` (no privilege, Linux 4.5+, six instructions: load the first
byte of the UDP payload, branch on the header form, load the first byte of the
destination connection id at offset 1 for a short header or 6 for a long one, return it)
makes the kernel deliver a packet to the socket whose index that byte names; a value at
or above the group's size, which is what a client-chosen Initial id gives, falls back to
the kernel's 4-tuple hash, deterministic for that client, and the worker that takes the
Initial answers with an id that names itself, so every later packet, including one from
a rebound NAT address, reaches the owner. nginx needs eBPF loaded as root and a map for
the same; the worker byte makes the map unnecessary. Where the attach fails (a kernel
without the option, a hardened container), the hash alone routes a connection correctly
until its address changes, and a packet whose id names another worker is forwarded to it
(one copy and one post to the owner's loop, only then). The forwarding path also serves
the single-socket platforms, so there is one code path for a misrouted packet.

### 6.2 Packets, keys and the TLS glue

**Packets** (RFC 9000 section 17, RFC 8999): long headers (Initial with its token,
0-RTT, Handshake, Retry; version, both ids up to 20 bytes, a length, coalescing by that
length) and short headers (our 8-byte id, the key phase bit, the spin bit ignored); header
protection removed with the sample at packet-number offset plus four (AES-ECB or ChaCha20,
one block); the packet number decoded against the largest received (RFC 9000 appendix A);
the AEAD opened with the nonce `iv XOR pn` and the header as associated data. A failed
tag or a length past the datagram drops the packet, the tag counted against the
integrity limit of the AEAD (RFC 9001 6.6, 2^52 for AES-GCM,
2^36 for ChaCha20: the connection closes at the limit); reserved header bits set after
protection is removed are PROTOCOL_ERROR (RFC 9000 17.2). Frames are parsed per packet
against the table of which level may carry which (RFC 9000 12.4); a violation is a
connection error. The version field accepts 1; any other value in a datagram of at least
1,200 bytes gets a Version Negotiation packet listing 1 and one random reserved value
(0x?a?a?a?a, RFC 9000 15), smaller datagrams nothing.

**Keys** (RFC 9001): the Initial secrets from the client's destination id and the
version-1 salt through HKDF-SHA256; a `Keys` object per level and direction holding
key, iv and header-protection key, an `EVP_CIPHER_CTX` initialised once with the key
(per packet only the nonce, the associated data, one update from the source into the
datagram buffer, the final and the tag: no key schedule per packet) and one for header
protection. AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 by the negotiated suite.
Initial keys are dropped when the first Handshake packet is sent or received, Handshake
keys with HANDSHAKE_DONE; the 1-RTT pair keeps the next generation for key updates (6.9)
and the AEAD's confidentiality counter. Test vectors: RFC 9001 appendix A (the client and
server Initials, the Retry tag, the ChaCha20 short header) as unit tests.

**The TLS glue** (`quic/tls.*`): one `SSL` per connection from the listener's context,
TLS 1.3 only, `SSL_set_accept_state`, `SSL_set_quic_tls_cbs` with our six callbacks and
`SSL_set_quic_tls_transport_params` with our encoded parameters. The callbacks: `crypto_send`
appends handshake bytes to the CRYPTO send buffer of the current write level (the level
of the last write secret yielded), consumed by the packetiser; `crypto_recv_rcd` hands
OpenSSL the contiguous prefix of the level's received CRYPTO data (a gap map per level,
16 KB buffered at most, RFC 9000 7.5 requires 4 KB) and `crypto_release_rcd` advances it;
`yield_secret` derives the level's keys for that direction; `got_transport_params` parses
the peer's; `alert` closes the connection with `0x100 + alert`. `SSL_do_handshake` runs
whenever CRYPTO data arrived; when it reports the handshake done we send HANDSHAKE_DONE,
the session tickets OpenSSL emits arrive through `crypto_send` at the application level
and go out as 1-RTT CRYPTO frames, and once they are acknowledged the `SSL` object is
freed: QUIC's key update is HKDF from our own secrets ("quic ku"), and nothing after the
handshake needs the TLS state (no renegotiation, no post-handshake authentication). The
SNI callback and the certificate names are the listener's (`select_certificate`); the ALPN
callback offers `h3`, and a client without ALPN gets the `no_application_protocol` alert
as the RFC requires. The API is OpenSSL 3.5's (April 2025; the devbox, trixie and brew
have 3.5.7); a build against an older OpenSSL has TLS, HTTP/1 and HTTP/2 and no `h3`.

### 6.3 Handshake, address validation, Retry

A client's Initial (at least 1,200 bytes, version 1, a destination id of at least 8
bytes; anything else dropped) for an id this worker does not know creates a connection
when the worker's half-open count is under its budget (1,024): the `SSL`, the Initial
keys, our source id (6.4), the stateless reset token, the transport parameters
(section 10 has the values), the CRYPTO data into the Initial level and the handshake
starts. Until the address is validated, what we send is capped at three times what we
received from it (RFC 9000 8.1, the anti-amplification limit); a packet protected with
Handshake keys validates it (the client proved it received our Initial), as does a
valid token. Our Initial datagrams are padded to 1,200 bytes (RFC 9000 14.1), and
Initial, Handshake and 1-RTT packets are coalesced into one datagram while the handshake
lasts, so a handshake is two datagrams from us on a clean path.

**Retry** (RFC 9000 8.1.2) costs no state: a Retry packet carries a new source id (ours,
naming this worker) and a token sealed with AES-128-GCM under a key the process derives
per hour from the server secret, holding the client's address, the time and the original
destination id; a client that comes back with the token within ten seconds from that
address gets its connection, with `retry_source_connection_id` and
`original_destination_connection_id` set as the RFC demands, and its address counts as
validated. `http3.retry = "auto"` sends Retry when the worker's half-open count passes
half its budget, `"always"` always (a deployment under attack), `"never"` never. At the
full budget further Initials are dropped. NEW_TOKEN for later connections is an I4 item.

The handshake must finish within `idle_timeout`; the Initial and Handshake spaces have
their own PTO (6.5) so a lost ServerHello is resent on time; a Handshake packet from a
peer whose address changed during the handshake is ignored.

### 6.4 Connection ids and stateless reset

Ours are 8 bytes, byte 0 the worker's index (6.1) and seven random bytes from the
worker's own generator; the worker's table is an open-addressed hash of the 8 bytes
(the id is its own hash) to the connection, several ids per connection, no shared state.
We issue as many as the peer's `active_connection_id_limit` allows, at most four, at
the handshake's end (NEW_CONNECTION_ID with their stateless reset tokens) and one more
each time the peer retires one; the peer's retirements (RETIRE_CONNECTION_ID) beyond the
ids we issued, or of a sequence we never used, are a protocol error. The peer's ids we
keep at most four (our advertised limit); a fifth active one is
CONNECTION_ID_LIMIT_ERROR. A peer may use a zero-length source id (common in clients);
our short headers then carry no destination id at all.

The stateless reset token of an id is HMAC-SHA256 of the id under the server secret,
truncated to 16 bytes: computed, never stored, so any worker can answer a short-header
packet for an id nobody knows with a stateless reset (RFC 9000 10.3: a random-looking
datagram ending in the token, shorter than the packet it answers), which is what a
client needs after we restarted. Resets are rate-limited per worker (1,000 per second),
always smaller than the packet they answer (one byte shorter when that packet is 43
bytes or less, RFC 9000 10.3.3, the loop guard) and never for a packet too short to
hold one.

### 6.5 Acknowledgements, loss recovery, congestion control, pacing

RFC 9002 as written, per packet-number space (Initial, Handshake, application):

- **Sent packets**: a record per packet (number, time, bytes, ack-eliciting, in flight,
  and what it carried in a compact form: stream ranges as id, offset, length, FIN;
  CRYPTO ranges per level; flags for the control frames, which are regenerated from
  current state on loss rather than replayed), in a per-connection ring recycled without
  allocation; the ring's size follows the congestion window.
- **Received packets**: ranges of packet numbers, at most 32 kept (older ones dropped;
  an ACK with more ranges than that is processed for the first 32); an ACK frame goes
  out after the second ack-eliciting packet, at once on a gap, or when `max_ack_delay`
  (25 ms) expires, and in every packet of a batch that carries data, so under load
  acknowledgements cost no packets of their own. ACK-only packets are not ack-eliciting.
- **RTT**: `min_rtt`, `smoothed_rtt`, `rttvar` from the largest-acknowledged with the
  peer's `ack_delay` (bounded by its `max_ack_delay`), initial RTT 333 ms until the
  first sample.
- **Loss detection**: packet threshold 3, time threshold 9/8 of the larger of the
  smoothed and latest RTT, granularity 1 ms; PTO = `smoothed_rtt + max(4 rttvar, 1 ms) +
  max_ack_delay`, doubled per consecutive expiry, one or two probe packets per PTO
  (new data if any, else PING); Initial and Handshake keys and records discarded with
  their level; persistent congestion per 7.6.
- **Congestion control**: NewReno of RFC 9002 section 7 (window 10 datagrams to start,
  2 minimum, slow start and additive increase, halved on loss); CUBIC (RFC 9438) in I3,
  a formula swap behind one interface, chosen by measurement on a real path; BBR not
  planned. **Pacing** (7.7): a token bucket at `cwnd / smoothed_rtt` times 1.25 with a
  burst of ten datagrams, scheduled through the worker's deadline heap; on loopback the
  bucket never limits, on the Internet it is what keeps a 64 KB GSO burst from filling a
  router's queue.
- **ACK of a packet never sent**: a protocol error; and packet numbers are skipped at
  random intervals so that a client acknowledging blindly (the optimistic ACK attack,
  RFC 9000 21.4) is caught.

### 6.6 Streams and flow control

Stream ids per RFC 9000 2.1 (bit 0 the initiator, bit 1 unidirectional): requests on
client-initiated bidirectional streams, the client's control, encoder and decoder
streams unidirectional, ours the same. Limits: `initial_max_streams_bidi` is
`max_concurrent_streams` (128), credit returned with MAX_STREAMS as streams close (a
stream is closed when its receive side is done and every byte we sent is acknowledged,
RFC 9000 3.3, so a pooled stream lives one round trip beyond its answer);
`initial_max_streams_uni` 8 (three are required, RFC 9114 6.2; the rest are for the
greasing types the RFC asks us to tolerate, whose bytes are discarded).

Receive windows are the HTTP/2 numbers (design-http2 6.5): a request stream starts with
`max_header_size` (16 KB) as `initial_max_stream_data_bidi_remote`, raised with
MAX_STREAM_DATA to the body limit (up to 1 MB) once the request declares a body, the
connection's `initial_max_data` 1 MB; credit is returned as the handler consumes, in
steps of a quarter window, never in dribbles. Data beyond a window is
FLOW_CONTROL_ERROR. Out-of-order STREAM data lands in the stream's gap map (a few ranges
over one buffer sized by the window: the peer cannot send more than we granted, so the
memory is bounded by the same number); in-order data is consumed at once, which is the
common case. Sending follows the peer's `initial_max_stream_data_bidi_local` (its limit
for our answers on its streams), `initial_max_stream_data_uni` for our control streams
and `initial_max_data`; STREAM_DATA_BLOCKED and DATA_BLOCKED are sent once per stall
(and a stall on a stream with under 1 KB of progress over `idle_timeout` resets it, the
HTTP/2 write-stall rule).

The send side of a stream keeps no copy of a memory body: the response's bytes stay
where they are (a cache entry through its `shared_ptr`, the handler's `MemoryBody`) and
the stream keeps offsets: sent, acknowledged in order, and the lost ranges to resend
first. A file body is read into chunks (64 KB, `preadv`) kept until acknowledged; a
`StreamBody` chunk likewise, since it cannot be pulled twice; at most 512 KB of such
chunks per connection (design-http2's "at most 8 chunks in flight"), and in flight is
bounded by the congestion window in any case.

### 6.7 The packetiser: one datagram batch per receive batch

The HTTP/2 writer's cycle (design-http2 6.6) becomes `QuicConnection::produce`: called
once after the connection's packets of a batch are processed (and by a timer for
PTO probes, pacing and delayed ACKs), it fills datagrams into the worker's send batch
while the congestion window, the pacer, the anti-amplification cap and the peer's credit
allow:

1. A packet starts in the datagram buffer with its header and a reserved 16-byte tag;
   frames are appended in this order: ACK when due, CONNECTION_CLOSE when closing (then
   nothing else), PATH_RESPONSE, HANDSHAKE_DONE, CRYPTO, NEW_CONNECTION_ID and
   RETIRE_CONNECTION_ID, the credits due (MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS),
   RESET_STREAM and STOP_SENDING, then STREAM frames: lost ranges first, then the
   control and QPACK streams, then the ready request streams round-robin with a quantum
   (the HTTP/2 scheduler's), each frame's payload encrypted straight from its source into
   the buffer by the AEAD's update call (frame headers written in place, no copy of the
   body before encryption: the "pre-framed chunk" lesson of the HTTP/2 TLS stream), the
   last STREAM frame without a length field so the packet is filled exactly.
2. A packet is sealed when full or when nothing else is due; the datagram closes at the
   path's size (1,200 until validated, then the probed MTU: a PING padded to 1,472 for
   IPv4 and 1,452 for IPv6 after the handshake, raised on its acknowledgement, RFC 8899
   DPLPMTUD in its simplest form; a lost probe keeps 1,200); Initial datagrams are padded
   to 1,200; during the handshake the levels' packets are coalesced.
3. Consecutive full datagrams of one size to the peer become one GSO message (6.1).

A small answer is therefore built at respond into the packet under construction, with
nothing kept but the sent-packet record's range, which is what "emit at respond" was in
HTTP/2 without the copy into the cycle buffer. Answers to a burst of 64 requests on one
connection (the arena's shape) fill three or four packets, one GSO message, one
`sendmmsg` entry beside the other connections of the batch.

### 6.8 Timers: the worker's deadline heap

QUIC needs timers per connection (PTO, ACK delay, pacing, idle, handshake, closing,
path validation) and a connection has one deadline at a time, the earliest of them. The
D1 finding (arming an Asio timer per exchange reprogrammed the reactor's timerfd on
every completion) applies with more force here, so no connection owns a timer: each
connection stores its next deadline and its index in the worker's heap
(`quic/timer_heap.hpp`, an intrusive binary heap, O(log n) update), and the worker's one
`asio::steady_timer` is re-armed only when the earliest deadline changes, quantised to
1 ms. A timer's firing runs `on_timeout` on every connection whose deadline passed, each
of which produces its datagrams into the same send batch (6.1). The clock is read once
per wake-up, the HTTP/2 rule.

### 6.9 Lifecycle: close, draining, idle, key update, address change

- **Close**: an application close (HTTP/3 GOAWAY first, CONNECTION_CLOSE of type 0x1d
  when the streams are done), a transport error (0x1c with the frame type), the idle
  timeout (`min(idle_timeout, the peer's max_idle_timeout)`, silent), the peer's
  CONNECTION_CLOSE (enter draining). Closing lasts three PTOs, answers further packets
  with the same CONNECTION_CLOSE at a rate that halves each time (RFC 9000 10.2.1), then
  the ids leave the table and the object is freed; draining sends nothing.
- **Key update** (RFC 9001 6): the peer flips the key phase, we derive the next
  generation, keep the previous for three PTOs for reordered packets, then drop it; a
  second flip before the first is acknowledged is KEY_UPDATE_ERROR; we initiate one only
  at the AEAD's confidentiality limit (2^23 packets for AES-GCM).
- **Address change**: `disable_active_migration` is set, so a client should not migrate,
  but a NAT rebinds; a packet from a new address on a known id starts path validation
  (PATH_CHALLENGE, one at a time), sending to the new address is capped at three times
  what it sent until PATH_RESPONSE arrives, the congestion state is reset for the new
  path, and the old path is abandoned when validated (RFC 9000 9). The worker byte in
  the id is what makes the packet arrive here at all (6.1).
- **Reload**: a UDP listener kept by the new generation keeps its sockets and its
  connections, which refresh their generation at the next stream (5.1); a listener that
  leaves the configuration sends GOAWAY to its connections, closes them after their
  streams and then its sockets, since a UDP connection shares its listener's socket.
- **Shutdown**: GOAWAY on every connection, CONNECTION_CLOSE after the streams, at most
  the drain timeout.

### 6.10 Memory per connection

| Part | Amount | Note |
|---|---|---|
| connection object: state, ids, windows, recovery, ACK ranges | about 3 KB | the sent-packet ring grows with the congestion window: 64 bytes per packet in flight |
| `SSL` during the handshake | about 10 KB | freed when the tickets are acknowledged (6.2) |
| keys and cipher contexts | about 2 KB | two AEAD and two header-protection contexts, the next generation |
| CRYPTO reassembly | up to 16 KB per level while the handshake lasts | freed with the level |
| QPACK decoder table | at most 4 KB | the peer decides how much of it to use |
| QPACK encoder table | at most 1 KB | as HTTP/2's |
| per active stream | Stream (6.4 KB) + arena at the request's exact size + the gap map and body buffer up to its window | pooled at the concurrency limit, emptied by the idle shed, as HTTP/2 |
| output in flight | memory bodies nothing; file and stream chunks at most 512 KB | 6.6 |
| idle connection, target | under 12 KB after the shed | HTTP/2 today 19 KB, of which 8 KB is the HPACK ring a client fills; the QPACK table is bounded at 4 KB |
| worst case at the defaults | 16 KB + 4 KB + 128 x 18 KB + 1 MB + 512 KB, about 3.8 MB | the HTTP/2 number; nothing unbounded |

The datagram buffers are the worker's, not the connection's: 2 MB for receiving and
2 MB for the send batch per worker, allocated once.

## 7. HTTP/3 (`src/http3/`)

### 7.1 Framing and the control streams

Frames (RFC 9114 7.2) are a varint type, a varint length and a payload, and may span
STREAM frames and packets, so the parser is incremental per stream: DATA, HEADERS,
SETTINGS, GOAWAY, MAX_PUSH_ID, CANCEL_PUSH (an error: we never push), PUSH_PROMISE (an
error from a client), reserved types (`0x1f * N + 0x21`) skipped. Each side opens a
control stream whose first frame must be SETTINGS (H3_MISSING_SETTINGS otherwise; a
second SETTINGS is H3_FRAME_UNEXPECTED), and a QPACK encoder and decoder stream; a
second stream of a type that allows one is H3_STREAM_CREATION_ERROR, closing a critical
stream is H3_CLOSED_CRITICAL_STREAM, a frame on the wrong stream type
H3_FRAME_UNEXPECTED. Our SETTINGS: `MAX_FIELD_SECTION_SIZE` = `max_header_size`,
`QPACK_MAX_TABLE_CAPACITY` 4,096, `QPACK_BLOCKED_STREAMS` 16, one greasing setting
(RFC 9114 7.2.4.1). The peer's: its table capacity and blocked streams bound our encoder
(7.2); its field section size bounds our answers (an answer whose head exceeds it is
never the case for ours).

### 7.2 QPACK

**Decoder** (our requests): the 99-entry static table generated by
`tools/gen-hpack-tables.py` from RFC 9204 appendix A next to HPACK's; the dynamic table
is `DynamicTable` from `src/http/field_codec` with QPACK's absolute indexing (an insert
count, a base per section, post-base references) over the same ring and the same
`checked` marks, so a request's field rules run once per entry and not once per
reference, as in HTTP/2 since 2026-09-24; the encoder stream's four instructions (set
capacity, insert with a name reference, insert with a literal name, duplicate) are
applied as they arrive, an insert larger than the capacity or a reference to an evicted
entry being QPACK_ENCODER_STREAM_ERROR; a field section whose Required Insert Count is
above the insert count waits for the encoder stream, the stream marked blocked, at most
16 of them (the setting we sent; a seventeenth is QPACK_DECOMPRESSION_FAILED), each
holding at most `max_header_size` of encoded section; our decoder stream carries Section
Acknowledgement for every section decoded with dynamic references, Insert Count
Increment otherwise, and Stream Cancellation when a stream is reset with a section
pending. Decoding runs into the connection's scratch with the exact-size copy per stream
and the list-size budget stopping at the first byte over `max_header_size`, as HPACK's.
`fuzz_qpack` decodes every input with nghttp3's decoder too when `libnghttp3-dev` is
present at build time and compares the fields, as `fuzz_hpack` does with nghttp2.

**Encoder** (our answers), in two steps like HTTP/2's:

- I1 (built 2026-09-24, and the decoder's dynamic table the same day: the encoder stream's
  four instructions, blocked sections with the 16-stream limit, the decoder stream's
  acknowledgements, cancellations and increments, appendix B as unit tests): the static
  table only for our answers. `:status` one byte for the fourteen static values,
  `content-type` one byte for its eleven, `server`, `date` and `content-length` literals
  with a static name reference, the cache entry's validators in the prebuilt tail, the section
  prefix `00 00`. About 40 bytes for the arena's answer, no encoder stream traffic, no
  state.
- I3 (built 2026-09-25, `qpack::Encoder`): the dynamic head of design-http2 6.2.1 over
  the encoder stream: `server`, `date` (one insert per second), `alt-svc` and the last
  `content-type` inserted with Insert With Name Reference, then referenced by one index
  byte each, the capacity at most 1 KB and at most the peer's setting. The rule QPACK
  adds: a section that references an entry the peer has not acknowledged (through Insert
  Count Increment or Section Acknowledgement) counts as a blocked stream, at most the
  peer's `QPACK_BLOCKED_STREAMS` at once (nghttp3 and Chrome allow 100; a peer that says
  0 gets literals until its acknowledgement arrives). The insert goes into the packet
  before the section that uses it (the encoder stream is enqueued ahead of the response
  stream), so on a clean path the decoder never blocks and under loss it blocks within
  its own limit. As built: the encoder mirrors the peer's table (at most 32 entries, a
  scan of them for a value, a memo for the run of one content-type), references entries
  inserted for the same section post-base (RFC 9204 4.5.3; appendix B.2's section comes
  out byte for byte), counts references per entry so no pending section's entry is ever
  evicted (2.1.1: the insert that would need it is refused and the field goes as a
  literal), releases them on Section Acknowledgement, Stream Cancellation or the stream's
  close, and reads the peer's decoder stream on the connection (an increment of zero or
  beyond the inserts is QPACK_DECODER_STREAM_ERROR). curl (OpenSSL) announces no table
  and gets literals as before; h2load and browsers announce 4 KB. Nothing in the encoder
  searches per answer: every field remembers its entry, and the `content-type` value's
  row of the static table (eleven values are rows of appendix A; the search was 3 % of
  the cycles per answer in the arena profile) is looked up once per value change.

### 7.3 Requests, responses, bodies, GOAWAY, errors

A request stream's first frame must be HEADERS (DATA first is H3_FRAME_UNEXPECTED); its
field section, once complete and unblocked, goes through `request_assembly` (section 4)
with the outcomes mapped to HTTP/3: a malformed request is answered 400 when the head
allows it (RFC 9114 4.1.2 permits a final response before the reset) and the stream is
reset with H3_MESSAGE_ERROR, a QPACK failure is a connection error. DATA frames feed the
`StreamBody` through the shared body source, credit returned as MAX_STREAM_DATA and
MAX_DATA; a declared `content-length` that disagrees with the DATA total is
H3_MESSAGE_ERROR; trailers (a second HEADERS after DATA) are decoded, to keep the QPACK
state in step, and discarded, as HTTP/2 does. A body the handler did not read is
discarded up to 64 KB, then STOP_SENDING(H3_NO_ERROR), the HTTP/2 rule.

The answer is HEADERS (7.2) then DATA frames from the body, FIN on the last; a HEAD or
304 answer is HEADERS with FIN. 1xx are not sent. The client's RESET_STREAM or
STOP_SENDING before the answer cancels the exchange (E9) and counts as a reset (the
budget of `src/http/budgets.hpp`); after the answer it is nothing.

GOAWAY carries the highest stream id we will serve, sent at `max_requests_per_connection`,
on reload retirement and on shutdown; new streams above it are reset with
H3_REQUEST_REJECTED so the client retries elsewhere; the connection closes when the
streams below it are done. The peer's GOAWAY stops us opening streams, which we never do.

### 7.4 Selection and Alt-Svc

There is no hand-over: a QUIC connection can only be HTTP/3, and the UDP listener's ALPN
offers `h3` alone. Discovery is `alt-svc: h3=":8443"; ma=86400` (the listener's port),
appended by the HTTP/1 and HTTP/2 writers as an extra field on every answer of a TLS
listener that also speaks `h3`, prebuilt per listener; browsers then switch on the next
connection and h2load or curl choose `h3` directly. `http3.alt_svc = false` switches
the field off. HTTPS DNS records (SVCB) are the operator's; the docs say how. Built
2026-09-25: the value and the prebuilt head line live in the `Listener` (`alt_svc`,
`alt_svc_line`), the connections hand them to the `Response` at respond time
(`Response::alt_svc_line`, `Response::alt_svc`) and the writers keep them off the hot
paths: the HTTP/1 writer's fast path (one borrowed prebuilt block, no tail) becomes the
block up to its last line plus a tail of the line and the blank line, so a cache hit
still builds no head; the HTTP/2 writer asks the HPACK encoder's memo
(`hpack::Encoder::alt_svc`), a literal with a new name inserted once per connection and
one index byte after that, the way `server` and `date` go. Adding the field to the
response's extra fields instead, the first version, sent every HTTP/1 answer down the
general path and cost the ten-stream HTTP/2 row 9 % of its CPU (a table scan per
answer). The HTTP/3 answers carry nothing. The same day, reload: an h3 listener that leaves the
configuration or loses h3 sends GOAWAY and closes its connections with H3_NO_ERROR on
its workers' loops and closes its sockets; a TLS listener that gains h3 opens them.

### 7.5 Access log and observability

The access log line is the same record with `HTTP/3.0`; `server_status` adds, per
listener, HTTP/3 connections, handshakes, Retries sent, stateless resets sent,
connections closed by budget with the reason (the HTTP/2 counters) and, per worker,
whether GSO and the reuseport program are in effect; `health` reports a UDP receive
buffer the kernel capped below what we asked (`net.core.rmem_max`), a listener whose
reuseport program could not be attached, and the same budget findings as HTTP/2.

## 8. Performance plan

### 8.1 What a request costs, and the target

On the arena's `baseline-h3` (64 connections, 64 streams each, a 60-byte answer) a
connection's burst of requests arrives in a few packets and its answers leave in three
or four; per packet the work is one header-protection block, one AEAD pass over about
1,400 bytes (roughly 1,500 to 2,500 cycles with AES-NI through EVP, the fixed cost of
the EVP calls included), the frame parse and the acknowledgement bookkeeping; per request
the HTTP/3 layer's share should be what HTTP/2's is (1,315 cycles per request over TLS
on one worker today, of which the TLS record is a part). Target for one worker: at most
1,500 cycles per request on that row. nginx's board rows put its HTTP/3 at 31 cores for
4.85M req/s (its HTTP/2 at 65 cores for 3.4M), and our HTTP/2 does 4.2 times its HTTP/2
in the lite harness; the same distance on HTTP/3 is the aim, the profile the judge. For `static-h3` (15 KB answers, eleven packets each) the cost is the crypto
pass over the entry's bytes and the packet count, which the MTU probe and the one-pass
encryption from the entry's memory decide. Numbers are targets until `bench/h3/run.sh`
and `profile.sh` replace them.

### 8.2 The levers, in order of expected impact

1. **Batching**: recvmmsg with GRO in, one `sendmmsg` with GSO out per wake-up, ACKs
   riding in data packets (6.1, 6.5).
2. **One crypto pass** from the source into the datagram buffer, contexts initialised
   per key not per packet (6.2, 6.7).
3. **Emit at respond**: the answer's frames built into the packet under construction,
   nothing copied and nothing allocated (6.7).
4. **The request side as HTTP/2's**: the rules once per table entry, the scratch decode,
   the assembler's length switch (7.2, section 4).
5. **The dynamic head** over the encoder stream (7.2).
6. **Path MTU** to 1,472 / 1,452: more answers per packet, fewer packets per file (6.7).
7. **Memory**: the `SSL` freed after the handshake, the pool at the concurrency limit,
   the idle shed, `malloc_trim` (6.10).
8. **CUBIC and pacing** for real paths, not for the benchmark (6.5).
9. **The AEAD's fixed cost**: if the EVP calls' overhead dominates on small packets, the
   alternative is our own AES-GCM with AES-NI and CLMUL intrinsics (h2o's fusion is the
   precedent, about a thousand lines); decided by the profile, not now.
10. **A speculative receive** instead of the wait's re-arm (6.1), measured.

### 8.3 The benchmark

`bench/h3/run.sh`, the shape of `bench/h2/run.sh`: rows `h3:/:64:1`, `h3:/:64:10`,
`h3:/:64:64` (the arena's shape), `h3:/style.css:64:10`, `h3:/big.bin:16:1`,
`h3:/:256:10`, h2load with `--alpn-list=h3`, the same docroot, certificate and metric
(server CPU microseconds per request, RSS), against nginx 1.26 (Debian's, built with
`http_v3_module`; `listen 8444 quic reuseport; http3 on;`) and Caddy 2.11 (`h3` on by
default). `bench/ab.sh <ref> -3` adds four HTTP/3 rows to the gate for the steps after
I1 (the code is new files; the gate is regression between our own steps, and the h1 and
h2 rows must stay flat throughout). `bench/httparena/profile-h3.sh` profiles one worker
against the arena's nginx image on the two rows, as `profile-h2o.sh` did against h2o.
`bench/h2/memory.sh` gets HTTP/3 rows (10,000 idle, 1,000 busy). The arena's lite
harness runs the two rows once `meta.json` subscribes them (I3).

### 8.5 Measured: the first slice (2026-09-24)

`bench/results/h3-profile-20260924.md` (`bench/httparena/profile-h3.sh`, the arena's own
h2load over QUIC, 64 connections with 64 streams each, one worker, the tree as
committed): 1.22M and 1.25M req/s on two runs, 0.61 us of server CPU per request, about
3,100 cycles per request at 3.19 instructions per cycle, the kernel 4.2 % of the cycles
(3,172 sendmmsg and 4,276 recvmmsg calls in three seconds for 7.3 million answers: about
a thousand answers per syscall pair, GSO and GRO doing what 6.1 measured), libcrypto
3.5 % (about 21 answers share a packet's AEAD), 18 MB resident, no failed request. The
devbox's nginx 1.26 with its http_v3 module on one worker, serving a two-byte file under
the same load: 402k to 433k req/s at 2.32 us and about 12,500 cycles per request, 137 MB
resident. In the arena's own harness (twelve workers pinned to six cores and their
siblings, twelve load threads elsewhere; one worker serves QUIC in this slice):
`baseline-h3` 1.77 to 1.81M req/s and `static-h3` 98 to 108k on that core, no failed
request, against the board's nginx entry at 4.85M and 361k on 31 and 50 cores; with the
per-worker sockets and the steering program (6.1, the same day) twelve workers do 3.86 to
3.89M at 2.6 cores on `baseline-h3`, where the twelve-thread load generator is the limit,
and 541k at 8.3 cores on `static-h3`, 83 and 92 MiB resident. One worker each on this box (`bench/h3/run.sh`, `h3-20260924-162836.md`): the 1 KB file at
64 connections and 64 streams agensio 0.90 us per request and 1.03M req/s, nginx 3.27 us
and 305k, Caddy 26.6 us and 38k; at ten streams 1.05, 2.70 and 26.8 us; the 100 KB file
at ten streams 24.8, 31.0 and 121 us; the 10 MB stream is nginx's (1.95 ms per response
against our 2.72 ms: our file windows are read and copied per packet, the one-pass AEAD
from the source of 6.7 and larger datagrams are the levers there). The first
item of our profile is the Huffman decoding of the request's literals (21 %): with the
QPACK table capacity at 0 (7.2's first step) the client sends `:path`, `:authority` and
`user-agent` as literals on every request where HPACK indexed them after the first, so
the decoder's dynamic table (I1c) is the first lever, ahead of the encoder's memo for
content-type (4 %), the stream lookup by slot (3.5 %) and the pooled stream's reset
(3.8 %). The datagram counts say our answer is about 57 bytes on the wire against
nginx's 25: the encoder's dynamic head (7.2's second step) halves the packets.

Two corrections the first rows forced, both kept in 6.5 and 6.1 now: the ACK of a
request rides on the response packet (a pending acknowledgement goes into any packet
sent for another reason; only an ACK with nothing else to carry waits for the delay),
because a client at one stream per connection cannot close its stream, and so start
the next request, until its FIN is acknowledged: the single-stream row went from 2,575
to 212k req/s over 64 connections. And a `[::]` endpoint is dual-stack (`IPV6_V6ONLY`
off), as the TCP acceptors are, because a load generator that resolves `localhost` to
`::1` cannot fall back to IPv4 over UDP the way TCP's connect does; the arena's harness
does exactly that.

Two more from the 100 KB row at ten streams, whose bursts overflow the client's
receive buffer (a 1 MB burst against a 208 KB socket buffer): loopback does lose packets
after all, and the first bug it found was the probe. A response whose last packet is
lost is recovered only by a PTO probe; ours was a one-byte PING behind a one-byte
packet number, shorter than header protection can sample (RFC 9001 5.4.2 requires the
number and the protected payload to be at least four bytes longer than the sample), so
the client could not unprotect it, never acknowledged it, and the probes backed off for
ever: every packet is padded to that minimum now. The second was the send batch: when
it filled during a wake-up, the connections behind it got no send and nothing woke them
until their idle timeout; the batch goes out when full and fills again. The tracing
build loses datagrams on purpose (`AGENSIO_QUIC_DROP=N` every Nth,
`AGENSIO_QUIC_DROP_TAIL=1` one final packet), which is how both were reproduced; the
loss proxy of 9.2 stays the test for the client's side of the same paths.

**The steps after the slice, the same day**, each with its A/B (h1 and h2 flat every
time) and the same profile load (`profile-transport.txt` and the files before it):

- Per-worker sockets with the reuseport program (6.1): twelve workers in the arena's
  harness 3.86 to 3.89M req/s on `baseline-h3` at 2.6 cores (the load generator is the
  limit) and 541k on `static-h3` at 8.3 cores.
- QPACK's dynamic table on the decoder side (7.2): the profile's Huffman share 21 % to
  7.9 %, 0.61 to 0.56 us per request under the arena load, a request's field section
  seven bytes with two dynamic references (`profile-qpack.txt`); on the way, the
  stream-ordering bug of 6.6 (a lower id arriving after a higher one was refused as
  closed), which also explains the two stalled requests of the first slice: none since.
- Larger datagrams and fewer packets (6.7): the MTU probe (1,472-byte datagrams) and
  MAX_STREAMS riding on the next packet. The trace of a client with one request at a
  time showed the cost: our 1,141-byte answer, then the client's 5-byte ACK, then our
  31-byte MAX_STREAMS packet, then the client's ACK of that. One-stream row 5.3 to 3.8 us
  of CPU per request; the 10 MB stream 2.72 to 2.40 ms (nginx 1.95); `static-h3` 541k to
  618 to 622k req/s. The one-stream row's req/s (52 to 57k for agensio, nginx and the
  previous build alike; a single connection does a request every 148 us) is h2load's own
  per-request work in this shape, not the server's.
- Stability (9.2) and the last per-request costs, 2026-09-25: the lossy relay
  `tests/quic-lossy.py` between curl and the server in the integration suite (3 % of
  the datagrams dropped, 5 % delayed up to 3 ms, both directions; the handshake, the
  page and the 10 MB file complete); six attack rows as raw frames written into
  aioquic's packets through its packet builder (the glitch budget, an optimistic ACK,
  a fifth connection id, retiring an unissued and the in-use id, data beyond the
  window) and a shutdown row; `fuzz_quic_packet`, `fuzz_transport_params` and
  `fuzz_qpack` (the HTTP/3 frame head is two varints the connection reads, covered by
  the packet fuzzer's varints and the suites); the interop runner harness in
  `bench/quic-interop/` with the `hq-interop` protocol in interop builds. Closed streams
  became a bitmap over the 64 indices below the highest opened (`incoming_stream` was
  7.4 % of the profile with its scan of 64 ids). GOAWAY then a close with H3_NO_ERROR
  at shutdown, on each endpoint's worker before its loop stops. And the MTU search
  (6.7) continues upward by doubling: the trace showed 1,472, 2,944, 5,888, 11,776,
  23,552 and 47,104-byte datagrams acknowledged in five round trips on loopback, which
  is what nginx does on the 10 MB row (its datagrams there average 22 KB, ours were
  1,364 bytes); probes stay outside the congestion window, and a datagram larger than
  the window's room shrinks to the room instead of waiting for it. The socket sets
  don't-fragment for both families (a `[::]` socket carries IPv4 peers as mapped
  addresses; the first version set it for IPv4 sockets only, and the interop runner's
  1,500-byte link then carried fragmented 11 KB probes that were acknowledged, so the
  search went past the link and a transfer crawled under fragment loss). Probe packets
  (6.5) carry the oldest unacknowledged CRYPTO or stream data of their space again, as
  RFC 9002 6.2.4 recommends, instead of a PING: the interop runner's multi-connection
  cases under 30 % loss and corruption completed 35 and 11 of 50 handshakes with quic-go
  in the time allowed while the PING probe cost two or three round trips per loss.
  Measured
  (`ab-20260925-013754.md`, h1 and h2 flat): the h3 rows at ten and sixty-four streams
  0.83 and 0.76 of the previous commit, the 100 KB file 0.53 (21.2 to 11.2 us); one
  worker 1.23M req/s at sixty-four streams, the 100 KB file 85k at 11.7 us, the 10 MB
  stream 1.44 ms per response (nginx 1.95, ours 2.72 in the first slice), 0.54 us per
  request under the arena load; the arena's own rows, on a 1,500-byte path, unchanged.
- The transport rows of I1b (6.3, 6.4, 6.9, above): no cost on the request path; the
  profile after them 1.14 to 1.15M req/s on one worker at 0.58 us per request, 2.98
  instructions per cycle, 16 MB resident. Its top items now: Huffman decoding 8.8 %
  (what the client still sends as literals), `incoming_stream` 7.4 % (the scan of the 64
  recently closed ids on every new stream: the next small lever, a bitmap over the
  recent range), the router 5.0 %, `apply_acked` 4.8 %, the stream's close 4.4 %, the
  QPACK decode 3.7 %; the kernel 4.5 % of the cycles.
- The encoder side of QPACK (7.2), `alt-svc` (7.4), GOAWAY on reload (6.9) and
  `fuzz_quic_conn` (9.2), 2026-09-25: the answer's head a dozen bytes instead of fifty,
  the bytes on the wire per answer a third; the h3 rows of the A/B on loopback, three
  rounds against v0.1.0-alpha.22, 1.05 / 1.04 / 1.02 / 1.02 with the first encoder that
  searched the static table for the content-type row per answer (3 % of the cycles) and
  1.00 / 0.99 / 0.99 / 0.98 once that row is remembered per value (`ab-20260925-084739.md`,
  `ab-20260925-085625.md`); 0.55 us per request under the arena load
  (`profile-altsvc.txt`), the arena's `baseline-h3` 3.89 to 3.90M at 2.1 cores
  (load-bound) and `static-h3` 597 to 603k, the 10 MB stream 1.38 ms per response
  (`h3-20260925-085922.md`). Two lessons: `alt-svc` as an extra response field cost the
  ten-stream HTTP/2 row 9 % (the HTTP/1 fast path skipped, an HPACK table scan per
  answer) and is free as a prebuilt line inside the fast path and an encoder memo; and
  the QUIC sockets' 4 MB buffers are capped by `net.core.rmem_max` (208 KB untuned), so
  256 connections opening at once on loopback lose Initials to the full socket and
  connect one to three seconds later after their probe timeouts, which the startup line
  now reports with the sysctl to raise.

## 9. Security

### 9.1 Threats and defences

| Attack | Mechanism | Defence | Limit | Test |
|---|---|---|---|---|
| Amplification with a spoofed source | Initials from a victim's address; the server's answers are several times the size | Initials under 1,200 bytes dropped; three times the bytes received until the address is validated; Retry under load; Version Negotiation only for datagrams of at least 1,200 bytes | 3x, RFC 9000 8.1 | `h3-attacks.py amplification` (a client that never acknowledges); the interop runner's `amplificationlimit` |
| Handshake flood, half-open exhaustion | Initials that never complete; each costs an `SSL` and keys | the half-open budget per worker, Retry at half, drop at full; the handshake bounded by `idle_timeout`; CRYPTO buffered at most 16 KB per level | 1,024 half-open per worker | `h3-attacks.py handshake-flood`; RSS and CPU sampled |
| Retry token forgery or replay | a token from another address or time | AEAD-sealed with the hourly key, bound to the address, the original id and the time; ten seconds of validity | | unit tests of the token |
| Optimistic ACK | acknowledge packets never received to inflate the window (RFC 9000 21.4) | an ACK of a number never sent is PROTOCOL_ERROR; packet numbers skipped at random | | `h3-attacks.py optimistic-ack` |
| ACK frame with many ranges | CPU per frame | 32 ranges processed, the rest ignored; frames bounded by the packet | 32 | `fuzz_quic_packet` |
| Connection id games (the 2024 quic-go class) | NEW_CONNECTION_ID with `Retire Prior To` floods, RETIRE floods | at most four active ids from the peer, CONNECTION_ID_LIMIT_ERROR beyond; the retirements a `Retire Prior To` demands are queued as one range, never one frame each; a retirement of an id we never issued is PROTOCOL_ERROR; retirements beyond the ids issued are glitches | 4 ids | `h3-attacks.py cid-flood` |
| Stream flood, Rapid Reset over QUIC | streams beyond the limit; streams reset at once | STREAM_LIMIT_ERROR beyond MAX_STREAMS; the reset counter (RESET_STREAM and STOP_SENDING before the answer, resets we send) closes at 128 per second; the glitch budget | 128 streams, 128 resets per second, 100 glitches | `h3-attacks.py stream-flood`, `rapid-reset` |
| Flow-control games | a zero window held, 1-byte MAX_STREAM_DATA dribbles, DATA_BLOCKED floods | the write-stall rule (`idle_timeout` per stalled stream); updates under 1 KB while more is pending are glitches | | `h3-attacks.py slow-read`, `dribble` |
| Reassembly memory | out-of-order STREAM and CRYPTO data held in gaps | bounded by the windows we granted (beyond is FLOW_CONTROL_ERROR) and the CRYPTO cap per level; the sum is 6.10 | 16 KB per level, the stream's window | `h3-attacks.py gaps`; `fuzz_quic_conn` |
| QPACK bomb, blocked-stream hold, encoder-stream games | a huge entry referenced thousands of times; sections referencing inserts that never come; capacity games | the decoder table at most 4 KB, blocked streams at most 16 with at most 16 KB each, the decoded list stopped at the first byte over `max_header_size`, capacity above ours or an insert above the capacity is QPACK_ENCODER_STREAM_ERROR | 4 KB, 16 streams, 16 KB | `fuzz_qpack` differential; `h3-attacks.py qpack-bomb`, `blocked-hold` |
| Control stream abuse | no SETTINGS first, a second SETTINGS, the control stream closed, frames on the wrong stream type, CANCEL_PUSH or PUSH_PROMISE, MAX_PUSH_ID games | the RFC's errors (7.1); reserved frame and stream types ignored, their bytes discarded and counted against the windows | | `fuzz_h3_frame`; `h3-attacks.py control-stream` |
| Forged packet flood | packets with bad tags for a known id cost a decryption each | the id lookup rejects unknown ids before any crypto; failed tags counted against the AEAD integrity limit, the connection closed at it; stateless resets rate-limited per worker | 2^52 (AES-GCM), 1,000 resets per second | `h3-attacks.py forged-flood`; CPU sampled |
| Key update flood | a key phase flipped repeatedly | a second update before the previous is acknowledged is KEY_UPDATE_ERROR; old keys kept three PTOs | | `h3-attacks.py key-update` |
| Path validation flood, migration to a victim | packets from spoofed new addresses | passive changes only, one validation at a time, three times the bytes on the new path until validated, PATH_RESPONSE rate-limited, migration to a validated path only | 1 validation in flight | `h3-attacks.py path-flood` |
| Spoofed stateless reset, Version Negotiation or CONNECTION_CLOSE | tear down a connection from outside | a reset must end in a token we issued (HMAC under the server secret); Version Negotiation answered only for unknown versions and ignored after the handshake; CONNECTION_CLOSE only from a packet that decrypts | | unit tests; the interop runner |
| Slow handshake, slowloris | a client that dribbles | the handshake bounded by `idle_timeout`, `max_idle_timeout` = `idle_timeout`, `body_timeout` between DATA frames | 15 s, 60 s | integration |
| 0-RTT replay | a replayed early request | early data refused in phase I (`SSL_set_quic_tls_early_data_enabled` off); later opt-in for GET and HEAD only, with `Early-Data: 1` to upstreams | | unit |
| Memory as a whole | anything that grows | every buffer belongs to a stream, a connection or the worker and has a cap; the worst case is 6.10 | about 3.8 MB per connection at the defaults | the attack suite samples RSS through every run |

### 9.2 Testing the code, not the list

- **The QUIC interop runner** (`quic-interop-runner`, the harness every QUIC stack is
  measured with) in `bench/quic-interop/`, run locally through Docker with its network
  simulator (loss, reordering, corruption) against the quic-go, ngtcp2, quiche, picoquic
  and aioquic clients, the test cases `handshake`, `transfer`, `retry`, `resumption`,
  `http3`, `multiconnect`, `chacha20`, `keyupdate`, `amplificationlimit`, `blackhole`,
  `rebind-addr`, `rebind-port`, `handshakeloss`, `transferloss` and `transfercorruption`;
  `zerortt`, `ecn`, `v2` and `connectionmigration` recorded as not claimed. The results table goes into the
  security page with each checkpoint.
- **The loss proxy** `tests/quic-lossy.py` between curl and the server in the
  integration suite: drop, reorder and delay at configured rates; every transfer must
  complete, the 10 MB file included.
- **Fuzzers**: `fuzz_quic_packet` (headers, coalescing, frames per level),
  `fuzz_transport_params`, `fuzz_qpack` (both instruction streams and field sections,
  differential against nghttp3), `fuzz_h3_frame`, `fuzz_quic_conn` (a connection driven
  through a fake clock and a test AEAD that keeps plaintext, arbitrary datagrams after
  the handshake). ASan and UBSan, minutes per checkpoint, the counts in the security page.
  As built (2026-09-25): `fuzz_quic_conn` keeps real packet protection instead of a test
  AEAD: `fuzz_establish` (fuzz builds only) puts the connection in the established state
  with application keys derived from one fixed secret both ways, and the harness seals
  the fuzzer's plaintext frame payloads with the same keys, so the input is frames, not
  ciphertext, and header protection, packet numbers and key phases are exercised for
  real; the clock is the harness's and its steps fire the timers. It links the crypto and
  needs a fuzz build with `-DAGENSIO_TLS=ON` (`build-fuzz-quic`). The HTTP/3 frame head
  is two varints read by the connection, covered by the packet fuzzer and the suites, so
  `fuzz_h3_frame` was not written.
- **The attack suite** `tests/h3-attacks.py` on aioquic (Debian's `python3-aioquic` in
  the devbox image), one function per row of 9.1, each asserting the server's response
  (the error code, the close, the log line) and that RSS did not grow beyond the budget.
- **Clients in the integration suite**: `curl --http3-only` (the devbox's curl carries
  OpenSSL's QUIC and nghttp3) for every handler and status, `h2load --alpn-list=h3`
  under the sanitizer build (the HTTP/2 lesson: the inline loops overflowed only under
  load), a browser check on the VPS with a real certificate.
- **Sanitizer builds** of everything, and `security-review-cpp` on every file of
  `src/quic/` and `src/http3/` before the checkpoint.

## 10. Configuration, reference rows, the agent interface

- `protocols` accepts `"h3"` next to `"h1"`, `"h2"`, `"h2c"`, server-wide and per site;
  `h3` requires a TLS listener and opens UDP on its port; sites on one address agree
  (the existing rule). Default: off, until the interop table is clean; then on for TLS
  listeners like `h2`.
- `[server] http3 = { max_concurrent_streams, alt_svc, retry }`: `max_concurrent_streams`
  defaults to `http2.max_concurrent_streams` so one number governs both; `alt_svc`
  (bool, default true) sends the field from the TLS listener's HTTP/1 and HTTP/2
  answers; `retry` (`"auto"`, `"always"`, `"never"`, default `"auto"`).
- Everything else derives: `max_header_size` (the field section limit, the first
  window, the QPACK section cap), `max_body_size` (the raised window, `initial_max_data`),
  `idle_timeout` (`max_idle_timeout`, the handshake bound), `body_timeout`,
  `max_requests_per_connection` (GOAWAY), the QPACK table (4 KB) and blocked streams
  (16), the ids (4), `max_ack_delay` (25 ms), the MTU probe sizes, the budgets. No key
  for congestion control until a real path says which to prefer.
- Each key is a row of `control/reference.cpp`, `docs/keys.md` regenerated,
  `docs/configuration.md` section 17 "HTTP/3" (what it needs from the firewall: UDP on
  the port; `net.core.rmem_max`; the SVCB record), the security page's table, the MCP
  texts where `protocols` is described, `agensio -t --explain`, `server_status` and
  `health` (7.5).

## 11. Staged plan

Each step: unit and integration suites green, the A/B with the h1 and h2 rows flat, the
h3 rows recorded from I1c on, docs and MCP texts in the same change, one commit per step.

- **I0, the lifts** (section 4): `src/http/` with the field codec, the request assembler,
  the stream pool, the body source and the budgets, HTTP/2 rebuilt on them; the QPACK
  twins' slots without content. Gate: `ab.sh -2` flat on every row, h2spec unchanged.
- **I1a, a handshake**: the UDP listener and steering, packets, frames, transport
  parameters, keys, the TLS glue, the handshake with address validation and Retry,
  connection ids and stateless reset, ACK generation and loss recovery with NewReno,
  idle and close, the deadline heap. Tests: the RFC 9001 vectors, the packet and
  parameter fuzzers, `curl --http3-only` completing a handshake to a connection that
  then closes with an application CONNECTION_CLOSE (H3_NO_ERROR), there being no HTTP/3
  layer yet, the loss proxy on the
  handshake.
- **I1b, streams**: send and receive state, flow control, the gap map, the packetiser
  with GSO, path MTU, the file and stream chunks, key update, address change. Tests: a
  raw stream echo through a test hook, the loss proxy on transfers, `fuzz_quic_conn`.
- **I1c, HTTP/3**: framing, the control streams, QPACK decoder and static encoder, the
  request path through `request_assembly`, answers for every handler with bodies both
  ways, GOAWAY, `alt-svc`, the three keys and their rows, section 17 of the configuration
  docs, the MCP texts. Tests: RFC 9204 appendix B, `fuzz_qpack` and `fuzz_h3_frame`, the
  curl rows for every handler and status, h2load over QUIC under the sanitizer build,
  `bench/h3/run.sh` and `ab.sh -3` recorded.
- **I2, conformance and hardening**: the interop runner table, the attack suite, the
  budgets tuned on it, the sanitizer and fuzz records, the security page's HTTP/3
  section, `server_status` and `health`.
- **I3, performance**: the levers of 8.2 measured one by one against nginx and Caddy,
  the dynamic head, CUBIC and pacing, memory per connection published, the arena's
  `meta.json` subscribing `baseline-h3` and `static-h3`, the lite harness run with the
  two rows, `profile-h3.sh` against the arena's nginx image.
- **I4, extras**: 0-RTT as an opt-in for GET and HEAD, NEW_TOKEN, ECN, active migration
  and `preferred_address`, version 2, the `gateway-h3` entry with our proxy, a
  congestion-control key if a real path asks for one.

## 12. Decisions requested

1. **Own transport, HTTP/3 and QPACK**, OpenSSL 3.5's QUIC TLS API and primitives for the
   crypto; ngtcp2 and nghttp3 not in the runtime, nghttp3 in the test bed as the QPACK
   oracle (section 3). Reverses the roadmap's phase I plan. Proposal: yes.
2. **The OpenSSL floor** for `h3` is 3.5, detected at configure (`AGENSIO_HAS_QUIC`);
   TLS, HTTP/1 and HTTP/2 keep building on older OpenSSL without it. Proposal: yes.
3. **The lifts first** as a pure refactor gated flat (I0, section 4). Proposal: yes.
4. **Steering**: per-worker sockets with the worker byte in the connection id and a
   classic BPF program on Linux, forwarding as the fallback, worker 0 alone on the other
   platforms (6.1). Proposal: yes.
5. **Three keys** (`h3` in `protocols`, `http3.max_concurrent_streams` defaulting to
   HTTP/2's, `http3.alt_svc`, `http3.retry`), everything else derived (section 10).
   Proposal: yes.
6. **Defaults**: 128 streams, 8 unidirectional, windows as HTTP/2's, a 4 KB QPACK table
   and 16 blocked streams, four ids, 25 ms ACK delay, 1,200 bytes then the MTU probe,
   NewReno first and CUBIC measured in I3, pacing on, 1,024 half-open per worker, Retry
   on `auto`; `h3` off by default until I2's table is clean. Proposal: yes.
7. **Not in phase I**: 0-RTT, active migration, ECN, push, datagrams, version 2
   (section 1). Proposal: yes.
8. **The conformance gate**: the interop runner's table, the loss proxy, the five
   fuzzers and the attack suite (9.2), recorded per checkpoint. Proposal: yes.
9. **The benchmark set** of 8.3, `ab.sh -3` from I1c on, the arena rows subscribed in
   I3 once the lite harness shows them above nginx's board numbers. Proposal: yes.
10. **The dynamic QPACK head** as a measured lever in I3, static-only in I1 (7.2).
    Proposal: yes.
11. **The staging** of section 11, I1 in three commits. Proposal: yes.

Built in the first slice (2026-09-24), with what it leaves: I0's codec, assembler and
pool lifts (the body source and the budgets stay per protocol until I1b and I2 unify
them); the endpoint on worker 0 (the per-worker sockets and the reuseport program are
I1b); packets, frames, transport parameters, keys, the TLS glue, the handshake with the
Handshake-packet validation (Retry and tokens I1b); ids issued once (replacements after
RETIRE_CONNECTION_ID and stateless reset I1b); acknowledgements, loss detection, PTO
probes and NewReno (CUBIC and pacing I3); streams, flow control, the gap map, the
packetiser with GSO (the external-source AEAD pass, path MTU, key update, path
validation I1b); idle and close (the closing packet's rate limit is in, GOAWAY on reload
and shutdown I1b); HTTP/3 framing, the control and QPACK streams, QPACK over the static
table (the dynamic table both ways I1c), request streams through the shared assembler,
answers with memory and file bodies (streamed upstream bodies I1b), request bodies
pulled from the QUIC buffer; `"h3"` in `protocols` (the `http3.*` keys and `alt-svc`
I1b); the unit vectors and the curl rows of the integration suite (the interop runner,
the loss proxy, the fuzzers and the attack suite I2).

Built later the same day: the per-worker sockets with the reuseport program (6.1), the
QPACK dynamic table on the decoder side (7.2), and the transport rows of I1b as 6.3, 6.4,
6.7 and 6.9 describe them, with these corrections found on the way. Retry tokens are
sealed with AES-128-GCM under a key derived per hour from the process secret, bound to
the address, the original id and the time, ten seconds of validity; an Initial whose
token does not open is answered with an INVALID_TOKEN close under the client's Initial
keys (RFC 9000 8.1.2), which costs one key schedule and no state. The stateless reset
token of an id is HMAC-SHA256 of the id under the same secret, so the token in our
transport parameters and in every NEW_CONNECTION_ID is computed, never stored, and a
worker answers a short-header packet for an unknown id with a reset one byte shorter than
the packet (43 bytes at most), never for a packet under 22 bytes, at most 1,000 per
second. Key update: the header-protection key does not change across updates (RFC 9001
6.1), which the first version got wrong (every packet after the update failed to open
with a garbage packet number); `Keys::install_next` copies it from the current keys.
The anti-amplification limit is a byte allowance, not a count of full datagrams: a
client that changed its address sends a small packet, and a check of "one more full
datagram fits" starved the PATH_CHALLENGE that validates the path; the datagram now
shrinks to what the allowance leaves (and the challenge goes unpadded when 1,200 bytes
do not fit, as 8.2.1 allows). A path MTU probe belongs to the path it was sent on: the
acknowledgement of a probe sent before the address changed no longer raises the new
path's datagram size. MAX_STREAMS: sent in a datagram of its own after every closed
stream, it cost a client with one request at a time a packet and an acknowledgement per
request (the trace of 6.7's timeline showed it); it rides on the next packet sent for
another reason and goes alone only when the peer's room is under a quarter of the limit.
The attack suite is `tests/h3-attacks.py` on aioquic (in the devbox image), driving the
connection by hand over its own sockets: handshake, retry (both modes), invalid-token,
key-update, key-update-twice (KEY_UPDATE_ERROR; the client, two phases ahead, cannot open
the close and sees a connection that answers nothing), rebind (answers follow the client
to its new port after validation), cid-retire (replacements), stateless-reset,
forged-flood (3,000 forged packets on a live id), rapid-reset (H3_EXCESSIVE_LOAD past
128 in a second), stream-flood (STREAM_LIMIT_ERROR), control-stream (a second SETTINGS),
handshake-flood (1,500 Initials in 1.1 s: Retry past the half budget in "auto", every one
in "always", a real client answered after). The rows that need raw frames or a spoofed
source (amplification, optimistic ACK, the connection-id and flow-control games) and the
interop runner stay in I2.

## 13. Sources

- RFC 8999 (QUIC invariants), RFC 9000 (transport), RFC 9001 (TLS), RFC 9002 (loss
  detection and congestion control), RFC 9114 (HTTP/3), RFC 9204 (QPACK), RFC 9438
  (CUBIC), RFC 8899 (DPLPMTUD), RFC 9287 (greasing the fixed bit), RFC 9369 (version 2).
- OpenSSL 3.5: `SSL_set_quic_tls_cbs(3)`, `SSL_set_quic_tls_transport_params(3)`,
  `SSL_set_quic_tls_early_data_enabled(3)`; the `OSSL_FUNC_SSL_QUIC_TLS_*` dispatch
  entries in `openssl/core_dispatch.h`; ngtcp2's `crypto/ossl` as the reference user.
- Linux: `udp(7)` (`UDP_SEGMENT`, `UDP_GRO`), `socket(7)` (`SO_ATTACH_REUSEPORT_CBPF`),
  `ip(7)` (`IP_MTU_DISCOVER`, `IP_PKTINFO`), `sendmmsg(2)`, `recvmmsg(2)`.
- nginx: `ngx_event_quic*`, the `quic_gso`, `quic_bpf`, `quic_retry`, `quic_host_key`
  and `http3_stream_buffer_size` directives; quic-go's GSO and ECN notes; quicly and
  Kazuho Oku's "fusion" AES-GCM; HAProxy's QUIC threading and `quic-cc-algo`.
- The QUIC interop runner (marten-seemann/quic-interop-runner) and its test cases; the
  arena's `scripts/lib/tools/h2load-h3.sh` (64 connections, 64 streams, `--alpn-list=h3`)
  and `frameworks/nginx/nginx.conf`; the board's `nginx.json` and `caddy.json` for the
  HTTP/3 rows.
- `docs/design-http2.md` sections 4, 5, 6.2.1, 6.6, 6.9, 7.3 and 8, whose decisions this
  document extends.
