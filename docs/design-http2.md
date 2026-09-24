# Design: HTTP/2 (phase G)

Status: accepted 2026-09-23 as proposed (every question of section 11) and G0 built the
same day. Two departures from the plan, both forward: request bodies (G1's first item) are
delivered in G0 already, because a stream that answers before its body has ended must
keep reading it to stay conformant, so the DATA path was needed anyway; and a stream whose
response is complete while its body is still open is kept half-closed and drained up to
64 KB (RST_STREAM(NO_ERROR) beyond, or for an unbounded body) rather than reset at once,
which is what h2spec's flow-control and content-length cases expect. h2spec: 146 of 146
over TLS, 145 of 146 on the plain listener, where an invalid preface is a malformed
HTTP/1 request and gets a 400 in HTTP/1 form (case 3.5/2 cannot read that as a frame).
G0 numbers against the targets of 7.1 (`bench/results/ab-20260923-171228.md`,
`h2-20260923-164706.md`, `h2-20260923-171144.md`): 0.2 to 0.4 us over HTTP/1 at one stream
per connection, below HTTP/1 at ten, 30 to 45 % less CPU per request than nginx on every
small-file row, 27 % less on the 10 MB TLS stream and 28 % less on 100 KB at ten streams
once levers 5 and 6 of 7.2 were in (the same day); the HTTP/1 rows of the A/B unchanged.
G2 (the same day): four workers 1.59M req/s on h2c against nginx's 665k; idle memory per
connection 19 KB against nginx's 7.5 KB and Caddy's 35 KB (section 7.3).

## 1. Goals

- Serve HTTP/2 (RFC 9113) with HPACK (RFC 7541) on every TLS listener through ALPN, and
  on plain listeners through the prior-knowledge preface when enabled, for every handler
  agensio has: static files from the cache, FastCGI, proxy, CGI, redirects, the ACME
  challenge. The control API stays HTTP/1 on its unix socket.
- The fastest and cheapest of its kind: CPU per request and memory per connection below
  nginx on the same box, with one worker and with several, measured with `h2load` the way
  phase 1 measured HTTP/1 with `wrk`.
- HTTP/1.1 unchanged: no cost on its path while HTTP/2 is idle and none when it is off,
  proven by the A/B gate on every step.
- A protocol layer: each protocol in its own directory with one contract to the request
  core, so that HTTP/3 (phase I) is a third directory and not a rewrite, and a new
  protocol feature is a change in one place.
- Secure by construction against the published attack classes (Imperva 2016, Netflix
  2019, Rapid Reset 2023, CONTINUATION 2024, MadeYouReset 2025, the HTTP/2 Bomb of June
  2026), with every limit a number in this document and a test in the suite.

Not in phase G: server push (Chrome removed it in 2022, nginx in 1.25.1), HTTP/2 to
origins (h2c, gRPC; a phase D item once the codec exists, see 5.5), the RFC 7540 priority
tree (deprecated by RFC 9113), `Upgrade: h2c` (dropped by RFC 9113), TLS-ALPN-01 (only
the ALPN hook is reserved), RFC 8441 CONNECT for WebSockets over h2 (G4).

## 2. What the other servers do

| Server | HTTP/2 code | HPACK | Worth knowing |
|---|---|---|---|
| nginx | own (`ngx_http_v2`) | own; decoder with a 4 KB dynamic table, encoder uses static indexes and literals, Huffman when shorter, never fills the dynamic table (Cloudflare carried a "full HPACK encoding" patch for exactly that) | `http2 on` per server since 1.25.1; h2c by prior knowledge with the same directive; 128 streams, `http2_body_preread_size 64k` (the upload complaints, section 3), `http2_chunk_size 8k`, a 256 KB receive buffer per worker; push removed 1.25.1; HTTP/2 to upstreams only since 1.29.4 (2026); Rapid Reset fix (1.25.3) caps new streams per event-loop iteration at 2x `http2_max_concurrent_streams`; 2026: HTTP/2 Bomb fixed in 1.29.8, a heap overflow on crafted HTTP/2 headers (CVE-2026-42055), request injection in the HTTP/2 proxy path (CVE-2026-42926), about 24 memory-safety advisories concentrated in the h2 and h3 code |
| Caddy | Go `net/http` + `x/net/http2` | Go's | h2 default on, h2c with `protocols h1 h2c`; HTTP/1.1 cannot be switched off while h2 is on; Rapid Reset fix counts resets (CVE-2023-39325); a goroutine per stream is behind the memory reports; 285k vs nginx's 310k req/s on a 2026 bare-metal static comparison |
| lighttpd | own (1.4.56, 2020) | LiteSpeed's `ls-hpack` | the closest model to ours: own framing and state machine, a library only for HPACK; small footprint |
| h2o | own | own | the reference scheduler (fair, RFC 9218 urgency); Fastly's fork carried the MadeYouReset fix |
| HAProxy | own h2 mux | own | "architecturally safe" from the 2026 Bomb by strict per-connection memory; the glitches counter (`fc_glitches`), threshold 200, graceful GOAWAY at 75 % of it, `tune.h2.fe.max-rst-at-once`; h2 to backends |
| Apache httpd | nghttp2 (mod_http2) | nghttp2 | CONTINUATION flood (CVE-2024-27316), Bomb (mod_http2 < 2.0.41); the "mod_http2 stability" complaints |
| Envoy | nghttp2, then Google's oghttp2 (1.34) | in the codec | oghttp2 cost 15 to 25 % RPS per core on header-heavy traffic because it materialises decoded headers byte by byte into `std::string` (13 to 20 % of all Envoy CPU) where nghttp2 writes into caller buffers; the codec plumbing was 20 to 30 us per request there |
| Node.js, curl | nghttp2 | nghttp2 | the library's users patch when it patches: the CONTINUATION limit arrived in nghttp2 1.61 (CVE-2024-28182) |

What the record says, in one line each:

- Header materialisation is where an HTTP/2 codec's CPU goes; frames are cheap. A codec
  that copies decoded fields once, into storage the request already owns, wins.
- The encoder needs no dynamic table to be fast and small; nginx never used one.
- Every published attack is a missing bound: on streams per unit of time, on header
  bytes per block, on decoded bytes per block, on memory held per connection, on
  progress per unit of time. Servers with one memory budget per connection (HAProxy) were
  not affected by the 2026 Bomb; servers with a list of unrelated limits were.
- Library codecs bound what a server can do about output copying, header storage and
  attack limits, and the memory-safety advisories cluster in exactly this code whoever
  writes it: the answer is bounded buffers and fuzzing, not the choice of author.

## 3. What administrators say

From `docs/web-server-feedback.md` and the HTTP/2 threads read for this design:

1. **Turn it on and forget it.** `http2 on` is nginx's whole configuration and Caddy's
   default; nobody wants to tune windows or tables. Consequence: one key to switch,
   defaults that need no tuning, every limit derived from the keys they already know.
2. **Uploads are slower over HTTP/2** than over HTTP/1.1 (2 MB/s against 25 MB/s in the
   Nextcloud reports, Firefox bug 1868987, Cloudflare's post on autotuning): a fixed
   64 KB window per stream cannot fill a link with a large bandwidth-delay product.
   Consequence: the receive window follows the site's body limit and the consumer's
   pace, not a constant (6.5).
3. **A new HTTP/2 CVE every year** and a patch cycle each time (Rapid Reset, CONTINUATION,
   MadeYouReset, Bomb). They want a server that is safe by construction and, while a
   patch is pending, a switch to turn HTTP/2 off without touching anything else.
   Consequence: section 8, and `protocols` as a one-line switch.
4. **Memory blowups** (Caddy OOM kills, mod_http2, the Bomb's 32 GB in 20 s). Consequence:
   a per-connection budget with a number, measured and published.
5. **Hard to debug.** They want the protocol in the access log (`$http2` in nginx), and
   error messages that name the stream, the frame and the reason when a connection is
   dropped. Consequence: `HTTP/2.0` in the request line of the log, a `protocol` field
   in JSON, an error-log line for every GOAWAY and RST_STREAM the server sends.
6. **Per-IP limits stop working** when one connection carries hundreds of requests.
   Consequence: the rate limits of phase E count streams, not connections; noted there.
7. **HTTP/2 to backends** (gRPC, h2c) took nginx until 2026; HAProxy and Caddy had it.
   Consequence: the codec is written so its client side is the same code (5.5).
8. **Nobody misses push or priorities.** Consequence: neither is built.

## 4. Library or our own code

| Option | What it gives | What it costs | Verdict |
|---|---|---|---|
| A. Own framing, state machine, flow control, scheduler and HPACK | zero copies beyond one into the stream's arena, prebuilt HPACK blocks per cache entry, writes batched across streams into our own `writev` / TLS records, every limit ours, the client side for free later, no runtime dependency | about 3,500 lines plus tests; correctness is ours to prove | **proposed** |
| B. nghttp2 session (the roadmap's 2026-09-16 plan) | ten years of conformance, HPACK included, the same author's nghttp3 for phase I | its own frame buffers copied into ours, headers delivered per callback and copied again, allocations per stream and frame through `nghttp2_mem`, an encoder that runs per response (no prebuilt blocks), a priority tree to switch off, limits added when the library adds them (CONTINUATION: 1.61), a session API that drives one output stream rather than a scheduler we can batch | rejected for the runtime, kept for tests |
| C. Own framing + `ls-hpack` (lighttpd's choice) | a proven HPACK | a dependency to vendor and justify for about 700 lines of ours; its API decodes into its own buffers | rejected |
| D. Own framing + nghttp2's public HPACK API | a proven HPACK, one dependency we would carry for phase I anyway | same copy as B for headers; the encoder cannot prebuild | rejected |

Proposal: **A, with nghttp2 in the test bed only**: `libnghttp2` as the oracle of a
differential fuzzer for our HPACK decoder (every input decoded by both, outputs compared),
`h2load` as the load generator, `nghttp` as a client in the integration suite, and
`h2spec` for conformance. None of them ships in the binary.

This reverses decision 1 of the roadmap's section 4 ("start with nghttp2 and ngtcp2 +
nghttp3; if the numbers disappoint, write HTTP/2 framing + HPACK"). The research above is
the reason: a library codec's cost is header materialisation and output copying, which
no amount of tuning on our side removes, and the attack limits arrive at the library's
pace. QUIC (phase I) stays a library (ngtcp2): a transport with its own crypto, loss
recovery and congestion control is a project of its own. Whether HTTP/3 framing and
QPACK use nghttp3 or our code is decided in phase I with the same test as here.

Cost estimate, lines of C++: framing 300, HPACK 700 plus a generated Huffman table,
streams and flow control 600, scheduler and writer 800, connection 900, shared field
rules 200; tests, fuzzers and attack scripts about as much again. The risk is
correctness, and the mitigations are named in section 8: h2spec, two fuzzers, one of
them differential, an attack suite that measures memory, sanitizer runs, and the
`security-review-cpp` checklist on every file.

## 5. The protocol layer

```
   listeners      TCP                     TCP + TlsStream (ALPN)            UDP (phase I)
                   |                        |                                 |
   protocol        v  preface?              v  "h2"?                          v
   selection    Http1Connection ---------> Http2Connection              Http3Connection
                (one Stream)   hand-over  (a Stream per stream id)      (ngtcp2 + h3 framing)
                   \                          |                              /
                    \                         v                             /
                     +------------------> Stream <-------------------------+
                                     Request, Response, ConnectionInfo
                                              |
                                          Dispatcher -> handlers -> upstreams
```

### 5.1 The contract every protocol connection fulfils

There is no base class and no virtual call on the request path: `Http1Connection<Socket>`
and `Http2Connection<Socket>` are templates over the socket type, like today, and the
contract is what the rest of the server relies on:

1. It owns the transport (socket or TLS stream) and its timer, and counts itself in
   `Worker::connections`.
2. It produces `Stream`s: a `Request` whose views point into storage the stream owns for
   its life (HTTP/1: the receive buffer; HTTP/2: the stream's arena), the request body as
   a `StreamBody` pulled with backpressure, `ConnectionInfo` filled once.
3. It drives the dispatcher the way `Http1Connection::dispatch` does: `route`, the static
   hops, or a handler with a `done` callback guarded by a per-stream generation counter.
4. It writes a `Response` in its own framing: status, the per-worker `Server` and `Date`,
   the response's prebuilt block for its protocol, the extra fields, then the `Body`
   (memory, file, or a `StreamBody` pulled one chunk at a time).
5. It applies the server's limits and timeouts (`max_header_size`, `max_body_size` per
   site, `idle_timeout`, `body_timeout`, `max_requests_per_connection`) in the terms of its
   protocol, and its own protocol's limits (section 8).
6. It refreshes its generation at each request boundary (one pointer compare) and retires
   when its listener leaves the configuration.
7. It logs each request through `WorkerLogs` with the protocol named.
8. It reports a client abort to the upstream exchange in flight (E9): HTTP/1 by an EOF
   watch, HTTP/2 by `RST_STREAM`.

### 5.2 Protocol selection: the seam, and why HTTP/1 does not pay for it

- **TLS listeners.** The ALPN protocol list comes from `[server] protocols` and is set on
  every context a generation builds (`SSL_CTX_set_alpn_select_cb`), so a reload can
  change it. After its handshake `Http1Connection::start` reads the selected protocol
  (`SSL_get0_alpn_selected`); on `h2` it hands the TLS stream, the certificate names, the
  generation and the listener to a new `Http2Connection<TlsStream>` and retires. That is
  one branch on the handshake path, which runs once per connection.
- **Plain listeners.** When `protocols` contains `h2c`, the parser's 505 branch (the only
  place a request line `PRI * HTTP/2.0` can land) checks the 24-byte preface and hands the
  socket over with the bytes already read. Nothing on the HTTP/1 request path changes;
  the check sits behind a failure that HTTP/1 clients never take.
- The accept code, the control socket and the tunnel hand-over (D3) are untouched. The
  hand-over follows `start_tunnel`'s precedent: the retiring connection cancels its timer,
  moves its socket, and the new object counts itself in.

### 5.3 What changes outside `src/http2/`

| Where | Change | Cost to HTTP/1 |
|---|---|---|
| `core/response.hpp` | `prebuilt_h2` view next to `prebuilt_headers`: the same four cached headers as an HPACK block | none on the hit path (a view set by the static handler, as `prebuilt_headers` is) |
| `cache.hpp` | `CacheEntry::h2_block`, built once at insert next to `headers` | the miss path only |
| `response.cpp` | error pages and redirects get their HPACK blocks at startup, like their text ones | none |
| `core/request.hpp` | `Request::protocol` view (`HTTP/1.1`, `HTTP/2.0`) for FastCGI's `SERVER_PROTOCOL` and the access log | one view assignment per request |
| `services/log.hpp` | `AccessRecord::protocol` replaces the assumption `HTTP/1.x` | none measurable |
| `core/fields.hpp` (new) | the RFC 9113 / 9114 field rules shared with HTTP/3: forbidden connection-specific fields, `TE`, pseudo-header order, byte validity of names and values | not on the HTTP/1 path |
| `server.hpp/.cpp` | `Listener::alpn` (the wire-format list) from `protocols`; ALPN callback on the contexts | handshake only |
| `config.*`, `control/reference.cpp` | the two keys of section 9, their rows, `docs/keys.md` | none |
| `Headers`, `StreamBody`, `Dispatcher`, `ConnectionInfo`, the handlers, the upstream pool | unchanged | none |

### 5.4 Source layout

```
src/http2/
  frame.hpp          the 9-byte frame header, types, flags, error codes; encode/decode (fuzzed)
  hpack.hpp/.cpp     decoder (static table, dynamic table ring, Huffman), the static-only encoder,
                     prebuilt-block helpers (fuzzed, differential against nghttp2 in tests)
  huffman_table.hpp  generated from RFC 7541 appendix B by tools/gen-huffman.py (checked in with it)
  settings.hpp       SETTINGS identifiers, the values we advertise, the peer's values
  stream.hpp         H2Stream: state, windows, arena, the embedded Stream, body state, scheduler links
  connection.hpp     Http2Connection<Socket>: reads, frame dispatch, stream table, timers, budgets,
                     GOAWAY and errors, generation refresh, access log
  writer.hpp         the head as HPACK, DATA framing onto writev / TLS records / sendfile, the
                     scheduler's write cycle, StreamBody pulls
src/core/fields.hpp  field rules shared by h2 and h3
tools/gen-huffman.py
tests/fuzz/fuzz_h2_frame.cpp, fuzz_hpack.cpp   (+ regressions/)
tests/h2-attacks.py  the attack suite of section 8 (raw sockets)
bench/h2/run.sh      h2load rows against nginx and Caddy
```

### 5.5 What this buys HTTP/3 and the proxy

`http3/` will own a UDP listener and a QUIC transport and reuse: `fields.hpp` (RFC 9114
has the same field rules), the prebuilt-block pattern (a QPACK block that uses only the
static table is as state-independent as ours), `Request::protocol`, the Stream and
StreamBody contract, and the scheduler's shape (QUIC does flow control, so less of it).
The framing and HPACK modules have no notion of "server": the same code encodes a
request and decodes a response, which is what `upstream = "h2c://..."` and gRPC to
origins need later.

## 6. The HTTP/2 connection

### 6.1 Framing

The connection reads into the 16 KB receive buffer HTTP/1 uses, with the E9 discipline
(`read_at_`, settle, compact). A frame is handled when complete; the payload cap is the
16,384 bytes we advertise as `SETTINGS_MAX_FRAME_SIZE`, so the buffer is that plus nine,
and a larger frame is a `FRAME_SIZE_ERROR` connection error before a byte of it is
buffered. Unknown frame types are ignored as the RFC requires; padding is validated;
frame header fields are read with bounds checks (CERT INT30, ARR30).

### 6.2 HPACK

Decoder: the 61-entry static table; a dynamic table as a ring of bytes capped at the
4,096 we advertise as `SETTINGS_HEADER_TABLE_SIZE` (an update above it is a
`COMPRESSION_ERROR`); Huffman decoding by a state table generated from the RFC's code
(`tools/gen-huffman.py`, output checked in and diffed by a unit test). Each decoded name
and value is appended once to the stream's arena and the `Headers` entry points there:
one copy, no allocation per field (the arena keeps its capacity between requests).
While decoding, the list size per RFC 7541 4.1 (name + value + 32 per field) is added
up and compared with `SETTINGS_MAX_HEADER_LIST_SIZE` (= `max_header_size`, 16 KB) at
every field: the classic HPACK bomb and the 2026 Bomb stop at the first byte over the
limit, before the arena grows, with an `ENHANCE_YOUR_CALM` connection error (a peer that
does this is not a browser).

Encoder, as built in G0: static indexes for the table's names and values, literal
without indexing for everything else, Huffman when it is shorter, and no dynamic table
at all: nginx's discipline, which makes every encoding state-independent. That is what
allows **prebuilt blocks**: the cache entry's headers become one HPACK block at insert,
Huffman-encoded once; error pages and redirects get theirs at startup; the per-worker
`server` and `date` pair is re-encoded once per second like `prefix200`. nginx encodes
every header of every response; we copy. Since 6.2.1 below (2026-09-24) the entry's
block is the *tail*, `content-length`, `last-modified`, `etag` and `accept-ranges`, and
the fields that repeat across a connection go through the connection's own dynamic
table: a static answer's head is the status byte, three index bytes and the tail.

#### 6.2.1 The dynamic-table head (designed and built 2026-09-24)

**Why.** With the write batching in, the arena's HTTP/2 baseline costs agensio 1.23 µs of
thread time per request against h2o's 0.68 at most. Captured with `nghttp -v`, our
HEADERS block is 48 bytes on every answer and h2o's is 7 after the first: `server` and
`date` as literals are 33 of our bytes, `content-type` 10 to 12 more, and encoding them
(`static_name_index`, Huffman) is about 5 % of the profile. On the wire an answer is 67
bytes from agensio and 26 from h2o; segments, TLS records and the client's decoding all
scale with it. The static-only encoder was the right first step; this adds a dynamic
table on the encoder side, while the prebuilt blocks stay prebuilt.

**What h2o does** (read in `lib/http2/hpack.c` and `lib/http2/connection.c`, 2026-09-24).
Its encoder, `do_encode_header`, tries the static table, then scans its dynamic table
for a name-and-value match and emits an index; otherwise it emits a *literal with
incremental indexing*, so every field it sends is inserted, except the tokens flagged
`dont_compress` (`cookie`, `set-cookie`, sent never-indexed) and `content-length`,
which `encode_content_length` always sends as a literal without indexing; `:status`
has its own fixed encoding. The table is capped at 32 entries
(`header_table_add(..., 32)`) and at the peer's `SETTINGS_HEADER_TABLE_SIZE`
(`header_table_adjust_size` only ever shrinks it, emitting the size update); eviction
is oldest first. Nothing is cached between answers: the same fields are looked up and
re-encoded per response, which is cheap once they are indexes. Its `date` is an ordinary
header the application adds (`h2o_resp_add_date_header`, from a per-context timestamp
cached per second); the arena's h2o entry does not add it, which is why its block is 7
bytes and not 8. Its writes are gathered per event-loop iteration: `request_gathered_write`
links a zero-length timer, `emit_writereq` then appends every stream's frames to one
buffer and writes once, and requests parsed from a read are queued in `_pending_reqs`
and run in order. That is the batching we built in 6.6, with one difference noted at
the end of this section.

**What goes into the table.** h2o's rule, with two deviations:

| field | representation |
|---|---|
| `server` | inserted once per connection, then one index byte; the encoder remembers its sequence, no scan |
| `date` | inserted once per second per connection, one index byte between; the insertion bytes are prebuilt per worker-second like today's literal, and the encoder remembers the second, no scan |
| `content-type`, `vary`, `content-encoding`, `cache-control`, `x-powered-by`, any other field of a handler's or an upstream's text block | h2o's rule: an index when the table holds name and value (a scan of at most 32 entries), else inserted |
| `content-length` | literal without indexing, like h2o: it changes per answer |
| `set-cookie`, `cookie`, `authorization`, `proxy-authorization`, `www-authenticate` | never indexed, and never inserted (RFC 7541 7.1.3) |
| `etag`, `last-modified`, `accept-ranges` of a cache entry | literal, in the entry's prebuilt tail, not inserted (deviation one) |

Deviation one: validators stay literal. A page load asks for tens of different files on
one connection, and inserting each file's `etag` and `last-modified` pushes 130 bytes of
table per file and evicts the fields that do repeat; with the cache entry's tail prebuilt
at insert, a static answer touches the table only for `server`, `date` and
`content-type`. The static rows lose nothing measurable by it: their bytes are the
bodies. Deviation two: we keep sending `date` (RFC 9110 requires it of an origin
server); through the table it costs one byte per answer and one insertion per
connection-second.

**The encoder's state, per connection** (`hpack::Encoder`): the same ring of bytes the
decoder uses for its dynamic table (`hpack.cpp`, allocated on the first insertion, so an
idle or HTTP/1-only connection pays nothing), with the entries' offsets and sizes, the
total size, `next_seq`, the remembered sequences of `server` and `date` and the date's
second, the size the peer's decoder assumes and a pending size update. An entry
inserted with sequence *s* has index `61 + next_seq - s` at emission time, so a
reference is computed per representation and stays right across insertions earlier in
the same block. An insertion adds `name + value + 32` and evicts oldest first until the
total fits, exactly what RFC 7541 4.4 makes the decoder do, so the two tables never
differ; using the decoder's own ring for it is what makes that a property of the code
rather than a promise.

**Table size.** `min(the peer's SETTINGS_HEADER_TABLE_SIZE, 1024)` and at most 32
entries like h2o: the fields that repeat on a real connection are a dozen, under 800
bytes, and a small ring keeps the per-connection memory near the idle 19 KB (h2o uses
the peer's 4,096; the difference is measured on the static-h2 and proxy rows during the
build, and the constant is one line). The first block on a connection begins with a
dynamic table size update to our size when it is below the peer's (RFC 7541 4.2, 6.3),
since the decoder assumes the SETTINGS value until told; a later SETTINGS that lowers the
limit shrinks the table, evicting, and the next block begins with the update; a limit of
0 disables insertion and the encoder falls back to today's literals. When the limit drops
and rises again before a block goes out, the block carries two updates, the lowest size
used and then the current one, so a decoder that evicts only on our updates loses the
same entries we did (RFC 7541 4.2; the fuzz target found the case). The decoder side is
untouched: we still advertise 4,096 and never depend on the client inserting anything.

**Where it plugs in.** `build_head` becomes: status index; `server` and `date` through
their remembered sequences (the worker keeps `h2_date_insert`, the insertion bytes for
the current second, next to `prefix200`); `content-type` through the table, the value
from the entry (`CacheEntry::content_type`, the error page's type, the text block's
field); then the entry's prebuilt **tail** (`content-length`, `last-modified`, `etag`,
`accept-ranges`, unchanged HPACK literals, still built once at insert) or the text
block's remaining fields through the table; `vary` and `content-encoding` through the
table for a twin; extra fields through the table. Per answer a static entry costs two
sequence compares and, since the per-request step of 2026-09-24, one more for its
content type: the encoder remembers the sequence of the last content-type it sent
through the table (`Encoder::content_type`), so a run of answers of one type costs a
comparison and an index byte, and only a change of type scans the table. A text block
costs a scan per field, what h2o pays for every field of every answer; the arena
handler no longer has one: its answer carries the type and a prebuilt content-length
literal, like a cache entry. Nothing changes for HTTP/1 or for the request path;
HTTP/3's QPACK will get the same encoder with its own instructions. On the decoder,
the same step stopped copying static-table fields into the arena (their views point
at the table, which lives for the program; dynamic entries are still copied, since a
later insertion in the same block can evict them) and made the Huffman decoder write
through a pointer into the arena, grown once per literal from the 5-bit minimum code
length, instead of a `push_back` per symbol.

**Expected effect.** The baseline-h2 block from 48 bytes to 7 or 8 (status, server, date
and content-type one byte each, content-length three), the answer on the wire from 67
bytes to about 27, h2o's 26; a static file's head from about 95 bytes to about 55, the
validators staying literal. Fewer bytes per record on TLS and less to decode on the
client, which shares the arena's machine.

**Correctness.** The failure mode is a table out of step, which a client answers with a
`COMPRESSION_ERROR` on the whole connection, so: unit tests round-trip sequences of
answers through `hpack::Encoder` and our own RFC-vector-tested `Decoder` under every
table size, with evictions, a SETTINGS change mid-way and a limit of 0; a libFuzzer
target drives random answer and settings sequences through the same pair; `nghttp -v`
in the integration suite checks the block lengths of the first and second answer on one
connection and that both decode; h2spec on both listeners as before; the arena's
validator. Gate: `bench/ab.sh <ref> -2` flat on the single-stream and HTTP/1 rows, the
pinned baseline-h2 row and `bench/h2/profile.sh` before and after.

**Bundled small items, same hot path, measured together (done in the per-request
step that followed, 2026-09-24):** one wall-clock and one steady-clock read per read of
the socket instead of two per stream (6.6), and the synchronous handler's completion
in the `std::function`'s own storage instead of on the heap (a two-word, trivially
copyable capture; the connection completes or cancels the body read itself, so no
owning reference is needed).

**The one gathering difference left, for later.** h2o gathers writes per event-loop
iteration, so answers that arrive asynchronously in one iteration (a hundred upstream
completions delivered by one `epoll_wait`) leave in one write too; our hold covers the
frames of one read, and an upstream answer still starts its own cycle. A posted flush
(`asio::post` runs after the completions already queued) would gather those as well, at
the cost of one loop trip for a connection with a single answer per iteration. To be
measured on the proxy and FastCGI HTTP/2 rows, not part of this step.

### 6.3 Streams

`H2Stream` holds the id, the state, the embedded `Stream` (Request and Response), the
arena, the send and receive windows, the request body state, the per-stream generation
guard for late upstream callbacks, and its links in the scheduler's lists. Streams are
pooled per connection with a free list, so once a connection has reached its concurrency
a new request allocates nothing (HTTP/1's property, kept). The table is a small
open-addressing map by id, sized for the 128 concurrent streams we allow. The state
machine is RFC 9113 5.1 reduced to what a server without push needs: idle, open,
half-closed (remote), closed; ids must increase; a lower id is a `PROTOCOL_ERROR`; a
frame for a closed stream within the last few ids is tolerated (in flight when we
reset), beyond that it counts as a glitch (6.9).

### 6.4 Request assembly and validation (`core/fields.hpp`)

Applied while decoding, so nothing invalid ever reaches the dispatcher:

- pseudo-headers before regular fields, each at most once; `:method`, `:scheme`,
  `:path` required (`:path` non-empty, `*` only for OPTIONS), `:authority` becomes
  `Request::host` and a synthetic `host` field so handlers see HTTP/1's shape; a `Host`
  field that differs from `:authority` is malformed (RFC 9113 8.3.1);
- field names lower-case and token characters only; values without CR, LF or NUL
  (RFC 9113 8.2.1 says malformed, and this is the HTTP/2 to HTTP/1.1 smuggling class of
  2021: what we forward to php-fpm or an origin can never contain a line break);
- `connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`
  forbidden; `te` only as `trailers`;
- `content-length` must match the DATA bytes received (else `PROTOCOL_ERROR`); a length
  above the site's body limit is answered 413 as HTTP/1 does, then the stream is reset;
- several `cookie` fields are joined with `; ` into one at decode time (RFC 9113 8.2.3),
  which also defeats "cookie crumbs" as a way around the field count;
- at most `Headers::kCapacity` (100) fields including the crumbs, 16 KB decoded, 16 KB
  compressed per block (6.9);
- trailers are accepted (a HEADERS after DATA with END_STREAM), validated, and dropped.

A malformed request is a `RST_STREAM(PROTOCOL_ERROR)` plus an error-log line naming the
remote, the stream and the rule, like `log_bad_request_line` does today.

### 6.5 Request bodies and the receive windows

DATA frames land in the stream's body buffer and the handler pulls them through the same
`StreamBody` interface as HTTP/1 (the FastCGI, proxy and CGI code does not change). The
window is the memory budget: the stream starts with the protocol default of 65,535, and
when a body is announced and a consumer is attached the connection grants it up to
min(site body limit, 1 MB), sending `WINDOW_UPDATE` as the consumer drains (at half of
the grant, the usual heuristic). The connection window is raised to 1 MB at the preface
and bounds the total buffered across streams. So an upload runs at the pace of the disk
or the origin, not at 64 KB per round trip (complaint 2), and the memory held for
bodies has a ceiling of 1 MB per connection whatever the client does. A body the
handler did not read is drained after the response, as in HTTP/1, with the window
returned as it drains.

### 6.6 Responses, flow control and the scheduler

A stream is ready when its `Response` is filled. The writer runs one write cycle at a
time per connection: it takes ready streams in order (FIFO by readiness with rotation,
RFC 9218 urgency as the sort key in G4), gives each up to one quantum (16 KB) within its
send window, the connection window and the peer's `SETTINGS_MAX_FRAME_SIZE`, and
assembles:

- one buffer per cycle (2026-09-24, the third shape of the cycle): control frames,
  every stream's HEADERS frame built straight into it by the encoder, DATA frame headers,
  and payloads up to `kCopyMax` (2 KB) copied behind their header. A larger payload on a
  plain socket (a cache entry, the stream's chunk) is written from where it is, as a
  scatter entry between the buffer's runs, so a 100 KB file still costs no copy; the
  entries per cycle are bounded (`kMaxExternal`, 128), as asio hands the kernel 64 per
  call. The answers of one read therefore leave in one `send`. Before this, a cycle was
  a scatter list of up to 256 pieces (a head piece per stream, a 9-byte header piece and
  a payload piece per frame) coalesced into a buffer when small, which capped a cycle at
  85 small answers and made two sends of a read's answers, and built every head in a
  per-stream string first, copied later;
- a file body as a pre-framed block: up to four frames read with one `preadv` straight
  into the payload slots of the stream's chunk, the headers written in place, one
  contiguous piece and no copy (built in G0; `sendfile` per frame on plain sockets stays
  a G2 measurement);
- on TLS, DATA payloads of 16,375 bytes so one frame with its header is exactly one
  16 KB record; every payload but a pre-framed block is copied into the cycle's buffer
  (`TlsStream` encrypts one buffer per write, so a separate 9-byte header piece would
  be a record of its own), and the blocks are written as their own entries, each an
  integral number of records; a cycle takes at most 64 KB of body (256 KB on plain
  sockets), because once the write batching filled every cycle, 256 KB cycles copied
  and encrypted outside the cache and cost the arena's static-h2 row 9 % (2026-09-24:
  770k to 834k req/s pinned, at less CPU and a third less memory).

The cycle is held while the connection runs the frame loop of one read (`Writer::Hold`,
2026-09-24): every answer, window update and control frame the frames of that read
produce leaves in one cycle when the loop ends. Before, a cycle started the moment one
stream was ready, the write completed inline on a fast socket, and the next cycle began
with whatever two or three streams were ready by then: the arena's baseline-h2 profile
counted one `sendmsg` per 2.4 answers, 61 % of the cycles in the kernel. A connection
with one stream per read sees no difference, and nothing waits past the loop iteration
that produced it.

A `StreamBody` (FastCGI, proxy, CGI) is pulled one chunk at a time per stream and at most
`kPullBudget` (8) streams pull at once per connection, so an origin is never read faster
than the client takes (Netflix's "internal data buffering", CVE-2019-9517). A window of
zero parks the stream until a `WINDOW_UPDATE` of at least 1 KB, or the end of the body;
smaller updates are not progress (6.9).

**Emit at respond, designed 2026-09-24, not built.** With the cycle one buffer, an answer
that is complete when `respond()` runs and small enough to be copied (a memory body up
to `kCopyMax`, or no body) needs nothing of its stream once its frames are in the
buffer. Today it waits in the ready list until the hold ends, and its stream stays open
until the write completes: a read with a hundred HEADERS frames therefore holds a
hundred stream objects per connection at once, and with twelve workers that working set
is what costs the row (the twelve-worker profile in the results file: instructions per
cycle 1.54 against 4.16 on one worker, h2o 2.73 against 3.89; h2o frees a stream's
memory as soon as its answer is in the connection's buffer). The change: while the writer
is held and no write is in flight, `respond()` for such an answer appends the HEADERS and
DATA frames to the cycle's buffer at once (the head through the encoder as now), logs
the request, and closes the stream, which goes back to the pool and is the object the
next HEADERS frame of the same read takes; the cycle is sent at release as today.
Answers that arrive asynchronously, bodies above `kCopyMax`, files and sources keep the
ready list and the write-completion path. Expected: a hot working set of one or two
stream objects per connection, the pool small again, the twelve-worker row at the
single-worker efficiency; the h1 rows untouched. Gate: the twelve-worker profile,
the pinned row, the A/B, h2spec and the suites.

The clock is read once per socket event (2026-09-24): the read completion takes the
steady time and the wall time (the `Date` of every answer of that read), the streams the
frame loop opens or answers take that timestamp (`Http2Connection::clock_now`), and a
write completion marks progress on every stream whose bytes it carried, which is also
where the response timeouts of 6.7 count from now (they used to count from the moment
the bytes were queued). A completion from elsewhere, an upstream's answer, reads the
clock itself. Before, a request read the clock four times (open, dispatch, respond,
emit), 9 % of the arena's HTTP/2 baseline profile. Likewise, the pool of released
streams holds as many as the client may have open at once (it held four): a client with
a hundred streams in flight used to construct and free a stream object, with its 200
header views, per request, a fifth of that profile, and the idle shed (7.3) empties the
pool anyway. Stream lookups are O(1): a new stream id is never searched for (it is
above the last one opened), a released stream is found by its slot, and a stream's
presence in the cycle in flight is a flag, not a scan.

### 6.7 Timers

One lazy `steady_timer` per connection, deadlines checked when it fires, as HTTP/1:

| Situation | Limit | Action |
|---|---|---|
| no stream open, no bytes | `idle_timeout` (15 s) | close (a browser reconnects; the admin raises the key for long-lived pages) |
| a stream's head incomplete (HEADERS without END_HEADERS, or waiting for CONTINUATION) | `idle_timeout` | `GOAWAY(ENHANCE_YOUR_CALM)` + close: slow headers |
| a body announced, handler waiting, no DATA | `body_timeout` (60 s) | `RST_STREAM(CANCEL)`, 408 not possible any more, log |
| response pending, no window progress of at least 1 KB | `idle_timeout` | `RST_STREAM(CANCEL)`, buffers freed: the Bomb's "hold", zero-window slow read; progress is marked when a write carrying the stream's bytes completes |
| response pending, socket not draining | `idle_timeout` | close: TCP-level slow read |

### 6.8 Lifecycle

Preface, our SETTINGS (`HEADER_TABLE_SIZE 4096`, `MAX_CONCURRENT_STREAMS 128`,
`INITIAL_WINDOW_SIZE 65535`, `MAX_FRAME_SIZE 16384`, `MAX_HEADER_LIST_SIZE 16384`,
`NO_RFC7540_PRIORITIES 1`), the ACK of the peer's, the connection `WINDOW_UPDATE` to
1 MB. `GOAWAY` with the last stream id: when `max_requests_per_connection` streams have
been opened (nginx's `keepalive_requests`), when the listener left the configuration
(H1's retire), at the soft glitch threshold, at shutdown; streams in flight finish and
the connection closes after `idle_timeout`. Every `GOAWAY` and `RST_STREAM` the server
sends produces an error-log line at level info with the remote address, the stream id,
the error code and the reason in words (complaint 5). The generation pointer is refreshed
per stream, one compare, as HTTP/1 does per request.

### 6.9 Budgets: the misbehaviour counter and the reset counter

Two counters per connection, HAProxy's idea and Go's, made one mechanism:

- **glitches**: every frame that costs us work and serves no request adds one: a PING
  beyond 10 per second, a SETTINGS beyond 10 per second, an empty DATA frame without
  END_STREAM, an empty HEADERS or CONTINUATION, a PRIORITY frame (ignored; deprecated), a
  `WINDOW_UPDATE` below 1 KB while more than 1 KB is pending, a `RST_STREAM` on a stream
  that is idle or long closed, a frame on a closed stream, a `SETTINGS` value out of range,
  a malformed request. At 75 of the budget of 100 the connection sends `GOAWAY` and
  finishes what it has (a slightly broken client keeps working on a new connection); at
  100 it closes.
- **resets**: streams that end before a response went out, whichever side reset them:
  the client's `RST_STREAM` (Rapid Reset), a reset we sent because of the client's own
  violation (MadeYouReset makes the server do the resetting, so server-sent resets count
  the same), a stream cancelled by a timeout. More than `max_concurrent_streams` (128)
  of them within one second closes the connection with `ENHANCE_YOUR_CALM`. A browser
  cancels a handful of requests per navigation; a flood cancels thousands.

The counters are visible: `server_status` reports connections closed by budget, by
reason, since start, and `health` names a listener whose count is climbing.

### 6.10 Client abort

A `RST_STREAM` from the client cancels the stream's upstream exchange at once (the
per-stream generation guard makes the late `done` callback a no-op, as in HTTP/1), frees
its buffers and returns its window. A connection EOF or a client `GOAWAY` cancels every
stream. The HTTP/1 slow-exchange watch is not needed: HTTP/2 tells us.

### 6.11 Access log and observability

The request line is logged as `GET /path HTTP/2.0`, JSON gets `"protocol":"HTTP/2.0"`,
FastCGI gets `SERVER_PROTOCOL=HTTP/2.0` (PHP applications read it). `agensio -t
--explain` prints the protocols of each listener, `server_status` the counts of
connections and streams per protocol, `site_show` whether the site's listeners offer h2.

## 7. Performance plan

### 7.1 What a request costs, and the target

HTTP/1 today on the Linux box: 2.0 us of CPU per plain 1 KB request, 2.7 to 2.8 us over
TLS, two syscalls. HTTP/2 adds per request: a 9-byte header parse, an HPACK decode of
about eight fields (most of them indexed, `:path` and `user-agent` as Huffman literals),
the field rules, a head of four copied pieces, two frame headers, and a scheduler step.
Estimated: 0.2 to 0.4 us. Target for G2: at most 0.5 us over HTTP/1 on the 1 KB TLS row
at one stream per connection, and **below HTTP/1** at ten streams per connection, where
one `writev` or one TLS record carries several responses and the syscalls per request
fall under two. nginx's HTTP/2 will be measured against its own HTTP/1 on the same box
rather than assumed; the published comparisons put HTTP/2 within 10 % of HTTP/1 for it.

### 7.2 The levers, in order of expected impact

1. No allocation per stream once the connection is warm (pooled streams, as many as the
   client may have open, arenas that keep their capacity), the property HTTP/1 has; and
   no allocation for a synchronous handler's completion.
2. No allocation or second copy per header: decode straight into the arena, views out;
   static-table fields not even that.
3. Prebuilt HPACK blocks per cache entry and per error page, the connection's dynamic
   table for `server`, `date`, `content-type` and what a text block repeats (6.2.1): a
   static answer's head is copied, not encoded, and the repeating fields cost a byte.
4. One syscall per write cycle across streams: the cycle is one buffer with large
   payloads as scatter entries on plain sockets, full records on TLS, held across a
   read's frame loop so a read's answers are one send (6.6).
5. DATA payloads sized to the TLS record, so framing never splits a record (G0: the
   10 MB TLS stream went from 2864 to 2017 us per request, nginx's 2771 overtaken).
6. Files read with one `preadv` into pre-framed chunks, no copy (G0); `sendfile` per frame
   on h2c is a G2 measurement; kTLS later removes the encrypt copy over TLS.
7. Immediate executors and the inline budget, shared with HTTP/1 (item 1 of the notes).
8. One lazy timer per connection, no timer per stream (the D1 lesson: `timerfd_settime`
   was two of seven syscalls).
9. The Huffman decoder as a nibble-table walk writing through a pointer, the encoder as a
   table lookup at build time. (A byte-wide table was considered and not built: 256 KB
   does not stay in L1 the way the 16 KB nibble table does.)
10. The clock read once per socket event, not per stream (6.6); routing and target
    normalisation with their common-case shortcuts (one site behind the listener, a
    target with nothing to decode or collapse).
11. The receive buffer released when a connection has been idle for a while (G2, both
    protocols: the pending read is cancelled, the buffers freed, the socket's readiness
    awaited; glibc keeps freed chunks mapped, so the worker trims the heap once a second
    after sheds and closes; an idle HTTP/1 connection went from 25 to 13 KB, an HTTP/2
    one from 40 to 19 KB).

### 7.3 Memory per connection

| Part | HTTP/1 today | HTTP/2 target |
|---|---|---|
| receive buffer | 16 KB | 16 KB + 9 |
| HPACK dynamic table | none | at most 4 KB (the peer decides how much of it to use) |
| connection object | about 1.5 KB | about 2 KB |
| per active stream | one Stream embedded (about 1.5 KB) | Stream (the two 100-field header arrays, 6.4 KB) + arena at the request's exact size (decoded in the connection's 16 KB scratch first, 2026-09-24) + body buffer up to its grant |
| output in flight | one chunk (64 KB) | at most 8 chunks (512 KB) |
| idle connection | about 18 KB | about 22 KB, target 6 KB with lever 10 |
| worst case at the defaults | 16 KB + 64 KB + body limit | 16 KB + 4 KB + 128 x 18 KB + 1 MB + 512 KB, about 3.8 MB, nothing unbounded |

Measured in G2 (`bench/h2/memory.sh`, `bench/results/h2-memory-20260923-204605.md`, one
worker): with lever 10 built (buffers shed two seconds after the last request, the heap
trimmed once a second after sheds and closes), 10,000 idle HTTP/2 connections cost
agensio 19 KB each, nginx 7.5 KB, Caddy 35 KB; 1,000 busy connections at ten streams
90 MB, nginx 93 MB, Caddy 209 MB; an idle HTTP/1 connection 13 KB. What remains per idle
HTTP/2 connection is the HPACK ring a client fills (8 KB, the protocol's) and the fixed
objects, of which the two 100-field header arrays of the stream (6.4 KB) are the next
lever.

A busy connection keeps as many stream objects as its client had in flight at once
(the pool of 6.6, emptied by the idle shed), so its memory follows the client's
concurrency: on the arena's baseline-h2 (512 connections, a hundred streams each) the
pool first cost 647 MiB resident against h2o's 65, because every stream reserved the
whole header limit for its arena, and the twelve-worker row fell to 0.87 of h2o while
one core did 1.27 of it: a burst walked a hundred cold 24 KB objects per connection.
Decoding into the connection's scratch and keeping the exact bytes per stream is the
fix in place; the header arrays are what remains per pooled stream.

### 7.4 The benchmark

`bench/h2/run.sh` runs `h2load` (Debian's `nghttp2-client`, 1.64 in trixie) against
agensio, nginx (`http2 on` on both listeners) and Caddy (`protocols h1 h2c` on the plain
one), lighttpd optional (1.4.79 in trixie), with the metric of phase 1: server CPU
microseconds per request from `ps` over `h2load`'s request count, plus RSS. Rows:

| row | connections x streams | what it shows |
|---|---|---|
| h2c `/` 1 KB | 64 x 1 | the codec's cost against the HTTP/1 row |
| h2c `/` 1 KB | 64 x 10 | multiplexing: fewer syscalls per request |
| h2 `/` 1 KB (TLS) | 64 x 1 and 64 x 10 | the same over TLS, the browser case |
| h2 `/style.css` 100 KB | 64 x 10 | flow control and record filling |
| h2 `/big.bin` 10 MB | 16 x 1 | streaming, sendfile per frame, windows |
| h2 `/` 1 KB | 256 x 10 | 2,560 concurrent streams, the scheduler |

Single worker first (one core saturated, so us/req is exact), then `-w 4` with the same
count on every server (`SO_REUSEPORT`), as phase 1 did. `bench/ab.sh` gets `-2`, which
adds the h2c and h2 1 KB rows; the gate for every G step is the static HTTP/1 rows
within noise (the "does not affect HTTP/1.1" proof) and the h2 rows recorded.

## 8. Security

### 8.1 Threats and defences

| Attack | Mechanism | Defence | Limit | Test |
|---|---|---|---|---|
| Rapid Reset (CVE-2023-44487) | open streams and reset them at once; the server does the work, the client stays under the concurrency limit | the reset counter (6.9); the upstream exchange is cancelled on the reset so no work is left behind | 128 per second per connection, then close | `h2-attacks.py rapid-reset`: 10,000 streams reset; asserts the close, the CPU and the exchanges cancelled |
| MadeYouReset (CVE-2025-8671) | provoke the server into resetting streams with invalid frames (a `WINDOW_UPDATE` of 0, a bad PRIORITY, DATA on a half-closed stream) so client-side reset counting never triggers | server-sent resets count in the same counter; each provocation is also a glitch | the same | `h2-attacks.py made-you-reset` |
| CONTINUATION flood (CVE-2024-27316 etc.) | HEADERS without END_HEADERS followed by CONTINUATION frames for ever | the header block is bounded by compressed bytes and by frame count; over either is a connection error, and the buffer is the 16 KB receive buffer, not a growing string | 16 KB compressed, 8 CONTINUATION frames per block | `h2-attacks.py continuation-flood`; RSS sampled |
| HPACK bomb (2016) and the HTTP/2 Bomb (CVE-2026-49975) | seed the dynamic table with a large or nearly empty entry and reference it thousands of times, splitting cookies to dodge field counts; hold the result with a zero window and 1-byte updates | decoded size counted per field during decoding, stop at the first byte over 16 KB; cookies joined after the count; a stream held by a zero window with under 1 KB of progress is reset at `idle_timeout`; 1-byte updates are glitches, not progress | 16 KB decoded per request, 100 fields, 4 KB table | `h2-attacks.py hpack-bomb`, `bomb-hold`; asserts memory flat |
| Slow read, zero window (Imperva 2016; CVE-2019-9511 data dribble) | the client stops reading or sets a zero window and never updates it | the write-stall timer; no DATA frame smaller than 1 KB unless it ends the body | `idle_timeout` per stalled stream | `h2-attacks.py slow-read`, `dribble` |
| Internal data buffering (CVE-2019-9517) | huge window advertised, TCP never read; the server buffers whole responses | responses are pulled from cache, file or origin only when a window and a socket accept them; at most 8 chunks in flight per connection | 512 KB per connection | `h2-attacks.py buffering`; origin bytes read counted |
| PING flood, SETTINGS flood (CVE-2019-9512, 9515) | frames that each demand a reply | answered, but each beyond 10 per second is a glitch | 100 glitches | `h2-attacks.py ping-flood`, `settings-flood` |
| Empty frames flood, 0-length headers leak (CVE-2019-9518, 9516) | DATA or HEADERS frames with no payload, no END_STREAM | each is a glitch | 100 | `h2-attacks.py empty-frames` |
| Resource loop, dependency cycle (CVE-2019-9513, Imperva 2016) | PRIORITY frames building a pathological tree | no tree: priorities are not implemented (`NO_RFC7540_PRIORITIES`), PRIORITY frames are glitches | 100 | `h2-attacks.py priority-flood` |
| Stream multiplexing abuse | thousands of streams | `MAX_CONCURRENT_STREAMS` enforced (`REFUSED_STREAM` beyond), ids monotonic, GOAWAY at `max_requests_per_connection` | 128 concurrent, 1,000 per connection | h2spec 5.1.2; `h2-attacks.py stream-flood` |
| Frame size, padding, reserved bits | frames larger than advertised, padding longer than the payload | `FRAME_SIZE_ERROR` / `PROTOCOL_ERROR` before buffering | 16 KB | h2spec 4.2, 6.1; `fuzz_h2_frame` |
| Request smuggling over the HTTP/1.1 downgrade (2021) | CR/LF in values, `transfer-encoding`, a `content-length` that disagrees with DATA, `:authority` against `Host` | the field rules of 6.4 at decode time, before the request exists | none reaches php-fpm or an origin | unit tests of `fields.hpp`; integration through the proxy and FastCGI fixtures |
| Header list size, table size games | `SETTINGS_HEADER_TABLE_SIZE` above ours, a dynamic table update larger than allowed | `COMPRESSION_ERROR`; our table never exceeds 4 KB; we never use the peer's table for encoding | 4 KB | `fuzz_hpack` differential |
| Memory as a whole | anything that grows without bound | every buffer belongs to a stream or the connection and has a cap; the sum of the caps is the connection's worst case (7.3) | about 3.8 MB worst case at the defaults, 22 KB idle | the attack suite samples RSS through every run |

### 8.2 Testing the code, not the list

- **h2spec** (summerwind/h2spec, the conformance suite for RFC 7540 and 7541) in the
  integration run, all sections, against a devbox image that carries its binary; G0
  records which cases wait for request bodies (G1), G1 passes them all.
- **Fuzzers**: `fuzz_h2_frame` drives a connection through a fake socket with arbitrary
  frame sequences (crashes, hangs, unbounded growth); `fuzz_hpack` decodes arbitrary
  blocks and, when `libnghttp2` is present at build time, decodes each with nghttp2's
  inflater too and compares the fields (a differential test against ten years of
  fixes). Both run under ASan and UBSan, minutes per checkpoint, the counts recorded in
  the security page.
- **The attack suite** `tests/h2-attacks.py`: raw sockets, one function per row of the
  table, each asserting the response of the server (the close, the error code, the
  log line) and that RSS did not grow beyond the budget.
- **Sanitizer builds** of the unit, integration and attack suites, as for every phase.
- **`security-review-cpp`** on every file of `src/http2/` before the checkpoint, and the
  threat table above kept in the security page with the rows of the control plane.

## 9. Configuration, reference rows, the agent interface

Two keys, both `[server]`:

| key | default | meaning | applies |
|---|---|---|---|
| `protocols` | `["h2", "h1"]` | what TLS listeners offer through ALPN, in order of preference (Caddy's names, chosen by the owner on 2026-09-23; `"http/1.1"` is accepted for `"h1"`); `"h2c"` in the list also accepts prior-knowledge HTTP/2 on plain listeners (off by default: browsers never use it; benchmarks and backends do) | reload |
| `http2 = { max_concurrent_streams }` | 128 | streams a client may have open at once per connection (nginx's default) | reload |

Everything else derives from keys administrators already know: `max_header_size` is the
header list size and the compressed block cap; `max_requests_per_connection` is the
streams per connection before `GOAWAY`; `idle_timeout` and `body_timeout` keep their
meaning per stream; `max_body_size` (server or site) sizes the windows. The two rows go
into the reference table, `docs/keys.md` is regenerated, `docs/configuration.md` gets a
section 16 "HTTP/2".

Agent interface: the MCP instructions say HTTP/2 is on for TLS sites, that a site's
uploads are not slower over it, how to switch it off during an incident (`protocols =
["h1"]`, `via = file`, a reload), and where the abuse counters are (`server_status`,
`health`). `agensio ctl status` shows the protocols; `site_show` shows them per listener.

## 10. Staged plan

Each step: unit and integration suites green, the A/B with the static rows within noise,
the h2 rows recorded, docs and MCP texts moved in the same change, one commit per step.

- **G0, a GET over HTTP/2** (the owner's "basic part first"): the two keys with their
  rows; ALPN on the contexts and the hand-over; the h2c preface hand-over; framing;
  the full HPACK decoder and the static encoder with prebuilt blocks; streams for every
  request without a body through the existing dispatcher (static files from cache and
  disk, 304, 206, error pages, redirects, 421 authority, and GET through FastCGI, proxy
  and CGI, since their code path is the same as static plus a callback); response flow
  control and the scheduler; SETTINGS, PING, GOAWAY, RST_STREAM; every connection-level
  limit and both budgets of section 8 (cheaper to build in than to add); request bodies
  drained with window accounting but not delivered. Tests: RFC 7541 appendix C vectors
  and the Huffman table, the field rules, both fuzzers, `curl --http2`, `nghttp` and
  h2spec in the integration run (body cases recorded as pending), the H2h coalescing
  check un-skipped, the h2 bench rows and `ab.sh -2`.
- **G1, request bodies**: DATA to `StreamBody`, the adaptive windows, POST through
  FastCGI, proxy and CGI, uploads on the WordPress and Drupal presets in the root suite
  over h2, abort by `RST_STREAM`, trailers, `content-length` rule, h2spec complete.
- **G2, performance**: the levers of 7.2 measured one by one, the multi-worker run
  against nginx and Caddy, memory per connection published, lever 10 decided.
- **G3, hardening**: the attack suite, budgets tuned on it, sanitizer and fuzz records,
  the security page's HTTP/2 section, `server_status` and `health` counters, MCP texts.
- **G4, extras**: RFC 9218 urgency in the scheduler, RFC 8441 CONNECT for WebSockets over
  h2 through the D3 tunnel, per-site protocols through the SNI callback, the
  TLS-ALPN-01 hook for H3, `GOAWAY` on reload reviewed.

## 11. Decisions requested

1. **Own implementation**, nghttp2 in the test bed only (section 4). Reverses the
   roadmap's decision 1. Proposal: yes.
2. **Encoder without a dynamic table**, static indexes and literals, Huffman at build
   time, prebuilt blocks (6.2). The bytes it costs on a response are a few dozen; G2
   measures them. Proposal: yes.
3. **Protocol selection by hand-over** from `Http1Connection` after ALPN or on the
   preface (5.2), no change to the accept path. Proposal: yes.
4. **Two configuration keys** (`protocols`, `http2.max_concurrent_streams`), everything
   else derived (section 9). Proposal: yes.
5. **Defaults**: h2 on for TLS listeners, h2c off, 128 streams, 1 MB windows for
   uploads, 100 glitches, 128 resets per second. Proposal: yes.
6. **No priority tree**; RFC 9218 urgency in G4. Proposal: yes.
7. **The budgets and their visibility** in `server_status` and `health` (6.9).
   Proposal: yes.
8. **The benchmark set** of 7.4 and `ab.sh -2` as the gate. Proposal: yes.
9. **The staging** of section 10, G0 as described. Proposal: yes.

## 12. Sources

- nginx `ngx_http_v2_module` directives and history: https://nginx.org/en/docs/http/ngx_http_v2_module.html
- nginx Rapid Reset mitigation in 1.25.3: https://www.f5.com/company/blog/nginx/http-2-rapid-reset-attack-impacting-f5-nginx-products and https://community.centminmod.com/threads/nginx-1-25-3-release-for-http-2-rapid-reset-ddos-attack-vulnerability-cve-2023-44487.24186/
- nginx HPACK encoding (the Cloudflare "full HPACK encoding" patch): https://github.com/cloudflare/sslconfig/issues/72 and https://blog.cloudflare.com/hpack-the-silent-killer-feature-of-http-2/
- nginx HTTP/2 uploads: https://github.com/nginx/nginx/issues/857, https://bugzilla.mozilla.org/show_bug.cgi?id=1868987, https://github.com/nextcloud/server/issues/30464, https://blog.cloudflare.com/delivering-http-2-upload-speed-improvements/
- nginx HTTP/2 to upstreams: https://github.com/nginx/nginx/issues/1066, https://community.nginx.org/t/http-2-support-for-reverse-proxy/5746
- nginx 2026 advisories: https://nginx.org/en/security_advisories.html, https://hivesecurity.gitlab.io/blog/nginx-configuration-dependent-vulnerabilities-2026/, https://gpt-lab.eu/nginx-vulnerabilities/
- HTTP/2 Bomb (CVE-2026-49975): https://www.haproxy.com/blog/haproxy-cve-2026-49975-http2-bomb, https://dailysecurityreview.com/cyber-security/cve-2026-49975-http-2-bomb-hits-nginx-apache-envoy-and-cloudflare/
- MadeYouReset (CVE-2025-8671): https://kb.cert.org/vuls/id/767506, https://www.wiz.io/vulnerability-database/cve/cve-2025-8671
- CONTINUATION flood: https://www.kb.cert.org/vuls/id/421644, https://access.redhat.com/security/cve/cve-2024-28182
- HAProxy glitches: https://www.haproxy.com/blog/haproxy-is-resilient-to-the-http-2-continuation-flood, https://www.haproxy.com/documentation/haproxy-configuration-manual/new/latest/
- lighttpd 1.4.56 and ls-hpack: https://www.lighttpd.net/2020/11/29/1.4.56/, https://redmine.lighttpd.net/projects/lighttpd/wiki/Release-1_4_56
- Caddy and Go: https://pkg.go.dev/golang.org/x/net/http2, https://caddyserver.com/docs/caddyfile/options, https://github.com/golang/go/issues/63417
- Envoy's codecs: https://apoxy.dev/blog/oghttp2-vs-nghttp2, https://github.com/envoyproxy/envoy/pull/24943, https://www.envoyproxy.io/docs/envoy/v1.31.0/version_history/v1.31/v1.31.0
- nghttp2 HPACK API: https://nghttp2.org/documentation/tutorial-hpack.html
- h2spec: https://github.com/summerwind/h2spec; h2load: https://nghttp2.org/documentation/h2load-howto.html
- Benchmarks: https://www.techplained.com/caddy-vs-nginx, https://h2o.examp1e.net/benchmarks.html, https://http2benchmark.org/ (vendor-published)
- RFCs: 9113 (HTTP/2), 7541 (HPACK), 9218 (extensible priorities), 8441 (CONNECT), 9114 (HTTP/3)
