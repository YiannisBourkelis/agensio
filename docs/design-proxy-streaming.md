# Design: an origin's answer on its way to the client

Status: built 2026-11-14, sections 4.1 to 4.3 and 11; the measurements are in section 10. Proposed and asked for by the owner the same day ("write the design and start
implementing it"). It follows the comparison with Pingora (`bench/pingora/README.md`) and the
measurements of `bench/results/proxy-body-techniques-20261114.md`. Sections 4.1 to 4.3 change no
behaviour and no key; section 8 holds the one decision that would (which mode is the default), and
that stays open.

## 1. Why

agensio takes an origin's answer in one of two ways. With `buffering = true` (the default of
`proxy`, `fastcgi` and `cgi`) it collects the whole answer, up to `buffer_max` in memory and beyond
it in a temporary file, and then sends it. With `buffering = false` it hands the answer on as it
arrives. Buffering frees the origin's connection as soon as the origin is done, whatever the
client's speed, which is what an application server with few workers needs. Streaming gives the
client the first bytes sooner and holds less.

Every comparison so far measured agensio buffering. Pingora, like every CDN proxy, streams. So the
first thing its engineers would ask of our numbers is how agensio does when it streams, and the
answer on 2026-11-14 was: 5 to 62 % worse than when it buffers.

| one worker, 64 connections, CPU per request | buffered | streaming | Pingora |
|---|---|---|---|
| small JSON | 8.0 us | 9.4 us | 14.2 us |
| 100 KB | 31.2 us | 41.8 us | 48.0 us |
| small JSON over HTTPS | 8.2 us | 11.8 us | 15.0 us |
| HTTP/2, small JSON, ten streams | 8.7 us | 14.0 us | 11.0 us |
| HTTP/2, 100 KB, ten streams | 64.2 us | 74.8 us | 77.5 us |

Streaming, agensio's lead over Pingora shrank from 1.2 to 1.8 times to 1.04 to 1.5, and one row
went to Pingora. The cause is not streaming itself; it is how the streaming path was built, as an
addition to the buffered one:

- **A small answer takes two writes.** The head goes to the client as soon as it is parsed, before
  the body bytes of the same read are looked at; the body follows in a write of its own (over TLS a
  record of its own, over HTTP/2 a write cycle of its own), and one more read of the origin is
  tried.
- **A large answer is copied twice and sent in small pieces.** Each read of the origin (16 KB)
  lands in the connection's buffer, is appended to the exchange's pending queue, and is copied from
  there into the buffer the client side writes from: eight sends and nine reads for 100 KB where
  the buffered path makes two sends.

The buffered path has one cost of the same kind: the body is read into the connection's buffer and
appended to a string that grows by doubling, so every byte is copied once more than needed and
some twice.

Where the rest of the time goes was measured too (perf, cycles per request, one worker):

| row | cycles per request | kernel | agensio | libc | OpenSSL |
|---|---|---|---|---|---|
| small JSON | 38,100 | 76 % | 16 % | 5 % | |
| small JSON over HTTPS | 52,900 | 74 % | 13 % | 4 % | 8 % |
| HTTP/2, ten streams | 42,000 | 72 % | 15 % | 4 % | 8 % |
| 100 KB | 163,100 | 84 % | 6 % | 9 % | |
| 100 KB over HTTPS | 252,300 | 70 % | 4 % | 10 % | 15 % |

A small proxied request is four system calls (read the request, send it on, read the answer, send
it) and the loopback's TCP work for each; agensio's own code is a sixth of the cycles. On the
100 KB rows 28 % (plain) and 16 % (TLS) of all cycles are `clear_page_erms`: Debian's kernel zeroes
every page it allocates (`init_on_alloc`), and a send copies the body into freshly allocated socket
pages. The copies agensio makes itself are the 7 % under `memmove`. So what is ours to remove is
system calls and copies; the rest is the kernel's price for a byte sent, the same for every proxy
on this host.

## 2. What the others do

- **nginx** reads an upstream's answer into its `proxy_buffers` and writes from them; with
  `proxy_buffering off` it reads into one buffer and sends from that same buffer. Head and first
  body bytes leave in one write when they arrived in one read.
- **Pingora** streams always. What its code does on this path is in section 9, read from its
  source.

## 3. The path today

`UpstreamRequest` (`src/upstream/client.*`) reads the origin into the connection's buffer
(`UpstreamConnection::in`, 16 KB, lent by the pool for the exchange). The derived class decodes
(`HttpRequest::decode`, `FcgiRequest::decode`): head bytes to `feed_head`, body bytes to
`store_body`.

- Buffered: `store_body` appends to `result_.body` (or the spill file); `finish` delivers the
  result once, and `apply_upstream_result` moves the body into the response as a memory body.
- Streaming: `feed_head` delivers the head the moment it is complete (`deliver_head`), the handler
  answers with a `StreamBody` (`UpstreamRequest::Source`), and the client side's writer pulls:
  `pull` records the writer's buffer and handler (`waiter_`), `store_body` appends to `pending_`
  and `satisfy_waiter` copies from there. Reading stops while 256 KB wait (`kHighWater`).

The pullers are the HTTP/1 writer (its 64 KB piece), the HTTP/2 writer (the stream's piece), HTTP/3
(the send block being filled) and a compressed answer (the encoder's input).

## 4. The design

### 4.1 A streamed answer that arrived whole goes out whole

In streaming mode the head is no longer delivered inside `feed_head`. The read that brought the
head is decoded to its end first, its body bytes collected in `result_.body`. Then:

- the exchange finished within that read: the answer is delivered as a buffered result is, once,
  with its body, and the client side sends head and body in one write, the buffered path's;
- otherwise the head is delivered as before, as a streamed answer, and the body bytes of that read
  become the first of `pending_`.

At most one read's bytes (16 KB) are held, which the streaming path holds today as well.

What the client sees:

- **An answer with a `Content-Length`**: the same bytes and the same framing, in one write.
- **An answer without one** (a chunked answer, a script's output) that arrived whole: its length
  is counted and sent, where it went out chunked. This is what a buffering location has always
  done with the same answer, so the two modes now agree; the payload is the same, and an HTTP/1.0
  client, which got such a body delimited by the connection's close, gets a length and keeps its
  connection. Decided by the owner 2026-11-14 (8.2), after a first, stricter step that left such
  answers chunked.
- **A script's answer whose `Content-Length` is not its body's**, and a HEAD's: these stay
  streamed answers, so the client side holds them to the declared length as before (surplus cut,
  a short body ending the connection).
- **An answer that breaks within the read that brought its head**: the head goes on first and the
  body is cut, as before.
- **A head whose framing cannot be trusted** (an origin's `Content-Length` that is no number
  agensio can hold, two that disagree, a `101` nobody asked for): it never goes on, the answer is a
  502 whatever the buffering (RFC 9112 6.3: a proxy discards such a response; `refuse_head`). Until
  0.1.0-alpha.149 a streaming location sent it on as a `200` (the alpha.148 report's F2).
- On a site that compresses, a small answer delivered whole is compressed whole, with its length,
  where it was compressed as a stream.

The integration suite pins the wrong-length and the chunked cases; a first version that took
every whole answer the buffered way failed the first.

### 4.2 A larger body is read into the buffer it is sent from

When the writer asks for bytes (`pull`) and none are pending, the exchange reads the origin
straight into the writer's buffer, for as many bytes as the writer asked for (64 KB from the
HTTP/1 writer), when the body is one whose bytes need no decoding: a body with `Content-Length`,
and a body that ends with the connection. No pass through the connection's buffer, no pending
queue, and a read as large as the writer's piece: 100 KB is two or three reads and writes.

Chunked bodies and FastCGI records need decoding and keep today's path.

Reading ahead stays as it is. When the exchange is asked to read and no writer waits (the client
is slower than the origin), it reads into the connection's buffer and queues, up to the high-water
mark, as today. So a slow client holds an origin no longer than it does now.

**The buffer's lifetime.** The writer's buffer is valid while its handler is held (`waiter_`). A
reader that goes away with a read in flight (`abandon_waiter`, the source's destructor) cancels
the socket's operation before the handler is let go; the exchange is then over (the bytes of that
read have nowhere to go), which is what `reader_gone` decides for an answer short of its end
anyway. A cancelled read performs no receive, on a plain socket and under the TLS stream alike, so
nothing is written to the buffer after its owner has gone.

### 4.3 A buffered body of known length is read into its place

With `buffering = true` and a `Content-Length` no larger than `buffer_max`, `result_.body` is
sized once from the header and the origin is read straight into it, after the bytes that came with
the head. No doubling, no second copy. Bounded as today: `buffer_max` per exchange, and memory an
origin declares but never sends is not touched.

### 4.4 Not in this step

- A chunked body decoded straight into the writer's buffer (one copy fewer). Later, if a row asks.
- `splice(2)` from the origin's socket to the client's, plain on both sides: it would take the
  kernel's page zeroing and both copies off the 100 KB row (about 40 % of it), but only where
  neither side is TLS. With kTLS it would reach HTTPS clients; that is the kTLS work, not this.
- The default. See section 8.

## 5. What does not change

Keys, defaults, limits, timeouts, the retry rule (none once a head byte arrived), the read-ahead
bound, what is logged, what `reader_gone` ends, the HTTP/3 send blocks. An answer's bytes are the
same in every mode; the tests of section 7 hold them equal.

## 6. Risks, and what answers each

| risk | answer |
|---|---|
| a read completes into a buffer whose owner has gone | 4.2: the operation is cancelled in `abandon_waiter`; a sanitizer run of `tests/proxy-streaming.sh` and `fuzz_h2_bodies` with a reader that leaves mid-body |
| an answer delivered twice or never (head deferred) | the deferral is one flag cleared at the end of the read's decoding; unit rows for: whole answer, head alone, head and part, 1xx then the head, 101, a failure in the same read |
| a body misframed (direct reads counted wrongly) | the derived class counts the bytes of a direct read as it counts decoded ones; rows comparing every size around the buffer sizes (0, 1, 16 KB +- 1, 64 KB +- 1, 1 MB) byte for byte, each protocol |
| the buffered path's allocation from the origin's word | bounded by `buffer_max`, as the body an origin really sends is |
| a slow client holding the origin | read-ahead kept (4.2); row: a client reading at 50 KB/s, the origin's connection back in the pool while the client still reads |

## 7. Staged plan

Each step: a failing test first, the change, the suites, `bench/ab.sh <ref> -P` (the default rows
flat), the streaming rows of `bench/pingora/run.sh -X 'buffering = false'`, one commit.

1. 4.1, the whole answer.
2. 4.2, the direct read, with the cancellation.
3. 4.3, the buffered body.
4. The Pingora suite once more, both modes.

## 8. Decisions for the owner

1. **Whether a proxied answer streams by default.** Not proposed now: buffering protects an
   application server with few workers from slow clients. With 4.2 a streamed answer up to the
   read-ahead (256 KB) frees its origin as early as a buffered one, so the difference left is an
   answer above that to a slow client. Until decided, `buffering = true` stays the default.
2. **Whether a whole answer without a length goes out with one.** Decided 2026-11-14: yes (4.1).
   A chunked answer, or a PHP script's output on a streaming location, that arrived whole with its
   head takes the one-write path and reaches the client with a `Content-Length`, as from a
   buffering location.
3. **How far a streamed answer is read ahead.** Decided 2026-11-14: 256 KB stays, no key. Over
   HTTP/2 with many streams at once this is what agensio holds and Pingora does not (section 10);
   a smaller bound would tie the origin to a slow client sooner.
4. **`SSL_MODE_RELEASE_BUFFERS` as a key.** Decided 2026-11-14: off, no key. 30 KB less per busy
   TLS connection for 2.3 % more CPU on small HTTPS answers (section 11); for a host with very
   many continuously busy TLS connections, if one appears.
5. **The boot copy of the configuration** (section 10's finding: 9 KB a site held twice). Not
   changed; see the answer given to the owner the same day: worth doing only for hosts with
   thousands of sites, and then as a type without sites, so the compiler lists every reader.

**Through the control plane** (0.1.0-alpha.147, agreed the same day): a managed site that proxies
sets how it talks to its application without the root additions file: the settings
`proxy_buffering`, `proxy_read_timeout`, `proxy_tunnel_timeout` and `proxy_max_connections` beside
`proxy_pool`, and the site field `stream_paths`, the paths answered as they arrive
(`docs/configuration.md` 12, `docs/examples/proxy.md`).

## 9. Pingora's path, from its source

Read from the crates of Pingora 0.9.1 as the comparison builds them (`bench/tmp/pingora/cargo`),
2026-11-14; counts are from reading, not from a profiler. File references are below the crate
named.

- **It never holds a whole answer.** The two halves of a request (read the origin, write the
  client) are two futures joined in the request's task, linked by channels of four pieces
  (`pingora-proxy/src/lib.rs:81`, `proxy_h1.rs:142`). A piece is at most 64 KB, so what is in flight
  per request is bounded by pieces, about 700 KB at worst, and by the client's pace. That is the
  design of section 4.2 with a fixed, small read-ahead.
- **A body piece is copied once or twice.** Read into a 64 KB buffer of the response, copied into a
  `Bytes` (`pingora-core/src/protocols/http/v1/client.rs:498`, `body.rs:31`), and copied again into
  the write buffer when pieces are batched (`v1/server.rs:1535`). 4.2 copies none.
- **Head and body are two writes** unless together they fit 1,460 bytes: the only coalescing is a
  `BufWriter` of that size (`pingora-core/src/protocols/l4/stream.rs:370`), no vectored write. 4.1
  sends a small answer in one.
- **Per request it allocates about 65 times**: a session object each side, two header maps per
  parsed head (values and a case-preserving copy), clones of them for the origin's request and the
  response task, a boxed future per filter call (`pingora-core/src/apps/mod.rs:360`,
  `pingora-http/src/lib.rs:85`, `pingora-proxy/src/proxy_trait.rs:47`). agensio's request path keeps
  its request and response objects with the connection and parses into views.
- **A client connection keeps a 64 KB read buffer for its life**, and a 4 KB head buffer
  (`l4/stream.rs:363`, `v1/server.rs:303`); nothing is given back while idle. A pooled origin
  connection keeps almost nothing (no stream buffers, no session), which is why its many-origins
  row was good before agensio lent its read buffers.
- **Its timers** are armed only when an operation does not finish at once, rounded to 10 ms and
  shared per tick (`pingora-timeout/src/timer.rs`). agensio's recorded deadline with one tick per
  pool is the same idea with less machinery.
- **tokio marks a socket drained after a short read**, so it does not try a read that would return
  EAGAIN (`tokio/src/io/poll_evented.rs:180`). Asio has the same rule for stream sockets
  (`try_speculative_`), and the system-call counts of section 10 show agensio at the four calls of
  a proxied request.

Nothing there is a technique agensio lacks after this step. What Pingora has and agensio does not
is by design: it never buffers, so its memory under many large answers at once follows the
clients' pace, where agensio's default holds each answer whole to free the origin (section 8).

## 10. Measured (2026-11-14)

Built the same day: 4.1 to 4.3 and section 11. Everything in
`bench/results/proxy-body-techniques-20261114.md` (the techniques one by one, a prototype on one
binary) and the files named below.

**The gate** (`bench/ab.sh HEAD -P -2`, three rounds, `ab-20261114-133451.md`, default
configuration): static rows 0.991 to 1.018, HTTP/2 rows 0.989 to 1.019, proxied small JSON 1.016,
the proxied 100 KB answer 0.780 (18.6 to 14.5 us), the slow row 1.029.

**Streaming, before and after** (one worker pinned, `bench/pingora/run.sh -X 'buffering = false'`,
`pingora-20261114-103905.md` and `pingora-20261114-135729.md`), with Pingora beside it:

| CPU per request | before | after | Pingora |
|---|---|---|---|
| small JSON | 9.40 us | 7.27 us | 12.79 us |
| 100 KB | 41.83 us | 29.89 us | 45.56 us |
| small JSON over HTTPS | 11.80 us | 8.52 us | 15.68 us |
| 100 KB over HTTPS | 50.96 us | 46.99 us | 54.91 us |
| HTTP/2, small JSON, one stream | 13.91 us | 10.02 us | 15.61 us |
| HTTP/2, small JSON, ten streams | 14.04 us | 8.91 us | 11.90 us |
| HTTP/2, 100 KB, ten streams | 74.85 us | 60.73 us | 80.91 us |
| request mix, one worker | 19.32 us | 16.64 us | 25.51 us |

**The default mode** (`pingora-20261114-134129.md` against `pingora-20261114-043030.md`): 100 KB
31.3 to 25.7 us, over HTTPS 49.9 to 41.3, HTTP/2 at ten streams 61.8 to 51.3, the request mix 16.6
to 14.2.

**Memory** (resident, after the row): HTTP/2 100 KB at ten streams about 100 MB to 38 (Pingora 48);
the request mix 60 to 46.5 MB (Pingora 37); streaming, the HTTP/2 100 KB row 58.8 MB (Pingora 51):
640 answers at once, each read ahead (decision 8.3).

**Checks**: unit tests (also under the address and thread sanitizers, and without OpenSSL),
`tests/proxy-streaming.sh` (16 rows, both sanitizers), the integration suite (869 rows).

**System calls per proxied request** (strace, before): four for a small buffered answer; a small
streamed one took two sends to the client and one more read; a streamed 100 KB body eight sends and
nine reads.

## 11. What a busy connection holds

Measured with the request mix over TLS, 256 connections (massif, the heap at its peak, 42 MB):
165 KB per connection.

| per busy TLS connection | bytes | whose |
|---|---|---|
| OpenSSL: its two record buffers | 33 KB | OpenSSL, kept between records |
| OpenSSL: the connection's state, keys | 30 KB | OpenSSL |
| the last buffered answer's body | 23 KB on average | `Response::buffer`, kept until the next answer replaced it |
| the TLS staging buffer | 17 KB | `BasicTlsStream`, held by the read that waits for the next request |
| the receive buffer | 16 KB | `Http1Connection`, held by the same read |
| the write-coalescing buffer | 16 KB | `Http1Writer::out_`, from the first answer above a record |
| the origin connection's read buffer | 11 KB | the pool's, lent for the exchange |
| the connection object | 8 KB | |

Pingora holds about 100 KB per busy TLS connection on the same mix. The idle shed gives agensio's
back after two seconds without a request (45 KB then); between the requests of a busy connection
nothing did.

What changes (0.1.0-alpha.147), none of it on the request's fast path:

- **The answer's body goes with the answer** (`Response::reset`): a buffer above 4 KB is freed when
  the response is done, where it was kept until the next buffered answer replaced it. The same
  number of frees, earlier.
- **The writer's buffers are the worker's** (`core/spare_buffers.hpp`): the coalescing buffer is
  taken for the first write and given back when that write is with the kernel; the 64 KB piece for
  files and streamed bodies is taken at its first use in an answer and given back when the answer
  is whole. A worker keeps sixteen and eight of them; what a connection held for its life is now
  held per answer in flight.

Not taken:

- **The two buffers a waiting read holds** (33 KB). Giving them up means waiting for readiness
  instead of reading, which is what the idle shed does, at the price of a system call per request
  (Asio re-arms the descriptor); under load that is CPU for memory at a bad rate.
- **OpenSSL's own record buffers** (33 KB). `SSL_MODE_RELEASE_BUFFERS` gives 30 KB back per busy
  connection (measured: 128 to 97 KB at 256 connections), and it was built and taken out again the
  same day: it costs an allocation per record, 4.86 against 4.75 us on the static HTTPS 1 KB row
  (four alternated rounds, pinned; nothing on 100 KB). 2.3 % of the static path for memory a
  connection gives back anyway once it is idle is not this project's trade. A key could offer it to
  a host with very many busy TLS connections; decision 8.4.

So a busy TLS connection holds 128 KB where it held 173 (111 against 158 at 1,024 connections), a
busy plain one 50 KB where it held 84, and Pingora about 100 KB over TLS.
