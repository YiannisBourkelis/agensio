# Security audit against the nginx comparison (2026-10-07)

The owner asked an outside model how agensio could be faster than nginx and received a
list of claims about what a "benchmark server" must have left out: Slowloris protection,
rate limiting, memory safety and fuzzing, request bounds, access control, TLS hardening,
and the operational layer (health checks, load balancing, reload without dropping
connections, misbehaving back ends). This document checks each claim against the code at
commit `0e0a9e5` (alpha.50 plus the MariaDB guide), lists what the check turned up, and
names what still has to be verified live. Everything here comes from reading the code;
nothing was run. Line numbers are at that commit.

Three readers went through the tree, one per question: the timeouts under slow and
stalled clients across HTTP/1, HTTP/2 and HTTP/3; the feature inventory (access control,
TLS options, proxy, bounds, logging); the fuzzing, sanitizer and parser-bound evidence.
Their findings were then checked by hand where they mattered (sections 2.1, 2.2, 2.4).

## 0. Status after the first fixes (2026-10-07)

Each item below was first reproduced by a test that failed on the unfixed code (or showed
the item was not a problem), then fixed, then the same test passed. Baseline A/B before
any change: `bench/results/ab-20261007-130450.md` (HEAD against itself, three rounds).
After all of them: `ab-20261007-142247.md` (the working tree against `0e0a9e5`, h1, h2 and h3
rows, three rounds) is flat within noise; its one row above 3 %, plain 100 KB at 1.058, was
0.996 over five rounds in `ab-20261007-143031.md`.

| Item | State | Test |
|---|---|---|
| 2.6 TLS 1.2 renegotiation | **not a problem**: OpenSSL 3 refuses client-initiated renegotiation by default (`no renegotiation` alert); nothing changed in the server | `tests/integration.sh` keeps the check, validated against an `s_server` that allows it |
| 2.7 reload and the connection limits | **fixed**: HTTP/1 and HTTP/2 take `idle_timeout`, `body_timeout` and `max_header_size` from the connection's generation | `tests/reload.sh`: a new connection after a reload to 2 s was open after 9 s before, closed within 4 s after, both protocols |
| 2.8 key reference defaults | **fixed**: 15 rows corrected, `docs/keys.md` regenerated | unit `test_config_reference_defaults`: 15 failures before, none after |
| 2.9 fuzzing behind the code | **done**: `scripts/fuzz-all.sh`, the weekly `fuzz.yml` job, every target on the before-tag list; the fuzz targets' `assert()` invariants were compiled out in every fuzz build until now (`NDEBUG`), fixed with `-UNDEBUG`; the campaign ran all thirteen targets five minutes each, clean but for one finding (next row) | the record in `docs/security-control-plane.md` |
| JSON numbers out of range (found by the campaign) | **fixed**: an overflowing literal parsed to infinity and was written back as `inf`; a whole number above 2^63 was converted to `long long` out of range (UBSan). The parser refuses such a literal, the writer checks the range and writes `null` for infinity and NaN | five unit checks and a replayed regression input failed before, pass after; the fuzzer replays the input clean under UBSan |
| integration suite on default builds | **fixed** (suite only): seven checks needed sites defined only with the HttpArena handler, two checks lost to `grep -q` under pipefail on the slower sanitizer binary | sanitizer build 588 checks, Release 596, no failure; server stderr clean |
| 2.10 design notes | **fixed**: both design notes say what the code does | documentation |
| 2.1 HTTP/2 timeout loop | **fixed in alpha.56, regression-proven 2026-10-25**: `check_timeouts` skips a stream already closed whose release is deferred, so the loop always ends; a stream waiting for its application's next bytes is bounded by the upstream's `read_timeout`, not cut by the client's idle clock (HTTP/1's rule) | `tests/timeout-regressions.py`, called by `tests/integration.sh`: alpha.55 spins at one CPU core and fails the plain probe with a stalled TLS writer, and cuts the paused FastCGI response; alpha.56 passes both, with the HTTP/1 sendfile control passing on both tags. Section 5.1 records the setup and results. Earlier non-regression coverage: unit, integration with h2spec, sanitizer and `-2` A/B (`ab-20261008-020159.md`) |
| 2.2 cached body in one write | **fixed in alpha.57, regression-proven 2026-10-25**: a memory body beyond the first write and one piece goes out in `stream_chunk_size` (64 KB) pieces, each refreshing the idle clock in `on_write`, over TLS and on plain sockets without sendfile; the first write is unchanged. Previously verified on the test VPS (alpha.57 report, finding 1): with idle_timeout 2 and 3,000,000 bytes at 300 KB/s, alpha.56 cut at 769,798 bytes over TLS and 740,942 on plain HTTP without sendfile; alpha.57 delivered it whole in 10.0 s | `tests/timeout-regressions.py` row `cached-tls`, called by `tests/integration.sh`: with idle_timeout 15, a 4 KB receive buffer and a 2 MiB cached file at 100 KiB/s, alpha.56 cuts at 1,572,614 bytes; alpha.57 receives all 2,097,152 bytes in 20.518 s. Section 5.1 records the loopback MSS setting needed to make this a regression test, not a pass on both tags |
| 2.5 tunnels | **fixed in alpha.114**: a tunnel write to either side not finished within `proxy.send_timeout` (30 s) ends the tunnel, said at info in the error log; a quiet tunnel, nothing waiting, is not affected, and `tunnel_timeout` keeps its meaning | `tests/integration.sh`, a private instance with `send_timeout = 2`: on `v0.1.0-alpha.113` the stalled tunnels stayed (the flood's origin held until its client let go, the sink's open), on alpha.114 both are cut within the limit; a quiet tunnel and `tunnel_timeout` are checked on both |
| 2.5 watchdog | **decided against** (2026-10-24, the owner): no path on the current code was found that keeps a worker from turning (the 2026-10-04 cause and 2.1 are fixed, tunnels bounded); what is left is storage that stops answering, a hung network filesystem under a docroot or the log directory, whose file and log calls run on the worker as nginx's do, and future bugs. External checks (a monitor or load balancer probing the sites) detect a hung server whatever the cause; revisit if a stall is seen or docroots move to network storage | none: nothing built |
| 2.3 HTTP/2 idle clock | **fixed in alpha.116, regression-proven 2026-10-25**: the idle close reads `last_progress_` (a completed frame, the preface, a write, the start), not every read; the header-block deadline is checked whether or not a stream is open (a request's stream opens only when its block completes). The connection-level WINDOW_UPDATE outside the glitch budget (section 5, item 8, measured in section 5.3) is **decided against** (2026-10-25, the owner): 52.7 ns per 13-byte update with 128 streams open is about 4 ns of server CPU per byte the client sends, below what ordinary requests cost per byte, so it amplifies nothing; volume from one address is the firewall's | `tests/timeout-regressions.py` rows `h2-idle` and `h2-header-block`, default rows: alpha.115 kept both dribblers open at 17 s and the unfinished header block past 18 s, alpha.116 closes the dribblers at 15.000 s and the block at 15.043 s. Sections 5.2 and 5.3 |
| 2.4 QUIC handshake deadline | **fixed in alpha.116, regression-proven 2026-10-25**: a handshake must finish within `idle_timeout` of `created_` whatever arrives, else the connection is dropped silently; only a packet that opens restarts the idle timer (RFC 9000 10.1), every datagram still counts for the amplification limit (8.1). The QUIC accept path asks the worker's connection ceiling before Retry: over it a new Initial gets CONNECTION_REFUSED (RFC 9000 20.1), stateless, counted with the TCP refusals | `tests/h3-attacks.py` rows `handshake-deadline`, `handshake-authenticated` and `connection-ceiling`, default rows, and `handshake-budget`, opt-in: alpha.115 kept the dribbled connection past 16 s and completed both QUIC handshakes over the ceiling; alpha.116 retires it at 15.0 s with Retry auto and always, a new handshake accepted beside it, and refuses both over-limit clients with CONNECTION_REFUSED. Sections 5.2 to 5.4 |

## 1. The claims, one by one

| Claim | What the code does | Verdict |
|---|---|---|
| Slowloris: nginx has `client_header_timeout`; a benchmark server waits indefinitely | HTTP/1: bytes of a request head never refresh the idle clock (`http1/connection.hpp:454-484`, `511-519`), so `idle_timeout` (15 s, `config.hpp:247`) is a deadline for the whole head, counted from the connection's start, the TLS handshake's end, or the first byte after a 2 s silence. nginx's default is 60 s. A head over 16 KB is 431 (`:420-422`); more than 100 fields is 431. The TLS handshake has the same 15 s (`:93-97`). | **Wrong for HTTP/1**: stricter than nginx. HTTP/2 and QUIC differ, see 2.3 and 2.4. |
| Slow body | `body_timeout` (60 s) bounds each read of a request body (`:255-262`), nginx's `client_body_timeout` semantics exactly; the body is capped at `max_body_size` (1 MB, 413 up front for a declared length, mid-stream for chunked). | Parity with nginx. A whole-body deadline would be stricter than either; see 4. |
| Slow reader (the client does not take the response) | No `send_timeout` key. The idle clock stands in: refreshed per progress on sendfile (`writer.hpp:436-446`), per 64 KB piece on TLS file streams, per chunk on streamed bodies, and only at completion for a memory body (`writer.hpp:186-212`, `255`). nginx's `send_timeout` (60 s) is also per write operation. | Parity, with one availability bug of our own: 2.2. |
| Burst rate limiting (`limit_req_zone`) | None in the server, by decision (`docs/configuration.md` 18, 2026-10-02): per-address accounting stays out of the accept path; `protection_show` renders an nftables table (30 new connections/s per address, 200 held, 50 QUIC handshakes/s, `control/protection.cpp:633-643`) and four fail2ban jails over the access logs. | **True as stated, decided.** What the decision does not cover: a per-URI request rate (a login path, an API) at the server, which nginx keys on anything. See 3. |
| Memory safety and fuzzing: nginx is audited, a C++ server is "more prone to out-of-bounds reads or segfaults on a crafted malformed packet" | 13 libFuzzer targets under `tests/fuzz/` (request parser, path normaliser, chunked decoder, FastCGI records and CGI head, upstream HTTP head, JSON, archive extractor, HPACK decoder and round trip, QPACK, QUIC packet header and frames, transport parameters, a whole established QUIC connection), each built with ASan+UBSan (`CMakeLists.txt:210-232`); 4,293 regression inputs, four corpora replayed by the unit tests. Every parser checks length before it reads and is `noexcept`; no `throw` or `try` on the request path. Hardening on in every release and package build: stack protector, zero auto-init, `_FORTIFY_SOURCE=2`, bounds-checked standard library, RELRO+PIE (`CMakeLists.txt:166-177`). The chunked decoder: 16 hex digits at most (no wrap), 4 KB per extension, 8 KB of trailers, an invalid chunk closes the connection (`http1/chunked.hpp:43-44,61`). | **Wrong on the evidence.** What is true: the fuzzers and the sanitizer build run by hand, not in CI, and the last recorded campaign is 2026-09-25 (2.9). |
| `client_max_body_size`, `large_client_header_buffers`: "benchmark engines skip these bounds" | `max_body_size` (1 MB, per site), `max_header_size` (16 KB, min 1 KB), 100 fields, Content-Length at most 19 digits, 431/413/400/501/417 as listed in `http1/connection.hpp:514-551`; HTTP/2 advertises `max_header_size` as `SETTINGS_MAX_HEADER_LIST_SIZE` and enforces it on the compressed and the decoded block, 8 CONTINUATION frames at most (`http2/connection.hpp:51,556-566,713`). | Wrong. nginx's defaults are 1 MB and 8 KB x 4; ours are the same or tighter. |
| Access control: `allow`/`deny`, WAF (ModSecurity, Coraza), `auth_basic`, JWT | None of the four. `Cidr` exists (`net/cidr.hpp`) and is used only for `trusted_proxies`. JWT is NGINX Plus only; the WAFs are third-party modules compiled into nginx. | **True.** Gaps ranked in 3. |
| TLS: OCSP stapling, cipher suite control, HSTS | Context built in `server.cpp:393-406`: TLS 1.2 minimum hard-coded, `SSL_OP_NO_COMPRESSION`, OpenSSL's default cipher list and groups, no key for any of them; sessions and tickets at OpenSSL's defaults, contexts rebuilt on reload (`:1445-1449`) so ticket keys change then; `SSL_OP_NO_RENEGOTIATION` not set. No OCSP stapling (roadmap H3a). HSTS through `add_headers` on a location; the managed site writes `max-age=31536000` on `/` when asked (`control/sites.cpp:673-674`), never by itself (`configuration.md:1436-1439`). | Partly true: no stapling, no cipher keys. Renegotiation is the one item with a security edge: 2.6. OCSP stapling matters less than it did: Let's Encrypt stopped putting OCSP URLs in certificates in May 2025 and switched its responders off in August 2025, so a `tls = "auto"` site has nothing to staple. |
| Operations: health checks, load-balancing algorithms, proxy buffers, reload without dropping connections, memory-leaking back ends | Passive health per worker (`max_fails` 3, `fail_timeout` 10 s, `upstream/options.hpp:65-69`), round-robin only, no active probe (open source nginx has no active probe either; `least_conn`, `ip_hash`, weights and `backup` it has). Buffers: `buffering`, `buffer_max`, `buffer_file_max`, `request_buffering`, `request_buffer_max`, `head_max` 64 KB. Reload: generations, `tests/reload.sh` (wrk at 750k req/s across six reloads, no error). A back end that hangs or leaks: `connect_timeout` 5 s, `send_timeout` 30 s, `read_timeout` 60 s between reads, pools bounded (`max_connections`, `queue_depth`, `queue_wait` then 503 with Retry-After), a response spilled to a temp file above `buffer_max` and refused above `buffer_file_max`. | Mostly wrong; the real gap is load-balancing choice and an active prober (roadmap, design section 6). |
| "nginx evaluates its configuration tree for every connection" | nginx compiles its configuration at start; location lookup is a tree walk, as ours is (`core/router.cpp`). | Not a difference. |

## 2. Findings

Ranked by what they would cost on a live host. None is confirmed by a run; 5 says what
each needs.

### 2.1 HTTP/2: the per-stream timeout loop may not terminate (high if confirmed)

`check_timeouts` (`http2/connection.hpp:1191-1240`) walks the open streams and, for one
that has a response the client does not take for `idle_timeout`, sends RST_STREAM,
counts a reset, calls `close_stream` and does `continue` without advancing the index,
on the assumption that `close_stream` swapped the slot out (`:1226-1230`). `close_stream`
(`:667-687`) does swap it out, except when the writer still has the stream's bytes in a
cycle or a pull from the body source is in flight: then it only marks `defer_release`
and returns, and on every later call returns at once because the state is already
`closed` (`:668`). The stream stays at the same index, the cut condition
(`responded && !finished && age >= idle_timeout`) is still true, and the loop runs again
on the same stream: another RST_STREAM appended to the control buffer, another reset
counted, forever. Nothing in the loop sets `closed_`: `count_reset` beyond the budget and
`connection_error` set `closing_after_write_` and return early afterwards (`:1145-1166`),
and the writer cannot finish because the loop never returns to the event loop.

Reachable shape, on paper: an HTTP/2 client that opens a large window, asks for a
response bigger than the socket buffers and stops reading; after `idle_timeout` the
write cycle is still in flight and the stream is cut. The second shape needs no
attacker: a `buffering = false` upstream (FastCGI, proxy or CGI) that pauses longer than
`idle_timeout` between two chunks of a response, within its own `read_timeout`, leaves
`pulling` set when the timer fires. With one worker, a spinning loop stops every site,
as the 2026-10-04 freeze did. The HTTP/1 connection has no such loop (one stream, the
timer closes the socket).

Proposed fix (one condition): a stream whose state is already `closed` is skipped
(`++i; continue;`) before any check; its release comes from the writer or the pull
completion as designed. With it, the "response the client does not take" case ends in
`close()` through the connection-level check at `:1234-1237` (four idle timeouts with
the writer busy), which should become one idle timeout once a cut stream is in flight.
Test: the two shapes above in `tests/integration.sh`, each followed by a plain request
on a second connection answered within a second.

### 2.2 HTTP/1: a cached body over TLS must reach the client within one idle timeout

A memory body goes out as one `async_write` (`http1/writer.hpp:186-212` TLS, `:224-246`
plain) and the idle clock is refreshed only when it completes (`on_write`, `:255`);
`respond()` has already cleared `handler_busy_` (`http1/connection.hpp:717`), so the
timer closes the connection at `idle_timeout` from its last refresh (`:352-365`). The
memory cache holds files up to `cache.max_file_size`, 4 MB (`config.hpp:301`). On a
plain socket entries from 48 KB go through sendfile, whose clock is refreshed per
progress (`writer.hpp:436-446`), so the one-write path carries at most 48 KB there. Over
TLS every cached entry takes it: a 4 MB image to a client slower than about 2.2 Mbit/s
(4 MB in 15 s) is cut mid-transfer, with the default settings, on every HTTPS site.
HTTP/2 is not affected (cycles of at most 64 KB on TLS, the clock per cycle).

This is availability, not security, and it will show up on real sites (a slow mobile
link, a large photo). Fix: write memory bodies above one record in pieces, as the file
path does (`:282-294`), refreshing the clock per piece; or refresh it from the TLS
stream's own progress. Measure on the 100 KB TLS row of the A/B.

### 2.3 HTTP/2: the idle clock is refreshed by every read, not by every frame

`on_read` refreshes `last_activity_` on each read, including one that completes no frame
(`http2/connection.hpp:249-250`); with no stream open only the idle check applies
(`:1193-1203`). A client can therefore hold a connection with one byte of a frame every
14 s, or a preface followed by nothing then a byte every 14 s, costing the server a
connection slot and about 19 KB. The header-block deadline (`block_since_`) and the
four-idle-timeouts check are inside the branch that runs only while a stream is open
(`:1204-1238`). There is no preface or SETTINGS timer. Bounded by `max_connections` per
worker and the firewall's 200 connections per address once that table is applied. Fix:
refresh the clock when a frame completes (and at the handshake), keep the per-read
refresh only for the shed; apply the header-block deadline whether or not a stream is
open. The glitch budget already covers the frame-level floods (PING, SETTINGS, PRIORITY,
small WINDOW_UPDATE, empty DATA and CONTINUATION, `:1148-1177`), with one hole: a
WINDOW_UPDATE of 1 KB or more is never a glitch and each connection-level one walks every
open stream (`:445-449`); cheap to count under the same rate.

### 2.4 QUIC: no handshake deadline, and half-open connections are pinnable

`created_` is set and never read (`quic/connection.hpp:73,1675`); `design-http3.md:354`
says a handshake "must finish within idle_timeout", but the only clock is
`last_receive_`, refreshed for every datagram that reaches the connection before
decryption (`:243-250`). A client that sends any datagram to its connection id every
14 s keeps a half-open handshake open indefinitely. Half-open handshakes are budgeted at
1,024 per endpoint (`quic/udp.hpp:233`): Retry from 512, new Initials dropped at 1,024
(`:525-532`). Retry binds a token to the address, so a client with real addresses can
pass it; 1,024 such connections kept alive by one small datagram each per 14 s is 73
packets a second, under the firewall's 50 handshakes a second, and no new HTTP/3
connection on that worker (browsers fall back to TCP through the Alt-Svc failure, so the
damage is HTTP/3 only). QUIC connections also count toward the worker's ceiling
(`http3/connection.hpp:65`) without the accept path ever checking it: only the TCP accept
handler does (`server.cpp:1040`), the reference row says "TCP and QUIC together".

Fix: the handshake completes within `idle_timeout` of `created_` or the connection is
dropped silently (the design's rule); only a packet that decrypted refreshes
`last_receive_`; the QUIC accept path refuses at the ceiling like TCP. Row for the
design's threat table and `tests/h3-attacks.py`.

### 2.5 Tunnels and the loop watchdog: the two follow-ups of hardening item 7 are open

`tunnel_timeout` is 0 by default, which cancels the timer altogether
(`http1/connection.hpp:588-592`); when set, only reads refresh it (`:470,625`) and a
write to the client that never completes is not timed out while the origin keeps
sending. No watchdog logs a worker that has not turned. Both were listed open on
2026-10-04 and nothing has been built since.

### 2.6 TLS: client-initiated renegotiation is allowed on TLS 1.2 (not confirmed: OpenSSL 3 refuses it, see section 0)

`SSL_OP_NO_RENEGOTIATION` is not set (`server.cpp:393-406`); OpenSSL 3 allows
client-initiated secure renegotiation on TLS 1.2 by default, and each one costs a
handshake's worth of CPU on the worker. nginx refuses it. One line, and the A/B should
not move. TLS 1.3 has no renegotiation, so this is the TLS 1.2 clients only.

### 2.7 Reload does not apply the timeouts to TCP connections

HTTP/1 and HTTP/2 connections take `idle_timeout`, `body_timeout` and
`max_header_size` from the boot configuration `cfg_` (`server.cpp:1044-1050`,
`server.hpp:221`), which `reload()` never replaces; the reference rows say "reload"
(`control/reference.cpp:10,13,15`). HTTP/3 reads the live generation
(`server.cpp:539`). Either read them from the generation at the request boundary or mark
the rows restart-only and warn at reload as the restart-only keys do (`:1441-1444`).

### 2.8 The key reference disagrees with the code on proxy and php defaults

`control/reference.cpp` and the generated `docs/keys.md` say `max_fails` 1 (code 3,
`upstream/options.hpp:68`), `proxy.forwarded = append | replace | off | rfc7239` (code
`x-forwarded | forwarded | both | off`, `config.cpp:200-204`), `proxy.send_timeout` 60
(code 30), pool sizes 32 / 256 / 10 (code 256 / 1024 / 64 and `queue_wait` 5 s,
`config.cpp:1243-1246`), `priority_reserve` an integer of connections (code a share in
[0, 1], `config.cpp:305-307`). Section 12 of `docs/configuration.md` matches the code. An
agent acting on the reference gets these wrong; the unit test holds the table to the
parser's key names, not to its defaults.

### 2.9 Fuzzing and the sanitizer build are hand-run and behind the code

No CI job runs a fuzzer or the sanitizer build (`.github/workflows/ci.yml`,
`release.yml`: Release build and unit tests); the "before every tag" list in
`docs/security-control-plane.md:184-192` names `fuzz_json` and `fuzz_archive` only. The
last recorded campaign is 2026-09-25; `src/path.cpp` changed on 2026-10-02 (encoded
separators) after it, and tags alpha.45 to alpha.50 shipped without a recorded run. The
roadmap checkpoint for phase E ("fuzzers clean for 1 h") is open. The claim that a
lightweight server is more prone to memory bugs is wrong on the evidence, but the
evidence is three weeks old.

### 2.10 Design documents promise timers the code does not have

`design-http3.md:854,862` describe per-stream stall and body timers; `H3Stream::since` is
set and never read, and `src/http3` has no per-stream timer. `design-http2.md:552-556`
describes the header-block and not-draining checks without the "only while a stream is
open" condition; its `h2-attacks.py` is not in the tree (`h3-attacks.py` is). The design
documents are what reviewers read; they should say what the code does.

### 2.11 Minor, for the record

- Chunk extensions and trailers do not count toward `max_body_size`, bounded at 4 KB per
  chunk and 8 KB per body (`chunked.hpp:43-44`); fine. A malformed chunk closes without a
  400 (`connection.hpp:233-238`); nginx answers 400. No 414: a long request line is 431.
- `connection_error` on HTTP/2 only sets `closing_after_write_`; whether the GOAWAY it
  builds is queued and the socket closed when the writer never drains was not traced.
- The chunked decoder accepts a bare LF nowhere, the head parser accepts it as a line
  terminator (`parser.cpp:27-36`); the asymmetry is deliberate but undocumented.
- `fuzz_chunked`, `fuzz_fcgi` and `fuzz_hpack_roundtrip` have no recorded run counts
  (recorded since, in `security-control-plane.md`'s fuzz tables).

## 3. Feature gaps that are real, and whether they matter here

In the order they matter for the hosting target (PHP and application sites behind the
control plane), with the nginx feature each stands in for.

1. **`allow` / `deny` on a location.** Not built. Admin paths (`/wp-admin/`,
   Statamic's `/cp`, Kanboard's settings) restricted to an office address are the most
   common nginx `allow` use; `net/cidr.hpp` and `trusted_proxies` give the matcher and
   the client-address rule (behind a proxy the rightmost untrusted hop). One list per
   location, checked after routing, no cost on a location without one. Small step.
   Built 2026-10-07 (`docs/configuration.md` 19, design section 22): a site-level rule checked
   before routing, since a per-location list repeats nginx's `.php` pitfall; the research
   behind it is `reports/Web server IP access control.md`.
2. **Basic authentication.** Not built. A staging site or an admin tool in front of an
   application that has no login (`uptime-kuma`'s metrics, a `proxy` site). htpasswd
   formats bcrypt and sha-crypt through the platform's `crypt_r` (OpenSSL is in already;
   `apr1` would need its own code). Medium step; a `[[site.location]] auth = { users =
   "file" }` key and a realm.
3. **A per-location request rate (`limit_req`).** Decided out at the address level, but
   the decision leaves a hole the firewall cannot see: a request rate on one path (a
   login, an API) per client, keyed inside the request. fail2ban covers the brute-force
   case after the fact from the log. Per-worker counters (no sharing, nginx shares through
   shared memory) keyed by address on the locations that name a rate would cost nothing
   elsewhere. Owner's call whether to reopen; this document only records that nginx's
   `limit_req` is a per-URI feature and the 2026-10-02 split answers the per-address one.
4. **TLS keys**: `min_version`, `ciphers`, `ciphersuites`, `curves`, and ticket key
   rotation (a per-process key reset only at reload today; nginx behaves the same without
   `ssl_session_ticket_key`). Small step for the keys; rotation is a timer on worker 0.
5. **Custom error pages** (`error_page`) and **on-the-fly compression** (`gzip on`):
   roadmap H4 and E2. Operators ask for the first with every branded site; the second
   matters for dynamic PHP and proxied output (static files have the twins).
6. **Load balancing beyond round-robin** (`least_conn`, weights, `backup`) and an active
   prober: design section 6, "until a real deployment asks". No deployment has.
7. **OCSP stapling**: moot for `tls = "auto"` since Let's Encrypt dropped OCSP (May and
   August 2025); only manual certificates from a CA that still runs responders benefit.
8. **WAF**: ModSecurity and Coraza are compiled into nginx by their users, not shipped by
   it. Out of scope for the server; a `auth_request`-style hook that lets an external
   process accept or refuse a request would be the agensio-shaped answer later.
9. **Directory listing**, **`rewrite`**, **`return` with any status**: the managed site
   and root additions cover redirects to https only (`redirect` on a site,
   `dispatch.cpp:11-43`); typed `headers` and `redirects` fields are the next planned
   step for the agent (design section 20).

## 4. Where agensio is already stricter than nginx (to keep)

- Head deadline 15 s against nginx's 60; keep-alive idle 15 s against 75.
- The connection ceiling with a 503 and Retry-After in one send, no object allocated
  (`server.cpp:887-897`), and the refused-address sample for health.
- Field syntax: 400 and close on every smuggling vector in `parser.cpp:98-209`; exact
  body framing; 431 above 100 fields.
- HTTP/2 budgets (glitches, resets per second at `max_concurrent_streams`, 8
  CONTINUATION frames, 16 KB blocks); nginx's `http2_max_concurrent_streams` and the
  2023 reset-flood fix are the comparable parts.
- QUIC: Retry past 512 half-open handshakes, the 3x amplification limit, stateless
  resets capped at 1,000 a second, the transport glitch budget.
- The sanitizer build and thirteen fuzzers (when they are run).

## 5. What remains to check live

Each item names the check and what a pass looks like. These belong in the suites, not in
a one-off.

1. **2.1, both shapes** (**done 2026-10-25**, section 5.1: the test fails
   on `v0.1.0-alpha.55` and passes from alpha.56). Live on 2026-10-08 (alpha.55 beside
   alpha.56, `idle_timeout = 2`): the pull-in-flight part is confirmed (a streaming proxy
   answer pausing 8 s between chunks was cut at 4.0 s on alpha.55, whole at 8.0 s on
   alpha.56); the worker stop was not reproduced by a client with a 1 KB window that never
   updates it: flow control blocks the response before the writer holds any of it, so
   `close_stream` releases the stream at once and the loop moves on. The failing state needs
   the stream's bytes inside a write when the cut lands: a client with a large window (2^31-1
   and a connection WINDOW_UPDATE to match), a small receive buffer (4 KB), a 10 MB response
   over TLS (plain HTTP sends a large cached file through sendfile, another path), never
   reading. Against a Release build with `idle_timeout = 3`: an HTTP/2
   client with a large window that stops reading a 10 MB response, and a `buffering =
   false` FastCGI script that sleeps longer than the idle timeout between two prints;
   in each, a plain request on another connection must be answered within a second and
   the worker's CPU must stay idle. Then the same with the fix. Run under the sanitizer
   build as well. The HTTP/1 counterpart (a slow reader on the sendfile path) as the
   control row.
2. **2.2** (**done 2026-10-25**, section 5.1: the test fails on `v0.1.0-alpha.56`
   and passes from alpha.57; the alpha.57 report, finding
   1, says what a loopback run needs for the two builds to differ): an HTTPS client with a 4 KB receive buffer reading a 2 MB cached file at
   100 KB/s must receive it whole; the old code cuts it at 15 s.
3. **2.3** (**done 2026-10-25**, section 5.2: fails on alpha.115, passes from alpha.116):
   an h2c client dribbling one byte of a frame every 14 s, and preface-only variants; the
   connection must close at the idle timeout. The header-block deadline with no stream
   open is also covered now: `h2-header-block`, section 5.3.
4. **2.4** (**done 2026-10-25**, section 5.2: fails on alpha.115, passes from alpha.116):
   a QUIC client that stalls its handshake and sends one undecryptable datagram every
   14 s; its connection must retire at the deadline, measured by the isolated server's
   `status.connections` delta, and a new handshake accepted while it exists. Section 5.3
   also proves the absolute deadline under authenticated Initial packets and release of
   the full 1,024-client budget. The existing `handshake-flood` row sends Initials but
   does not keep them alive; `handshake-budget` does.
5. **2.6**: `openssl s_client -tls1_2` with a renegotiation request must be refused after
   the fix; the TLS rows of the A/B flat.
6. **2.7**: change `idle_timeout` and reload; a new keep-alive connection must get the
   new value (today it gets the boot value).
7. **2.9**: one hour per fuzzer on the regression corpora with the current tree, the
   sanitizer build through `tests/integration.sh`, `tests/acme.sh`, `tests/h3-attacks.py`
   and h2load over TLS, h2c and QUIC; the counts into `security-control-plane.md`, every
   fuzzer onto the before-tag list, and a scheduled CI job for both (roadmap H7b).
8. **HTTP/2 floods not in the glitch budget**: connection-level WINDOW_UPDATEs of 1 KB
   at the line rate with 128 open streams, CPU per second measured; a SETTINGS flood at
   just under 10 a second; both against the sanitizer build. WINDOW_UPDATE is measured
   in section 5.3, including a sanitizer run, and left as it is (section 0, row 2.3); the
   SETTINGS reproduction remains to do.
9. **HTTP/1 body dribble**: one byte per 59 s up to `max_body_size`; parity with nginx,
   so the check is only that the connection is counted idle for health and that the
   ceiling's refusal shape names it. By the code (2026-10-25) it is not counted: the
   HTTP/1 `shed()` returns while a body is pending or a head is incomplete (`body_pending_`,
   `in_len_ > 0`), the only place `Worker::idle` is raised, and HTTP/2 raises it only with no
   stream open. A ceiling filled by such clients from many addresses would then get
   `refusal_finding`'s third reading, "legitimate load from many addresses: raise the
   open-file limit", rather than slow clients. To reproduce before deciding anything.
10. **The GOAWAY path of `connection_error`** with a writer that never drains (2.11). By the
    code (2026-10-25) it is bounded: after `connection_error` the read loop stops
    (`closing_after_write_`), so nothing refreshes `last_activity_`, and `check_timeouts`
    closes a connection whose writer does not drain at four idle timeouts. To confirm live.
11. **The host itself** (**done 2026-10-25**): `health_check` on the test VPS (alpha.115)
    reports no `firewall_limits_missing`, `fail2ban_missing` or `protection_unchecked`, so
    the nftables table and the jails are applied; what is left is info: the WordPress and
    Drupal failure jails wait for the applications' side (`fail2ban_failures_unseen`).
12. **HTTP/2, a stalled reader that keeps sending** (found by reading, 2026-10-25): the
    check for a writer that does not drain (`check_timeouts`: `now - last_activity_ >=
    idle_timeout_ * 4 && !writer_.idle()`) reads `last_activity_`, which every read
    refreshes, and reads go on while the writer is blocked. A client that takes part of a
    response, stops reading and sends any frame more often than every four idle timeouts
    (a PING every 50 s, far under the control rate) would keep the connection, its stream
    and the bytes in its socket indefinitely, the control replies piling up in the writer's
    `ctl_`, which has no cap. HTTP/1 refreshes its clock only on writes outside tunnels, and
    tunnels have `proxy.send_timeout` (alpha.114); nginx's `send_timeout` closes after 60 s
    without a write whatever the client sends. The fix would time the drain check from the
    writer's last completed write. To reproduce first: on the current code the connection
    must still be open well past four idle timeouts.

### 5.1 Regression evidence for 2.1 and 2.2 (2026-10-25)

[`tests/timeout-regressions.py`](../tests/timeout-regressions.py) owns a fresh
single-worker server per row, bounds its clients and shutdown, and checks server stderr
for sanitizer reports. [`tests/integration.sh`](../tests/integration.sh) runs it on Linux
with python3-h2, adding the FastCGI row when php-fpm is installed; the standalone runner
fails explicitly if a selected row lacks a dependency. The checks ran inside
`agensio-devbox` with `--network none`, no published ports and no host networking:
the host's 8080-8082 belong to production containers.

Environment: x86-64 Linux 6.12.113, Debian 13.6 devbox, GCC 14.2, OpenSSL 3.5.7.
The old tags were built unmodified from `git archive`, in Release mode. The same test
script was first run against the old tags, then against the fixed tags and fresh
Release and ASan+UBSan builds of `354a495`.

| Row | Old tag, observed failure | First fixed tag, same test |
|---|---|---|
| `h2-stalled` (2.1) | alpha.55: after the first 16,375 DATA bytes the client stops reading; at the timeout the worker consumes 1.000 CPU s per second and the plain probe times out | alpha.56: probes under 1 s, CPU samples 0.000 s |
| `fastcgi` (2.1) | alpha.55: RST_STREAM CANCEL after the first 65,536 bytes; the second print is lost | alpha.56: both prints, 131,072 bytes, in 8.001 s; plain probes and idle CPU checks pass during the pause |
| `h1-sendfile` (control) | alpha.55 passes: the slow plain reader does not stall the worker | alpha.56 passes |
| `cached-tls` (2.2) | alpha.56: EOF at 1,572,614 of 2,097,152 bytes after 15.398 s | alpha.57: complete, byte-for-byte correct, in 20.518 s |

All four rows also pass together on alpha.57 and on the current Release and sanitizer
builds, with no sanitizer reports. The sanitizer build uses `RelWithDebInfo`,
`-DAGENSIO_SANITIZE=address,undefined`, `ASAN_OPTIONS=detect_leaks=1` and
`UBSAN_OPTIONS=halt_on_error=1`. The full integration suite with this hook passed on
alpha.115 (776 checks, the four rows among them). The rows were then reproduced
independently from fresh worktree builds of the three tags, with the same failures and
byte counts as the table above, and on a rebuilt ASan+UBSan binary of alpha.115.
The stalled rows use `idle_timeout = 3`; the cached row keeps the default 15 s.
The 10 MiB file exceeds the 4 MiB memory-cache limit (TLS HTTP/2 writer versus plain
HTTP/1 sendfile), while the 2 MiB file fits it and is aged before startup so current
builds do not take the deliberately uncached, unsettled-file path. The FastCGI script
flushes two 64 KiB prints around an 8 s sleep, with `buffering = false`,
`read_timeout = 20`, and PHP output buffering and compression off.

The clients set `SO_RCVBUF = 4096` **before connecting**, and advertise
`TCP_MAXSEG = 1024`. This last setting matters on loopback: its jumbo segments and
large send queue let alpha.56 pass the 15 s cached-body check, hiding the regression;
lowering the timeout to 2 s alone cut **both** alpha.56 and alpha.57 at 1,801,990 bytes.
With segments below the small receive window, the original 15 s test distinguishes
them. No server socket option, kernel setting or production network is changed.
The HTTP/2 client advertises both the stream and connection windows as 2^31-1, so
HTTP/2 flow control cannot prevent the stalled write. After the timeout, plain probes
must finish within 1 s and idle CPU samples must stay below 0.2 CPU s in a 1 s interval
(a bound to reject the spin, not a throughput benchmark).

Run from the repository root, using a binary built in the devbox:

```sh
docker run --rm --network none -v "$PWD:/src:ro" agensio-devbox \
  python3 /src/tests/timeout-regressions.py /src/build/agensio
```

For the tag checks, select `--rows h2-stalled,fastcgi,h1-sendfile` on alpha.55 (two
failures, one control pass) and alpha.56 (three passes); select `--rows cached-tls` on
alpha.56 (failure) and alpha.57 (pass). Any failed row makes the runner exit 1; it
does not special-case old versions or turn their failures into passes.

### 5.2 Deadline regressions for 2.3 and 2.4 (2026-10-25)

Both rows assert the deadline and exit 1 on alpha.115; neither turns the known failure into a
pass. Written first, they failed on alpha.115 as the table below records; the fixes in
alpha.116 make them pass (the last table), and both are now default rows of their suites.

The Release and ASan+UBSan binaries have unchanged alpha.115 server sources; both were
checked with `cmake --build` inside `agensio-devbox`. The tests use `--network none`,
with no host networking or published ports. ASan leak detection and UBSan halt-on-error
were enabled; the failures below had no sanitizer reports.

| Row / variant | Observed on alpha.115, Release and ASan+UBSan | Required after the fix |
|---|---|---|
| `h2-idle`: SETTINGS complete, then a partial PING | SETTINGS exchanged and acknowledged, no stream opened; one byte at 14 s keeps the connection open at 17 s | close at 15 s, with 1 s scheduling tolerance |
| `h2-idle`: preface, then a partial first SETTINGS | only the 24-byte magic initially; one frame byte at 14 s keeps it open at 17 s | same deadline |
| `h2-idle`: silent preface control | closes at 15.000 s without any dribble | passes already |
| `handshake-deadline`: silent control | one allocated half-open connection retires after 15.02-15.09 s | passes already |
| `handshake-deadline`: undecryptable dribble | one packet at 14 s leaves the connection allocated at 16 s | retire at 15 s, with 1 s scheduling tolerance |

The HTTP/2 variants share a fresh single-worker server and open no streams. A plain
probe still succeeds and the worker's idle CPU sample stays at 0.000 s. The QUIC row
runs first in its suite, with no other suite clients: each variant allocates exactly
one connection, verified against a baseline of `status.connections`. The control
request is present in both counts; the separate normal client's handshake and GET
must succeed, and its connection must retire before measuring the half-open lifetime.
No explicit half-open status field is added or implied.

The QUIC client sends a real Initial, verifies and answers Retry if required, and
observes the server's Initial without feeding its TLS flight into aioquic; it never
sends Finished. The dribble is a correctly framed Handshake packet with the server's
issued destination id and bogus ciphertext (RFC 9000 17.2.4), not arbitrary garbage
that the endpoint would discard before finding the connection. An unknown Handshake
cannot allocate a new connection after expiry, unlike a corrupted Initial. The
Release test also reproduces with `--retry always`, proving it is not testing a
stateless Retry instead of an allocated half-open connection.

Both loops schedule a byte/datagram every 14 s but stop soon after the first missed
15 s deadline: one dribble suffices for a bounded failure. The follow-up rows in section 5.3
cover the absolute handshake deadline under authenticated Initial packets, the HTTP/2
incomplete-header-block deadline with no stream open, and the 1,024-client budget. The QUIC
accept path's connection ceiling is not part of these fixes and stays open.

Run from the repository root (the HTTP/3 runner writes its existing `bench/tmp` files):

```sh
docker run --rm --network none -v "$PWD:/src:ro" agensio-devbox \
  python3 /src/tests/timeout-regressions.py /src/build/agensio --rows h2-idle
docker run --rm --network none -v "$PWD:/src" agensio-devbox \
  python3 /src/tests/h3-attacks.py /src/build/agensio --rows handshake-deadline
```

With the fixes (alpha.116), the same rows, unchanged:

| Row / variant | alpha.115 | alpha.116 |
|---|---|---|
| `h2-idle`: SETTINGS complete, then a partial PING | open at 17 s | closed at 15.000 s |
| `h2-idle`: preface, then a partial first SETTINGS | open at 17 s | closed at 15.000 s |
| `h2-idle`: silent preface control | closed at 15.000 s | closed at 15.000 s |
| `handshake-deadline`: silent control, Retry auto / always | retired at 15.0 s | retired at 15.042 / 15.015 s |
| `handshake-deadline`: undecryptable dribble, Retry auto / always | allocated at 16 s | retired at 15.017 / 15.013 s |

The two fixes: HTTP/2's idle close reads a clock only a completed frame, the preface, a write
or the connection's start moves, and its header-block deadline applies with no stream open
(`http2/connection.hpp`, `check_timeouts`); QUIC's idle timer restarts only for a packet that
opens, and a connection still handshaking is dropped at `created_ + idle_timeout`
(`quic/connection.hpp`, `receive`, `on_timer`, `reschedule`). All five timeout rows and all
22 HTTP/3 attack rows pass on the Release and the ASan+UBSan builds, `fuzz_h2_conn` (15.2M
runs) and `fuzz_quic_conn` (11.6M) ran ten minutes each clean on the fixed code, and the A/B
(`bench/ab.sh -2 -3` in the devbox) is flat: the baseline of the unfixed code against itself
spans 0.934 to 1.013 (`ab-20261025-135840.md`, three rounds); against it the fixed code is 0.973
to 1.026 over five rounds (`ab-20261025-141825.md`), the HTTP/3 rows 0.966 to 0.996 over eight
(`ab-20261025-143125.md`), after a three-round run whose 1.05 to 1.11 on four HTTP/2 and
HTTP/3 rows did not repeat (`ab-20261025-141029.md`).

### 5.3 Remaining deadline coverage and open-item reproductions (2026-10-25)

No server code changed for these checks. Both server binaries were built in Release from
unmodified `git archive` sources: alpha.115 (`354a495c1763d04c673c1d6b1418c44093c26ded`)
and the fixed tree (`d579167b8e3676b06f41c84aa52f2f9b84045d80`, upcoming alpha.116).
The latter still prints alpha.115; the source hash, not that version string, identifies
the fixed build. All runs used `agensio-devbox --network none`, without published ports.
Environment: AMD Ryzen 9 9900X, Linux 6.12.113, Debian 13.6, GCC 14.2, OpenSSL 3.5.7,
aioquic 1.2.0 and python3-h2 4.2.0.

Each row owns a fresh single-worker server, bounds its clients and shutdown, and checks
server stderr for sanitizer reports. `h2-header-block` joins the default timeout rows and
the integration hook; `handshake-authenticated` joins the default HTTP/3 rows.
`handshake-budget`, `h2-window-flood` and `connection-ceiling` are opt-in.

| Regression | alpha.115, required failure | Fixed tree, same row |
|---|---|---|
| `h2-header-block` (2.3) | Four nonempty CONTINUATIONs; no GOAWAY or EOF by 18 s | GOAWAY(ENHANCE_YOUR_CALM), debug data `header block not completed in time`, then EOF at 15.043 s |
| `handshake-authenticated` (2.4) | Fresh Initial PINGs 1000 and 1001 ACKed, the latter at 14.000 s; connection delta still 1 at 16.016 s | Both PINGs ACKed; delta 0 at 15.046 s; new handshake and GET succeed |
| `handshake-budget` (2.4) | All 1,024 slots occupied after dribbles, no retirement by the last client's age 16.003 s; new handshake fails | First retirement at 15.019 s; all slots released by the last client's age 15.019 s; new handshake and GET succeed |

The header row sends HEADERS with END_STREAM but without END_HEADERS on stream 1, with
no other stream open. The incomplete block has not yet allocated a server stream. Valid,
nonempty CONTINUATION fragments arrive every four seconds (RFC 9113 6.10), below the
eight-CONTINUATION cap, so neither a protocol error nor the continuation budget substitutes
for the block deadline. The assertion checks the GOAWAY code, its exact debug data and EOF.

The authenticated row uses public Initial keys (RFC 9001 5.2), the server-issued destination
id, fresh packet numbers and 1,200-byte Initial datagrams (RFC 9000 17.2.2). It decrypts the
server's Initial ACKs and checks that they cover each PING's packet number. It never feeds
the TLS flight into aioquic or sends Finished. This proves successful decryption of fresh
packets, not replay handling or an undecryptable-packet refresh, while exercising the
absolute creation-time deadline.

The budget row allocates **exactly 1,024** half-open connections, including answering Retry,
and confirms that a 1,025th handshake is blocked while the budget is full. It sends each
connection a targeted undecryptable Handshake packet at its own creation time plus 14 s.
Status deltas track retirement; an unknown Handshake cannot allocate a replacement after
expiry. The old cohort filled in 1.026 s and the fixed cohort in 0.953 s. Both sent all
1,024 dribbles; only the fixed server released the budget and admitted the final probe.
The fixed authenticated and budget rows also pass with `--retry always`.

**WINDOW_UPDATE reproduction (section 5 item 8).** `h2-window-flood` holds 128 responses
open with zero stream windows and sends connection-level increments of 1,024. A
1,023-byte control gets GOAWAY(ENHANCE_YOUR_CALM); the 1,024-byte updates do not. Each
connection processes 999,424 updates, then rotates before its connection window can
overflow `2^31-1` (RFC 9113 6.9.1). A PING ACK after each batch proves the server processed
the updates; the row also checks that the streams remain open. Alternating zero-stream
controls separates the stream-scan cost from basic frame processing:

| Open streams | Server CPU seconds / wall second | CPU ns / update | Updates / second |
|---|---|---|---|
| 0, first control | 0.923 | 2.9 | 316,432,111 |
| 128, first sample | 0.524 | 52.7 | 9,941,959 |
| 128, second sample | 0.518 | 51.3 | 10,094,734 |
| 0, final control | 0.939 | 2.9 | 328,933,265 |

This is a real per-update cost: about **18 times** the CPU with 128 streams, at roughly
129-131 MB/s of HTTP/2 frame bytes in those samples. It is **not** a reproduced worker
hang or saturation with 128 streams: this client drove about half a core, and the server
returned to idle and answered the plain probe afterward. The sample CPU includes connection
and stream setup/teardown, not just the update loop; these are unpaced local measurements,
not equal-input-rate comparisons or a demonstrated low-bandwidth denial of service.
The row's PASS means that the reproduction and measurements completed, not that the
unbudgeted-update issue is fixed. Raw Release output, machine/source metadata and command:
[`audit-window-20261025-alpha115.txt`](../bench/results/audit-window-20261025-alpha115.txt).

**QUIC ceiling reproduction (2.4, last paragraph).** `connection-ceiling` sets
`server.max_connections = 3` and holds three TCP connections. An extra plain TCP client
gets 503 with Retry-After and EOF; an extra TLS/TCP client gets EOF before handshake.
Two additional QUIC clients nevertheless complete handshakes and GETs, with connection
delta **5** and **2** TCP refusals. This reproduces on **both** alpha.115 and the fixed
tree; the opt-in row fails the desired ceiling assertion on both. The QUIC accept ceiling
remains open.

Validation: all **six** default timeout rows and **23** default HTTP/3 rows pass on the
fixed Release build. ASan+UBSan passes `h2-header-block`, `h2-window-flood`,
`handshake-deadline`, `handshake-authenticated` and the full `handshake-budget`, with no
server sanitizer reports. The sanitizer WINDOW_UPDATE output is retained separately as
[`audit-window-20261025-asan.txt`](../bench/results/audit-window-20261025-asan.txt);
its instrumented timings are not a Release performance comparison. The SETTINGS flood
was not added or measured in this change.

Commands, from the repository root (`PROOF` is a writable output directory mounted at
`/results`; no host server is started):

```sh
PROOF="$PWD/bench/tmp/audit-extra"
mkdir -p "$PROOF"
docker run --rm --network none --memory 4g \
  -v "$PWD:/src:ro" -v "$PROOF:/results" agensio-devbox bash -c '
set -euo pipefail
mkdir -p /results/audit-extra-bin
for ref in v0.1.0-alpha.115 d579167b; do
  mkdir /tmp/$ref
  git -C /src archive "$ref" | tar -x -C /tmp/$ref
  cmake -S /tmp/$ref -B /tmp/$ref/build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DAGENSIO_TESTS=OFF \
    -DASIO_INCLUDE_DIR=/src/build/_deps/asio-src/include \
    > /results/audit-extra-build-$ref.log 2>&1
  cmake --build /tmp/$ref/build --target agensio -j3 \
    >> /results/audit-extra-build-$ref.log 2>&1
  cp /tmp/$ref/build/agensio /results/audit-extra-bin/$ref
done'

for ref in v0.1.0-alpha.115 d579167b; do
  docker run --rm --network none --memory 2g \
    -v "$PWD:/src:ro" -v "$PROOF:/results" agensio-devbox \
    python3 /src/tests/timeout-regressions.py \
    "/results/audit-extra-bin/$ref" --rows h2-header-block
  docker run --rm --network none --memory 4g \
    -v "$PWD:/src" -v "$PROOF:/results" agensio-devbox \
    python3 /src/tests/h3-attacks.py "/results/audit-extra-bin/$ref" \
    --rows handshake-authenticated,handshake-budget,connection-ceiling
done
# Expected exits: old H2/H3 = 1/1; fixed H2/H3 = 0/1 (ceiling still open).

# Run alone, without simultaneous build/load work; raw output linked above.
docker run --rm --network none --memory 2g \
  -v "$PWD:/src" -v "$PROOF:/results" agensio-devbox \
  python3 /src/tests/timeout-regressions.py \
  /results/audit-extra-bin/v0.1.0-alpha.115 --rows h2-window-flood

docker run --rm --network none --memory 3g \
  -v "$PWD:/src:ro" -v "$PROOF:/results" agensio-devbox \
  python3 /src/tests/timeout-regressions.py /results/audit-extra-bin/d579167b
docker run --rm --network none --memory 4g \
  -v "$PWD:/src" -v "$PROOF:/results" agensio-devbox \
  python3 /src/tests/h3-attacks.py /results/audit-extra-bin/d579167b
docker run --rm --network none --memory 4g \
  -v "$PWD:/src" -v "$PROOF:/results" agensio-devbox \
  python3 /src/tests/h3-attacks.py /results/audit-extra-bin/d579167b \
  --retry always --rows handshake-authenticated,handshake-budget

# Existing ASan+UBSan build, refreshed at its original CMake source mount.
docker run --rm --network none --memory 4g \
  -v "$PWD:$PWD" -w "$PWD" agensio-devbox \
  cmake --build build-asan --target agensio -j3
docker run --rm --network none --memory 3g \
  -e ASAN_OPTIONS=detect_leaks=1 -e UBSAN_OPTIONS=halt_on_error=1 \
  -v "$PWD:/src:ro" agensio-devbox python3 /src/tests/timeout-regressions.py \
  /src/build-asan/agensio --rows h2-header-block,h2-window-flood
docker run --rm --network none --memory 4g \
  -e ASAN_OPTIONS=detect_leaks=1 -e UBSAN_OPTIONS=halt_on_error=1 \
  -v "$PWD:/src" agensio-devbox python3 /src/tests/h3-attacks.py \
  /src/build-asan/agensio --rows handshake-deadline,handshake-authenticated,handshake-budget
```

The archive builds use the already cached Asio include directory so the network-disabled
build does not try FetchContent. Do not run two HTTP/3 harness instances concurrently
against the same bind mount: they share the runner's existing `bench/tmp` filenames.

### 5.4 The QUIC accept path at the connection ceiling, fixed (2026-10-25)

The reproduction of section 5.3 is fixed in alpha.116. The UDP endpoint asks the worker's
ceiling once for a first Initial that would make a connection (`EndpointBase::at_ceiling`,
after the 1,200-byte and id-length checks, before the token and Retry), never for a packet
of a known connection. Over the ceiling it answers with one Initial packet under the keys
the client derives from its destination id, closing with CONNECTION_REFUSED (RFC 9000 20.1),
built as the INVALID_TOKEN answer is (`build_initial_close`): 58 bytes with 8-byte ids, at
most 82, against the 1,200 it answers, no state kept. A refusal needs no Retry round trip,
so the check comes first. The refusal is counted, sampled and logged with the TCP ones
(`Server::note_refusal`, taken out of `refuse_connection`): `connections_refused`,
`workers_detail`, health's `connections_refused`, and the error-log line, which names the
QUIC listener.

The row `connection-ceiling` is now a default row, and asks for more than in 5.3: each
over-limit QUIC client must be closed with CONNECTION_REFUSED, not only fail to connect.

| Build | QUIC handshakes with GET | CONNECTION_REFUSED | connection delta | refusals | Row |
|---|---|---|---|---|---|
| alpha.115 (`bench/tmp/verify/a115`, Release) | 2/2 | 0/2 | 5 | 2 | FAIL |
| fixed tree, Release, Retry auto | 0/2 | 2/2 | 3 | 4 | pass |
| fixed tree, Release, Retry always | 0/2 | 2/2 | 3 | 4 | pass |
| fixed tree, ASan+UBSan, Retry auto and always | 0/2 | 2/2 | 3 | 4 | pass, no reports |

An ordinary aioquic client against `max_connections = 1` with one TCP connection held
receives the server's answer 2 ms after its Initial; aioquic reports the termination
(error 0x2, reason `server busy`) after its own draining period, 0.6 s (RFC 9000 10.2.2).
alpha.115 completes that handshake in 3 ms. The same over IPv6 (`[::1]`) and through a
dual-stack `[::]` listener with an IPv4 client: refused, and the error-log line names the
client `::1` and `127.0.0.1` (unmapped), as the TCP path does. The default attack suite passes whole (24 rows,
Retry auto), the Retry-always subset with the ceiling row too, and the unit tests.

Cost: two relaxed loads per new-connection Initial, nothing per packet of a known
connection. A/B against `d579167b` in the devbox: the baseline of `d579167b` against itself
spans 0.941 to 1.011 (`ab-20261025-161033.md`, `-3 -r 3`); the fix 0.980 to 1.037 over three
rounds (`ab-20261025-163225.md`), its three rows above 1.03 back at 0.979 to 1.000 over five
(`ab-20261025-163830.md`, `-3 -r 5`, all rows 0.947 to 1.000).

## 6. Proposed order

Small steps, each gated by the suites and `bench/ab.sh` (the `-2` and `-3` rows where
the code is HTTP/2 or QUIC):

1. 2.1 (the loop) with its two integration checks.
2. 2.6 (renegotiation off) and 2.2 (memory bodies in pieces over TLS).
3. 2.4 (QUIC handshake deadline, decrypted-packet refresh, ceiling in the accept path).
4. 2.3 (frame-based activity, the header-block deadline always, large WINDOW_UPDATEs
   under the control rate).
5. 2.5 (tunnel write timeout, loop watchdog).
6. 2.7 and 2.8 (reload semantics; reference rows and a unit test on defaults), 2.10
   (design documents corrected).
7. 2.9 (the fuzz campaign and the CI schedule).
8. Then the features of section 3 in that order, each a design note first.
