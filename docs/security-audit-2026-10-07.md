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
| 2.1 to 2.5 | **open**: the HTTP/2 timeout loop, the slow TLS download, the HTTP/2 idle clock, the QUIC handshake deadline, the tunnel timeout and watchdog. Not changed in this session: no reproduction test was written for them, and without one the rule of a failing test first cannot be met | section 5 lists the checks each needs |

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
- `fuzz_chunked`, `fuzz_fcgi` and `fuzz_hpack_roundtrip` have no recorded run counts.

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

1. **2.1, both shapes**, against a Release build with `idle_timeout = 3`: an HTTP/2
   client with a large window that stops reading a 10 MB response, and a `buffering =
   false` FastCGI script that sleeps longer than the idle timeout between two prints;
   in each, a plain request on another connection must be answered within a second and
   the worker's CPU must stay idle. Then the same with the fix. Run under the sanitizer
   build as well. The HTTP/1 counterpart (a slow reader on the sendfile path) as the
   control row.
2. **2.2**: an HTTPS client with a 4 KB receive buffer reading a 2 MB cached file at
   100 KB/s must receive it whole; today the expectation is a cut at 15 s.
3. **2.3**: an h2c client dribbling one byte of a frame every 14 s, and one sending the
   preface only; the connection must close at the idle timeout after the fix.
4. **2.4**: a QUIC client that stalls its handshake and sends one garbage datagram every
   14 s; the half-open count (`status`) must drop at the deadline, and new handshakes
   must still be accepted with 1,024 such clients. Add the row to `tests/h3-attacks.py`.
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
   just under 10 a second; both against the sanitizer build.
9. **HTTP/1 body dribble**: one byte per 59 s up to `max_body_size`; parity with nginx,
   so the check is only that the connection is counted idle for health and that the
   ceiling's refusal shape names it.
10. **The GOAWAY path of `connection_error`** with a writer that never drains (2.11).
11. **The host itself**: `health_check` on the VPS says whether the nftables table and
    the jails rendered on 2026-10-02 are applied; the per-address limits this document
    leans on exist only once they are.

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
