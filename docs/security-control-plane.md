# Control plane security review (F7)

The control API, `agensio ctl` and the MCP bridge (`docs/configuration.md` section 15,
`docs/mcp.md`) are the one part of agensio that changes the server. This page lists the
threat model from the roadmap, the rule that answers each threat, where the rule lives,
and the test that proves it. Reviewed 2026-09-19 for the pre-alpha; every later change
under `src/control/` updates the row it touches.

## Threat model

1. A local unprivileged user, or a compromised PHP/Node application running as its own
   account.
2. A browser on the administrator's machine (CSRF, DNS rebinding).
3. Anything on the network.
4. An AI agent or a script misusing the interface, by mistake or through prompt injection.
5. An attacker holding a token or a copy of the configuration.

## Rules and their evidence

| # | rule | where | test |
|---|---|---|---|
| 1 | The control API is a separate listener with its own code path; no site listener can route to it, no shared port | `Generation::control` is its own `Listener` with a synthetic site of kind `control`; the data-plane routers never contain that site (`server.cpp`, `build_listeners`) | `tests/integration.sh` "no TCP listener in the control plane"; every data-plane request to `/v1/...` on a site is a normal 404 |
| 2 | Unix socket only; nothing on the network reaches it | `open_control` binds `asio::local::stream_protocol`; there is no TCP transport in the alpha (deferred with token and mTLS) | same static check; threat 3 has nothing to connect to |
| 3 | The socket's directory is created by the server, owned by it, never world-writable, so a site user cannot replace the socket path | `open_control`: `create_directories`, `chmod 0755`, `chown` to `server.user` | `tests/control.sh` "directory owned by the server user" |
| 4 | Peer credentials are checked on every connection regardless of file mode; root and `server.user` are admin, the three groups map to roles, anyone else is closed before a byte is read | `start_accept_control` + `control/peer.hpp` (`SO_PEERCRED` / `getpeereid`) + `control/roles.hpp` | `tests/control.sh`: root, server user, admin group, operator group, viewer supplementary group, outsider refused; unit test of `role_of` |
| 5 | File mode is the second line: `0660` for a single admin group, else `0666` | `open_control` | `tests/control.sh` "socket 0660 / 0666" |
| 6 | Roles: viewer reads, operator reloads and reopens logs and renews, admin changes sites; a lower role gets 403 naming the role needed | `ControlHandler::require`, `mutate` | `tests/control.sh` role matrix through the MCP tool lists; `tests/integration.sh` 405/404/428 answers |
| 7 | Every mutation needs `confirm: true`, carries a `reason`, and is written to the audit log with uid, gid, role and outcome; refused connections are audited too | `ControlHandler::mutate`, `audit` | `tests/integration.sh` "428 without confirm", "audit has every mutation"; `tests/control.sh` "refusal is in the audit log" |
| 8 | Mutations are safe by construction: the result is validated before it is applied, a refused change is undone, anything overwritten keeps a `.bak` | `site_create` / `site_update` / `site_toggle` call `reload_now` and roll back on refusal; `write_site_file` | `tests/integration.sh` create, update, disable, enable, delete, "reload with a broken file is refused, old configuration serves" |
| 9 | `site_create` accepts only syntactically valid host names, and the file name is derived from that name, so no path can escape `sites.d` | `control::valid_domain` (lower-case labels, no `/`, no `..`), `site_file` | unit tests of `valid_domain` (`../etc.com`, `a.com/x`, spaces refused); `tests/control.sh` "a site name with a slash never reaches a file" |
| 10 | Generated TOML comes from a renderer with quoted strings, never from concatenating user text into structure | `control::render_site`, `toml_string` | unit test: rendered file loads back through `load_config` |
| 11 | The API never executes a shell command; root work is returned as text | no `system`, `popen`, `exec*`, `fork`, `posix_spawn` under `src/control/` | `tests/integration.sh` static grep |
| 12 | Request bodies on the control socket are capped (256 KB) and must be a JSON object | `ControlHandler::start`, `mutate` | `tests/control.sh` "1 MB body refused with 413"; `tests/integration.sh` 400 on a non-object |
| 13 | The JSON parser is bounded (depth 64) and fuzzed | `services/json.hpp`, `tests/fuzz/fuzz_json.cpp` | libFuzzer run recorded below |
| 14 | Log queries read at most 2 MB per file from the end, return at most 5000 lines, and never follow user-supplied paths (files come from the configuration) | `control::LogQuery`, `scan_log`, `logs` | unit test of the byte cap and the limit |
| 15 | Kill switch: no `[control]` table, no socket, nothing to reach | `open_control` returns at once | `tests/control.sh` "without [control] no socket exists" |
| 16 | The MCP bridge is not a listener; it inherits the caller's role and holds no secret; a viewer's session does not list mutating tools; mutating tools carry `readOnlyHint: false` and `destructiveHint` where it applies and require `confirm` and `reason` | `control/mcp.cpp` | `tests/control.sh` tool counts per role; `tests/integration.sh` annotations and the 428 through the bridge |
| 17 | Server logs opened as root are handed to the service user so rotation works after the drop; the audit log is among them | `own_site_logs` | `tests/control.sh` "audit log owned by the server user" |
| 18 | The same fuzzed HTTP/1.1 parser as the data plane reads the control socket | `Http1Connection<local socket>` | the parser's own fuzz target and its 17 smuggling tests |
| 19 | An application install writes only as the site's account into an empty directory that account owns: the site's `user`, or the owner of the site's directory when it is a site account or the server's; root and login accounts are refused; the helper's child drops privileges before it reads a byte. The target is reached from the site's directory by a walk that never follows a symlink and requires every existing component to be the account's; `create_path` makes missing levels as that account with the parent's pattern, and a refusal removes what the call created | `provision.cpp` `install_account`, `app_install`; `install::execute` (the walk, `create_path`, cleanup) checks the owner against its own euid again | `tests/install.sh`: files and created directories owned by the site user, root-owned, login-owned and other-account components refused; unit tests of the walk (symlink, `..`, outside, two-level creation and its cleanup, dry run) |
| 20 | Downloads are https only, certificate and host verified, every address of every hop checked against the private-address fence (loopback, link-local, RFC 1918, ULA, 100.64/10, multicast, IPv4-mapped), 5 redirects, 1 GB, 15 minutes; `install = false` turns downloads off and leaves uploads; `install_private` opens the fence knowingly | `services/fetch.*` | unit test of `is_private_address` and `split_url`; `tests/integration.sh` "a private https address is fenced", "install = false"; `tests/install.sh` download as the site user with `install_private` |
| 21 | Archives are unpacked by agensio's own bounded extractor: symlinks, hard links, devices, fifos, absolute paths, `..`, backslashes, control characters, encrypted and zip64 entries, checksum and CRC mismatches, entry, size, depth and path caps all end the install with the reason and an emptied directory; files are created `O_EXCL | O_NOFOLLOW` with modes from the target's own; an optional sha256 gates the whole thing | `services/archive.*`, `services/install.*`, `tests/fuzz/fuzz_archive.cpp` | unit tests of every refusal on in-memory tar and zip; `tests/install.sh` "symlink refused, directory empty"; fuzz run recorded below |
| 23 | `site-copy` moves bytes the site already has to another path of the same site and nothing else: both paths reached by the walk of row 19 from the site's directory, so no path can name another site or anything outside (through `..`, an absolute path or a symlink placed inside); the source must be a regular file; the destination's directory must exist; an existing destination needs `overwrite` and is reported; the file is written under a temporary name and linked (no overwrite: EEXIST is the race) or renamed into place; no caller content, no directory, no chmod, no chown, no move, no delete, and no configuration option relaxes any of it | `install::copy_file`, helper op `file_copy` (`provision::validate`), `ControlHandler::site_copy` | unit tests of every refusal and of the outside-the-site cases; `tests/integration.sh` copy checks; `tests/install.sh`: the file owned by the site user with the layout's pattern, another account's directory refused |
| 24 | A writer never answers ok to a state the validator refuses: `site-install` and `site-copy` create the preset's credential files (`preset_secrets`, the list the hosting rule reads) `0600`, check hosting rule 3 on what they wrote as the writing account, and compare the configuration's validation errors before and after the call in the server; a new error answers `409` with `written: true` and the validator's words | `install::execute` / `copy_file` (`secured`), `secret_paths` and `secret_exposed` shared with `check_hosting`, `ControlHandler` `validation_errors` / `new_errors` | unit tests: secrets `0600` after an unwrap and below a plugin path, a copy onto a secret, the rule on Drupal's files, every preset's secrets among its never-served list; `tests/integration.sh` and `tests/install.sh`: `wp-config.php` `0600` after install and copy, `validate` ok |
| 25 | Per-site settings are an allowlist of typed resource limits (`control/settings.cpp`, one table for what is accepted, what is advertised and the MCP schema), each moving only within the ceiling `[control] site_limits` sets, which only the root-owned file changes; no ini map, no `open_basedir`, no path, no key that changes what a site may reach or run: `extra`, `sendmail_path`, `auto_prepend_file`, `extension`, `disable_functions` and every other name are refused as unknown | `control::apply_settings`, `settings_catalog`, `settings_schema` in the bridge | unit tests: every dangerous name refused, ceilings and minimums, enum, sizes; `tests/integration.sh`: the same through the socket, and a check that the schema, the catalogue and what `site_update` accepts are one set |
| 22 | Uploads land in `<state_dir>/uploads`, the server's own directory (0700), by name only (no path), capped by `upload_max` (413 before a byte is stored), a partial transfer leaves nothing, and are readable by no site account; the helper opens them as root for the install child | `ControlHandler::upload_receive`, `Server::prepare_uploads`, `body_limit()` on the local socket | `tests/integration.sh` upload checks; `tests/install.sh` "unreadable by the site account" |

Threat 2 (browsers) is answered by rule 2: there is no TCP transport, so no browser can
reach the socket. When the loopback transport arrives after the alpha, the `Origin`
refusal, the `Host` check and the custom header requirement from the roadmap come with
it, plus their tests. Threat 5 (a stolen token or configuration) is answered by rules 2
and 4: there is no token, and a configuration copy grants nothing without an account in
a role.

## The provisioning helper (F8, 2026-09-20)

`[control] provision = true` (default) forks a root helper before the privilege drop. It
changes the trust model, so here is exactly what it is:

- **Reachability.** The helper holds one end of a socketpair; there is no path and no
  port. Only the server process can talk to it. A site user, a PHP application or a
  network peer has nothing to connect to.
- **Vocabulary.** Seven requests, each validated again inside the helper against the
  configuration it started with (`provision::validate`, unit tested): `account_add`
  (name by the account rule, no system accounts, no words for "none"; `useradd --system
  --no-create-home`, home in `state_dir`, `nologin`), `site_layout` (a normalised
  absolute path strictly below `sites_root`; owner must be a site account, i.e. `nologin`
  with its home in `state_dir`; the walk uses `openat(O_NOFOLLOW)` so a planted symlink is
  refused; a directory owned by anyone but root, the server or that owner is refused, so
  no site is ever handed over to another), `log_own` (a `.log` below the log directory,
  `agensio:<group> 0640`, `O_NOFOLLOW`), `pools_apply` (re-reads the configuration
  itself, runs the hosting rules, writes the pool files, reloads php-fpm),
  `service_restart` (once a minute at most), and `app_install` (F9: a target strictly
  below `sites_root`, one source that is an https URL or a plain upload name, the
  account rule of row 19; a forked child becomes that account with `setgroups`,
  `setgid`, `setuid` and a check that root cannot be regained, then downloads or reads
  the upload, verifies the digest and unpacks with the fences of rows 20 and 21; the
  helper waits with a 20-minute deadline), and `file_copy` (F9b: the same account rule
  and child, one regular file of the site to another path of the same site, row 23;
  narrower than `app_install` in every way).
- **Execution.** `useradd`, `groupadd` and `systemctl` by absolute path, fixed argument
  list, empty environment. No shell, ever. Nothing the server sends can name a program.
- **Audit.** Every request and every refusal is written to the audit log with the
  control-socket peer's uid and the reason of the command that caused it.

What a fully compromised server process gains: it can create `nologin` system accounts
without a home, lay out directories under `sites_root` for such accounts, regenerate pool
files the hosting rules accept, restart the service (rate-limited), have an archive
of its choosing unpacked, as a site account, into an empty directory that account owns
under `sites_root` (regular files and directories only, no symlinks, no set-uid, no
program run), and have one of a site's files copied to another path of the same site as
that account. What it cannot do: obtain a shell or run any other program, read or write
outside `sites_root`, `state_dir`, the pool directory and the log directory, take over a
directory of another site, write as root or as any login account, or touch an account
that has a login shell. That exposure is smaller than php-fpm's root master on the same
host. `provision = false` removes the helper, and with it the one-call site creation:
the commands come back as text, as before, and installs run as the server's own account
into directories it owns. Tested in `tests/provision.sh` and `tests/install.sh` (root
devbox): the one-call paths and each refusal.

## Deferred, and why it is acceptable for the alpha

- `agensio -t` isolation warning (a pool or origin running as the server's own user or
  in the admin group): the rule is documented in section 15 and `health_check` reports
  application sites sharing the server's account; the load-time warning follows.
- Loopback TCP, token, mutual TLS: not needed for the SSH workflow the alpha targets.
- `cache/purge`: waits for the cache invalidation API.

## Sanitizer and fuzz record

2026-09-25, the HTTP/3 stability step: `fuzz_quic_packet` 20.58 M runs in 121 s
(`-max_len=2048`, corpus 378 inputs, 195 edges), `fuzz_transport_params` 121.37 M runs
(corpus 119, 185 edges), `fuzz_qpack` 11.72 M runs (corpus 333, 386 edges), all under
ASan and UBSan with no findings; the corpora are checked in under
`tests/fuzz/regressions/`. The same day the release and sanitizer builds ran the
integration suite (530 checks, the lossy relay's two included) and the twenty-row attack
suite with no report, and the sanitizer build served h2load over QUIC (one and sixty-four
streams per connection, 64 connections, 3.3 M requests) clean.


2026-09-20, F9 (site-install): `fuzz_archive` 14.73 M runs in 121 s (`-max_len=65536`,
seeded with a tar and a zip), no finding. Unit tests, `tests/install.sh` and
`tests/provision.sh` under `-fsanitize=address,undefined`: clean.

2026-09-19, the run that closed F7: `fuzz_json` 5.83 M runs in 121 s (`-max_len=4096`),
no finding. Unit, integration, root-role, reload and Pebble suites under
`-fsanitize=address,undefined`: one finding, a use-after-free at shutdown in the ACME
manager's second `stop()` (timer cancelled after its io_context was destroyed), fixed;
all suites clean afterwards. Repeat both before every tag:

```
cmake -B build-san -DAGENSIO_SANITIZE=address,undefined -DAGENSIO_TESTS=ON && cmake --build build-san
build-san/agensio_tests && tests/integration.sh build-san/agensio && tests/acme.sh build-san/agensio
cmake -B build-fuzz -DAGENSIO_FUZZ=ON -DAGENSIO_TESTS=OFF -DAGENSIO_TLS=OFF -DCMAKE_CXX_COMPILER=clang++
cmake --build build-fuzz --target fuzz_json fuzz_archive && build-fuzz/fuzz_json tests/fuzz/regressions/json -max_total_time=120
build-fuzz/fuzz_archive tests/fuzz/regressions/archive -max_len=65536 -max_total_time=120
```


## HTTP/2 (phase G)

The request-path threats of HTTP/2 (Rapid Reset, MadeYouReset, CONTINUATION floods, HPACK
bombs and the 2026 HTTP/2 Bomb, slow reads and window dribbles, PING, SETTINGS and empty
frame floods, priority trees, request smuggling over the HTTP/1.1 downgrade) and the
bound each one meets are the table of `docs/design-http2.md` section 8; the limits are
constants at the top of `src/http2/connection.hpp` and derive from `max_header_size`,
`max_requests_per_connection`, `idle_timeout`, `body_timeout` and the body limits. Fuzz
record: `fuzz_hpack` (decoder, persistent decoder, encoder round trip, Huffman round trip).
The attack suite (`tests/h2-attacks.py`) and the differential fuzz against nghttp2 are
step G3 of the roadmap.

## HTTP/3 (phase I)

The QUIC transport and the HTTP/3 layer (`src/quic/`, `src/http3/`) follow the threat table
of `docs/design-http3.md` section 9: the anti-amplification limit before the address is
validated, Initial packets under 1,200 bytes dropped, the packet number spaces' frame
rules, flow-control and stream limits enforced as FLOW_CONTROL_ERROR and STREAM_LIMIT_ERROR,
CRYPTO data bounded per level, an acknowledgement of a packet never sent closing the
connection, the QPACK dynamic table bounded at 4 KB with at most 16 sections waiting for it
(a section beyond the table is refused, an insert larger than it or a reference to an
evicted entry closes the connection), control-stream rules of RFC 9114 (SETTINGS first, one of each critical stream,
request frames refused on control streams), unread bodies drained up to 64 KB then
STOP_SENDING. Since the transport step of 2026-09-24 (design 6.3, 6.4, 6.9): address
validation with Retry (`http3.retry`: tokens sealed under a per-hour key from the
process secret, bound to the address, the original id and the time, valid ten seconds;
an Initial with a token that does not open is answered with INVALID_TOKEN and forgotten;
"auto" sends Retry once a worker has 512 handshakes in progress and drops Initials at
1,024), stateless resets for ids nobody knows (tokens computed from the process secret,
a reset always smaller than the packet, at most 1,000 per second per worker), at most
four connection ids each way with replacements after RETIRE_CONNECTION_ID (a retirement
of an id never issued or of the id the packet came to is PROTOCOL_VIOLATION, a fifth
active id of the peer's is CONNECTION_ID_LIMIT_ERROR, at most 64 issued per connection),
key update with the previous keys kept three PTOs and a second update before the first
is acknowledged refused with KEY_UPDATE_ERROR, path validation when a client's address
changes (three times the bytes received on the new path until PATH_RESPONSE, one
validation at a time, the previous address restored when it fails), the reset budget
(RESET_STREAM and STOP_SENDING past `http2.max_concurrent_streams` in one second close
with H3_EXCESSIVE_LOAD) and the glitch budget (100 credit updates that raise nothing).
`tests/h3-attacks.py` (aioquic, in the devbox image; the integration suite runs it where
aioquic is installed) asserts twenty rows of the design's table against the release and
sanitizer builds: the handshake, Retry in both modes, a garbage token, a key update and a
second one before the first is acknowledged, a client that changes its port, retired ids,
a stateless reset, 3,000 forged packets on a live id, 200 stream resets in a second, 300
streams beyond the limit, a second SETTINGS, 1,500 Initials in a second, and, as raw
frames written into aioquic's packets, 101 credit updates that raise nothing, an
acknowledgement of a packet never sent, a fifth connection id, retiring an unissued and
the in-use id, data beyond a stream's window; the last row opens a connection and sends
the server SIGINT, expecting GOAWAY and a close with H3_NO_ERROR at once. The loss proxy
`tests/quic-lossy.py` sits between curl and the server in the integration suite (3 % of
the datagrams dropped, 5 % delayed up to 3 ms, both ways; the 10 MB file must arrive).
The transport's parsers are fuzzed: `fuzz_quic_packet` (headers, coalescing, the frames
of every space), `fuzz_transport_params` (decode and the round trip through the encoder),
`fuzz_qpack` (the encoder stream, a section against the table, the decoder stream's
answers); runs recorded below.

The QUIC interop runner (`bench/quic-interop/run.sh`, design 9.2), agensio as the server
against the quic-go and ngtcp2 clients through the ns-3 simulator, 2026-09-25
(`bench/results/interop-20260925-061102.md`):

| case | quic-go | ngtcp2 | what it proves |
|---|---|---|---|
| handshake, transfer, longrtt (750 ms), http3, ipv6 | pass | pass | the handshake, streams and flow control, HTTP/3 over both address families |
| chacha20 | pass | pass | the ChaCha20-Poly1305 suite for the packets |
| multiplexing (2,000 files on one connection) | pass | pass | stream limits raised as streams close; a request retransmitted after loss is not refused as stale |
| retry | pass | pass | Retry with the sealed token, the client's Initial with the token accepted |
| resumption | pass | pass | TLS session resumption on a second connection |
| keyupdate | pass | pass | the client's key update followed, the header-protection key kept |
| amplificationlimit | pass | pass | three times the bytes received until the address is validated |
| blackhole (the path goes dark, then returns) | pass | pass | probes, timers and the congestion controller recover |
| handshakeloss, handshakecorruption (50 connections at 30 % loss or corruption) | pass | pass (one run counted 51 handshakes for 50 connections: the client restarted an attempt) | probes carry the oldest unacknowledged data (RFC 9002 6.2.4) |
| transferloss, transfercorruption | pass | pass | loss recovery and retransmission on a busy connection |
| rebind-port, rebind-addr | pass | pass | path validation when the client's address changes |
| zerortt, ecn, v2, connectionmigration | unsupported by choice (exit 127) | same | early data, ECN, version 2 and active migration are the design's I4 |

Three server bugs the runner found before the table came out like this, all fixed the same
day: no Version Negotiation was ever sent (the header parser applied version 1's rules to
an unknown version), the closed-stream window of 64 indices refused retransmitted
requests, and don't-fragment was set for IPv4 sockets only, so the MTU search went past a
1,500-byte link on fragments. Still the design's I2: a connection-level fuzzer and the
amplification row of the attack suite (a spoofed source). `"h3"` stays off by default
until the design's checkpoint.
