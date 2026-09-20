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
- **Vocabulary.** Five requests, each validated again inside the helper against the
  configuration it started with (`provision::validate`, unit tested): `account_add`
  (name by the account rule, no system accounts, no words for "none"; `useradd --system
  --no-create-home`, home in `state_dir`, `nologin`), `site_layout` (a normalised
  absolute path strictly below `sites_root`; owner must be a site account, i.e. `nologin`
  with its home in `state_dir`; the walk uses `openat(O_NOFOLLOW)` so a planted symlink is
  refused; a directory owned by anyone but root, the server or that owner is refused, so
  no site is ever handed over to another), `log_own` (a `.log` below the log directory,
  `agensio:<group> 0640`, `O_NOFOLLOW`), `pools_apply` (re-reads the configuration
  itself, runs the hosting rules, writes the pool files, reloads php-fpm), and
  `service_restart` (once a minute at most).
- **Execution.** `useradd`, `groupadd` and `systemctl` by absolute path, fixed argument
  list, empty environment. No shell, ever. Nothing the server sends can name a program.
- **Audit.** Every request and every refusal is written to the audit log with the
  control-socket peer's uid and the reason of the command that caused it.

What a fully compromised server process gains: it can create `nologin` system accounts
without a home, lay out directories under `sites_root` for such accounts, regenerate pool
files the hosting rules accept, and restart the service (rate-limited). What it cannot
do: obtain a shell or run any other program, read or write outside `sites_root`,
`state_dir`, the pool directory and the log directory, take over a directory of another
site, or touch an account that has a login shell. That exposure is smaller than php-fpm's
root master on the same host. `provision = false` removes the helper, and with it the
one-call site creation: the commands come back as text, as before. Tested in
`tests/provision.sh` (root devbox): the one-call path and each refusal.

## Deferred, and why it is acceptable for the alpha

- `agensio -t` isolation warning (a pool or origin running as the server's own user or
  in the admin group): the rule is documented in section 15 and `health_check` reports
  application sites sharing the server's account; the load-time warning follows.
- Loopback TCP, token, mutual TLS: not needed for the SSH workflow the alpha targets.
- `cache/purge`: waits for the cache invalidation API.

## Sanitizer and fuzz record

2026-09-19, the run that closed F7: `fuzz_json` 5.83 M runs in 121 s (`-max_len=4096`),
no finding. Unit, integration, root-role, reload and Pebble suites under
`-fsanitize=address,undefined`: one finding, a use-after-free at shutdown in the ACME
manager's second `stop()` (timer cancelled after its io_context was destroyed), fixed;
all suites clean afterwards. Repeat both before every tag:

```
cmake -B build-san -DAGENSIO_SANITIZE=address,undefined -DAGENSIO_TESTS=ON && cmake --build build-san
build-san/agensio_tests && tests/integration.sh build-san/agensio && tests/acme.sh build-san/agensio
cmake -B build-fuzz -DAGENSIO_FUZZ=ON -DAGENSIO_TESTS=OFF -DAGENSIO_TLS=OFF -DCMAKE_CXX_COMPILER=clang++
cmake --build build-fuzz --target fuzz_json && build-fuzz/fuzz_json tests/fuzz/regressions/json -max_total_time=120
```
