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
| 11 | The API never executes a shell command; root work is returned as text; the one thing that runs programs for it, a site task (row 26), lives in `src/services/tasks.cpp` with a fixed argv and no shell | no `system`, `popen`, `exec*`, `fork`, `posix_spawn` under `src/control/` | `tests/integration.sh` static grep |
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
| 24 | A writer never answers ok to a state the validator refuses: `site-install`, `site-copy` and `site-task` create the preset's credential files (`preset_secrets`, the list the hosting rule reads) `0600`, take the group's read and write and everything for others from credential directories (`secret_dir_mode`; before 2026-09-26 a directory there failed the install), check hosting rule 3 on what they wrote as the writing account, and compare the configuration's validation errors before and after the call in the server; a new error answers `409` with `written: true` and the validator's words | `install::execute` / `copy_file` (`secured`), `secret_paths` and `secret_exposed` shared with `check_hosting`, `ControlHandler` `validation_errors` / `new_errors` | unit tests: secrets `0600` after an unwrap and below a plugin path, a copy onto a secret, the rule on Drupal's files, every preset's secrets among its never-served list; `tests/integration.sh` and `tests/install.sh`: `wp-config.php` `0600` after install and copy, `validate` ok |
| 25 | Per-site settings are an allowlist of typed resource limits (`control/settings.cpp`, one table for what is accepted, what is advertised and the MCP schema), each moving only within the ceiling `[control] site_limits` sets, which only the root-owned file changes; no ini map, no `open_basedir`, no path, no key that changes what a site may reach or run: `extra`, `sendmail_path`, `auto_prepend_file`, `extension`, `disable_functions` and every other name are refused as unknown | `control::apply_settings`, `settings_catalog`, `settings_schema` in the bridge | unit tests: every dangerous name refused, ceilings and minimums, enum, sizes; `tests/integration.sh`: the same through the socket, and a check that the schema, the catalogue and what `site_update` accepts are one set |
| 26 | A site task (F13) is a row of a table, never a command line: the caller names a task of the site's preset and gives typed parameters, each checked against its row's pattern (no flag or option can be given, so `rails new -m URL` is not expressible); the argv the row builds is what runs, by `execve`, no shell. It runs as the site's account under the account rule of row 19 (the helper derives the site's app, directory and user from the configuration on disk; the server sends names and parameters), in the site's directory reached without following a symlink, with an environment built for it (nothing inherited; the account's gems isolated from the system's with `GEM_PATH = GEM_HOME`; the site's own variables of row 28 after agensio's, never replacing one, and shown in the answer by name only), stdin `/dev/null`, umask `027`, `RLIMIT_NPROC` (`task_limits.processes`), 4096 open files, no core files; `task_limits.timeout` then SIGTERM to the process group and SIGKILL ten seconds later; whatever the program leaves in its group is killed when it exits; output kept up to 1 MB (its first 256 KB and last 768 KB beyond that), the answer carrying a part of it and the whole readable by an admin in slices (`site_task_output`) until the site's next task or a restart, in the server's memory only; one task per site; the preset's credential files swept private and the configuration validated after every run (row 24); the audit log names the exact argv that ran, the account and the outcome | `services/tasks.*` (`check_params`, `build`, `run`, `sweep`, `execute`), helper op `task_run` (`provision::validate`, `task_run`, `ensure_home`), `ControlHandler::site_task` | unit tests: the table, every parameter refusal, the exact argv and environment of each row, the runner on real processes (environment, directory, umask, both streams, a timeout that kills a TERM-ignoring shell, a left-behind child, the output cap, an unexecutable program), the sweep (patterns, directories, a symlink not followed), `execute`'s refusals, the helper's validation; `tests/tasks.sh` (root devbox, fake interpreters): argv, account, directory, environment without the server's, umask, limits, the sweep, one task per site, the time limit, nothing left running, refusals, audit lines; `tests/integration.sh` task checks; `tests/rails.sh` (real Ruby, rubygems.org): the whole Rails workflow behind agensio |
| 27 | An interpreter is root's decision alone: `[control] runtimes` names its directory and lives in root's main file only (an included file carries sites alone; the helper reads the key from that file for every task, so a reload applies it); before every run the configured program, the file it resolves to and every directory above both must belong to root and be writable by nobody else, the file regular and executable and outside `sites_root`; anything else is refused naming the component, so no site account, and not the server, can choose what runs. The resolved path is what is executed, so no name can be swapped between the check and `execve`. A Django row (2026-09-28) runs that same checked file under another name, `argv[0]` = the site's virtualenv's `bin/python`, which is how Python finds the virtualenv (`pyvenv.cfg` beside the name): the executed program stays root's, the packages it loads are the site's own, as a Gemfile's gems are; the virtualenv and its `pyvenv.cfg` are the account's, so the account can point Python at other code, which is the account running its own code as itself, what every task does by design (a Gemfile, `requirements.txt`, `manage.py`). The answer and the audit line name both the program and the name (`/usr/bin/python3.13 as <venv>/bin/python -m pip ...`). `venv_create` is refused before it runs when the interpreter has no `ensurepip` (Debian without `python3-venv`), with the package command. A Node row (2026-09-28) runs `npm` from `runtimes.node`: Debian's is a root-owned script whose `#!/usr/bin/env node` finds the runtime's `node` first on the task's `PATH`, which agensio builds |  `tasks::trusted_program`, `tasks::venv_support`, `Row::argv0`, `Plan::exec`, the `[control] runtimes` parser (absolute, not below `sites_root`) | unit tests (a file under a world-writable directory, a symlink in a directory someone else owns, below `sites_root`, a relative path, a missing file; the plan of a Django row: the executed file and the name; the ensurepip check on a laid-out prefix); `tests/tasks.sh` (a group-writable runtime directory, a runtime file owned by `nobody`; a fake Python 3.13: venv_create refused without ensurepip, the program and the name in the answer and the audit line); `tests/integration.sh` (a runtime directory the test's account owns is refused, dry run or not) |
| 28 | A site's environment (the variables its tasks and its application service get: `SECRET_KEY_BASE`, `DATABASE_URL`) is one file per site, `<config dir>/env/<site>.env`, root's `0600` in a directory root owns alone (`0700`), written and read by the helper only (`env_write`, `env_read`), for a site of the configuration on disk with `app = "rails"` or `"proxy"`, the file named by its first host name; systemd reads it as root for the application's unit, so no file the site's account could replace or link is ever read. Every open is `O_NOFOLLOW`, owner and mode are checked on the directory and the file before a byte is read (the file: regular, one link, writable by root alone; a root-owned directory open to others, or a file others could only read, is tightened and said under `tightened`; anything else refused with the `chown`/`chmod` line), a write goes to a temporary name, is synced and renamed; health reports `site_env_unsafe` for the directory (its own `lstat`) and each file, through the helper's read-only `env_check` (owner, mode, links, parse; no value leaves the helper; asked without waiting, so a running task only makes health say `site_env_unchecked`), and a deleted site's file as `site_env_orphan`; a file others can read is a warning with the advice to rotate when the directory is open to others too (it may have leaked), info when the directory is root's alone; whatever closes an open directory makes every file in it that others could read 0600 in the same pass and records its variables in `env/.exposed` (site, name, fingerprint, time; root's 0600, never a value), and health warns for that site until each value has changed. Names: upper-case, never one agensio sets for a task or one that chooses or loads a program (`PATH`, `HOME`, `RAILS_ENV`, `GEM_*`, `BUNDLE_*` but a gem source's credentials, `LD_*`, `DYLD_*`, `RUBYOPT`, `NODE_OPTIONS`, `PYTHON*`, `PIP_*` (pip's index is where code comes from), `NPM_CONFIG_*` (npm's registry, cache and script shell), `VIRTUAL_ENV`, `DJANGO_SETTINGS_MODULE`, `AGENSIO_*` (what agensio tells a Django site about itself), `GIT_*`, `BASH_ENV`, ...), refused when written and when read; on a Node site also `HOST`, `PORT` and `NODE_ENV`, which its unit sets and an environment file would override (systemd lets `EnvironmentFile=` win over `Environment=`), so the application stays bound to its upstream's loopback address; values one line of UTF-8, 4 KB; 128 variables. `generate` draws 64 bytes from `getentropy` and never replaces a value. Admin only both ways. A read answers names, lengths and fingerprints (HMAC-SHA256 under `env/.fingerprint.key`, root's, made on first use, so a fingerprint neither shows a value nor lets a weak one be found with a dictionary) and a value only for the names in `reveal` (the owner's decision of 2026-09-27: a value returned is in the agent's context and transcript), audited as REVEALED; a write is audited with the names it changed; no value is ever in the audit log | `services/appenv.*` (`check_name`, `check_value`, `parse`, `render`, `read`, `apply`, `parse_change`), helper ops `env_read` / `env_write` (`provision::validate`, `env_op`), `ControlHandler::site_env_show` / `site_env_set`, the task's environment (`tasks::build`, `task_run`) | unit tests: names, values, render and parse round trip, systemd's hand-written forms, the change request, the files as the test's account (modes, a group-readable file, a symlink, a reserved name in the file, a group-readable directory, a site name with `..`), the helper's validation; `tests/tasks.sh` (root devbox): the file root's `0600` in root's `0700`, no value in the answer or the audit log, the task gets it, the admin's read audited, rotation, a refused name, a file others can read stops the task, an archive install without credentials generates `SECRET_KEY_BASE`; `tests/control.sh`: a viewer and an operator get 403; `tests/integration.sh` without the helper |
| 29 | Template tasks and the rendered unit add no way to run a program or write a file of the caller's choosing. A template row (`database_config`, `gemfile_local`) has no program and no argv: it writes one fixed text, compiled into agensio, to one fixed path below the site's directory, as the site's account through the task machinery of row 26 (the helper derives site, app and account from the configuration on disk), every directory on the way opened without following a symlink and required to be the account's, the file created with `O_EXCL` (never replaced; since 0.1.0-alpha.36 `django_settings` alone replaces a file that is still agensio's own earlier version, a regular file of the account with one link that starts with `# Written by agensio (site task django_settings)`: the new text goes to a new name with `O_EXCL | O_NOFOLLOW` and is renamed over the old one, which is kept as `.bak`, so a link planted meanwhile is replaced, never followed), `database.yml` `0600` and swept; its only input is whether the site's environment holds `DATABASE_URL`, whose value the template reads at run time, as the application would. The unit `site-unit` renders is text for root, never written by agensio: every value in it (the site's name, root, account, group, the runtime directory, the home, the environment file) must be a plain path or name, so no value can add a line; it runs Puma as the site's account, with `NoNewPrivileges` and the rest of the hardening, and refuses a site without its own account or with a non-loopback upstream. `load_default_data` takes one parameter, a language code checked against `^[a-z]{2}(-[A-Za-z]{2,4})?$`, passed as `REDMINE_LANG`. Django (2026-09-28): `django_settings` writes the fixed `agensio_settings.py`, which holds no secret and names no host: it reads the project's name, the site's names and the served paths from `AGENSIO_*` variables agensio sets (reserved, row 28) and the secret and a database from the site's environment. `createsuperuser` takes a username and an email checked against Django's own rules (never starting with `-`, passed as `--username=VALUE`) and reads the password from `DJANGO_SUPERUSER_PASSWORD` in the site's environment, never from the caller. The Gunicorn unit runs root's `python3` under the virtualenv's name (systemd's `ExecStart=@`), the project's package checked as a package name and the site's names as host names before they reach a line, and carries `UnsetEnvironment=` for the three `DJANGO_SUPERUSER_*` names, so the application never holds the admin's password | `tasks::write_template`, the rows, `control::service_unit`, `ControlHandler` (`/unit`), `check_project_name`, `app_context` | unit tests (the rows' shape, the renderer's text and each refusal, a root with a newline), `tests/tasks.sh` (the template written as the account, `0600`, never replacing, refused without `DATABASE_URL`, the audit line; the unit; a parameter that is not a language), `tests/redmine-install.sh` (Redmine 7.0.1 through the control plane, Puma started from the rendered unit) |
| 30 | The application service is visible, not steerable: `site_service_status` and `site_service_logs` read the unit of a Rails, Django or Node site with its own account through the helper (`app_status`, `app_logs`; health's `app_check`). The call names a site; the helper finds it in the configuration on disk, requires a Rails preset and a valid account, and derives the unit's name from that account, so no call can name another unit. `systemctl show` gets a fixed property list, `journalctl` fixed options with a line count (1 to 1000) and a `since` (digits and one of `smhd`) that both the server and the helper check; both by absolute path, no shell, a fixed environment, their output capped (the journal's newest 256 KB) and cleaned of control characters. The state is a viewer's (what `health` shows anyway); the journal is admin only and every read is audited with the line count, since an application may log what it should not. No operation starts, stops or restarts a unit: that stays root's (the owner's decision of 2026-09-27), and the answers carry the root line instead. Health asks without waiting, so a running task only makes it silent about services | helper ops `app_status`, `app_logs`, `app_check` (`provision::validate`, `app_op`, `app_check`, `unit_states`), `ControlHandler::site_service`, `control::service_findings` | unit tests (the helper's validation of every argument, the findings of each state, a busy helper), `tests/tasks.sh` (root devbox, fake `systemctl` and `journalctl`: the exact argv, the unit from the account, running / failed / missing with their next steps and health findings, one `systemctl show` for all sites, the journal read audited, out-of-range arguments refused), `tests/control.sh` (a viewer and an operator get 403 for the journal and a task's output), `tests/integration.sh` (a site without its own account has no service) |
| 31 | A Django site (`app = "django"`, `"wagtail"`, 2026-09-28) is the first preset that serves files from the project directory and proxies the rest: only `/static/` and `/media/` are answered from disk, each refusing dot segments, symlinks that leave the project, and the endings `.py`, `.pyc`, `.pyo`, the SQLite files, `.log`, `.key`, `.sql`, `.env`; a missing file there is a 404, never the application's. Uploads are the visitors' and editors' files on the site's origin: `/media/` answers with `X-Content-Type-Options: nosniff` and `Content-Security-Policy: script-src 'none'; form-action 'none'; base-uri 'none'`, so an uploaded HTML or SVG page runs no script and posts no form (not `sandbox`, which a browser's PDF viewer refuses). Wagtail's `/media/documents/` is refused whole: its documents go through Wagtail's view, which enforces a collection's privacy. `/manage.py`, `/agensio_settings.py`, `/requirements.txt`, `/db.sqlite3`, `/.env`, `/.git/` are 404 at the edge. The settings agensio writes trust `X-Forwarded-Proto` for `https`, which is safe because agensio replaces the field a client sends, and make the session and CSRF cookies https-only on a TLS site. A hand-written location that sets only `add_headers` joins the preset's location at its path (since 0.1.0-alpha.36): before, the `/` location a managed site file carries for `hsts` replaced a proxy preset's `/`, so a `rails`, `redmine`, `django` or `wagtail` site with `hsts` served its project directory from disk, source files included, and never reached the application | `apply_preset` (the python branch), `kDjangoRefused`, `kDjangoRefusedEndings` | unit tests (the locations, their headers and endings, the refusals), `tests/tasks.sh` (the files served from disk as the server's account, the headers, the 404s, the rest to the upstream), `tests/wagtail-install.sh` (Wagtail 8.0 with real pip and Gunicorn: the stylesheet from disk, the admin's login past Django's CSRF check over https, the documents refused) |
| 32 | A task whose caller names what gets installed runs only on the user's own confirmation (`pip_install`, 2026-09-28, the owner's decision: any package the site's account may install, but never on an agent's word). Its value can only be requirement specifiers (a name, extras, version clauses; no URL, path, marker, option or whitespace inside one), passed to pip after `--`, one argument each, as the site's account with row 26's bounds. The control API refuses it (428, with the warning and the terminal command) unless the body says how the user confirmed: `user_confirmed: "mcp"`, which the bridge sets only after the user ticked "Install these packages" in the MCP client's own dialog (MCP elicitation, which the model neither sees nor answers), or `"terminal"`, which `agensio ctl` sets after printing the warning, the `--yes` the user typed being the confirmation. The bridge drops an agent's own `user_confirmed` or `client` argument, refuses when the client cannot show the dialog or the user declines, and hands back the `ctl` command; the audit line says which confirmation it was and in which client. The binding holds while the bridge is the agent's only way to the socket: an agent with a shell as the same account could call the socket itself, so the agent's SSH key is limited to `command="agensio mcp"` (docs/mcp.md). A dry run needs no confirmation; `pip_install_requirements` needs none, the project's own file naming the packages | `tasks::Row::user_confirm`, `tasks::requirements`, `tasks::confirmation_warning`, `ControlHandler::site_task`, the bridge's `ask_user`, `agensio ctl site-task` | unit tests (every accepted and refused shape of a specifier, the argv after `--`, the warning), `tests/integration.sh` (a scripted MCP client: no dialog support, a decline, an unticked box and an agent's `user_confirmed` all refused with the terminal command; an accept runs, recorded as the dialog's; a request arriving during the dialog is answered after it; the control API's 428), `tests/tasks.sh` (the 428 with the warning, an option or URL refused by shape, ctl's warning and the terminal confirmation in the audit log), `tests/wagtail-install.sh` |
| 33 | A Node site (`app = "node"`, 2026-09-28) forwards every request to its application and answers a few paths and endings itself with a 404, never forwarded: `/.env`, `/.git/`, `/.npmrc`, `/node_modules/`, `/package.json`, `/package-lock.json`, `/npm-shrinkwrap.json`, `/yarn.lock`, `/pnpm-lock.yaml`, and databases, logs, keys and dumps by their ending wherever they are (Uptime Kuma keeps `kuma.db` in `data/`). Its tasks are rows like row 26's: `npm_ci` installs exactly what the application's `package-lock.json` pins, integrity hashes included, and `npm_run` runs one script of the project's own `package.json` by a name checked as a name (never an option); both run the project's code as the site's account, as a Gemfile or `manage.py` does, with npm's cache and user configuration in the account's own home and `NPM_CONFIG_*` refused in the site's environment. The rendered unit runs root's `node` on `entry`, a path inside the project checked as a plain relative `.js`, `.mjs` or `.cjs` file (no `..`, no segment starting with a dot), bound to the upstream's loopback address through `HOST` and `PORT`, which the site's environment cannot override (row 28) | `kNodeRefused`, `kNodeRefusedEndings`, the node rows and family (`tasks.cpp`), `check_entry`, `control::service_unit`, `appenv::check_change_for_app` | unit tests (the locations and endings, the rows' argv and environment, a script name that looks like an option, `entry`'s refusals, the unit's text, the reserved names), `tests/tasks.sh` (a fake node and npm: the account, the cache in its home, the refusals, the unit, the edge), `tests/integration.sh` (without the helper), `tests/kuma-install.sh` (Uptime Kuma 2.5.5 with Debian's node and npm: npm ci from the lockfile, its frontend, node on loopback from the rendered unit, its pages, socket.io polling and WebSocket through agensio over TLS, the project's files refused) |
| 34 | A site deleted with its files (F12b, 2026-09-30) goes into `<sites_root>/.trash/<domain>-<stamp>/`, opened and created by the helper as a directory that is root's alone (`0700`, never through a symlink, tightened when found wider), so no account and not the server can read another tenant's deleted files. The server sends a site's name; the helper finds the site in the configuration on disk and derives every path from it (the tree below `sites_root`, refused when the root is not below it; the account's state directory only when no other site uses the account; the log only below the logs directory; the environment file only under the environment directory), and refuses while the site's unit is active (`systemctl show`), since a renamed working directory keeps a running process writing into the trash. Every piece moves by `rename` (a small file on another filesystem is copied without following symlinks, a directory goes to a trash beside its own base, `<state_dir>/.trash/<entry>`); a failure puts back what moved. The manifest names the pieces and their origins; a restore or a removal trusts only paths under the entry's own directory or that entry's side trash, never anything else the manifest could name. Removal walks with `openat` and `O_NOFOLLOW`, entering each directory through its own descriptor, never leaving the entry, unlinking symlinks as entries. Restore moves pieces back only where nothing stands (a missing path or an empty directory), refuses when the site exists again or its file is there, and only when the account exists with the uid the files carry (the files' ownership is never changed); the site file is written from the manifest with `O_EXCL`, owned as its directory is. Entry names are validated everywhere (`valid_trash_entry`: a host name and a stamp; no `/`, no `..`); the account is never removed. Admin only, every operation audited with the paths moved; the trash keeps `[control] trash_keep` days (from root's file, applied to what is in the trash) and expires hourly on worker 0 through `try_request`, so a running task only delays it. The registry of log sinks opens and reopens only the files the configuration names (`LogRegistry::unmark_all`), so a deleted site's log is not recreated empty at each reload | `provision::site_trash`, `site_restore`, `trash_list`, `trash_delete`, `trash_expire`, `remove_tree`, `open_private_dir`, `move_path`, `valid_trash_entry`, `site_tree`; `ControlHandler::site_trash` / `trash_restore` / `trash_delete` / `trash_list`; `Server::arm_trash_expiry` | unit tests (the entry-name rule, the helper's validation of every argument, the tree rule with a shared domain directory and a root outside `sites_root`, `trash_keep`'s bounds); `tests/trash.sh` (root devbox: two sites on one account, the refusal while the unit runs, every piece moved and the account's state kept while shared then taken whole, the trash unreadable to another tenant and to the server, the listing, restore refused into a non-empty place then done, a bad entry name, trash-delete, expiry by an aged manifest, the account kept, the plain delete unchanged); `tests/control.sh` (a viewer and an operator get 403); `tests/integration.sh` (without the helper: 409, the site stays) |
| 35 | An application's own server guidelines as a managed site's `rules` (2026-10-01, the Kanboard proposal): `private` paths, the `.php` files that run (`entry_points`), cached directories, a front controller. The control plane validates the object against the preset as it stands after the request (entry points and a front controller on PHP presets only, a cache on PHP and static sites only, the front controller one of the entry points, nothing under a private path, bounded counts, `/`-rooted plain paths without `..` or `//`, never `/` itself) and renders it into ordinary locations of the site file (`handler = "deny"`, `final`, a denying `.php` suffix location, `deny_suffixes` with every PHP ending and source backup on the cached directory), so a rule can only narrow what the bare preset serves and `--explain` shows exactly what the file does; the kept rules are checked again on every later change, so an `app` change they no longer fit is refused until they are cleared. The php preset itself refuses `.sqlite`, `.sqlite3`, `.db` and `/web.config` now, since Kanboard's `data/db.sqlite` was downloadable under it. The `.htaccess` files of an installed archive are read once, at install time, for one shape only (a whole-directory `Require all denied` or `Deny from all` outside `<Files>` blocks, in files up to 64 KB, three levels deep); the directories are reported as `facts.htaccess_denied` and the matching `private` rule suggested in the next steps, never applied by the server and never read when serving (an attacker who can write an `.htaccess` into the tree gains nothing) | `control::check_rules`, `render_site` (`rules_locations`), `apply_request`, `install::htaccess_denies_all`, `app_facts`, `kSourceBackups`, the php row of `kPhpPresets`, `parse_location` (`deny`) | unit tests (every accepted and refused rule shape, rendering and loading back, the router's answer for private, entry, other-PHP, cached and front-controller paths, the preset's new refusals, the `.htaccess` parser on Kanboard's two forms and on `<Files>` blocks and comments), `tests/integration.sh` (a php site with rules on the wire, the refusals, `site_show`, an app change the rules no longer fit), `tests/kanboard-install.sh` (root devbox with php-fpm: Kanboard 1.2.54 from GitHub, `htaccess_denied` and the suggestion, `app/Core/Base.php` running under the bare preset and 404 after `site-update` with the rules, the login page, jsonrpc, healthcheck, the cached assets, a nice URL, the database private) |
| 36 | Root additions (2026-10-02, design section 20): a file beside a managed site's file, `sites.d/<domain>.root.toml`, with a top-level `site = "<domain>"` and `[[location]]` tables, gives root the whole location grammar on a site the control plane manages, which never writes or reads it. The loader accepts it only as a regular file (no symlink) owned by the owner of the main configuration file and writable by nobody else, so the server's account, which writes the managed files, and the admin role, which writes only rendered content through the handler, cannot make one; a lax file refuses the load with the line to run. Its locations are hand-written locations: they win over the preset's at their path, and a path the managed file already has is a duplicate the reload refuses, so a later `site_update` that would collide is undone with the file named. A file whose site is gone is kept and ignored with a warning (health `root_additions_orphan`), never an error, so disabling or deleting a site cannot break a reload. The trash moves the file with the site (piece `root`, beside the site file only) and restore puts it back root-owned by rename; a plain delete renames it `.bak` beside the site file's `.bak` (a rename, so still root's; put back when the reload refuses) and names it in the answer and the audit line. `site_show` names the file and what it added; the MCP texts send an agent asked for what no field covers to that file, never to the managed one | `RootAdditions`, `check_additions_file`, `parse_root_additions`, `parse_site` (the merge), `Config::orphan_additions`, `ControlHandler` site_show, health `root_additions_orphan`, `provision::site_trash` | unit tests (merge and origin, a headers-only addition joining the preset's location, one replacing it, the duplicate, every refused file shape: a foreign key, no site, a symlink, a group-writable file; an orphan kept), `tests/integration.sh` (a managed site extended on the wire, `site_show` before and after, `--explain`, `site_update` still working, a rule at an added path refused naming the file, a writable file refused, the orphan after `site-disable`), `tests/trash.sh` (a file owned by the tenant refused with the rule; root's moved with the site and restored) |
| 37 | Host protection (2026-10-02, `docs/configuration.md` 18): agensio renders the firewall ruleset and the fail2ban jails for its host and reads back what is in place, but applies nothing. The ruleset is a table of its own (`inet agensio`) over the host's public ports, so it can neither cut root off (SSH and every other port are not its business, no policy is set) nor disturb a panel's or the distribution's rules, and root applies it commit-confirmed (a trial with a timer that removes it, then the keep step). Every value rendered into a file is a port number from the configuration, a log path from the configuration, or a login path `check_login_path` accepted (plain characters, `/`-rooted, no `..`, an optional query of letters, digits and `._~/=&+:-` with no `%`, quotes or spaces, rendered into the jail as a regex of every spelling with `%` written `\x25` and every metacharacter escaped), so no caller can put a line into the ruleset or the jail or reach configparser's interpolation. The check is the helper's `host_protection`: read-only, no argument, four programs by absolute path with fixed arguments (`nft -j list ruleset`, `systemctl show` of six named units, `fail2ban-client status` and `status <jail>` for the jail names fail2ban itself listed, plain names of up to 64 characters, at most 64, and `journalctl` for one line of each failure jail that reads the journal, its match words of three field names and plain values built from the configuration on disk), the answers raw and read by the server. A failure jail that reads the journal matches each site account's `_UID`, a field journald sets from the sender's credentials, with the php-fpm unit or Drupal's identity, never `SYSLOG_IDENTIFIER` alone, which any local process can claim (alpha.49 report: forged lines from any account would have banned any address); a site without an account of its own is listed as not read. `login_paths` on a site (control plane or file) is data for the jail: nothing is served, refused or executed by it. `[control] host_protection` is root's. | `control/protection.*` (`protection_input`, `render_nft`, `render_jail`, `read_probe`, `protection_findings`), `config.cpp` (`check_login_path`, `login_paths`, `host_protection`), `provision.cpp` (`host_protection`), `handler.cpp` `/v1/protection` (viewer) | `tests/tests.cpp` (`test_protection`: the input from a configuration, the shipped files held to the renderers, nft's JSON with a foreign table's named set, the unit states, fail2ban's status, every finding state), `tests/integration.sh` (rendered on a loopback host, nothing exposed; the packaged copies; `login_paths` through the API and the command line, a bad path refused), `tests/protection.sh` (root, the real nft and fail2ban: both missing, the ruleset loaded twice and seen, four jails over the site's log, a loopback address banned after eleven POSTs and the site refusing it, a site added later making the table and the jail stale, two sites on accounts of their own and one without, the journal asked under the accounts' uids, empty and then answering one line through a stand-in journalctl, `external` and `off`) |
| 38 | Access by client address (2026-10-07, `docs/configuration.md` 19, design section 22): a managed site's `rules.restricted` becomes `[[site.access]]` tables through the admin-only `site_update`, like every rule, and only narrows the site: a rule is an allow list, never a deny list, and an empty list, an unknown key, an unknown `@set`, a zone id or an unnormalised path is refused by `check_rules` and again by the loader at reload. The address sets are root's, in the main file (`[addresses]`), so the control plane can name them but never change them. `access_check` (viewer) is a pure function over the running configuration that parses one path and one address and opens nothing. The check runs before routing on the normalised path and on the other ways an origin may read it (a `;` segment parameter, a second decoding, the path after a script), so neither a `.php` suffix location nor a proxied application's own path rules step around it; the address is the peer or, behind `trusted_proxies`, the rightmost untrusted `X-Forwarded-For` hop across every line (the three client-address bugs fixed the same day). The refusal names only the address the server saw; the error log line is rate-limited to one a second per worker, report mode to each rule and client once a minute and 16 new lines a second, the rest counted (alpha.53). `rules.admin` (alpha.53, design section 23) is the same allow list over the preset's administration paths, rendered by the same code; it is never set by default (an admin stays reachable until its owner restricts it), and the openings the WordPress preset keeps under a `/wp-admin` rule (`admin-ajax.php`, the login page's `css/`, `js/`, `images/`) are shields where no script runs, so a rule never reopens PHP. | `core/access.hpp`, `handlers/dispatch.cpp` (`admit`, `access_log_tick`), `config.cpp` (`parse_access`, `[addresses]`, `preset_admin_paths`), `control/sites.cpp` (`check_rules`, `admin_rules`), `control/commands.cpp` (`access_check`) | unit `test_access_rules`; integration `access:` and `mcp: access_check` checks |
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
- **Vocabulary.** Eleven requests, each validated again inside the helper against the
  configuration it started with (`provision::validate`, unit tested): `account_add`
  (name by the account rule, no system accounts, no words for "none"; `useradd --system
  --no-create-home`, home in `state_dir`, `nologin`), `site_layout` (a normalised
  absolute path strictly below `sites_root`; owner must be a site account, i.e. `nologin`
  with its home in `state_dir`; the walk uses `openat(O_NOFOLLOW)` so a planted symlink is
  refused; a directory owned by anyone but root, the server or that owner is refused, so
  no site is ever handed over to another), `log_own` (a `.log` below the log directory,
  `agensio:<group> 0640`, `O_NOFOLLOW`), `pools_apply` (re-reads the configuration
  itself, runs the hosting rules, writes the pool files, reloads php-fpm),
  `service_restart` (once a minute at most), `task_run` (F13: a site's name, a task's name
  and short string parameters, nothing else; the helper loads the configuration from disk,
  finds the site, its app, directory and user, takes the command from the task table, the
  interpreter from `[control] runtimes` and the bounds from `task_limits` of that same
  root-owned file, the site's environment from its root file (row 28), creates the account's home `<state_dir>/<account>` `0700` when missing
  (never handing over a directory it did not create), and runs `tasks::execute` in a child
  that has become the account, row 26), and `app_install` (F9: a target strictly
  below `sites_root`, one source that is an https URL or a plain upload name, the
  account rule of row 19; a forked child becomes that account with `setgroups`,
  `setgid`, `setuid` and a check that root cannot be regained, then downloads or reads
  the upload, verifies the digest and unpacks with the fences of rows 20 and 21; the
  helper waits with a 20-minute deadline), and `file_copy` (F9b: the same account rule
  and child, one regular file of the site to another path of the same site, row 23;
  narrower than `app_install` in every way), `env_read` and `env_write` (a site's name
  and, for a write, names and one-line values the rules of row 28 accept; the helper finds
  the site on disk and reads or writes its root file), and `env_check` (no argument: the
  read-only pass health asks for, over the sites the configuration on disk names; findings
  and file names only), `app_status` and `app_logs` (a site's name, for the journal a
  line count of 1 to 1000 and a `since` of up to four digits and one of `smhd`; the helper
  derives the unit `agensio-app-<account>.service` from the site's account on disk and
  runs `systemctl show` or `journalctl -u` read-only, row 30), `app_check` (no
  argument: one `systemctl show` over every such unit, for health), and the trash's five
  (row 34): `site_trash` (a site's name; the helper finds the site on disk and derives every
  path from it), `site_restore` and `trash_delete` (an entry's name of the form
  `<domain>-<date>-<time>`, nothing else), `trash_list` and `trash_expire` (no argument), and
  `host_protection` (row 37, no argument: `nft -j list ruleset`, `systemctl show` of six named
  units, `fail2ban-client status` and `status <jail>` for the names fail2ban listed, and
  `journalctl -q -n 1 -o cat --since=-30d` with the match words of each failure jail that
  reads the journal (`_UID=` and digits, `_SYSTEMD_UNIT=` or `SYSLOG_IDENTIFIER=` with a
  value of letters, digits, `.`, `-`, `(`, `)` and `@`, and `+`), built from the
  configuration on disk and never from the request; read-only, the answers raw for the
  server to read).
- **Execution.** `useradd`, `groupadd`, `systemctl`, `journalctl`, `nft` and `fail2ban-client` by absolute path, fixed argument
  list, empty environment. No shell, ever. Nothing the server sends can name a program.
- **Audit.** Every request and every refusal is written to the audit log with the
  control-socket peer's uid and the reason of the command that caused it.

What a fully compromised server process gains: it can create `nologin` system accounts
without a home, lay out directories under `sites_root` for such accounts, regenerate pool
files the hosting rules accept, restart the service (rate-limited), have an archive
of its choosing unpacked, as a site account, into an empty directory that account owns
under `sites_root` (regular files and directories only, no symlinks, no set-uid, no
program run), have one of a site's files copied to another path of the same site as
that account, and have one of the task table's fixed commands run as a site account in
that site's directory (for a Rails site that runs the site's own code, the Gemfile and
`bin/rails`, as the site's account: the capability the site's application has anyway,
and for a PHP site an archive install already gave), and read or change the environment
file of a Rails or proxy site (its secrets: what an admin may read by the owner's decision,
and what the application's own account has in its process anyway; never a name that
chooses a program). What it cannot do: obtain a shell or
run any program as root, run a command that is not a row of the task table, choose the
interpreter, read or write outside `sites_root`, `state_dir`, the pool directory and the
log directory, take over a directory of another site, write as root or as any login
account, or touch an account that has a login shell. That exposure is smaller than php-fpm's root master on the same
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

2026-10-07, the security audit's campaign (`docs/security-audit-2026-10-07.md`), the first
with the targets' assertions compiled in (every fuzz build before defined `NDEBUG`, so the
recorded runs above checked memory safety only): every target five minutes on its corpus
through `scripts/fuzz-all.sh`, ASan and UBSan, clang 19.

| target | runs | edges | result |
|---|---|---|---|
| fuzz_parser | 7.95 M | 286 | clean |
| fuzz_chunked | 35.56 M | 72 | clean |
| fuzz_fcgi | 9.43 M | 133 | clean |
| fuzz_http_head | 121.13 M | 195 | clean |
| fuzz_path | 16.51 M | 297 | clean |
| fuzz_json | 16.61 M | 646 | one finding before the fix, clean after (below) |
| fuzz_archive | 20.56 M | 808 | clean |
| fuzz_hpack | 0.60 M | 709 | clean |
| fuzz_hpack_roundtrip | 0.48 M | 601 | clean |
| fuzz_qpack | 11.93 M | 859 | clean |
| fuzz_quic_packet | 5.50 M | 192 | clean |
| fuzz_transport_params | 276.69 M | 185 | clean |
| fuzz_quic_conn | 0.84 M | 2,346 | clean |

The finding: a number literal whose exponent overflows a double parsed to infinity and was
written back as `inf`, and a whole number above 2^63 was converted to `long long` (UBSan,
undefined behaviour); fixed in `services/json.hpp`, the input kept as
`tests/fuzz/regressions/json/overflow-exponent`. The first pass ran all thirteen targets at
once next to an eight-job sanitizer build, and seven reported timeouts after 11 to 22
seconds on inputs that replay in under 5 ms; rerun alone they were clean (the counts above).
Rule: the campaign runs on an otherwise idle machine. The sanitizer build passed the unit
tests, the integration suite (588 checks, the server's stderr empty) and the reload suite
(20); the ACME suite was not run (it needs Pebble through `docker compose`). Two suite
defects were found on the way, both hidden by the Release build: two sites the SNI and
authority checks need were defined only when the binary had the HttpArena handler, and four
checks piped `agensio ctl protection` into `grep -q`, which fails under pipefail when the
writer is slower than grep (the sanitizer build's `ctl` lost to SIGPIPE every time).

2026-09-25, the QPACK encoder, `alt-svc`, reload and connection-fuzzer step:
`fuzz_quic_conn` (design 9.2: a connection established by a fuzz-build hook, the
fuzzer's frames sealed with its keys, the timers stepped) 431 k runs in 120 s on its
first day, which found an ACK delay field that overflowed the clock's arithmetic on its
way to a duration (bounded now), then 213 k runs in 61 s on the tree with the
`alt-svc` fast paths with no finding (corpus 861 inputs, 2,321 edges); `fuzz_hpack` 1.13 M runs in 61 s (473 inputs,
708 edges) after the encoder's `alt-svc` memo; `fuzz_qpack` 5.44 M runs in 91 s feeding
the encoder's decoder-stream parser too. The release and sanitizer builds ran the
integration suite (534 checks) and the twenty-one-row attack suite (the reload row
included) with no report, the reload suite 18 checks, and the sanitizer build served
h2load over QUIC (one and sixty-four streams, 2.5 M requests) clean.

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
all suites clean afterwards. Repeat both before every tag, every fuzzer since 2026-10-07
(the security audit found tags alpha.45 to alpha.50 shipped with no recorded run, and the
list named two of the thirteen targets):

```
cmake -B build-san -DAGENSIO_SANITIZE=address,undefined -DAGENSIO_TESTS=ON && cmake --build build-san
build-san/agensio_tests && tests/integration.sh build-san/agensio && tests/acme.sh build-san/agensio
scripts/fuzz-all.sh -t 300      # every target, five minutes each on its corpus; the table goes below
```

`scripts/fuzz-all.sh` configures `build-fuzz-all` with clang++ and TLS on, so `fuzz_quic_conn`
is built where OpenSSL has the QUIC API (3.5, the devbox); new inputs go to a scratch
corpus under `bench/tmp/`, and an input worth keeping is copied into
`tests/fuzz/regressions/<target>/` by hand. The weekly CI job (`.github/workflows/fuzz.yml`)
runs the same script and the sanitizer build on Ubuntu 24.04, without `fuzz_quic_conn`.


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
aioquic is installed) asserts twenty-one rows of the design's table against the release and
sanitizer builds: the handshake, Retry in both modes, a garbage token, a key update and a
second one before the first is acknowledged, a client that changes its port, retired ids,
a stateless reset, 3,000 forged packets on a live id, 200 stream resets in a second, 300
streams beyond the limit, a second SETTINGS, 1,500 Initials in a second, and, as raw
frames written into aioquic's packets, 101 credit updates that raise nothing, an
acknowledgement of a packet never sent, a fifth connection id, retiring an unissued and
the in-use id, data beyond a stream's window; a reload row rewrites the configuration
without h3 and sends SIGHUP, expecting GOAWAY and a close with H3_NO_ERROR on its open
connection and no QUIC server on the port after, then brings h3 back with another reload;
the last row opens a connection and sends the server SIGINT, expecting GOAWAY and a close
with H3_NO_ERROR at once. The loss proxy
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
