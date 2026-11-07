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
| 14 | Log queries read at most 2 MB per file from the end, return at most 5000 lines, and never follow user-supplied paths (files come from the configuration) | `control::LogQuery`, `scan_log`, `logs` | unit test of the byte cap and the limit; the line parser (`control/loglines.*`) fuzzed by `fuzz_log_line`, recorded below |
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
| 26 | A site task (F13) is a row of a table, never a command line: the caller names a task of the site's preset and gives typed parameters, each checked against its row's pattern (no flag or option can be given, so `rails new -m URL` is not expressible); the argv the row builds is what runs, by `execve`, no shell. It runs as the site's account under the account rule of row 19 (the helper derives the site's app, directory, user and, for a PHP site, the interpreter (its own version's command-line binary, under the same interpreter rule) from the configuration on disk; the server sends names and parameters), in the site's directory reached without following a symlink (Laravel's rows, 2026-11-04: the directory that holds `artisan`, from `served_dir` up to the project, chosen without following a symlink and opened again without following one, inside the site's directory by construction and checked so by the helper), with an environment built for it (nothing inherited; the account's gems isolated from the system's with `GEM_PATH = GEM_HOME`; the site's own variables of row 28 after agensio's, never replacing one, and shown in the answer by name only), stdin `/dev/null`, umask `027`, `RLIMIT_NPROC` (`task_limits.processes`), 4096 open files, no core files; `task_limits.timeout` then SIGTERM to the process group and SIGKILL ten seconds later; whatever the program leaves in its group is killed when it exits; output kept up to 1 MB (its first 256 KB and last 768 KB beyond that), the answer carrying a part of it and the whole readable by an admin in slices (`site_task_output`) until the site's next task or a restart, in the server's memory only; one task per site; the preset's credential files swept private and the configuration validated after every run (row 24); the audit log names the exact argv that ran, the account and the outcome | `services/tasks.*` (`check_params`, `build`, `run`, `sweep`, `execute`), helper op `task_run` (`provision::validate`, `task_run`, `ensure_home`), `ControlHandler::site_task` | unit tests: the table, every parameter refusal, the exact argv and environment of each row, the runner on real processes (environment, directory, umask, both streams, a timeout that kills a TERM-ignoring shell, a left-behind child, the output cap, an unexecutable program), the sweep (patterns, directories, a symlink not followed), `execute`'s refusals, the helper's validation; `tests/tasks.sh` (root devbox, fake interpreters): argv, account, directory, environment without the server's, umask, limits, the sweep, one task per site, the time limit, nothing left running, refusals, audit lines; `tests/integration.sh` task checks; `tests/rails.sh` (real Ruby, rubygems.org): the whole Rails workflow behind agensio |
| 27 | An interpreter is root's decision alone: `[control] runtimes` names its directory and lives in root's main file only (an included file carries sites alone; the helper reads the key from that file for every task, so a reload applies it); before every run the configured program, the file it resolves to and every directory above both must belong to root and be writable by nobody else, the file regular and executable and outside `sites_root`; anything else is refused naming the component, so no site account, and not the server, can choose what runs. The resolved path is what is executed, so no name can be swapped between the check and `execve`. A Django row (2026-09-28) runs that same checked file under another name, `argv[0]` = the site's virtualenv's `bin/python`, which is how Python finds the virtualenv (`pyvenv.cfg` beside the name): the executed program stays root's, the packages it loads are the site's own, as a Gemfile's gems are; the virtualenv and its `pyvenv.cfg` are the account's, so the account can point Python at other code, which is the account running its own code as itself, what every task does by design (a Gemfile, `requirements.txt`, `manage.py`). The answer and the audit line name both the program and the name (`/usr/bin/python3.13 as <venv>/bin/python -m pip ...`). `venv_create` is refused before it runs when the interpreter has no `ensurepip` (Debian without `python3-venv`), with the package command. A Node row (2026-09-28) runs `npm` from `runtimes.node`: Debian's is a root-owned script whose `#!/usr/bin/env node` finds the runtime's `node` first on the task's `PATH`, which agensio builds |  `tasks::trusted_program`, `tasks::venv_support`, `Row::argv0`, `Plan::exec`, the `[control] runtimes` parser (absolute, not below `sites_root`) | unit tests (a file under a world-writable directory, a symlink in a directory someone else owns, below `sites_root`, a relative path, a missing file; the plan of a Django row: the executed file and the name; the ensurepip check on a laid-out prefix); `tests/tasks.sh` (a group-writable runtime directory, a runtime file owned by `nobody`; a fake Python 3.13: venv_create refused without ensurepip, the program and the name in the answer and the audit line); `tests/integration.sh` (a runtime directory the test's account owns is refused, dry run or not) |
| 28 | A Laravel site's `.env` (2026-11-04, its `env_file`) is written and read the same way by the helper, which takes the site's name alone and finds the project, the file and the account on disk: below the project through directories opened without following a symlink, each the account's or root's and writable by no other, the file regular with one link, at most 64 KB, replaced by a temporary file renamed over it, root's with the group the site's pool runs as, `0640` (the application reads it, neither the account nor a compromised application changes it in place), names, lengths and fingerprints answered and a value only on a reveal, the change approved as below; the file is read as phpdotenv reads it (`services/dotenv`, fuzzed by `fuzz_dotenv`), every line a change does not touch kept, a file with a quote never closed refused whole (the lines after it belong to that value), and the change read back before it is written (until 0.1.0-alpha.125 an `unset` and `generate` of one name, the rotation the tools advise, removed it). A site's environment (the variables its tasks and its application service get: `SECRET_KEY_BASE`, `DATABASE_URL`) is one file per site, `<config dir>/env/<site>.env`, root's `0600` in a directory root owns alone (`0700`), written and read by the helper only (`env_write`, `env_read`), for a site of the configuration on disk with `app = "rails"` or `"proxy"`, the file named by its first host name; systemd reads it as root for the application's unit, so no file the site's account could replace or link is ever read. Every open is `O_NOFOLLOW`, owner and mode are checked on the directory and the file before a byte is read (the file: regular, one link, writable by root alone; a root-owned directory open to others, or a file others could only read, is tightened and said under `tightened`; anything else refused with the `chown`/`chmod` line), a write goes to a temporary name, is synced and renamed; health reports `site_env_unsafe` for the directory (its own `lstat`) and each file, through the helper's read-only `env_check` (owner, mode, links, parse; no value leaves the helper; asked without waiting, so a running task only makes health say `site_env_unchecked`), and a deleted site's file as `site_env_orphan`; a file others can read is a warning with the advice to rotate when the directory is open to others too (it may have leaked), info when the directory is root's alone; whatever closes an open directory makes every file in it that others could read 0600 in the same pass and records its variables in `env/.exposed` (site, name, fingerprint, time; root's 0600, never a value), and health warns for that site until each value has changed. Names: upper-case, never one agensio sets for a task or one that chooses or loads a program (`PATH`, `HOME`, `RAILS_ENV`, `GEM_*`, `BUNDLE_*` but a gem source's credentials, `LD_*`, `DYLD_*`, `RUBYOPT`, `NODE_OPTIONS`, `PYTHON*`, `PIP_*` (pip's index is where code comes from), `NPM_CONFIG_*` (npm's registry, cache and script shell), `VIRTUAL_ENV`, `DJANGO_SETTINGS_MODULE`, `AGENSIO_*` (what agensio tells a Django site about itself), `GIT_*`, `BASH_ENV`, ...), refused when written and when read; on a Node site also `HOST`, `PORT` and `NODE_ENV`, which its unit sets and an environment file would override (systemd lets `EnvironmentFile=` win over `Environment=`), so the application stays bound to its upstream's loopback address; values one line of UTF-8, 4 KB; 128 variables. `generate` draws 64 bytes from `getentropy` and never replaces a value. Admin only both ways. A read answers names, lengths and fingerprints (HMAC-SHA256 under `env/.fingerprint.key`, root's, made on first use, so a fingerprint neither shows a value nor lets a weak one be found with a dictionary) and a value only for the names in `reveal` (the owner's decision of 2026-09-27: a value returned is in the agent's context and transcript), audited as REVEALED; a write is audited with the names it changed; no value is ever in the audit log | `services/appenv.*` (`check_name`, `check_value`, `parse`, `render`, `read`, `apply`, `parse_change`), helper ops `env_read` / `env_write` (`provision::validate`, `env_op`), `ControlHandler::site_env_show` / `site_env_set`, the task's environment (`tasks::build`, `task_run`) | unit tests: names, values, render and parse round trip, systemd's hand-written forms, the change request, the files as the test's account (modes, a group-readable file, a symlink, a reserved name in the file, a group-readable directory, a site name with `..`), the helper's validation; `tests/tasks.sh` (root devbox): the file root's `0600` in root's `0700`, no value in the answer or the audit log, the task gets it, the admin's read audited, rotation, a refused name, a file others can read stops the task, an archive install without credentials generates `SECRET_KEY_BASE`; `tests/control.sh`: a viewer and an operator get 403; `tests/integration.sh` without the helper |
| 29 | Template tasks and the rendered unit add no way to run a program or write a file of the caller's choosing. A template row (`database_config`, `gemfile_local`) has no program and no argv: it writes one fixed text, compiled into agensio, to one fixed path below the site's directory, as the site's account through the task machinery of row 26 (the helper derives site, app and account from the configuration on disk), every directory on the way opened without following a symlink and required to be the account's, the file created with `O_EXCL` (never replaced; since 0.1.0-alpha.36 `django_settings` alone replaces a file that is still agensio's own earlier version, a regular file of the account with one link that starts with `# Written by agensio (site task django_settings)`: the new text goes to a new name with `O_EXCL | O_NOFOLLOW` and is renamed over the old one, which is kept as `.bak`, so a link planted meanwhile is replaced, never followed), `database.yml` `0600` and swept; its only input is whether the site's environment holds `DATABASE_URL`, whose value the template reads at run time, as the application would. The unit `site-unit` renders is text for root, never written by agensio: every value in it (the site's name, root, account, group, the runtime directory, the home, the environment file) must be a plain path or name, so no value can add a line; it runs Puma as the site's account, with `NoNewPrivileges` and the rest of the hardening, and refuses a site without its own account or with a non-loopback upstream. `load_default_data` takes one parameter, a language code checked against `^[a-z]{2}(-[A-Za-z]{2,4})?$`, passed as `REDMINE_LANG`. Django (2026-09-28): `django_settings` writes the fixed `agensio_settings.py`, which holds no secret and names no host: it reads the project's name, the site's names and the served paths from `AGENSIO_*` variables agensio sets (reserved, row 28) and the secret and a database from the site's environment. `createsuperuser` takes a username and an email checked against Django's own rules (never starting with `-`, passed as `--username=VALUE`) and reads the password from `DJANGO_SUPERUSER_PASSWORD` in the site's environment, never from the caller. The Gunicorn unit runs root's `python3` under the virtualenv's name (systemd's `ExecStart=@`), the project's package checked as a package name and the site's names as host names before they reach a line, and carries `UnsetEnvironment=` for the three `DJANGO_SUPERUSER_*` names, so the application never holds the admin's password | `tasks::write_template`, the rows, `control::service_unit`, `ControlHandler` (`/unit`), `check_project_name`, `app_context` | unit tests (the rows' shape, the renderer's text and each refusal, a root with a newline), `tests/tasks.sh` (the template written as the account, `0600`, never replacing, refused without `DATABASE_URL`, the audit line; the unit; a parameter that is not a language), `tests/redmine-install.sh` (Redmine 7.0.1 through the control plane, Puma started from the rendered unit) |
| 30 | The application service is visible, not steerable: `site_service_status` and `site_service_logs` read the unit of a Rails, Django or Node site with its own account through the helper (`app_status`, `app_logs`; health's `app_check`). A Laravel site's scheduler (2026-11-04) is rendered for root alone to install: its service runs `agensio ctl site-task NAME schedule_run --scheduled` as the server's own account, which holds no right of the site and only asks agensio, which runs the fixed row as the site's account (row 26); a scheduled run holds no task slot and is skipped while one runs; its status reads the two units and the cron files (the account's crontab, `/etc/crontab`, `/etc/cron.d`, regular files read without following a symlink, at most 64 KB each and 64 files) and names a cron line by file and line only, never its text, which may carry a secret. The call names a site; the helper finds it in the configuration on disk, requires a Rails preset and a valid account, and derives the unit's name from that account, so no call can name another unit. `systemctl show` gets a fixed property list, `journalctl` fixed options with a line count (1 to 1000) and a `since` (digits and one of `smhd`) that both the server and the helper check; both by absolute path, no shell, a fixed environment, their output capped (the journal's newest 256 KB) and cleaned of control characters. The state is a viewer's (what `health` shows anyway); the journal is admin only and every read is audited with the line count, since an application may log what it should not. No operation starts, stops or restarts a unit: that stays root's (the owner's decision of 2026-09-27), and the answers carry the root line instead. Health asks without waiting, so a running task only makes it silent about services | helper ops `app_status`, `app_logs`, `app_check` (`provision::validate`, `app_op`, `app_check`, `unit_states`), `ControlHandler::site_service`, `control::service_findings` | unit tests (the helper's validation of every argument, the findings of each state, a busy helper), `tests/tasks.sh` (root devbox, fake `systemctl` and `journalctl`: the exact argv, the unit from the account, running / failed / missing with their next steps and health findings, one `systemctl show` for all sites, the journal read audited, out-of-range arguments refused), `tests/control.sh` (a viewer and an operator get 403 for the journal and a task's output), `tests/integration.sh` (a site without its own account has no service) |
| 31 | A Django site (`app = "django"`, `"wagtail"`, 2026-09-28) is the first preset that serves files from the project directory and proxies the rest: only `/static/` and `/media/` are answered from disk, each refusing dot segments, symlinks that leave the project, and the endings `.py`, `.pyc`, `.pyo`, the SQLite files, `.log`, `.key`, `.sql`, `.env`; a missing file there is a 404, never the application's. Uploads are the visitors' and editors' files on the site's origin: `/media/` answers with `X-Content-Type-Options: nosniff` and `Content-Security-Policy: script-src 'none'; form-action 'none'; base-uri 'none'`, so an uploaded HTML or SVG page runs no script and posts no form (not `sandbox`, which a browser's PDF viewer refuses). Wagtail's `/media/documents/` is refused whole: its documents go through Wagtail's view, which enforces a collection's privacy. `/manage.py`, `/agensio_settings.py`, `/requirements.txt`, `/db.sqlite3`, `/.env`, `/.git/` are 404 at the edge. The settings agensio writes trust `X-Forwarded-Proto` for `https`, which is safe because agensio replaces the field a client sends, and make the session and CSRF cookies https-only on a TLS site. A hand-written location that sets only `add_headers` joins the preset's location at its path (since 0.1.0-alpha.36): before, the `/` location a managed site file carries for `hsts` replaced a proxy preset's `/`, so a `rails`, `redmine`, `django` or `wagtail` site with `hsts` served its project directory from disk, source files included, and never reached the application | `apply_preset` (the python branch), `kDjangoRefused`, `kDjangoRefusedEndings` | unit tests (the locations, their headers and endings, the refusals), `tests/tasks.sh` (the files served from disk as the server's account, the headers, the 404s, the rest to the upstream), `tests/wagtail-install.sh` (Wagtail 8.0 with real pip and Gunicorn: the stylesheet from disk, the admin's login past Django's CSRF check over https, the documents refused) |
| 32 | A task whose caller names what gets installed runs only on a person's approval with a code from their authenticator app (`pip_install`; the owner's decisions of 2026-09-28, any package the site's account may install but never on an agent's word, and of 2026-11-01, the code; row 50). Its value can only be requirement specifiers (a name, extras, version clauses; no URL, path, marker, option or whitespace inside one), passed to pip after `--`, one argument each, as the site's account with row 26's bounds. Until 0.1.0-alpha.120 the control API believed a `user_confirmed` field of the request, which the bridge set after its dialog and `ctl` after `--yes`, but which any process of the agent's account could send; that field means nothing now. A dry run is never held; `pip_install_requirements` is not held, the project's own file naming the packages | `tasks::Row::user_confirm`, `tasks::requirements`, `tasks::confirmation_warning`, `ControlHandler::site_task`, the gate of row 50 | unit tests (every accepted and refused shape of a specifier, the argv after `--`, the warning); `tests/integration.sh` (pip_install through MCP waits, a forged `user_confirmed` waits all the same, the right code runs it); `tests/tasks.sh` (in the root devbox: an option or URL refused by shape before anything is stored, the run after an approval with root's approver, the audit line naming the approver) |
| 33 | A Node site (`app = "node"`, 2026-09-28) forwards every request to its application and answers a few paths and endings itself with a 404, never forwarded: `/.env`, `/.git/`, `/.npmrc`, `/node_modules/`, `/package.json`, `/package-lock.json`, `/npm-shrinkwrap.json`, `/yarn.lock`, `/pnpm-lock.yaml`, and databases, logs, keys and dumps by their ending wherever they are (Uptime Kuma keeps `kuma.db` in `data/`). Its tasks are rows like row 26's: `npm_ci` installs exactly what the application's `package-lock.json` pins, integrity hashes included, and `npm_run` runs one script of the project's own `package.json` by a name checked as a name (never an option); both run the project's code as the site's account, as a Gemfile or `manage.py` does, with npm's cache and user configuration in the account's own home and `NPM_CONFIG_*` refused in the site's environment. The rendered unit runs root's `node` on `entry`, a path inside the project checked as a plain relative `.js`, `.mjs` or `.cjs` file (no `..`, no segment starting with a dot), bound to the upstream's loopback address through `HOST` and `PORT`, which the site's environment cannot override (row 28) | `kNodeRefused`, `kNodeRefusedEndings`, the node rows and family (`tasks.cpp`), `check_entry`, `control::service_unit`, `appenv::check_change_for_app` | unit tests (the locations and endings, the rows' argv and environment, a script name that looks like an option, `entry`'s refusals, the unit's text, the reserved names), `tests/tasks.sh` (a fake node and npm: the account, the cache in its home, the refusals, the unit, the edge), `tests/integration.sh` (without the helper), `tests/kuma-install.sh` (Uptime Kuma 2.5.5 with Debian's node and npm: npm ci from the lockfile, its frontend, node on loopback from the rendered unit, its pages, socket.io polling and WebSocket through agensio over TLS, the project's files refused) |
| 34 | A site deleted with its files (F12b, 2026-09-30) goes into `<sites_root>/.trash/<domain>-<stamp>/`, opened and created by the helper as a directory that is root's alone (`0700`, never through a symlink, tightened when found wider), so no account and not the server can read another tenant's deleted files. The server sends a site's name; the helper finds the site in the configuration on disk and derives every path from it (the tree below `sites_root`, refused when the root is not below it; the account's state directory only when no other site uses the account; the log only below the logs directory; the environment file only under the environment directory; the password users file only as `<config dir>/auth/<site>.users`, so a site created again under the name inherits no users, and back on a restore into the server's group's `0750` directory; a parent of a log or users file the restore must create is made root's with the server's group, `0750`, or the restore fails and puts back what it moved, 2026-10-12), and refuses while the site's unit is active (`systemctl show`), since a renamed working directory keeps a running process writing into the trash. Every piece moves by `rename` (a small file on another filesystem is copied without following symlinks, a directory goes to a trash beside its own base, `<state_dir>/.trash/<entry>`); a failure puts back what moved. The manifest names the pieces and their origins; a restore or a removal trusts only paths under the entry's own directory or that entry's side trash, never anything else the manifest could name. Removal walks with `openat` and `O_NOFOLLOW`, entering each directory through its own descriptor, never leaving the entry, unlinking symlinks as entries. Restore moves pieces back only where nothing stands (a missing path or an empty directory), refuses when the site exists again or its file is there, and only when the account exists with the uid the files carry (the files' ownership is never changed); the site file is written from the manifest with `O_EXCL`, owned as its directory is. Entry names are validated everywhere (`valid_trash_entry`: a host name and a stamp; no `/`, no `..`); the account is never removed. Admin only, every operation audited with the paths moved; the trash keeps `[control] trash_keep` days (from root's file, applied to what is in the trash) and expires hourly on worker 0 through `try_request`, so a running task only delays it. The registry of log sinks opens and reopens only the files the configuration names (`LogRegistry::unmark_all`), so a deleted site's log is not recreated empty at each reload | `provision::site_trash`, `site_restore`, `trash_list`, `trash_delete`, `trash_expire`, `remove_tree`, `open_private_dir`, `move_path`, `valid_trash_entry`, `site_tree`; `ControlHandler::site_trash` / `trash_restore` / `trash_delete` / `trash_list`; `Server::arm_trash_expiry` | unit tests (the entry-name rule, the helper's validation of every argument, the tree rule with a shared domain directory and a root outside `sites_root`, `trash_keep`'s bounds); `tests/trash.sh` (root devbox: two sites on one account, the refusal while the unit runs, every piece moved and the account's state kept while shared then taken whole, the trash unreadable to another tenant and to the server, the listing, restore refused into a non-empty place then done, a bad entry name, trash-delete, expiry by an aged manifest, the account kept, the plain delete unchanged); `tests/control.sh` (a viewer and an operator get 403); `tests/integration.sh` (without the helper: 409, the site stays) |
| 35 | An application's own server guidelines as a managed site's `rules` (2026-10-01, the Kanboard proposal): `private` paths, the `.php` files that run (`entry_points`), cached directories, a front controller. The control plane validates the object against the preset as it stands after the request (entry points and a front controller on PHP presets only, a cache on PHP and static sites only, the front controller one of the entry points, nothing under a private path, bounded counts, `/`-rooted plain paths without `..` or `//`, never `/` itself) and renders it into ordinary locations of the site file (`handler = "deny"`, `final`, a denying `.php` suffix location, `deny_suffixes` with every PHP ending and source backup on the cached directory), so a rule can only narrow what the bare preset serves and `--explain` shows exactly what the file does; the kept rules are checked again on every later change, so an `app` change they no longer fit is refused until they are cleared. The php preset itself refuses `.sqlite`, `.sqlite3`, `.db` and `/web.config` now, since Kanboard's `data/db.sqlite` was downloadable under it. The `.htaccess` files of an installed archive are read once, at install time, for one shape only (a whole-directory `Require all denied` or `Deny from all` outside `<Files>` blocks, in files up to 64 KB, three levels deep); the directories are reported as `facts.htaccess_denied` and the matching `private` rule suggested in the next steps, never applied by the server and never read when serving (an attacker who can write an `.htaccess` into the tree gains nothing). A cached directory below a preset's shield keeps the shield's refusals and serves-only endings at load, whoever wrote the location (0.1.0-alpha.120, the alpha.119 report: a cache rule on Grav's `user/themes/` became the longest prefix with only the PHP endings and the backups, and served the themes' yaml, markdown and twig files with a public lifetime), and one below a directory the preset never answers is refused, by `check_rules` first and by the loader for a hand-written file | `control::check_rules`, `render_site` (`rules_locations`), `apply_preset` (the shield inheritance), `preset_never_dirs`, `apply_request`, `install::htaccess_denies_all`, `app_facts`, `kSourceBackups`, the php row of `kPhpPresets`, `parse_location` (`deny`) | unit tests (every accepted and refused rule shape, rendering and loading back, the router's answer for private, entry, other-PHP, cached and front-controller paths, the preset's new refusals, the `.htaccess` parser on Kanboard's two forms and on `<Files>` blocks and comments), `tests/integration.sh` (a php site with rules on the wire, the refusals, `site_show`, an app change the rules no longer fit), `tests/kanboard-install.sh` (root devbox with php-fpm: Kanboard 1.2.54 from GitHub, `htaccess_denied` and the suggestion, `app/Core/Base.php` running under the bare preset and 404 after `site-update` with the rules, the login page, jsonrpc, healthcheck, the cached assets, a nice URL, the database private) |
| 36 | Root additions (2026-10-02, design section 20): a file beside a managed site's file, `sites.d/<domain>.root.toml`, with a top-level `site = "<domain>"` and `[[location]]` tables, gives root the whole location grammar on a site the control plane manages, which never writes or reads it. The loader accepts it only as a regular file (no symlink) owned by the owner of the main configuration file and writable by nobody else, so the server's account, which writes the managed files, and the admin role, which writes only rendered content through the handler, cannot make one; a lax file sets its site's file aside with the line to run (since alpha.62, design section 26: the site is never served without its additions, a running one keeps its last good version, the other sites load). Its locations are hand-written locations: they win over the preset's at their path, and a path the managed file already has is a duplicate that sets the site's file aside, and a `site_update` reloads with its own file required to load, so one that would collide is refused and undone with the file named. A file whose site is gone is kept and ignored with a warning (health `root_additions_orphan`), never an error, so disabling or deleting a site cannot break a reload. The trash moves the file with the site (piece `root`, beside the site file only) and restore puts it back root-owned by rename; a plain delete renames it `.bak` beside the site file's `.bak` (a rename, so still root's; put back when the reload refuses) and names it in the answer and the audit line. `site_show` names the file and what it added; the MCP texts send an agent asked for what no field covers to that file, never to the managed one | `RootAdditions`, `check_additions_file`, `parse_root_additions`, `parse_site` (the merge), `Config::orphan_additions`, `ControlHandler` site_show, health `root_additions_orphan`, `provision::site_trash` | unit tests (merge and origin, a headers-only addition joining the preset's location, one replacing it, the duplicate, every refused file shape: a foreign key, no site, a symlink, a group-writable file; an orphan kept), `tests/integration.sh` (a managed site extended on the wire, `site_show` before and after, `--explain`, `site_update` still working, a rule at an added path refused naming the file, a writable file setting the site aside, the orphan after `site-disable`), `tests/isolation.sh` (an additions file refused: its site not served, health says why), `tests/trash.sh` (a file owned by the tenant refused with the rule; root's moved with the site and restored) |
| 37 | Host protection (2026-10-02, `docs/configuration.md` 18): agensio renders the firewall ruleset and the fail2ban jails for its host and reads back what is in place, but applies nothing. The ruleset is a table of its own (`inet agensio`) over the host's public ports, so it can neither cut root off (SSH and every other port are not its business, no policy is set) nor disturb a panel's or the distribution's rules, and root applies it commit-confirmed (a trial from its own file in `/run`, with a timer that goes back to the kept ruleset or, on a host that kept none, removes the table, so a missed keep never takes away limits the host had; then the keep step). Every value rendered into a file is a port number from the configuration, a log path from the configuration, or a login path `check_login_path` accepted (plain characters, `/`-rooted, no `..`, an optional query of letters, digits and `._~/=&+:-` with no `%`, quotes or spaces, rendered into the jail as a regex of every spelling with `%` written `\x25` and every metacharacter escaped), so no caller can put a line into the ruleset or the jail or reach configparser's interpolation. The check is the helper's `host_protection`: read-only, no argument, four programs by absolute path with fixed arguments (`nft -j list ruleset`, `systemctl show` of six named units, `fail2ban-client status` and `status <jail>` for the jail names fail2ban itself listed, plain names of up to 64 characters, at most 64, and `journalctl` for one line of each failure jail that reads the journal, its match words of three field names and plain values built from the configuration on disk), the answers raw and read by the server. A failure jail that reads the journal matches each site account's `_UID`, a field journald sets from the sender's credentials, with the php-fpm unit or Drupal's identity, never `SYSLOG_IDENTIFIER` alone, which any local process can claim (alpha.49 report: forged lines from any account would have banned any address); a site without an account of its own is listed as not read. `login_paths` on a site (control plane or file) is data for the jail: nothing is served, refused or executed by it. `[control] host_protection` is root's. The files root loads (the jail, the ruleset, the firewall unit, a site's application unit, a generated pool) are written by agensio itself (`--out`, 0.1.0-alpha.95): whole, through a temporary file created `0644` with `O_EXCL | O_NOFOLLOW` and renamed into place, never with root's umask, and left as they were when a render fails, so a stopped server or a refused call can no longer empty the jail the next reload loads; a fix given to root as one line chains its steps with `&&`, and the lists of steps (`fail2ban.install`, `firewall.trial`, `run_as_root`) are to be run in order, each after the one before it succeeded; health's `root_file_writable` names one of these files its group or anyone may write | `control/protection.*` (`protection_input`, `render_nft`, `render_jail`, `read_probe`, `protection_findings`), `config.cpp` (`check_login_path`, `login_paths`, `host_protection`), `provision.cpp` (`host_protection`), `handler.cpp` `/v1/protection` (viewer); `file.cpp` (`write_file_atomic`), `main.cpp` (`ctl --out`, `agensio protection --out`), `control/commands.cpp` (`root_file_findings`) | `tests/tests.cpp` (`test_protection`: the input from a configuration, the shipped files held to the renderers, nft's JSON with a foreign table's named set, the unit states, fail2ban's status, every finding state), `tests/integration.sh` (rendered on a loopback host, nothing exposed; the packaged copies; `login_paths` through the API and the command line, a bad path refused), `tests/protection.sh` (root, the real nft and fail2ban: both missing, the ruleset loaded twice and seen, four jails over the site's log, a loopback address banned after eleven POSTs and the site refusing it, a site added later making the table and the jail stale, two sites on accounts of their own and one without, the journal asked under the accounts' uids, empty and then answering one line through a stand-in journalctl, `external` and `off`); `tests/tests.cpp` (`test_root_files`: `0644` under umask `0002`, a `0664` file replaced, a failure leaving the file and nothing beside it, the finding) and `tests/integration.sh` (`--out` live: an unreachable server and an unknown part leave the ruleset byte for byte, health names it while group-writable, no command root is given writes with `>`) |
| 38 | Access by client address (2026-10-07, `docs/configuration.md` 19, design section 22): a managed site's `rules.restricted` becomes `[[site.access]]` tables through the admin-only `site_update`, like every rule, and only narrows the site: a rule is an allow list, never a deny list, and an empty list, an unknown key, an unknown `@set`, a zone id or an unnormalised path is refused by `check_rules` and again by the loader at reload. The address sets are root's, in the main file (`[addresses]`), so the control plane can name them but never change them. `access_check` (viewer) is a pure function over the running configuration that parses one path and one address and opens nothing. The check runs before routing on the normalised path and on the other ways an origin may read it (a `;` segment parameter, a second decoding, the path after a script), so neither a `.php` suffix location nor a proxied application's own path rules step around it, nor a directory answering with an index file a rule covers (alpha.55: the index is routed as a request for it by name); an exact rule covers the script a request runs too (2026-10-09, the alpha.58 report: `/wp-login.php/x` ran `/wp-login.php` through PHP past an exact rule, and `/cgi-bin/report/2026` ran `report`), through `access::script_of`, which takes the split from `core/script_split.hpp`, the one the FastCGI and CGI handlers use, so the rules and the handlers cannot disagree on the script (Caddy's CVE-2026-27590 and CVE-2026-45135 came from a second split), and widens a rule only where agensio runs that script (no false positive on `/info.phpx`, a static path or a proxied location, where `-t` and health note the exact rule instead, `exact_rule_proxied_script`); the address is the peer or, behind `trusted_proxies`, the rightmost untrusted `X-Forwarded-For` hop across every line (the three client-address bugs fixed the same day). The refusal names only the address the server saw; the error log line is rate-limited to one a second per worker, report mode to each rule and client once a minute and 16 new lines a second, the rest counted (alpha.53). `rules.admin` (alpha.53, design section 23) is the same allow list over the preset's administration paths, rendered by the same code; it is never set by default (an admin stays reachable until its owner restricts it), and the openings the WordPress preset keeps under a `/wp-admin` rule (`admin-ajax.php`, the login page's `css/`, `js/`, `images/`, and since alpha.61 its `load-styles.php` and `load-scripts.php`, exactly) are shields where no script runs, except those three core scripts WordPress keeps public (no plugin, no database, no login; the concatenating two print only core files named in the query), so a rule never reopens PHP. | `core/access.hpp`, `handlers/dispatch.cpp` (`admit`, `access_log_tick`), `config.cpp` (`parse_access`, `[addresses]`, `preset_admin_paths`), `control/sites.cpp` (`check_rules`, `admin_rules`), `control/commands.cpp` (`access_check`) | unit `test_access_rules`, `test_exact_script_rules`; integration `access:` and `mcp: access_check` checks, `exact rule on a PHP script: ...`; `fuzz_fields` (the client address behind `trusted_proxies`, CIDRs), recorded below |
| 39 | Refused paths and path_check (2026-10-08, `docs/configuration.md` 6b, design section 24): a managed site's `rules.refuse` becomes the site's `refuse` through the admin-only `site_update`, like every rule; it only narrows the site (a match is a 404, no pattern reopens anything), so an agent translating an application's documentation can make the site serve less and never more. Each pattern is compiled when it arrives and again at reload: only `*` and `**` (one), no regex, braces, `?` or percent escapes, at most 64 of 200 characters, so matching is linear and a pattern cannot cost a worker more than a few hundred nanoseconds; a pattern that would refuse the site's index, a `try_files` target or an exact location that runs something is refused, so a translation error cannot take a site down. The check runs before routing, on every internal redirect and on a directory's index file, case-insensitively and on the other readings of a path, so no location, suffix or index steps around it; since alpha.55 a directory's index that the site refuses by name (`refused_request`) is passed over as if missing, so it is never the answer, served or run, and the directory goes on to `try_files`' next step. `path_check` (viewer) is a pure description over the running configuration plus `stat` of the paths it names, as the server account: it fetches nothing from an application and opens nothing for writing. | `core/refuse.hpp`, `handlers/dispatch.cpp` (`route`, `serve_static`), `handlers/static.cpp` (`index_lookup`), `config.cpp` (`parse_refuse`, `check_refuse_conflicts`), `control/sites.cpp` (`check_rules`, `render_site`), `control/commands.cpp` (`path_check`) | unit `test_refuse_patterns`, `test_refuse_config`, `test_path_check`; integration `refuse:` checks; `fuzz_refuse` (the indexed set agrees with every pattern alone), recorded below |
| 40 | Passwords (`[[site.auth]]`, 2026-10-08, `docs/configuration.md` 19b, design section 25): the rules are checked before routing and on every hop and index, so no location steps around them, and an exact rule covers the script a request runs with path info as the access rules do (row 38, 2026-10-09); the user file is root's, not readable by others, opened without following a symlink, and strong hashes only (yescrypt, bcrypt, sha-crypt, scrypt; MD5, SHA-1, plaintext and DES refused at load). The slow hash never runs on a worker's loop (a pool of at most four threads, eight verifications in flight per worker, 503 beyond); what is remembered is an HMAC under a per-process key of the user, the stored hash and the password (never the password, never a failure), so a changed password or another area never matches; an unknown user costs the same verification as a known one. The parser refuses control characters (a NUL would cut the password for `crypt`). No password is asked over plain HTTP from another host unless the rule allows it (behind a trusted proxy, by the proxy's `X-Forwarded-Proto` and the client it names, never its own loopback address: alpha.61, the alpha.58 report); the application never receives `Authorization` unless the site runs PHP or the rule says `pass`, and never from a client `skip_for` let in, whose field nobody verified (alpha.61, the alpha.58 report); a client cannot supply the `forward_user` field. No protected answer is one a shared cache may keep: `Cache-Control: private` on every answer of a protected path, static or from PHP, CGI or a proxied application, with the application's `public`, `s-maxage` and `proxy-revalidate` removed and the fields only CDNs act on (`*-Cache-Control` targeted fields, RFC 9213 2.2; `Surrogate-Control`, `Edge-Control`) dropped, for a client let in by `skip_for` too (2026-10-09, `core/private_cache.hpp`; before, only static answers). Failure lines put the client first and escape the user name, so a name cannot pass for another address in fail2ban: the `agensio-auth` filter is anchored at the date and `[warn] auth failed: client <ADDR>`, takes addresses only, and counts a wrong password, an unknown or locked user and malformed credentials, never the challenge (a 401 without credentials, which every browser meets first: the filter of alpha.57 counted every 401 of the access logs and so banned a protected site's own users; health warns `fail2ban_auth_challenges` while that filter is installed) and never an expired user's right password. A managed site's users (step 4b, 2026-10-09) are kept by the control plane in `<config dir>/auth/<site>.users`, root's, the server's group, `0640`, in a `0750` directory of root's, written by the helper (`auth_users_write`) through a temporary file and a rename without following a symlink, so the site's account can neither read nor replace it; a password never travels to the server: the helper generates one and answers it once (kept nowhere), or `agensio ctl --prompt` hashes on the user's terminal and sends the hash, which must be one the loader accepts; the API refuses a `password` field and the MCP bridge drops a `hash` from the agent; the listing never shows a hash; every call is admin only and audited with the user's name and what changed. A managed site's `rules.auth` (step 4c) renders `[[site.auth]]` tables reading that file and is refused until the file has a user (a rule over a missing or empty file would make the next load refuse the configuration) and on `site_create`, so an old file left under the name never comes into force unseen (`site_create` warns when one exists, health reports it as `auth_users_orphan`). Health reads every users file a rule names the way the next load will (`auth_users_unloadable`, an error, since a restart would not start the server) and reports a rule nobody can log in to (`auth_no_valid_user`), expired users and `plain_http` on a listener the network reaches. | `core/auth.*`, `handlers/dispatch.cpp` (`check_auth`, `start_auth`, `auth_failed_line`), `config.cpp` (`parse_auth`, `load_auth_users`), `handlers/static.cpp` (`add_headers`, `index_lookup`), `control/protection.cpp` (`kFilterAuth`, `kFilterDenied`, the `agensio-auth` jail), `services/authusers.*`, `provision.cpp` (`auth_users_op`), `control/handler.cpp` (`site_auth_users`, `site_auth_user_change`, `auth_users_needed`), `control/sites.cpp` (`check_rules`, `render_site`: `rules.auth`), `control/commands.cpp` (`auth_findings`, `auth_rule_json`), `config.cpp` (`auth_users_problem`) | unit `test_auth_core`, `test_auth_config`, `test_protection`; `tests/auth.sh` (16 checks; an exact rule on a CGI script run with path info, 2026-10-09); `tests/protection.sh` (challenges and an expired user's right password not counted, wrong passwords banned, the old filter warned about); unit `test_auth_users`; `tests/auth.sh` (the users tools and MCP without the helper), `tests/provision.sh` (through the helper: owner, group, mode, a symlink refused), `tests/control.sh` (admin only); unit `test_auth_managed`; `tests/auth.sh` (`rules.auth` refused without a user and on a new site, the managed site asking, path_check, the health findings, `--no-auth`); `tests/trash.sh` (the users file into the trash and back); `fuzz_auth_users` (the user file, its dates, the Basic field), recorded below |
| 41 | Site isolation (2026-10-10, 0.1.0-alpha.62, design section 26, `docs/configuration.md` 12c): each included site file loads on its own, so one tenant's mistake no longer stops every site at boot or blocks every reload (renewals included). It fails closed: a site is set aside whole when its root additions file or a users file of its password rules does not load, never served without the location or rule that protected part of it, and a running one keeps its last good version, the one that loaded with them. A file claiming a name another file serves on the same address is set aside, the served one keeping its place, so a new file cannot take over a running site's name; and a file set aside for its own error keeps a claim on its names, so at start a duplicate that yielded to it does not take its name over without its rules (the alpha.62 report); and a start ranks conflicts by the record of the files served at the last start or reload (`<state_dir>/.server/served`), so a restart never gives a name to another file than the one the running server served (the alpha.63 report). The main file (root's: `[server]`, `[control]`, `[addresses]`, `trusted_proxies`) stays all or nothing. The control plane requires its own file to load (`reload_now` with the file): a `site-create`, `site-update`, `site-enable`, restore or users change that would be set aside is refused or reported as not applied, never answered as done. The hosting rules (step C2) set aside a site that breaks one, and a site is served only by a version that passes every rule now, so a root opened to others or a socket of another account takes that site down at the next reload instead of being kept; the writers of row 24 count a site set aside as a refused state, and `write_pools` removes no pool while a file is set aside. A certificate and key pair that does not load (step C3) sets its site aside the same way; a served site keeps the certificate material loaded before, copied into the new contexts from memory, so an unreadable renewal never serves a site without TLS nor takes it down | `config.cpp` (`load_config` with the running configuration, `first_site_conflict`, `Config::held_back`, `SiteConfig::source`/`carried`), `Server::reload` (`must_load`), `ControlHandler` (every writer passes its file), health `site_file_held_back` | unit `test_site_isolation` and the root additions checks; `tests/isolation.sh` (start, reload with the last good version, a newcomer claiming a served name, an additions file refused, a `site-create` set aside refused and removed, a broken main file still refused) |
| 42 | Path redirects (`[[site.redirect]]`, 2026-10-13, 0.1.0-alpha.82 and .83, `docs/configuration.md` 14b, `docs/redirects.md` 5): a managed site's `redirects` reach the file only through the admin-only, audited `site_update`, sent whole and judged by the loader's own parse and checks before anything is written, then again by the reload, which undoes a refused change. A rule can only send a request elsewhere, never serve a file or run anything: it stands after `refuse` (a refused path is never redirected) and before the access and password rules (a redirect reveals no content; its target meets its own rules, and a rule under a protection is noted). Every `Location` is written by agensio byte by byte (`core/redirect.hpp`): a target of the site stays relative, so it never depends on the Host a client sent; the rest of the path and the query are percent-encoded again, so no control character, space or backslash reaches it raw; a relative one never starts with `//` or `/\`; an absolute one names exactly the host of `to`, which must be http(s) with no user name or password; a prefix never takes a path that spelled a separator as `%2F`. Loops and circles, the same `from` twice, rules `refuse` makes unreachable and more than 1,000 rules are refused at load. `fuzz_redirect` holds the `Location` to those promises. `path_check`'s preview (viewer) compiles proposed rules on a copy of the site and changes nothing. | `core/redirect.hpp`, `parse_redirects` and `check_redirects` in `config.cpp`, `Dispatcher::route` / `redirect_https` / `redirect_host`, `apply_request`'s `redirects` and `load_redirect_rules`, the `path_check` handler | `fuzz_redirect`, unit `test_redirect_rules`, the integration checks of the design's examples, the one hop and the managed field |
| 43 | The PHP versions in sight (2026-10-20, 0.1.0-alpha.107, `docs/configuration.md` 7b, `docs/design-php-versions.md`): `php_versions` reads what is installed and installable, and changes nothing. Each version's programs are its own FPM binary, found at the fixed path of a known layout (`/usr/sbin/php-fpmX.Y`, Remi's, Alpine's, Homebrew's) or named by root in the main file's `[php.runtimes]` (absolute paths without `..`; the unit a systemd name of letters, digits and `@._-`; refused in an included file, which a site's files may be), never by a caller: the request has no argument. They run with fixed arguments (`-v`, `-m`, `-i`, `-tt -y <conf>`, `systemctl show` with two properties, `apt-cache policy` for package names built from the compiled release table), an empty environment and no shell, their output capped. As root (the helper's `php_runtimes`) only for the configuration test, which opens php-fpm's own log; the rest runs as the server's account when there is no helper. The answer is a viewer's: versions, extensions, service states and file paths root chose; installing stays root's, the answer carrying the lines | `services/php_runtimes.*` (`discover`, `gather`, `system_exec`, `installable`), `control/php.*`, `config.cpp` (`parse_php_runtimes`), `provision.cpp` (`php_runtimes`), `Server::php_versions_async`, `handler.cpp` `/v1/php` (viewer) | `tests/tests.cpp` (`test_php_runtimes`: discovery on described machines, root's table and its refusals, the programs' output, the support table, `apt-cache`), `tests/integration.sh` (`ctl php` as the server's account: no configuration test, said), `tests/provision.sh` (through the helper as root: the test and `process_control_timeout`) |
| 44 | A pool per site (2026-10-20, 0.1.0-alpha.107, `docs/configuration.md` 7b and 11, `docs/design-php-versions.md` 5): each site with a user has its own php-fpm pool, in the pool directory of its PHP version. The account stays the boundary between accounts (pools of two users never share a socket, a state directory or a root, as before); within an account a site's PHP now has its own `open_basedir`, `tmp/` and `sessions/` (`<state_dir>/<user>/php/<domain>`, the account's directory and its `php/` `0700`), so one site's scripts no longer read another's sessions through PHP's file functions (PHP's `open_basedir` is not a security boundary; the uid is). Pool files stay root's, written whole and `0644`; every directory a run changes is tested by its own php-fpm before its reload and restored when refused, so a pool never stops a master. A pool's name is the account and 8 hex digits of the domain (FNV-1a), with the version in the socket's name; two sites of one account whose digits collide are refused at load. The trash moves a site's PHP state with it when its account serves other sites | `config.cpp` (`parse_pool`, `pool_name`, `first_site_conflict`), `services/pools.*` (`write_pools`, `test_runtime`, `reload_command`), `provision.cpp` (`pools_apply`, `site_trash` piece `php`), `control/commands.cpp` (`pools_stale`, `php_version_missing`, `php_default_unpinned`, `php_fpm_hard_reload` per version) | `tests/tests.cpp` (`test_pools`: names, sockets, versions, placement across two versions, a move, a refused test put back, a missing version), `tests/pools.sh` and `tests/provision.sh` (real php-fpm as root, each through `[php.runtimes]`) |
| 45 | The switch of a site's PHP version without downtime, and the pools at a start (2026-10-20, 0.1.0-alpha.107, `docs/configuration.md` 7b, `docs/design-php-versions.md` 6.1, 6.2): every reload that gives a site a new pool socket runs, off the workers, a preflight (the version installed; for a moving site its php-fpm running and `process_control_timeout` in both versions' `php-fpm.conf`, the last overridable by an admin's `cut_requests`), the helper's `up` phase, the switch, then its `full` phase; one reload at a time. The server's part reads world-readable files only (`php-fpm.conf`, `/proc/<pid>/cmdline`) and asks systemd for one property; it never signals a process. The helper signals only a php-fpm master: by its unit through `systemctl reload`, or with SIGUSR2 to the pid in the pid file the version's own root-owned `php-fpm.conf` names, after `/proc/<pid>/exe` matched that version's binary, so a pid file pointing elsewhere is refused; it starts no service (root's line instead). The wait is a connect to the written pools' own sockets, bounded at 30 s, so a pool that never comes up cannot hold the helper. At a start the same reconciliation runs once before the listeners accept | `server.cpp` (`reload_async`, `prepare_reload`, `commit_reload`, `pools_after`, the start in `run`), `services/pools.*` (`pool_switches`, `switch_preflight`, `restore_pools`, the up phase of `write_pools`), `services/php_runtimes.*` (`pid_file`, `master_running`, `unit_state`), `provision.cpp` (`pools_apply`, `reload_runtime`, `socket_accepts`), `control/handler.cpp` (`reload_then`, `refused_reload`, `pool_report`) | `tests/tests.cpp` (`test_pools`: the switches, the preflight, the up phase and its put-back; the pid file parser), `tests/provision.sh` (as root on two real masters: a switch and its way back under load with no failed request, the timeout refusal, a configuration php-fpm refuses, the start writing a missing pool before the first request, a start that changes nothing) |
| 46 | What an application needs of its PHP (2026-10-21, 0.1.0-alpha.107, `docs/configuration.md` 7b, `docs/design-php-versions.md` 7): a compiled table per preset from the applications' own pages, and what an installed release declares: `composer.json`'s `require` (`php`, `ext-*`), WordPress's `$required_php_version`. These are text from a site's files or an uploaded archive, so they are read bounded (512 KB, the JSON parser fuzzed with the rest, the Composer constraint reader fuzzed by `fuzz_php_constraint`) and judged, never run: a constraint the reader does not understand refuses nothing. The installer reads them as the site's account through the extracted tree's descriptor with `O_NOFOLLOW`; the server reads a site's on disk as its own account with `O_NOFOLLOW`, for the preflight and health. The version's facts (`php-fpm -v`, `-m`, fixed arguments) come from the helper's own discovery as root before `app_install` drops to the account, which takes `php_version` and `php_app` as names only, never paths. A release the site's PHP cannot run is taken out again by the installer's own cleanup; `ignore_requirements` is an admin's choice like `cut_requests` | `services/php_requirements.*` (`app_requirement_table`, `parse_composer`, `parse_wp_required`, `constraint_allows`, `check_requirements`), `services/php_runtimes.*` (`loaded`, `declared_on_disk`), `services/pools.cpp` (`switch_preflight`), `services/install.cpp` (`read_small`, the check after extraction), `provision.cpp` (`app_install`), `control/commands.cpp` (`php_extensions_missing`, `php_version_unsupported_by_app`, `php_version_eol`) | `tests/tests.cpp` (`test_php_requirements`: constraints, the declarations, the judgement, the table; `test_pools`: the preflight's requirements and health's findings with a fake php-fpm), `tests/fuzz/fuzz_php_constraint.cpp`, `tests/provision.sh` (a move refused for an extension `composer.json` requires, `--ignore-requirements`, an install refused and taken out, then installed with the override) |
| 47 | The served directory of a plain PHP project (`served_dir`, 2026-10-22, 0.1.0-alpha.109, `docs/configuration.md` 2): a managed site's `served_dir` reaches the file only through the admin-only, audited `site_create` and `site_update`, checked by the loader's own `check_served_dir` (a plain relative path of letters, digits, `.`, `_`, `-`, `/`; no `..`, no segment starting with `.`, no `/` at either end; `app = "php"` only). It only narrows what the site serves: the served root is a directory inside `root`, which stays PHP's `open_basedir` and the install's target; a served directory that exists is resolved at load and refused when it leaves the project (a symlink to `/etc` is refused, not served); one that does not exist is the lexical path inside the project and serves nothing. The project's `.env` and `.git` join the credential files the hosting rules check and the installer makes private. Health's `php_any_script_runs` says that every `.php` of a php site runs, uploads included, until the site names its scripts | `config.cpp` (`check_served_dir`, `parse_site`), `services/pools.cpp` (`secret_paths`), `control/sites.cpp` (`apply_request`, `render_site`), `control/commands.cpp` (`served_dir_missing`, `php_any_script_runs`, `site_summary`) | `tests/tests.cpp` (`test_served_dir`: the served root, `open_basedir`, the secrets, the refusals, a symlink leaving the project, a missing directory, health's two findings, the managed field rendered and loaded back), `tests/integration.sh` (a project's `public/` served, its `src/` required by PHP and never served) |
| 48 | An exact `.php` location and its script's path-info form (2026-10-22, 0.1.0-alpha.109, `docs/configuration.md` 6): PHP runs `/install.php/x` as `/install.php`, so the location deciding `/install.php` decides `/install.php/x` too. Before, an exact location was its literal path only, and on a site whose `.php` suffix location runs any script (`app = "php"`, `wordpress`) the path-info form of a script an exact `deny` refused reached that location and ran: a managed site's `rules.private` `.php` file, WordPress's never-served drop-ins and `wp-config.php`. The router and the FastCGI split now agree, as the access and password rules already did (`access::script_of`, alpha.59): the flag is set once at load for an exact path ending in `.php` with no `.php/` before its end, and an exact location naming the whole path still wins (exact locations are sorted longest first) | `config.cpp` (`finalize_site`: `LocationConfig::script_exact`), `core/router.hpp` (`Router::location`), `core/script_split.hpp` (`php_end`, the split it agrees with) | `tests/tests.cpp` (`test_presets`: deny, fastcgi and longer exact locations, `/a.php/b.php/c`, a non-.php exact path, WordPress's and Laravel's), `tests/integration.sh` (a managed `rules.private` `/install.php` with path info 404 and never run, WordPress's `wp-config.php/x` and `wp-content/db.php/x` 404 and never run, Laravel's `/index.php/extra` with `PATH_INFO`), `bench/ab.sh -A` row `exact` |
| 49 | A credential file readable by others no longer takes its site down (2026-10-22, 0.1.0-alpha.110, `docs/configuration.md` 11): an update made in place (`cp .env.example .env` gives `0644`, `chmod -R 775 storage`, `rsync -a`) left the file readable by the server's group or others, and the next reload, whatever caused it, set the site aside, though a site stopped makes the file no more private. The rule now sets nothing aside for it (`isolate_hosting` lists it in `Config::exposed_credentials`); at a start and on every reload the helper's `credentials_tighten` makes the site's account's own files private with the installer's modes, deciding from the configuration and files on disk what to change (never the server's word, never a link, never another account's file, only what the rule flags), and audits each change; what is left is health's `credential_exposed` error. The rules for what another account could write (a root or `open_basedir` directory not the site's, or writable by others) stay fail-closed, as Apache's suEXEC refuses a script writable by others | `services/pools.cpp` (`hosting_errors`: `HostingError::credential`; `isolate_hosting`), `services/provision.cpp` (`credentials_tighten`), `services/tasks.cpp` (`sweep`), `server.cpp` (`tighten_credentials`, `log_tightened`: at the start, in `reload`, in `reload_async`'s thread), `control/commands.cpp` (`credential_exposed`, `validate`'s `credentials_exposed`), `main.cpp` (`-t`'s warning) | `tests/tests.cpp` (`test_hosting_isolation`: no site set aside at a start or on reload, the main file's site too, the site's own group allowed), `tests/provision.sh` (a 0644 `.env` of the site's account: still 200 after a reload, `0600` as the account, both logs; a root-owned one: still 200, health's error with the `chown` and `chmod`), `tests/pools.sh` (`-t` warns and passes) |
| 50 | Approvals (2026-11-01, `docs/design-site-operations.md` 27, the owner's decisions): a change that can run code, move a secret or data off the host, grant access or destroy beyond undo is stored by the gate in `mutate` instead of run, and runs only once a person approved it with a code from an authenticator app; what runs is the stored request (path, body, the requester's identity), through the same code path, marked by `approving_` only around that call, so nothing the request says about itself (`user_confirmed`, `client`, a `code` field) lets it through. A task is dry-run first and stored only when the dry run passes, so a person is never asked about a change that fails anyway; a dry run is never held and says it would wait (`needs_approval`), so `mutate` lets `dry_run: true` through only to a command whose handler answers one without changing anything (`has_dry_run`: site create and update, install, copy, task, the file tools, an environment change) and refuses it (400) for any other before `confirm` is read (so a dry run needs no `confirm`: only one that changes nothing gets past): until 0.1.0-alpha.126 the environment, a reveal by POST, the trash, a site's disable, enable and delete and a reload read no `dry_run` and ran, the gated ones without approval (`agensio ctl ... --dry-run`, which sends `confirm`, or the socket; the MCP bridge refused the argument for those tools). At most 32 wait, each ten minutes, in the server's memory only (a restart applies nothing of them) | `control/approvals.*`, `ControlHandler::mutate` (the gate), `queue_for_approval`, `approvals_post`, `run_approved` | unit test `test_pending_changes`; `tests/integration.sh` "approvals: pip_install through MCP waits ..." (a forged `user_confirmed` waits all the same, the right code runs the change named and only it) and "dry runs: a command without one refuses it ..."; `tests/trash.sh` (`trash-delete --dry-run` removes nothing) |
| 51 | The code (TOTP, RFC 6238: HMAC-SHA1, 6 digits, 30 s, one step each way) is checked by the root helper's reader (`approval_check`, row 57; it takes six digits and nothing else and answers the approver's name, never a secret) against `<config dir>/approvers/NAME.totp`, root's, `0600`, in a root `0700` directory, each file opened `O_NOFOLLOW` and refused when another owns it or group or others may read it; a code is accepted once (the last step kept in `NAME.step`, RFC 6238 5.2); five wrong codes in ten minutes stop approvals for ten minutes, counted in the reader's memory, which the server cannot reset, and in no other process: the main helper refuses `approval_check` while a reader serves it. Approvers are written only by `agensio approver-add`, a local command, root's on a server with the helper: the control plane has no route that writes the directory, so no agent can enroll itself. A server without the helper checks codes itself against files of its own account, which an agent running as that account could read (`docs/approvals.md` 4) | `services/totp.*`, `services/approvers.*`, helper op `approval_check` (`provision::validate`), `agensio approver-add` | unit tests `test_totp` (RFC 4226 and RFC 6238 vectors, the window, a code once), `test_approvers` (modes, owner, symlink, the stop after five); `tests/integration.sh` approver-add, a reused code refused |
| 52 | The person reads the change as the server describes it, never as the agent does: the preview is built from the stored request, the reasons first (`!!`), the requester's words last and marked as not checked, and every byte a terminal could act on written `\xHH` by the server and again by `agensio ctl`, a reason's newline too (alpha.133: a file name from the site's tree in a reason printed a line of its own under it) and its backslash, so no two names print alike (alpha.134); the code is asked on `/dev/tty`, never standard input, so nothing piped in answers it; in an MCP client the code goes into the client's own dialog (elicitation), which the model neither sees nor answers, and the bridge sends it to the server with the ids shown; no tool takes a code, and the bridge refuses a `code`, `user_confirmed` or `client` argument | `control::escape_for_terminal`, `escape_line`, `pending_text`, `ctl_approve` and `ask_code` in `main.cpp`, `Mcp::ask_approvals` | unit test `test_pending_changes` (an escape sequence in a preview and in the requester's words shown as text; a newline and an escape in a file name a reason carries); `tests/integration.sh` (code-refused, uc-refused, no-terminal, elicit, wrong-refused) |
| 53 | The site's files (F12, 2026-11-01, `docs/design-site-operations.md` 3 and 27.6): an operation runs as the site's account (the helper's child after the drop, the account from the site's directory as for a copy, root refused), on one site's tree below `sites_root`, never outside it: every path cleaned (`archive::clean_path`: no `..`, no absolute path, no backslash, no control character), walked component by component `O_NOFOLLOW | O_DIRECTORY` with every component the account's (`install::walk_dirs`), the leaf never followed (a symlink on the way or as the leaf is refused; a listing shows a symlink's target and a delete removes the link, never its target); a write goes to a temporary name `O_CREAT | O_EXCL | O_NOFOLLOW` and is linked (a new file) or renamed (over one) into place, an existing file keeps its mode, a new one its directory's, a credential file `0600` checked as written, no set-uid or set-gid bit, nothing executed; content at most 180 KB a call inside row 12's body cap; admin role for every operation, listing and reading included | `services/files.*` (`parse`, `execute`), helper op `file_op` (`provision::validate`), `ControlHandler::site_files` | unit test `test_site_files` (every refused shape, a planted directory symlink and file symlink refused for read and write and the target untouched, the delete of a link leaving its target); `tests/files.sh` in the root devbox (another account's directory refused, modes, the walk as the site's account) |
| 54 | Every change to a site's files waits for approval (row 50), and what waits is bound to what the person saw: the server dry-runs the change, shows the diff against the file there and what the site does with the path (`path_check`: served as a file, RUNS as a script, refused, not served), and adds the file's sha256 (or `absent`) to the stored request, so a file changed meanwhile refuses the approved write (`if_sha256`); a read of a credential or database file (`files::secret_path`: the preset's credential files, `.env*`, `.git/`, `*.key`, `*.pem`, SQLite files, anything below `.ssh/` and the private keys' own names, `id_rsa`, `id_ecdsa`, `id_ed25519` and their kin; and, by `files::private_key_head`, any file whose first line is a private key's: an unapproved read of one answers nothing of it and remembers the path, so the next read waits, and a write of one is made `0600` with a masked preview) waits too, its dry run carrying no content, and its content is handed out once, only to `GET /v1/approvals/ID` (`approvals_list` with the id), never in the list or the approval's own answer. A change to such a file shows no value anywhere: its diff, context lines included, keeps the names of an env-like file with each value's length (`DB_PASSWORD=<16 bytes>`) and only the lengths of any other (a key, `wp-config.php`), in the dry run, the preview and `approvals_list` alike; env-like is decided by the `.env` reader itself, so a file with a value over several lines, whose lines may look like assignments, is masked by lengths only, and a comment shows a name only in a variable's capitals (until 0.1.0-alpha.125 both could show part of a value as a name; held by `fuzz_dotenv`, which checks every masked line against the line it came from), and no write or edit answers a file's text, its previous one included, so no result kept for `approvals_list` carries it (until 0.1.0-alpha.124 the context lines of a `.env` edit showed the values around it, and an approved write answered the previous file whole: the grabloop.app report); nor a sha256 of such a file, the old or the new, in the preview, a dry run, a result, an error or the audit log: with the names and lengths of the diff it would confirm a guessed value offline, so it stays inside the server, which binds the stored change to it through the approval's own dry run (`ControlHandler::binding_run`, `without_digest`; until 0.1.0-alpha.125 the preview and every answer carried both, the alpha.124 report) | `control::approval_reasons` (`file`), `queue_for_approval`, `file_preview`, `take_read_once`, `control::mask_credential_diff` | unit test `test_site_files` (a stale sha256 refused; a credential diff masked, context included); `tests/files.sh` (a credential file's preview, dry run, result and list carry no value and no sha256 of it, nor the audit log; changed after it was queued, the approved edit is refused naming no digest); `tests/integration.sh` (a write waits with its diff and verdict, approved it is served; a changed file refuses the approved write; a secret's read waits and is handed out once) |
| 55 | What a change replaced or removed is kept in `<sites_root>/.history/<domain>/<version>/` (the holder's alone: root `0700` with the helper, else the server account's, never served, out of the site account's reach), reached on the site's side by the same `O_NOFOLLOW` walk with every component the site account's (`install::walk_dirs_owned`): a file a write replaces hard-linked before the account's rename, a deleted path or a replaced destination renamed there whole, so no copy is made and nothing is read by root; a restore renames the version back, keeping what stands there first; the versions beyond `[control] file_history` go only once the change succeeded (a refused change undoes its keep and leaves every version as it was), and worker 0's hourly check expires them after its days | `services/history.*`, helper ops `file_op` and `history_expire`, `Server::arm_trash_expiry` | unit test `test_site_files` (versions kept and capped, a refused change leaving them, a restore over a file, a tree deleted and restored whole, expiry, a history directory opened too wide tightened); `tests/files.sh` (the history root's, a site account cannot reach it) |
| 56 | The rest of design 27.2 waits for approval (2026-11-02, step 3): `site_install` from any source and `site_copy`; `site_env_set` and a `site_env` reveal (the GET is stored as a change and replayed, the values handed out once by id, to whoever asked and only to that account (`approvals_get` compares the peer's uid with the request's: another admin account gets a note and an audit line; until 0.1.0-alpha.128 any admin account that read the id in the list took it): `agensio ctl approve` prints the note in their place, and only a command typed at a terminal shows the secret it asked for there; until 0.1.0-alpha.127 `ctl approve` fetched and printed every secret it approved, so the requester got none); `site_auth_user_set` (a generated password handed out once by id); `trash_delete` and `trash_expire`; a `site_update` judged against the managed spec as it is (`ApprovalContext`): `app`, `root`, `served_dir`, the entry points or the front controller changed, `upstream` changed, a redirect to a host that is none of the site's names and was not there before, a password or address rule removed or widened (`rules_widened`: a rule gone, an allow list or `skip_for` grown, `open`, report mode, `plain_http = "allow"`); a `site_create` of a static site or a PHP preset whose root holds any entry or cannot be read (`control::root_state`, one directory read, nothing walked and no file named: alpha.135 for a PHP preset, alpha.136 for static, the owner's decision after the walk of alpha.132 to .135 kept missing layouts; before alpha.136 a static create waited only for a PHP file the walk found), whose upstream is off this host (`upstream_off_host`: anything but `unix:`, loopback and localhost) or with a redirect to another host. The previews never carry a value or a hash (names only for the environment; the user and flags for a password user); install, copy, update, create and an environment change are dry-run first and stored only when the dry run passes (the environment since 0.1.0-alpha.126: an open quote in a `.env` or a lower-case name was stored and failed once approved), update and create previewed as the managed file's diff | `control::approval_reasons` with `ApprovalContext`, `ControlHandler::mutate`, `queue_for_approval`, `checked_preview`, `approval_preview`, `approvals_get` | unit test `test_pending_changes` (every case above, narrowing and adding free); `tests/integration.sh` "approvals, step 3" (what waits and what does not through the raw API, a secret handed out once by id, an install the dry run refuses never stored); `tests/files.sh` (a credential file's content asked by id from another admin account: a note and an audit line, then the requester's); `tests/tasks.sh` (an environment change its dry run refuses waits for no one, `--dry-run` writes nothing); every suite's gated commands approved through `tests/approve-lib.sh` |
| 57 | The reads and the approval codes have a root process of their own, the helper's reader (2026-11-04, the alpha.126 report, problem 3: a scheduled run held the one helper for up to 50 s of every minute, so health, `protection_show`, `site_service_status` and `site_service_logs` answered busy and a code waited behind the task, past its life): forked in `Provisioner::start` before the privilege drop and before the main helper, on a socketpair of its own, running the same loop, which refuses before anything else every request not in `provision::reader_op` (`approval_check`, `approvers_list`, `env_check`, `app_check`, `app_status`, `app_logs`, `host_protection`, `php_runtimes`, `trash_list`) but `ping`; the main helper refuses those nine while the reader runs, so every request has exactly one process, and the wrong codes and the codes' last steps are kept in one. The reader adds no request: its nine are the helper's, validated by the same `provision::validate`, run by the same code, read-only but for the codes' step files, which only it writes. Kept on the main helper, behind tasks: the expiries (they remove files), `env_read` and `auth_users_read` (they may tighten a mode), every write. A read the reader serves meanwhile sees the files as a running task or trash operation leaves them at that instant, as any reader of the disk would: what it answers is a report, never a decision another request acts on. The server waits for the reader at most `Provisioner::kReadWait` (30 s) on its threads and never on a worker (busy past it), so a read that hangs holds neither tasks nor the server. A reader that does not start leaves the helper serving everything, as before. Both helpers close every descriptor they inherit but their own socket (until alpha.127, those below 1024 only) | `provision.cpp` `helper_loop`, `close_all_but`, `spawn`, `Provisioner::start`, `channel_for`, `request`, `read`; `provision::reader_op` | unit test: `reader_op`'s list; each helper's loop over a socketpair (`provision::serve`): the reader refusing writes, tasks, the expiries and unknown requests, the main helper beside a reader refusing `approval_check` and `host_protection`, alone serving them; a descriptor at 1500 closed; `tests/tasks.sh`: while a task holds the helper for three seconds, `site-service` answers at once, not busy, and a code is checked at once |
| 58 | Fewer records of a site (2026-11-05, 0.1.0-alpha.128, `docs/configuration.md` 8b): `access_log_exclude_paths` and `access_log_keep_days` reach a managed file only through the admin-only, audited `site_update` or `site_create`, and a change that adds or widens a path or sets or lowers the days waits for a person's approval (`control::approval_reasons`), since a prompt-injected agent's first wish after an attack is fewer records of it. What the jails count cannot be excluded, whoever writes the file: the loader refuses a path covering or under a login path (the preset's and the site's), one a password rule protects or an address rule restricts (report mode included), and `/` (`check_log_exclusions`); an excluded path is matched on the cleaned path routing judges, never the raw target, so `/api/notices/../../wp-login.php` is logged. Since 0.1.0-alpha.129 (the alpha.128 report, P1 and P2): a path through the site's front controller is judged as the path the application runs it as (`/index.php/login` is `/login`, and `/index.php` itself is refused), and an exact rule on a script covers the paths that run it with path info (`/adm.php/x`), as the rules do at the request; the managed request runs the same checks before anything is written or stored for approval (P3). Since 0.1.0-alpha.130 (the alpha.129 report, P1): a login is judged in every form the login jail counts, `/index.php` before any login path on a PHP site and alone for a query login on `/` (`/index.php?_task=login`), and path info below a `.php` script's form whatever the query. Since 0.1.0-alpha.131 (the alpha.130 report, F1): the jail counts what the loader refuses to exclude, `/index.php` with path info before a query login on `/` (`/index.php/x?_task=login`); before, those posts met `agensio-post` alone. The path-info part is written so a 16 KB line costs linear time (the one after a `.php` login cost 0.2 s on an 8 KB line of slashes before). A login whose routing parameter is in the body (Roundcube's `_task`, phpBB's `mode`) has no access-log line to count; `docs/fail2ban.md` 2 names the application's own log for it. The deletes are the main helper's `log_expire` (behind tasks, never the reader), which takes nothing from the request: it loads the configuration from disk and deletes, for each site with the key, only logrotate's numbered rotations (`NAME.N`, `NAME.N.gz`) of a log below `<log directory>/sites/` named `*.log` (`log_retention::keeps_of` checks it again, normalised), the log's directory reached from the log directory (resolved as the main file names it) one component at a time with `O_NOFOLLOW`, since the log directory is the server account's and a `sites` it replaced by a link to `/var/log` must not send root's deletes there, each entry a regular file reached with `AT_SYMLINK_NOFOLLOW`, never the current file, `[log] access`, the error log or a file two sites write (refused at load). It adds no power to a compromised server: the rotated files are the server account's own (logrotate keeps their owner), which it can already empty or rewrite; the helper only does the unlink a root-owned directory refuses that account (the start makes a site log's directory as root when the log is named before the first start). Tested in `tests/tests.cpp` (`test_access_log_privacy`: the matcher, every refusal, a rotation that is a link and a `sites` that is a link never followed, names that are not rotations untouched, the gate) and `tests/integration.sh`. |
| 59 | Where root opens the logs (2026-11-05, 0.1.0-alpha.129, `docs/configuration.md` 8c): the start opened every site's `access_log` as root with `O_CREAT`, following links, kept the descriptor across the privilege drop and `chown`ed a user site's log by path, from site files the server's account writes (`sites.d` is its, and so was `/var/log/agensio`), so a compromised server could name `/etc/passwd`, or plant a link in the log directory, and have the helper's restart hand it root's open descriptor or the file itself. Now a site file is trusted by its ownership, never by the managed marker (text that account writes): under `server.user`, one that is a regular file of the main configuration's owner, writable by nobody else, names any path, as nginx's and Apache's root-owned configuration does; any other names only `<log directory>/sites/<name>.log` (a plain name), `[log] access` or `off`, judged by the loader (`site_log_problem`), which sets the file aside otherwise; `access_log` is no longer a request field, the managed renderer writes that one path and a `site_update` writes it back over an older request's. Below the log directory every log is opened through one walk (`open_below_log_dir`): the directory resolved as named, each component below it `O_NOFOLLOW`, the file a regular one with one name (a hard link refused, for a host with `fs.protected_hardlinks` off) owned by root or the server's account, `O_NONBLOCK` against a FIFO that would hold the start, only `sites/` made (0750, the server's); the hand-over is `fchown` on the open descriptor (`LogFile::own`), never by path, for the server's files and every site's, a user site's group only when every site writing the file is that account's; the helper's `log_own` and the retention's deletes use the same walk, and `log_own` takes only `sites/<name>.log`. A site whose log cannot be opened is set aside with its file (design 26), never the whole reload; the server's own files refuse it with the one command. The package makes `/var/log/agensio` root's with the server's group and `sites/` the server's (Debian's nginx layout since CVE-2016-1247), so the account can replace nothing root or logrotate opens in the log directory, and logrotate's shipped entries stay inside it. Since 0.1.0-alpha.130 (the alpha.129 report): `-t`, which the packaged unit runs before the start, walks every log below the log directory read-only as the start does (`probe_below_log_dir`, `isolate_log_paths`), so a log the start cannot open sets its site aside in `-t` too, not at the start alone, and a site of the main file is set aside alone (the main file's other sites served), so nothing the server's account plants in `sites/` keeps the host from starting; only the server's own files, in the root-owned log directory, refuse the start; the reload's lines and health say it before the next start (`log_path_link`, `log_path_refused`); a reopen that cannot open a file again is said (error log, `logs_reopen`'s `failed`, health `log_reopen_failed`), never answered ok while the lines go on into the rotated file. What is left is root's choice, as with nginx and Apache: a log a root-written file names elsewhere is opened as named, and its directory is root's to own (the guide says so) | `services/log.*` (`open_below_log_dir`, `LogFile::open`, `own`, `LogRegistry::open_wanted`), `config.cpp` (`file_of_owner`, `Config::owner_files`, `site_log_problem`, `site_log_name`), `server.cpp` (`isolate_logs`, `own_logs`), `provision.cpp` (`log_own`), `log_retention.cpp` (`expire`), `control/sites.cpp` (`site_request_fields`, `apply_request`), `packaging/deb/postinst`, `packaging/rpm/post`, `packaging/rpm/agensio.spec`, `packaging/agensio.logrotate` | unit `test_log_placement` (the walk: a link as the file, as a directory on the way, a directory it does not make, a `..`, a FIFO, a hard link refused by name and the victim untouched, the log directory itself a link followed, `sites/` made 0750, the file 0640, a reopen through the walk, the hand-over read back; the loader: a group-writable file set aside for a log elsewhere, the owner's served, `sites/<name>.log`, `[log] access` and `off` for anyone, the plain name for everybody, no boundary without `server.user`, the main file all or nothing); `tests/isolation.sh` (a group-writable site file naming a log elsewhere set aside and served once `0644`; a link planted as a site's log in `sites/` refused, the victim untouched, the other sites served); `tests/provision.sh` as root (the packaged layout: the log directory root's, `sites/` made by the start as the server's, a no-user site's log handed over and the reloads after it; the server's three files handed over; a site file written as the server's account naming a log elsewhere set aside and nothing created, one naming `sites/` served and the server's own; a link to `/etc/passwd` planted in `sites/` refused on a reload and at a restart with `/etc/passwd` untouched; `site_create`'s `log_own`) |
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
  network peer has nothing to connect to. Its reader (row 57) holds one end of another,
  and serves nine of the requests below, the reads and the approval codes, which the main
  helper then refuses, so that no task holds them.
- **Vocabulary.** Twenty-two requests, each validated again inside the helper against the
  configuration it started with (`provision::validate`, unit tested): `account_add`
  (name by the account rule, no system accounts, no words for "none"; `useradd --system
  --no-create-home`, home in `state_dir`, `nologin`), `site_layout` (a normalised
  absolute path strictly below `sites_root`; owner must be a site account, i.e. `nologin`
  with its home in `state_dir`; the walk uses `openat(O_NOFOLLOW)` so a planted symlink is
  refused; a directory owned by anyone but root, the server or that owner is refused, so
  no site is ever handed over to another), `log_own` (a `.log` below the log directory,
  `agensio:<group> 0640`, `O_NOFOLLOW`), `pools_apply` (re-reads the configuration
  itself, runs the hosting rules, writes each site's pool file into the pool directory of its PHP
  version, a version root's main file names or a fixed layout's, never a caller's; tests each
  directory that changed with that version's own `php-fpm -t -y <conf>` and puts it back when
  php-fpm refuses it; reloads only the versions whose pools changed, by their unit, or, without
  one, by SIGUSR2 to the master named by the pid file of that version's own `php-fpm.conf` after
  `/proc/<pid>/exe` proved it that version's binary; its one argument, `phase`, is `full`, `up`
  (nothing removed, then each written pool's socket awaited, at most 30 s, and a version's files
  put back when one does not come up) or `start` (`full` plus the wait, asked once at a start
  before the listeners accept); see row 45),
  `task_run` (F13: a site's name, a task's name
  and short string parameters, nothing else; the helper loads the configuration from disk,
  finds the site, its app, directory and user, takes the command from the task table, the
  interpreter from `[control] runtimes` and the bounds from `task_limits` of that same
  root-owned file, the site's environment from its root file (row 28), creates the account's home `<state_dir>/<account>` `0700` when missing
  (never handing over a directory it did not create), and runs `tasks::execute` in a child
  that has become the account, row 26), `credentials_tighten` (row 49: a site's name only;
  the helper loads the configuration from disk, finds the site, runs the hosting rules there and
  keeps the credential paths they flag for that site under its directory, then a child that has
  become the account runs the task sweep over exactly those: `O_NOFOLLOW` walks, a link never
  followed, another account's file never changed, a file `0600`, a directory `secret_dir_mode`),
  and `app_install` (F9: a target strictly
  below `sites_root`, one source that is an https URL or a plain upload name, the
  account rule of row 19; a forked child becomes that account with `setgroups`,
  `setgid`, `setuid` and a check that root cannot be regained, then downloads or reads
  the upload, verifies the digest and unpacks with the fences of rows 20 and 21; the
  helper waits with a 20-minute deadline), and `file_copy` (F9b: the same account rule
  and child, one regular file of the site to another path of the same site, row 23;
  narrower than `app_install` in every way), `env_read` and `env_write` (a site's name
  and, for a write, names and one-line values the rules of row 28 accept; the helper finds
  the site on disk and reads or writes its root file), `auth_users_read` and
  `auth_users_write` (row 40: a site's name and, for a write, one user's change, a name of
  letters, digits and `._@+-`, `generate`, an accepted hash without `:` or blanks, a date, a
  one-line note, `locked`; never a password; the helper finds the site on disk, refuses one the
  control plane does not manage, names the file `<config dir>/auth/<site>.users` from the main
  configuration's directory, writes it root's with the server's group `0640` through a
  temporary file and a rename with `O_NOFOLLOW`, and keeps the last user of a file a rule of the
  configuration on disk reads), and `env_check` (no argument: the
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
  server to read), and `php_runtimes` (row 43, no argument: for each PHP version found on disk
  or named in root's `[php.runtimes]` of the configuration on disk, its own FPM binary with `-v`,
  `-m`, `-i` and `-tt -y <its php-fpm.conf>`, `systemctl show <its unit>` with two fixed
  properties, and `apt-cache policy phpX.Y-fpm` for the versions of the compiled release table;
  read-only, the output capped at 512 KB a program).
- **Execution.** `useradd`, `groupadd`, `systemctl`, `journalctl`, `nft`, `fail2ban-client`, `apt-cache` and the PHP versions' own `php-fpm` by absolute path, fixed argument
  list, empty environment. No shell, ever. Nothing the server sends can name a program.
- **Audit.** Every request and every refusal is written to the audit log with the
  control-socket peer's uid and the reason of the command that caused it.

What a fully compromised server process gains (through either helper; the reader adds no request to the list above): it can create `nologin` system accounts
without a home, lay out directories under `sites_root` for such accounts, regenerate pool
files the hosting rules accept (the rate-limited restart of the service went with the site_create
path that used it, 2026-11-03: a restart is root's), have an archive
of its choosing unpacked, as a site account, into an empty directory that account owns
under `sites_root` (regular files and directories only, no symlinks, no set-uid, no
program run), have one of a site's files copied to another path of the same site as
that account, and have one of the task table's fixed commands run as a site account in
that site's directory (for a Rails site that runs the site's own code, the Gemfile and
`bin/rails`, as the site's account: the capability the site's application has anyway,
and for a PHP site an archive install already gave), and read or change the environment
file of a Rails or proxy site (its secrets: what an admin may read by the owner's decision,
and what the application's own account has in its process anyway; never a name that
chooses a program), and add, change, lock or remove a managed site's password users (what an
admin does through the control socket; a hash in that file is one the server reads anyway to
verify logins, and the file stays root's `0640` at the one path the helper derives). What it cannot do: obtain a shell or
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

2026-11-07, the release check of 0.1.0-alpha.137 (7dee8ae5, response compression's step 6: answers
compressed in pieces, `CompressedBody`, the new `fuzz_compressed_body`), finished after the tag.
`scripts/fuzz-all.sh -t 300`, every target at once (twenty-five, one process each on 24 cores, five
minutes): 664.8 M runs, no finding. Before it, `fuzz_compressed_body` alone on 8 workers: two
ten-minute campaigns (the first found only its harness's empty pieces, which a source reads as its
end) and 2.9 M runs on the final code, clean. The sanitizer build (`build-asan`, GCC 14): unit and the
integration suite (850 checks; no sanitizer report): clean. The release build: unit, integration
(850, isolation 53 inside it), reload (29), pools (26), control (28), auth (51, in
`agensio-devbox:php`, after a root-owned `bench/tmp/authsuite` of a run of 2026-11-05 was removed: its
first attempt failed 48 rows on the leftover, not on the code) and Pebble (21) pass. The builds
without OpenSSL, without libxcrypt, without libbrotli and without libzstd link and pass their unit
tests; the one without libzstd first failed to compile the unit tests (a zstd frame-size check guarded
at run time only), fixed after the tag. The release workflow's `packages` job failed its unit tests on
Ubuntu 22.04: its libzstd 1.4.8 holds more at levels 5 and 6 (4.5 and 5.6 MB) than the per-level table
measured on Debian 13's 1.5.7 (3.9), and a test held the table to that; the budget now counts what the
library reports once it allocated (`StreamEncoder::run`), the table only the admission estimate, so
alpha.137's release carries only the Debian 13 and Arch packages (no Debian 12/Ubuntu .deb, no Fedora
package, no APT update) and the fix goes out as alpha.138. The A/B against alpha.136, `bench/ab.sh v0.1.0-alpha.136 -P
-C` in the devbox (a Dart tool held the upstream's port 9100 on the host): 0.930 to 1.054 on every
existing row (`ab-20261107-000304.md`), the new 512 KB row the cost of compressing it.

2026-11-05, the release check of 0.1.0-alpha.129, before the tag, on the tree with the log placement (row 59)
and the alpha.128 report's three fixes (row 58). The release build: unit, integration (every row; h2spec h2c 145 of
146, the one the suite tolerates), the file tools' (27), tasks (135), reload (29), isolation (48), auth (49,
`--network none`), control (28), pools (26), the provisioning helper's (68), protection (33), trash (27), Pebble
(21), the package (14, with the log directory's new owners) and the cookbook (553) pass; the builds without OpenSSL
and without libxcrypt link and pass their unit tests. The sanitizer build (`build-asan`, GCC 14): unit, the
integration suite and Pebble (21) clean, no sanitizer report in what the runs wrote; its first unit run found a
stack-use-after-scope in the new `log_view_of` (a temporary's `items()` iterated after its death), fixed before
this run. `scripts/fuzz-all.sh -t 300`, every target at once (twenty-four, one process each on 24 cores, five
minutes): 524.2 M runs, no finding, no timeout. The A/B against alpha.128, `bench/ab.sh v0.1.0-alpha.128 -r 3`
in the devbox (`ab-20261105-155529.md`): 0.981 to 1.019, as expected of changes with no request-path code (the plain 10 MB row's 1.019 is one round of three; the other two were level).

| target | runs | edges | result |
|---|---|---|---|
| fuzz_archive | 11.35 M | 641 | clean |
| fuzz_auth_users | 18.45 M | 497 | clean |
| fuzz_chunked | 104.94 M | 63 | clean |
| fuzz_cron_lines | 12.12 M | 120 | clean |
| fuzz_dotenv | 1.25 M | 2359 | clean |
| fuzz_fcgi | 59.29 M | 96 | clean |
| fuzz_fields | 3.85 M | 588 | clean |
| fuzz_h2_conn | 0.72 M | 11979 | clean |
| fuzz_hpack | 2.46 M | 529 | clean |
| fuzz_hpack_roundtrip | 0.36 M | 466 | clean |
| fuzz_http_head | 59.00 M | 152 | clean |
| fuzz_json | 5.83 M | 550 | clean |
| fuzz_log_line | 5.13 M | 768 | clean |
| fuzz_parser | 41.68 M | 240 | clean |
| fuzz_path | 8.21 M | 236 | clean |
| fuzz_php_constraint | 10.68 M | 760 | clean |
| fuzz_qpack | 6.60 M | 646 | clean |
| fuzz_quic_conn | 0.47 M | 1555 | clean |
| fuzz_quic_packet | 24.49 M | 217 | clean |
| fuzz_redirect | 4.54 M | 1216 | clean |
| fuzz_refuse | 3.05 M | 874 | clean |
| fuzz_response_headers | 0.51 M | 3357 | clean |
| fuzz_sql_scan | 2.34 M | 158 | clean |
| fuzz_transport_params | 136.82 M | 211 | clean |

2026-11-04, the release check of 0.1.0-alpha.124, after the tag (cefe191e), on the tag plus the fixes
after it: two fuzz targets for what a site's account writes and the root helper reads (`fuzz_dotenv`, the
`.env` reader with every change read back and the masking of its diff; `fuzz_cron_lines`, the crontab
reader of the scheduler's visibility), and the four bugs reading the code for them found in the tag's
code, each shown failing there by a unit test built on the tag (a rotation removed the name, `export` lost
on a short name, a variable appended inside a quote never closed, a value's line shown as a name in a
masked diff, plain or commented). The release build: unit, integration (830), the file tools' (24),
tasks (122), reload (29), isolation (45), auth (49, `--network none`), control (28), pools (26), the
provisioning helper's (57), protection (33) and Pebble (21) pass; the builds without OpenSSL and without
libxcrypt link and pass their unit tests. The sanitizer build (`build-asan`, GCC 14): unit, the
integration suite (830) and Pebble (21) clean, no sanitizer report in what the runs wrote. The
integration suite first failed one check on both builds, `hsts_ramp` missing: the suite's 30-day
certificates were made again a week before they expired, and from 14 days left (2026-11-03 23:39 UTC)
health calls one `certificate_expiring`, which holds back the findings that need a certificate without
trouble; the suite now makes them again fifteen days before. The two new targets for an hour each, one
process: `fuzz_dotenv` 17.59 M runs, 2413 edges, `fuzz_cron_lines` 271.7 M runs, 120 edges, clean.
`scripts/fuzz-all.sh -t 300`, every target at once (twenty-four, one process each on 24 cores, five
minutes): 524.0 M runs, no finding, no timeout. The A/B against alpha.123, `bench/ab.sh
v0.1.0-alpha.123 -r 3` in the devbox (`ab-20261104-021401.md`): 0.995 to 1.020, as expected of
changes with no request-path code.

| target | runs | edges | result |
|---|---|---|---|
| fuzz_archive | 15.86 M | 642 | clean |
| fuzz_auth_users | 27.87 M | 497 | clean |
| fuzz_chunked | 96.07 M | 63 | clean |
| fuzz_cron_lines | 13.38 M | 120 | clean |
| fuzz_dotenv | 1.32 M | 2339 | clean |
| fuzz_fcgi | 60.87 M | 96 | clean |
| fuzz_fields | 2.91 M | 588 | clean |
| fuzz_h2_conn | 0.77 M | 11919 | clean |
| fuzz_hpack | 2.31 M | 529 | clean |
| fuzz_hpack_roundtrip | 0.34 M | 466 | clean |
| fuzz_http_head | 55.97 M | 152 | clean |
| fuzz_json | 6.28 M | 550 | clean |
| fuzz_log_line | 5.18 M | 775 | clean |
| fuzz_parser | 36.93 M | 240 | clean |
| fuzz_path | 7.85 M | 236 | clean |
| fuzz_php_constraint | 11.05 M | 760 | clean |
| fuzz_qpack | 7.65 M | 646 | clean |
| fuzz_quic_conn | 0.47 M | 1556 | clean |
| fuzz_quic_packet | 21.27 M | 217 | clean |
| fuzz_redirect | 4.93 M | 1231 | clean |
| fuzz_refuse | 3.07 M | 874 | clean |
| fuzz_response_headers | 0.51 M | 3367 | clean |
| fuzz_sql_scan | 2.73 M | 158 | clean |
| fuzz_transport_params | 138.42 M | 211 | clean |

2026-11-03, the release check of 0.1.0-alpha.121 (dce3ad8f, the alpha.120 report's fixes: a flag
per listen key, the listen findings' fix, the file tools' dry run), the suites before the tag and the
sanitizer, fuzz and A/B items after it, so that none shared the cores with the release build. The
release build: unit, integration (828), the file tools' (14, as root), reload (29: one row had to
follow the per-key flag, it expected both keys named on a reload that added `listen_plain`), isolation
(45), auth (49, `--network none`), control (28), pools (26), the provisioning helper's (57) and
Pebble (21) pass; the builds without OpenSSL and without libxcrypt link and pass their unit tests.
The sanitizer build (`build-asan`, GCC 14): unit and the integration suite (828) clean, no sanitizer
report in what the run wrote. `scripts/fuzz-all.sh -t 60`, every target at once (twenty-two, one
minute each): 120.8 M runs, no finding. The A/B against alpha.120, `bench/ab.sh v0.1.0-alpha.120 -r
3` in the devbox (`ab-20261103-141516.md`): 0.950 to 1.018, the static rows within the noise band,
as expected of a change with no request-path code (the 0.950 is the plain 10 MB stream's round-to-
round spread). The first A/B attempt ran on the host, where port 8080 is a production container's,
and stopped before measuring.

2026-11-03, the release check of 0.1.0-alpha.120, before the tag. `scripts/fuzz-all.sh -t 300`,
every target at once (twenty-two, one process each on 24 cores, five minutes): 519.7 M runs, no
finding, no timeout. The fuzz build had stopped compiling with the access log's format step
(2026-11-02: `fuzz_h2_conn` read the `json` field that `vhost_combined` replaced, so the script built
nothing), fixed before this run. The sanitizer build (`build-asan`, GCC 14): unit, the integration
suite (827 checks, the HTTP/3 attack suite with Retry auto and always among them; no sanitizer
report in any of the 17,389 files the run wrote under bench/tmp), the Pebble suite (21): clean. The
release build: unit, integration (827), reload (25), auth (49, `--network none`), pools (26), control
(28), isolation (45), protection (33), the provisioning helper's (57) and Pebble (21) pass; the builds
without OpenSSL and without libxcrypt link and pass their unit tests (the one without OpenSSL first
failed to compile on the branch for the server's own TLS address without a site, which named the
listener's TLS context: guarded before this run). The A/B against alpha.119, `bench/ab.sh
v0.1.0-alpha.119 -P -A -2 -r 3`, ran twice (`ab-20261103-001708.md` beside VS Code's C++ indexer at a
full core, re-indexing the A/B worktree, 0.922 to 1.079; `ab-20261103-004339.md` with the fuzz
processes still winding down at load 12.9, 0.867 to 1.122), each with its first round polluted on a
few rows; the quiet check of the plain 1 KB and the access rows at five rounds
(`ab-20261103-005912.md`) is 0.980 to 1.015, the `baseline` row that both runs had put at 1.03 to
1.06 at 1.008, and nothing of alpha.120 runs on a static request's path. The HTTP/3 rows
(`ab-20261103-002954.md`, `-3 -r 3`): 0.964 to 1.055, the 1.055 the sixty-four-stream row with one
round of three at 0.82 against 0.75 and 0.70.

| target | runs | edges | result |
|---|---|---|---|
| fuzz_archive | 15.98 M | 645 | clean |
| fuzz_auth_users | 17.66 M | 499 | clean |
| fuzz_chunked | 121.34 M | 63 | clean |
| fuzz_fcgi | 59.76 M | 96 | clean |
| fuzz_fields | 4.43 M | 589 | clean |
| fuzz_h2_conn | 0.69 M | 11926 | clean |
| fuzz_hpack | 2.16 M | 529 | clean |
| fuzz_hpack_roundtrip | 0.35 M | 466 | clean |
| fuzz_http_head | 49.12 M | 152 | clean |
| fuzz_json | 7.16 M | 551 | clean |
| fuzz_log_line | 5.92 M | 770 | clean |
| fuzz_parser | 35.81 M | 240 | clean |
| fuzz_path | 7.69 M | 236 | clean |
| fuzz_php_constraint | 12.25 M | 758 | clean |
| fuzz_qpack | 7.14 M | 646 | clean |
| fuzz_quic_conn | 0.45 M | 1556 | clean |
| fuzz_quic_packet | 19.00 M | 217 | clean |
| fuzz_redirect | 4.72 M | 1248 | clean |
| fuzz_refuse | 3.17 M | 874 | clean |
| fuzz_response_headers | 0.52 M | 3359 | clean |
| fuzz_sql_scan | 2.88 M | 159 | clean |
| fuzz_transport_params | 141.48 M | 211 | clean |

2026-11-01, the release check of 0.1.0-alpha.118, before the tag. `scripts/fuzz-all.sh -t 300`,
every target at once (twenty-two, one process each on 24 cores, five minutes): 526.6 M runs, no
finding, no timeout. The fuzz build had stopped linking with response compression's step 2
(2026-10-30: the fuzzing copy of the core took the core's definitions but not libzstd and
libbrotlienc, so `fuzz_h2_conn` and `fuzz_response_headers` failed to link and the script ran
nothing), fixed before this run. The sanitizer build (`build-asan`, GCC 14): unit, the integration
suite (797 checks, the HTTP/3 attack suite with Retry auto and always among them; no sanitizer line in
the 70 logs the run wrote), the Pebble suite (21): clean. The release build: unit, integration (797),
reload (25), auth (50, with a network: `--network none` leaves loopback alone and two plain-HTTP rows
skip), pools (26), control (27) and Pebble (21) pass; the builds without OpenSSL, without libxcrypt,
without libbrotli and libzstd, and without zlib link and pass their unit tests, and the one without
brotli and zstd refuses a `codings` list naming brotli with the package and offers gzip alone by
default. The A/B against alpha.117: `bench/ab.sh v0.1.0-alpha.117 -P -A -2 -r 3` (`ab-20261031-221151.md`)
ran beside KDE's file indexer and VS Code's C++ indexer, both kept busy by the A/B worktrees under
bench/tmp, and put three rows at 1.07 to 1.12; on a quiet machine, by hand (`release-118-rows-20261101.md`),
they are 1.005 to 1.013, and plain HTTP 1 KB read 1.022 with every new round above every base round. That
new side was `build/agensio`, configured with the HttpArena handler, which `bench/ab.sh` takes as its new
side whatever the base's options: built alike (`release-118-clean-20261101.md`), alpha.118 against
alpha.117 is 1.004 to 1.016 on four rows with the same instructions and instruction-cache misses per
request (the arena handler's code had moved the layout: one source, 279 to 292 misses built one way, 309
to 316 the other). The HTTP/3 rows (`ab-20261031-225221.md`, `-3 -r 3`): 1.001 to 1.021; that run's
plain 100 KB row at 1.066 is 1.010 by hand.

| target | runs | edges | result |
|---|---|---|---|
| fuzz_archive | 16.46 M | 646 | clean |
| fuzz_auth_users | 25.18 M | 498 | clean |
| fuzz_chunked | 97.24 M | 63 | clean |
| fuzz_fcgi | 63.85 M | 96 | clean |
| fuzz_fields | 3.83 M | 591 | clean |
| fuzz_h2_conn | 0.71 M | 11760 | clean |
| fuzz_hpack | 2.21 M | 528 | clean |
| fuzz_hpack_roundtrip | 0.34 M | 466 | clean |
| fuzz_http_head | 53.29 M | 152 | clean |
| fuzz_json | 6.62 M | 550 | clean |
| fuzz_log_line | 5.39 M | 725 | clean |
| fuzz_parser | 44.13 M | 240 | clean |
| fuzz_path | 7.64 M | 236 | clean |
| fuzz_php_constraint | 12.96 M | 760 | clean |
| fuzz_qpack | 7.52 M | 646 | clean |
| fuzz_quic_conn | 0.48 M | 1551 | clean |
| fuzz_quic_packet | 21.39 M | 217 | clean |
| fuzz_redirect | 4.99 M | 1252 | clean |
| fuzz_refuse | 3.27 M | 874 | clean |
| fuzz_response_headers | 0.53 M | 3352 | clean |
| fuzz_sql_scan | 2.95 M | 158 | clean |
| fuzz_transport_params | 145.60 M | 211 | clean |

2026-10-25, the release check of 0.1.0-alpha.116, before the tag. `scripts/fuzz-all.sh -t 300`,
every target at once (twenty-two, one process each on 24 cores, five minutes): 553 M runs, no
finding, no timeout. Before it, on their own: `fuzz_h2_conn` ten minutes on eight processes (26.7 M
runs) after the stalled-writer fix, `fuzz_qpack` ten minutes on six (269.3 M) after the static-table
fix, both clean. The sanitizer build (`build-asan`, GCC 14): unit, the integration suite (777 checks,
no sanitizer line), the HTTP/3 attack suite with Retry auto and always, the Pebble suite (21): clean.
The release build: unit, integration (777), reload (25), auth (50), pools (26), control (27; its MCP
counts had stayed at sixteen read tools since `php_versions` was added in alpha.107, fixed) and Pebble
(21) pass; the builds without OpenSSL and without libxcrypt link and pass their unit tests.
The A/B against alpha.115 (`bench/ab.sh v0.1.0-alpha.115 -2 -3 -r 3`, `ab-20261025-210334.md`): flat
but the ten-stream HTTP/2 row over TLS at 1.070, which five rounds of the HTTP/2 rows put at 0.993
(`ab-20261025-211135.md`, every row 0.964 to 1.007).

| target | runs | edges | result |
|---|---|---|---|
| fuzz_archive | 12.89 M | 640 | clean |
| fuzz_auth_users | 20.87 M | 497 | clean |
| fuzz_chunked | 100.69 M | 63 | clean |
| fuzz_fcgi | 55.18 M | 96 | clean |
| fuzz_fields | 6.67 M | 571 | clean |
| fuzz_h2_conn | 0.78 M | 11,826 | clean |
| fuzz_hpack | 2.60 M | 529 | clean |
| fuzz_hpack_roundtrip | 0.37 M | 466 | clean |
| fuzz_http_head | 64.89 M | 152 | clean |
| fuzz_json | 7.53 M | 554 | clean |
| fuzz_log_line | 5.58 M | 746 | clean |
| fuzz_parser | 48.14 M | 240 | clean |
| fuzz_path | 11.07 M | 235 | clean |
| fuzz_php_constraint | 16.34 M | 771 | clean |
| fuzz_qpack | 6.10 M | 646 | clean |
| fuzz_quic_conn | 0.54 M | 1,551 | clean |
| fuzz_quic_packet | 22.88 M | 217 | clean |
| fuzz_redirect | 4.88 M | 1,232 | clean |
| fuzz_refuse | 3.50 M | 875 | clean |
| fuzz_response_headers | 0.59 M | 3,356 | clean |
| fuzz_sql_scan | 3.10 M | 158 | clean |
| fuzz_transport_params | 158.25 M | 211 | clean |

2026-10-21, a new target before its commit: `fuzz_php_constraint` (the Composer constraints and the
`composer.json` and `version.php` readers of row 46), twenty minutes alone on 24 processes
(`scripts/fuzz-all.sh -t 1200 php_constraint`, ASan and UBSan, clang 19): 1,187.50 M runs, 767 edges,
a corpus of 1,471 inputs, no finding, no timeout. The next release check runs it with the other
twenty-one.

2026-10-17, the release check of 0.1.0-alpha.97 (97cef77), run after the tag. Two hours of fuzzing
with `scripts/fuzz-all.sh -t 600`, twelve rounds of ten minutes on one corpus that grew from round to
round, every target at once (twenty-one, one process each on 24 cores), the container capped at 13 GB
(8.2 GB used): 15.1 G runs, no finding, no timeout, no sanitizer line in any log, the coverage still
growing in the second hour (`fuzz_response_headers` 2,955 to 3,049 edges, `fuzz_archive` 642 to 660,
`fuzz_h2_conn` 11,293 to 11,341). The unit tests, the integration suite (737 checks) and the Pebble
suite on the sanitizer build (`build-asan`, GCC 14): clean, no report in the suite's output or any
server's own. The release build: unit, reload (24), auth (48), pools (26), control (27) and Pebble
(21) pass; the builds without OpenSSL and without libxcrypt link and pass their unit tests. The A/B
against alpha.96 (`ab-20261017-002309.md`, `ab-20261017-003454.md` for HTTP/3): flat.

| target | runs | edges | result |
|---|---|---|---|
| fuzz_archive | 477.93 M | 660 | clean |
| fuzz_auth_users | 635.06 M | 499 | clean |
| fuzz_chunked | 1,936.66 M | 63 | clean |
| fuzz_fcgi | 1,686.63 M | 96 | clean |
| fuzz_fields | 356.23 M | 579 | clean |
| fuzz_h2_conn | 13.20 M | 11,341 | clean |
| fuzz_hpack | 60.12 M | 530 | clean |
| fuzz_hpack_roundtrip | 9.13 M | 466 | clean |
| fuzz_http_head | 1,664.31 M | 152 | clean |
| fuzz_json | 357.94 M | 557 | clean |
| fuzz_log_line | 184.28 M | 753 | clean |
| fuzz_parser | 1,487.91 M | 240 | clean |
| fuzz_path | 559.68 M | 236 | clean |
| fuzz_qpack | 189.00 M | 647 | clean |
| fuzz_quic_conn | 12.24 M | 1,581 | clean |
| fuzz_quic_packet | 969.92 M | 217 | clean |
| fuzz_redirect | 166.23 M | 1,230 | clean |
| fuzz_refuse | 97.48 M | 875 | clean |
| fuzz_response_headers | 7.92 M | 3,049 | clean |
| fuzz_sql_scan | 209.78 M | 129 | clean |
| fuzz_transport_params | 4,024.47 M | 211 | clean |

2026-10-16, the release check of 0.1.0-alpha.96 (4819aab), which also covers alpha.94 and alpha.95:
both were tagged with no run recorded here. Every target five minutes on its corpus
(`scripts/fuzz-all.sh -t 300`, ASan and UBSan, clang), twenty targets: no finding, no timeout, no
sanitizer line in any log. The unit tests, the integration suite (735 checks) and the Pebble suite
on the sanitizer build (`build-asan`, GCC 14): clean, no report in the suite's output or in any
server's own output file. The release build: unit, reload (24), auth (48), pools (26), control (27)
and Pebble (21) suites pass; the reload suite first failed on a `bench/tmp/reload` left by a run as
root, which the account the suite runs as could not write (removed, then 24 of 24). The builds
without OpenSSL and without libxcrypt link and pass their unit tests. The A/B against alpha.95
(`ab-20261016-022440.md` with every row set but HTTP/3, `ab-20261016-025547.md` for HTTP/3): flat.

| target | runs | edges | result |
|---|---|---|---|
| fuzz_archive | 21.62 M | 641 | clean |
| fuzz_auth_users | 28.10 M | 498 | clean |
| fuzz_chunked | 206.05 M | 63 | clean |
| fuzz_fcgi | 102.48 M | 96 | clean |
| fuzz_fields | 15.14 M | 571 | clean |
| fuzz_h2_conn | 1.13 M | 11,277 | clean |
| fuzz_hpack | 3.92 M | 529 | clean |
| fuzz_hpack_roundtrip | 0.45 M | 466 | clean |
| fuzz_http_head | 109.91 M | 152 | clean |
| fuzz_json | 8.64 M | 554 | clean |
| fuzz_log_line | 8.84 M | 725 | clean |
| fuzz_parser | 75.74 M | 240 | clean |
| fuzz_path | 19.74 M | 236 | clean |
| fuzz_qpack | 11.68 M | 647 | clean |
| fuzz_quic_conn | 0.86 M | 1,545 | clean |
| fuzz_quic_packet | 46.10 M | 217 | clean |
| fuzz_redirect | 9.68 M | 1,230 | clean |
| fuzz_refuse | 5.03 M | 875 | clean |
| fuzz_response_headers | 1.50 M | 2,964 | clean |
| fuzz_transport_params | 284.96 M | 211 | clean |

2026-10-14, the security pass over the response headers (`[[site.response_headers]]`, alpha.89 to
alpha.92): every target twenty minutes on its corpus, twelve at once (`scripts/fuzz-all.sh -t 1200`),
ASan and UBSan, clang; the new `fuzz_response_headers` among them. No finding, no timeout, no
sanitizer line in any log. Then `fuzz_h2_conn` with the response header rules in its site and a
head over one frame on `b.test`'s `/dir` (fifteen minutes on ten processes, `-fork=10`): 2.34 M runs,
11,449 edges, clean, after the CONTINUATION fix of alpha.93; a head over one frame was a
`FRAME_SIZE_ERROR` before it (found by the integration check, not the fuzzer, whose site had no head
that large). The unit tests under ASan and UBSan (`build-asan`, GCC 14) found a use after free in
three of the tests themselves (a pointer into the vector `health_findings` returns, kept past the
temporary), fixed. The integration suite on that build found one in the server: a heap use after
free in `~Server` at every stop of a server with TLS (the certificate watch's timer, declared before
`workers_`, destroyed after worker 0's context; the HTTP/3 attack suite had counted the same report
as a failed row), fixed in alpha.93 with a check that the main server stops with exit 0 and no
report; and two checks that failed on the timing of a pipe (`-t | grep -q` under `pipefail`), not on
the server, rewritten with two more of the same form. Rerun after the fixes: the unit tests and the
integration suite (716 checks, the HTTP/3 attack suite with both Retry modes among them) pass on
that build with no report in any server's stderr. The builds without OpenSSL and without libxcrypt
link and pass their unit tests, the first after a test fix: since alpha.84 one check there expected
a TLS site among the canonical probes, which that build leaves out on purpose.

| target | runs | edges | result |
|---|---|---|---|
| fuzz_parser | 368.92 M | 240 | clean |
| fuzz_chunked | 870.98 M | 63 | clean |
| fuzz_fcgi | 492.30 M | 96 | clean |
| fuzz_http_head | 456.89 M | 152 | clean |
| fuzz_path | 96.18 M | 236 | clean |
| fuzz_json | 51.20 M | 557 | clean |
| fuzz_archive | 90.83 M | 646 | clean |
| fuzz_hpack | 12.35 M | 530 | clean |
| fuzz_hpack_roundtrip | 1.05 M | 466 | clean |
| fuzz_qpack | 41.18 M | 647 | clean |
| fuzz_quic_packet | 221.94 M | 217 | clean |
| fuzz_transport_params | 1,137.38 M | 211 | clean |
| fuzz_quic_conn | 3.36 M | 1,560 | clean |
| fuzz_refuse | 10.08 M | 875 | clean |
| fuzz_redirect | 20.52 M | 1,230 | clean |
| fuzz_fields | 51.07 M | 610 | clean |
| fuzz_auth_users | 95.56 M | 498 | clean |
| fuzz_log_line | 21.63 M | 753 | clean |
| fuzz_response_headers (new) | 5.00 M | 2,905 | clean |
| fuzz_h2_conn | 3.35 M, then 2.34 M in 15 min on 10 with the rules | 10,519, 11,449 | clean |

2026-10-12, the campaign after the UBSan correction and the five HTTP/2 fixes (d85b590), with
undefined behaviour fatal for the first time: every target thirty minutes on its corpus, one
process each and eighteen at once (`scripts/fuzz-all.sh -t 1800 -j 18`), ASan and UBSan, clang
19; then the two connection fuzzers an hour each on ten processes (libFuzzer's `-fork=10`) from
those corpora. No finding, no timeout, no UBSan line in any log. The machine was not idle (other
work held about four of its 24 threads). Coverage counts are not comparable with the rows before
this date: the instrumentation changed with `-fno-sanitize-recover`.

| target | runs | edges | result |
|---|---|---|---|
| fuzz_parser | 323.40 M | 240 | clean |
| fuzz_chunked | 766.40 M | 63 | clean |
| fuzz_fcgi | 402.64 M | 96 | clean |
| fuzz_http_head | 462.93 M | 152 | clean |
| fuzz_path | 96.17 M | 236 | clean |
| fuzz_json | 57.34 M | 557 | clean |
| fuzz_archive | 119.12 M | 646 | clean |
| fuzz_hpack | 16.46 M | 529 | clean |
| fuzz_hpack_roundtrip | 1.00 M | 464 | clean |
| fuzz_qpack | 40.14 M | 645 | clean |
| fuzz_quic_packet | 201.92 M | 217 | clean |
| fuzz_transport_params | 1,096.14 M | 211 | clean |
| fuzz_quic_conn | 3.18 M, then 33.99 M in 1 h on 10 | 1,559, 1,579 | clean |
| fuzz_refuse | 10.37 M | 875 | clean |
| fuzz_fields | 67.61 M | 574 | clean |
| fuzz_auth_users | 195.05 M | 498 | clean |
| fuzz_log_line | 21.39 M | 750 | clean |
| fuzz_h2_conn | 3.74 M, then 18.26 M in 1 h on 10 | 10,382, 10,566 | clean |

2026-10-12, `fuzz_h2_conn`: the HTTP/2 connection as an h2c listener runs it, over a socket
pair, in front of the server's own dispatcher, static handler, cache and logs, a proxy and a
FastCGI location whose origins are not there, and time moved by the fuzz-build hook
`Http2Connection::fuzz_age` (the release code section byte-identical with and without it).
Beyond ASan and UBSan it checks what the server sends against RFC 9113 and 7541 and that the
connection ends with its client (`docs/design-http2.md` 8.2). The first run, five minutes on
twenty processes, made 8.0 M runs to 15,319 edges and stopped 1,676 times in five classes;
two of them were the target's own checks being wrong (a HEAD answer carries content-length
and no body, read now from the request block the client really sent; an RST_STREAM answering
a PRIORITY that makes an idle stream depend on itself is what h2spec 5.3.1 expects), the other
three came from two server bugs, and the log held a third, UBSan's `memcpy` report (1,675
times; not yet fatal in that build). With those fixed in the working tree every one of the
1,676 inputs replayed clean but eleven, a fourth bug, and the twenty-minute run after it
(41.3 M runs, 15,376 edges) found a fifth in its last seconds. The five, each fixed in its own change of alpha.72 and kept
as an input under `tests/fuzz/regressions/h2_conn/`: a closed stream queued again by a
WINDOW_UPDATE, a SETTINGS window change or a pull completion, then pooled while the writer's
list still held it (a blank 200 head on the stream just reset, the queue behind it cut off, a
freed stream in the list when the pool was full or shed); a second GOAWAY naming a higher last
stream id than the first (RFC 9113 6.8); a HEADERS served on a stream the server had reset
while idle (RFC 9113 5.1); `memcpy` from a null pointer in the constructor for an empty
hand-over (UBSan); and a WINDOW_UPDATE of zero for an empty DATA frame while a window was low,
a connection error for the client on stream 0 (RFC 9113 6.9).

2026-10-12, a correction: until today UBSan in the fuzz builds printed its report and let the
target go on, so libFuzzer exited 0, left no input, and `scripts/fuzz-all.sh` called the run
clean. The log of the 2026-10-11 campaign holds four reports from `fuzz_log_line`, all signed
overflow in `parse_since` (`control/loglines.cpp` lines 141 and 155: a relative time with too
many digits, or too large for its unit); the first five-minute run of the new targets that day
also had a JSON log line's `status` of 1e30 converted to `int` (line 107). Its row below said
clean. The logs kept since 2026-10-07 hold no other report but the JSON finding of that day,
which its assertion caught and the record names. Every fuzz
target is now built with `-fno-sanitize-recover=undefined`: undefined behaviour stops the run and
leaves its input, as a memory error does (three inputs that reach those lines exit 1 now, 0
before). The parser was fixed the same day (a relative time further back than a century is the
beginning, a status outside 0 to 999 is 0); the three inputs are its regression files, and
`fuzz_log_line` then ran 2.75 M inputs in 120 s from the campaign's corpus with no report.

2026-10-11, four new targets for the parsers the audit's list did not reach (alpha.72):
`fuzz_refuse` (patterns compiled, capped and indexed as the loader does, then paths through the
normaliser: the indexed set's answer is the answer of every pattern alone, and the hit it names
matches), `fuzz_fields` (`Range` against four body sizes, `If-Range`, `Accept-Encoding` and its
q values, `X-Forwarded-For` and `-Proto` behind three trusted ranges, CIDRs: a satisfiable range
lies inside the body, an encoding is never one the entry lacks, the client address parses back to
the one recorded, a parsed CIDR contains its own address), `fuzz_auth_users` (the htpasswd lines
with `expires=` and `note=`, the dates, the Basic field: names without `:` or a newline) and
`fuzz_log_line` (the three log formats `logs` reads, moved for it from `control/commands.cpp`
to `control/loglines.*`; the escaped text is valid UTF-8, unchanged when the line was, and
escaping it again changes nothing; `since`). `fuzz_auth_users` is built only with libxcrypt.
Every target five minutes on its corpus, twelve at once, ASan and UBSan, clang 19:

| target | runs | edges | result |
|---|---|---|---|
| fuzz_parser | 72.48 M | 286 | clean |
| fuzz_chunked | 193.80 M | 72 | clean |
| fuzz_fcgi | 79.82 M | 133 | clean |
| fuzz_http_head | 97.85 M | 195 | clean |
| fuzz_path | 13.53 M | 305 | clean |
| fuzz_json | 7.46 M | 646 | clean |
| fuzz_archive | 23.38 M | 808 | clean |
| fuzz_hpack | 3.09 M | 708 | clean |
| fuzz_hpack_roundtrip | 0.48 M | 601 | clean |
| fuzz_qpack | 14.07 M | 859 | clean |
| fuzz_quic_packet | 38.13 M | 192 | clean |
| fuzz_transport_params | 259.78 M | 185 | clean |
| fuzz_quic_conn | 0.75 M | 2,350 | clean |
| fuzz_refuse | 4.25 M | 1,135 | clean |
| fuzz_fields | 13.35 M | 710 | clean |
| fuzz_auth_users | 32.93 M | 609 | clean |
| fuzz_log_line | 4.52 M | 901 | four UBSan reports, missed (2026-10-12 above) |

2026-10-13, `fuzz_redirect` (alpha.82, `[[site.redirect]]`, `core/redirect.hpp`): rules compiled as
the loader does, request targets normalised and looked up as the dispatcher does. The index must
agree with a scan of every rule for the most specific one, and every Location written holds no
control character, space or backslash; a relative one never starts with `//` or `/\` (another host
to a browser), an absolute one starts with exactly the target's origin and then `/`, so no path or
query moves it to another host. 120 s beside `fuzz_refuse` and `fuzz_path`, three at once, ASan and
UBSan (`scripts/fuzz-all.sh -t 120 -j 3 redirect refuse path`): `fuzz_redirect` 3.46 M runs and
1,212 edges, `fuzz_refuse` 2.11 M, `fuzz_path` 4.08 M, all clean.

2026-10-09, the password users (step 4b of design section 25): the unit tests, `tests/auth.sh`
(27 checks) and `tests/provision.sh` with the sanitizer build, its reports kept with
`ASAN_OPTIONS=log_path=` since the helper suite's own directory is removed at its end. One
finding, older than the step: `Server::restart_timer_` and `trash_timer_` were declared before
`workers_`, so at every exit with the helper running (which arms the trash timer) the timer was
destroyed after its worker's `io_context` had freed the timer service, a heap use-after-free in
`~basic_waitable_timer`. Moved after `workers_`; `tests/provision.sh` now stops the server
with SIGTERM, waits for it and fails on any sanitizer report in its stderr (it failed before
the move, passes after). `AcmeManager` holds a timer the same way but resets it in `stop()`,
which `Server::stop()` calls first.

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
`tests/fuzz/regressions/<target>/` by hand. It sizes the run to the machine (2026-10-17): as many
processes as the cores, or as the free memory holds at 600 MB each, every target at once when they
fit, so the campaign takes one `-t`, and the processes left over shared among the targets through
libFuzzer's `-jobs` on one corpus each: a single target after a parser change gets them all
(`scripts/fuzz-all.sh -t 30 sql_scan` ran 24 processes at 1.2 M runs a second, against 47 k on one
core). `-j` and `-w` set the targets at once and the processes per target by hand. The weekly CI job
(`.github/workflows/fuzz.yml`) runs the same script and the sanitizer build on Ubuntu 24.04, without
`fuzz_quic_conn`.


## HTTP/2 (phase G)

The request-path threats of HTTP/2 (Rapid Reset, MadeYouReset, CONTINUATION floods, HPACK
bombs and the 2026 HTTP/2 Bomb, slow reads and window dribbles, PING, SETTINGS and empty
frame floods, priority trees, request smuggling over the HTTP/1.1 downgrade) and the
bound each one meets are the table of `docs/design-http2.md` section 8; the limits are
constants at the top of `src/http2/connection.hpp` and derive from `max_header_size`,
`max_requests_per_connection`, `idle_timeout`, `body_timeout` and the body limits. Fuzz
record: `fuzz_hpack` (decoder, persistent decoder, encoder round trip, Huffman round trip) and
`fuzz_h2_conn` (the connection itself, 2026-10-12, recorded below).
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
aioquic is installed) asserts twenty-four rows of the design's table against the release and
sanitizer builds (and a twenty-fifth on request, `handshake-budget`: 1,024 half-open clients
held to the deadline): the handshake deadline (a half-open connection silent or fed
undecryptable packets, and one fed Initial packets that open, retired at `idle_timeout` of its
creation), new connections over `server.max_connections` refused with CONNECTION_REFUSED
while TCP holds the slots, the handshake, Retry in both modes, a garbage token, a key update and a
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
