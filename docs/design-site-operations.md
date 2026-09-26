# Design: applications beyond PHP through the control plane (F12 files, F13 tasks, F14 services)

Status: decided with the owner on 2026-09-26 (section 10 lists every decision). F13, the
first step of section 9, was built the same day (section 12 says what changed from this
plan and what the work found); the rest follows the order of section 9, one step per
commit with its tests, its documentation and its security-page rows. Written from
the live report against 0.1.0-alpha.23 (`ag5.edoc.gr`, Rails 8 under Puma behind
`app = "proxy"` with its own account `ag5`, host debmain) and the owner's requirements:
an MCP client in the admin role installs a Rails application, runs its commands, manages
the site's files and can delete a site with its files, all as the site's account and never
as root, without a terminal. Findings 1 and 2 of the report were fixed the same day (the
pool derivation, `CHANGELOG.md` alpha.24).

## 0. The report against the code

| report | verdict | where |
|---|---|---|
| 1. `php_tmp_missing` at error severity on a proxy site with a user | confirmed, fixed | `parse_pool` (`config.cpp`) derived a pool for every site with `user` and no `php.socket`, whatever its `app`; health then looked for the PHP directory of a Rails site. Now only a PHP preset, or a `handler = "fastcgi"` location without a socket of its own, derives one; pool keys on any other site are refused naming the rule |
| 2. `pools_stale` after creating a proxy site | confirmed, fixed | the same cause: `generated_pools` listed the Rails site, so `write_pools` wanted to write `agensio-ag5.conf` and reload php-fpm, and `agensio pools` would have done exactly that. `site_create` itself skipped the pool for a proxy site (`finish_pool` tests the app), which is why no file existed: the loader and the control plane disagreed |
| 3. no finding for an unreachable upstream | confirmed | `health` (`control/commands.cpp`) has no probe; section 6 |
| 4. what `root` means on a proxy site | answered | it is the site's directory, and nothing is served from it: the preset's `/` location is `handler = "proxy"` (`apply_preset`), so the static handler never sees that root. It is what `site_install` fills (`project_root`), what the hosting rules check (owner, mode, secrets), what `site_create` lays out `2750 user:<server group>`, and what sections 3 to 5 use as the working directory. A Rails project directory there exposes nothing today; the docs say only "root is not needed", which is what the report read. What is missing is serving `public/` from disk, and a guard against an `app` flip that would serve the project; section 7 |
| A. an application process as a first-class thing | decided | section 5 |
| B. framework commands without a general exec tool | decided, every constraint of the report kept | section 4 |
| owner: file operations as the site's account | decided | section 3 |
| owner: delete a site with its files, recoverable | decided | section 3b |
| owner: know when the application's port is reachable from outside | decided | section 6 |

## 1. Goal and non-goals

Goal: through `agensio mcp` (or `agensio ctl`) as admin, and nothing else:

1. create the site (exists);
2. put the application there: `rails new`, or an archive (`site_install`, exists);
3. run its preparation: `bundle install`, `db:prepare`, `assets:precompile`;
4. run and supervise its server (Puma), see its logs and its memory;
5. read, write, create, move and delete the site's files;
6. delete a site together with its files, and get them back for thirty days;
7. learn from `health` that the application is down, or reachable from the network
   without agensio in front, before a visitor does.

Every step runs as the site's account. Root work happens only inside the provisioning
helper's fixed vocabulary. Every action is one audit line with the caller's uid and
reason. Nothing general exists anywhere: no command string, no shell, no path outside the
site, no program the caller names.

Non-goals: a command runner or a terminal; installing packages (ruby, node, build tools
are root's, handed back as `run_as_root` commands as prerequisites are today); running
anything the caller sent as root; changing the request path (the A/B gate stays flat;
only section 7 touches it, behind a key).

## 2. The trust model, unchanged

Three parties, as in `docs/security-control-plane.md`: the peer on the control socket
with its role; the server process, unprivileged after the drop; the helper, root, one
socketpair, a fixed vocabulary validated again inside (`provision::validate`). Everything
below is:

- a new helper operation, validated inside the helper, executed in a child that has
  become the site's account (`run_as_account`: `setgroups`, `setgid`, `setuid`, root not
  regainable) under the account rule of row 19: the site's `user`, else the owner of the
  site's directory when it is a site account (`nologin`, home in the state directory) or
  the server's own; root, a login account and another site's account refused;
- without the helper (`provision = false`, or not started as root), the same code on a
  server thread as the server's own account, so it reaches only directories that account
  owns, as `site_install` does today; what needs root (units, the trash) comes back as
  commands, as today;
- never a spawn under `src/control/` (rule 11's static check); execution lives in
  `src/services/`;
- audited: operation, site, arguments, the account it ran as, the outcome.

The ceiling to state for each tool is "what the site's own application, running as that
account, can already do". A PHP site's admin already has arbitrary execution as the site
user through `site_install` (the report's point). For a Rails site the tasks of section 4
are a new capability, and the table bounds it.

## 2b. The site's directories

The recommended tree of `docs/install.md` section 3 gains one directory:

```
/var/www/<domain>/      user:agensio 2750
├── web/                the document root of a static or PHP site (`root`; Laravel: the project, public/ served)
├── app/                the application of a proxy-family site (`root`): the Rails project; app/public served (section 7)
├── log/                the site's access log (agensio:<site group> 0750)
├── private/            files the site reads and never serves (user:user 0700)
└── ssl/                certificates managed by hand (root 0700)
```

`root` names `web/` or `app/`, and everything the control plane does with a site's files
happens below `root`: installs (`project_root`), the file tools of section 3, the tasks of
section 4, the service's writable path of section 5. `site_create` suggests
`<sites_root>/<domain>/app` for `app = "rails"` and for a proxy site whose files live on
this host, `.../web` for the rest; the helper's `site_layout` creates either the same way.

Why a separate directory (the owner's point): the application's directory holds its
secrets, `config/master.key`, `.env`, `db/*.sqlite3`, and an `app` changed by mistake to
`static` or `php` would make `root` a served document root. The directory alone does not
close that, because `root` would still name `app/`, so a load rule closes it:

**`root_is_project`.** A preset that serves its root directly (`static`, `php`,
`wordpress`, `grav`, `drupal` without a `web/`) refuses a root that holds an unmistakable
project marker: `artisan`; `Gemfile` together with `config/application.rb`; `manage.py`;
`config/master.key`; `package.json` together with `node_modules/`. The message names the
framework and the fix (`app = "laravel"` or `"rails"`, or point `root` at the public
directory). `site_update` validates through the reload, so the flip is refused and undone
and nothing is served; a hand-written file fails `-t` with the same words. Softer signals
(`package.json` alone, `composer.json` with `vendor/`, a `.env`) are a `health` warning
of the same name, not a refusal, so an upgrade never stops a site that boots today. The
rule protects Laravel as much as Rails: a Laravel site flipped to `static` would serve
`config/` and `storage/logs/`.

## 3. F12: the site's files, one tool per operation

What a panel's SFTP account gives a customer, through the control plane, as the site's
account, and no login shell.

**Paths.** Relative to `root` (`project_root`), cleaned by `archive::clean_path` (no `..`,
no absolute path, no backslash, no control character), walked by the install's walk
(`openat` with `O_NOFOLLOW`, every existing component owned by the account), the leaf
opened `O_NOFOLLOW`. A symlink anywhere on the way is refused, so a link the application
planted cannot point a write outside the site; a symlink as the leaf is reported as one,
never followed, and may be deleted.

**Tools** (decision 1: one per operation, each with exact annotations, so an agent host
allows the reads without asking and confirms the rest):

| tool | method and path | role | what it does |
|---|---|---|---|
| `site_files_list` | GET `/v1/sites/NAME/files?path=` | admin | the entries of a directory: name, type, size, mode, mtime, `owner_is_site`; at most 2,000, one level; symlinks shown with their target, never followed |
| `site_file_read` | GET `/v1/sites/NAME/files?path=&read=1&offset=&tail=&base64=` | admin | a regular file as UTF-8 text, or `base64`; at most `[control] file_max` (1 MB) per call; `offset`, `tail` (bytes from the end, for a log); with `size` and `sha256` |
| `site_file_write` | POST `/v1/sites/NAME/file` op `write` | admin | `path`, `content` (text or `base64`), at most `file_max`; `overwrite`, `executable`, `if_sha256` |
| `site_file_edit` | POST, op `edit` | admin | `path`, `old`, `new`: `old` must occur exactly once; the same write path; a small change without resending the file |
| `site_dir_create` | POST, op `mkdir` | admin | `path`, `parents`; mode from the parent, set-gid bit and group from the kernel, as the install's `create_path` |
| `site_path_move` | POST, op `move` | admin | `from`, `to`: `renameat` within the site; the destination absent unless `overwrite`; directories included |
| `site_path_delete` | POST, op `delete`, `destructiveHint` | admin | `path`: a regular file, a symlink (unlinked, not followed) or an empty directory; `recursive: true` removes a tree without following symlinks, at most 10,000 entries per call, never `root` itself |

Every mutating tool takes `confirm`, `reason` and `dry_run`. Writes are created under a
temporary name `O_EXCL | O_NOFOLLOW`, `fsync`, then `linkat` (new file) or `renameat`
(`overwrite: true`), the `copy_file` pattern; mode from the directory's pattern (`0640`
in a `2750` directory), `executable: true` adds the directory's execute bits, a path in
the credential list gets `0600`, no set-uid or set-gid bit ever. `if_sha256` refuses a
write when the file changed since the caller read it; the answer carries `replaced:
{bytes, mtime, sha256}`. Answers name the account (`as`), the absolute path, bytes and
mode; every operation is one audit line, writes with the sha256 of the content. After
`write`, `edit` and `move` the credential sweep and hosting rule 3 run as they do for
`site_install` (row 24): a credential file left readable is `409` with `written: true`.

**Credential files** (decision 2). The list is `secret_paths` (the preset's secrets,
`.env*`, `.git`; Rails adds `config/master.key`, `config/credentials*`,
`config/database.yml`) plus names ending in `.key` or `.pem`. They are readable like any
other file: the admin owns the site and the SSH account behind the bridge could read them
anyway. What agensio adds is visibility of the path the bytes then take (the agent's
context, the model provider, the host's transcript, and whatever other tools the agent
host has, which agensio cannot see): a read of one is its own audit line, `credential
file read`, and the answer carries `credentials: true` so the agent knows what it holds.
`[control] reveal_secrets = false` in root's file makes such a read require
`reveal_secrets: true` on the call, for a host where the agent works next to untrusted
content; the default is `true`.

Roles (decision 7): admin for all of it, listing and reading included; a site's source and
data are the customer's, and hosting staff who watch the server have no business in it.

Ceiling: read, write and delete any of the site's files as its account, below `root`;
never another site's, never the server's own, nothing executed. The same as an SFTP login
for that account, which is the panel feature it replaces, minus the shell.

Implementation: `services/files.*` (the path rules pure and unit-tested; the operations
over an open directory descriptor, reusing `walk_dirs` and the temporary-name write of
`install.cpp`), helper operation `file_op` next to `file_copy` (validated in
`provision::validate`: site root below `sites_root`, clean relative paths, typed flags,
content size), the server thread without the helper (`install_async` grows a branch),
`ControlHandler` actions `files` (GET) and `file` (POST) under `/v1/sites/NAME/`, `agensio
ctl site-files NAME [PATH]`, `site-file-read NAME PATH [--tail N]`, `site-file-write NAME
PATH [FILE]` (content from a file or stdin), `site-file-edit`, `site-dir-create`,
`site-path-move`, `site-path-delete`; MCP tools as in the table; `docs/mcp.md`,
`docs/configuration.md` 15, security page rows, `tests/files.sh` in the root devbox with
two accounts (another account's directory refused, a planted symlink refused, modes, the
credential sweep, the audit line of a credential read), unit tests of every refusal.
About 500 lines plus tests. New keys: `[control] file_max`, `[control] reveal_secrets`,
each with its reference row and `docs/keys.md` regenerated.

The bridge's rule "files cannot travel through the bridge" narrows to "archives cannot; a
text file up to `file_max` can", in `docs/mcp.md` and the server instructions.

## 3b. F12b: deleting a site with its files, and the recycle bin

Today `site_delete` removes the site file (a `.bak` stays) and touches neither the files
nor the account. With `files: true` (marked destructive, `confirm`, `reason`) it also
moves the files away, recoverably.

- **What is moved.** The site's directory in the layout of section 2b: the first
  directory below `sites_root` on the root's path (`/var/www/example.com` for
  `root = /var/www/example.com/web`), provided no other site's root lies under it;
  otherwise `root` alone. The account's state directory (`<state_dir>/<user>`) goes with
  it when no other site uses the account.
- **Where.** The helper renames it into `<sites_root>/.trash/<domain>-<stamp>/`, same
  filesystem by construction, so the move is instant and copies nothing. The trash
  directory is `0700 root:root`: no account, and not the server, can read another
  tenant's deleted files. A manifest next to the tree keeps the site file's text, the
  spec, the original path, the account and the time.
- **What follows.** The site file is removed and the configuration reloaded; the existing
  apply steps remove the account's generated pool and unit (they already remove what the
  configuration no longer names). The account stays until the entry expires, because the
  files carry its uid and a restore needs it; the audit line says so.
- **Restore.** `site_restore DOMAIN` (admin) moves the tree back to its original path,
  refused when that path exists again, rewrites the site file from the manifest and
  reloads. `trash_list` (admin) shows entries with size and age; `trash_delete ENTRY`
  (admin, destructive) removes one now.
- **Expiry.** `[control] trash_keep`, thirty days by default; worker 0's hourly timer asks
  the helper for `trash_expire`, which removes expired entries and then the account of
  one that no site references (`account_remove`: a site account only, by the rule of
  `site_account`). The removal runs as root, walks with `O_NOFOLLOW` and never leaves the
  trash directory; the entry name is validated against the manifest before anything is
  unlinked. `health` reports `trash_size` when the trash holds more than a configurable
  share of the filesystem.

Helper operations: `site_trash`, `site_restore`, `trash_delete`, `trash_expire`,
`account_remove`; each validated inside the helper (paths below `sites_root`, entry names
of the form `<domain>-<stamp>`, accounts by the site-account rule). MCP: `site_delete`
gains `files`; `site_restore`, `trash_list`, `trash_delete`. `tests/trash.sh` in the root
devbox: delete, restore, expiry with a short `trash_keep`, the account gone afterwards,
another tenant unable to read the trash.

## 4. F13: the framework's own commands (`site_task`)

Named tasks from a table, fixed argv, typed parameters, no command string, ever. The
report's constraints are the specification; this is where each one lands.

**The table** (`src/services/tasks.*`, rows unit-tested), Rails first:

| task | interpreter | argv (fixed) | parameters | network |
|---|---|---|---|---|
| `gem_install_rails` | ruby | `gem install rails --no-document --version V` (default `~> 8.0`) into the account's `GEM_HOME` | `version` `^8(\.[0-9]{1,4}){1,3}$` | yes |
| `rails_new` | ruby | `ruby $GEM_HOME/bin/rails new . --name=NAME --database=sqlite3 --skip-git --skip-docker --skip-thruster --skip-ci` | `name` `^[A-Za-z][A-Za-z0-9_]{0,63}$` | yes |
| `bundle_install` | ruby | `bundle install` with `BUNDLE_PATH=vendor/bundle`, `BUNDLE_WITHOUT=development:test` | none | yes |
| `db_prepare`, `db_migrate` | ruby | `bundle exec rails db:prepare` / `db:migrate` | none | no |
| `assets_precompile` | ruby | `bundle exec rails assets:precompile` | none | no |
| later rows | php, node, python | `composer install --no-dev`, `php artisan migrate --force`, `php artisan key:generate --force`, `npm ci`, `npm run build`, `python3 -m venv .venv` then `.venv/bin/python -m pip install -r requirements.txt`, `manage.py migrate`, `manage.py collectstatic --noinput` | none | as marked |

The `rails new -m URL` template and every other flag are simply not in any row; the
`Gemfile` that `bundle install` honours is the site's own code and runs as the site,
which is the point of the exercise and the reason for the bounds below. Task rows belong
to a preset (decision 6): `app = "rails"` has these, `app = "proxy"` has none until a
row for its framework exists.

**Execution** (helper operation `task_run`, validated inside the helper, the child by
`run_as_account`):

- Flags never come from the caller. A parameter is validated against its row's pattern or
  range and refused by name; the argv the row builds is the argv that runs, and the answer
  and the audit line carry it.
- `argv[0]` is an interpreter from `[control] runtimes` (decision 5; section 4b). What
  that interpreter then loads from the site (`Gemfile`, `vendor/bundle`, `bin/rails`,
  `node_modules`) is the site's code and runs as the site. A missing interpreter answers
  the `apt install` line as `run_as_root`, the way prerequisites are handed back today.
- Working directory: `root` (`app/`), reached by the walk of row 19 and `fchdir`, so a
  symlink cannot move it. Environment: cleared, then `PATH` (the runtime's directory and
  the system directories), `HOME` = `<state_dir>/<user>` (the account's home since
  `account_add`; created `0700 <user>:<user>` by the helper when missing, with `tmp/`),
  `TMPDIR` = `<state_dir>/<user>/tmp`, `LANG=C.UTF-8`, `RAILS_ENV=production` or
  `NODE_ENV=production`, and the row's own variables (`GEM_HOME`, `BUNDLE_PATH`). Nothing
  from the caller.
- Bounds (decision 3, the first way): a wall-clock timeout per row (default 20 minutes,
  like installs; `bundle install` compiling native gems needs it), then `SIGTERM`, ten
  seconds, `SIGKILL` of the process group; `setrlimit` in the child: `RLIMIT_NPROC` 512
  for the account, `RLIMIT_NOFILE` 4,096, `RLIMIT_CORE` 0; `[control] task_limits = {
  timeout = "20m", processes = 512 }` as the ceilings. Output merged and captured up to
  64 KB (the first 16 and the last 48, the cut marked), returned with the exit status and
  the duration; one task per site at a time (a lock in the helper; a second call is 409
  naming the running task). `dry_run` reports the argv, the account, the directory, the
  environment names and the limits. Memory and CPU caps come with the second way, once
  F14 brings systemd testing: the same argv as a transient unit (`systemd-run --wait
  --pipe --collect --uid --gid --working-directory -p MemoryMax= -p TasksMax= -p
  CPUQuota= -p IPAddressDeny=<the private ranges>`), the row unchanged.
- After every task: the preset's credential sweep (Rails: `config/master.key`,
  `config/credentials.yml.enc`, `config/credentials/`, `config/database.yml`, `.env*`,
  `storage/`, `db/*.sqlite3`; the row's `secrets`) to `0600` (directories `0700`), hosting
  rule 3 on what changed, the configuration validated: the row-24 pattern, so the answer
  is never an ok the validator refuses.
- Network: `gem install` and `bundle install` fetch from rubygems.org as the site's
  account. Rows are marked; `[control] task_network = false` refuses the marked rows (an
  air-gapped host installs an archive that carries `vendor/bundle`). The private-address
  fence of downloads cannot apply to a package manager's own connections; the transient
  unit of the second way can, as `IPAddressDeny`.

**Control API**: `POST /v1/sites/NAME/task` `{task, params, dry_run, confirm, reason}`
(admin), deferred like an install; `GET /v1/sites/NAME/tasks` (viewer): the rows the
site's `app` offers, with their parameters and marks, from the table (as `presets` is
from its table). MCP `site_task` and `site_tasks_list`; `agensio ctl site-task NAME TASK
[--param k=v] [--dry-run]`.

Ceiling: the enumerated argv of the table as the site's account, in the site's
directory, the site's own code loaded by a system interpreter. A prompt-injected agent can
run those tasks and nothing else, and the audit log names each one with what actually
ran.

### 4b. `[control] runtimes`

Tasks and services run interpreters: ruby, bundle, gem, node, npm, php, composer,
python3. Each must be a root-owned file in a root-owned directory, not under
`sites_root`, not writable by others, checked before every run; otherwise a compromised
site could plant its own `ruby` and the audit line would say "ran ruby" while it ran
anything. `[control] runtimes = { ruby = "/usr/bin", node = "/usr/bin", php =
"/usr/bin", python3 = "/usr/bin" }` are the defaults; a host with Ruby under
`/opt/rbenv/versions/3.3.6/bin` points the key there. The key lives in root's main file
only: no site file and nothing on the control socket can change it. Reference rows and
`docs/configuration.md` 15 document it.

## 5. F14: the application's process (`service = { ... }`)

What the generated pool is to php-fpm, a generated systemd unit is to Puma: rendered from
validated configuration keys by one renderer, written and reloaded by the helper,
reported by health. No `ExecStart` from the caller, ever.

```toml
[[site]]
server_name = ["ag5.edoc.gr"]
listen = ["0.0.0.0:443"]
tls = "auto"
app = "rails"                        # section 7: proxy, app/public from disk, the Rails rows
root = "/var/www/ag5.edoc.gr/app"    # the project directory (section 2b)
user = "ag5"
service = { runtime = "puma", workers = 2, threads = 5, memory_max = "512M", env = { RAILS_LOG_TO_STDOUT = "1" } }
# upstream is derived: unix:/run/agensio/apps/ag5/app.sock (decision 4)
```

Keys: `runtime` (the templates: `puma` first; then `node`, `next`, `gunicorn`,
`uvicorn`), `listen` (`"socket"`, the default where the runtime supports it, or a
loopback TCP port 1024 to 65535, unique across the host's sites, checked at load as
sockets are; anything but loopback refused), `workers`, `threads` (ranges per runtime),
`memory_max`, `tasks_max` (within `[control] service_limits`, the `site_limits` pattern,
settable through `settings`), `env` (names `^[A-Z_][A-Z0-9_]{0,63}$`, values without
control characters, 4 KB in all; `PATH`, `LD_*`, `RUBYOPT`, `RUBYLIB`, `GEM_*`,
`BUNDLE_*`, `NODE_OPTIONS`, `PYTHON*` and the other names that change what runs are
refused), `entry` for node (a clean relative path). `upstream` may still be written by
hand; with `service` it is derived from `listen`.

**Transport** (decision 4). A unix socket by default for the runtimes that support it
(Puma, gunicorn, uvicorn): file permissions decide who connects, and another tenant's
process cannot reach the application behind agensio's back, as with the pool sockets.
The socket directory `/run/agensio/apps/<user>/` is created by the helper at start and at
`service_apply`, `2750 <user>:<server group>`, so the socket the application creates
inherits the server's group; Puma's bind URL takes `umask=0117`, giving the socket
`srw-rw---- <user> <server group>`, the pool socket's pattern; the unit runs `User=<user>
Group=<the site's group>` and never carries the server's group (the pools' isolation
rule: a process in the server's group could read every site's `web/`). Loopback TCP for
the rest (`node`, `next`), the template binding `127.0.0.1` explicitly, so the
application cannot publish itself; a non-loopback address is refused at load for a
managed service. What an unmanaged application binds is section 6's business.

**The unit** (`render_service`, golden-tested like `render_pool`),
`/etc/systemd/system/agensio-app-<user>.service`: one application per account, as one
pool per account; the sites of one user share it and must agree, as they do for pools.

```ini
# generated by agensio from /etc/agensio/agensio.toml, site ag5.edoc.gr; do not edit
[Unit]
Description=agensio application ag5 (ag5.edoc.gr)
After=network.target agensio.service

[Service]
User=ag5
Group=ag5
WorkingDirectory=/var/www/ag5.edoc.gr/app
Environment=RAILS_ENV=production HOME=/var/lib/agensio/ag5 TMPDIR=/var/lib/agensio/ag5/tmp BUNDLE_PATH=vendor/bundle RAILS_LOG_TO_STDOUT=1
ExecStart=/usr/bin/bundle exec puma -e production -b 'unix:///run/agensio/apps/ag5/app.sock?umask=0117' -w 2 -t 5:5
Restart=on-failure
RestartSec=2
KillMode=mixed
TimeoutStopSec=30
UMask=0027
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/www/ag5.edoc.gr/app /var/lib/agensio/ag5 /run/agensio/apps/ag5
ProtectHome=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictRealtime=yes
LockPersonality=yes
CapabilityBoundingSet=
MemoryMax=512M
TasksMax=256
```

What the application writes lands under `app/`, whose set-gid bit hands the server's
group down, so uploads and logs stay readable by the server as they are for PHP.
`ExecStart` is the runtime's template with the validated values in it: puma as above;
node `<node dir>/node <entry>` with `PORT` and `HOST=127.0.0.1`; next `<node dir>/npm run
start -- -H 127.0.0.1 -p <port>`; gunicorn `<python dir>/python3 -m gunicorn -b
unix:/run/agensio/apps/<user>/app.sock -w <workers> <module>`. Nothing else reaches the
file.

**Helper operations**: `service_apply` (the `pools_apply` shape: re-reads the
configuration itself, runs the hosting rules, renders every unit, writes the changed
ones and removes the units of sites that are gone, only files carrying the generated
header, creates the socket directories, then `systemctl daemon-reload`, `enable --now`
for new units, `restart` for changed ones; nothing from the caller but "apply");
`service_control` (`start`, `stop` or `restart` of a unit the configuration names,
refused for any other name); `service_logs` (`journalctl -u <unit> -n <N> --no-pager -q
-o short-iso`, N at most 1,000, output capped at 256 KB). Programs by absolute path with
fixed arguments, as today.

**When**: `site_create` and `site_update` with `service` apply it once the site file is
live (where `finish_pool` runs), `site_delete` removes it; `agensio services` (as
`agensio pools`) for hand-written configurations, exit 3 when something changed; `-t`
validates the keys and `--explain` prints the unit.

**health**, with no spawn in the server: `service_dead` (the unit's cgroup under
`/sys/fs/cgroup/system.slice/` missing or without a process while the configuration
expects one; fix: `site_service restart` and the journal), `service_resident`
(`memory.current` of that cgroup, the analogue of `php_pool_resident`: every managed
application with its memory), plus section 6's findings.

**Control API** (decision 7): `GET /v1/sites/NAME/service` (viewer: state from the
cgroup, memory, process count, the unit name), `GET /v1/sites/NAME/service/logs?lines=`
(operator, through the helper; a stack trace can print anything), `POST
/v1/sites/NAME/service` `{action}` (operator, `confirm`, `reason`, like a reload). MCP
`site_service` (operator: start, stop, restart), `site_service_status` (viewer),
`site_service_logs` (operator); `agensio ctl site-service NAME status|start|stop|restart|logs`.

Ceiling: start, stop and restart of the units the configuration names; unit files that
are exactly the renderer's output for the validated configuration; journal lines of those
units. A compromised server cannot name a unit, a program or an environment value the
loader did not accept.

Platform: Linux with systemd (the helper already calls `systemctl`); elsewhere the
commands come back as text, as without the helper. Tests: golden unit files;
`tests/services.sh` in a systemd-capable devbox (`agensio-devbox-systemd`: the devbox
image with systemd as PID 1, `docker run --privileged --cgroupns=host`); the live check
on the owner's host with `ag5`.

## 6. Finding 3 and the exposed port: `upstream_unreachable`, `upstream_exposed`

A prober on worker 0, every 60 seconds, for every upstream of every proxy site (TCP and
unix): an async connect with a one-second deadline, nothing sent, the socket closed;
results kept per upstream (reachable, refused, timed out, since when). `health` reads the
last results (`health_findings` takes them as an input, so it stays a pure function) and
reports `upstream_unreachable` at error severity for a site whose every upstream fails
and `upstream_degraded` (warn) for a group with a member down, naming the address and
the fix (`site_service restart` for a managed application, else "nothing is listening on
ADDRESS; start the application"). No prober when no proxy site exists; one connect per
upstream per minute; nothing on the request path. `server_status` shows the results per
site. Probing on demand when `health` is called, with a deferred reply, was considered
and rejected: health should answer at once, and "down since 03:12" is what an operator
needs.

**`upstream_exposed`** (the owner's point 4, and the report's last one). Rails' generated
`puma.rb` binds `0.0.0.0:3000`, which publishes the application next to agensio, without
its TLS, refusals and logs. The prober also reads the kernel's listening sockets,
`/proc/net/tcp` and `/proc/net/tcp6` (no process spawned), and for each TCP upstream on
this host checks the address its port is bound to. A wildcard (`0.0.0.0`, `::`) or a
non-loopback address of the host is a `warn` finding: "the application behind SITE
listens on 0.0.0.0:3000: reachable from the network unless a firewall blocks it,
bypassing agensio"; the fix names both remedies: make it listen on `127.0.0.1` or a unix
socket (a managed service always does, so the finding never fires for one), or block the
port, with the rule as `run_as_root` text in the three common spellings (`nft add rule
inet filter input tcp dport 3000 drop`, `ufw deny 3000/tcp`, `firewall-cmd
--permanent --remove-port=3000/tcp`). agensio cannot see the host's firewall from
inside, so the finding says "unless a firewall blocks it" rather than claiming exposure.

## 7. `root`, `app/`, static files from disk, `app = "rails"`

`root` stays the site's directory, the project, which is what every other part of agensio
already treats it as (installs, hosting rules, layout, the working directory of sections
3 to 5); section 2b puts it in `app/` and adds the `root_is_project` rule. Serving from
disk comes from a new key:

`static = "public"` on a proxy-family site: a directory below `root` whose files are
served before the upstream is asked. The preset adds a static `/` location with `root =
<root>/<static>`, the site's `hidden_files` policy, and `try_files = ["$uri",
"@upstream"]`: a new `try_files` step kind that hands the request, target unchanged, to
the site's upstream location (the dispatcher's hop loop already re-routes fallbacks; this
step keeps `ws.path` and selects the proxy location). POST and the other application
methods already pass a static location that has a fallback (`Dispatcher::check_method`).
Precompiled assets get their immutable `Cache-Control` from the preset (`/assets/` for
Rails) through `add_headers`.

Refused at load: a `static` naming `root` itself, or a directory holding one of the
`root_is_project` markers: "would serve the project; static must be its public
directory". `health` says the same for an existing site, and `detect_app` learns `rails`
(`Gemfile` with `config/application.rb`), so `site_create` suggests it and
`preset_mismatch` covers proxy-family sites too.

`app = "rails"` as a row of a new proxy-family table (`kAppPresets`, the shape of
`kPhpPresets`): `static = "public"`, the `secrets` of section 4, the immutable asset
prefixes, the task rows, the service template (`puma`), the marker for `detect_app`.
`app = "proxy"` stays as the bare form for anything generic (decision 6): any upstream,
`static` and `service` available, no task rows. Later rows (`node`, `next`, `django`) are
each a row, a fixture and a docs section, as the PHP presets are.

Performance: a dynamic request costs one cache lookup and, on a miss, one stat under the
static root before it is proxied; nginx's `try_files $uri @app` pays the same. Gate:
`bench/ab.sh <ref> -P` with a `static` site added to the proxy rows; the bare proxy rows
must stay flat, since nothing changes without the key.

## 8. What changes elsewhere

- `docs/security-control-plane.md`: rows for `file_op`, `task_run` and the runtimes rule,
  `service_apply`, `service_control`, `service_logs`, the trash operations, the prober;
  the helper section's vocabulary and its "what a compromised server gains" paragraph
  rewritten to say so.
- `src/control/mcp.cpp`: the server instructions (the Rails workflow; files through the
  file tools; "files cannot travel" narrowed to archives; credential reads are audited),
  the tool texts, a `new_app` prompt; `docs/mcp.md` table and session; the `agensio ctl`
  help.
- New keys, each with a `reference.cpp` row and `docs/keys.md` regenerated: `[control]
  file_max`, `reveal_secrets`, `trash_keep`, `task_limits`, `task_network`, `runtimes`,
  `service_limits`; on a site `static`, `service`. `docs/configuration.md` 4b (what
  `root` is on a proxy site, `app/`, `static`, `service`), 11 (non-PHP sites with an
  account: the home, the tasks), 15 (the commands); `docs/install.md` section 3 (the
  tree with `app/`).
- `docs/ROADMAP.md`: F12, F12b, F13 and F14 as steps; the Rails row of the application
  matrix moves from "E" to them; `bench/rails/` as the Rails test bed (a `rails new`
  application in a container, as `bench/redmine/` is Redmine).
- The devbox image gains `ruby ruby-dev bundler build-essential libsqlite3-dev
  libyaml-dev` for `tests/tasks.sh`; a systemd-capable variant for `tests/services.sh`.
- Every step: `CHANGELOG.md`, unit tests, the root-devbox suite of the step, the
  integration suite green, the sanitizer build for new parsers, and the MCP texts checked
  against what the tools do.

## 9. Order and size (decision 8)

| step | size | depends on |
|---|---|---|
| the fix of findings 1 and 2 | done 2026-09-26 | |
| F13 tasks, the Rails rows, `[control] runtimes`, `app = "rails"` in its first form | done 2026-09-26 (section 12) | |
| F14 service, puma, the unix socket transport | about 500 lines, golden tests, `tests/services.sh` | F13's runtimes table |
| section 7 and 2b: `app/`, `root_is_project`, `static`, `@upstream`, the rest of `app = "rails"` | about 350 lines, the `-P` A/B | |
| section 6: the prober, `upstream_unreachable`, `upstream_exposed` | about 200 lines | |
| F12 files, seven tools | about 500 lines, `tests/files.sh` | |
| F12b the trash: delete with files, restore, expiry | about 350 lines, `tests/trash.sh` | F12's helper plumbing |

The first three make the operator's Rails site possible without a terminal; the prober,
the files and the trash round it off.

## 10. Decisions (2026-09-26, with the owner)

1. File tools: one tool per operation, seven tools, exact annotations each.
2. Credential files are readable by default; each read is audited as such and the answer
   marks it; `[control] reveal_secrets = false` requires the per-call flag on hosts that
   want it.
3. Tasks run in the helper's child with `setrlimit` and a timeout first; systemd
   transient units later, once F14 brings systemd testing, with the argv unchanged.
4. Service transport: unix socket by default where the runtime supports it, loopback TCP
   otherwise, never a non-loopback address for a managed service; an unmanaged
   application listening on all addresses is a health finding with the firewall rule
   handed back as root work.
5. `[control] runtimes` in root's file names the interpreter directories, `/usr/bin` by
   default; nothing else supplies an interpreter.
6. `app = "rails"` is a preset row with the Rails rules; `app = "proxy"` stays for
   generic setups.
7. Roles: every file tool admin; tasks admin; service start, stop and restart operator;
   service status viewer; application logs operator; trash listing, restore and
   emptying admin.
8. Order as in section 9.
9. The application's directory is `app/` beside `web/` (the owner's proposal, named
   `app/` rather than `proxy/`), with the `root_is_project` rule so an `app` flip can
   never serve it.
10. A site can be deleted with its files; they go to a root-only recycle bin under
    `sites_root` for `trash_keep` days and can be restored with one command.

## 11. Notes for the implementing session

- Reuse, do not rewrite: `run_as_account` and `install_account` (`provision.cpp`),
  `walk_dirs` and the temporary-name write of `copy_file` (`install.cpp`),
  `archive::clean_path`, `render_pool` and `write_pools` as the shape of the unit
  renderer and `service_apply`, `finish_pool` as the place where a site's pool or service
  is applied after its file is live, `secret_paths` for the credential list,
  `health_findings` with a new input struct for the prober's results.
- The static check of rule 11 forbids `fork`, `exec*`, `system`, `popen` and
  `posix_spawn` under `src/control/`; everything that runs a program lives in
  `src/services/provision.cpp` or a new `src/services/*.cpp` the helper calls.
- Every helper operation gets its branch in `provision::validate` with a unit test of
  each refusal, and its row on the security page.
- Root-devbox suites run as `docker run --rm --init --user root -v "$PWD:$PWD" -w "$PWD"
  agensio-devbox tests/NAME.sh build/agensio`; a background job in those scripts ignores
  SIGINT, so helpers are stopped with SIGTERM.
- Only section 7 touches the request path: `bench/ab.sh <ref> -P` before and after, the
  numbers in the commit message.
- Every new key is a reference row (`src/control/reference.cpp`) and `docs/keys.md` is
  regenerated with `build/agensio keys --markdown > docs/keys.md`; every changed
  behaviour is checked against the MCP texts, `agensio ctl` help and `docs/mcp.md`.

## 12. What F13 changed from this plan, and what it found (2026-09-26)

- `rails_new` does not pass `--skip-bundle`: Rails 8 skips its importmap, Hotwire and Solid
  Cache/Queue/Cable installers when the bundle is skipped, and the application left behind
  references `solid_cache_store` without its configuration. It bundles into
  `vendor/bundle` with the preset's environment (`RAILS_ENV=production`,
  `BUNDLE_WITHOUT=development:test`), so it downloads. Its options are Rails 8's
  (`--skip-thruster`, `--skip-ci`: agensio is the proxy), which is why `gem_install_rails`
  offers exact 8.x versions only and defaults to `~> 8.0`. Kamal's files are not skipped:
  Rails 8.1 writes the production databases' paths into `database.yml` only when
  `config/deploy.yml` exists and leaves them commented out otherwise, so `db:prepare`
  failed on every fresh application until `tests/rails.sh` ran for real; the sweep covers
  `.kamal/secrets*` too.
- The order of section 9 put tasks before `app = "rails"`, but tasks belong to a preset
  (decision 6). F13 therefore introduces `rails` in its first form: the proxy preset's
  routing plus its task rows and its credential files (`config/master.key`,
  `config/credentials/`, `config/database.yml`, `storage/`); section 7 adds `static`, the
  asset headers and `detect_app`.
- Credential directories get `secret_dir_mode`: no read or write for the group and nothing
  for others, set-gid and group-execute kept (2750 to 2710), which is what hosting rule 3
  asks and what Laravel's `public/storage` link needs; for a Rails account outside the
  server's group the kernel drops the set-gid bit, so `storage/` ends `0710`. Section 4's
  "directories 0700" became this. The installer had the same list and failed on any
  directory in it (`.git` in an archive made every install fail); fixed with the same rule.
- `task_limits` takes seconds (`timeout = 1200`), like every other duration in the
  configuration. The three task keys are read by the helper at start, so they are
  restart-only, and `health` lists them under `restart_needed` when the file differs.
- One task per site is kept by the server (a map on worker 0): the helper serves one
  request at a time, so while a task runs every other helper request (a `site_create`, an
  install) waits for it, as installs already made them wait. A helper that runs tasks
  concurrently is a later step if waiting proves a problem.
- Found by the live Rails run: an HTTP/1 connection closed a request whose handler was
  still working once `idle_timeout` (15 s) passed, with an empty reply. `gem install
  rails` takes minutes, so the control connection died mid-task; the same bug cut slow
  PHP scripts and proxied requests. Fixed in `http1/connection.hpp` (a working handler is
  not idleness, only a body the client does not send is), as HTTP/2 already did.
