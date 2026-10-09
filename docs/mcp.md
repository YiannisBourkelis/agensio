# Managing agensio with an AI agent (MCP)

agensio ships a [Model Context Protocol](https://modelcontextprotocol.io) server:
`agensio mcp`. An agent host such as Claude Code, Claude Desktop, Cursor or any MCP
client spawns it, and the agent can then inspect and configure the web server through
a fixed set of tools: check its health, list sites, read recent errors, create or change
a site, install an application into it, run a Rails application's named tasks, reload,
renew a certificate. The server never
embeds a model; the one network action it takes on an agent's behalf, downloading an
application archive for `site_install`, is fenced (https only, public addresses only,
size caps, verified certificate, optional sha256) and audited. It offers precise,
audited tools and nothing else.

The rule the bridge gives every agent, first: whatever a tool can do is done through the
tool, over this connection; a terminal command or a file edit is offered only when no tool
covers the change, which is the root-owned main configuration file, a hand-written site
file, and, on a server without the provisioning helper, the root work `site_create` hands
back. Then the agent gives the exact command or line and says why no tool can do it.

## How it is wired

```
agent host  --stdin/stdout-->  agensio mcp  --unix socket-->  agensio (control API)
```

- `agensio mcp` is **not a listener**. It talks only on its own stdin and stdout, so
  nothing on the machine can connect to it.
- It connects to the control socket **as the account that started it** and inherits
  that account's role (`docs/configuration.md` section 15): `root` and the service user
  are admins, members of the configured groups are admins, operators or viewers, anyone
  else is refused by the server. The bridge holds no token or secret.
- A viewer's session does not even list the mutating tools. Mutating tools carry the
  MCP annotations (`readOnlyHint: false`, `destructiveHint` on delete) so the host asks
  the user before running them, and they require `confirm: true` plus a one-line
  `reason` that the server writes to its audit log with the caller's uid.
- `site_create` and `site_update` report every prerequisite at once, each with a code and
  its command, so one round of root work suffices; `dry_run: true` runs the same checks and
  shows the file that would be written without writing it. A privileged port the dropped
  server cannot bind by a reload comes back as `needs_restart` with the restart command.
- Every value that could end up in a root command (`user`, `group`, `root`, certificate
  paths) is validated first: account names must match `^[a-z_][a-z0-9_-]{0,31}$` and may
  not be a system account or a word for "none"; paths must be absolute and free of shell
  characters. A refused value never produces a `useradd` or `chown` line. "No account"
  is `no_user: true` (or JSON `null`), never the string `"null"`.
- On a server started as root with `[control] provision = true` (the default), a small
  root helper forked before the privilege drop does the root work of a site on the
  server's behalf: the account, the directory layout, the site's log, the php-fpm pool,
  a restart, an application install or a file copy as the site's account, and a site task
  as the site's account. `site_create` is then one call and reports what it did under
  `done`. The helper does those things and nothing else; `docs/security-control-plane.md`.
- **A bridge knows its own version.** Every answer of the control socket names the
  server's version (`X-Agensio-Version`), and when it differs from the bridge's the tool
  result carries a note saying so: a long-lived `agensio mcp` keeps the tools and texts it
  started with after an upgrade (reconnect the MCP server in the agent host), and a server
  not restarted after one still runs the old code (`systemctl restart agensio`). Bridges
  before 0.1.0-alpha.26 cannot tell; reconnect them once after upgrading.
- **Files cannot travel through the bridge**: a tool argument is JSON inside the model's
  context, so an archive on your machine reaches the server by `ssh admin@host agensio
  ctl upload NAME < file` (the same SSH session the bridge uses), and the agent then
  installs it with `site_install` and `file: NAME`. `uploads_list` shows what is stored.
- Otherwise, anything that needs root (creating a system account, making a directory, restarting
  the service, reloading php-fpm) is never executed: the server answers with the exact
  commands and waits. The agent shows them, you run them, the agent continues.

## Connect from your machine to a VPS

The bridge runs on the server; your agent runs on your laptop; SSH carries the traffic.
No port is opened and nothing new is trusted: SSH's keys and fail2ban apply, the
server-side account decides the role, and the audit log names it.

Claude Code (`~/.claude.json` or the project's `.mcp.json`):

```json
{
  "mcpServers": {
    "vps1": {
      "command": "ssh",
      "args": ["-o", "BatchMode=yes", "admin@vps1.example.com", "agensio", "mcp"]
    }
  }
}
```

Claude Desktop (`claude_desktop_config.json`) takes the same `mcpServers` block. Any
other host: the command is `ssh admin@vps1.example.com agensio mcp`, transport stdio.
One entry per server is the right granularity. The SSH account needs a role: put it in
the `admins` group of `[control]`, or use the service user or root.

On the server itself (an agent running inside an SSH session, or a local machine):

```json
{ "mcpServers": { "agensio": { "command": "agensio", "args": ["mcp"] } } }
```

`agensio mcp` finds the socket from the configuration file (the usual search path) or
takes `--socket PATH`.

### Give the agent's key the bridge and nothing else

What the bridge asks the user in person (the confirmation of `pip_install`, below) binds
only when the bridge is the agent's one way in. A key that may run any command lets an
agent that also has a shell on your laptop call `agensio ctl` on the server itself and
answer for you. Give the agent its own key and limit it in the server account's
`~/.ssh/authorized_keys`:

```
command="agensio mcp",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA... agent@laptop
```

The MCP entry then needs no `agensio mcp` of its own (the server runs it for that key
whatever is asked), and your own key, used in a terminal, keeps `agensio ctl`.

### Confirmations the user gives in person

`pip_install` (Django and Wagtail sites) installs any package the site's account may
install, named by the agent, so the agent's `confirm` is not enough: before it sends the
task the bridge asks you in the MCP client's own dialog (MCP elicitation), which the model
neither sees nor answers. The dialog names the packages, the site, the account and the
virtualenv, links each name on pypi.org and warns that a look-alike name is a common way to
get malicious code; you tick "Install these packages" to go ahead. A client that cannot show
the dialog (no elicitation; at the time of writing Claude Code's CLI shows it, its VS Code
extension declines every question without showing it and its desktop app does not offer it)
or a decline gets a refusal carrying the `agensio ctl` command for you to run in a terminal
on the server, where the same warning is printed and `--yes` is your confirmation. The audit
log records which of the two it was.

## Tools

| tool | role | what it does |
|---|---|---|
| `health_check` | viewer | findings with a fix each: certificates, missing redirects, port 80 for ACME, recent errors, connections refused at a worker's ceiling (`connections_refused`: raise the limit, or let the firewall and fail2ban deal with the source), settings waiting for a restart, root, shared accounts, stale pools, every `static` or `dynamic` pool with the PHP processes it keeps resident and their memory (`php_pool_resident`, fix: `settings: {pm: "ondemand"}`; judged from the pool file php-fpm runs, so a pool left `static` on disk after the configuration changed is a warning fixed by `agensio pools`), a site whose files belong to another application than its `app` says (`preset_mismatch`, fix: the detected `app`), backup archives and database dumps under a served tree (`archives_in_root`); on a host with a public listener, whether the kernel's firewall limits the web ports per address and a fail2ban jail reads the access logs (`firewall_limits_missing`, `firewall_limits_trial`, `firewall_limits_unsaved`, `firewall_quic_unlimited`, `fail2ban_missing`, `fail2ban_jail_stale`, `fail2ban_filter_stale`, `fail2ban_failures_unseen`, `fail2ban_auth_unseen` (a site with a password whose failed logins nothing counts), `fail2ban_auth_challenges` (the installed `agensio-auth` filter is an older build's that counts every 401, the challenge included, so it bans the site's own users), `fail2ban_log_format`, `fail2ban_blind`, `protection_unchecked`; `protection_show` has the files and root's commands; informational under `[control] host_protection = "external"`); access by client address (`access_allows_proxy`, `access_loopback`, `access_ipv4_only`, `access_single_ipv6`, `access_site_restricted`, `docs/configuration.md` 19); passwords (`auth_users_unloadable`, an error: a users file the next load would refuse, so a restart would not start; `auth_no_valid_user`, `auth_users_expired`, `auth_plain_http`, `auth_users_orphan`, `docs/configuration.md` 19b) |
| `protection_show` | viewer | the host protection agensio does not apply itself (`docs/configuration.md` 18, the fail2ban guide `docs/fail2ban.md`), rendered for this host and checked: the nftables ruleset (a table of its own over the public ports, per-address connection rate and count, QUIC handshakes) with root's commit-confirmed commands (a trial a timer undoes in ten minutes, then keep), the fail2ban jails over the access logs with the sites' login paths (the presets' and each site's `login_paths`), `agensio-auth` over the error log counting failed passwords on `[[site.auth]]` paths (never the 401 challenge; `auth` says which sites, whether a jail reads the log, and root's line when the log is on stderr or at level error) and `agensio-denied` counting 403s, and the install commands, and what is in place now through the root helper: which ports any table limits (a panel's count), whether the agensio table is loaded, on trial or enabled at boot with each rule's hit counter, which jails read the logs and how many addresses they banned, whether the installed jail file is stale, and for a failure jail that reads the journal whether the journal holds a line of the application yet (`journal_seen`; false keeps health's `fail2ban_failures_unseen`) and which sites it cannot read for want of an account of their own (`unidentified`) |
| `server_status` | viewer | version, pid, uptime, workers, connections, the per-worker connection ceiling (`max_connections`), the `connections_refused` at it since start and `connections_idle`, per worker the refused addresses and listeners and when (`workers_detail`), listeners with their `protocols` (`h2` and `h1` on TLS, `h3` too when QUIC is on, `h2c` when enabled on plain), sites, the caller's role |
| `sites_list`, `site_show` | viewer | sites with their certificate state; one site with its effective locations (each saying where it came from: a preset, the `rules`, `root:<file>`, or nothing for a hand-written one) and, for a managed site, its `rules` and `root_additions`: the root-owned file beside the managed one where root extends the site with locations no field covers, named before it exists; `auth`: the password rules in force with where they come from, their users file, `users_count` and `usable` (no names, no hashes) |
| `config_validate` | viewer | the file on disk: errors and restart-only differences |
| `config_reference` | viewer | every configuration key with type, default, meaning, reload or restart, who changes it (root in the main file, a site file, `site_create`, `settings`), the reference section, and the running value of server-level keys; the agent answers "how do I change X" from it, handing root's edits back as the exact line plus the reload or restart command; the running value of `addresses` is root's address sets with their entries (the `@name` an access rule names) and of `trusted_proxies` the proxy ranges |
| `path_check` | viewer | what a site does with a GET for one path, and why, as the server decides it: `decision` refused (a `refuse` pattern, named in `refused_by`, or a location's refusal by name), static (`file`), runs (the script, with PATH_INFO), proxied (`upstream`), redirect, forbidden or not_found, `status` when the server decides it, the deciding `location` with where it comes from, `script` when PHP or CGI runs the path as another path (`/wp-login.php/x` runs `/wp-login.php`; exact access and password rules judge that script too), every `steps` on the way (try_files, a directory's index, each internal redirect), `access` when an access rule covers the path, `auth` and `auth_note` when a password rule covers it (or frees it, `open`), and a one-line `summary`. A description, nothing is fetched. The agent runs it after translating an application's official server configuration into `rules` (one path each rule must refuse, the paths that must still work), before and after applying |
| `access_check` | viewer | what a site's access rules (`rules.restricted`, `rules.admin`, `[[site.access]]`) decide for one path and one client address: `allowed`, `refused` or `report`, the deciding rule with where it comes from, and a one-line summary. The agent runs it with the user's own address before `site_update` restricts a path they use, and with the address a refused user's 403 page shows |
| `site_settings_list` | viewer | the per-site limits `site_update` accepts under `settings`, with type, unit, default, minimum, the ceiling root set, what a change costs and derives; with `name`, each key's current value and source. The schema of `settings` is generated from the same table |
| `presets_list` | viewer | what each `app` value does: served root, which `.php` runs, refusals, the endings a directory serves alone, the files never served (also refused in every backup spelling: `wp-config.php.bak`, `~`, `.swp`, `wp-config.txt`); from the preset table, so a new preset appears at once; `never_served_directories` lists what a preset refuses whole (Grav's `logs/`, `backup/`), `admin_paths` the administration paths `rules.admin` restricts on request (wordpress, drupal; the login one marked), and `source` the official archive `site_install` fetches (wordpress, drupal, grav) |
| `logs_query` | viewer | recent error-log and access-log lines, filtered by site, time, level and status; each line's `source` is `error`, `access` (the server-wide log every site without its own `access_log` writes into: the catch-all, the redirects, scanners by IP, so a line there is nobody's in particular) or a site's name (its own log); `sources` says who writes where; a site sharing the server-wide log answers `shared: true` with a note (JSON lines filtered by host, combined lines cannot be); an unknown site is a 404; lines are valid text, a client's stray byte written `\xHH` |
| `reload`, `logs_reopen` | operator | reload without dropping connections; reopen logs after rotation |
| `cert_renew` | operator | order an automatic certificate again now |
| `site_create`, `site_update` | admin | write or change a managed site file, validate, reload; answer with open decisions or root commands first; `settings` changes a site's limits within `[control] site_limits` and the answer lists under `done` what was written and reloaded; `rules` narrows a PHP or static site to what its application documents (`private` paths, the `.php` files that run, cached directories, a front controller) and, on any app, `restricted`: paths only some client addresses reach (403 for the rest, `docs/configuration.md` 19), `refuse`: the application's deny rules as gitignore-style path patterns, answered 404 whichever location would serve them (`docs/configuration.md` 6b; checked with `path_check`), and on WordPress and Drupal `admin`: the preset's administration paths kept to some addresses (`login`, `languages`, `mode`), never set unless the user asks, because an admin stays reachable from anywhere by default; the answer carries the notes `-t` would give for the rules (`access: ...`); replaced whole, `{}` clearing it, refused when a rule would widen the site or no longer fits the app; `rules.auth` puts a password in front of paths with the site's own users, refused until the site has a user and on `site_create` |
| `site_disable`, `site_enable`, `site_delete` | admin | rename the file away and back; delete it (a `.bak` stays, the site's root additions file set aside as `.bak` beside it), or with `files: true` move everything of the site (directory, account state, logs, environment file, the configuration's text) into root's trash for `trash_keep` days; refused while the site's service runs |
| `trash_list`, `site_restore`, `trash_delete` | admin | what the trash holds (site, account and whether it is still in use, size, expiry, pieces); a site brought back into an empty place, its configuration with it; an entry removed for good |
| `site_install` | admin | put an application's files into a site's empty directory as the site's account: the preset's official archive (`version` optional), any https `url`, or a stored upload (`file`); a plugin or theme goes into `path` with `create_path: true`; `sha256`, `strip`, `dry_run`; the server enforces the fences and reports the source, digest and what it created. For a Rails site the next steps are the bundle tasks, with the Ruby the application pins; a Rails archive without credentials gets its `SECRET_KEY_BASE` generated into the site's environment; every site but a static one is told its request-body limit; for a PHP or static site the facts name the directories the archive's own `.htaccess` files deny whole (`htaccess_denied`) and the next steps carry the matching `rules`, a suggestion the server never applies by itself |
| `site_copy` | admin | copy one regular file of a site to another path of the same site, as the site's account: the drop-ins applications ship as templates (WordPress's `wp-content/db.php` from the SQLite plugin, Drupal's `settings.php`); `overwrite`, `dry_run`; never across sites, never caller content, never a directory. Like `site_install`, credential files come out `0600` and the configuration is validated before the answer |
| `site_tasks_list` | viewer | the named tasks of the site's preset (`app = "rails"`: `gem_install_rails`, `rails_new`, `bundle_install`, `db_prepare`, `db_migrate`, `assets_precompile`; `"django"` and `"wagtail"`: `venv_create`, `pip_install` (any packages, confirmed by the user in person), `startproject`, `pip_install_requirements`, `django_settings`, `migrate`, `collectstatic`, `createsuperuser`, `check_deploy`; `"node"`: `npm_ci`, `npm_run`) with their parameters, whether each downloads, its effective time limit, whether its interpreter is in place (`run_as_root` lists every missing package once, before the first task), the account that runs them and the directory; other presets have none |
| `site_task` | admin | runs one of them as the site's account in the site's directory: a fixed command from the table, typed parameters, never a command line; the answer carries the exact argv, the exit status, a summary (migrations applied, `Bundle complete!`, the files in `public/assets`) and a part of the output (its last 4 KB on success, its first 4 KB and last 12 KB on a failure), and after a task that changes a running application the root line that restarts its service; the credential files are made the site's alone and the configuration is validated; `dry_run` shows the command without running it and meets the same refusals (a missing interpreter as `run_as_root`, a missing result of an earlier task naming the task to run); a task that exits 0 without what the next one needs is a 409; a failure with a known cause carries `hint` (Rails' missing `secret_key_base`, a Gemfile pinning another Ruby); the site's environment reaches the task and shows as `NAME=<site environment>`. Marked destructive, so the host asks |
| `site_service_unit` | viewer | the systemd unit that runs a Rails or Redmine site's Puma, a Django or Wagtail site's Gunicorn, or a Node site's node, rendered from the site (account, directory, loopback port, a Django site's project and names) and `[control] runtimes`, with the root commands that install it; the agent shows them, root runs them |
| `site_service_status` | viewer | whether that unit runs, from `systemctl show` through the root helper: loaded, active, failed, since when, pid, exit status, restarts, enabled at boot, with a summary and the next step (`site_service_unit` when it is missing, `site_service_logs` and root's restart line when it failed) |
| `site_service_logs` | admin | the unit's journal (`journalctl -u` with fixed options through the helper, `lines` 1 to 1000, `since` like `3h`); audited, since an application may print what it should not |
| `site_task_output` | admin | the whole output of the site's last task in 64 KB slices (`offset`, `next_offset`), kept until the next task or a restart |
| `site_env` | admin | a Rails, Django or proxy site's environment: the variables its tasks and its application service get (`SECRET_KEY_BASE`, `DJANGO_SECRET_KEY`, `DATABASE_URL`) from a root-owned `0600` file, as names, lengths and fingerprints (the same fingerprint means the same value); a value only for the names in `reveal`, which the agent uses only when you ask to see that value, audited as REVEALED; `exists` false when there is no file yet |
| `site_env_set` | admin | `set`, `unset`, `generate` (a random secret for a missing name; a name in `unset` and `generate` is rotated) on that file, through the root helper; names that choose a program (`PATH`, `LD_*`, `GEM_*`, `RUBYOPT`, ...) are refused; the answer and the audit log carry names only, and the next step is the application service's restart |
| `site_auth_users` | admin | a managed site's password users (`[[site.auth]]`, `docs/configuration.md` 19b) from its users file (root's, the server's group, `0640`): each one's name, `method`, `expires` and `expired`, `note` and `locked`, never a hash; `used` says whether a rule reads the file; every read audited |
| `site_auth_user_set` | admin | adds or changes one user: `generate: true` (a new password made by the server, answered once in `password` and kept nowhere; required for a new user), `expires` (`YYYY-MM-DD`, `""` for none), `note`, `locked` (true refuses every login and keeps the password). A password is never an argument and the bridge drops a `hash`: a user who chooses their own runs `agensio ctl site-auth-user-set SITE USER --prompt` on the server. A rule that reads the file makes the server reload, so the change applies to the next request |
| `site_auth_user_delete` | admin | removes one user; the last user of a file a rule reads is kept (lock it instead) |
| `uploads_list` | viewer | archives stored with `agensio ctl upload`, for `site_install` |
| `upload_delete` | operator | remove a stored upload |

Two prompts help a newcomer: `getting_started` (greet, run the health check, offer the
usual jobs) and `new_site` (walk through a new website: HTTPS, its own user, what runs
there, where the files are).

## A session, in practice

> **You:** create a website for www.example.com, https only.
>
> **Agent:** calls `site_create` with the domain. The server answers with four open
> decisions. The agent asks: HTTPS automatic (recommended, port 80 must be reachable)?
> Its own system user, suggested `example`? What runs there, and where are the files?
>
> **You:** answer.
>
> **Agent:** calls `site_create` again with every field and `confirm: true`. The server
> answers that the account `example` does not exist and returns the `useradd`, `mkdir`
> and `chown` commands. The agent shows them and waits.
>
> **You:** run them as root, say "done".
>
> **Agent:** calls `site_create` once more. The file `sites.d/www.example.com.toml` is
> written, validated and live; the certificate arrives within a minute; `site_show`
> confirms it. Since the site is `app = "wordpress"`, the agent offers to install it.
>
> **You:** yes, the newest.
>
> **Agent:** calls `site_install`. The server downloads `wordpress.org/latest.tar.gz` as
> the site's account, verifies the archive, unpacks it into the site's directory and
> answers with the file count and the sha256. The agent reports both.
>
> **You:** no database server here; use SQLite.
>
> **Agent:** calls `site_install` with the SQLite plugin's URL, `path:
> wp-content/plugins/sqlite-database-integration` and `create_path: true`, then
> `site_copy` from that plugin's `db.copy` to `wp-content/db.php`, and tells you to open
> the site to finish WordPress's own setup. Zero terminal commands from start to end.

Every step is one line in the audit log with your uid and the reason the agent gave.

A Rails application goes the same way. The agent creates the site with `app: "rails"`,
its own user, `root` at `/var/www/example.com/app` and `upstream` at
`http://127.0.0.1:3000`, then runs `site_task` four times: `gem_install_rails`,
`rails_new` with `params: {"name": "shop"}`, `db_prepare` and `assets_precompile`, each as
the site's account, reading the output when one fails. When Ruby is missing, the first
answer carries the `apt-get` line for you to run as root. The one step left for a terminal
is starting Puma, until agensio manages the application process: `site_service_unit`
renders the site's unit and the agent hands you its three root commands. Afterwards
`site_service_status` tells the agent whether Puma came up, and `site_service_logs` why
not. After a later `bundle_install`, `db_migrate` or `assets_precompile` the agent gives
you the restart line from the task's answer. `health_check` lists every Rails site whose
service is missing, stopped or failing.

Redmine goes the same way with `app: "redmine"`: `site_install` with `version: "7.0.1"`
and redmine.org's sha256, `site_env_set` with `DATABASE_URL`, then `site_task`
`database_config` (a fixed `config/database.yml` reading that variable), `gemfile_local`
(Puma, which Redmine keeps in its test group), `bundle_install`, `db_migrate`,
`load_default_data` with `lang`, `assets_precompile`, and the unit.

A Wagtail site is created with `app: "wagtail"` and `project: "mysite"`, the project's
Python package, which `site_create` asks for. Every task runs in a virtualenv of the site's
own, outside the served tree: `venv_create`, `pip_install` with `wagtail gunicorn`,
`startproject`, `pip_install_requirements`. Then `site_env_set` generates
`DJANGO_SECRET_KEY`, and `django_settings` writes the settings agensio runs the project
with. `migrate`, `collectstatic`, then `site_env_set` generates `DJANGO_SUPERUSER_PASSWORD`
and `createsuperuser` makes the first admin; the password never passes through the
conversation, and the agent reveals it only when you ask. agensio serves `/static/` and
`/media/` itself and sends the rest to Gunicorn, whose unit `site_service_unit` renders.
On Debian the first answer names `apt-get install -y python3-venv` for you to run as root.

A Node application such as Uptime Kuma goes the same way with `app: "node"`: `site_install`
with its release archive (the answer reads its `package.json`: the Node it asks for against
the one installed, the file it starts), `site_task` `npm_ci` (its dependencies exactly as its
lockfile pins them) and `npm_run` with the post-install script it documents (Kuma's
`download-dist`), `site_env_set` for what it reads (Kuma's `DATA_DIR`, in the site account's
home), `site_update` with `entry`, and the unit, which runs root's `node` bound to loopback.
An application that creates its admin on the first visit is claimed by whoever opens it
first: the agent tells you to open it as soon as the service starts. On Debian the first
answer names `apt-get install -y nodejs npm` for you to run as root.

A PHP application without a preset of its own, Kanboard say, runs under `app: "php"`.
`site_install` with its release URL unpacks it as the site's account and reports that its
`.htaccess` files deny `app/` and `data/`; the agent reads the application's own server
guidelines and calls `site_update` with `rules`: the private paths, the only `.php` files
that run (`index.php`, `jsonrpc.php`, `healthcheck.php`), the assets cached a week, and
`index.php` as the front controller for its nice URLs. The server renders them into the
site's file, where every rule can only narrow what the preset serves, and `site_show`
shows them; the agent never writes a site file by hand for this.

TYPO3 goes the same way, from its documentation rather than its archive. The agent reads
the web server configuration TYPO3 publishes for your version (its nginx example in the
system requirements) and translates it: `entry_points` `/index.php` and
`/typo3/install.php`, `index.php` as the front controller (which takes `/typo3/` and
`/typo3/module/...`, the backend, as TYPO3 13 routes it; the deprecated `typo3/index.php` is
not listed, so it never runs and `/typo3/` passes over it), and every deny rule as a `refuse`
pattern:
`composer.json`, `*.yaml`, `*.typoscript`, `_recycler_/`, `/vendor/`, `/typo3temp/var/`,
`/typo3/sysext/*/Resources/Private/` and the rest, about fifty. It shows you the list with
the page it came from, sends it with `dry_run`, and runs `path_check` on the paths the
documentation names: `/typo3conf/ext/news/Configuration/TypoScript/setup.typoscript` must
be refused, `/`, `/typo3/` and a `Resources/Public` asset must still work. Only then, with
your agreement, does it apply the rules, and it runs the same checks once more.

> **You:** why does /typo3conf/ext/news/Resources/Public/Css/news.css give a 404?
>
> **Agent:** calls `path_check`. The answer names the deciding pattern and the steps; the
> agent shows you the one line (`refused by the site's refuse pattern '/typo3conf/ext/*/'`,
> say, a pattern too wide) and proposes the narrower one the documentation meant.

When you ask for what no field covers (a redirect, a header on one path, an alias outside
the root, a second upstream, CGI), the agent does not edit the site's file, which would
unmanage it. It hands you the exact `[[location]]` block for the site's root additions
file, `sites.d/<domain>.root.toml`, root's alone, with `site = "<domain>"` on its first
line, then `agensio reload`, and reads the result back with `site_show`.

An existing application comes as an archive. For Writebook the agent calls
`site_install` with the GitHub release URL; the answer says the application pins Ruby
3.4.7 and that `SECRET_KEY_BASE` was generated into the site's environment, since the
archive has no Rails credentials. When `[control] runtimes` gives another Ruby, the agent
hands you the build commands of `docs/configuration.md` 15 and the one line for the main
configuration file, then `agensio reload`. Then `site_task` `bundle_install`,
`db_prepare` and `assets_precompile`, and the Puma unit, which loads the same
environment file. A `DATABASE_URL` or an API key goes the same way, with `site_env_set`;
the agent never writes a secret into a file of the application or into a unit.

> **You:** someone is hammering the login page. Are we protected?
>
> **Agent:** calls `health_check` and `protection_show`. The host has a public listener and
> neither the firewall limits nor a fail2ban jail: it explains the split (the server's
> ceiling refused the overflow, the firewall and fail2ban are root's), shows the three trial
> commands exactly, says that the timer undoes them in ten minutes unless kept, and asks you
> to check the site and your SSH session, then shows the two keep commands and the
> fail2ban install. For the Kanboard site, whose preset cannot know the login path, it asks
> where the form posts and sets `login_paths` with `site_update` before rendering the jail.
> Afterwards `protection_show` reports the table loaded and enabled, the jail reading the
> logs, and the first address banned.

## What it cannot do

Run a command of its choosing (`site_task` runs only the named tasks of the site's preset,
as the site's account, with an interpreter only root could have put there), install packages, edit hand-written site files, a site's root additions file or the main configuration file (root's:
for a `[server]`, `[cache]`, `[log]` or `[control]` key the agent tells you the exact line
and whether a reload or a restart follows, from `config_reference`), run anything as
root, change the host's firewall or fail2ban (it renders the files and the commands, root applies them, with a trial first), reach other machines except to download an archive you named into a site (and
never a private address), carry files itself, remove an account, or delete a site's files
except into the trash, from which `site_restore` brings them back for `trash_keep` days.
Those are yours, on purpose. On a server with the helper
it creates site accounts, restarts the service after a change that needs it and installs
applications as the site's account; without the helper it hands the commands back.
