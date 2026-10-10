# Hosting: accounts, the control plane, agents

Recipes for a server that hosts many sites: one system account per site, the control socket
that creates and changes them, the trash that keeps a deleted site for a while, and an AI agent
that does the same work over SSH with the same roles and the same audit log as a person. The
main file stays root's; the site files under `sites.d/` are written by `agensio ctl site-create`
(or by a panel, or by hand), and one set of rules checks them at every start, reload and change.
The [cookbook's index](../examples.md) says how a recipe is laid out and how to apply one.

## The main file of a shared host

**When:** a new server will host sites for several customers, created and changed through
`agensio ctl` or an agent rather than by editing files.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]             # where site-create writes; it refuses to work without this line

[server]
user = "agensio"                         # start as root, bind the ports and open the logs, then run as this account
acme = { email = "admin@example.com" }

[log]
access = "/var/log/agensio/access.log"   # site-create puts a site's own log beside it, in sites/<domain>.log
error = "/var/log/agensio/error.log"     # the audit log goes beside it, audit.log

[control]
socket = "/run/agensio/control.sock"     # a unix socket, never a TCP port; agensio ctl and agensio mcp use it
admins = "agensio-admin"                 # groups; root and the server's own account are always admins
operators = "agensio-ops"
viewers = "agensio-view"
sites_root = "/var/www"                  # where site roots are suggested and created; the trash lives below it
trash_keep = 30                          # days a site deleted with its files can be restored (default 60)
```

```toml
# /etc/agensio/sites.d/default.toml
[[site]]
server_name = ["*"]                      # every name no other site lists, and the bare IP address
listen = ["0.0.0.0:80"]
root = "/var/www/html"
```

**What it does.** The `[control]` table turns the control plane on: without it `agensio ctl`
and `agensio mcp` have nothing to talk to. Every connection to the socket is judged by the uid
the kernel reports for the process at the other end and by that account's groups, whatever
the file mode says; anyone without a role is disconnected and the attempt goes to the audit
log. Started as root (the packaged unit does that), the server forks a small root helper
before it drops to `user`: it creates site accounts and directories, hands a site its log,
writes the php-fpm pools and installs applications as the site's account, so `site-create`
does the whole job in one call (`provision = false` hands those steps back as commands
instead). The catch-all site answers requests whose Host no site lists; without one they get
`421`, and `site-create` warns about it for every new site.

Easy to get wrong: `strict_users = true` refuses every site without `user`, and that includes
the plain-port redirect site `site-create` writes for an HTTPS site, so leave it off on a host
the control plane manages. `user`, `socket` and `provision` take effect at a restart, not a
reload; the role groups apply on reload, the next connection judged by them.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml
systemctl restart agensio
agensio ctl status          # version, listeners, sites, and under peer the role you have
agensio ctl health          # what to look at first, each finding with its fix
```

**MCP:** `server_status` and `health_check` first on a server the agent does not know;
`config_reference` for a key's running value and whether a change needs a reload or a restart.

**Reference:** [Control socket](../configuration.md#15-control-socket),
[Hosting: one user per site](../configuration.md#11-hosting-one-user-per-site),
[Logging](../configuration.md#8-logging),
[the directory layout](../install.md#2-directory-layout-per-platform).

## One account per site

**When:** customers must not read each other's files: each customer's PHP runs as its own
account in its own php-fpm pool, so a hole in one application stays inside that account.

```sh
# as root, once per account and per site (site-create does this itself: next recipe)
useradd --system --no-create-home --home-dir /var/lib/agensio/acme --shell /usr/sbin/nologin acme
install -d -o acme -g agensio -m 2750 /var/www/shop.example.com /var/www/shop.example.com/web
```

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
user = "agensio"
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/shop.example.com.toml
[[site]]
server_name = ["shop.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/shop.example.com/web"
app = "wordpress"
user = "acme"                                                 # PHP runs as acme, in a pool agensio generates
access_log = "/var/log/agensio/sites/shop.example.com.log"    # the site's own: acme reads it, nobody else
php = { children = 6 }                                        # every site of acme says the same: they share one pool
tls = "auto"
```

```toml
# /etc/agensio/sites.d/blog.example.com.toml
[[site]]
server_name = ["blog.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/blog.example.com/web"
app = "wordpress"
user = "acme"                                                 # the same customer, the same pool
access_log = "/var/log/agensio/sites/blog.example.com.log"
php = { children = 6 }
tls = "auto"
```

```toml
# /etc/agensio/sites.d/bakery.example.com.toml
[[site]]
server_name = ["bakery.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/bakery.example.com/web"
app = "php"
user = "bakery"                                               # another customer: its own pool, socket and state
access_log = "/var/log/agensio/sites/bakery.example.com.log"
php = { children = 6 }
tls = "auto"
```

**What it does.** For each account agensio derives a php-fpm pool: it runs as the site's
`user` (and `group`, by default the account's primary group), listens on
`/run/php/agensio-<user>.sock`, owned by the account with the server's group and `0660`, so
agensio connects and nobody else can, starts children on demand (`pm = "ondemand"`: nothing
stays resident while a site is quiet), and keeps PHP's uploads, temp files and sessions in the
account's own `/var/lib/agensio/<user>/tmp` and `sessions`, with `open_basedir` at the project
directory plus those two. `agensio pools` writes the pool files into the distribution's
php-fpm directory and creates the account's directories.

The rules `agensio -t` holds every start, reload and control-plane change to, each refusal
naming the path, its owner and mode and the fix:

- the account (and `group`) exists;
- the root belongs to the account or to root, nobody else can write to it, and the server
  reads it through its group (`chown acme:agensio ROOT && chmod 2750 ROOT`);
- the preset's credential files (`wp-config.php` here), `.env` and `.git` are readable by the
  account alone: `0600`, or `0640` with the site's own group, never the server's;
- the pool socket belongs to the account and the server's group, with no bits for others;
- the access log is readable by the account and the server alone, and nobody else can write
  to its directory;
- sites of different accounts never share a root (or nest one inside the other), an access
  log, a state directory or a php socket.

A site that breaks one of these is set aside with its file, and the other sites go on: at a
boot it is not served, and on a reload it keeps its running version only when that version
passes them, so an edit that breaks a rule changes nothing while a root opened to others while
the site serves takes that one site down until it is fixed (health `hosting_rule` says which and
how). Before 0.1.0-alpha.62 one site's rule refused the whole start or reload.

Sites of one account share one pool, so they must agree on its keys (`children`, `pm`,
`max_requests`, `memory_limit`, `max_execution_time`, `version`, `extra`); `agensio -t` names
the key that differs. Easy to get wrong: a site without `access_log` writes the server-wide
log, and two accounts on one log are refused, so give each site its own; started as root,
agensio makes it `agensio:<site group> 0640`, so the customer can read it. A site that runs no
PHP (`app = "proxy"`, `app = "static"`) gets no pool from its `user`: the account owns the
files and, behind a proxy, runs the application.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml    # names any path that breaks the rules, with its fix
agensio pools                              # writes agensio-acme.conf and agensio-bakery.conf; exit 3 when files changed
systemctl reload php8.4-fpm
agensio reload
ls -l /run/php/agensio-*.sock              # each owned by its account, group agensio, srw-rw----
```

**On a managed site.** `site-create` with `--user` does all of this, the account, the
directories, the pool and the php-fpm reload included (next recipe). The pool's size is a
setting, raised within the ceilings root sets in `[control] site_limits`:

```sh
agensio ctl settings bakery.example.com            # the keys, the current values, the ceilings
agensio ctl site-update bakery.example.com --set children=12 --yes --reason "the bakery's busy season"
```

**MCP:** `site_settings_list` with `name`, then `site_update` with `settings` =
`{"children": 12}`.

**Reference:** [Hosting: one user per site](../configuration.md#11-hosting-one-user-per-site),
[the recommended site layout](../install.md#3-recommended-site-layout).

## Create a site through the control plane

**When:** a new customer site, and you want the account, the directories, the log, the php-fpm
pool and the certificate done in one step, checked before anything is written.

```sh
agensio ctl site-create --domain shop.example.com --yes --reason "new customer"
```

The first answer is `422` with the decisions still open, each with a suggestion: `https`
(`auto`), `root` (`/var/www/shop.example.com/web`, below `sites_root`), `app` (what the files
under the root look like, else `static`) and `user` (`shop`, from the domain). Decide them,
try the result, then send it for real:

```sh
agensio ctl site-create --domain shop.example.com --alias www.shop.example.com --app wordpress --user shop --https auto --root /var/www/shop.example.com/web --dry-run --yes --reason "new customer"
agensio ctl site-create --domain shop.example.com --alias www.shop.example.com --app wordpress --user shop --https auto --root /var/www/shop.example.com/web --yes --reason "new customer"
```

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
user = "agensio"
acme = { email = "admin@example.com" }   # --https auto needs it; site-create says so otherwise

[log]
access = "/var/log/agensio/access.log"

[control]
admins = "agensio-admin"
```

```toml
# /etc/agensio/sites.d/shop.example.com.toml: what site-create writes (its first line shortened here)
# agensio:managed {"domain":"shop.example.com","aliases":["www.shop.example.com"],"https":"auto",...}
# shop.example.com: written by agensio ctl on 2026-10-09 10:12:31. `agensio ctl site-update` rewrites it from the line above; edit by hand and
# remove that line to take it over.

[[site]]
server_name = ["shop.example.com", "www.shop.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https"

[[site]]
server_name = ["shop.example.com", "www.shop.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/shop.example.com/web"
app = "wordpress"
user = "shop"
access_log = "/var/log/agensio/sites/shop.example.com.log"
tls = "auto"
```

**What it does.** `--dry-run` runs every check and answers with the file it would write
(`would_write`), every problem at once with the command that fixes it, and the warnings, and
writes nothing; it is still a change request, so it needs `--yes` too. The real call, with the
root helper: the missing account (`useradd --system`, no login, its home the state directory)
and directories (`shop:agensio 2750`) are created, the file is written and validated through a
reload, the site's log is handed to its group, the pool is written and php-fpm reloaded, and
the answer lists all of it under `done`. Without the helper, or when it refuses something, the
answer is `409 prerequisites missing` with `run_as_root`: the exact `useradd`, `mkdir` and
`chown` lines; run them as root and send the same command again. A file that does not validate
is removed and the old configuration keeps serving. A site that adds a privileged port the
running server has not bound yet (the first site on 443) answers `202` with `needs_restart`:
the file is written and valid, and the helper restarts the service (without it the restart is
yours). The answer's `next_steps` say what is left: DNS and port 80 for the certificate, the
request-body limit, and `agensio pools` with the php-fpm reload whenever the call did not do
them itself.

Easy to get wrong: writing a pool reloads php-fpm, and unless `php-fpm.conf` sets
`process_control_timeout`, every PHP request in flight on every site answers `502` at that
moment; `agensio ctl health` reports `php_fpm_hard_reload` with the line to add. The managed
file is regenerated by every `site-update` from its first line: an edit by hand makes the next
update refuse it (`409`). What no field covers goes into the root additions file (below).

**Check it.**

```sh
agensio ctl site shop.example.com                  # the effective locations, the pool, the certificate
curl -sI http://shop.example.com/ | head -1        # 301 to https
tail -n 3 /var/log/agensio/audit.log               # the call, your uid, your reason, the outcome
```

**MCP:** `site_create` with the domain alone (the answer carries the questions), then with
every field and `dry_run`, then for real; `site_show` afterwards. The `new_site` prompt walks a
user through the same questions.

**Reference:** [Control socket](../configuration.md#15-control-socket),
[a session, in practice](../mcp.md#a-session-in-practice).

## Install an application into a managed site

**When:** the site exists, its directory is empty, and the application comes from its official
archive, from an https URL you trust, or from your own machine.

```sh
agensio ctl presets                                  # under source: the presets with an official archive
agensio ctl site-install shop.example.com --dry-run --yes --reason "WordPress"
agensio ctl site-install shop.example.com --yes --reason "WordPress, the newest release"
```

From an https URL (add `--sha256 HEX` when the publisher gives a digest):

```sh
agensio ctl site-install tasks.example.com --url https://github.com/kanboard/kanboard/archive/refs/tags/v1.2.54.tar.gz --yes --reason "Kanboard 1.2.54"
```

From your own machine: the archive travels over SSH, then installs by its name; a theme or a
plugin goes into a new directory of its own:

```sh
ssh admin@host.example.com agensio ctl upload shop-theme.zip < shop-theme.zip    # operator role, no --yes
agensio ctl uploads
agensio ctl site-install shop.example.com --file shop-theme.zip --path wp-content/themes/shop-theme --create-path --yes --reason "the shop's theme"
agensio ctl uploads-delete shop-theme.zip --yes --reason "installed"
```

A plugin that ships a drop-in file as a template, copied to its place inside the same site:

```sh
agensio ctl site-install shop.example.com --url https://downloads.wordpress.org/plugin/sqlite-database-integration.latest-stable.zip --path wp-content/plugins/sqlite-database-integration --create-path --yes --reason "WordPress on SQLite"
agensio ctl site-copy shop.example.com --from wp-content/plugins/sqlite-database-integration/db.copy --to wp-content/db.php --yes --reason "WordPress on SQLite"
```

**What it does.** The files are written as the site's account, never as root or another site's
account, into the site's directory (above a preset's `public/` or `web/`), which must be
empty; `--path` puts them below it and `--create-path` makes the missing levels, as the account.
Archives (`.tar`, `.tar.gz`, `.zip`) are unpacked by agensio's own extractor: a link, a device,
an absolute path or a `..` entry ends the install, and every refusal leaves the directory as
it was. Downloads are https only with the certificate verified, never to a private, loopback
or link-local address on any hop, at most 5 redirects, 1 GB and 15 minutes. For an internal
mirror `[control] install_private = true` lets private addresses through and `install_ca`
names the mirror's CA; `install = false` keeps uploads only. Files get their modes from the
directory (`0640` and `2750` in a `2750` site directory), the preset's credential files
`0600`. The configuration is validated before the answer, which names the source, the sha256,
what was created, and the next steps: the application's own setup in the browser, the site's
request-body limit, and for WordPress and Drupal what makes fail2ban count failed logins.
Uploads wait in `/var/lib/agensio/uploads/`, `[control] upload_max` (512 MB) at most each.

Easy to get wrong: an application's own setup writes its credential file (WordPress's
`wp-config.php`) with php-fpm's umask, not agensio's; `agensio ctl health` reports it as
`hosting_rule` with the fix. An existing destination is never replaced: `site-install` needs an
empty directory, `site-copy` refuses an existing file unless `--overwrite`.

**Check it.**

```sh
agensio ctl health                     # hosting_rule, preset_mismatch, archives_in_root
tail -n 2 /var/log/agensio/audit.log   # the source and the sha256 of what was installed
```

**MCP:** `site_install` with `version`, `url` or `file` (and `path`, `create_path`, `sha256`,
`dry_run`); `uploads_list`; `site_copy` for a drop-in. Files cannot travel through the bridge:
the agent gives the user the `upload` line.

**Reference:** [Control socket](../configuration.md#15-control-socket) (what `site-install`
enforces), [security of the helper](../security-control-plane.md#the-provisioning-helper-f8-2026-09-20).

## Something no field covers: the root additions file

**When:** a managed site needs a location the control plane has no field for: a directory
outside the site's tree, a header on one path, another application behind one path. The
managed file is not the place: `site-update` regenerates it, and refuses one edited by hand.

```sh
agensio ctl site shop.example.com     # root_additions: the file's path, whether it exists, what it added
```

```text
# /etc/agensio/sites.d/shop.example.com.root.toml: root's, 0644, beside the managed file
site = "shop.example.com"                         # the managed site's domain

[[location]]
path = "/downloads/"
alias = "/srv/downloads/shop/"                    # a directory outside the site's tree
add_headers = { "X-Robots-Tag" = "noindex" }

[[location]]
path = "/wp-content/uploads/"                     # only add_headers: joins the preset's location there
add_headers = { "Access-Control-Allow-Origin" = "https://www.example.com" }

[[location]]
path = "/status/"
upstream = "http://127.0.0.1:3001"                # another application for one path
```

```sh
chown root:root /etc/agensio/sites.d/shop.example.com.root.toml
chmod 0644 /etc/agensio/sites.d/shop.example.com.root.toml
agensio -t && agensio reload
```

**What it does.** The loader sorts the included files by what they hold: one whose top level
says `site = "<domain>"` carries `[[location]]` tables for that site, with any key a
`[[site.location]]` takes. They are read after the site file's own locations and before the
preset expands, so they count as hand-written: at a preset's path one replaces the preset's
location, except one with only `add_headers`, which adds its fields to it (the uploads keep
their refusals and their cache header and gain the CORS field). A path the site file already
has is a duplicate, and the reload sets the site's file aside naming the file. The file must be
a regular file owned by the owner of the main file and writable by nobody else, or the site is
set aside with the line to run (never served without it; the other sites load): the server's own account, which writes the managed files, cannot add one. The
control plane never writes it. This block is shown as text because it lives in a file of its
own; `agensio -t` checks it on the host.

Easy to get wrong: the tables are `[[location]]`, not `[[site.location]]`, and a `[[site]]` in
this file is refused. There is no location key for a redirect of one path; a whole site's
`redirect` is a site key. A plain `site-delete` renames the file `.root.toml.bak` beside the
site file's `.bak`, `site-delete --files` moves it into the trash with the site, and a file whose
site is disabled or gone is ignored with a warning (`agensio -t`, the error log, health
`root_additions_orphan`).

**Check it.**

```sh
agensio -t --explain | grep -A3 'from root:'                       # the added locations, marked with their file
agensio ctl path-check shop.example.com /downloads/price-list.pdf  # the location that answers, and the file
curl -sI https://shop.example.com/downloads/price-list.pdf | grep -i x-robots-tag
```

**MCP:** `site_show` names the file; the agent hands the user the exact block for it, never
edits the managed file, and reads the result back with `site_show` after `agensio reload`.

**Reference:** [Control socket](../configuration.md#15-control-socket) (root additions to a
managed site), [Locations, the reference](../configuration.md#6-locations-the-reference).

## Delete a site and get it back

**When:** a customer leaves or stops paying, and the site must stop, or go, while staying
recoverable for a while.

```sh
agensio ctl site-disable shop.example.com --yes --reason "invoice unpaid"    # off; the file kept as .disabled
agensio ctl site-enable shop.example.com --yes --reason "paid"
```

```sh
agensio ctl site-delete shop.example.com --files --yes --reason "customer left"
agensio ctl trash                                                     # the entries, their pieces, sizes and expiry
agensio ctl site-restore shop.example.com-20261009-101231 --yes --reason "customer is back"
agensio ctl trash-delete shop.example.com-20261009-101231 --yes --reason "gone for good"
```

**What it does.** Without `--files`, `site-delete` removes the configuration alone: the file
becomes `.bak` (and the root additions file `.root.toml.bak` beside it), the files and the
account stay where they are, and renaming both back and reloading returns the site. With
`--files` everything of the site moves by rename into
`/var/www/.trash/<domain>-<date>-<time>/` (the time in UTC), a directory root owns alone
(`0700`): the site's directory (the first one below `sites_root` on its root's path,
`/var/www/shop.example.com`), the account's state directory (or only the site's virtualenv
when another site shares the account), its access log with its rotations, its environment file,
its root additions file, and the site file's text in the entry's manifest. Nothing is copied.
An entry expires after `[control] trash_keep` days (60 by default, 0 keeps it until
`trash-delete`), removed by worker 0's hourly check or by `agensio ctl trash-expire`.
`site-restore` puts every piece back and reloads, but only into an empty place (never over
files that appeared since) and only with the account at the uid the files carry; otherwise the
answer gives root the `useradd --uid` line.

Easy to get wrong: the account is never removed (`trash` says when no site uses it any more,
for root's `userdel`). Deleting with files is refused while the site's application service
runs (the answer carries root's `systemctl` lines), for a directory outside `sites_root`, and
on a server without the root helper, where the files are removed by hand. A restore does not
bring back the service that runs a Rails, Django or Node application: `site-unit` renders its
unit again for root.

**Check it.**

```sh
agensio ctl sites                                        # the site is gone
grep 'customer left' /var/log/agensio/audit.log          # what moved, and where to
```

**MCP:** `site_delete` with `files: true` (the agent asks which of the two the user means),
`trash_list`, `site_restore` with `entry`; `trash_delete` only for an entry the user named.

**Reference:** [Control socket](../configuration.md#15-control-socket) (deleting a site with
its files).

## Who may do what: roles and the audit log

**When:** several people work on the host: an administrator, someone on call who reloads and
renews certificates, a developer or a customer who should only read the logs and the health.

```sh
groupadd --system agensio-admin && groupadd --system agensio-ops && groupadd --system agensio-view
usermod -aG agensio-admin anna       # creates, changes, installs, deletes
usermod -aG agensio-ops oncall       # reloads, reopens logs, renews certificates, uploads archives
usermod -aG agensio-view dev1        # reads: status, sites, logs, health, presets, settings
agensio reload                       # after the groups appear in [control]; members log in again for a new group
```

The groups are the `[control]` table of [the main file](#the-main-file-of-a-shared-host).

**What it does.** Each connection gets one role from its peer's uid and that account's groups:
root and `[server] user` are always admins, otherwise the highest of the groups the account is
in; the roles nest, so an operator also reads and an admin does everything. Anyone else is
disconnected at once. A few reads are an admin's because they show secrets or a tenant's
private data: `trash`, `site-env`, `site-auth-users`, `site-service-logs`,
`site-task-output`. A command above the caller's role answers `403` naming the role it needs.
Every change, every refused connection and every refused command is one line of the audit
log (beside the error log by default, `[control] audit` elsewhere): time, uid, gid, role, the
command with its reason, and the outcome:

```text
2026/10/09 10:12:31 uid=1001 gid=1001 role=admin sites (new customer): created /etc/agensio/sites.d/shop.example.com.toml
```

Easy to get wrong: a group named in `[control]` that does not exist gives nobody that role, and
the error log says so when the server starts. With `admins` as the only role group the socket
file is `0660` for that group, so a new member logs in again before `agensio ctl` works for
them; with more groups it is `0666` and the credentials alone decide. Never put a site's
account in a role group, and never run a site's PHP or application as the server's own
account: a process running as either reaches the socket with that role, which is why each site
gets its own account.

**Check it.**

```sh
agensio ctl status | grep -o '"role":"[a-z]*"'     # as each user: the role the server gives them
tail -f /var/log/agensio/audit.log
```

**Reference:** [Control socket](../configuration.md#15-control-socket) (who may connect,
audit, the role of each command).

## Let an AI agent manage the host

**When:** an agent on your own machine (Claude Code, Claude Desktop, any MCP client) should
create sites, install applications, read logs and run health checks on the server, with a role
and an audit trail like a person's.

On the server, give the agent its own key on your account (here `anna`, in the
`agensio-admin` group of the previous recipe) and let that key run the bridge and nothing else:

```text
# ~anna/.ssh/authorized_keys on the server
command="agensio mcp",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA... agent@laptop
```

On your machine, a host entry for that key and the MCP server entry (Claude Code:
`~/.claude.json` or the project's `.mcp.json`; Claude Desktop takes the same block):

```text
# ~/.ssh/config
Host host1-agent
    HostName host1.example.com
    User anna
    IdentityFile ~/.ssh/agent_ed25519
    IdentitiesOnly yes
```

```json
{
  "mcpServers": {
    "host1": { "command": "ssh", "args": ["-o", "BatchMode=yes", "host1-agent"] }
  }
}
```

**What it does.** `agensio mcp` is not a listener: it talks on its own stdin and stdout, over
the SSH session, and connects to the control socket as the account that started it, so the
agent has that account's role and every change it makes is an audit line with that uid and the
reason it gave. A viewer's session does not even list the tools that change anything; each
change needs a confirmation and a reason, and the agent host asks you before running it. What
needs root on a server without the helper comes back as commands for you to run. The forced
command matters: the confirmations the bridge asks of you in person (a `pip_install` of
packages the agent named) bind only when the bridge is the agent's one way in, and a key that
may run anything would let the agent call `agensio ctl` itself and answer for you. Keep your
own key, without the restriction, for your terminal.

Easy to get wrong: files do not travel through the bridge; an archive on your machine goes up
with `ssh anna@host1.example.com agensio ctl upload NAME < FILE`, with your own key, and the
agent installs it by name. After an upgrade, reconnect the MCP server in the agent host: a
bridge keeps the tools and texts it started with, and its answers say when the server's version
differs. The agent cannot edit the main file, a hand-written site file or a root additions file,
run a command of its choosing, change the firewall, remove an account, or delete files except
into the trash; it hands you those as exact lines.

**Check it.**

```sh
ssh anna@host1.example.com agensio ctl status | grep -o '"role":"[a-z]*"'   # your own key: the role the agent will have
tail -f /var/log/agensio/audit.log                                          # on the server, while the agent works
```

**MCP:** the `getting_started` prompt has the agent run `health_check` and `server_status`,
explain the findings and offer the usual jobs; `new_site` walks a user through a new site.

**Reference:** [Managing agensio with an AI agent](../mcp.md),
[connecting from your machine](../mcp.md#connect-from-your-machine-to-a-vps),
[the agent's own key](../mcp.md#give-the-agents-key-the-bridge-and-nothing-else),
[what it cannot do](../mcp.md#what-it-cannot-do).

## A host a panel manages

**When:** a hosting panel writes the site files itself and runs the host's firewall and
fail2ban; agensio serves the sites and should not report protection the panel already gives.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
user = "agensio"
acme = { email = "admin@example.com" }

[control]
host_protection = "external"            # the panel runs the firewall and fail2ban: health's findings are informational
```

```toml
# /etc/agensio/sites.d/example.com.toml: written by the panel
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https"

[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"                  # the panel's web/
user = "web35"                                     # the panel's account for this site
group = "client8"                                  # the customer's group: it reads the site's log
app = "wordpress"
php = { children = 6 }
access_log = "/var/www/example.com/log/access.log" # the panel's log/
tls = "auto"
```

**What it does.** The panel's layout maps directly: its `web` is `root`, its `log` is
`access_log` (made `agensio:client8 0640` at start, so the customer reads it), its `ssl` is
`tls = { cert, key }` or `tls = "auto"`, and a `cgi-bin` is a `handler = "cgi"` location. The
file has no managed first line, so `site-update` refuses it and the panel stays its owner; the
hosting rules of [one account per site](#one-account-per-site) apply all the same, and
`agensio reload` checks every file before it signals the server. With
`host_protection = "external"` health's protection findings (no per-address limit in the
firewall, no fail2ban jail over agensio's logs) stay at info level; `"off"` skips the check.
The renderer stays available, so the panel can install agensio's jail drop-in and its firewall
table (`inet agensio`, a table of its own beside the panel's rules) from a script.

**Check it.**

```sh
agensio protection -c /etc/agensio/agensio.toml --jail    # the jails for this host's logs, no server needed
agensio ctl protection                                     # what the firewall and fail2ban do now
agensio ctl health                                         # the protection findings, informational
```

**MCP:** `protection_show` and `health_check`.

**Reference:** [Connection limits and host protection](../configuration.md#18-connection-limits)
(hosting panels), [Let fail2ban count failed logins](protection.md#let-fail2ban-count-failed-logins),
[the recommended site layout](../install.md#3-recommended-site-layout).
