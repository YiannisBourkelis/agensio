# Managing agensio with an AI agent (MCP)

agensio ships a [Model Context Protocol](https://modelcontextprotocol.io) server:
`agensio mcp`. An agent host such as Claude Code, Claude Desktop, Cursor or any MCP
client spawns it, and the agent can then inspect and configure the web server through
a fixed set of tools: check its health, list sites, read recent errors, create or change
a site, install an application into it, reload, renew a certificate. The server never
embeds a model; the one network action it takes on an agent's behalf, downloading an
application archive for `site_install`, is fenced (https only, public addresses only,
size caps, verified certificate, optional sha256) and audited. It offers precise,
audited tools and nothing else.

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
  a restart, and an application install as the site's account. `site_create` is then one
  call and reports what it did under `done`. The helper does those six things and nothing
  else; `docs/security-control-plane.md`.
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

## Tools

| tool | role | what it does |
|---|---|---|
| `health_check` | viewer | findings with a fix each: certificates, missing redirects, port 80 for ACME, recent errors, settings waiting for a restart, root, shared accounts, stale pools |
| `server_status` | viewer | version, pid, uptime, workers, connections, listeners, sites, the caller's role |
| `sites_list`, `site_show` | viewer | sites with their certificate state; one site with its effective locations |
| `config_validate` | viewer | the file on disk: errors and restart-only differences |
| `presets_list` | viewer | what each `app` value does: served root, which `.php` runs, refusals; from the preset table, so a new preset appears at once |
| `logs_query` | viewer | recent error-log and access-log lines, filtered by site, time, level and status |
| `reload`, `logs_reopen` | operator | reload without dropping connections; reopen logs after rotation |
| `cert_renew` | operator | order an automatic certificate again now |
| `site_create`, `site_update` | admin | write or change a managed site file, validate, reload; answer with open decisions or root commands first |
| `site_disable`, `site_enable`, `site_delete` | admin | rename the file away and back; delete it (a `.bak` stays) |
| `site_install` | admin | put an application's files into a site's empty directory as the site's account: the preset's official archive (`version` optional), any https `url`, or a stored upload (`file`); a plugin or theme goes into `path` with `create_path: true`; `sha256`, `strip`, `dry_run`; the server enforces the fences and reports the source, digest and what it created |
| `site_copy` | admin | copy one regular file of a site to another path of the same site, as the site's account: the drop-ins applications ship as templates (WordPress's `wp-content/db.php` from the SQLite plugin, Drupal's `settings.php`); `overwrite`, `dry_run`; never across sites, never caller content, never a directory |
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

## What it cannot do

Install packages, edit hand-written site files, run anything as root, reach other
machines except to download an archive you named into a site (and never a private
address), carry files itself. Those are yours, on purpose. On a server with the helper
it creates site accounts, restarts the service after a change that needs it and installs
applications as the site's account; without the helper it hands the commands back.
