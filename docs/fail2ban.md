# fail2ban with agensio

How agensio uses fail2ban, what it renders for the host, what each application type gets,
and what the application side needs so that failed logins are counted rather than guessed.
This is the administrator's guide; the reference for the keys is `docs/configuration.md`
section 18, and the protection split it belongs to is explained there too.

## 1. Where fail2ban fits

Protection against abuse is split by who can see what:

| concern | owner | why |
|---|---|---|
| timeouts, protocol budgets, the connection ceiling per worker | agensio | only the server sees a connection's state |
| connections and connection rate per address, QUIC handshakes per address | nftables (`table inet agensio`) | the kernel keeps that table already; the server would pay on every accept |
| brute force on logins, scanners, abusive clients over time | fail2ban, reading the access logs and the applications' logs | a ban is a firewall rule for a while; the logs carry the evidence |
| volumetric floods | the provider or a CDN | nothing on the host can absorb a filled pipe |

fail2ban bans through nftables into a table of its own (`banaction = nftables-multiport`), so
it coexists with agensio's limits table and with a panel's rules. Both pieces are rendered
by agensio for the host they run on and applied by root; agensio never writes into
`/etc/fail2ban` or the live firewall itself.

## 2. What agensio renders

```sh
agensio ctl protection                 # the whole picture as JSON: files, commands, what is in place
agensio ctl protection --jail          # the jail file for this host
agensio ctl protection --filter NAME   # one of the five shipped filters
agensio protection -c /etc/agensio/agensio.toml --jail   # the same, from the configuration alone, no server needed
```

The MCP tool `protection_show` answers the same picture to an agent. The shipped copies
under `/usr/share/agensio/fail2ban/` are the rendering for a default host; the host's own
rendering carries its ports, its access logs and error log, the login paths of its sites and the
jails of the application types it runs.

Install, as root:

```sh
install -m 644 /usr/share/agensio/fail2ban/filter.d/agensio-*.conf /etc/fail2ban/filter.d/
agensio ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf
fail2ban-client reload
```

The jail file is rendered from the sites that exist, so adding a site, a log or a login path
makes the installed copy stale; health says so (`fail2ban_jail_stale`) and the second and
third lines above refresh it. An upgrade that changes a shipped filter is reported the same
way (`fail2ban_filter_stale`), with the first line ahead of the others. A site change through
the control plane puts the same lines into the answer's `next_steps` when they apply.

Two tiers of jails come out of that file.

### 2a. The attempt tier: the access logs

These jails need nothing from the application. They read agensio's access logs, which are
in the combined format (`[log] format = "combined"`, the default; JSON logs are not read)
with the client address first. Behind a load balancer or CDN, `server.trusted_proxies`
makes that address the real client's, so bans hit the right one.

| jail | counts | threshold | ban |
|---|---|---|---|
| `agensio-login`, one per access log | POST requests to the login paths of the sites writing that log, in every spelling the server accepts | 10 in 10 min | 1 h |
| `agensio-denied` | answers 403: an address outside a site's access rule (`[[site.access]]`), a password asked for over plain HTTP, an application refusing; never 401 (section 2c) | 10 in 10 min | 1 h |
| `agensio-scan` | answers 404 | 40 in 5 min | 1 h |
| `agensio-post` | POST requests to any path, the catch-all for a login nobody named | 120 in 2 min | 30 min |

An access log cannot tell a failed login from a successful one, so `agensio-login` counts
attempts: no person types ten passwords in ten minutes, every brute-force tool does. The
login paths come from the preset (`wordpress`: `/wp-login.php` and `/xmlrpc.php`, `drupal`:
`/user/login`, `laravel`: `/login` and `/cp/auth/login`, `grav`: `/admin`, `redmine`:
`/login`, `django` and `wagtail`: `/admin/login/`) and from each site's `login_paths`
(`agensio ctl site-update NAME --login-path /login`, the `login_paths` field of
`site_update`), including a path with the start of its query for an application that routes
its login that way. Because the log holds the request as the client sent it, the rendered
filter matches each path in every spelling the server and the applications accept:
percent-encoding, repeated slashes, dot segments, case, a trailing slash, `/index.php`
before a PHP application's path, a `.format` suffix on a Rails path, query parameters in any
order. One canonical spelling in `login_paths` is enough. The server-wide access log gets
the jail `agensio-login`; a site with its own `access_log` gets `agensio-login-<site>` with
its own paths, so one application's paths are never counted on another's log.

An API that clients legitimately post to often is excluded from `agensio-post` with the
filter's `ignore` parameter in a local override (section 4).

### 2b. The failure tier: the applications' own logs

An application that logs its own failed logins gives fail2ban the better signal: failures,
not attempts, with the client address in the line and no URL spelling to match. This is
also what fail2ban ships filters for and what the application communities recommend. Where
a preset's application does, the jail file carries a jail over that log:

| jail | application | log | filter | threshold |
|---|---|---|---|---|
| `agensio-wordpress-soft` | WordPress with the WP fail2ban plugin | the auth log (`/var/log/auth.log`, `/var/log/secure` on RHEL), or the journal | the plugin's `wordpress-soft` | 5 failed logins in 10 min, 1 h |
| `agensio-wordpress-hard` | the same | the same | the plugin's `wordpress-hard` | 1 hit (blocked user names, pingback errors), 1 day |
| `agensio-drupal-auth` | Drupal with its Syslog module | the system log (`/var/log/syslog`, `/var/log/messages` on RHEL), or the journal | fail2ban's own `drupal-auth` | 5 in 10 min, 1 h |

**Files or the journal.** Both applications log through syslog. On a host where a syslog
daemon writes files (rsyslog or syslog-ng, told by their pid files under `/run`) the jails
read those files. On a host that runs journald alone, Debian 13's default, there is no
`/var/log/syslog`, and an `auth.log` left over from an earlier install stays empty while the
lines go to the journal; so there the jails are rendered with `backend = systemd` and a
`journalmatch` naming each site account's uid: `SYSLOG_IDENTIFIER=drupal _UID=<uid>` for a
Drupal site, `_SYSTEMD_UNIT=<php-fpm unit> _UID=<uid>` for a WordPress site, one group per
account with `+` (or) between them, and no log file is needed or asked for. The uid is a
field journald sets from the sender's credentials. The identity alone is never matched: it
is whatever a writer passes to `openlog()` or `logger -t`, so five forged lines from any
account on the host (another site's compromised plugin, a shell user) would have banned any
address, a visitor's or Let's Encrypt's (the alpha.49 report). The plugin's own identity
`wordpress(<host>)` carries the client's Host header and is not matched either; the filter
still requires it in the line. A site without an account of its own (`user`) has no trusted
field: the jail lists it as not read, health says so with the account as the fix, and only
the sites with accounts are counted. With a syslog daemon the files carry no uid, which is
the usual fail2ban position and the reason the journal is the better log here.

Three facts from fail2ban's own documentation (`docs/fail2ban-ref/`) shape these lines.
fail2ban's `drupal-auth` filter pins no identity of its own (it keeps `common.conf`'s default
`_daemon = \S*`), so the `SYSLOG_IDENTIFIER=drupal` word of the match is what selects Drupal's
lines, and `drupal` is the Syslog module's default identity: a site that changes it in the
module's settings leaves the jail reading nothing. The WP fail2ban filters do pin theirs,
`_daemon = (?:wordpress|wp)`, so a line must still carry `wordpress(<host>)` to match. And
fail2ban's systemd backend opens the system journal alone by default (`journalflags` 4), while
journald files the lines of a process with an ordinary uid, 1000 or above, under that user's
own journal; so a jail over such an account (a hosting panel's web user, not the system
accounts agensio creates) is rendered `backend = systemd[journalflags=1]`, the fix the
project's wiki gives for exactly this plugin. Debian's and Fedora's `fail2ban` packages depend
on `python3-systemd`, which the backend needs.

Each jail is rendered enabled only when its filter file exists, and with a syslog daemon
its log too, because fail2ban refuses a configuration that names either when missing. Until
then the jail is written disabled with its `needs` as comments, health reports
`fail2ban_failures_unseen` for the application, and `site_install` of such a site lists the
steps. agensio installs no plugin and changes no application: those steps are yours, in the
application's admin panel and as root. The attempt tier keeps counting meanwhile.

On a journald-only host the Drupal jail is enabled at once, since fail2ban ships its filter
and the journal is always there, and the WordPress jails as soon as their filters are in
place; neither says whether the application writes anything yet. So health asks the journal
itself, through the helper, for one line matching the jail's own `journalmatch` (the trusted
fields above) from the last 30 days, and keeps `fail2ban_failures_unseen` while there is
none: the Syslog module is still off, or the plugin is not active yet (or nobody has logged
in since). `agensio ctl protection` and `protection_show` report it as `journal_seen` per
jail and the sites it cannot read as `unidentified`.

### 2c. Passwords agensio asks for: the error log

A site's `[[site.auth]]` paths (`docs/configuration.md` 19b) are agensio's own login, so agensio
writes its failures itself: one `warn` line in the error log per login it refused, and none for
anything else.

```
2026/10/08 17:20:01 [warn] auth failed: client 198.51.100.4 site shop.example realm "Shop staging" user "anna" (wrong password) GET /private/
```

| jail | counts | threshold | ban |
|---|---|---|---|
| `agensio-auth` | `auth failed` lines with the reason `wrong password`, `unknown user`, `locked user` or `malformed credentials` | 10 in 10 min | 1 h |

**Why not the 401s.** A 401 in the access log is mostly not a failure. It is the challenge:
a browser's first request to a protected path carries no password, the 401 makes it ask, and
on a site protected as a whole a browser meets several: it sends the password unasked only
below the directory of the address that was challenged (RFC 7617 2.2, `docs/rfc/`), so each
other directory it loads from starts with a 401. A client that does not send credentials
preemptively (WebDAV, .NET's `HttpClient`, many API libraries) meets one before every
request. Until alpha.58 the filter called `agensio-auth` counted every 401 and 403 in the
access logs, so a password-protected site banned the people who had the password. fail2ban's
own filters do the same as agensio does now: `apache-auth` and `nginx-http-auth` read the
error logs, and `apache-auth.conf` says why: "An unauthorized response 401 is the first step
for a browser to instigate authentication however apache doesn't log this as an error"
(`docs/fail2ban-ref/config/filter.d/`). The 403s the old filter also counted are
`agensio-denied`'s now, over the access logs as before.

**What counts.** A wrong password, a user the file does not have, a locked user (`!` or `*`
in the file), and an `Authorization` field that does not decode: in each, the client did not
show that it knows a password. An expired user's right password (`expired`) is no guess and
is not counted; a challenge writes no line at all. The line is anchored: the date, `[warn]`,
then `auth failed: client <ADDR>`, so the address is always the server's own reading of the
connection (behind `trusted_proxies`, the client X-Forwarded-For named); the realm and the
user name come after it with every `"`, backslash and control byte escaped, so a user name
cannot pass for another address. The filter takes addresses only (`<ADDR>`), never names to
resolve.

**What it needs.** The error log in a file at `warn` or more: `[log] error =
"/var/log/agensio/error.log"` and `level = "warn"`, the package's defaults. With the error
log on stderr or at `level = "error"` the jail is rendered disabled with root's line, and
health reports `fail2ban_auth_unseen` for the sites with a password. The jail names no site,
so a site that gains a password needs no new rendering.

**Who else gets banned.** A browser asks again after a wrong password, so a person
mistyping writes one line each time; ten in ten minutes is no person. A script or a monitor
that keeps sending an old password after it changed writes one per request and is banned
like a guesser; list the monitor's address in `ignoreip` (section 4) or give it the new
password. An application's own 401s (one that asks for a password itself, an API with
tokens) are not counted by any agensio jail: put `[[site.auth]]` in front of it to have the
failures counted, or add a local failure jail over the application's log (section 4).

Test it on the host's own log: `fail2ban-regex /var/log/agensio/error.log agensio-auth`.

## 3. What each application type gets, and what to add

### WordPress (`app = "wordpress"`)

- Attempt tier: `/wp-login.php` and `/xmlrpc.php`. One XML-RPC `system.multicall` can carry
  hundreds of password tries, which is why `xmlrpc.php` is a login path; a client that posts
  there more than ten times in ten minutes, the WordPress mobile application without
  Jetpack, is banned for an hour.
- Failure tier: install and activate the **WP fail2ban** plugin from the WordPress admin
  panel (Plugins, Add New, "WP fail2ban"). It writes every failed login, form and XML-RPC,
  to the system's auth log as `wordpress(example.com)[pid]: Authentication failure for admin
  from 203.0.113.9`, and it ships its own filters. Root installs those two filter files once
  per host, then renders the jail again. Take them from the plugin's release, not from the
  site's directory: that directory belongs to the site's account, and whoever takes over the
  WordPress site could plant a filter that bans your own address or carries a regex that
  freezes fail2ban. Or read the site's copies before installing them.

  ```sh
  cd /tmp && curl -fsSLO https://downloads.wordpress.org/plugin/wp-fail2ban.latest-stable.zip \
    && unzip -o -j wp-fail2ban.latest-stable.zip wp-fail2ban/filters.d/wordpress-hard.conf \
                                               wp-fail2ban/filters.d/wordpress-soft.conf -d /etc/fail2ban/filter.d/
  agensio ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf && fail2ban-client reload
  ```

  Behind a trusted proxy the plugin needs `WP_FAIL2BAN_PROXIES` in `wp-config.php` so that
  it logs the client, not the proxy. On a journald-only host nothing else is needed; the
  jails read the journal.
- Also worth doing in the application: disable XML-RPC when nothing uses it (a one-line
  plugin, or the WP fail2ban setting that blocks it); an application-level lockout plugin
  such as Limit Login Attempts Reloaded, which stops password guessing per account and so
  covers an attack spread over many addresses, which fail2ban's per-address bans cannot;
  two-factor authentication for the administrator accounts. The preset itself never serves
  `wp-config.php`, `readme.html` or `license.txt` and never executes PHP under `uploads`.

### Drupal (`app = "drupal"`)

- Attempt tier: `/user/login`.
- Failure tier: enable the core **Syslog** module (Extend, Syslog). Drupal then writes
  `...|user|203.0.113.9|...|Login attempt failed for admin.` to syslog, which fail2ban's own
  `drupal-auth` filter reads from the system log or, on a journald-only host, from the
  journal under the identity `drupal`; nothing to copy or install.
- Drupal's own flood control is on by default: 50 failed logins per address per hour and 5
  per account in six hours block further attempts. The Flood Control module gives those
  numbers a settings page; the Login Security module adds notifications and per-account
  lockouts; the TFA module adds two-factor authentication.

### Laravel and Statamic (`app = "laravel"`)

- Attempt tier: `/login` and `/cp/auth/login` (Statamic's control panel).
- Laravel's starter kits throttle the login route in the application (five attempts a minute
  per account and address); Statamic's control panel does the same. There is no standard
  failure log for fail2ban; the attempt tier covers the rest.

### Grav (`app = "grav"`)

- Attempt tier: `/admin`, where the admin plugin's login form posts.
- Keep the Admin and Login plugins current, and turn on two-factor authentication for the
  administrator accounts in the admin panel.

### Redmine (`app = "redmine"`) and other Rails applications (`app = "rails"`)

- Attempt tier: `/login` for Redmine; a Rails application names its own path with
  `login_paths` (Devise's is `/users/sign_in`). A `.format` suffix (`/login.html`) is
  matched as well.
- Redmine writes `Failed login for 'admin' from 203.0.113.9 at ...` to its
  `log/production.log`, and Redmine's own wiki page "HowTo Configure Fail2ban For Redmine"
  gives a filter for it (section 4 shows the shape). One caveat from that page: Redmine's
  log lines carry no timestamp, so fail2ban dates every line at the moment it reads it; a
  restart of fail2ban can count old failures as fresh ones. agensio does not render this
  jail yet.

### Django and Wagtail (`app = "django"`, `app = "wagtail"`)

- Attempt tier: `/admin/login/`, and `/django-admin/login/` for Wagtail.
- In the application, django-axes is the standard brute-force protection: lockouts per
  account and address, with its own record of failures. Wagtail's admin uses Django's
  authentication, so it benefits as well.

### Node (`app = "node"`)

- No login path is known; set the application's with `login_paths` (an Uptime Kuma instance
  logs in through Socket.IO, so it has none to name). Rate limiting in the application
  (`express-rate-limit` or the framework's equivalent) is the application's own layer.

### Plain PHP and static sites (`app = "php"`, `app = "static"`)

The preset cannot know the application, so name its login path:

| application | `login_paths` | notes |
|---|---|---|
| Kanboard | `["/?controller=AuthController&action=check"]` | Kanboard shows a captcha after three failures and locks the account for fifteen minutes after six (`BRUTEFORCE_*` settings); its documentation points to fail2ban for scans |
| Roundcube | `["/?_task=login"]` | fail2ban ships `roundcube-auth`, which reads Roundcube's `logs/errors.log` (`Login failed for user from 203.0.113.9`); a local jail over the site's file completes the failure tier (section 4) |
| phpBB | `["/ucp.php?mode=login"]` | |
| anything else | the path its login form posts to, with the query when the application routes by it | the agent asks you; it never guesses |

## 4. Operating it

**Your own address.** fail2ban ignores the host's own addresses by default (`ignoreself`),
and loopback. Add the addresses you administer from in a local file that fail2ban reads
after agensio's, since `jail.d` is read in alphabetical order:

```ini
# /etc/fail2ban/jail.d/zz-local.conf
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 198.51.100.7
```

**Changing a threshold or excluding an API.** Override a section in the same local file;
never edit `agensio.conf`, which the next rendering replaces:

```ini
[agensio-login]
maxretry = 20

[agensio-post]
filter = agensio-post[ignore="/api/|/jsonrpc\.php"]
```

**Seeing and lifting bans.**

```sh
fail2ban-client status                       # the jails
fail2ban-client status agensio-login         # files read, failures counted, addresses banned
fail2ban-client set agensio-login unbanip 203.0.113.9
```

`agensio ctl protection` shows the same counts under `fail2ban.detected`, and health reports
when no jail reads agensio's logs (`fail2ban_missing`), when the jail or a filter on disk is
older than the build (`fail2ban_jail_stale`, `fail2ban_filter_stale`), when a site has no
access log for fail2ban to read (`fail2ban_blind`), when the logs are JSON
(`fail2ban_log_format`), when an application's failure tier is not in place yet
(`fail2ban_failures_unseen`), when a site has a password and nothing counts its failed logins
(`fail2ban_auth_unseen`), and, as a warning to act on at once, when the installed
`agensio-auth` filter is an older build's that counts every 401 and so bans the people with
a site's password (`fail2ban_auth_challenges`).

**A local failure jail for an application agensio does not render.** The shape, for Redmine's
production log, with the regex from Redmine's own wiki:

```ini
# /etc/fail2ban/filter.d/redmine-auth.conf
[Definition]
failregex = Failed [-/\w]+ for .* from <HOST>

# /etc/fail2ban/jail.d/zz-local.conf
[redmine-auth]
enabled  = true
port     = 80,443
filter   = redmine-auth
logpath  = /var/www/redmine.example.com/app/log/production.log
banaction = nftables-multiport
maxretry = 5
findtime = 10m
bantime  = 1h
```

Test a filter against a log before trusting it: `fail2ban-regex /path/to/log redmine-auth`.

**Testing and reading what fail2ban runs.** `fail2ban-regex` takes a log file, one line in
quotes, or the journal; a journal jail is tested with the same words agensio rendered:

```sh
fail2ban-regex 'Oct  4 10:00:01 host wordpress(example.org)[123]: Authentication failure for admin from 203.0.113.9' wordpress-soft
fail2ban-regex systemd-journal[journalflags=1] drupal-auth -m 'SYSLOG_IDENTIFIER=drupal _UID=997'
fail2ban-regex -v /var/log/agensio/access.log 'agensio-login[paths="/wp-login\.php"]'   # -v shows which line matched which regex
fail2ban-client -d | grep agensio-drupal-auth     # the merged configuration the server loaded, journal matches included
fail2ban-client -vvv -x start                     # when the service will not start: which jail, filter or action
```

`Found` lines in `/var/log/fail2ban.log` without a `Ban` mean `maxretry` within `findtime`
was not reached. The reference set in `docs/fail2ban-ref/` holds the manuals (`jail.conf(5)`,
`fail2ban-regex(1)`, `fail2ban-client(1)`), the shipped jails, filters and nftables actions,
the journal backend's source and the project wiki's pages on regexes and troubleshooting.

**A panel host.** When a hosting panel manages fail2ban, agensio's jail file is one drop-in
among the panel's, which appears in its fail2ban page like Postfix's or Dovecot's. Set
`[control] host_protection = "external"` so that health reports the missing pieces as
information rather than warnings, or `"off"` to skip the check; the files are rendered
either way.

## 5. What it does not do

The attempt tier counts attempts, not failures; a person who logs in correctly ten times in
ten minutes is banned too, which is why the failure tier is worth its two steps. Every ban
is per address: an attack spread over many addresses, each under the threshold, is the
application's lockout or captcha to stop, which is why the application-level measures above
are listed next to the jails. Per-address connection limits and QUIC are the firewall's
(`docs/configuration.md` 18), and bans never reach the UDP side. And fail2ban reads files:
a site whose `access_log` is off, or a host whose logs are JSON, gives it nothing to read.

## 6. References

`docs/fail2ban-ref/` is fail2ban as its authors document it, kept in the tree the way
`docs/rfc/` keeps the protocol specifications: the 1.1.0 manuals rendered as text, the shipped
`jail.conf`, path, filter and nftables action files, the systemd backend's source
(`filtersystemd.py`: how `journalmatch` is parsed and how a journal entry becomes the line a
filter sees), the project wiki's pages on developing regexes, best practice, troubleshooting
and the 0.10.5 `journalflags` change, and the WP fail2ban plugin's three filters. Its README
maps each file to the renderer or section here that depends on it and lists the facts that
bind them. Read it before changing a jail or a filter; cite it when you do.
