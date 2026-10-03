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
agensio ctl protection --filter NAME   # one of the four shipped filters
agensio protection -c /etc/agensio/agensio.toml --jail   # the same, from the configuration alone, no server needed
```

The MCP tool `protection_show` answers the same picture to an agent. The shipped copies
under `/usr/share/agensio/fail2ban/` are the rendering for a default host; the host's own
rendering carries its ports, its access logs, the login paths of its sites and the jails of
the application types it runs.

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
| `agensio-auth` | answers 401 and 403 | 10 in 10 min | 1 h |
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
| `agensio-wordpress-soft` | WordPress with the WP fail2ban plugin | the auth log (`/var/log/auth.log`, `/var/log/secure` on RHEL) | the plugin's `wordpress-soft` | 5 failed logins in 10 min, 1 h |
| `agensio-wordpress-hard` | the same | the same | the plugin's `wordpress-hard` | 1 hit (blocked user names, pingback errors), 1 day |
| `agensio-drupal-auth` | Drupal with its Syslog module | the system log (`/var/log/syslog`, `/var/log/messages` on RHEL) | fail2ban's own `drupal-auth` | 5 in 10 min, 1 h |

Each of these is rendered enabled only when its filter file and its log exist on the host,
because fail2ban refuses a configuration that names either when missing. Until then the jail
is written disabled with its `needs` as comments, health reports `fail2ban_failures_unseen`
for the application, and `site_install` of such a site lists the steps. agensio installs no
plugin and changes no application: those steps are yours, in the application's admin panel
and as root. The attempt tier keeps counting meanwhile.

## 3. What each application type gets, and what to add

### WordPress (`app = "wordpress"`)

- Attempt tier: `/wp-login.php` and `/xmlrpc.php`. One XML-RPC `system.multicall` can carry
  hundreds of password tries, which is why `xmlrpc.php` is a login path; a client that posts
  there more than ten times in ten minutes, the WordPress mobile application without
  Jetpack, is banned for an hour.
- Failure tier: install and activate the **WP fail2ban** plugin from the WordPress admin
  panel (Plugins, Add New, "WP fail2ban"). It writes every failed login, form and XML-RPC,
  to the system's auth log as `wordpress(example.com)[pid]: Authentication failure for admin
  from 203.0.113.9`, and it ships its own filters. Root copies them once per host, then
  renders the jail again:

  ```sh
  install -m 644 /var/www/example.com/wp-content/plugins/wp-fail2ban/filters.d/wordpress-hard.conf \
                 /var/www/example.com/wp-content/plugins/wp-fail2ban/filters.d/wordpress-soft.conf /etc/fail2ban/filter.d/
  agensio ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf && fail2ban-client reload
  ```

  Behind a trusted proxy the plugin needs `WP_FAIL2BAN_PROXIES` in `wp-config.php` so that
  it logs the client, not the proxy.
- Also worth doing in the application: disable XML-RPC when nothing uses it (a one-line
  plugin, or the WP fail2ban setting that blocks it); an application-level lockout plugin
  such as Limit Login Attempts Reloaded, which stops password guessing per account and so
  covers an attack spread over many addresses, which fail2ban's per-address bans cannot;
  two-factor authentication for the administrator accounts. The preset itself never serves
  `wp-config.php`, `readme.html` or `license.txt` and never executes PHP under `uploads`.

### Drupal (`app = "drupal"`)

- Attempt tier: `/user/login`.
- Failure tier: enable the core **Syslog** module (Extend, Syslog). Drupal then writes
  `...|user|203.0.113.9|...|Login attempt failed for admin.` to the system log, which
  fail2ban's own `drupal-auth` filter reads; nothing to copy. On a host that runs only
  journald there is no `/var/log/syslog`; install `rsyslog` so the lines reach a file.
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
(`fail2ban_log_format`) and when an application's failure tier is not in place yet
(`fail2ban_failures_unseen`).

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
