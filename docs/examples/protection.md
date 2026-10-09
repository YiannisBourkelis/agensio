# Protection: addresses, passwords, refused paths, fail2ban

Recipes that narrow who reaches what: a site's admin kept to the office, a staging site behind
a password, what an application never serves, the logins fail2ban counts. Every rule here is
checked before agensio picks a location, so no `.php` file, fallback or proxied path steps
around it. The [cookbook's index](../examples.md) says how a recipe is laid out and how to
apply one.

## Keep the WordPress admin to the office

**When:** the site's editors work from known networks (an office, a VPN), and nobody else has
any business in `/wp-admin`.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }

[addresses]
office = ["203.0.113.0/24", "2001:db8:5::/64"]   # one edit here reaches every site naming @office
```

```toml
# /etc/agensio/sites.d/shop.example.com.toml
[[site]]
server_name = ["shop.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/shop.example.com/web"
app = "wordpress"
user = "shop"
tls = "auto"

[[site.access]]
path = "/wp-admin"           # /wp-admin, /wp-admin/ and everything below; never /wp-administrator
allow = ["@office"]
```

**What it does.** A request for `/wp-admin` or below from any other address gets `403` with a
page naming the address the server saw, whichever location would have served it: a `.php`
file, a fallback, a static file. The WordPress preset keeps `/wp-admin/admin-ajax.php` and the
login page's own `css/`, `js/` and `images/` open, because the public site calls them (search,
carts, comment forms) and nothing runs there but WordPress's own files. The login page itself,
`/wp-login.php`, stays open: a shop's customers log in there. When no visitor ever does, add
it with an exact rule (next recipe).

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml && agensio reload
agensio ctl access-check shop.example.com /wp-admin/ 198.51.100.7     # refused, names the rule
agensio ctl access-check shop.example.com /wp-admin/ 203.0.113.20     # allowed
curl -sI https://shop.example.com/wp-admin/ | head -1                  # 403 from outside the office
```

**On a managed site.** The office set stays in the main file, root's; the rule is one field:

```sh
agensio ctl site-update shop.example.com --restrict-admin @office --yes --reason "admin to the office"
```

**MCP:** `access_check` with the user's own address first, then `site_update` with
`rules.admin` = `{"allow": ["@office"]}` (`"mode": "report"` to try it first).

**Reference:** [Access by client address](../configuration.md#19-access-by-client-address).

## Protect one script exactly, the login page included

**When:** one script must be kept to some addresses while its neighbours stay public: the
login page of a site whose visitors never log in, Drupal's `/update.php`, a monitoring script.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }

[addresses]
office = ["203.0.113.0/24", "2001:db8:5::/64"]
```

```toml
# /etc/agensio/sites.d/blog.example.com.toml
[[site]]
server_name = ["blog.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/blog.example.com/web"
app = "wordpress"
user = "blog"
tls = "auto"

[[site.access]]
path = "/wp-admin"
allow = ["@office"]

[[site.access]]
path = "/wp-login.php"
match = "exact"              # this script, and every request PHP runs as this script
allow = ["@office"]

[[site.access]]
path = "/xmlrpc.php"         # WordPress takes passwords here too; refuse it when no app uses it
match = "exact"
allow = ["@office"]
```

**What it does.** An exact rule covers its path and every request agensio runs as that same
script: PHP runs `/wp-login.php/anything` as `/wp-login.php` (path info), so those requests
meet the rule too. Nothing else does: `/wp-login.phpx` or a static `/wp-login.html` are other
paths. Before 0.1.0-alpha.59 an exact rule covered the path alone, and `/wp-login.php/x`
reached the login page past it; nginx's `location =` and Caddy's exact `path` still behave
that way. In front of a proxied application agensio runs no script, so an exact rule there
covers its path alone, and `agensio -t` says so; use a prefix rule there.

**Check it.**

```sh
agensio ctl path-check blog.example.com /wp-login.php/x      # runs the script /wp-login.php, and the rule that covers it
agensio ctl access-check blog.example.com /wp-login.php/x 198.51.100.7   # refused
```

**On a managed site.** `--admin-login` adds the login page to the admin rule:

```sh
agensio ctl site-update blog.example.com --restrict-admin @office --admin-login --yes --reason "nobody logs in from outside"
agensio ctl site-update blog.example.com --restrict-exact /xmlrpc.php=@office --yes --reason "no app uses XML-RPC"
```

**MCP:** `site_update` with `rules.admin` = `{"allow": ["@office"], "login": true}`;
`path_check` shows the script a path runs (`script`).

**Reference:** [Access by client address](../configuration.md#19-access-by-client-address),
[Passwords](../auth.md#51-the-order) (the same matching).

## Try an address rule before it locks anyone out

**When:** you are not sure who reaches a path today (a plugin posting to `/wp-admin/`, an
agency's address you do not know) and want to see before enforcing.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }

[addresses]
office = ["203.0.113.0/24", "2001:db8:5::/64"]
```

```toml
# /etc/agensio/sites.d/shop.example.com.toml
[[site]]
server_name = ["shop.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/shop.example.com/web"
app = "wordpress"
user = "shop"
tls = "auto"

[[site.access]]
path = "/wp-admin"
allow = ["@office"]
mode = "report"              # everyone is served; the error log names who would be refused
```

**What it does.** Nothing changes for visitors. Each rule and client that would have been
refused is written to the error log once a minute (`access would refuse: site ...`). After a few days,
add the addresses you recognise to the set and remove `mode`, or set `mode = "enforce"`.

**Check it.**

```sh
agensio ctl logs --level warn --since 1d | grep 'access would refuse'
```

**On a managed site.**

```sh
agensio ctl site-update shop.example.com --restrict-admin @office --yes --reason "admin to the office"
```

**MCP:** `site_update` with `rules.admin` = `{"allow": ["@office"], "mode": "report"}`, later
the same without `mode`.

**Reference:** [Access by client address](../configuration.md#19-access-by-client-address).

## A staging site behind a password, the office without one

**When:** a copy of a site for review must not be public or indexed, the team in the office
should not be asked, and the load balancer's health check needs no password.

```sh
install -d -m 750 -o root -g agensio /etc/agensio/auth
agensio passwd anna >> /etc/agensio/auth/staging.example.com.users     # asks twice, prints anna:$y$...
chown root:agensio /etc/agensio/auth/staging.example.com.users
chmod 640 /etc/agensio/auth/staging.example.com.users
```

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }

[addresses]
office = ["203.0.113.0/24", "2001:db8:5::/64"]
```

```toml
# /etc/agensio/sites.d/staging.example.com.toml
[[site]]
server_name = ["staging.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/staging.example.com/web"
app = "wordpress"
user = "staging"
tls = "auto"

[[site.auth]]
path = "/"                                   # the whole site
users = "/etc/agensio/auth/staging.example.com.users"
realm = "Shop staging"                       # the name the browser's dialog shows
skip_for = ["@office"]                       # the office gets in without a password

[[site.auth]]
path = "/health.html"
match = "exact"
open = true                                  # the monitor's check needs no password
```

**What it does.** Everyone outside the office is asked for a password (`401` with the realm);
a right one is verified once on a small thread pool and remembered for five minutes per worker,
so the slow hash is not paid per request. Over plain HTTP nobody is asked: the browser would
send the password in clear, so a request on port 80 is sent to https or refused with a page
saying to use it. Every answer from the protected site is `Cache-Control: private`, so a CDN or
shared cache in front never keeps it. PHP receives `REMOTE_USER`.

**Check it.**

```sh
curl -sI https://staging.example.com/ | head -1                       # 401 from outside the office
curl -sI -u anna https://staging.example.com/ | head -1               # 200 with the password
curl -sI https://staging.example.com/health.html | head -1            # 200, open
agensio ctl path-check staging.example.com /wp-admin/                 # names the password rule
```

**On a managed site.** The control plane keeps the users file itself
(`/etc/agensio/auth/<site>.users`), so nothing is written by hand:

```sh
agensio ctl site-auth-user-set staging.example.com anna --generate --yes --reason "staging review"   # answers the password once
agensio ctl site-update staging.example.com --auth / --auth-realm "Shop staging" --auth-skip @office --auth-open /health.html --yes --reason "staging behind a password"
```

**MCP:** `site_auth_user_set` with `generate`, then `site_update` with `rules.auth`. An agent
can only generate passwords: it never receives one the user typed.

**Reference:** [Passwords](../configuration.md#19b-passwords-siteauth), [the whole feature](../auth.md).

## Temporary access for a client

**When:** a client reviews the staging site for two weeks; their login should stop working on
its own, and the users file should say whose login it is.

```sh
agensio ctl site-auth-user-set staging.example.com acme-review --generate --expires 2026-10-31 --note "Acme Ltd, design review" --yes --reason "client review"
agensio ctl site-auth-users staging.example.com          # names, methods, expiry and notes; never a hash
```

**What it does.** From 00:00 UTC on the `expires` day the login is refused, right password or
not, and a login remembered before is not honoured past that time. Health lists expired users
(`auth_users_expired`) so they can be deleted. To end the access early, lock the user (the
password is kept, `--unlock` gives it back) or delete it:

```sh
agensio ctl site-auth-user-set staging.example.com acme-review --lock --yes --reason "review over"
agensio ctl site-auth-user-delete staging.example.com acme-review --yes --reason "review over"
```

On a hand-written site the same fields go into the users file after the hash:
`acme-review:$y$j9T$...:expires=2026-10-31:note=Acme Ltd, design review`.

**MCP:** `site_auth_user_set` with `generate`, `expires` and `note`; `locked` to lock;
`site_auth_users` to list.

**Reference:** [The users file](../auth.md#4-the-users-file).

## A password in front of a proxied tool that wants the user's name

**When:** a dashboard (Grafana, an internal tool) runs behind agensio, has no login of its own
or can take the user's name from a request field.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/grafana.example.com.toml
[[site]]
server_name = ["grafana.example.com"]
listen = ["0.0.0.0:443"]
app = "proxy"
upstream = "http://127.0.0.1:3000"
tls = "auto"

[[site.auth]]
path = "/"
users = "/etc/agensio/auth/grafana.users"
realm = "Grafana"
forward_user = "X-WEBAUTH-USER"   # the verified name; a client's own X-WEBAUTH-USER is dropped first

[[site.auth]]
path = "/api/health"
match = "exact"
open = true
```

**What it does.** The application never sees the password: `Authorization` is taken out before
the request is forwarded (the default on a site that runs no PHP), and the verified user name
arrives in `X-WEBAUTH-USER`. Grafana trusts that field with `[auth.proxy] enabled = true` and
`header_name = X-WEBAUTH-USER`; make sure it listens on `127.0.0.1` only, so nothing else can
send the field.

**Check it.**

```sh
curl -sI https://grafana.example.com/ | head -1                 # 401
curl -sI -u anna https://grafana.example.com/ | head -1         # the application's answer
```

**Reference:** [What the application sees](../auth.md#7-what-the-application-the-caches-and-the-logs-see).

## Refuse what an application never serves

**When:** an application without a preset (or one whose files sit under the served
directory) ships configuration, dependencies or templates that must never be fetched: its
official server configuration lists them.

```toml
# /etc/agensio/sites.d/tasks.example.com.toml
[[site]]
server_name = ["tasks.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/tasks.example.com/web"
app = "php"
user = "tasks"
tls = { cert = "/etc/ssl/tasks.example.com/fullchain.pem", key = "/etc/ssl/tasks.example.com/privkey.pem" }
refuse = [
  "/vendor/",            # from the root: the directory and everything below it
  "/data/",
  "/config.php",
  "composer.json",       # a name in any directory
  "composer.lock",
  "*.sqlite",
  "*.log",
  "/plugins/*/Schema/",  # '*' within one segment
  "/app/**/*.tpl",       # '**' any number of directories
]
```

**What it does.** A request whose path matches a pattern gets `404`, whichever location would
serve it, on every internal redirect and on a directory's index too. Case and trailing dots are
ignored (`/VENDOR/`, `/config.php.`). There is no order and no exception: a match is a 404. A
pattern that would refuse the site's own index or front controller is refused by `agensio -t`
with both names.

**Check it.**

```sh
agensio ctl path-check tasks.example.com /vendor/autoload.php     # refused, names the pattern
agensio ctl path-check tasks.example.com /index.php               # runs the script
```

**On a managed site.**

```sh
agensio ctl site-update tasks.example.com --refuse /vendor/ --refuse /data/ --refuse /config.php --refuse composer.json --refuse '*.sqlite' --yes --reason "the application's own denials"
```

**MCP:** `site_update` with `rules.refuse`, then `path_check` on one path each pattern must
refuse and on the paths that must still work.

**Reference:** [Refused paths](../configuration.md#6b-refused-paths-refuse).

## Judge the real client behind a CDN or load balancer

**When:** the site sits behind a CDN, a load balancer or a local tunnel, so every connection
comes from the proxy's address, and the access rules, passwords' `skip_for` and logs must see
the visitor instead.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
trusted_proxies = ["198.51.100.0/24"]   # the load balancer's addresses: only these may say who the client is

[addresses]
office = ["203.0.113.0/24"]
```

```toml
# /etc/agensio/sites.d/shop.example.com.toml
[[site]]
server_name = ["shop.example.com"]
listen = ["0.0.0.0:80"]                  # the load balancer ends TLS and forwards plain HTTP
root = "/var/www/shop.example.com/web"
app = "wordpress"
user = "shop"

[[site.access]]
path = "/wp-admin"
allow = ["@office"]
```

**What it does.** From a trusted proxy, the client is the rightmost address in
`X-Forwarded-For` that is not itself a trusted proxy, and `X-Forwarded-Proto: https` counts as
https (so a password is asked, and PHP sees `HTTPS=on`). From anyone else those fields are
ignored, so a visitor cannot claim the office's address by sending them. Never list the proxy
in an `allow`: a request it sends without the field would pass as the proxy; `agensio -t` warns
about that.

**Check it.**

```sh
agensio ctl access-check shop.example.com /wp-admin/ 203.0.113.20
tail -f /var/log/agensio/access.log      # the visitors' addresses, not the load balancer's
```

**Reference:** [Behind a reverse proxy or load balancer](../configuration.md#10-behind-a-reverse-proxy-or-load-balancer).

## Let fail2ban count failed logins

**When:** an application's login form is guessed at, and you want the address banned after a
few failures. agensio writes the logs and renders the jails; fail2ban and the firewall do the
banning.

```toml
# /etc/agensio/sites.d/tasks.example.com.toml
[[site]]
server_name = ["tasks.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/tasks.example.com/web"
app = "php"
user = "tasks"
tls = { cert = "/etc/ssl/tasks.example.com/fullchain.pem", key = "/etc/ssl/tasks.example.com/privkey.pem" }
login_paths = ["/login", "/?controller=AuthController&action=check"]   # where this application takes passwords
```

**What it does.** The presets know their own login paths (WordPress `/wp-login.php` and
`/xmlrpc.php`, Drupal `/user/login`, Laravel `/login`, ...); `login_paths` adds an application's
own, a query-string login included. Nothing is served or refused by it: the `agensio-login`
jail that `agensio ctl protection` renders counts POSTs there, every spelling of the path
included, and bans after ten in ten minutes. Failed passwords of `[[site.auth]]` rules are
counted by the `agensio-auth` jail from the error log.

**Check it.**

```sh
agensio ctl protection                   # the jails and firewall table for this host, what is in place, root's commands
agensio ctl health                       # fail2ban_missing, firewall_limits_missing until both are in place
```

**On a managed site.**

```sh
agensio ctl site-update tasks.example.com --login-path /login --yes --reason "count failed logins"
```

**MCP:** `site_update` with `login_paths`; `protection_show` for the jails.

**Reference:** [Connection limits and host protection](../configuration.md#18-connection-limits),
[fail2ban](../fail2ban.md).
