# Applications behind the proxy

Recipes for applications that speak HTTP themselves (Node, Rails, Django, Java, a chat or IoT
server) and run on a port of this host. agensio ends TLS, answers from disk what it can,
refuses the project files nobody should fetch, and forwards the rest to the application.
WebSockets, keep-alive to the origin and the forwarded client address need no configuration.
An upstream is an IP address and a port (or `unix:/path`), never a host name: `agensio -t`
refuses `http://localhost:3000`, and warns while nothing listens on an address it names. The
[cookbook's index](../examples.md) says how a recipe is laid out and how to apply one.

## A Node.js application

**When:** an Express, Fastify, Next.js or similar application runs under `node` on a loopback
port, and its project directory is on this host.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/notes.example.com.toml
[[site]]
server_name = ["notes.example.com"]
listen = ["0.0.0.0:443"]
tls = "auto"
app = "node"
root = "/var/www/notes.example.com/app"   # the project directory, where package.json is; nothing is served from it
entry = "server.js"                        # the file node runs, relative to root
user = "notes"
upstream = "http://127.0.0.1:3000"         # an address and a port; a name such as localhost is refused
proxy = { idle_timeout = 4 }               # Node closes an idle kept connection after 5 s: let go of it first

[[site.location]]                          # optional: files the application serves unchanged, from disk
path = "/assets/"
alias = "/var/www/notes.example.com/app/public/assets"
add_headers = { "Cache-Control" = "public, max-age=86400" }
```

**What it does.** Every request goes to the application, WebSocket upgrades included, except
two kinds. `/assets/` comes from disk, which costs the application nothing; keep it only when
the application serves that directory as it is. And the project's own files are a `404` from
agensio, never forwarded: `/.env`, `/.git/`, `/.npmrc`, `/node_modules/`, `/package.json` and
the lockfiles, and any path ending in `.db`, `.sqlite`, `.sqlite3`, `.log`, `.key`, `.sql` or
`.env`. Node closes a kept connection after 5 s without a request, while agensio keeps one for
30 s by default; a request sent at the moment Node closes gets `502`, unless it is a GET or
HEAD, which is retried once. With `idle_timeout = 4` agensio closes first. Raising the
application's own `server.keepAliveTimeout` above 30 s does the same.

agensio sends the visitor's address in `X-Forwarded-For`, replacing whatever a client sent.
Express reads it into `req.ip` only with `app.set("trust proxy", "loopback")`.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml && agensio reload    # warns until something listens on 127.0.0.1:3000
agensio ctl path-check notes.example.com /api/notes          # goes to the application
agensio ctl path-check notes.example.com /node_modules/      # 404 from agensio, never forwarded
agensio ctl site-unit notes.example.com                      # the systemd unit for root, HOST and PORT from upstream
```

The rendered unit runs root's `node` (`[control] runtimes.node`) on `entry` as the site's
account, with `HOST=127.0.0.1` and `PORT=3000` from the upstream. The application must listen
where they say: one that binds every address is reachable without agensio, its TLS and its
refusals.

**On a managed site.** `site-install`'s answer guesses `entry` from `package.json`:

```sh
agensio ctl site-create --domain notes.example.com --app node --root /var/www/notes.example.com/app --user notes --upstream http://127.0.0.1:3000 --yes --reason "notes application"
agensio ctl site-install notes.example.com --url https://example.com/releases/notes-1.4.0.tar.gz --sha256 <published sha256> --yes --reason "notes application"
agensio ctl site-task notes.example.com npm_ci --yes --reason "notes application"
agensio ctl site-update notes.example.com --entry server.js --yes --reason "notes application"
agensio ctl site-unit notes.example.com --raw > /etc/systemd/system/agensio-app-notes.service   # as root
systemctl daemon-reload && systemctl enable --now agensio-app-notes.service
```

The `/assets/` location goes into the site's root additions file (see
[one path of a PHP site](#one-path-of-a-php-site-sent-to-another-service)). For the keep-alive
race, raise the application's `server.keepAliveTimeout` instead: `idle_timeout` is an option
of the `/` location, and a `/` location of your own replaces the preset's, with its refused
endings.

**MCP:** `site_create` with `app` "node", `root`, `user` and `upstream`; `site_install`;
`site_task` with `task` "npm_ci"; `site_update` with `entry`; `site_service_unit` for root's
unit, `site_service_status` for whether it runs.

**Reference:** [Node.js](../configuration.md#4f-nodejs-app--node),
[Reverse proxy](../configuration.md#12-reverse-proxy).

## A Rails application behind Puma

**When:** a Ruby on Rails application (your own, Redmine, a ONCE application) runs under Puma
on a loopback port, and its precompiled assets should come from disk.

```toml
# /etc/agensio/sites.d/projects.example.com.toml
[[site]]
server_name = ["projects.example.com"]
listen = ["0.0.0.0:443"]
tls = { cert = "/etc/ssl/projects.example.com/fullchain.pem", key = "/etc/ssl/projects.example.com/privkey.pem" }
app = "rails"
root = "/var/www/projects.example.com/app"   # the project directory: site tasks run here
user = "projects"
upstream = "http://127.0.0.1:3000"            # where Puma listens; keep it on loopback

[[site.location]]                             # precompiled assets straight from disk
path = "/assets/"
alias = "/var/www/projects.example.com/app/public/assets"
add_headers = { "Cache-Control" = "public, max-age=31536000, immutable" }   # the name changes with the content
```

**What it does.** Puma answers everything except `/assets/`, which agensio reads from
`public/assets/` with the year-long cache that fingerprinted asset names allow. The rails
preset answers `404` itself for what scanners look for in a Rails tree, so Puma never sees
those requests: `/config/master.key`, `/config/database.yml`, `/config/credentials/`, `/.env`,
`/.git/`, `/Gemfile.lock`, everything below `/storage/` (the SQLite databases and Active
Storage's files), and any path ending in `.sqlite3`, `.log`, `.key` or `.sql`. Rails builds
its links and redirects from `Host` and `X-Forwarded-Proto`, which agensio sends; a redirect
that still names Puma's own address (`http://127.0.0.1:3000/...`) is rewritten to the site.

Easy to get wrong: the `puma.rb` that `rails new` writes binds every address, which publishes
the application beside agensio, without TLS or the refusals. Start Puma with
`-b tcp://127.0.0.1:3000`, as the rendered unit and [puma.service](puma.service) do. A request
body is limited to 1 MB unless the site sets `max_body_size`; an Active Storage upload above
it is a `413` the application never sees.

**Check it.**

```sh
agensio ctl path-check projects.example.com /assets/application.css    # the file below public/assets/, or 404
agensio ctl path-check projects.example.com /config/master.key         # 404, refused by the preset
agensio ctl site-unit projects.example.com                             # Puma's unit for root
agensio ctl site-service projects.example.com                          # whether that unit runs
```

**On a managed site.** The tasks run as the site's account in its directory, with the
environment Puma gets from the unit:

```sh
agensio ctl site-create --domain projects.example.com --app rails --root /var/www/projects.example.com/app --user projects --upstream http://127.0.0.1:3000 --yes --reason "projects application"
agensio ctl site-install projects.example.com --url https://example.com/releases/projects-2.1.0.tar.gz --sha256 <published sha256> --yes --reason "projects application"
for t in bundle_install db_prepare assets_precompile; do agensio ctl site-task projects.example.com $t --yes --reason "projects application"; done
agensio ctl site-unit projects.example.com --raw > /etc/systemd/system/agensio-app-projects.service   # as root
systemctl daemon-reload && systemctl enable --now agensio-app-projects.service
```

`site-install` generates `SECRET_KEY_BASE` into the site's environment when the archive has no
Rails credentials. The `/assets/` location goes into the site's root additions file (see
[one path of a PHP site](#one-path-of-a-php-site-sent-to-another-service)). After
`bundle_install`, `db_migrate` or `assets_precompile` the task's answer carries the restart
line for root.

**MCP:** `site_create` with `app` "rails"; `site_install`; `site_task` with `task`
"bundle_install", "db_prepare", "assets_precompile"; `site_service_unit`, then
`site_service_status` and `site_service_logs`.

**Reference:** [Proxied applications and Rails](../configuration.md#4b-proxied-applications-app--proxy),
[the unit by hand](puma.service).

## Django or Wagtail behind Gunicorn

**When:** a Django project or a Wagtail site runs under Gunicorn on a loopback port.

```toml
# /etc/agensio/sites.d/cms.example.com.toml
[[site]]
server_name = ["cms.example.com"]
listen = ["0.0.0.0:443"]
tls = { cert = "/etc/ssl/cms.example.com/fullchain.pem", key = "/etc/ssl/cms.example.com/privkey.pem" }
app = "wagtail"                         # or "django": the same, without Wagtail's documents rule
root = "/var/www/cms.example.com/app"   # where manage.py is; only static/ and media/ below it are served
project = "mysite"                      # the Python package: mysite/settings, mysite/wsgi.py
user = "cms"
upstream = "http://127.0.0.1:8000"      # where Gunicorn listens
max_body_size = "50MB"                  # image and document uploads; the default is 1 MB
```

**What it does.** Gunicorn serves no files, so agensio answers `/static/` and `/media/` from
`static/` and `media/` below the project directory; a missing file there is a `404`, never a
request to Gunicorn. A static name that carries its content's hash (`base.85e6f9d19e42.css`,
what Wagtail's production settings write) is cached for a year; any other name for five
minutes, then revalidated, so an upgrade reaches browsers. Uploads under `/media/` get
`nosniff` and a `Content-Security-Policy` that keeps an uploaded HTML or SVG page from running
script on the site's origin. Under Wagtail, `/media/documents/` is a `404`: Wagtail serves
documents through its own view, which checks a collection's privacy. `/manage.py`, `.py` files,
`db.sqlite3`, `.env` and the other project files are a `404` at the edge.

Easy to get wrong: the project's settings must put `STATIC_ROOT` and `MEDIA_ROOT` at
`<root>/static` and `<root>/media`, or `collectstatic` writes where nothing is served. The
`agensio_settings.py` that the `django_settings` task writes does that, sets `ALLOWED_HOSTS`
and `CSRF_TRUSTED_ORIGINS` from the site's names, and trusts `X-Forwarded-Proto`
(`SECURE_PROXY_SSL_HEADER`), which is safe here because agensio replaces that field when a
client sends it. Without `max_body_size` every image above 1 MB is a `413` Wagtail never sees.

**Check it.**

```sh
agensio ctl path-check cms.example.com /static/css/site.css           # the file below static/, or 404
agensio ctl path-check cms.example.com /media/documents/report.pdf    # 404: documents go through Wagtail's view
agensio ctl path-check cms.example.com /admin/                        # goes to the application
agensio ctl site-unit cms.example.com                                 # Gunicorn's unit for root
```

**On a managed site.** An existing project, uploaded as an archive with `manage.py` at its top:

```sh
agensio ctl site-create --domain cms.example.com --app wagtail --project mysite --root /var/www/cms.example.com/app --user cms --upstream http://127.0.0.1:8000 --set max_body_size=50MB --yes --reason "wagtail site"
agensio ctl upload mysite.tar.gz < mysite.tar.gz                                    # the archive on standard input
agensio ctl site-install cms.example.com --file mysite.tar.gz --yes --reason "wagtail site"    # generates DJANGO_SECRET_KEY
for t in venv_create pip_install_requirements; do agensio ctl site-task cms.example.com $t --yes --reason "wagtail site"; done
agensio ctl site-task cms.example.com pip_install --param "packages=gunicorn" --yes --reason "wagtail site"   # prints a warning; your --yes confirms it
for t in django_settings migrate collectstatic; do agensio ctl site-task cms.example.com $t --yes --reason "wagtail site"; done
agensio ctl site-unit cms.example.com --raw > /etc/systemd/system/agensio-app-cms.service   # as root, then enable it
```

**MCP:** `site_create` with `app` "wagtail", `project` and `settings`
`{"max_body_size": "50MB"}`; `site_install`; `site_task` for each task; for "pip_install" the
bridge asks the user in the client's own dialog, an agent's `confirm` is not enough;
`site_service_unit` for root's unit.

**Reference:** [Django and Wagtail](../configuration.md#4e-django-and-wagtail-app--django-app--wagtail).

## A chat server with WebSockets (Rocket.Chat)

**When:** Rocket.Chat (or another application whose clients keep a WebSocket open) runs on a
loopback port, and its users upload files.

```toml
# /etc/agensio/sites.d/chat.example.com.toml
[[site]]
server_name = ["chat.example.com"]
listen = ["0.0.0.0:443"]
tls = { cert = "/etc/ssl/chat.example.com/fullchain.pem", key = "/etc/ssl/chat.example.com/privkey.pem" }
app = "proxy"
upstream = "http://127.0.0.1:3000"
max_body_size = "100MB"                 # file uploads; the default is 1 MB
proxy = { tunnel_timeout = 3600 }       # optional: close a WebSocket on which nothing moved for an hour
```

**What it does.** A request with `Connection: Upgrade` and an `Upgrade` field (Rocket.Chat's
`/websocket` and `/sockjs/`) is forwarded as one; when the application answers `101`, the
connection becomes a tunnel that copies bytes both ways until a side closes. There are no
`Upgrade` or `Connection` lines to add. A tunnel has no idle limit by default, and
`read_timeout` (60 s) applies to ordinary requests only, so a quiet chat is never cut (nginx's
read timeout dropping idle WebSockets is the usual surprise there). An application that pings
its clients ends the tunnels of the ones that stopped answering by itself; `tunnel_timeout`
is for one that does not, and closes a tunnel on which no byte moved in either direction for
that long. A reload leaves open tunnels alone: each finishes on the configuration it started
with.

An upload is read in full before Rocket.Chat is contacted (to a temporary file above 256 KB),
so a slow client never holds the application. Above `max_body_size` it is a `413` Rocket.Chat
never sees: keep Rocket.Chat's own upload limit at or below it. Rocket.Chat builds its links
from its `ROOT_URL` setting, which should be `https://chat.example.com`.

**Check it.**

```sh
curl --http1.1 -si --max-time 3 -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' https://chat.example.com/websocket | head -1   # HTTP/1.1 101 Switching Protocols
agensio ctl logs --level warn --since 1d | grep 'refused with 413'    # uploads above the limit: site, size, limit
```

**On a managed site.** The upload limit is a setting; `tunnel_timeout`, an option of the `/`
location, is the root additions file's (a `/` location with `handler = "proxy"` and the
`proxy` table above; see [one path of a PHP site](#one-path-of-a-php-site-sent-to-another-service)):

```sh
agensio ctl site-create --domain chat.example.com --app proxy --upstream http://127.0.0.1:3000 --no-user --set max_body_size=100MB --yes --reason "Rocket.Chat"
```

**MCP:** `site_create` with `app` "proxy", `upstream`, `no_user` and `settings`
`{"max_body_size": "100MB"}`.

**Reference:** [Reverse proxy](../configuration.md#12-reverse-proxy) (WebSockets and other
upgrades).

## An IoT platform with device telemetry (ThingsBoard)

**When:** ThingsBoard (Java, port 8080) serves its web interface and REST API through agensio,
and devices post telemetry over HTTP at a high rate.

```toml
# /etc/agensio/sites.d/iot.example.com.toml
[[site]]
server_name = ["iot.example.com"]
listen = ["0.0.0.0:443"]
tls = { cert = "/etc/ssl/iot.example.com/fullchain.pem", key = "/etc/ssl/iot.example.com/privkey.pem" }
app = "proxy"
upstream = "http://127.0.0.1:8080"
proxy = { read_timeout = 120, max_connections = 512 }   # a dashboard's long query; many devices at once
```

**What it does.** Dashboards keep a WebSocket open for live values (`/api/ws`), which needs
nothing. A device's request body is read in full before agensio takes one of ThingsBoard's
connections (`request_buffering`, on by default), so a device on a slow mobile link never holds
one. `max_connections` counts per worker the requests in flight to ThingsBoard; beyond it a
request waits in a queue of 1,024 for up to 5 s, then gets `503` with `Retry-After`, which a
device can back off on. ThingsBoard therefore sees at most workers × 512 connections.
`read_timeout = 120` gives a dashboard's telemetry query two minutes before the `504`.

MQTT and CoAP are not HTTP: devices reach ThingsBoard on those ports directly, and the
firewall decides who may. ThingsBoard's HTTP device API carries the device's access token in
the path (`/api/v1/TOKEN/telemetry`), so the access log records every token: keep that log's
readers few.

**Check it.**

```sh
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/json' -d '{"temperature":21.5}' https://iot.example.com/api/v1/DEVICE_TOKEN/telemetry
agensio ctl logs --site iot.example.com --status 5xx --since 1h     # 503: the queue was full; 504: read_timeout
```

**Reference:** [Reverse proxy](../configuration.md#12-reverse-proxy) (options),
[Connection limits](../configuration.md#18-connection-limits).

## One path of a PHP site sent to another service

**When:** a PHP site (here WordPress) stays as it is, and one path belongs to a separate
service: a booking API in Node or Go, a search engine, an older application.

```toml
# /etc/agensio/sites.d/shop.example.com.toml
[[site]]
server_name = ["shop.example.com"]
listen = ["0.0.0.0:443"]
tls = { cert = "/etc/ssl/shop.example.com/fullchain.pem", key = "/etc/ssl/shop.example.com/privkey.pem" }
root = "/var/www/shop.example.com/web"
app = "wordpress"
user = "shop"

[[site.location]]
path = "/api/"
upstream = "http://127.0.0.1:4000/"   # the trailing / replaces the prefix: /api/rooms reaches the service as /rooms
final = true                          # nothing PHP-like under /api/: /api/export.php goes to the service too
```

**What it does.** A request under `/api/` goes to the service with `/api/` replaced by the
upstream's own path, the query string kept: `/api/rooms?from=2026-10-01` arrives as
`/rooms?from=2026-10-01`. Without a path on the upstream (`http://127.0.0.1:4000`) the request
line goes unchanged, `/api/rooms`. A redirect the service sends to its own address
(`http://127.0.0.1:4000/rooms/7`) reaches the browser as `https://shop.example.com/api/rooms/7`.

Two things are easy to get wrong. A PHP site's `.php` location is checked before any prefix,
so without `final = true` a request for `/api/export.php` runs PHP (or is a `404`) instead of
reaching the service. And a prefix matches characters, not path segments: `/api` without the
slash is not under `/api/` and WordPress answers it, while a location written `/api` would also
take `/apidocs` and `/api-keys`. The site's access rules, passwords and refused paths are
checked before any location, so they cover `/api/` too.

**Check it.**

```sh
agensio ctl path-check shop.example.com /api/rooms         # goes to the application (location /api/, proxy)
agensio ctl path-check shop.example.com /api/export.php    # the same, because of final
agensio ctl path-check shop.example.com /api               # WordPress
```

**On a managed site.** No field of `site-update` adds a location. Root writes it into the
site's root additions file, beside the managed file; the control plane never writes or reads
it. It must be root's and writable by nobody else:

```sh
cat > /etc/agensio/sites.d/shop.example.com.root.toml <<'EOF'
site = "shop.example.com"

[[location]]
path = "/api/"
upstream = "http://127.0.0.1:4000/"
final = true
EOF
agensio reload
agensio ctl site shop.example.com     # root_additions: the file and the location it added
```

A location there at a path the preset already has (`/`, say) replaces the preset's own.

**MCP:** `site_show` names the site's root additions file; the agent hands the block to root,
since no tool writes it, then checks with `path_check`.

**Reference:** [Reverse proxy](../configuration.md#12-reverse-proxy) (target),
[Locations](../configuration.md#6-locations-the-reference) (`final`),
[root additions](../configuration.md#15-control-socket).

## Two application servers with passive health

**When:** the application runs as two processes (to restart one at a time, or on two hosts),
and a process that is down should be skipped.

```toml
# /etc/agensio/sites.d/app.example.com.toml
[[site]]
server_name = ["app.example.com"]
listen = ["0.0.0.0:443"]
tls = { cert = "/etc/ssl/app.example.com/fullchain.pem", key = "/etc/ssl/app.example.com/privkey.pem" }
app = "proxy"
upstream = ["http://127.0.0.1:3000", "http://127.0.0.1:3001"]   # round-robin
proxy = { max_fails = 3, fail_timeout = 10 }                     # the defaults, written out
```

**What it does.** Each worker sends requests to the members in turn. A member that refuses the
connection costs the client nothing: nothing was sent, so the request moves to the next member
at once, whatever its method. After `max_fails` failures in a row a worker skips that member
for `fail_timeout` seconds, then tries it again; when every member is down, the one marked
longest ago is tried anyway. A failure is a refused connection, a timeout, a failed TLS
handshake, a connection closed before the answer ended or an answer that is not HTTP; an answer
the application gives, a `500` included, is a success. Once bytes went out, only a GET or HEAD
moves to the next member, so a POST is never delivered twice. Each worker keeps its own count,
and each member has its own pool with the location's limits. No weights and no active health
checks.

So processes can be restarted one at a time without clients noticing, as long as each finishes
the requests it holds before it exits: new requests meet the stopped one, are refused, and go
to the other. Members on other hosts are written the same way, by address
(`"http://198.51.100.11:3000"`); every member must have the same path part.

**Check it.**

```sh
agensio -t --explain -c /etc/agensio/agensio.toml | grep '^upstream'   # both members, on every proxy location
agensio ctl logs --level warn --since 1h | grep -E 'marked down|is back'
```

**On a managed site.** `site-create --upstream` takes one address. A group is a `/` location
with the `upstream` list in the site's root additions file (see
[one path of a PHP site](#one-path-of-a-php-site-sent-to-another-service)), which replaces the
preset's `/`. On a rails, redmine, node, django or wagtail site that drops the preset's
refused endings with it, so add them as `deny_suffixes` there (`agensio -t --explain` lists
them), and `site-unit` renders a unit for the first member only.

**MCP:** `site_show` lists the upstreams in force.

**Reference:** [Reverse proxy](../configuration.md#12-reverse-proxy) (groups).

## An origin over HTTPS

**When:** the application only speaks HTTPS (an appliance, a container image built that way),
or it runs on another host and the traffic between crosses a network you do not control.

```toml
# /etc/agensio/sites.d/reports.example.com.toml
[[site]]
server_name = ["reports.example.com"]
listen = ["0.0.0.0:443"]
tls = { cert = "/etc/ssl/reports.example.com/fullchain.pem", key = "/etc/ssl/reports.example.com/privkey.pem" }
app = "proxy"
upstream = "https://127.0.0.1:8443"   # another host is written the same way, by address
proxy = { tls = { ca = "/etc/ssl/internal-ca.pem", server_name = "reports.internal.example.com" } }
```

**What it does.** agensio talks TLS to the origin and keeps the connections open, so a
handshake is paid once per pooled connection, not per request. The origin's certificate is
verified against `ca` (without it, the system's store), and `server_name` is both the name sent
in SNI and the name the certificate must carry. Always set it: an upstream is always an IP
address, and without `server_name` agensio checks that a trusted CA signed the certificate but
not whose it is. A failed handshake or verification is a `502`, logged as `tls_error`.
`agensio -t` only checks that something listens; the certificate is checked by the first
request.

For an origin on this host with a certificate it made itself, `tls = { verify = false }`
accepts any certificate. Across a network that gives up what TLS was for; give the origin's
own certificate as `ca`, and the name it carries as `server_name`, instead.

**Check it.**

```sh
openssl s_client -connect 127.0.0.1:8443 -servername reports.internal.example.com -verify_hostname reports.internal.example.com -CAfile /etc/ssl/internal-ca.pem </dev/null | grep 'Verify return code'   # 0 (ok)
curl -sI https://reports.example.com/ | head -1
agensio ctl logs --level error --since 1h | grep tls_error
```

**On a managed site.** No field covers `proxy.tls`: root writes a `/` location with the
`upstream` and the `proxy` table above into the site's root additions file (see
[one path of a PHP site](#one-path-of-a-php-site-sent-to-another-service)).

**Reference:** [Reverse proxy](../configuration.md#12-reverse-proxy) (TLS to the origin).

## Choose the headers the origin and the client see

**When:** an origin expects its own host name or a field such as `X-Real-IP`, a second service
reads RFC 7239 `Forwarded`, or answers carry fields that name the software behind.

```toml
# /etc/agensio/sites.d/portal.example.com.toml
[[site]]
server_name = ["portal.example.com"]
listen = ["0.0.0.0:443"]
tls = { cert = "/etc/ssl/portal.example.com/fullchain.pem", key = "/etc/ssl/portal.example.com/privkey.pem" }
app = "proxy"
upstream = "http://127.0.0.1:8080"
proxy = { host = "portal.internal.example.com", headers = { "X-Real-IP" = "$remote_addr" }, hide = ["X-Powered-By", "X-AspNet-Version"] }

[[site.location]]
path = "/partners/"
upstream = "http://127.0.0.1:8090"
proxy = { host = "pass", forwarded = "forwarded", headers = { "X-Gateway" = "portal" } }   # X-Real-IP and hide still apply
```

**What it does.** By default the origin gets the client's `Host`, `X-Forwarded-For` and
`X-Forwarded-Proto`; from a client that is not in `trusted_proxies`, those fields are replaced,
never appended to. Here the main origin gets `Host: portal.internal.example.com` and, because
Host was rewritten, `X-Forwarded-Host: portal.example.com`. An application that builds links
from `Host` then shows its internal name, and a redirect to that name is passed on as it is:
only one to the origin's address (`http://127.0.0.1:8080/...`) is rewritten to the site. Keep
`host = "pass"` unless the origin refuses other names.

`headers` sets fields on every request, with `$host`, `$remote_addr` (the client, behind
trusted proxies the forwarded one), `$scheme`, `$server_name` and `$server_port`; the client's
own copy of such a field is dropped, so nobody can send an `X-Real-IP` of their choice, and
`""` removes a client's field. A location's `proxy` table changes only what it names: its
headers join the site's field by field, so `/partners/` gets `X-Real-IP` and `X-Gateway`
(nginx's `proxy_set_header` drops the outer ones). `forwarded = "forwarded"` sends `Forwarded:
for=...;proto=https;host=...` instead of the `X-Forwarded-*` fields; `"both"` sends both,
`"off"` neither. `hide` takes fields out of the answers; `Server` and `Date` are always
agensio's own.

Easy to get wrong: `X-Forwarded-*`, `Forwarded` and `Host` are not for `headers`. agensio
sets them itself, and a configured `X-Forwarded-Proto` is sent next to its own, not instead
of it; use `host` and `forwarded`.

**Check it.**

```sh
agensio -t --explain -c /etc/agensio/agensio.toml | grep '^proxy\.'   # host, forwarded, the merged headers, hide
curl -sI https://portal.example.com/ | grep -i -E 'x-powered-by|x-aspnet'   # nothing
```

**Reference:** [Reverse proxy](../configuration.md#12-reverse-proxy) (what the origin sees,
what the client sees), [Behind a reverse proxy or load balancer](../configuration.md#10-behind-a-reverse-proxy-or-load-balancer).

## Stream server-sent events and long downloads

**When:** an application pushes events (`text/event-stream`), produces large exports that take
a while, or reads uploads as they arrive.

```toml
# /etc/agensio/sites.d/dashboard.example.com.toml
[[site]]
server_name = ["dashboard.example.com"]
listen = ["0.0.0.0:443"]
tls = { cert = "/etc/ssl/dashboard.example.com/fullchain.pem", key = "/etc/ssl/dashboard.example.com/privkey.pem" }
app = "proxy"
upstream = "http://127.0.0.1:3000"

[[site.location]]
path = "/events/"
handler = "proxy"                                    # the site's upstream; without it this location would serve files
proxy = { buffering = false, read_timeout = 300 }    # each event as it comes; the longest silence between two

[[site.location]]
path = "/exports/"
handler = "proxy"
proxy = { buffering = false }                        # bytes reach the client while the export is made

[[site.location]]
path = "/import/"
handler = "proxy"
proxy = { request_buffering = false }                # the application reads the upload as it arrives
```

**What it does.** By default agensio collects the whole answer (1 MB in memory, then a
temporary file) before sending it, so a slow client never holds the application. An event
stream does not end, so buffered, nothing reaches the browser until the temporary file holds
1 GB (`buffer_file_max`). With `buffering = false` each piece is passed on as it arrives, at
the client's pace: the application waits while the client is slow. `read_timeout` is the
longest wait between two pieces from the application; the stream is cut after it, so keep it
above the application's heartbeat interval. agensio does not read an `X-Accel-Buffering: no`
field from the application (nginx's per-answer switch): the location decides.
`request_buffering = false` hands the body over as it arrives instead of collecting it first;
`max_body_size` still applies.

Easy to get wrong: a location with a `proxy` table but neither `upstream` nor `handler =
"proxy"` is a static location, and `agensio -t` does not warn. `handler = "proxy"` with no
`upstream` uses the site's.

**Check it.**

```sh
curl -sN --max-time 20 https://dashboard.example.com/events/stream     # events appear one by one
agensio -t --explain -c /etc/agensio/agensio.toml | grep -A4 '^path = "/events/"'   # handler = "proxy"
```

**On a managed site.** These locations go into the site's root additions file (see
[one path of a PHP site](#one-path-of-a-php-site-sent-to-another-service)).

**Reference:** [Reverse proxy](../configuration.md#12-reverse-proxy) (options),
[Customising a preset](../configuration.md#5-customising-a-preset) (the same on a PHP site).

## A legacy CGI script

**When:** an old tool ships as CGI scripts (a report, a statistics page) and has to keep
running next to the site.

```toml
# /etc/agensio/sites.d/tools.example.com.toml
[[site]]
server_name = ["tools.example.com"]
listen = ["0.0.0.0:443"]
tls = { cert = "/etc/ssl/tools.example.com/fullchain.pem", key = "/etc/ssl/tools.example.com/privkey.pem" }
root = "/var/www/tools.example.com/web"

[[site.location]]
path = "/cgi-bin/"
alias = "/var/www/tools.example.com/cgi-bin"   # scripts only: every file here is run, never served
index = ["index.cgi"]                          # what /cgi-bin/ runs; without it, the site's index.html
cgi = { env = { "APP_ENV" = "production" } }

[[site.location]]
path = "/stats/"
alias = "/var/www/tools.example.com/stats"
cgi = { interpreter = "/usr/bin/perl" }        # for scripts that are not executable themselves
```

**What it does.** A request under a CGI location starts a process: the script is the longest
leading part of the path that names a file, the rest is `PATH_INFO`
(`/cgi-bin/report.cgi/2026`), and a directory runs the location's first `index`. The process
runs in the script's directory with the CGI variables, the location's `env` and a plain
`PATH`; the request body is its standard input and its output is the answer; its standard
error goes to the error log. At most 8 processes per worker and location run at once and 32
wait (a `503` beyond); a script silent for 30 s is killed (`504`).

Easy to get wrong: every file under the location is run, a stylesheet or an image included, so
keep only scripts there. A CGI location takes the site's `index` like any other, so without its
own `index` a request for `/cgi-bin/` tries to run `index.html`. The process runs as the
server's own account, never a site's `user`: on a shared host, keep CGI off the sites of other
accounts.

**Check it.**

```sh
agensio ctl path-check tools.example.com /cgi-bin/report.cgi   # runs /cgi-bin/report.cgi
curl -s https://tools.example.com/cgi-bin/report.cgi/2026 | head
agensio ctl logs --level warn --since 1h | grep 'cgi '        # what the scripts wrote to standard error
```

**On a managed site.** These locations go into the site's root additions file (see
[one path of a PHP site](#one-path-of-a-php-site-sent-to-another-service)).

**Reference:** [CGI](../configuration.md#13-cgi).
