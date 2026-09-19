# Configuring agensio

A configuration is one TOML file: `[server]`, `[log]`, `[cache]` and one `[[site]]` per
virtual host, with optional `[[site.location]]` blocks. Paths are relative to the file's
directory. `include = ["sites.d/*.toml"]` pulls in more `[[site]]` tables, one file per
site if a panel writes them.

Two commands you will use while editing:

```sh
agensio -t -c agensio.toml            # validate; warns about FastCGI upstreams it cannot reach
agensio -t --explain -c agensio.toml  # print the effective configuration after presets
```

`--explain` is the authoritative answer to "what does `app = "..."` do": it prints every
site and location as agensio sees it, marking the blocks a preset generated with
`# from preset:<name>`. The hand-written equivalents below were taken from that output.

## 1. Static site

```toml
[[site]]
server_name = ["www.example.com", "example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/example"
```

Defaults you get without writing them: `index = ["index.html"]`, dotfiles and
dot-directories hidden (404), symlinks followed, files up to 4 MB cached in memory and
larger ones streamed with sendfile, access log on (see section 8), and Range requests
(one range per request, `If-Range` honoured; video seeking, resumable downloads, PDF
viewers) answered with 206 from the cache and from disk alike.

A single-page application that routes on the client:

```toml
[[site]]
server_name = ["app.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/app/dist"
try_files = ["$uri", "$uri/", "/index.html"]   # unknown paths get the shell, assets stay assets
```

`try_files` elements: `$uri` (the path as a file), `$uri/` (as a directory: its index, or a
redirect to the slash form), `=403` / `=404` (answer that status), or `/path` (internal
redirect, routed again through the locations; a `?$query_string` suffix is accepted and
ignored for static files). Without `try_files` the rule is: file, directory index (403 if
there is none), 301 to the slash form for a directory, else 404.

## 2. Plain PHP: `app = "php"`

Any `.php` file under the root runs; `index.php` or `index.html` serves directories.

```toml
[[site]]
server_name = ["php.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/php-site"
app = "php"
php = { socket = "unix:/run/php/php8.4-fpm.sock" }
```

What it expands to, written by hand:

```toml
[[site]]
server_name = ["php.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/php-site"
index = ["index.php", "index.html"]
try_files = ["$uri", "$uri/", "=404"]
php = { socket = "unix:/run/php/php8.4-fpm.sock" }

[[site.location]]        # every request whose path ends in .php (also /x.php/extra: PATH_INFO)
path = ".php"
match = "suffix"
handler = "fastcgi"
```

## 3. Laravel: `app = "laravel"`

`root` is the project directory; the preset serves its `public/`.

```toml
[[site]]
server_name = ["app.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/app"
app = "laravel"
php = { socket = "unix:/run/php/php8.4-fpm.sock" }
```

Equivalent by hand:

```toml
[[site]]
server_name = ["app.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/app/public"
index = ["index.php"]
try_files = ["$uri", "$uri/", "/index.php?$query_string"]
php = { socket = "unix:/run/php/php8.4-fpm.sock" }

[[site.location]]        # the front controller is the only script that ever runs
path = "/index.php"
match = "exact"
handler = "fastcgi"

[[site.location]]        # everything else: static files, or the front controller; PHP in
path = "/"               # any spelling is refused (404), never executed, never served as source
deny_suffixes = [".php", ".phtml", ".phar", ".php5", ".php7", ".php8", ".phps"]

[[site.location]]        # Vite output is content-hashed: cache it for a year
path = "/build/"
try_files = ["$uri", "=404"]
deny_suffixes = [".php", ".phtml", ".phar", ".php5", ".php7", ".php8", ".phps"]
add_headers = { "Cache-Control" = "public, max-age=31536000, immutable" }
```

Why it is shaped like this: a Laravel application has exactly one entry point. A
request for any other `.php` under `public/`, existing or not, answers 404 from the
static handler before anything is read from disk, so a stray or uploaded `.php` file is
neither a code-execution path nor a download of its source (2026-09-19: before this
rule an existing second `.php` was served as a file). An application with several
entry points is not Laravel; use `app = "drupal"` (section 4c) or `app = "php"`.
Dotfiles (`.env`) stay hidden by the site default. `public/storage` is a symlink into the project, which is
why `symlinks = "allow"` is the default; set `symlinks = "deny"` on sites that have no
such link.

**Statamic** is a Laravel application: use `app = "laravel"` unchanged. Its control panel
uploads and PATCH/DELETE requests all go through `/index.php`. Raise
`[server] max_body_size` (default 1 MB) for asset uploads.

## 4. WordPress: `app = "wordpress"`

```toml
[server]
max_body_size = "64MB"    # media uploads (a server-wide setting)

[[site]]
server_name = ["blog.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/blog"
app = "wordpress"
php = { socket = "unix:/run/php/php8.4-fpm.sock" }
```

Equivalent by hand:

```toml
[[site]]
server_name = ["blog.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/blog"
index = ["index.php"]
try_files = ["$uri", "$uri/", "/index.php?$query_string"]   # pretty permalinks
php = { socket = "unix:/run/php/php8.4-fpm.sock" }

[[site.location]]        # wp-login.php, wp-admin/*.php, wp-cron.php, plugin endpoints
path = ".php"
match = "suffix"
handler = "fastcgi"

[[site.location]]        # nothing under uploads is ever executed; files are cacheable
path = "/wp-content/uploads/"
final = true             # nginx ^~: the .php suffix location is not consulted here
deny_suffixes = [".php", ".phtml", ".phar", ".php5", ".php7", ".phps"]
try_files = ["$uri", "=404"]
add_headers = { "Cache-Control" = "public, max-age=604800" }

[[site.location]]        # core assets: same shield, longer cache
path = "/wp-includes/"
final = true
deny_suffixes = [".php", ".phtml", ".phar", ".php5", ".php7", ".phps"]
try_files = ["$uri", "=404"]
add_headers = { "Cache-Control" = "public, max-age=2592000" }
```

`wp-content/plugins` is deliberately not shielded: some plugins expose PHP endpoints
there. `wp-config.php` and `wp-config-sample.php` are answered 404 by exact locations the
preset adds (`try_files = ["=404"]`): the credentials file is never executed nor shown,
whereas nginx recipes usually execute it (it prints nothing). `.htaccess` and
`.user.ini` are dotfiles and hidden. agensio never reads `.htaccess`; see section 4c.

## 4c. Drupal and other multi-entry-point PHP applications: `app = "drupal"`

```toml
[[site]]
server_name = ["drupal.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/drupal"            # the composer project; its web/ is served (a tarball without web/ is served as is)
app = "drupal"
php = { socket = "unix:/run/php/php8.4-fpm.sock" }
```

expands to:

```toml
root = "/var/www/drupal/web"
index = ["index.php"]
try_files = ["$uri", "$uri/", "/index.php?$query_string"]   # pretty paths reach the front controller

[[site.location]]        # any .php runs: index.php, core/install.php, update.php, core/rebuild.php
path = ".php"
match = "suffix"
handler = "fastcgi"

[[site.location]]        # what Drupal's .htaccess protects, refused natively (404): PHP source in its
path = "/"               # other spellings, templates, translations, dumps, editor backups
deny_suffixes = [".inc", ".install", ".module", ".theme", ".engine", ".profile", ".make", ".po", ".sql",
                 ".twig", ".yml", ".yaml", ".sqlite", ".sqlite3", ".db", ".bak", ".orig", ".save", ".swp", ".swo", ".tpl", ".xtmpl"]

# final prefixes (nginx ^~): nothing PHP-like under library, vendor and upload directories
[[site.location]]  path = "/core/lib/"             final = true  try_files = ["$uri", "=404"]  deny_suffixes = [...php and the list above...]
[[site.location]]  path = "/core/includes/"        final = true  (same)
[[site.location]]  path = "/vendor/"               final = true  (same)
[[site.location]]  path = "/node_modules/"         final = true  (same)
[[site.location]]  path = "/sites/default/files/"  final = true  (same)

# never answered, whatever is on disk (404, existence not disclosed)
[[site.location]]  path = "/sites/default/settings.php"  match = "exact"  try_files = ["=404"]
# likewise settings.local.php, default.settings.php, services.yml, default.services.yml,
# composer.json, composer.lock, web.config
```

`.htaccess`, `.ht.sqlite` (Drupal's SQLite database), `.env` and `.git/` are dotfiles and
stay hidden by the site default. A `.php` that does not exist answers 404 before php-fpm.

**agensio never reads `.htaccess`.** Applications that ship one (Drupal, WordPress,
Joomla, most PHP software) rely on it for exactly these refusals under Apache; under
agensio the preset provides them, and a hand-written site for such an application must
provide its own. The list above is the subset of Drupal's `.htaccess` that matters:
source disclosure and execution of files that are not entry points. Drupal's other
rules (canonical redirects, caching headers) are optional and can be added as locations.

The preset fits any application with a front controller *and* several real `.php` entry
points; the deny list is Drupal's, harmless elsewhere.

## 4b. Proxied applications: `app = "proxy"`

Node, Rails, Go, Java, Python: anything that speaks HTTP on a local port. `root` is not
needed; hand-written locations serve files from disk next to the proxied application.

```toml
[[site]]
server_name = ["app.example.com"]
listen = ["0.0.0.0:80"]
app = "proxy"
upstream = "http://127.0.0.1:3000"        # or a list: round-robin with health marking
proxy = { read_timeout = 120 }            # defaults for every proxied location of the site

[[site.location]]                         # optional: assets straight from disk
path = "/assets/"
alias = "/srv/app/public/assets"
add_headers = { "Cache-Control" = "public, max-age=31536000, immutable" }
```

Equivalent by hand: one `[[site.location]]` with `path = "/"`, `handler = "proxy"` and the
site's upstreams and options. WebSockets, redirects pointing at the origin, forwarded
headers and keep-alive need nothing (section 12). Worked examples for Node, Rails,
Rocket.Chat and ThingsBoard are in `docs/examples/`; two real applications run this
way in the repository's test beds, Redmine (Rails) in `bench/redmine/` and Uptime Kuma
(Node, Socket.IO over WebSockets) in `bench/uptime-kuma/`.

## 5. Customising a preset

A preset never overrides what the site writes itself:

- `index`, `try_files`, `hidden_files`, `symlinks`, `access_log`: site keys apply, and the
  locations the preset generates inherit them.
- `php = { ... }`: every option in it reaches the preset's FastCGI location(s).
- A `[[site.location]]` with the same `path` and `match` as a preset location replaces it
  entirely. Other locations coexist under the normal precedence.

Example, Laravel with streaming responses (server-sent events) and a shorter asset cache:

```toml
[[site]]
server_name = ["app.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/app"
app = "laravel"
php = { socket = "unix:/run/php/php8.4-fpm.sock", buffering = false, read_timeout = 300 }

[[site.location]]        # replaces the preset's /build/ block
path = "/build/"
try_files = ["$uri", "=404"]
add_headers = { "Cache-Control" = "public, max-age=86400" }
```

Two things a preset does not let you change: under `app = "laravel"` the web root is
always `public/` and only `/index.php` runs. A project that needs otherwise uses
`app = "php"` or explicit locations.

## 6. Locations, the reference

Precedence: `exact` matches first, then `suffix` locations (an ending such as `.php`,
matched at the end of the path or before a `/`), then the longest `prefix`; an implicit
`/` prefix with the site's settings always exists. A prefix location with `final = true`
(nginx `^~`) that is the longest prefix match shields its subtree from suffix locations.

| key | meaning |
|---|---|
| `path`, `match` | `"prefix"` (default), `"exact"`, or `"suffix"` |
| `root` | file = root + path (default: the site's root) |
| `alias` | file = alias + (path minus the location prefix); prefix locations ending in `/` only |
| `index`, `try_files`, `hidden_files`, `symlinks` | as on the site; the location's value wins |
| `handler` | `"static"` (default) or `"fastcgi"` |
| `fastcgi = { ... }` | overrides the site's `php = { ... }` for this location (section 7) |
| `methods` | narrows what the handler serves, e.g. `["GET", "HEAD"]`; the rest get 405 with `Allow` |
| `final` | prefix only: nginx `^~` |
| `deny_suffixes` | endings answered with 404 (like hidden files: a refusal never confirms a file exists), e.g. `[".php"]` under an uploads directory |
| `add_headers` | response fields added on 200 and 304, e.g. `{ "Cache-Control" = "..." }` |
| `priority` | may use the FastCGI pool slots reserved by `priority_reserve` |

## 7. PHP and FastCGI options

`php = { ... }` on the site is the default for its FastCGI locations; `fastcgi = { ... }`
on a location overrides it. Pool bounds are per upstream socket and per worker, so every
location on the same socket must agree on them: set them once on the site.

| option | default | meaning |
|---|---|---|
| `socket` | required | `"unix:/run/php/php8.4-fpm.sock"`, a bare path (relative to the config file), `"127.0.0.1:9000"` or `"[::1]:9000"` |
| `remote_root` | none | the docroot as php-fpm sees it when it runs in a container (section 9) |
| `buffering` | `true` | collect the whole reply (memory, then a temp file) and release the fpm child at once; `false` streams it |
| `buffer_max` | `"1MB"` | reply bytes kept in memory before spilling to a temp file |
| `buffer_file_max` | `"1GB"` | temp-file cap; beyond it the rest of the reply is streamed |
| `request_buffering` | `true` | collect the request body (memory, then temp file) before talking to fpm; `false` streams it |
| `request_buffer_max` | `"256KB"` | request body bytes kept in memory before the temp file |
| `connect_timeout`, `send_timeout`, `read_timeout` | 5, 30, 60 s | 504 when exceeded; `read_timeout` is between two records from fpm |
| `max_connections` | 16 | in-flight requests per worker to this socket; more wait in the queue |
| `queue_depth`, `queue_wait` | 64, 5 s | queue size and longest wait; beyond either, 503 with `Retry-After` |
| `priority_reserve` | 0 | share of `max_connections` kept for `priority = true` locations |
| `max_idle` | 8 | idle connections kept per worker to this socket when `keep_conn` is on |
| `keep_conn` | `false` | FastCGI keep-alive; php-fpm pins a child to every kept connection, so `max_connections` x workers must stay below `pm.max_children`. Not worth it through a Docker-published port (see below) |
| `head_max` | `"64KB"` | reply head larger than this is 502 |
| `path_info` | `true` | split `/x.php/extra` into SCRIPT_NAME and PATH_INFO |

Transport, measured on a Laravel page (`bench/results/laravel-keepconn-20260917.md`):
a unix socket costs agensio about half the CPU per request of a TCP port, and
`keep_conn` on top of it saves a little more. On TCP, agensio sets `TCP_NODELAY` and,
for kept connections, `TCP_QUICKACK` (Linux) so php-fpm's Nagle cannot stall large
responses; a port published through docker-proxy is out of reach of that fix, so keep
`keep_conn` off there or bind-mount the socket directory instead.

Failures are logged with a reason and a fix hint (socket owner/group/mode against
agensio's uid, the script php-fpm could not open, bytes seen before a child closed) and
appear in the JSON access log as `upstream`.

## 8. Logging

```toml
[log]
access = "logs/access.log"   # default: this path next to the config file; "off" disables
format = "combined"          # Apache/nginx combined (fail2ban filters work) or "json"
error = "stderr"             # or a file
level = "warn"               # error | warn | info
```

A site sets `access_log = "path"` or `"off"` to differ. Logs are buffered per worker and
flushed every second; `kill -USR1 <pid>` reopens all files after rotation.

## 9. php-fpm in a container

When php-fpm runs elsewhere (Docker, ddev), publish its port and tell agensio the docroot
as php-fpm sees it:

```toml
[[site]]
server_name = ["app.example.com"]
listen = ["0.0.0.0:80"]
root = "/srv/app"                       # the project on this host (bind-mounted into the container)
app = "laravel"
php = { socket = "127.0.0.1:9000", remote_root = "/var/www/html/public" }
```

`SCRIPT_FILENAME`, `DOCUMENT_ROOT` and `PATH_TRANSLATED` are rewritten from the local root
to `remote_root`; agensio still checks locally that the script exists. The three ddev test
beds under `bench/` are complete working examples of this shape.

## 10. Behind a reverse proxy or load balancer

```toml
[server]
trusted_proxies = ["10.0.0.0/8", "127.0.0.1"]
```

From those peers `X-Forwarded-For` (rightmost hop that is not itself trusted) becomes the
client address in the access log and `REMOTE_ADDR`, and `X-Forwarded-Proto: https` sets
`HTTPS` and `REQUEST_SCHEME` for PHP. Unset, the headers are ignored, so nothing can be
spoofed from the open internet.

## 11. Hosting: one user per site

`user = "web1"` on a site makes PHP for that site run as `web1` in a php-fpm pool that
agensio generates. Nothing else is needed:

```toml
[server]
user = "agensio"             # the account the server serves as; its group reads the sites and the pool sockets
# group = "agensio"          # default: the user's primary group
# pools = "/etc/php/8.3/fpm/pool.d"   # where `agensio pools` writes (default: detected)
# pools_run = "/run/php"              # where generated pools listen (default: per distro)
# state_dir = "/var/lib/agensio"      # per-user tmp and session directories
# strict_users = true                 # refuse a site without `user`

[[site]]
server_name = ["shop.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/clients/web1/shop"
user = "web1"
group = "client1"            # optional, default: the user's primary group
app = "laravel"
php = { children = 8 }       # no socket: it is derived, /run/php/agensio-web1.sock
```

Then, as root:

```sh
agensio pools -c /etc/agensio/agensio.toml   # writes agensio-web1.conf, exit 3 when something changed
systemctl reload php8.3-fpm
```

What the pool gets: `user`/`group` of the site, socket `0660 web1:agensio`, `pm` and
`children`, `pm.max_requests`, a private `tmp/` and `sessions/` under
`state_dir/web1` (0700, owned by the user), `open_basedir` at the project directory
plus those two, `memory_limit`, `max_execution_time`, upload limits from
`max_body_size`, `clear_env`, `expose_php = off`. `agensio -t --explain` prints the
whole file. agensio's own FastCGI options for a generated pool default to
`keep_conn = true` with `max_connections = children / workers`, so kept connections can
never pin every child (section 7).

Pool keys in `php = { ... }`, all optional:

| key | default | meaning |
|---|---|---|
| `children` | 8 | `pm.max_children` |
| `pm` | `"static"` | `"static"`, `"dynamic"` (half the children on standby) or `"ondemand"` |
| `max_requests` | 500 | `pm.max_requests`; 0 = unlimited |
| `memory_limit` | `"256M"` | `memory_limit` |
| `max_execution_time` | 60 | seconds |
| `version` | newest installed | php version whose pool directory `agensio pools` writes to |
| `open_basedir` | project, tmp, sessions | replaces the default list |
| `extra` | none | `{ "date.timezone" = "Europe/Athens" }` becomes `php_admin_value[...]` lines |

Rules: two sites with the same `user` share one pool and must agree on these keys;
sites with different users may never name the same socket; a site with `user` and an
explicit `php.socket` keeps its own pool and gets no generated file.

**What `agensio -t` (and every start) refuses** for a site with `user`, naming the path,
its owner and mode, and what was expected:

- the user or group does not exist;
- the root or an `open_basedir` entry is not owned by the user (or root), or is writable
  by other users;
- the root (or the project above a Laravel `public/`) cannot be read by the server's
  account: the fix it prints is `chown <user>:<server group> ROOT && chmod 2750 ROOT`,
  the layout `site-create` prescribes;
- a secret is readable by other users: `.env`, `config/`, `storage/` and `.git` for
  Laravel (in the project directory), `wp-config.php` for WordPress, `.env` and `.git`
  under the root otherwise (make them `0640 user:group`);
- the pool socket is not owned by the user, not in the server's group (owner = site user,
  group = server group, `0660`: the server connects through the group bit, nobody else
  can), or has mode bits for others; or its directory is world-writable;
- the access log is readable by other users, or its directory is writable by them;
- two sites with different users share a root (or nest one inside the other), an access
  log or a state directory.

Sites without `user` are not checked, so a single-tenant machine changes nothing.

One rule set answers `agensio -t`, the server's own start, every reload and site change
through the control socket, and the health check: a configuration that reloads is one
that boots. The server's group in those rules is `server.group`, else the primary group
of `server.user`, never the group of whoever runs the check.

**Starting as root.** With `user` set on sites you normally want privileged ports and
per-site logs too:

```toml
[server]
user = "agensio"     # bind, open the logs, then become this user
group = "agensio"
```

agensio binds its listeners and opens every log as root, makes each site's access log
`agensio:<site group> 0640` (agensio writes it, the customer reads it through their
group, nobody else), then switches to `user` with its groups before accepting the first
connection. Started as that user already, as systemd would, it just runs. Started as root
without `user` it warns and keeps running as root. Without root the per-site chown fails
and one warning per site says which customer cannot read their log.

## 12. Reverse proxy

`upstream = "http://host:port"` (or `"unix:/path"`) on a location forwards everything under
it to an HTTP/1.1 origin. The defaults are what a site behind a proxy needs, so most setups
are one line per location:

```toml
[[site]]
server_name = ["app.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/app/public"      # static files served here where a location says so
tls = { cert = "...", key = "..." }
proxy = { read_timeout = 120 }    # site-wide defaults for every proxy location below

[[site.location]]                 # the application
path = "/"
upstream = "http://127.0.0.1:3000"

[[site.location]]                 # an API on another service, its prefix dropped:
path = "/api/"                    # /api/users -> http://127.0.0.1:4000/users
upstream = "http://127.0.0.1:4000/"

[[site.location]]                 # server-sent events: stream, do not buffer
path = "/events/"
upstream = "http://127.0.0.1:3000"
proxy = { buffering = false, read_timeout = 3600 }

[[site.location]]                 # assets straight from disk
path = "/assets/"
```

**Groups.** `upstream = ["http://10.0.0.11:3000", "http://10.0.0.12:3000"]` spreads
requests over several origins, round-robin within each worker. An origin that fails
`max_fails` times in a row (default 3) is skipped for `fail_timeout` (default 10 s), then
tried again; when every member is down the one marked longest ago is tried anyway. A
request whose origin refuses the connection or times out before answering moves to the
next member: any request when nothing was sent yet (a refused connection), only GET and
HEAD once bytes went out, so a POST is never delivered twice. Each member is a pool of its
own with the location's limits; all members must share the URI part. Both events are in
the error log: `marked down for 10 s after 3 failure(s)` and `is back`. No weights and no
active health checks until a real deployment asks for them.

**TLS to the origin.** `upstream = "https://10.0.0.11:8443"` talks TLS to the origin,
keep-alive included, so a handshake is paid once per pooled connection rather than per
request. The certificate is verified against the system store by default;
`proxy = { tls = { ca = "/etc/ssl/internal-ca.pem", server_name = "app.internal" } }`
names a private CA and the name to check (also sent as SNI; needed whenever the address is
an IP literal), and `tls = { verify = false }` accepts anything, for a self-signed origin
you control. A failed handshake or verification is a 502 logged as `tls_error`.

**Target.** The client's request line is forwarded as sent. With a URI part on `upstream`
(`http://host:port/` or `.../v1/`) the location's prefix is replaced by it, the way
nginx's `proxy_pass` with a URI works; without one the path is untouched. Exact and
suffix locations cannot rewrite.

**What the origin sees**, with no configuration:

- `Host` as the client sent it. (nginx forwards the upstream's address unless told
  otherwise, which is the first thing everyone has to fix; here `host = "upstream"` is the
  opt-in and `host = "app.internal"` a literal.)
- `X-Forwarded-For` and `X-Forwarded-Proto`, always set by agensio; `X-Forwarded-Host`
  only when Host was rewritten (or a trusted proxy in front sent one), because with Host
  passed through it would only repeat it and every field costs the origin parsing time.
  A client that is not one of `server.trusted_proxies` gets its own X-Forwarded-* replaced,
  never appended to, so nothing from the open internet reaches the application as a
  believed address. Behind a trusted proxy the chain is appended to. `forwarded =
  "forwarded"` sends RFC 7239 `Forwarded` instead, `"both"` sends both, `"off"` neither.
- Every other field except the hop-by-hop ones (`Connection` and whatever it lists,
  `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `Expect`) and the framing.
- The body with a Content-Length when its size is known (also after agensio collected a
  chunked body), chunked otherwise. Keep-alive to the origin, HTTP/1.1: nothing to enable.

`headers = { ... }` sets fields on the way to the origin. A value may use `$host`,
`$remote_addr` (the client as agensio knows it, forwarded-aware), `$scheme`,
`$server_name` and `$server_port`; an empty value removes the client's field. A site's
`proxy = { headers = ... }` and a location's are merged, the location winning per field:
nothing is silently reset by a nested table, which is nginx's best-known
`proxy_set_header` trap.

**What the client sees.** The origin's status and fields, except framing and connection
ones, `Server` and `Date` (agensio's own), and whatever `hide = [...]` lists. A chunked
origin body is re-framed with a Content-Length when buffered, passed on as chunked when
streaming. A `Location` that points at the origin's own address is rewritten to this site
and location (`redirects = "pass"` leaves it alone). The location's `add_headers` are
added on 2xx and 3xx answers (HSTS, CORS, cache policy), for proxied and PHP responses
alike.

**WebSockets and other upgrades** need nothing: a request carrying `Connection: Upgrade`
and an `Upgrade` field is forwarded as one, and when the origin answers 101 the connection
becomes a tunnel that copies bytes both ways until a side closes. There is no idle limit on
a tunnel by default (nginx's 60 s read timeout silently dropping idle WebSockets is the
usual surprise); `tunnel_timeout = 3600` sets one, `upgrade = false` refuses upgrades
on a location.

**Options** of `proxy = { ... }`, on a site (defaults for its locations) or a location:

| option | default | meaning |
|---|---|---|
| `host` | `"pass"` | `"pass"` the client's Host, `"upstream"` the origin's address, or a literal name |
| `forwarded` | `"x-forwarded"` | `"x-forwarded"`, `"forwarded"` (RFC 7239), `"both"`, `"off"` |
| `headers` | none | fields set toward the origin, `{ "X-Real-IP" = "$remote_addr" }`; `""` removes |
| `hide` | none | fields dropped from the origin's answer, `["X-Powered-By"]` |
| `redirects` | `"rewrite"` | Location pointing at the origin rewritten to this site, or `"pass"` |
| `upgrade` | `true` | forward Upgrade requests and tunnel after a 101 (WebSocket) |
| `tunnel_timeout` | 0 | seconds a tunnel may stay idle in both directions; 0 = no limit |
| `buffering` | `true` | collect the whole answer (memory, then a temp file above `buffer_max`) so a slow client never holds the origin; `false` streams with backpressure |
| `request_buffering` | `true` | collect the request body before connecting; `false` streams it as it arrives |
| `connect_timeout`, `send_timeout`, `read_timeout` | 5, 30, 60 s | 504 when exceeded; `read_timeout` is between two reads from the origin |
| `keep_conn`, `max_idle` | `true`, 64 | keep-alive to the origin; idle connections kept per worker |
| `max_connections`, `queue_depth`, `queue_wait` | 256, 1024, 5 s | per worker: in flight, waiting, and the longest wait before a 503 with `Retry-After` |
| `head_max` | 64 KB | an origin head larger than this is a 502 |
| `max_fails`, `fail_timeout` | 3, 10 s | consecutive failures that mark a group member down, and for how long |
| `tls` | verify on, system store | `{ verify, server_name, ca }` for `https://` origins |

The pool is per worker, so an origin sees at most workers x `max_connections` connections
and workers x `max_idle` idle ones. A GET or HEAD whose kept connection turns out dead is
retried once on a fresh one. An origin that is down gives 502, a timeout 504, a full
queue 503; each is logged with the reason and appears in the JSON access log as
`upstream`. `agensio -t` connects to every origin once and warns when it cannot, and
`-t --explain` prints the effective policy of every proxy location.

Not here on purpose: separate buffer-size knobs (nginx's `proxy_buffer_size`,
`proxy_buffers`, `proxy_busy_buffers_size` and their interplay), a `proxy_http_version`
switch, the three-directive Upgrade/Connection incantation for WebSockets, and
`proxy_redirect` rules with regular expressions.

## 12b. Reload without restart

Edit the file, then:

```sh
agensio reload        # validates the file, then signals the running server
```

No path is needed on an installed machine: the file is looked for in the working
directory, then `/etc/agensio/agensio.toml` (and the brew locations on macOS), the same
search every command uses; `-c` points elsewhere. The server writes its pid to
`server.pid_file`, `/run/agensio.pid` by default (`""` disables it), which is how the
command finds it; `kill -HUP $(cat /run/agensio.pid)` does the same without the
validation step. What
happens in the server, in this order: the file is loaded and checked exactly as `-t`
does, including the hosting rules; certificates are read and new listen addresses are
bound; only then does every worker switch to the new configuration, between requests.
Nothing is interrupted:

- a request being served, an upstream exchange waiting on php-fpm or an origin, a CGI
  process, a WebSocket tunnel: each finishes on the configuration it started with;
- a keep-alive connection serves its next request from the new configuration on the
  same connection;
- a connection on a listen address that was removed serves its current request, then is
  told `Connection: close`; the address stops accepting at once;
- a broken file, a certificate that cannot be read or a port that cannot be bound refuses
  the whole reload, with the reason in the error log, and the old configuration keeps
  serving.

Under a 64-connection load the switch itself costs nothing measurable and no request
fails (`tests/reload.sh`). Restart-only settings, logged as kept when the file changes
them: `workers`, `reuse_port`, `user`, `group`, `sendfile` and the cache sizes.

Note: the static file cache starts cold for every reloaded site (entries are keyed by
the location the configuration created), so the first request for each file after a
reload reads it from disk again.

## 13. CGI

`handler = "cgi"` (or just a `cgi = { ... }` table) on a location runs the requested file
as a process per request with the CGI/1.1 environment, for the legacy applications that
still ship that way:

```toml
[[site.location]]
path = "/cgi-bin/"
alias = "/var/www/cgi-bin"
cgi = { max_connections = 8, read_timeout = 30, env = { "APP_ENV" = "production" } }

[[site.location]]                 # scripts that need an interpreter in front
path = "/legacy/"
cgi = { interpreter = "/usr/bin/perl" }
```

The script is the longest leading part of the path that names a regular file (Apache's
rule), the rest is `PATH_INFO`; a directory URI takes the location's `index`
(`index.cgi` by default). The process runs in the script's directory with the same
variables the FastCGI handler sends (`REQUEST_METHOD`, `SCRIPT_NAME`, `PATH_INFO`,
`QUERY_STRING`, `CONTENT_LENGTH`, `REMOTE_ADDR`, `HTTPS`, `HTTP_*` and the rest), the
location's `env` entries, and a plain `PATH`. The request body is its stdin, its stdout
is the response (a CGI head with `Status:` or `Location:`, then the body until it exits),
its stderr goes to the error log. The options are those of section 7 with these
defaults: `max_connections = 8` processes per worker and `queue_depth = 32` waiting
(more are a 503), `read_timeout = 30` (no output for that long: the process is killed,
504), buffering and request buffering on. Every other descriptor of the server is closed
in the child. Not a fast path: a process per request is what CGI is.

## 14. TLS

```toml
[[site]]
server_name = ["example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example"
tls = { cert = "/etc/ssl/example/fullchain.pem", key = "/etc/ssl/example/privkey.pem" }
```

A listen address is either plain or TLS for every site on it.

### Automatic certificates

```toml
[server]
acme = { email = "admin@example.com" }

[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/example/public"

[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example/public"
tls = "auto"
```

`tls = "auto"` makes agensio obtain and renew the certificate itself from an ACME
(RFC 8555) certificate authority, Let's Encrypt by default. There is no separate client
to install, no cron job and no reload hook: the server does the whole thing and switches
to the new certificate through the reload path, so no request is interrupted.

What happens:

1. **Start.** If no certificate exists yet, a self-signed placeholder is written so the
   listener can come up at once. An order is placed immediately.
2. **Validation (HTTP-01).** The CA fetches
   `http://<name>/.well-known/acme-challenge/<token>` for every name in `server_name`.
   agensio answers that path itself, on any plain listener and before any site or location
   rule, so nothing in your configuration can get in the way. The names must therefore
   resolve to this server and **port 80 must be reachable from the internet** (the plain
   site above). Nothing else needs configuring: no location, no writable webroot.
3. **Issue.** A fresh P-256 key is generated per certificate, a CSR covering all the
   names is finalized, the chain is downloaded and both files are written atomically.
4. **Switch.** The server reloads itself (`reloaded ...` in the error log): new
   connections get the new certificate, connections in flight finish undisturbed.
5. **Renew.** Once an hour the certificates are checked and renewed when a third of
   their lifetime is left (day 60 of a 90-day certificate, day 4 of a 6-day one), so
   short-lived profiles work too. A failed order is logged with the CA's reason and
   retried an hour later; the current certificate keeps serving meanwhile. Adding a
   name to `server_name` triggers a new order at the next check (or at once on reload).

`[server] acme` keys:

| key | default | meaning |
|---|---|---|
| `email` | required | The account contact. The CA sends expiry warnings there; it never appears in a certificate. |
| `directory` | Let's Encrypt production | The CA's directory URL. Staging: `https://acme-staging-v02.api.letsencrypt.org/directory`; any RFC 8555 CA (ZeroSSL, Buypass, Google, a private step-ca or Pebble) works. |
| `storage` | `<state_dir>/acme` | Where the account key and the certificates live: `account.key`, then `<first server_name>/key.pem` (0600) and `<first server_name>/fullchain.pem`. Started as root with `server.user`, the tree is handed to that user so renewals work after the privilege drop. |
| `ca` | system trust store | A PEM file to trust for the directory's own TLS; only for private CAs and tests. |

### HTTPS only

```toml
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https"

[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example/public"
tls = "auto"

[[site.location]]
path = "/"
add_headers = { "Strict-Transport-Security" = "max-age=31536000" }
```

`redirect = "https"` answers every request on that site with a 301 to the same host and
path over https (the Host header without its port, the query string kept). The site
needs no `root`, no locations and no preset. The ACME validation still works on it: the
challenge path is answered before the redirect. For a TLS listener on a non-standard port
give the prefix instead: `redirect = "https://example.com:8443"`. A `redirect` on a site
that itself has `tls` is refused (it would loop).

**One canonical host.** To serve everything from `www.example.com` and send the bare
name there, give the bare name its own redirecting sites, on both ports. The one on 443
needs a certificate too (browsers check it before following any redirect), which
`tls = "auto"` provides:

```toml
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https://www.example.com"

[[site]]
server_name = ["example.com"]
listen = ["0.0.0.0:443"]
tls = "auto"
redirect = "https://www.example.com"

[[site]]
server_name = ["www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = "auto"
```

`http://example.com/x?y`, `http://www.example.com/x?y` and `https://example.com/x?y`
all answer 301 to `https://www.example.com/x?y`. The same shape with the names swapped
makes the bare name canonical. `redirect = "https"` (same host) is refused on a TLS site
because it would loop; a prefix naming another host is fine there.

The `Strict-Transport-Security` header is deliberately not automatic: once a browser has
seen it, it refuses plain http for that host until `max-age` expires, so set it when the
https site is known to work. `add_headers` on the `/` location puts it on every response
of the site.

Rules checked by `agensio -t`: `tls = "auto"` needs `[server] acme`; `server_name` must
list real host names (no `*`, no wildcards: those need DNS-01, which is not in this
release); an `email` is required. `agensio -t --explain` prints the resolved file paths.
Manual certificates on other sites, `tls = { cert, key }`, coexist with automatic ones.

Backups: the `storage` tree is all there is to keep. Restoring it on another machine and
starting agensio there continues renewals without a new account or order. Deleting a
site's directory orders a new certificate at the next start.

Not in this release: TLS-ALPN-01 (for servers with no port 80), DNS-01 and wildcards,
OCSP stapling, external-account binding. They follow on the roadmap (H3a) in the order
users ask for them.

Testing against a local CA: `tests/acme.sh build/agensio` starts Pebble (Let's Encrypt's
test server, `bench/acme/docker-compose.yml`), orders a certificate for
`host.docker.internal` over port 5002, verifies the served chain against Pebble's root
and checks that a restart keeps the certificate.

## 15. Control socket

```toml
[control]
socket = "/run/agensio/control.sock"   # default on Linux; macOS: /usr/local/var/run/agensio/control.sock
admins = "agensio-admin"               # groups; root and server.user are always admin
operators = "agensio-ops"
viewers = "agensio-view"
audit = "/var/log/agensio/audit.log"   # default: audit.log next to the error log
sites_root = "/var/www"                # where site-create suggests document roots
```

The control API is how `agensio ctl`, the MCP bridge (`agensio mcp`) and any local tool
inspect and, in later steps, configure the running server. It exists only when the
`[control]` table is present. It is a unix domain socket, never a port: nothing on the
network can reach it, and a site listener can never route to it because it is a separate
listener with its own code path.

**Who may connect.** Every connection is checked by its peer credentials, the uid and
gid the kernel reports for the process at the other end, whatever the file mode says.
`root` and the account in `server.user` are admins. Members of the `admins` group are
admins, members of `operators` may reload, purge and read logs, members of `viewers` may
only read. Anyone else is disconnected at accept and the attempt goes to the audit log
with its uid. The socket's directory is created by the server, owned by it and never
writable by others, so a site user cannot replace the socket path. With only `admins`
configured the socket file is `0660` for that group; with several groups it is `0666`
and the credentials alone decide.

**Audit.** One line per refused connection and, from F3 on, per mutating command: time,
uid, gid, role, command and outcome. Rotated with the other logs (`SIGUSR1`).

**Commands** (`agensio ctl <command>`, or HTTP/1.1 + JSON on the socket, `GET /v1/...`):

| command | role | answer |
|---|---|---|
| `status` | viewer | version, pid, uptime, configuration path, workers, open connections, listeners, sites (names, listen, root, app, user, tls, redirect), whether ACME is on, and the caller's uid/gid/role |
| `sites` | viewer | every site: names, listen, root, app, user, redirect, access log, and its certificate (mode, issuer, names, days left, whether it is still the placeholder) |
| `site NAME` | viewer | one site in full: the above plus index, php socket and generated pool, upstreams, and every location after the preset expanded (path, match, handler, root/alias, upstream, added headers, which preset added it) |
| `validate` | viewer | loads the file on disk again and runs the hosting rules: `ok`, `errors`, site count, and the restart-only settings that differ from the running server |
| `logs` | viewer | `--site NAME` (default: all sites plus the error log), `--since 3h` (`m`, `h`, `d`, `w`, seconds, or a local `YYYY-MM-DDThh:mm:ss`; default 1h), `--level error|warn|info` for the error log (default warn = error+warn), `--status 5xx|4xx|all|NNN` for access logs (default 5xx), `--limit N` (default 200, newest). Reads at most 2 MB per file from the end; `truncated` says when that cut in |
| `health` | viewer | findings with `severity`, `code`, `site`, `message`, `fix`: configuration on disk invalid or failing the hosting rules, restart-only settings changed, running as root, certificate unreadable / still the placeholder / expired / expiring within 14 days (manual), `tls = "auto"` without a plain port-80 site for the names, no http-to-https redirect, application sites sharing the server's account, generated pools out of date, errors in the last 24 hours. `ok` is true when nothing above info level was found |

**Changes** (`POST` with a JSON body; every one needs `"confirm": true`, takes a
`"reason"` that goes to the audit log, and answers 428 without the confirmation):

| command | role | what it does |
|---|---|---|
| `reload` | operator | the same as `agensio reload`: validate the file on disk, bind, switch; 409 with the reason when refused, nothing changed then |
| `logs-reopen` | operator | reopen every log file (what `SIGUSR1` does) |
| `site-create` | admin | writes `sites.d/<domain>.toml`, validates, reloads. Fields: `domain`, `aliases`, `https` (`auto`, `none`, or `{cert, key}`), `redirect_http` (default true), `hsts`, `user` (`null` for none), `group`, `app`, `root`, `upstream`, `php_socket`, `php_children`, `php_version`, `listen_plain`, `listen_tls`. Until `https`, `root` (or `upstream`), `app` and `user` are decided it answers 422 with the open questions and a suggestion each (a user name from the domain, the app the files under root suggest); when the account or the root directory does not exist it answers 409 with the commands to run as root and waits for the same command again. A new site is HTTPS-only: the plain site redirects. |
| `site-update NAME` | admin | the same fields on a site `site-create` wrote (the file carries its spec on its first line); a hand-written file is refused with 409, edit it yourself |
| `site-disable NAME`, `site-enable NAME` | admin | renames the file to `.disabled` and back, reloads |
| `site-delete NAME` | admin | removes the file (a `.bak` stays), reloads; never touches the root or the account |
| `cert-renew NAME` | operator | orders the site's automatic certificate again now |

A change that does not validate is undone before the answer: the file is removed or the
previous one restored, and the old configuration keeps serving. The server never runs
a shell command for any of these; what needs root comes back as text.

Unknown commands answer a JSON 404, a wrong method a 405 with `Allow`, a role that is too
low a 403 naming the role needed. `curl --unix-socket /run/agensio/control.sock
http://control/v1/status` is the same call by hand.

`agensio mcp` exposes the same commands to an AI agent host as Model Context Protocol
tools, locally or over SSH: see `docs/mcp.md`.

`agensio -t` on a shared host warns when a php-fpm pool, proxy origin or CGI location
runs as the server's own user or as a member of the admin group: with everything under
one account the peer-credential check cannot tell sites apart. Per-site users (section
11) are what makes the control socket safe on a shared host.
