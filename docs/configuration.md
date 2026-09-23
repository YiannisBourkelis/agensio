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

Every key, with its type, default, whether a change needs a reload or a restart, and who
may change it, is listed in `docs/keys.md`, generated from the same table that the MCP
tool `config_reference` and `agensio keys` serve; the sections below explain them.

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

## 1b. Which site answers a request

A site answers the names in its `server_name`, compared case-insensitively and without
the port. On each listen address exactly one site may be the **catch-all**: the one with
`server_name = ["*"]`, or with `default = true`. It answers every other Host, requests
by IP address, and HTTP/1.0 requests without a Host header.

A listener **without** a catch-all is strict: a request whose Host no site on it lists
answers `421 Misdirected Request` with `Cache-Control: no-store` and a constant body.
Nothing reaches an application for a name it did not claim, so forged Host headers
(the class Drupal's `trusted_host_patterns` and Laravel's `TrustedHosts` defend
against) never get there, and an HTTP/2 client that coalesced connections retries on a
fresh one rather than caching a 404. If you want the old behaviour of "the only site
serves everything", say so with `server_name = ["*"]`, or add `default = true` to the
site. Monitors that check the IP address need the hostname, or a catch-all.

**TLS** follows the same rule at the handshake: the certificate is the one of the site
that lists the name the client sent (SNI), each site on a listener may have its own
certificate, and a name no site lists ends the handshake with `unrecognized_name`, so no
other site's certificate is ever shown. A client that sends no name gets the catch-all's
certificate, or is refused when the listener has none. An HTTP/1.1 request without a
Host header stays a 400.

**A TLS connection is authoritative only for the names its certificate covers** (RFC 9110
section 7.4, RFC 6125 matching: the subject CN, the DNS and IP entries of the
subjectAltName, a wildcard for exactly one leftmost label). Whatever sites the listener
holds, a request whose Host the presented certificate does not name answers `421`, the
same constant answer as an unknown Host: a connection opened with `b.example`'s
certificate never serves `a.example`, and a catch-all site on a TLS listener is bounded
the same way. A certificate covering several names (a SAN or wildcard certificate) makes
every site it names reachable on one connection, which is what an HTTP/2 client's
connection coalescing relies on. The decision uses the certificate presented at the
handshake, so a renewal or reload never changes what an established connection may
serve. Plain listeners have no certificate and keep the listener rule; a request without
a Host (HTTP/1.0) claims no name and reaches the catch-all as before.

`agensio ctl status` names each listener's catch-all or `null`; `sites` marks catch-all
sites; `site-create` warns when it adds the first site to a listener without one.

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
path = "/"               # any spelling is refused (404), never executed, never served as source,
deny_suffixes = [".php", ".phtml", ".phar", ".pht", ".phtm", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".phps",
                 ".inc", ".bak", ".orig", ".save", ".swp", ".swo", "~"]   # and .inc and editor backups too

[[site.location]]        # Vite output is content-hashed: cache it for a year
path = "/build/"
try_files = ["$uri", "=404"]
deny_suffixes = [...the same list...]
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

[[site.location]]        # everything else: static files or the front controller; PHP in a spelling
path = "/"               # the suffix location does not take (x.PHP, x.phtml), .inc and editor backups
deny_suffixes = [".php", ".phtml", ".phar", ".pht", ".phtm", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".phps",
                 ".inc", ".bak", ".orig", ".save", ".swp", ".swo", "~"]

[[site.location]]        # nothing under uploads is ever executed; files are cacheable
path = "/wp-content/uploads/"
final = true             # nginx ^~: the .php suffix location is not consulted here
deny_suffixes = [...the same list...]
try_files = ["$uri", "=404"]
add_headers = { "Cache-Control" = "public, max-age=604800" }

[[site.location]]        # core assets: same shield, longer cache
path = "/wp-includes/"
final = true
deny_suffixes = [...the same list...]
try_files = ["$uri", "=404"]
add_headers = { "Cache-Control" = "public, max-age=2592000" }
```

`wp-content/plugins` is deliberately not shielded: some plugins expose PHP endpoints
there. `wp-config.php`, `wp-config-sample.php`, `readme.html`, `license.txt` and the
`wp-content` drop-ins `db.php`, `advanced-cache.php` and `object-cache.php` are answered
404 by exact locations the preset adds (`try_files = ["=404"]`): the credentials file is
never executed nor shown, whereas nginx recipes usually execute it (it prints nothing);
the readme and the licence name the installed WordPress version, the first thing a
vulnerability scanner reads, and cost nothing to withhold; the drop-ins run only inside
WordPress's own bootstrap and answer 500 when fetched directly. `.htaccess`, `.user.ini`
and the SQLite plugin's `wp-content/database/.ht.sqlite` are dotfiles and hidden. agensio
never reads `.htaccess`; see section 4c.

**Backups of those names are the same 404.** `wp-config.php~`, `wp-config.php.bak`,
`.save`, `.orig`, `.txt`, `.old`, `.dist`, `wp-config.bak`, `wp-config.txt`,
`.wp-config.php.swp` (vim), `#wp-config.php#` (emacs), `wp-config.php-old`, in any case:
every name a preset never serves is protected in every backup spelling within its
directory, without configuration and whatever `hidden_files` says. The rule is anchored
on the name, not on an ending, so `ads.txt`, `security.txt` and every other public file
are untouched, and `/readme`, `/license` and `/license-agreement` stay permalinks
(2026-09-20: a live host served `wp-config.php~` and four other backups with the database
password and the salts in them; the exact name was 404). The presets catalogue
(`agensio ctl presets`, MCP `presets_list`) states the rule.

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
deny_suffixes = [".inc", ".bak", ".orig", ".save", ".swp", ".swo", "~", ".log", ".sql",   # the shared list (below)
                 ".install", ".module", ".theme", ".engine", ".profile", ".make", ".po", ".twig", ".yml", ".yaml",
                 ".sqlite", ".sqlite3", ".db", ".tpl", ".xtmpl"]                             # Drupal's own

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

A file below `sites/default/files/` that exists is served statically, cached like any
asset; one that does **not** exist reaches `index.php` with its query string, because
that is how Drupal makes image-style derivatives (`styles/<style>/public/...?itok=...`)
and rebuilds aggregated `css/` and `js/` after a cache rebuild: Drupal's own `.htaccess`
does the same. PHP-like endings below `files/` stay refused with 404 and never reach
PHP, whether the file exists or not; the refusal ignores case and trailing dots
(`x.PHP`, `x.PhP`, `x.php.`), covers `.php`, `.phtml`, `.phar`, `.pht`, `.phtm`,
`.php3` to `.php8`, `.phps`, Drupal's source spellings and editor backups (`~`, `.bak`,
`.orig`, `.save`, `.swp`), and a `.php.jpg` is a jpg (2026-09-20: upper-case and
trailing-dot spellings were served as source). (2026-09-20: a deleted derivative was answered 404
by the server for ever; the other shields, `core/lib/`, `vendor/`, keep answering 404
for a miss.)

**One list for every PHP preset.** Besides the PHP spellings, every preset's root and
every shield refuse `.inc` (the include suffix PHP code ships as; a bare Apache serves it
as text), editor or copy backups of anything: `.bak`, `.orig`, `.save`, `.swp`,
`.swo`, `~`, and since alpha.20 logs and database dumps, `.log` and `.sql` (2026-09-23:
a Grav site's `logs/grav.log` named the backup archive next to it; WordPress's
`wp-content/debug.log` is the classic). A hand-written location still serves any of them
where a site means to. Drupal's list is that plus its own spellings. The root refuses the PHP
spellings too, on every preset: when every `.php` runs, the suffix location takes the
exact spelling first, so what reaches the root is `x.PHP` or `x.phtml`, which nothing
runs and which would otherwise be served as source. The integration suite plants one
table of spellings under every preset's shields and roots and asserts each is refused
(2026-09-20: testing each preset against its own list had let WordPress fall behind
Drupal, and `x.inc`, `x.php~` under `wp-content/uploads` were served as source). And
every name a preset never serves (section 4, WordPress) is refused in every backup
spelling: `settings.php~`, `settings.php.bak`, `settings.bak`, `.settings.php.swp`.

**The preset must be the application's.** A site whose files belong to another
application than its `app` says gets that application's refusals and none of its own:
run on the drupal preset, a Grav site served its `logs/grav.log` (before `.log` was on
the shared list) and, named in it, the `backup/*.zip` with the admin account and the
signing salt inside (2026-09-23, a live host). `health` reports such a site as
`preset_mismatch` with the application it detected (`bin/grav` and `system/defines.php`
for Grav, `artisan`, `core/lib/Drupal.php`, `wp-config.php`) and the `app` to set;
`site-create` warns the same way when the directory already holds files. Backup
archives and database dumps under any served tree (`.zip`, `.tar.gz`, `.7z`, `.sql`,
...) are reported as `archives_in_root`, whatever the preset refuses today: nothing
served should hold a copy of the site.

## 4d. Grav: `app = "grav"`

```toml
[[site]]
server_name = ["grav.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/grav"              # the Grav directory itself (index.php, system/, user/)
app = "grav"
php = { socket = "unix:/run/php/php8.4-fpm.sock" }
```

expands to Grav's own nginx recipe, which denies directories rather than endings:

```toml
index = ["index.php"]
try_files = ["$uri", "$uri/", "/index.php?$query_string"]   # every page route reaches the front controller

[[site.location]]        # only index.php runs; any other .php is refused (404), never served as source
path = "/index.php"
match = "exact"
handler = "fastcgi"

[[site.location]]        # the root: PHP spellings, .inc, editor backups, .log and .sql refused
path = "/"
deny_suffixes = [".php", ".phtml", ..., ".inc", ".bak", ".orig", ".save", ".swp", ".swo", "~", ".log", ".sql"]

# never answered, whatever they hold: Grav's own nginx recipe denies these directories, and a
# backup archive under backup/ is the site (accounts, salt, configuration, pages)
[[site.location]]  path = "/logs/"    final = true  try_files = ["=404"]     # handler = "deny"
[[site.location]]  path = "/logs"     match = "exact"  try_files = ["=404"]  # the bare name: no redirect confirms the directory
# likewise /backup/, /cache/, /bin/, /tests/, /tmp/

# assets only below system/ and vendor/ (css, js, images, fonts): no source, templates,
# configuration or documentation
[[site.location]]  path = "/system/"  final = true  try_files = ["$uri", "=404"]
                   deny_suffixes = [...the root's list..., ".txt", ".xml", ".md", ".html", ".yaml", ".yml", ".pl", ".py", ".cgi", ".twig", ".sh", ".bat"]
[[site.location]]  path = "/vendor/"  (same)

# user/: images, css, js, fonts and uploads are served; pages (.md), accounts and
# configuration (.yaml), templates (.twig) and scripts are not
[[site.location]]  path = "/user/"    final = true  try_files = ["$uri", "=404"]
                   deny_suffixes = [...the root's list..., ".txt", ".md", ".yaml", ".yml", ".pl", ".py", ".cgi", ".twig", ".sh", ".bat"]

# never answered although present (404): the version fingerprints and composer files
[[site.location]]  path = "/LICENSE.txt"  match = "exact"  try_files = ["=404"]
# likewise composer.json, composer.lock, nginx.conf, web.config, htaccess.txt, CHANGELOG.md,
# README.md, user/config/security.yaml (the signing salt; the preset's `secret`)
```

`.htaccess` and `.git/` are dotfiles and stay hidden by the site default. Grav's
processed images (`images/`), the asset pipeline (`assets/`) and theme and plugin assets
under `user/` are plain files and cache like any other. The admin plugin's routes
(`/admin`) are pages and reach `index.php`. `site-install` fetches the newest
`grav-admin` release from getgrav.org (`--version 1.7.48` for a release); the site's
directory is Grav's own, no `public/`. Health looks at `user/pages` first for
unreadable uploads. What every `never` name gets (section 4c) applies here: backups of
`security.yaml` in any spelling are refused.

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
| `idle_timeout` | 30 | seconds a kept connection may stay idle before agensio closes it (0 = kept until the peer closes); a kept connection pins a php-fpm child, and an `ondemand` child can only exit once it is closed |
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
`state_dir/web1` (`tmp/` is `2750 web1:<server group>`, `sessions/` `0700 web1:web1`, see
below), `open_basedir` at the project directory
plus those two (`upload_tmp_dir` and `sys_temp_dir` at `<state_dir>/<user>/tmp`,
`session.save_path` at `<state_dir>/<user>/sessions`, both created by `agensio pools` as
the user and listed in `open_basedir`, so PHP's uploads and temp files land in the user's
private space and never in `/tmp`. `tmp/` is `2750 <user>:<server group>`, like the
document root: an uploaded file is created there, so it is born with the server's group,
and `move_uploaded_file()` renames it into the document root with that group kept, where
the server can read it; a set-gid document root alone would not do that, since rename
keeps a file's group (2026-09-20: every upload was `0640 user:user` and answered 404).
`sessions/` stays `0700 <user>:<user>`, nothing leaves it. `agensio pools` repairs a
`tmp/` from an earlier layout when run as root; files uploaded before that need `chgrp
-R <server group>` on the application's upload directory, and `health` reports them
as `files_unreadable` until then, with `php_tmp_missing` when the directory is gone), `memory_limit`, `max_execution_time`, upload limits from
`max_body_size`, `clear_env`, `expose_php = off`. `agensio -t --explain` prints the
whole file. agensio's own FastCGI options for a generated pool default to
`keep_conn = true` with `max_connections = children / workers`, so kept connections can
never pin every child (section 7).

Pool keys in `php = { ... }`, all optional:

| key | default | meaning |
|---|---|---|
| `children` | 8 | `pm.max_children` |
| `pm` | `"ondemand"` | `"ondemand"`: a child starts on the first request and exits after 60 s idle, nothing resident while the site is quiet; `"dynamic"`: half the children on standby; `"static"`: every child resident, predictable, what a PHP benchmark should use |
| `max_requests` | 500 | `pm.max_requests`; 0 = unlimited |
| `memory_limit` | `"256M"` | `memory_limit` |
| `max_execution_time` | 60 | seconds |
| `max_input_time` | 60 | seconds, how long a request body may take to arrive |
| `version` | newest installed | php version whose pool directory `agensio pools` writes to |
| `open_basedir` | project, tmp, sessions | replaces the default list |
| `extra` | none | `{ "date.timezone" = "Europe/Athens" }` becomes `php_admin_value[...]` lines |

**Why `ondemand` is the default** (2026-09-21, a live host): with `static`, every site
with its own account kept its 8 children resident around the clock, 15 to 25 MB of
private memory each on top of the shared PHP image, about 150 to 200 MB per idle site,
and a 4 GB machine ran out at 15 to 20 sites before serving anything. `ondemand` costs a
fork on the first request after a quiet minute (tens of milliseconds) and starts
children up to `children` under a burst; agensio writes `pm.process_idle_timeout =
60s` and closes its own kept connections after `idle_timeout` (30 s, section 7) so the
children are free to exit. Set `pm = "static"` on a site that must not pay that first
fork, and in a development environment when measuring PHP throughput: the benchmark beds
under `bench/` use static pools, and a comparison against nginx in front of an
`ondemand` pool would measure php-fpm's forking. `health` names every `static` or
`dynamic` pool with the PHP processes it keeps and their memory (`php_pool_resident`),
so the cost is visible before the machine is full. The verdict comes from the pool file
php-fpm runs, not from the configuration: a pool whose file still says `static` after the
configuration changed to `ondemand` is named as a warning until `agensio pools` and a
php-fpm reload (2026-09-23: two such pools held 681 MB while the finding stayed silent).

A site's own `max_body_size = "200MB"` (a site key, next to `root`) bounds its request
bodies (413 above) and sets the pool's `upload_max_filesize` and `post_max_size`; without
it the site takes `[server] max_body_size`. The keys `children`, `pm`, `max_requests`,
`memory_limit`, `max_execution_time`, `max_input_time` and the site's `max_body_size` are
also settable through the control plane (`site-create` / `site-update` with `settings`,
section 15), within the ceilings `[control] site_limits` sets. `open_basedir` and `extra`
are not: they change what a site may reach or run, and stay in this file, root's.

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
- a secret is readable by other users: the preset's credential files (`presets` lists
  them under `secrets`: `wp-config.php` for WordPress; `settings.php`,
  `settings.local.php` and `services.yml` for Drupal), `.env` and `.git` under the root,
  and for Laravel the project's `.env`, `config/`, `storage/` and `.git` (make them
  `0600`, or `0640 user:<the site's own group>`; `site-install` and `site-copy` create
  them `0600`, the same list, so what they write always passes);
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
| `keep_conn`, `max_idle`, `idle_timeout` | `true`, 64, 30 s | keep-alive to the origin; idle connections kept per worker; how long one may stay idle before agensio closes it (0 = until the origin does) |
| `max_connections`, `queue_depth`, `queue_wait` | 256, 1024, 5 s | per worker: in flight, waiting, and the longest wait before a 503 with `Retry-After` |
| `head_max` | 64 KB | an origin head larger than this is a 502 |
| `max_fails`, `fail_timeout` | 3, 10 s | consecutive failures that mark a group member down, and for how long |
| `tls` | verify on, system store | `{ verify, server_name, ca }` for `https://` origins |

The pool is per worker, so an origin sees at most workers x `max_connections` connections
and workers x `max_idle` idle ones, none of them idle for longer than `idle_timeout`
(the pool's 250 ms tick closes them, so an origin with a shorter keep-alive timeout, Node's
5 s, should get `idle_timeout` below it). Before a kept connection that has been idle for longer
than a pool tick (250 ms) is reused it is peeked once without blocking: a peer that closed it (php-fpm reloaded, an origin's idle timeout)
is dropped for a fresh connection, so a POST or an upload never meets a dead one. A GET or HEAD whose kept connection turns out dead is
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
provision = true                       # the root helper: accounts, layout, pools, restart, installs on request (false: commands are handed back)
install = true                         # site-install may download from https URLs (false: only uploaded archives are installed)
install_private = false                # true: site-install may fetch from loopback, private and link-local addresses (internal mirrors, test beds)
install_ca = "/etc/ssl/mirror-ca.pem"  # PEM bundle site-install trusts instead of the system store (private mirrors); default: the system store
upload_max = "512M"                    # the largest archive `agensio ctl upload` may store
site_limits = { max_body_size = "512MB", memory_limit = "512M", max_execution_time = 300, max_input_time = 300, children = 32, max_requests = 1000000 }
                                       # the ceilings site-create / site-update may raise a site's limits to (these are the defaults)
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
| `site NAME` | viewer | one site in full (`handler` is `deny` for a path answered 404 whatever exists, and a location lists the endings it `refuses`): the above plus index, php socket and generated pool, upstreams, and every location after the preset expanded (path, match, handler, root/alias, upstream, added headers, which preset added it) |
| `presets` | viewer | the application presets: for each `app` value the served root, whether every `.php` runs or only the front controller, refused suffixes, directories that never run PHP, files never served, `secrets` (the credential files among them: what the hosting rules check and every write path creates `0600`), and `source`, the official archive `site-install` takes when the preset has one |
| `validate` | viewer | loads the file on disk again and runs the hosting rules: `ok`, `errors`, site count, and the restart-only settings that differ from the running server |
| `logs` | viewer | `--site NAME` (default: all sites plus the error log), `--since 3h` (`m`, `h`, `d`, `w`, seconds, or a local `YYYY-MM-DDThh:mm:ss`; default 1h), `--level error|warn|info` for the error log (default warn = error+warn), `--status 5xx|4xx|all|NNN` for access logs (default 5xx), `--limit N` (default 200, newest). Reads at most 2 MB per file from the end; `truncated` says when that cut in |
| `uploads` | viewer | the archives stored with `upload` (`file`, `bytes`, `uploaded`), ready for `site-install --file` |
| `settings [NAME]` | viewer | the per-site limits `site-create` and `site-update` accept under `settings`: for each key its type, unit and spellings, meaning, default and its origin, minimum, the ceiling from `[control] site_limits`, what changing it costs (agensio reload, php-fpm reload) and what it derives; with a site, the current value and whether it comes from the site, the server or a built-in default. `site NAME` reports the same `settings` |
| `health` | viewer | findings with `severity`, `code`, `site`, `message`, `fix` (also `files_unreadable`: files under a document root, the preset's upload directory first, that the server's account cannot open and that answer 404 with no log line; `php_tmp_missing`; `php_fpm_hard_reload`; `php_pool_resident`, judged from the pool file php-fpm runs; `preset_mismatch`: the files under a site's directory belong to another application than its `app` says, with the application detected and the `app` to set; `archives_in_root`: backup archives and database dumps under a served tree, the directories a preset never answers excepted): configuration on disk invalid or failing the hosting rules, restart-only settings changed, running as root, certificate unreadable / still the placeholder / expired / expiring within 14 days (manual), `tls = "auto"` without a plain port-80 site for the names, no http-to-https redirect, application sites sharing the server's account, generated pools out of date, errors in the last 24 hours. `ok` is true when nothing above info level was found |

**Changes** (`POST` with a JSON body; every one needs `"confirm": true`, takes a
`"reason"` that goes to the audit log, and answers 428 without the confirmation):

| command | role | what it does |
|---|---|---|
| `reload` | operator | the same as `agensio reload`: validate the file on disk, bind, switch; 409 with the reason when refused, nothing changed then |
| `logs-reopen` | operator | reopen every log file (what `SIGUSR1` does) |
| `site-create` | admin | writes `sites.d/<domain>.toml`, validates, reloads. Fields: `domain`, `aliases`, `https` (`auto`, `none`, or `{cert, key}`), `redirect_http` (default true), `hsts`, `user` (an account name; `no_user: true` or JSON `null` for none; the words null, none, nil and system accounts are refused, never turned into commands), `group`, `app`, `root`, `upstream`, `php_socket`, `php_children`, `php_version`, `listen_plain`, `listen_tls`. Until `https`, `root` (or `upstream`), `app` and `user` are decided it answers 422 with the open questions and a suggestion each (a user name from the domain, the app the files under root suggest); when the account or the root directory does not exist it answers 409 with the commands to run as root and waits for the same command again. A new site is HTTPS-only: the plain site redirects. |
| `site-create` answers | | 422 with `needs` while decisions are open; 409 `prerequisites missing` with `problems` (every one at once, each with a `code`, a `detail` and its `run_as_root` command: `missing_account`, `missing_group`, `root_missing`, `root_unreadable`, `certificate_missing`) plus the flat `run_as_root` list; 202 `needs_restart` when the site adds a privileged port the dropped server cannot bind by a reload (the file is written and valid, `systemctl restart agensio` serves it); 201 with `next_steps` (separate commands: `agensio pools`, then the php-fpm reload) and `warnings`. `dry_run: true` runs every check and returns the file that would be written without writing or reloading |
| `site-update NAME` | admin | the same fields on a site `site-create` wrote (the file carries its spec on its first line); a hand-written file is refused with 409, edit it yourself. `settings = {key: value}` (CLI `--set KEY=VALUE`, repeatable) sets the per-site limits: `max_body_size` (any site), and for a site with its own user `memory_limit`, `max_execution_time`, `max_input_time`, `children`, `pm`, `max_requests`. Each value is checked against `[control] site_limits` and refused above it naming the key, the value and the ceiling; a key outside that list (`extra`, `open_basedir`, any ini name) is refused as unknown, whatever it is. The answer's `done` lists what was written and reloaded: the site file and agensio, and the php-fpm pool and php-fpm when a pool key changed (a php-fpm reload briefly affects every PHP site unless `process_control_timeout` is set) |
| `site-disable NAME`, `site-enable NAME` | admin | renames the file to `.disabled` and back, reloads |
| `site-delete NAME` | admin | removes the file (a `.bak` stays), reloads; never touches the root or the account |
| `cert-renew NAME` | operator | orders the site's automatic certificate again now |
| `upload NAME [FILE]` | operator | stores FILE (stdin by default) as `<state_dir>/uploads/NAME`, the server's own directory (0700); `PUT /v1/uploads/NAME` with the raw bytes on the socket; no `--yes`; at most `upload_max`; names are plain file names (letters, digits, `.`, `_`, `-`, no leading dot); a partial transfer leaves nothing |
| `uploads-delete NAME` | operator | removes a stored upload |
| `site-install NAME` | admin | puts an application's files into the site's directory (the `root` as given, above a preset's `public/` or `web/`; `--path SUB` for a subdirectory such as `wp-content/plugins/NAME`, with `--create-path` when it does not exist yet) **as the site's account**, from one source: `--url https://...` (a `.tar.gz`, `.tar` or `.zip`), `--file UPLOAD` (a stored upload), or nothing, which takes the preset's official archive (`presets` lists it under `source`; `--version V` picks a release, default the newest; WordPress and Drupal have one, Laravel is made with composer). `--sha256 HEX` refuses an archive whose digest differs. `--strip 0|1` keeps or unwraps a single top directory (default: unwrap when there is exactly one). `--dry-run` takes the same walk as the real call, as the same account, and answers with the target, the account and `would_create`, or with the refusal the real call would meet; nothing is downloaded or written. Answers 201 with `files`, `bytes`, `sha256`, `unwrapped`, `created` (each directory made, with owner and mode), `next_steps`; 409 with the reason and nothing left behind; 403 when `install = false` and a URL was given; 422 when no source can be found |

| `site-copy NAME --from SUB --to SUB` | admin | copies one regular file of the site to another path of the same site **as the site's account**: the drop-in files applications ship as templates (`wp-content/db.php` from the SQLite plugin's `db.copy`, `advanced-cache.php` or `object-cache.php` from a caching plugin, Drupal's `sites/default/settings.php` from `default.settings.php`). Both paths are relative to the site's directory and reached by the same walk as an install; `from` must be an existing regular file (no directory, no symlink); the destination's directory must exist (`site-install --create-path` makes one); an existing destination is refused unless `--overwrite`, and the answer then reports the replaced file's size and mtime. The new file gets the directory's pattern (`0640` in a `2750` directory, the execute bits when the source has them), or `0600` when it is one of the preset's credential files (`secured: true`); written under a temporary name and linked or renamed into place, so a refusal leaves nothing; the configuration is validated afterwards (see below). Never across sites, never content from the caller, never a directory, no chmod or chown. `--dry-run` runs the same checks. Answers 201 (200 when replaced) with `from`, `to`, `as`, `bytes`, `mode`, `replaced`; 409 with the reason |

**What `site-install` enforces.** The account that installs is the site's `user`, or for
a site without one the owner of the site's directory, which must be a site account
(`nologin`, home in the state directory) or the server's own account; root, a login
account and another site's account are refused, so an install can never write as anyone
else. The target is the site's directory or `--path` below it (normalised, `..` refused),
reached by a walk that opens every component without following symlinks and requires
each existing one to belong to that account. The leaf must be empty: a whole application
goes into the fresh site directory, a plugin or theme into its own new directory. A
missing directory is refused unless `--create-path` is given, which creates the missing
levels as the account with the parent's permission bits (the set-gid bit and group come
down from the parent, as for extracted files); an existing directory is never emptied.
A refusal at any point, a symlink on the way, another account's directory, a bad
archive, a wrong digest, removes every directory the call created, so the tree is as it
was.

**Credential files and validation.** A site directory is `2750` with the server's group,
so everything created under it is readable by the server, which is what serving needs
and exactly what hosting rule 3 forbids for a credential file. The two are reconciled by
the preset table: each preset names its `secrets` (`wp-config.php`; Drupal's
`settings.php`, `settings.local.php`, `services.yml`; `presets` shows them), the hosting
rule checks precisely those files plus `.env` and `.git` (Laravel: the project's `.env`,
`config/`, `storage/`), and `site-install` and `site-copy` create precisely those files
`0600` whatever the directory's pattern gives the rest, listing them under `secured`.
Each call then checks the hosting rule on what it wrote and validates the whole
configuration before answering: when the result would be refused by `agensio -t`, the
answer is `409` with `written: true` and the validator's `errors`, never a bare ok. A
file the application writes itself (WordPress's own setup writing `wp-config.php`)
follows php-fpm's umask, not agensio's; `health` reports it as `hosting_rule` with the
fix.

**php-fpm reloads.** Writing a pool (`site-create` with a user, `agensio pools`) reloads
php-fpm. Unless the global `php-fpm.conf` sets `process_control_timeout` (php-fpm's
default is 0), the master kills its children at once and every PHP request in flight on
every site of that php-fpm answers 502. `health` reports `php_fpm_hard_reload` with the
one-line fix (`process_control_timeout = 10s`), and `site-create`'s `done` entry says
the reload happened. Downloads are `https://` only, with the
certificate and host name verified (the system store, or `install_ca`); every address of
every hop, redirects included, is checked against the private-address fence (loopback,
link-local, RFC 1918, ULA, shared 100.64/10, multicast, the IPv4-mapped forms) unless
`install_private = true`; at most 5 redirects, 1 GB, 15 minutes. Archives are unpacked by
agensio's own extractor: an entry that is a symbolic link, hard link, device or fifo, an
absolute path, a `..` segment, a backslash, a control character, an encrypted or zip64
entry, a tar checksum or zip CRC that does not match, more than 200 000 entries or 4 GB,
each ends the install with the reason, and the directory is emptied again. Files are
created `O_EXCL | O_NOFOLLOW`, never through a symlink, with modes derived from the
directory's own (a `2750` site directory gets `0640` files and `2750` directories; a
`0755` one gets `0644` and `0755`); set-uid bits are never kept. A download is written
to an unlinked temporary file inside the target and is gone with the process. The audit
log carries the source and the sha256 of what was installed.

A change that does not validate is undone before the answer: the file is removed or the
previous one restored, and the old configuration keeps serving.

**Root work.** With `provision = true` (the default) a server started as root forks a
small helper before it drops privileges. It holds the other end of a socketpair, never a
path, and does six things and nothing else: create a site account (`useradd --system`,
`nologin`, home in the state directory), lay out a site's directories under `sites_root`
(`owner:<server group> 2750`, walked without following symlinks, refused when a directory
belongs to another site), hand a per-site log to the site's group, write the php-fpm
pools and reload php-fpm, restart the service after a change that needs one, and run a
`site-install` in a child that has become the site's account (the helper opens an
upload as root, the child drops to the account before reading a byte). Programs
run by absolute path with a fixed argument list and no shell; every argument is checked
again inside the helper with the same rules; every action is audited. `site-create` then
does the whole job in one call and lists what it did under `done`. With `provision =
false`, or a server not started as root, what needs root comes back as commands, as
before, and `site-install` runs on a thread of the server as its own account, so it can
only fill directories that account owns. `docs/security-control-plane.md` states what a
compromised server could and could not do through the helper.

Unknown commands answer a JSON 404, a wrong method a 405 with `Allow`, a role that is too
low a 403 naming the role needed. `curl --unix-socket /run/agensio/control.sock
http://control/v1/status` is the same call by hand.

`agensio mcp` exposes the same commands to an AI agent host as Model Context Protocol
tools, locally or over SSH: see `docs/mcp.md`.

`agensio -t` on a shared host warns when a php-fpm pool, proxy origin or CGI location
runs as the server's own user or as a member of the admin group: with everything under
one account the peer-credential check cannot tell sites apart. Per-site users (section
11) are what makes the control socket safe on a shared host.

## 16. HTTP/2

HTTP/2 (RFC 9113) is on for every TLS listener: a client that offers `h2` through ALPN
gets it, any other client gets HTTP/1.1 on the same port. Nothing is configured per
site, and every HTTP/2 limit derives from keys you already know. The design, the
comparison with nginx, Caddy, lighttpd and HAProxy, and the threat model are in
`docs/design-http2.md`.

```toml
[server]
protocols = ["h2", "h1"]          # the default; order = ALPN preference
# protocols = ["h1"]              # HTTP/2 off, for instance during an incident
# protocols = ["h2c", "h2", "h1"] # also accept prior-knowledge HTTP/2 on plain listeners
http2 = { max_concurrent_streams = 128 }
```

| key | default | meaning |
|---|---|---|
| `protocols` | `["h2", "h1"]` | what TLS listeners offer through ALPN, in order of preference (Caddy's names; `"http/1.1"`, the ALPN identifier, is accepted for `"h1"`). `"h2c"` in the list makes plain listeners accept HTTP/2 with prior knowledge (the connection preface; `curl --http2-prior-knowledge`, `h2load`, a backend behind a proxy). Browsers never use h2c, so it is off by default. `"h3"` arrives with phase I. |
| `http2.max_concurrent_streams` | 128 | streams a client may have open at once on one connection (`SETTINGS_MAX_CONCURRENT_STREAMS`, nginx's default); a stream beyond it is refused, the connection stays |

What derives from the other keys, so that HTTP/2 needs no tuning of its own:

| HTTP/2 limit | comes from | value at the defaults |
|---|---|---|
| `SETTINGS_MAX_HEADER_LIST_SIZE`, the decoded size of a request's fields, and the size of a compressed header block | `max_header_size` | 16 KB each; a block over either closes the connection (`ENHANCE_YOUR_CALM`), a peer doing that is not a browser |
| streams on one connection before `GOAWAY` | `max_requests_per_connection` | 1000, like a keep-alive connection's requests |
| a connection with no stream open, or a stream whose head or response makes no progress | `idle_timeout` | 15 s |
| a body announced but not arriving | `body_timeout` | 60 s |
| the request-body limit and the size of the receive windows | `max_body_size`, or the site's own | 1 MB per stream and per connection at most, so an upload runs at the pace of the disk or the origin rather than 64 KB per round trip |
| `SETTINGS_MAX_FRAME_SIZE`, `SETTINGS_HEADER_TABLE_SIZE` | fixed | 16 KB, 4 KB |

Two counters per connection close it when a client misbehaves, whatever the shape of the
attack (Rapid Reset, MadeYouReset, CONTINUATION floods, PING and SETTINGS floods, empty
frames, window-update dribbles, HPACK bombs; the list is in the design document): 100
protocol glitches (a `GOAWAY` is sent at 75 so a slightly broken client can reconnect and
carry on), and 128 streams cancelled before a response within one second, by either
side. Every `GOAWAY` and `RST_STREAM` the server sends is one line in the error log at
level info with the client address, the stream id, the error code and the reason.

Requests over HTTP/2 are logged as `"GET /path HTTP/2.0"` (`"proto":"HTTP/2.0"` in JSON),
and PHP sees `SERVER_PROTOCOL=HTTP/2.0`. `agensio ctl status` names the protocols of each
listener. Server push is not implemented (browsers removed it), nor the RFC 7540
priority tree (deprecated; PRIORITY frames are ignored), nor `Upgrade: h2c`.
