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
larger ones streamed with sendfile, access log on (see section 8).

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

[[site.location]]        # Vite output is content-hashed: cache it for a year
path = "/build/"
try_files = ["$uri", "=404"]
add_headers = { "Cache-Control" = "public, max-age=31536000, immutable" }
```

Why it is shaped like this: a request for `/anything.php` does not execute that file, it
falls through `try_files` to `/index.php` and Laravel's router answers, so a stray or
uploaded `.php` file under `public/` is never a code-execution path. Dotfiles (`.env`)
stay hidden by the site default. `public/storage` is a symlink into the project, which is
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
there. `wp-config.php` is under the root and would be executed by PHP (it prints
nothing), exactly as with nginx; `.htaccess` and `.user.ini` are dotfiles and hidden.

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
| `deny_suffixes` | endings answered with 403, e.g. `[".php"]` under an uploads directory |
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
| `keep_conn` | `false` | FastCGI keep-alive; php-fpm pins a child per idle connection, so enable only with a pool sized for it |
| `head_max` | `"64KB"` | reply head larger than this is 502 |
| `path_info` | `true` | split `/x.php/extra` into SCRIPT_NAME and PATH_INFO |

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

## 11. TLS

```toml
[[site]]
server_name = ["example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example"
tls = { cert = "/etc/ssl/example/fullchain.pem", key = "/etc/ssl/example/privkey.pem" }
```

A listen address is either plain or TLS for every site on it. Automatic certificates come
with phase H of the roadmap.
