# PHP applications

Recipes for sites that run PHP: an application preset on an account of its own, an application
without a preset, a php-fpm pool you run yourself or in a container, larger limits, streamed
output, and changes to what a preset does. A preset decides which `.php` files run and what is
never served; `agensio -t --explain` prints what it expands to and `agensio ctl path-check` says
what one path meets, so every rule here can be seen before a visitor meets it. The
[cookbook's index](../examples.md) says how a recipe is laid out and how to apply one.

## WordPress on its own account

**When:** a WordPress site on a host that runs more than one site, or one you want kept apart
from the server: its PHP runs as an account of its own, which owns the site's files and reads
nothing of the others.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
user = "agensio"                          # the packaged file has it; its group is the one that may connect to the pools
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/blog.example.com.toml
[[site]]
server_name = ["blog.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/blog.example.com/web"
app = "wordpress"
user = "blog"                    # PHP runs as blog, in a php-fpm pool agensio writes
tls = "auto"
max_body_size = "64MB"           # media uploads: 413 above it; also the pool's upload_max_filesize and post_max_size
```

**What it does.** `user` gives the site a php-fpm pool of its own, which `agensio pools`
writes: PHP runs as `blog` and listens on `/run/php/agensio-blog.sock` (`0660`, `blog` and the
server's group, so only agensio connects), starts children on demand (8 at most, none kept while
the site is quiet) and keeps uploads in progress, temporary files and sessions under
`/var/lib/agensio/blog/`, with `open_basedir` at the site's directory and those two. The preset
decides what runs: any `.php` (`wp-login.php`, `wp-admin/`, `wp-cron.php`, plugin endpoints),
and a path without a file reaches `/index.php` (permalinks). Nothing under
`wp-content/uploads/` or `wp-includes/` ever runs or is sent as source, in any spelling
(`x.PHP`, `x.phtml`, `x.php~`), and both are cached (7 and 30 days). `wp-admin/includes/`,
`wp-includes/theme-compat/`, `wp-config.php`, `readme.html`, `license.txt` and the `wp-content`
drop-ins (`db.php`, `advanced-cache.php`, `object-cache.php`) answer 404, and so does every
backup of those names (`wp-config.php.bak`, `wp-config.php~`, `.wp-config.php.swp`).

What is easy to get wrong: until `agensio pools` has written the pool and php-fpm has reloaded,
every PHP request answers 502 and `-t` warns that the socket is missing. `agensio pools` exits
with 3 when it changed a file, so do not chain the reload behind it with `&&`. A php-fpm reload
stops the PHP requests in flight on every site unless php-fpm's `process_control_timeout` is set
(health reports `php_fpm_hard_reload`). The site's directory must be `blog`'s with the server's
group (`2750`; `-t` prints the `chown` and `chmod`), and `wp-config.php` must be readable by
nobody else: WordPress's installer writes it with php-fpm's umask, and `agensio -t`, so every
reload, refuses the configuration while it is open to others, naming the file. Make it `0600`
(or `0640` with the site's own group).

**Check it.**

```sh
agensio -t --explain -c /etc/agensio/agensio.toml | less      # the pool file and every location the preset adds
agensio pools -c /etc/agensio/agensio.toml                    # writes agensio-blog.conf; exit 3 when something changed
systemctl reload php8.4-fpm
agensio ctl path-check blog.example.com /wp-content/uploads/2026/10/shell.php   # 404: nothing under uploads runs
agensio ctl path-check blog.example.com /wp-login.php                           # runs the script
curl -sI https://blog.example.com/wp-config.php.bak | head -1                   # 404
```

**On a managed site.** With the provisioning helper (the default when agensio starts as root)
`site-create` makes the account, the directory and the pool and reloads php-fpm itself, and
lists what it did under `done`; without it the answer lists the commands for root. `site-install`
with no source takes WordPress's official archive and unpacks it as `blog`:

```sh
agensio ctl site-create --domain blog.example.com --https auto --user blog --app wordpress --root /var/www/blog.example.com/web --set max_body_size=64MB --yes --reason "new blog"
agensio ctl site-install blog.example.com --yes --reason "WordPress from wordpress.org"
```

**MCP:** `site_create` with `domain`, `https`, `user`, `app`, `root` and `settings`, then
`site_install`; `path_check` on the paths above afterwards.

**Reference:** [WordPress](../configuration.md#4-wordpress-app--wordpress),
[Hosting: one user per site](../configuration.md#11-hosting-one-user-per-site).

## Laravel

**When:** a Laravel or Statamic application, deployed as its project directory (`artisan`,
`.env`, `vendor/`, `public/`).

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/crm.example.com.toml
[[site]]
server_name = ["crm.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/crm.example.com/project"   # the project, not its public/: the preset serves public/
app = "laravel"
user = "crm"
tls = "auto"
```

**What it does.** agensio serves the project's `public/`. A request for a file there gets the
file; anything else reaches `/index.php` with its query string, the one script that ever runs.
Any other `.php` under `public/`, existing or not, answers 404 before anything is read from disk,
so a stray `info.php` or an uploaded script is neither run nor sent as source. `/build/`, Vite's
hashed output, is cached for a year (`immutable`). Dotfiles answer 404. `public/storage` is a
symlink into the project, which is why symlinks are followed by default; on a project without
it, `symlinks = "deny"` refuses any file whose real path leaves `public/`. PHP's
`open_basedir` is the whole project, so the application reaches `storage/` and `vendor/`.

What is easy to get wrong: `root` pointing at `public/` itself is refused (`-t` looks for
`public/public`). With `user`, `agensio -t` and every reload refuse the configuration while the
project's `.env`, `config/`, `storage/` or `.git` can be read by other users or by the server's
group, naming each: a deployment into the site's `2750` directory usually leaves them readable
by the server's group, so make the files `0600` and the directories `2710` (the server may pass through `storage/` to
the `public/storage` link's target, never list it). An application with several entry points
is not Laravel: run it under `app = "php"` with its own rules (below). Statamic needs nothing
else: its control panel at `/cp` goes through `/index.php`; raise `max_body_size` for asset
uploads.

**Check it.**

```sh
agensio ctl path-check crm.example.com /info.php          # 404: only /index.php runs
agensio ctl path-check crm.example.com /customers/12      # runs /index.php
curl -sI https://crm.example.com/build/assets/app-4f3a9c.js | grep -i cache-control
```

**On a managed site.** Laravel has no official archive: deploy the project into the directory
as the site's account, or upload an archive of it (`agensio ctl upload`) and install that:

```sh
agensio ctl site-create --domain crm.example.com --https auto --user crm --app laravel --root /var/www/crm.example.com/project --yes --reason "CRM"
agensio ctl site-install crm.example.com --file crm-release.tar.gz --yes --reason "CRM release"
```

**MCP:** `site_create` with `app` set to `laravel` and `root` the project, then `site_install`
with `file` (the user runs `agensio ctl upload` for it; the bridge carries no files).

**Reference:** [Laravel](../configuration.md#3-laravel-app--laravel),
[Hosting: one user per site](../configuration.md#11-hosting-one-user-per-site).

## Drupal

**When:** Drupal 10 or 11, from a composer project (with `web/` inside) or from the release
archive.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/magazine.example.com.toml
[[site]]
server_name = ["magazine.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/magazine.example.com/project"   # a composer project's web/ is served when it holds index.php; a release archive as it is
app = "drupal"
user = "magazine"
tls = "auto"
```

**What it does.** PHP runs where Drupal's own `.htaccess` lets it: a script directly in the web
root (`index.php`, `update.php`), a script directly in `core/` (`install.php`, `authorize.php`,
`rebuild.php`), and `core/modules/statistics/statistics.php`. Every other `.php`, a module's, a
theme's, one a plugin left behind, and `autoload.php` answer 404 and never reach php-fpm. A path
without a file reaches `/index.php` (`/node/1`), also below `sites/default/files/`, where Drupal
makes image styles and aggregated CSS and JS on the first request; a file that exists there is
served, and nothing PHP-like there ever runs. agensio never reads `.htaccess`, so what Drupal's
refuses under Apache is refused natively: `settings.php`, `services.yml`, the composer and
package files, templates (`.twig`), module source (`.module`, `.inc`, `.install`), `.yml`,
dumps, SQLite files and editor backups. `settings.php`, `settings.local.php` and `services.yml`
are the site's secrets: with `user`, `-t` refuses them while others can read them.

What is easy to get wrong: a module whose documentation asks for a script of its own to be
reachable gets nothing by default; give that one script an exact location (`match = "exact"`,
`handler = "fastcgi"`), in the root additions file on a managed site. The admin is open to
everyone until you restrict it ([protection](protection.md#keep-the-wordpress-admin-to-the-office),
`--restrict-admin` works on Drupal too).

**Check it.**

```sh
agensio ctl path-check magazine.example.com /core/install.php                                    # runs the script
agensio ctl path-check magazine.example.com /core/lib/Drupal.php                                 # 404
agensio ctl path-check magazine.example.com /sites/default/files/styles/thumbnail/public/a.jpg   # runs /index.php while the file is missing
```

**On a managed site.** `site-install` takes the release archive from drupal.org; Drupal's
installer then wants `sites/default/settings.php`, which `site-copy` makes from the template as
the site's account, `0600`:

```sh
agensio ctl site-create --domain magazine.example.com --https auto --user magazine --app drupal --root /var/www/magazine.example.com/project --yes --reason "magazine"
agensio ctl site-install magazine.example.com --yes --reason "Drupal from drupal.org"
agensio ctl site-copy magazine.example.com --from sites/default/default.settings.php --to sites/default/settings.php --yes --reason "the installer needs settings.php"
```

**MCP:** `site_create`, `site_install`, then `site_copy` with `from` and `to`.

**Reference:** [Drupal](../configuration.md#4c-drupal-app--drupal),
[Control socket](../configuration.md#15-control-socket) (`site-install`, `site-copy`, root additions).

## Grav

**When:** a Grav site, the admin plugin included.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/docs.example.com.toml
[[site]]
server_name = ["docs.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/docs.example.com/web"   # the Grav directory itself: index.php, system/, user/
app = "grav"
user = "docs"
tls = "auto"
```

**What it does.** Only `/index.php` runs, and every page route reaches it, `/admin` included.
Grav's private directories answer 404 whatever they hold: `logs/`, `backup/` (a backup archive
there is the whole site, accounts and salt included), `cache/`, `bin/`, `tests/`, `tmp/`,
`webserver-configs/`, `user/config/` and `user/env/`. Below `system/`, `vendor/` and `user/`
only assets are served, never `.yaml`, `.md`, `.json`, `.twig` or scripts; `user/accounts/`
answers avatar images and nothing else, `user/data/` public media and nothing else. `images/`
and `assets/` never serve a script, and a file missing there reaches Grav, which makes it. The
release's `LICENSE.txt`, `README.md`, `CHANGELOG.md` and composer files answer 404, and
`user/config/security.yaml` (the signing salt) in every backup spelling.

What is easy to get wrong: the preset must be the application's. A Grav site run under another
preset gets that preset's refusals and none of Grav's, so `logs/` and `backup/` are served;
`agensio ctl health` reports such a site as `preset_mismatch`, with the `app` to set.

**Check it.**

```sh
agensio ctl path-check docs.example.com /user/config/system.yaml          # 404, whatever exists
agensio ctl path-check docs.example.com /user/pages/01.home/default.md    # 404: pages are not files to fetch
agensio ctl path-check docs.example.com /admin                            # runs /index.php
```

**On a managed site.** `site-install` takes the newest `grav-admin` release from getgrav.org,
or the one `--version` names:

```sh
agensio ctl site-create --domain docs.example.com --https auto --user docs --app grav --root /var/www/docs.example.com/web --yes --reason "docs site"
agensio ctl site-install docs.example.com --version 1.7.48 --yes --reason "Grav with the admin plugin"
```

**MCP:** `site_create`, then `site_install` with `version`; `health_check` reports a preset that
does not match the files.

**Reference:** [Grav](../configuration.md#4d-grav-app--grav).

## A PHP application without a preset, from its own rules

**When:** an application with no preset of its own (`agensio ctl presets` lists the presets):
Kanboard, phpBB, TYPO3, Nextcloud. Its documentation publishes an nginx or Apache
configuration, or it ships `.htaccess` files, saying which scripts run and what is never
served. Kanboard here: it runs `index.php`, `jsonrpc.php` and `healthcheck.php`, routes nice
URLs to `index.php`, and its own files say to deny `app/` and `data/`.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/tasks.example.com.toml
[[site]]
server_name = ["tasks.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/tasks.example.com/web"
app = "php"
user = "tasks"
tls = "auto"
try_files = ["$uri", "$uri/", "/index.php?$query_string"]   # nice URLs reach the front controller
refuse = ["/app/", "/data/", "/libs/", "/vendor/", "/tests/", "/cli",
          "/composer.json", "/ChangeLog", "/Makefile", "/Dockerfile"]

[[site.location]]            # the scripts the application runs, and only these
path = "/index.php"
match = "exact"
handler = "fastcgi"

[[site.location]]
path = "/jsonrpc.php"
match = "exact"
handler = "fastcgi"

[[site.location]]
path = "/healthcheck.php"
match = "exact"
handler = "fastcgi"

[[site.location]]            # replaces the preset's .php location: any other .php is 404, never run, never sent as source
path = ".php"
match = "suffix"
handler = "deny"

[[site.location]]            # static assets: cached a week, nothing runs or is served as source here
path = "/assets/"
final = true
deny_suffixes = [".php", ".phtml", ".phar", ".inc", ".bak", "~", ".log", ".sql", ".sqlite", ".db"]
add_headers = { "Cache-Control" = "public, max-age=604800" }
```

**What it does.** The bare `php` preset runs every `.php` under the root, the application's
internals included (`/app/Core/Base.php`), and refuses its database files only by their ending.
The site narrows that to the application's rules: three exact locations run, a suffix location
with the preset's path and match replaces the preset's, so every other `.php` anywhere (a
plugin's under `plugins/` too) answers 404, and a path without a file goes to `/index.php`
(`/login`, `/board/1`). The `refuse` patterns answer 404 before any location is chosen, on every
internal redirect and on a directory's index too, so no location can step around them.

What is easy to get wrong: translate the rules of the version you run, and read regexes
closely: nginx's `location ~ ^vendor` refuses nothing as written (a path always starts with
`/`), the intent is `/vendor/`. A pattern that would refuse the site's index or its front
controller is refused by `-t` with both names. agensio never reads the application's
`.htaccess` files when serving; `site-install` names the directories they deny whole, for you
to add.

**Check it.**

```sh
agensio ctl path-check tasks.example.com /app/Core/Base.php     # 404, names the pattern
agensio ctl path-check tasks.example.com /plugins/X/Plugin.php  # 404, the .php location that denies
agensio ctl path-check tasks.example.com /login                 # runs /index.php
agensio ctl path-check tasks.example.com /assets/css/app.css    # the file, cached a week
```

**On a managed site.** The same as the site's `rules`, which the control plane renders into the
locations above (`--private PATH` is the other way to say a path is never served: a
`handler = "deny"` location instead of a pattern). Try it with `--dry-run` first, which shows
the file it would write:

```sh
agensio ctl site-update tasks.example.com --entry-point /index.php --entry-point /jsonrpc.php --entry-point /healthcheck.php --front-controller /index.php --cache /assets/=604800 --refuse /app/ --refuse /data/ --refuse /libs/ --refuse /vendor/ --refuse /tests/ --refuse /cli --refuse /composer.json --dry-run --yes --reason "Kanboard's own rules"
```

**MCP:** `site_update` with `rules` = `{"entry_points": ["/index.php", "/jsonrpc.php",
"/healthcheck.php"], "front_controller": "/index.php", "cache": [{"path": "/assets/",
"max_age": 604800}], "refuse": ["/app/", "/data/", ...]}` and `dry_run` first; `path_check` on
one path each rule must refuse and on the paths that must still work, before and after.

**Reference:** [Plain PHP](../configuration.md#2-plain-php-app--php),
[Refused paths](../configuration.md#6b-refused-paths-refuse),
[Control socket](../configuration.md#15-control-socket) (application rules),
[Refuse what an application never serves](protection.md#refuse-what-an-application-never-serves).

## Use a php-fpm pool you already run

**When:** a single-tenant server whose php-fpm pool exists already (the distribution's `www`
pool, a pool you tuned), or a site moved from nginx with its pool.

```toml
# /etc/agensio/sites.d/www.example.com.toml
[[site]]
server_name = ["www.example.com", "example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/www.example.com/web"
app = "wordpress"
tls = { cert = "/etc/ssl/www.example.com/fullchain.pem", key = "/etc/ssl/www.example.com/privkey.pem" }
php = { socket = "unix:/run/php/php8.4-fpm.sock" }   # the pool's listen; nothing is generated
```

```ini
; /etc/php/8.4/fpm/pool.d/www.conf: the pool's socket, opened for agensio's group
listen = /run/php/php8.4-fpm.sock
listen.owner = www-data
listen.group = agensio
listen.mode = 0660
```

**What it does.** agensio connects to the pool's socket and leaves the pool to you: its user,
`pm`, children, `memory_limit` and upload sizes are php-fpm's settings, in its pool file. The
socket must be one agensio's account can open; if it is not, every PHP request answers 502 and
the error log names the socket's owner, group and mode against agensio's account. `agensio -t`
connects once and warns with the reason.

What is easy to get wrong: the pool keys of `php = { ... }` (`children`, `pm`, `memory_limit`,
`max_execution_time`, ...) belong to a pool agensio generates. Without `user`, `-t` refuses them;
with `user` next to a `socket`, nothing is generated and they change nothing. With `user`, the
hosting rules check your socket too: it must belong to that account, with the server's group and
mode `0660`, so a pool shared by several sites cannot serve a site with its own account. Kept
connections (`keep_conn`) are off for a pool you run: php-fpm ties a child to each kept
connection, so turn them on only with `max_connections` times the workers below the pool's
`pm.max_children`.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml                 # warns when the socket cannot be opened, and why
curl -sI https://www.example.com/ | head -1
agensio ctl logs --level error --since 10m             # a fastcgi line names the socket and what refused it
```

**On a managed site.**

```sh
agensio ctl site-create --domain www.example.com --alias example.com --https auto --no-user --app wordpress --root /var/www/www.example.com/web --php-socket unix:/run/php/php8.4-fpm.sock --yes --reason "existing pool"
```

**MCP:** `site_create` with `php_socket` and `no_user`.

**Reference:** [PHP and FastCGI options](../configuration.md#7-php-and-fastcgi-options),
[Hosting: one user per site](../configuration.md#11-hosting-one-user-per-site).

## php-fpm in a container

**When:** PHP runs in Docker (the official `wordpress:fpm` image, a compose or ddev project)
and agensio on the host serves the site.

```toml
# /etc/agensio/sites.d/wp.example.com.toml
[[site]]
server_name = ["wp.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/wp.example.com/web"            # the files on this host, bind-mounted into the container
app = "wordpress"
tls = { cert = "/etc/ssl/wp.example.com/fullchain.pem", key = "/etc/ssl/wp.example.com/privkey.pem" }
php = { socket = "127.0.0.1:9000", remote_root = "/var/www/html" }   # the published port; the same directory as the container sees it
```

```sh
docker run -d --name wp-fpm -p 127.0.0.1:9000:9000 -v /var/www/wp.example.com/web:/var/www/html wordpress:fpm
```

**What it does.** agensio reads static files from the host's directory, as for any site. For a
script it checks locally that the file exists (a script only the container has is 404), then
sends php-fpm `SCRIPT_FILENAME`, `DOCUMENT_ROOT` and `PATH_TRANSLATED` with the local root
replaced by `remote_root`. Over TCP agensio sets `TCP_NODELAY` on the connection.

What is easy to get wrong: publish the port on `127.0.0.1` only. FastCGI has no
authentication: whoever reaches the port can have php-fpm run any file it can read. Keep
`keep_conn` off through Docker's published port: kept connections stalled large answers there,
and agensio's fix for that cannot reach inside the container. A unix socket in a directory
bind-mounted from the host is the faster transport (about half the CPU per request of the TCP
port): `socket = "unix:/path/on/the/host.sock"` with the same `remote_root`. `remote_root` is a
site-file key; the control plane has no field for it.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml                 # warns while nothing listens on the port
agensio ctl path-check wp.example.com /wp-login.php     # runs the script (the local file decides)
curl -sI https://wp.example.com/wp-login.php | head -1
```

**Reference:** [php-fpm in a container](../configuration.md#9-php-fpm-in-a-container),
[PHP and FastCGI options](../configuration.md#7-php-and-fastcgi-options).

## Raise the upload and PHP limits of one site

**When:** one site needs more than the defaults (1 MB request bodies, 256M of memory, 60 s per
script): a shop importing large files, a media library taking video, a report that runs for
minutes.

```toml
# /etc/agensio/sites.d/shop.example.com.toml
[[site]]
server_name = ["shop.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/shop.example.com/web"
app = "wordpress"
user = "shop"
tls = { cert = "/etc/ssl/shop.example.com/fullchain.pem", key = "/etc/ssl/shop.example.com/privkey.pem" }
max_body_size = "256MB"          # 413 above it, before PHP sees a byte; also the pool's upload_max_filesize and post_max_size
php = { memory_limit = "512M", max_execution_time = 300, max_input_time = 300, read_timeout = 300 }
```

**What it does.** agensio checks `max_body_size` itself: a declared body above it gets 413 at
once, and the generated pool's `upload_max_filesize` and `post_max_size` follow it.
`memory_limit`, `max_execution_time` and `max_input_time` (how long an upload may take to
arrive) go into the generated pool as `php_admin_value` lines, which the application cannot
raise with `ini_set`. `read_timeout` is agensio's own: how long it waits for php-fpm to send
something (60 s by default) before answering 504.

What is easy to get wrong: a script allowed 300 s that sends nothing until it is done needs
`read_timeout` raised too, or the visitor gets 504 after a minute while PHP goes on. The pool
keys apply only to a pool agensio generates (`user` and no `socket`), and only after `agensio
pools` and a php-fpm reload. A site without its own `max_body_size` takes `[server]
max_body_size`.

**Check it.**

```sh
agensio -t --explain -c /etc/agensio/agensio.toml | grep 'php_admin_value'   # the values the pool file gets
agensio pools -c /etc/agensio/agensio.toml
systemctl reload php8.4-fpm
agensio ctl settings shop.example.com     # each limit, where its value comes from, and the ceiling
```

**On a managed site.** The limits are the site's settings. Each value is checked against
`[control] site_limits` in the main file (by default 512MB, 512M, 300 s, 300 s, 32 children) and
refused above it, naming the ceiling; the answer's `done` names the pool written and the php-fpm
reload. `read_timeout` is not among the settings: a managed site keeps 60 s.

```sh
agensio ctl site-update shop.example.com --set max_body_size=256MB --set memory_limit=512M --set max_execution_time=300 --set max_input_time=300 --yes --reason "product imports"
```

**MCP:** `site_settings_list` for the keys, values and ceilings, then `site_update` with
`settings` = `{"max_body_size": "256MB", "memory_limit": "512M", "max_execution_time": 300}`.

**Reference:** [Hosting: one user per site](../configuration.md#11-hosting-one-user-per-site)
(the pool keys), [PHP and FastCGI options](../configuration.md#7-php-and-fastcgi-options).

## Send PHP's output as it is produced

**When:** a page must reach the browser while the script still runs: server-sent events, a
progress page, a large export that should start downloading at once.

```toml
# /etc/agensio/sites.d/reports.example.com.toml
[[site]]
server_name = ["reports.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/reports.example.com/web"
app = "php"
user = "reports"
tls = { cert = "/etc/ssl/reports.example.com/fullchain.pem", key = "/etc/ssl/reports.example.com/privkey.pem" }
php = { buffering = false, read_timeout = 300 }   # every PHP answer of the site streamed; at most 5 minutes between two pieces
```

**What it does.** By default agensio collects php-fpm's whole answer (in memory up to 1 MB,
then in a temporary file) and frees the PHP child at once, then sends the answer at the
client's pace: a slow client never holds PHP, but nothing reaches the browser before the script
has finished. With `buffering = false` each piece goes on as php-fpm sends it.

What is easy to get wrong: the child then stays busy until the client has taken the answer, so
while 8 slow downloads run, a pool of 8 children serves nothing else. The key is the site's: every PHP
answer of the site is streamed. `read_timeout` is the longest silence between two pieces; an
event stream sends a comment line more often than that. The script must still flush its own
output, or PHP keeps it. On a Laravel site the same line streams its event routes, since only
`/index.php` runs there anyway.

**Check it.**

```sh
curl -N https://reports.example.com/progress.php          # lines arrive as the script prints them
```

**Reference:** [PHP and FastCGI options](../configuration.md#7-php-and-fastcgi-options),
[Customising a preset](../configuration.md#5-customising-a-preset) (Laravel with server-sent events).

## PHP in one directory of a static site

**When:** a static site with one PHP part: a contact form, a small tool under `/forms/`. PHP must
run there and nowhere else, and no `.php` elsewhere may be sent as text.

```toml
# /etc/agensio/sites.d/info.example.com.toml
[[site]]
server_name = ["info.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/info.example.com/web"
user = "info"                    # a fastcgi location without a socket of its own: agensio generates the pool
tls = { cert = "/etc/ssl/info.example.com/fullchain.pem", key = "/etc/ssl/info.example.com/privkey.pem" }

[[site.location]]                # a .php runs wherever no final prefix shields it
path = ".php"
match = "suffix"
handler = "fastcgi"

[[site.location]]                # the whole site: static, and a .php here is 404, never run, never sent as text
path = "/"
final = true
deny_suffixes = [".php", ".phtml", ".phar", ".inc"]

[[site.location]]                # the one directory where PHP runs: the longest prefix there, and not final
path = "/forms/"
index = ["index.php", "index.html"]
deny_suffixes = [".php", ".phtml", ".phar", ".inc"]   # the spellings the suffix location does not take: x.PHP, x.phtml
```

**What it does.** Locations are chosen in this order: an exact match, then a suffix location,
then the longest prefix, except that a longest prefix with `final = true` keeps the suffix
locations out. So `/`, final, keeps every path of the site static, and `/forms/`, the longest
prefix for everything below it and not final, lets `/forms/send.php` and `/forms/` (its
`index.php`) run.

What is easy to get wrong: a static site sends every file it holds, a `.php` included, as a
download with its source. The suffix location takes the exact ending `.php` only, so without the
`deny_suffixes` lists `x.PHP`, `x.phtml` or an `.inc` would be sent as text. A `refuse = ["*.php"]`
is no shortcut: refused paths are judged before any location, so it would refuse the scripts in
`/forms/` too (and next to an exact location that runs a script, `-t` refuses it outright). For a
single script an exact location is shorter (`path = "/contact.php"`, `match = "exact"`,
`handler = "fastcgi"`), with the same `/` refusing the rest.

**Check it.**

```sh
agensio ctl path-check info.example.com /forms/send.php     # runs the script
agensio ctl path-check info.example.com /old/test.php       # 404: the ending is refused
agensio ctl path-check info.example.com /forms/X.PHP        # 404
agensio ctl path-check info.example.com /forms/style.css    # the file
```

**Reference:** [Locations, the reference](../configuration.md#6-locations-the-reference),
[PHP and FastCGI options](../configuration.md#7-php-and-fastcgi-options).

## Add headers to a preset's directory without losing its shield

**When:** part of a preset's site needs extra response fields: `nosniff` and a policy that
blocks scripts on WordPress's uploads, so an uploaded HTML or SVG file cannot run script under
your domain.

```toml
# /etc/agensio/sites.d/blog.example.com.toml
[[site]]
server_name = ["blog.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/blog.example.com/web"
app = "wordpress"
user = "blog"
tls = { cert = "/etc/ssl/blog.example.com/fullchain.pem", key = "/etc/ssl/blog.example.com/privkey.pem" }

[[site.location]]                # path and add_headers only: joins the preset's location at this path
path = "/wp-content/uploads/"
add_headers = { "X-Content-Type-Options" = "nosniff", "Content-Security-Policy" = "script-src 'none'" }
```

**What it does.** A location that sets nothing but `path` and `add_headers` joins the location
the preset makes at that path: its fields are added to answers there (200 and 304), one of the
same name replacing the preset's, and everything else stays: `final`, the refused endings, the
7-day `Cache-Control`.

What is easy to get wrong: add one more key, a `try_files` say, and the location replaces the
preset's instead. The shield is gone with it: the `.php` suffix location reaches
`wp-content/uploads/` again, and an uploaded script runs. `-t` does not warn about it;
`--explain` shows it, since a joined location keeps `final = true` and the preset's
`deny_suffixes`. A location at a path the preset does not use is added next to the preset's,
under the usual order.

**Check it.**

```sh
agensio -t --explain -c /etc/agensio/agensio.toml | grep -A12 'path = "/wp-content/uploads/"'   # final = true, the deny list, all three fields
curl -sI https://blog.example.com/wp-content/uploads/2026/10/photo.jpg | grep -i 'content-security-policy\|cache-control'
```

**On a managed site.** No field covers it, and the managed file is rewritten by every change, so
the location goes into the site's root additions file, root's and writable by root alone:

```sh
cat > /etc/agensio/sites.d/blog.example.com.root.toml <<'EOF'
site = "blog.example.com"

[[location]]
path = "/wp-content/uploads/"
add_headers = { "X-Content-Type-Options" = "nosniff", "Content-Security-Policy" = "script-src 'none'" }
EOF
chmod 644 /etc/agensio/sites.d/blog.example.com.root.toml
agensio reload
agensio ctl site blog.example.com          # its root additions: the file and the location it added
```

**MCP:** `site_show` names the root additions file and what it added; an agent hands the user
this block and never writes the file itself.

**Reference:** [Customising a preset](../configuration.md#5-customising-a-preset),
[Control socket](../configuration.md#15-control-socket) (root additions).
