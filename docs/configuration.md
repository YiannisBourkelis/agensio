# Configuring agensio

A configuration is one TOML file: `[server]`, `[log]`, `[cache]` and one `[[site]]` per
virtual host, with optional `[[site.location]]` blocks. Paths are relative to the file's
directory. `include = ["sites.d/*.toml"]` pulls in more `[[site]]` tables, one file per
site if a panel writes them, and root additions files beside managed sites (section 15).

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

**Pre-compressed files.** A `name.br` or `name.gz` beside a cached file is served, with
`Content-Encoding` and `Vary: Accept-Encoding`, to a client whose `Accept-Encoding` takes it
(`br` wins a tie, `q=0` refuses one, `*` covers the rest), and the file itself to any other
client. Vite, webpack and the `brotli` and `gzip` tools write these twins at build time;
nothing is compressed at request time (nginx: `gzip_static`, `brotli_static`). A twin is
used only when it is at least as new as the file, since an older one is a build that was
not redone, and it is cached beside the file with an ETag and Last-Modified of its own and
revalidated with it, so a twin added, replaced or removed shows within
`cache.revalidate_interval`. Files above `cache.max_file_size` are served as stored.
`[cache] precompressed = false` turns the lookup off.

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

A directory's index is a file the site would answer by name. When another location owns it
(a `.php` that runs) it runs there. When the site refuses it by name (a `refuse` pattern, a
`deny` location, a refused ending, a dotfile, a backup of a protected name) it is passed over
as if it were missing: the next index name is tried, then `try_files` goes on to its next step,
the front controller where there is one, else `=404`, or 403 for a directory without an index
when there is no `try_files`. A refused index is never served and never run. So on a preset
where only some scripts run, `/sub/` holding a stray `index.php` is answered by the application,
and TYPO3 13's `/typo3/` reaches `/index.php` as its documentation routes it, without listing
the deprecated `typo3/index.php` (alpha.55; alpha.54 answered 404 there, and before alpha.54
the drupal, laravel and grav presets served `sub/index.php` as a file).

nginx (`index`, `try_files $uri/`), Apache (`DirectoryIndex`) and Caddy (`php_fastcgi`'s
`{path}/index.php`) choose an index by existence alone and leave the refusal to a later rule,
which answers 403 or, in a configuration that runs only `/index.php`, can hand the file out as
text; their documented configurations special-case such directories by hand (TYPO3's `location
/typo3/` without `$uri/`, a rewrite without `!-d`). Here the choice and the refusal are one
decision, and `path-check` (section 15) shows it.

**Encoded separators.** A request whose path spells a slash or a backslash as a percent
escape (`%2F`, `%5C`, in either case) is answered 404 by every location that resolves paths
on disk, static, FastCGI and CGI alike, before anything is looked up: it is Apache's
`AllowEncodedSlashes Off`, and it closes spellings such as `/x%2F..%2Fwp-login.php`, which
decoded and normalised to the script (2026-10-02). Every other escape decodes as before
(`/style%2Ecss` is `/style.css`). A proxied location hands the raw target to its origin
undecoded, as nginx does, so an application that encodes a slash inside a path segment
(GitLab's `group%2Fproject`) keeps working behind `app = "proxy"`. A PHP application behind a
front controller that does the same and reads `REQUEST_URI` itself gets `encoded_slashes =
"allow"` on its site (Apache's `NoDecode` in effect: the escape is decoded for the lookup,
`try_files` reaches `index.php`, PHP sees the raw `REQUEST_URI`); `site_update` sets it,
`agensio ctl site-update NAME --encoded-slashes allow`. nginx has no such switch: it decodes
`%2F` for files and locations always, and passes it untouched only through a plain
`proxy_pass`.

```toml
[[site]]
server_name = ["wiki.example.com"]
app = "php"
encoded_slashes = "allow"      # the application encodes slashes inside path segments
```

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
deny_suffixes = [".php", ".phtml", ".phar", ".pht", ".phtm", ".php2", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".phps",
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
entry points is not Laravel; use `app = "php"` (with `rules.entry_points` on a managed
site, section 15), or `app = "drupal"` for Drupal (section 4c).
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
deny_suffixes = [".php", ".phtml", ".phar", ".pht", ".phtm", ".php2", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".phps",
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

[[site.location]]        # WordPress's hardening guide: never reached from the web
path = "/wp-admin/includes/"
final = true
handler = "deny"         # 404 whatever exists; likewise /wp-includes/theme-compat/

[[site.location]]        # the admin's static files: served, nothing runs (no Cache-Control added);
path = "/wp-admin/css/"  # likewise /wp-admin/js/ and /wp-admin/images/
final = true
deny_suffixes = [...the same list...]
try_files = ["$uri", "=404"]
```

`wp-admin/includes/` and `wp-includes/theme-compat/` answer 404 and never run (since
alpha.53), the two directories WordPress's "Hardening WordPress" guide blocks besides
`wp-includes/` itself: their scripts are libraries loaded by WordPress, and run directly
they print errors that name paths. `wp-content/plugins` is deliberately not shielded: some
plugins expose PHP endpoints there. `wp-config.php`, `wp-config-sample.php`, `readme.html`, `license.txt` and the
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

## 4c. Drupal: `app = "drupal"`

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

[[site.location]]        # Drupal's own rule: a script directly in / runs (index.php, update.php)
path = ".php"            # (shown by --explain as "only a script directly in /"; a preset rule,
match = "suffix"         #  not a key a hand-written site can set)
handler = "fastcgi"

[[site.location]]        # and a script directly in /core/ (install.php, authorize.php, rebuild.php)
path = ".php"
match = "suffix"
handler = "fastcgi"      # "only a script directly in /core/"

[[site.location]]        # the one deeper script Drupal's .htaccess lets run
path = "/core/modules/statistics/statistics.php"
match = "exact"
handler = "fastcgi"

[[site.location]]        # what Drupal's .htaccess protects, refused natively (404): PHP source in its
path = "/"               # other spellings, templates, translations, dumps, editor backups
deny_suffixes = [".inc", ".bak", ".orig", ".save", ".swp", ".swo", "~", ".log", ".sql",   # the shared list (below)
                 ".install", ".module", ".theme", ".engine", ".profile", ".make", ".po", ".twig", ".yml", ".yaml",
                 ".sqlite", ".sqlite3", ".db", ".tpl", ".xtmpl", ".sh",                      # Drupal's own
                 "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",  # these names in any
                 "/yarn.lock", "/web.config"]                                                # directory

# final prefixes (nginx ^~): nothing PHP-like under library, vendor and upload directories
[[site.location]]  path = "/core/lib/"             final = true  try_files = ["$uri", "=404"]  deny_suffixes = [...php and the list above...]
[[site.location]]  path = "/core/includes/"        final = true  (same)
[[site.location]]  path = "/vendor/"               final = true  (same)
[[site.location]]  path = "/node_modules/"         final = true  (same)
[[site.location]]  path = "/sites/default/files/"  final = true  (same)

# never answered, whatever is on disk (404, existence not disclosed)
[[site.location]]  path = "/sites/default/settings.php"  match = "exact"  try_files = ["=404"]
# likewise settings.local.php, default.settings.php, services.yml, default.services.yml,
# composer.json, composer.lock, package.json, package-lock.json, yarn.lock, web.config,
# and autoload.php (Drupal's .htaccess refuses it by name: it is a script directly in /)
```

**Which PHP runs is Drupal's own rule** (since alpha.53, from the `.htaccess` that Drupal 10
and 11 ship): a script directly in the web root (`index.php`, `update.php`), a script
directly in `core/` (`install.php`, `authorize.php`, `rebuild.php`) and
`core/modules/statistics/statistics.php`; `autoload.php` and every other `.php` (a
module's, a theme's, a library's, anything a plugin left under `modules/` or `themes/`) is
refused with 404 and never reaches php-fpm, in any case spelling. PATH_INFO after a script
that runs still works (`/index.php/node/1`). Before alpha.53 any `.php` ran, as most nginx
recipes for Drupal do; a module's stray script was then executable from the web. A module
whose documentation asks for a script of its own to be reachable (Drupal's `.htaccess`
says to copy the statistics line for it) gets an exact `handler = "fastcgi"` location in
the site's root additions (section 15).

`.htaccess`, `.ht.sqlite` (Drupal's SQLite database), `.env` and `.git/` are dotfiles and
stay hidden by the site default. A `.php` that does not exist answers 404 before php-fpm.
`composer.json`, `package.json`, `yarn.lock`, `web.config` and `.sh` scripts are refused in
any directory, as the `FilesMatch` of Drupal's `.htaccess` refuses them.

**agensio never reads `.htaccess`.** Applications that ship one (Drupal, WordPress,
Joomla, most PHP software) rely on it for exactly these refusals under Apache; under
agensio the preset provides them, and a hand-written site for such an application must
provide its own. The list above is the subset of Drupal's `.htaccess` that matters:
source disclosure and execution of files that are not entry points. Drupal's other
rules (canonical redirects, caching headers) are optional and can be added as locations.

The preset is Drupal's. An application with a front controller and several `.php` entry
points of its own that are not where Drupal keeps them (Kanboard, phpBB) takes `app =
"php"`, where any `.php` runs, narrowed with `rules.entry_points` on a managed site
(section 15).

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

expands to Grav's own nginx recipe and its user-folder-exposure guidance
(https://learn.getgrav.org/2/security/user-folder-exposure), which deny directories rather
than endings wherever a directory is private:

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

# never answered, whatever they hold: Grav's recipe denies these directories whole, and a
# backup archive under backup/ is the site (accounts, salt, configuration, pages); user/config/
# and user/env/ hold the configuration and the signing salt, webserver-configs/ the recipes
[[site.location]]  path = "/logs/"    final = true  try_files = ["=404"]     # handler = "deny"
[[site.location]]  path = "/logs"     match = "exact"  try_files = ["=404"]  # the bare name: no redirect confirms the directory
# likewise /backup/, /cache/, /bin/, /tests/, /tmp/, /webserver-configs/, /user/config/, /user/env/

# assets only below system/ and vendor/ (css, js, images, fonts): no source, templates,
# configuration, documentation or json
[[site.location]]  path = "/system/"  final = true  try_files = ["$uri", "=404"]
                   deny_suffixes = [...the root's list..., ".txt", ".xml", ".md", ".html", ".htm", ".shtml", ".shtm", ".json",
                                    ".yaml", ".yml", ".pl", ".py", ".cgi", ".twig", ".sh", ".bat"]
[[site.location]]  path = "/vendor/"  (same)

# user/: images, css, js, fonts and uploads are served; pages (.md), accounts and
# configuration (.yaml, .json), templates (.twig) and scripts are not
[[site.location]]  path = "/user/"    final = true  try_files = ["$uri", "=404"]
                   deny_suffixes = [...the root's list..., ".txt", ".md", ".json", ".yaml", ".yml", ".pl", ".py", ".cgi", ".twig", ".sh", ".bat"]

# user/accounts/ answers avatar images and nothing else (the account files sit beside them;
# svg stays out on purpose, a stored-XSS vector); user/data/ answers public media, documents,
# fonts, css and js and nothing else (Flex objects keep their data there). A directory or a
# bare name below either is 404 too.
[[site.location]]  path = "/user/accounts/"  final = true  try_files = ["$uri", "=404"]
                   allow_suffixes = [".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".bmp", ".ico"]
[[site.location]]  path = "/user/data/"      final = true  try_files = ["$uri", "=404"]
                   allow_suffixes = [".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".bmp", ".ico", ".mp4", ".webm", ".ogg", ".ogv",
                                     ".mov", ".mp3", ".wav", ".m4a", ".flac", ".pdf", ".woff2", ".woff", ".ttf", ".otf", ".eot", ".css", ".js"]

# the public caches images/ (derivatives) and assets/ (pipelined css and js): scripts are
# never run or served there, and a missing file reaches the front controller, which makes it
[[site.location]]  path = "/images/"  final = true  try_files = ["$uri", "/index.php?$query_string"]
                   deny_suffixes = [...the root's list..., ".pl", ".py", ".cgi", ".sh", ".bat"]
[[site.location]]  path = "/assets/"  (same)

# never answered although present (404): the version fingerprints, composer files and the
# markdown files the release ships at the root
[[site.location]]  path = "/LICENSE.txt"  match = "exact"  try_files = ["=404"]
# likewise composer.json, composer.lock, nginx.conf, web.config, htaccess.txt, CHANGELOG.md,
# README.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, user/config/security.yaml (the
# signing salt; the preset's `secret`)
```

Two things Grav's recipe leaves to the operator stay so here. Media under `user/pages/` is
served directly, because Grav's `pages.media_route_urls` is off by default (a hand-written
`[[site.location]]` for `/user/pages/` with `try_files = ["=404"]` hands it to the page
route once that setting is on). And `.md` is refused by name at the root rather than by
ending, because a page route that ends in `.md` is Grav's Markdown output, not a file.

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

On a proxy site `root` is optional and nothing is served from it: every request goes to
the upstream. When it is given, it is the application's directory, which `site-install`
fills and the hosting rules check (section 11).

**Ruby on Rails: `app = "rails"`.** The same routing as `proxy` (every request to the
site's upstream, where Puma listens), plus what a Rails application needs from the
control plane: `root` is required and is the project directory, by convention `app/`
beside `web/` in the site's tree (`/var/www/example.com/app`, what `site-create`
suggests), and the preset's named tasks run there as the site's account (section 15,
`site-task`): `gem_install_rails`, `rails_new`, `bundle_install`, `db_prepare`,
`db_migrate`, `assets_precompile`. Its credential files, `config/master.key`,
`config/credentials/`, `config/database.yml` and `storage/` (the SQLite databases and
Active Storage's files), are held to the hosting rule of section 11 like `wp-config.php`
is, and every writer and task leaves them the site's alone. A site with its own `user`
and `app = "rails"` gets no php-fpm pool. Nothing is served from the project directory
yet: every request goes to Puma, and Rails' own public file server answers what lies in
`public/` (serving it from disk is step 7 of `docs/design-site-operations.md`). The paths
scanners probe are answered 404 by agensio itself and never reach the application:
`/config/master.key`, `/config/database.yml`, `/config/credentials.yml.enc`,
`/config/credentials/`, `/.env`, `/.env.production`, `/.kamal/`, `/.git/`, `/Gemfile`,
`/Gemfile.lock`, `/log/production.log` and everything below `/storage/` (Rails keeps its
databases and Active Storage's disk files there and routes none of it; Active Storage
answers under `/rails/active_storage/`), and any path ending in `.sqlite3`,
`.sqlite3-wal`, `.sqlite3-shm`, `.sqlite3-journal`, `.log`, `.key` or `.sql`, the ending in
any case, wherever the application keeps its files (the `/storage/` prefix is matched as
written, as every path is; `/Storage/db/production.sqlite3` is refused by its ending) (Writebook's database is
`storage/db/production.sqlite3`). `presets` lists them under `never_served`; a hand-written
location of the same path wins, and a hand-written `/` location replaces the endings too. Every task prints
"Using vips to process variants requires the libvips library" until `libvips42` is
installed; only Active Storage's image variants need it.

```toml
[[site]]
server_name = ["ag5.example.com"]
listen = ["0.0.0.0:443"]
tls = "auto"
app = "rails"
root = "/var/www/ag5.example.com/app"   # the project directory: tasks run here, nothing is served from it
user = "ag5"
upstream = "http://127.0.0.1:3000"      # where Puma listens; keep it on loopback
```

The application server itself is not started by agensio yet (roadmap F14): until then a
systemd unit runs Puma as the site's account with the environment the tasks use, rendered
for the site by `agensio ctl site-unit NAME` (MCP `site_service_unit`): its account, its
directory, the loopback port of its `upstream`, the Ruby of `[control] runtimes` first on
`PATH` and in `ExecStart` (the one its bundle was built with), and the site's environment
file. Root puts it in place:

```sh
agensio ctl site-unit ag7.example.com --raw > /etc/systemd/system/agensio-app-ag7.service
systemctl daemon-reload && systemctl enable --now agensio-app-ag7.service
```

It binds loopback (`-b tcp://127.0.0.1:3007`; the `puma.rb` Rails generates binds every
address, which would publish the application beside agensio, without its TLS and
refusals) and loads the site's environment file (section 15, "The site's environment"),
so a secret is written once, through the control plane, and the tasks and Puma both see
it. The unit is refused for a site without its own account or whose upstream is not
plain HTTP on loopback, and every value in it must be a plain path or name, so nothing
can add a line to it. `docs/examples/puma.service` is the same unit written by hand.
`agensio ctl site-service NAME` (MCP `site_service_status`) says whether it runs,
`site-service-logs NAME` (MCP `site_service_logs`, admin) shows its journal, and `health`
reports every Rails site whose unit is missing (`site_service_missing`, info), stopped
(`site_service_down`) or failing (`site_service_failed`), all read through the
provisioning helper. Starting, stopping and restarting the unit stays root's: after a
task that changes what the application loads (`bundle_install`, `db_migrate`,
`assets_precompile`) the task's answer carries the restart line.

An existing application (a GitHub release tarball, an upload) goes in with `site-install`,
then `bundle_install`, `db_prepare` and `assets_precompile`. One that ships
`config/database.yml.example` and no `config/database.yml` first gets its database:
`site-env-set NAME --set DATABASE_URL=sqlite3:db/production.sqlite3` (or
`postgresql://USER:PASSWORD@HOST/NAME`, `mysql2://...`), then the task `database_config`,
which writes `config/database.yml` from a fixed template (the database from
`DATABASE_URL`, the adapter from its scheme, no password in the tree; `0600`, only when the
file is missing); `bundle_install` then bundles the matching driver where the Gemfile reads
`database.yml`, and a `bundle_install` that exits 0 while the application says it found no
database configuration answers 409. The install's answer says so (its `facts` name
`database_yml` and `database_yml_example`),
names the Ruby the application pins in `.ruby-version` when it has one, and, when the
archive came without Rails credentials (`config/credentials.yml.enc`, as every ONCE
application such as Writebook and every Kamal deployment), generates `SECRET_KEY_BASE`
into the site's environment, once. A new site's answer also states its request-body
limit: 1 MB unless `settings.max_body_size` raises it, and an upload above it is a 413 the
application never sees (the error log names the site, the size and the limit).

**Redmine: `app = "redmine"`.** The rails preset's routing, refusals and tasks for an
application installed from an archive (`gem_install_rails` and `rails_new` are not
offered), plus Redmine's own: `gemfile_local` writes the fixed `Gemfile.local` Redmine's
Gemfile evaluates, adding Puma (Redmine keeps it in its test group, which the tasks'
`BUNDLE_WITHOUT` skips); `load_default_data` loads trackers, statuses and roles in one
language (`--param lang=en`); `plugins_migrate` runs the migrations of `plugins/` after a
plugin's `site-install --path plugins/NAME --create-path` and `bundle_install`. Its
credential files are `config/database.yml`, `config/configuration.yml` (SMTP) and
`config/initializers/secret_token.rb`. `site-install --version 7.0.1` fetches
`https://www.redmine.org/releases/redmine-7.0.1.tar.gz` (a version is required; pass the
`--sha256` redmine.org publishes). A Redmine archive installed on a `rails` site is named
in the answer's warnings. The whole path, which `tests/redmine-install.sh` runs:

```sh
agensio ctl site-create --domain pm.example.com --app redmine --root /var/www/pm.example.com/app --user pm --upstream http://127.0.0.1:3007 --yes --reason redmine
agensio ctl site-install pm.example.com --version 7.0.1 --sha256 <redmine.org's> --yes --reason redmine
agensio ctl site-env-set pm.example.com --set DATABASE_URL=sqlite3:db/production.sqlite3 --yes --reason redmine
for t in database_config gemfile_local bundle_install db_migrate; do agensio ctl site-task pm.example.com $t --yes --reason redmine; done
agensio ctl site-task pm.example.com load_default_data --param lang=en --yes --reason redmine
agensio ctl site-task pm.example.com assets_precompile --yes --reason redmine
agensio ctl site-unit pm.example.com --raw > /etc/systemd/system/agensio-app-pm.service   # as root, then enable it
```

## 4e. Django and Wagtail: `app = "django"`, `app = "wagtail"`

A Django project runs under Gunicorn on a loopback port; agensio serves its `/static/`
(what `collectstatic` gathers) and `/media/` (uploads) from the project directory, since
Gunicorn serves no files, and sends every other request to Gunicorn. `wagtail` is built on
`django` as `redmine` is on `rails`: the same routing and tasks, plus Wagtail's own. `root`
is the project directory (where `manage.py` lives) and `project` names the project's Python
package (`NAME/settings`, `NAME/wsgi.py`), required for both presets: a new project is
created under that name, an installed one must match its own.

```toml
[[site]]
server_name = ["ag8.example.com"]
listen = ["0.0.0.0:443"]
tls = "auto"
app = "wagtail"
root = "/var/www/ag8.example.com/app"   # the project directory; only static/ and media/ below it are served
project = "mysite"                       # the Python package: mysite/settings, mysite/wsgi.py
user = "ag8"
upstream = "http://127.0.0.1:3008"      # where Gunicorn listens; keep it on loopback
```

What the preset adds:

| path | answered by |
|---|---|
| `/static/` | the file below `<root>/static/`, else 404 (never the application); a name that carries its content's hash (`base.85e6f9d19e42.css`, what `ManifestStaticFilesStorage` writes, Wagtail's production default) gets `Cache-Control: public, max-age=31536000, immutable`, any other name `public, max-age=300`, then revalidation by `ETag`, so an upgrade reaches browsers |
| `/media/` | the file below `<root>/media/`, else 404; `X-Content-Type-Options: nosniff` and `Content-Security-Policy: script-src 'none'; form-action 'none'; base-uri 'none'`, so an uploaded HTML or SVG page runs no script on the site's origin (no `sandbox`: a browser's PDF viewer refuses a sandboxed document) |
| `/media/documents/` (wagtail) | 404: Wagtail serves documents through its own view (`/documents/ID/NAME`), which checks a collection's privacy |
| `/.env`, `/.git/`, `/manage.py`, `/requirements.txt`, `/agensio_settings.py`, `/db.sqlite3`, `/Dockerfile`, `/.dockerignore` | 404 at the edge |
| a path ending in `.py`, `.pyc`, `.pyo`, `.sqlite3` (and `-wal`, `-shm`, `-journal`), `.log`, `.key`, `.sql`, `.env` | 404, on the application's paths and in the two served directories |
| everything else | the upstream (Gunicorn) |

Both served directories refuse dot segments and follow no symlink out of the project.

**The virtualenv.** Every task runs in a virtualenv of the site's own,
`<state_dir>/<account>/venvs/<site>`, outside the served tree and never shared between
sites (a virtualenv holds one version of each package). `venv_create` makes it with the
`python3` of `[control] runtimes`; every other task runs that same root-owned `python3`
under the virtualenv's name (`argv[0]` is `<venv>/bin/python`, which is how Python finds
its virtualenv), so the packages are the site's while the program executed stays root's,
as the interpreter rule requires. Debian and Ubuntu ship venv's `ensurepip` apart: without
`python3-venv` the task list marks the interpreter and names
`apt-get install -y python3-venv` for root, and `venv_create` is refused before it runs.

**`pip_install` needs the user's own confirmation.** It installs whatever packages it is
given (one to ten requirement specifiers: a name, extras, version clauses; no URL, path or
option, each passed to pip after `--`), and their code runs as the site's account, so every
run is confirmed by the user in person, never by an agent's `confirm`. Through MCP the bridge
asks in the client's own dialog (MCP elicitation) before it sends the task: the packages, the
site, the account, the virtualenv, and a warning to check each name on pypi.org, since a
look-alike name is a common way to get malicious code. A client that cannot show the dialog,
or a user who declines, gets a refusal carrying the `agensio ctl` command for the user to run
in a terminal on the server, where the same warning is printed and `--yes` is the
confirmation. The control API refuses the task without one of the two (428, with the warning
and the command), and the audit log says how the user confirmed. `pip_install_requirements`
needs no confirmation: the project's own file names the packages. That the agent cannot run
`agensio ctl` itself depends on how it reaches the server: give its SSH key
`command="agensio mcp"` (docs/mcp.md).

**The tasks**, in the order a new Wagtail site takes them:

| task | runs | notes |
|---|---|---|
| `venv_create` | `python3 -m venv <venv>` | again keeps what is installed |
| `pip_install` | `pip install -- PACKAGES` | any packages, `--param "packages=wagtail gunicorn"`; the user confirms every run in person (below); downloads |
| `startproject` | wagtail: `wagtail start PROJECT .`; django: `django-admin startproject PROJECT .` | the directory must be empty; needs the framework from `pip_install` |
| `pip_install_requirements` | `pip install -r requirements.txt` | after a new project, an install, a change; downloads |
| `django_settings` | no program: writes `agensio_settings.py` | a fixed template, `0640`, only when missing; needs `DJANGO_SECRET_KEY` |
| `migrate` | `manage.py migrate --noinput` | |
| `collectstatic` | `manage.py collectstatic --noinput` | into `static/`, which agensio serves |
| `createsuperuser` | `manage.py createsuperuser --noinput --username=U --email=E` | the password from `DJANGO_SUPERUSER_PASSWORD` in the site's environment |
| `check_deploy` | `manage.py check --deploy` | reports, changes nothing |

Every Python task runs with `DJANGO_SETTINGS_MODULE=agensio_settings`,
`VIRTUAL_ENV=<venv>`, `PYTHONNOUSERSITE=1` (never the account's user site-packages),
`PYTHONUNBUFFERED=1`, `PIP_DISABLE_PIP_VERSION_CHECK=1`, `PIP_NO_INPUT=1`, and what
`agensio_settings.py` reads about the site: `AGENSIO_DJANGO_PROJECT`, `AGENSIO_HOSTS` (the
site's names, `*.example.com` as Django's `.example.com`), `AGENSIO_ORIGINS` (those names
with the scheme the site is reached by), `AGENSIO_BASE_URL`, `AGENSIO_STATIC_ROOT` and
`AGENSIO_MEDIA_ROOT` (`<root>/static`, `<root>/media`). The site's environment cannot set
any of these (section 15, "The site's environment"), nor `PIP_*`.

**The production settings.** A generated Wagtail project's production settings have no
`SECRET_KEY` (only its dev settings do) and no `ALLOWED_HOSTS`, so Django refuses every
request until someone writes them; a plain `startproject` has `DEBUG = True` and no
`STATIC_ROOT`. `django_settings` writes `agensio_settings.py` from a fixed template:
it imports the project's own settings (`PROJECT.settings.production` when there is one,
else `PROJECT.settings`), then sets `DEBUG = False`, `SECRET_KEY` from
`DJANGO_SECRET_KEY`, `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` from the site's names,
`SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")` (agensio replaces a
client's `X-Forwarded-Proto` and sets `https` on its TLS listeners, which is what makes
that setting safe), `STATIC_ROOT` and `MEDIA_ROOT` where agensio serves them,
`WAGTAILADMIN_BASE_URL` for a Wagtail project, `SESSION_COOKIE_SECURE` and
`CSRF_COOKIE_SECURE` on a site with TLS, and `DATABASES` from `DATABASE_URL` when
the site's environment has one (`sqlite:///db.sqlite3`, `postgresql://USER:PASSWORD@HOST/NAME`,
`mysql://...`; the driver must be in `requirements.txt`). `manage.py check --deploy`
cannot see what agensio does at the edge, so the file silences `security.W008` (the
redirect of plain http) when the site redirects to https and `security.W004`
(Strict-Transport-Security) when the site has `hsts`, and nothing else: a warning left
means something (on a TLS site without `hsts`, W004 stays until `site_update` with
`hsts: true` sends the header on every answer; `check_deploy` sees the change at once). It
holds no secret and names no host, so a new alias needs no new file, only a new unit.
Running `django_settings` again replaces agensio's own earlier version of the file (it
starts with `# Written by agensio (site task django_settings)`), keeping it as
`agensio_settings.py.bak`, so a site gets a later template's fixes; a file without that
marker is left alone. `manage.py` and `wsgi.py` default to the dev settings; agensio always
sets `DJANGO_SETTINGS_MODULE`, in its tasks and in the unit.

**The first admin.** `site-env-set NAME --generate DJANGO_SUPERUSER_PASSWORD`, then
`site-task NAME createsuperuser --param username=admin --param email=ADDRESS`: the
password is made on the server and never passes through the caller; `site-env NAME
--reveal DJANGO_SUPERUSER_PASSWORD` shows it when the user asks. The rendered unit keeps
it from the application (`UnsetEnvironment=` for the three `DJANGO_SUPERUSER_*` names).

**The unit.** `agensio ctl site-unit NAME` renders the Gunicorn unit: the site's account
and directory, the environment above, the site's environment file, and
`ExecStart=@<runtimes.python3>/python3 <venv>/bin/python -m gunicorn PROJECT.wsgi:application
--bind 127.0.0.1:PORT --workers 2` (systemd's `@` passes the second word as `argv[0]`: root's
interpreter as the site's virtualenv), with the hardening of the Rails unit. Root installs
it with the three commands in its answer; after a change of the site's names or its
Python, root renders it again. `site-service` and `site-service-logs` read it as for Rails.

An existing project goes in with `site-install` (its `manage.py` at the archive's top); the
answer generates `DJANGO_SECRET_KEY` into the site's environment, lists the tasks from
`venv_create` on (`pip_install_requirements`, then `pip_install` for Gunicorn), and warns when the archive's package (the directory holding `wsgi.py`,
`facts.wsgi_packages`) is not the site's `project`. A new Wagtail site, the whole path,
which `tests/wagtail-install.sh` runs:

```sh
agensio ctl site-create --domain ag8.example.com --app wagtail --project mysite --root /var/www/ag8.example.com/app --user ag8 --upstream http://127.0.0.1:3008 --yes --reason wagtail
agensio ctl site-task ag8.example.com venv_create --yes --reason wagtail
agensio ctl site-task ag8.example.com pip_install --param "packages=wagtail gunicorn" --yes --reason wagtail   # prints the warning
for t in startproject pip_install_requirements; do agensio ctl site-task ag8.example.com $t --yes --reason wagtail; done
agensio ctl site-env-set ag8.example.com --generate DJANGO_SECRET_KEY --generate DJANGO_SUPERUSER_PASSWORD --yes --reason wagtail
for t in django_settings migrate collectstatic; do agensio ctl site-task ag8.example.com $t --yes --reason wagtail; done
agensio ctl site-task ag8.example.com createsuperuser --param username=admin --param email=admin@example.com --yes --reason wagtail
agensio ctl site-unit ag8.example.com --raw > /etc/systemd/system/agensio-app-ag8.service   # as root, then enable it
```

## 4f. Node.js: `app = "node"`

A Node application runs as the site's account under root's `node` (`[control] runtimes.node`)
on a loopback port; agensio forwards every request to it, WebSocket upgrades included (it
serves its own files), and answers these itself with a 404, never forwarded: `/.env`,
`/.git/`, `/.npmrc`, `/node_modules/`, `/package.json`, `/package-lock.json`,
`/npm-shrinkwrap.json`, `/yarn.lock`, `/pnpm-lock.yaml`, and any path ending in `.db`,
`.db-wal`, `.db-shm`, `.db-journal`, `.sqlite`, `.sqlite3` (and its `-wal`, `-shm`,
`-journal`), `.log`, `.key`, `.sql` or `.env`. `root` is the project directory (where
`package.json` lives) and `entry` the file `node` runs, relative to it. `entry` may wait
until the application is installed: `site-install`'s facts guess it from `package.json`
(the start script, one level of `npm run NAME`, else `main`).

```toml
[[site]]
server_name = ["ag9.example.com"]
listen = ["0.0.0.0:443"]
tls = "auto"
app = "node"
root = "/var/www/ag9.example.com/app"   # the project directory: npm runs here, nothing is served from it
entry = "server/server.js"               # the file node runs
user = "ag9"
upstream = "http://127.0.0.1:3009"      # where it listens; keep it on loopback
```

**The tasks**, as the site's account in the project directory:

| task | runs | notes |
|---|---|---|
| `npm_ci` | `npm ci --omit=dev --no-audit --no-fund` | the dependencies exactly as `package-lock.json` pins them, into `node_modules/`; their install scripts run as the account; needs the lockfile; downloads |
| `npm_run` | `npm run SCRIPT` | one script of the project's `package.json` by name (`--param script=download-dist`): a post-install step the application documents; the project's own code; may download |

Every task runs with `NODE_ENV=production` and npm's cache and user configuration in the
account's own home (`NPM_CONFIG_CACHE=<home>/.npm`, `NPM_CONFIG_USERCONFIG=<home>/.npmrc`),
no update notice, no funding or audit chatter; never the host's `~/.npmrc` or a global
install. The site's environment cannot set `NPM_CONFIG_*` on any site, and on a Node site not
`HOST`, `PORT` or `NODE_ENV` either (section 15, "The site's environment"): systemd lets an
environment file override a unit's own lines, and those three bind the application to its
upstream. `site-tasks` names the missing runtime with `apt-get install -y nodejs npm` for
root. A task that fails names the cause when it is a known one: no lockfile, a lockfile out
of step with `package.json`, a missing script, an engine the runtime's Node does not satisfy,
a native module that needs a compiler.

**The unit.** `agensio ctl site-unit NAME` renders it: the site's account and directory,
`NODE_ENV=production`, `HOST` and `PORT` from the upstream (what Express, Uptime Kuma and most
servers read), the site's environment file, and `ExecStart=<runtimes.node>/node <root>/<entry>`,
with the hardening of the Rails unit. It is refused without `entry`. `site-service`,
`site-service-logs`, `health` and the restart lines after `npm_ci` and `npm_run` work as for
Rails and Django.

**An application from an archive.** `site-install`'s answer reads `package.json`: its name,
the Node it asks for (`engines.node`, compared with the runtime's `node --version`: they
match, they do not, or the range is not one agensio reads), its scripts, whether a lockfile
ships, and the entry it guesses; the next steps are `npm_ci`, the post-install steps through
`npm_run`, the `entry`, and the unit. A Node archive installed on an `app = "proxy"` site is
named in the answer's warnings. Uptime Kuma, the whole path (the setup script Kuma documents is
`npm ci --omit dev` and `npm run download-dist`; `DATA_DIR` keeps `kuma.db`, which holds every
monitored service's credentials, in the account's own home, and `UPTIME_KUMA_DB_TYPE=sqlite`
skips Kuma 2's database page, which the first visitor would otherwise answer):

```sh
agensio ctl site-create --domain ag9.example.com --app node --root /var/www/ag9.example.com/app --user ag9 --upstream http://127.0.0.1:3009 --yes --reason kuma
agensio ctl site-install ag9.example.com --url https://codeload.github.com/louislam/uptime-kuma/tar.gz/refs/tags/2.5.5 --yes --reason kuma
agensio ctl site-task ag9.example.com npm_ci --yes --reason kuma
agensio ctl site-task ag9.example.com npm_run --param script=download-dist --yes --reason kuma
agensio ctl site-env-set ag9.example.com --set DATA_DIR=/var/lib/agensio/ag9/data/ --set UPTIME_KUMA_DB_TYPE=sqlite --yes --reason kuma
agensio ctl site-update ag9.example.com --entry server/server.js --yes --reason kuma
agensio ctl site-unit ag9.example.com --raw > /etc/systemd/system/agensio-app-ag9.service   # as root, then enable it
```

Kuma, like WordPress's installer and Writebook's first run, creates its admin in the browser
on the first visit: whoever opens the site first becomes its admin, so open it right after
the service starts.

## 5. Customising a preset

A preset never overrides what the site writes itself:

- `index`, `try_files`, `hidden_files`, `symlinks`, `access_log`: site keys apply, and the
  locations the preset generates inherit them.
- `php = { ... }`: every option in it reaches the preset's FastCGI location(s).
- A `[[site.location]]` with the same `path` and `match` as a preset location replaces it
  entirely. Other locations coexist under the normal precedence.
- A `[[site.location]]` that sets nothing but `path` (a prefix) and `add_headers` joins
  the location the preset, or the implicit `/`, makes at that path: its fields are added,
  a field of the same name replacing the preset's value, and everything else of the
  preset's location stays. This is how `hsts = true` on a managed site reaches every
  answer (its file carries such a `/` location). Before 0.1.0-alpha.36 it replaced the
  preset's location: a proxy preset's site (`proxy`, `rails`, `redmine`, `django`,
  `wagtail`) with `hsts` served its `root` from disk instead of the application, source
  files included, and a PHP preset's site lost its front controller.

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

An application with server guidelines of its own and no preset (Kanboard, say) runs under
`app = "php"` with the site's `rules` (section 15: private paths, the `.php` files that
run, cached directories, a front controller), which the control plane renders into the
locations below, each marked `# rules: ...`; they can only narrow what the preset serves.

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
| `handler` | `"static"` (default), `"fastcgi"`, `"proxy"`, `"cgi"`, or `"deny"` (404 for every path here whatever exists, as hidden files are; what a managed site's `rules.private` renders) |
| `fastcgi = { ... }` | overrides the site's `php = { ... }` for this location (section 7) |
| `methods` | narrows what the handler serves, e.g. `["GET", "HEAD"]`; the rest get 405 with `Allow` |
| `final` | prefix only: nginx `^~` |
| `deny_suffixes` | endings answered with 404 (like hidden files: a refusal never confirms a file exists), e.g. `[".php"]` under an uploads directory; `"~"` (an editor's `name~` backup) is the one entry without a dot |
| `allow_suffixes` | when set, the only endings served here; every other path, directories and bare names included, is 404 whatever exists (Grav's `user/data`: public media beside private data) |
| `add_headers` | response fields added on 200 and 304, e.g. `{ "Cache-Control" = "..." }` |
| `priority` | may use the FastCGI pool slots reserved by `priority_reserve` |
| `httparena = { dataset }` | with `handler = "httparena"`, in a build made with `-DAGENSIO_HTTPARENA=ON` only: the HttpArena benchmark endpoints answered in-process from the dataset (`bench/httparena/`); a release build refuses the handler |

## 6b. Refused paths: `refuse`

Paths a site answers with 404 whichever location would serve them, written as gitignore-style
patterns. It is where an application without a preset of its own gets the denials its
official server configuration lists (an nginx `location ~ ... { deny all; }`, an Apache
`<FilesMatch>` or `RewriteRule ... [F]`), and it works on every `app`, since it only narrows
what the site serves.

```toml
[[site]]
server_name = ["cms.example.com"]
app = "php"
root = "/srv/www/cms.example.com/web"
refuse = ["/vendor/", "composer.json", "*.yaml", "*.typoscript",
          "/typo3conf/ext/*/Resources/Private/", "/fileadmin/templates/**/*.ts", "_recycler_/"]
```

| pattern | refuses |
|---|---|
| `/vendor/` (or `/vendor`) | `/vendor`, `/vendor/` and everything below; never `/vendors/` or `/a/vendor/` |
| `composer.json` | that name in any directory: `/composer.json`, `/core/composer.json` |
| `*.yaml` | every path with a segment ending in `.yaml`: `/config/x.yaml`, and below a directory so named |
| `_recycler_/` | a directory of that name anywhere and everything below it |
| `/typo3conf/ext/*/Resources/Private/` | `*` is any run of characters within one segment: `/typo3conf/ext/news/Resources/Private/x.html`, not `/typo3conf/ext/a/b/Resources/Private/` |
| `/fileadmin/templates/**/*.ts` | `**` is any number of directories, none included: `/fileadmin/templates/a.ts`, `/fileadmin/templates/x/y/a.ts` |
| `**/Tests/Unit/` | that directory pair at any depth |

The rules, all of them on purpose:

- **A match is a 404, and order does not exist.** No pattern reopens what another refuses, and
  none is shadowed by a location: the check runs on the request path before any location is
  chosen, again on every internal redirect (`try_files` fallbacks), and on the index file a
  directory would answer with, so `/docs/` is 404 when `/docs/index.html` is refused. That is
  the class of mistake nginx invites, where a `location ~ \.php$` before a deny, or a `^~`
  prefix, steps around it.
- **A pattern refuses what it matches and everything below it**, with or without the trailing
  `/`. A pattern without a `/` (but a trailing one) is a name in any directory; one with a `/`
  inside is anchored at the root and starts with `/` (or `**/` for any depth): `typo3conf/ext/x`
  without the leading `/` is refused with that advice, rather than guessed at.
- **Case and trailing dots are ignored** (`/VENDOR/`, `x.yaml.`), as for every refusal by
  name; the other ways an application may read a path (a `;parameter` in a segment, a second
  decoding, the path after a script) are judged too, as for the access rules (section 19).
- **Wildcards are `*` and `**` only.** No `?`, brackets or braces (write one pattern per
  alternative), no percent escapes (paths are matched decoded), at most one `**`, at most 64
  patterns of 200 characters; matching is linear and allocates nothing. A pattern of
  wildcards alone (`/*`, `**/*`) or `/` is refused: disable the site or restrict it by
  address instead.
- **A pattern may not refuse what the site serves on purpose**: the index of its root, a
  path `try_files` sends a miss to (a front controller), or an exact location that runs
  something. `-t` refuses the configuration with both named: `'*.php' refuses /index.php,
  the site's index`.

Translating another server's rules: `location ~* \.(yaml|yml)$ { deny all; }` is `*.yaml`,
`*.yml`; `location ~ /\.git { deny all; }` needs nothing (dotfiles are hidden by default);
`RewriteRule ^(vendor|typo3_src)/ - [F]` and nginx's `location ~ ^/vendor/` are `/vendor/`,
`/typo3_src/`; an unanchored `location ~ _(recycler|temp)_/` is `_recycler_/`, `_temp_/`;
`<FilesMatch "^(composer\.json|package\.json)$">` is `composer.json`, `package.json`. Beware an
nginx regex anchored without its slash (`^vendor`): nginx matches it against a path that
always begins with `/`, so as written it refuses nothing; the intent is `/vendor/`.

On a managed site the same list is `rules.refuse` (section 15), and `path-check` (MCP
`path_check`) says what the site does with one path and which pattern or location decides.
A server older than 0.1.0-alpha.54 ignores `refuse` without a word: after an upgrade, check
with `agensio -t --explain` that the patterns are listed.

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
flushed every second; `kill -USR1 <pid>` reopens all files after rotation. The escaping is
nginx's (`ngx_http_log_escape`): in the combined format `"`, `\`, control bytes and every
byte from 0x7F up are written `\xHH`, so a line is ASCII whatever a client sent; a JSON line
keeps well-formed UTF-8 and writes a stray byte as `\xHH` too (a TLS ClientHello sent to
port 80 used to land raw, 2026-10-02). `agensio ctl logs` and `logs_query` escape the same
way when they read, so older files are answered as valid text as well.

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

An entry may carry a port, as some load balancers write it: `198.51.100.7:1234` and
`[2001:db8::7]:443` are the address alone (a port is 1 to 65535; any other is not an address). Several `X-Forwarded-For` lines are one list in order, read from the end of the last line,
so a proxy that adds a line of its own (HAProxy's `option forwardfor`) decides, and a line
the client wrote before it is reached only through hops you trust. `X-Forwarded-Proto`
counts the last value of its last line. An entry that is not an address stops the walk.
A reverse-proxy location forwards a trusted chain whole, every line in order, then its peer.

An IPv4 client of a listener on `[::]` is recorded as its IPv4 address (`192.0.2.7`, never
`::ffff:192.0.2.7`), in the logs, in `REMOTE_ADDR` and when it is matched against a list;
an entry written in that mapped form (`::ffff:10.0.0.0/104`) means the IPv4 range it names,
and an IPv6 entry never matches an IPv4 client. Entries with a zone id (`fe80::1%eth0`) are
refused. A reload that changes the list applies to connections already open from their
next request on.

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
explicit `php.socket` keeps its own pool and gets no generated file. A site that runs
no PHP (`app = "proxy"`, `app = "static"`, no `handler = "fastcgi"` location) derives no
pool from its `user`: the account owns the files and, behind a proxy, runs the
application; `agensio pools` writes nothing for it, `health` looks for no PHP
directory, and pool keys in its `php = { ... }` are refused (2026-09-26: a Rails site
was reported `php_tmp_missing` and `pools_stale` before this rule).

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

The account's home is its state directory, `<state_dir>/<user>`. For a PHP site `agensio
pools` creates it with `tmp/` and `sessions/`; for an account without a PHP pool (a Rails
site) the provisioning helper creates it, `0700` with a `tmp/`, the first time a site task
runs, because `gem` and `bundle` write below `HOME` (section 15, `site-task`).

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
- One `Cookie` line, whatever the client sent: a browser sends one `cookie` field per
  cookie over HTTP/2 and HTTP/3, and they are joined with `; ` in the order received (RFC
  9113 8.2.3, RFC 9114 4.2.1), as are two `Cookie` lines from an HTTP/1.1 client, so an
  origin that reads the first line only (Rack, Puma) sees every cookie. FastCGI and CGI get
  the same single `HTTP_COOKIE`.
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
runtimes = { ruby = "/usr/bin" }       # where site tasks find ruby, gem and bundle (also node, php, python3); root's files only; reload applies it
task_limits = { timeout = 1200, processes = 512 }   # a task's wall-clock seconds and the processes its account may have
task_network = true                    # tasks that download (gem install, rails new, bundle install) may run
trash_keep = 60                        # days a site deleted with its files stays in <sites_root>/.trash; 0 keeps entries until trash-delete
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
| `logs` | viewer | `--site NAME` (default: all sites plus the error log), `--since 3h` (`m`, `h`, `d`, `w`, seconds, or a local `YYYY-MM-DDThh:mm:ss`; default 1h), `--level error|warn|info` for the error log (default warn = error+warn), `--status 5xx|4xx|all|NNN` for access logs (default 5xx), `--limit N` (default 200, newest). Reads at most 2 MB per file from the end; `truncated` says when that cut in. A line's `source` is `error`, `access` (the server-wide `[log] access` file, which every site without an `access_log` of its own writes into, so a line there is no site's in particular) or the site's name (a file it alone writes); `--site NAME` for a site sharing the server-wide file answers `shared: true` with a note, JSON lines filtered to the site's host names, combined ones not attributable |
| `uploads` | viewer | the archives stored with `upload` (`file`, `bytes`, `uploaded`), ready for `site-install --file` |
| `trash` | admin | the sites deleted with their files, one entry each (`<domain>-<date>-<time>`): site, preset, account and whether any site still uses it, deleted and expiry times, size and file count, the pieces with their original paths; the whole is read by the helper, so 503 `busy` while a task runs |
| `site-unit NAME [--raw]` | viewer | the systemd unit that runs a Rails or Redmine site's Puma, a Django or Wagtail site's Gunicorn (section 4e), or a Node site's node (section 4f), rendered from the site and `[control] runtimes`, with the root commands that install it (`--raw` prints the unit alone, for `> /etc/systemd/system/...`); 409 for a site without its own account or a non-loopback upstream |
| `site-service NAME` | viewer | whether a Rails, Redmine, Django, Wagtail or Node site's application service runs: `agensio-app-USER.service`, derived from the site's account, read by the provisioning helper with `systemctl show` (`state`: `LoadState`, `ActiveState`, `SubState`, `Result`, `ExecMainStatus`, `MainPID`, the enter timestamps, `MemoryCurrent`, `NRestarts`, `UnitFileState`), with `summary` and `next_steps` (`site-unit` when the unit is missing, `site-service-logs` and `systemctl restart` when it failed, `systemctl enable --now` when it is stopped); 409 for a site without its own account, a non-Rails site or a server without the helper; 503 `busy` while the helper runs a task |
| `site-service-logs NAME [--lines N] [--since 3h] [--raw]` | admin | the unit's journal (`journalctl -u UNIT -n N -o short-iso`, N from 1 to 1000, 200 by default; `--since` a number and `s`, `m`, `h` or `d`), newest last, the newest 256 KB at most; every read audited; `--raw` prints the lines alone |
| `site-task-output NAME [--offset N] [--length N] [--raw]` | admin | the whole output of the site's last task (see `site-task`), up to 64 KB per call from `offset`, with `next_offset` (null at the end), `kept_all` (false when the task printed more than the 1 MB kept) and the task's name and time; 404 when no task ran since the server started |
| `site-tasks NAME` | viewer | the named tasks the site's preset offers (`app = "rails"`: seven; `"redmine"`: eight; `"django"` and `"wagtail"`: nine each, with the site's `project` and `virtualenv`; `"node"`: two, with its `entry`), each with its summary, its parameters (name, meaning, pattern, required), whether it downloads, whether the directory must be empty, its effective time limit (the row's, capped by `[control] task_limits.timeout`) and its `interpreter`: the program, whether the interpreter rule accepts it and, when not, why and the package command; `run_as_root` at the top lists every missing package once, so root installs them before the first task; the account that runs them (`runs_as`), the directory, the task running now; a site of another preset has none |
| `settings [NAME]` | viewer | the per-site limits `site-create` and `site-update` accept under `settings`: for each key its type, unit and spellings, meaning, default and its origin, minimum, the ceiling from `[control] site_limits`, what changing it costs (agensio reload, php-fpm reload) and what it derives; with a site, the current value and whether it comes from the site, the server or a built-in default. `site NAME` reports the same `settings` |
| `health` | viewer | findings with `severity`, `code`, `site`, `message`, `fix` (also `files_unreadable`: files under a document root, the preset's upload directory first, that the server's account cannot open and that answer 404 with no log line; `php_tmp_missing`; `php_fpm_hard_reload`; `php_pool_resident`, judged from the pool file php-fpm runs; `preset_mismatch`: the files under a site's directory belong to another application than its `app` says, with the application detected and the `app` to set; `archives_in_root`: backup archives and database dumps under a served tree, the directories a preset never answers excepted; `site_env_unsafe`: the site environments' directory is not root's alone, or a site's file is open to others, not root's or has a second link (checked by the helper, read-only), with the `chown`/`chmod` line; `site_env_orphan`: a deleted site's environment file, with its `rm -f`; `site_env_unchecked`: the helper was busy with a task): configuration on disk invalid or failing the hosting rules, restart-only settings changed, running as root, certificate unreadable / still the placeholder / expired / expiring within 14 days (manual), `tls = "auto"` without a plain port-80 site for the names, no http-to-https redirect, application sites sharing the server's account, generated pools out of date, errors in the last 24 hours. `ok` is true when nothing above info level was found |

**Changes** (`POST` with a JSON body; every one needs `"confirm": true`, takes a
`"reason"` that goes to the audit log, and answers 428 without the confirmation):

| command | role | what it does |
|---|---|---|
| `reload` | operator | the same as `agensio reload`: validate the file on disk, bind, switch; 409 with the reason when refused, nothing changed then |
| `logs-reopen` | operator | reopen every log file (what `SIGUSR1` does) |
| `site-create` | admin | writes `sites.d/<domain>.toml`, validates, reloads. Fields: `domain`, `aliases`, `https` (`auto`, `none`, or `{cert, key}`), `redirect_http` (default true), `hsts`, `user` (an account name; `no_user: true` or JSON `null` for none; the words null, none, nil and system accounts are refused, never turned into commands), `group`, `app`, `root`, `upstream`, `project` (app = django or wagtail: the project's Python package), `php_socket`, `php_children`, `php_version`, `listen_plain`, `listen_tls`, `rules` (an application's own server guidelines as bounded rules, below). Until `https`, `root` (or `upstream`), `app`, `user` and, for a Django site, `project` are decided it answers 422 with the open questions and a suggestion each (a user name from the domain, the app the files under root suggest); when the account or the root directory does not exist it answers 409 with the commands to run as root and waits for the same command again. A new site is HTTPS-only: the plain site redirects. |
| `site-create` answers | | 422 with `needs` while decisions are open; 409 `prerequisites missing` with `problems` (every one at once, each with a `code`, a `detail` and its `run_as_root` command: `missing_account`, `missing_group`, `root_missing`, `root_unreadable`, `certificate_missing`) plus the flat `run_as_root` list; 202 `needs_restart` when the site adds a privileged port the dropped server cannot bind by a reload (the file is written and valid, `systemctl restart agensio` serves it); 201 with `next_steps` (separate commands: `agensio pools`, then the php-fpm reload) and `warnings`. `dry_run: true` runs every check and returns the file that would be written without writing or reloading |
| `site-update NAME` | admin | the same fields on a site `site-create` wrote (the file carries its spec on its first line); a hand-written file is refused with 409, edit it yourself. `settings = {key: value}` (CLI `--set KEY=VALUE`, repeatable) sets the per-site limits: `max_body_size` (any site), and for a PHP site with its own user (a generated pool) `memory_limit`, `max_execution_time`, `max_input_time`, `children`, `pm`, `max_requests`. Each value is checked against `[control] site_limits` and refused above it naming the key, the value and the ceiling; a key outside that list (`extra`, `open_basedir`, any ini name) is refused as unknown, whatever it is. The answer's `done` lists what was written and reloaded: the site file and agensio, and the php-fpm pool and php-fpm when a pool key changed (a php-fpm reload briefly affects every PHP site unless `process_control_timeout` is set) |
| `site-disable NAME`, `site-enable NAME` | admin | renames the file to `.disabled` and back, reloads |
| `site-delete NAME [--files]` | admin | removes the file (a `.bak` stays) and sets the site's root additions file aside the same way (`<domain>.root.toml.bak`, still root's; `root_additions_set_aside` in the answer), reloads; never touches the root or the account. With `--files` (`files: true`) everything of the site goes into root's trash first (below): its directory, the account's state directory (or the site's virtualenv when another site shares the account), its access log with its rotations, its environment file, and the site file's text into the entry's manifest; refused while the site's service runs (with the `systemctl` lines for root) or when the directory is not below `sites_root`; a reload that fails afterwards puts everything back. The account is kept |
| `site-restore ENTRY` | admin | brings an entry of the trash back: every piece to its original path, the site file from the manifest, a reload; only into an empty place (refused when the site exists again, its file is there, or any original path exists and is not empty), and only with the account at the uid the files carry (else the `useradd --uid` line for root). The application's service is not restored: `site-unit` renders it again |
| `trash-delete ENTRY` | admin | removes one entry now, for good |
| `trash-expire` | admin | removes the entries older than `trash_keep` now (worker 0 does it every hour) |
| `cert-renew NAME` | operator | orders the site's automatic certificate again now |
| `upload NAME [FILE]` | operator | stores FILE (stdin by default) as `<state_dir>/uploads/NAME`, the server's own directory (0700); `PUT /v1/uploads/NAME` with the raw bytes on the socket; no `--yes`; at most `upload_max`; names are plain file names (letters, digits, `.`, `_`, `-`, no leading dot); a partial transfer leaves nothing |
| `uploads-delete NAME` | operator | removes a stored upload |
| `site-install NAME` | admin | puts an application's files into the site's directory (the `root` as given, above a preset's `public/` or `web/`; `--path SUB` for a subdirectory such as `wp-content/plugins/NAME`, with `--create-path` when it does not exist yet) **as the site's account**, from one source: `--url https://...` (a `.tar.gz`, `.tar` or `.zip`), `--file UPLOAD` (a stored upload), or nothing, which takes the preset's official archive (`presets` lists it under `source`; `--version V` picks a release, default the newest; WordPress and Drupal have one, Laravel is made with composer). `--sha256 HEX` refuses an archive whose digest differs. `--strip 0|1` keeps or unwraps a single top directory (default: unwrap when there is exactly one). `--dry-run` takes the same walk as the real call, as the same account, and answers with the target, the account and `would_create`, or with the refusal the real call would meet; nothing is downloaded or written. Answers 201 with `files`, `bytes`, `sha256`, `unwrapped`, `created` (each directory made, with owner and mode), `facts` for an install into the site's directory itself (`gemfile`, `credentials`: Rails' `config/credentials.yml.enc` or `config/credentials/production.yml.enc`, `ruby_version`: what `.ruby-version` pins), `next_steps` (for `app = "rails"`: the pinned Ruby, then `bundle_install`, `db_prepare`, `assets_precompile` and Puma; for the others the application's own setup in the browser; for every site but a static one its request-body limit), and `done` when a Rails archive without credentials got its `SECRET_KEY_BASE` generated into the site's environment (once: an existing value is kept); 409 with the reason and nothing left behind; 403 when `install = false` and a URL was given; 422 when no source can be found |
| `site-copy NAME --from SUB --to SUB` | admin | copies one regular file of the site to another path of the same site **as the site's account**: the drop-in files applications ship as templates (`wp-content/db.php` from the SQLite plugin's `db.copy`, `advanced-cache.php` or `object-cache.php` from a caching plugin, Drupal's `sites/default/settings.php` from `default.settings.php`). Both paths are relative to the site's directory and reached by the same walk as an install; `from` must be an existing regular file (no directory, no symlink); the destination's directory must exist (`site-install --create-path` makes one); an existing destination is refused unless `--overwrite`, and the answer then reports the replaced file's size and mtime. The new file gets the directory's pattern (`0640` in a `2750` directory, the execute bits when the source has them), or `0600` when it is one of the preset's credential files (`secured: true`); written under a temporary name and linked or renamed into place, so a refusal leaves nothing; the configuration is validated afterwards (see below). Never across sites, never content from the caller, never a directory, no chmod or chown. `--dry-run` runs the same checks. Answers 201 (200 when replaced) with `from`, `to`, `as`, `bytes`, `mode`, `replaced`; 409 with the reason |
| `site-task NAME TASK [--param KEY=VALUE]...` | admin | runs one named task of the site's preset **as the site's account** in the site's directory (`root`): a row of the task table, never a command line (below). `--dry-run` answers with the exact argv, the account, the directory, the environment and the limits, and runs nothing. `pip_install` (Django and Wagtail) runs only on the user's own confirmation (section 4e): ctl prints the warning and the `--yes` typed is the confirmation; without one the answer is 428 with the warning and the command. Answers 200 when the task exited 0, 409 when it failed, was stopped at its time limit or was refused, each with `argv` (what ran, the interpreter resolved), `as`, `cwd`, `env` (the site's own variables as `NAME=<site environment>`, never their values), `exit` or `signal`, `timed_out`, `duration_ms`, `summary` when the output has one (`N migrations applied`, `Bundle complete! ...`, `Default configuration data loaded.`, `public/assets holds N files`), `output` (stdout and stderr together: its last 4 KB when the task succeeded, its first 4 KB and last 12 KB when it failed, the cut marked; `truncated`, `output_bytes` and `output_kept`, the part kept for `site-task-output`), `next_steps` with root's restart line of the site's service after `bundle_install`, `db_migrate`, `db_prepare`, `plugins_migrate` or `assets_precompile`, `secured` (credential paths made private), `hint` when the failure has a known cause (Rails' "Missing secret_key_base": generate one into the site's environment; "Your Ruby version is X, but your Gemfile specified Y": a Ruby for one application, below), and `run_as_root` when the interpreter is missing; 400 for an unknown task or a parameter that does not match; 422 for a preset without tasks; 409 while another task runs on the same site |
| `site-env NAME [--reveal KEY]...` | admin | the site's environment (`app = "rails"`, `"redmine"`, `"django"`, `"wagtail"`, `"node"` or `"proxy"`): `variables` with each name, its `length` and its `fingerprint` (16 hex digits of a keyed hash: the same fingerprint means the same value), no value; a value only for each `--reveal KEY` (`?reveal=KEY,KEY` on the API), audited as `REVEALED`; `exists` false when the site has no file yet; `tightened` when the helper made the directory or the file private on the way. Every call is audited with the names it returned. 422 for a site of another preset; 409 with `run_as_root` when the directory or the file cannot be trusted |
| `site-env-set NAME [--set KEY=VALUE]... [--unset KEY]... [--generate KEY]...` | admin | changes the site's environment: `--set` adds or replaces, `--unset` removes, `--generate` puts a random secret (128 hex digits) under a name that is missing and keeps an existing one; a name in both `--unset` and `--generate` is rotated. Answers 200 with the names under `set`, `unset`, `generated`, `kept`, `absent` and `names` (every name now in the file), never a value, and the restart of the application's service as a next step; 400 for a name or value the rules refuse (below), 409 when the helper refuses |

**Application rules** (`rules`, 2026-10-01). A PHP application without a preset of its own
ships server guidelines (Kanboard: "deny `app/` and `data/`, run only `index.php` and
`jsonrpc.php`"; its `.htaccess` files say the same to Apache). A managed site under
`app = "php"` (or `"static"`) carries them as one bounded object the control plane checks
and renders into ordinary locations, so the file stays one `--explain` can show and no
hand-written location or root edit is needed:

```json
"rules": {
  "private": ["/app/", "/data/", "/libs/", "/vendor/", "/cli", "/web.config"],
  "entry_points": ["/index.php", "/jsonrpc.php", "/healthcheck.php"],
  "cache": [{"path": "/assets/", "max_age": 604800}],
  "front_controller": "/index.php"
}
```

`private` paths (a directory with a trailing `/`, or one file) answer 404 whatever exists
there, before any suffix location (`final = true`, `handler = "deny"`). `entry_points`
(PHP presets only) are the only `.php` files that run; every other `.php` anywhere under
the root is 404, never served as source (the preset's `.php` suffix location is replaced
by a denying one). `cache` (PHP and static sites) names directories served straight from
disk with `Cache-Control: public, max-age=N` (0 to a year), where nothing runs and no
source backup is served (`deny_suffixes` = the PHP endings plus `.inc`, `.bak`, `~`,
`.log`, `.sql`, `.sqlite`, `.sqlite3`, `.db`). `front_controller` (one of
`entry_points`) makes a path the site has nothing to serve for (no file, and no directory
with an index it serves: a directory whose `index.php` is not an entry point included) reach
that script with the query string (Kanboard's nice URLs, TYPO3's `/typo3/`). Every rule only narrows what the bare preset serves: a path under a private
one cannot be an entry point or cached, at most 64 private paths, 16 entry points and 16
cached directories, a path is `/`-rooted plain characters without `..`, and `/` itself is
refused. `rules` replaces the whole object (`{}` clears it); a later `app` change the rules
no longer fit is refused until they are cleared. `site-install` reports the directories an
archive's own `.htaccess` files deny whole (`Require all denied`, `Deny from all`, outside
`<Files>` blocks) as `facts.htaccess_denied` and suggests the matching `private` rule in
its next steps; agensio never reads `.htaccess` when serving and never applies the rule
on its own. On the command line: `--private PATH`, `--entry-point /x.php`, `--cache
PATH=SECONDS` (repeatable), `--front-controller /x.php`, `--no-rules`.

**Access by client address** (`rules.restricted`, 2026-10-07, section 19): on any app, a list
of `{"path": "/wp-admin", "allow": ["203.0.113.7", "@office"]}` with optional `"match":
"exact"` and `"mode": "report"`, rendered as `[[site.access]]` tables marked `# rules:
restricted`; `path` may be `/` (the whole site). `--restrict PATH=ADDR[,ADDR...]` and
`--restrict-exact` replace that list and keep the other rules, `--no-restrict` clears it;
`access-check SITE PATH ADDRESS` (MCP `access_check`) says what the rules decide for one
client before they are applied.

**Admin panels by address** (`rules.admin`, 2026-10-07, section 19): on `app = "wordpress"`
and `"drupal"`, `{"allow": ["@office"]}` with optional `"login": true` (the login page too),
`"languages": ["fr"]` (Drupal's URL prefixes, at most 16) and `"mode": "report"` restricts the
preset's administration paths, which `presets` lists as `admin_paths`, rendered as
`[[site.access]]` tables marked `# rules: admin`. Nothing restricts an admin by default.
`--restrict-admin ADDR[,ADDR...]`, `--admin-login`, `--admin-language L` (repeatable) and
`--no-restrict-admin` replace that object and keep the other rules; refused on another app,
and on a path `rules.restricted` names too.

**Passwords** (`rules.auth`, 2026-10-09, section 19b): on any app, a list of `{"path": "/"}` with
optional `"match": "exact"`, `"realm"`, `"skip_for": ["@office"]` and `"plain_http": true`, or
`{"path": "/health.html", "open": true}` for a path below a protected one that needs no
password, rendered as `[[site.auth]]` tables marked `# rules: auth` that read the site's own
users file (`users = "../auth/<site>.users"`, the control plane's). At most 16 rules; an open
rule must lie below a protected one; `skip_for` never `"any"`. Refused until the site has a
user (`site-auth-user-set` first), and on `site-create`. `--auth PATH`, `--auth-exact PATH`,
`--auth-open PATH` (repeatable) with `--auth-realm TEXT`, `--auth-skip ADDR[,ADDR...]` and
`--auth-plain-http` replace the list and keep the other rules; `--no-auth` clears it.

**Refused paths** (`rules.refuse`, 2026-10-08, section 6b): on any app, a list of
gitignore-style patterns (`"/vendor/"`, `"*.yaml"`, `"/ext/*/Resources/Private/"`,
`"/a/**/*.ts"`) rendered as the site's `refuse` key, marked `# rules`; each pattern is
compiled when the change arrives, so a bad one is answered with what to write instead (a `/`
inside without a leading one, a `?` or a brace, a percent escape), and one that would refuse
the site's index, its front controller or an entry point is refused when the change is
validated, the site keeping the rules it had. `--refuse PATTERN` (repeatable) replaces the
list and keeps the other rules, `--no-refuse` clears it. It is where an application without a
preset gets the deny rules its official server configuration lists; `path-check SITE PATH`
(MCP `path_check`, viewer) says what the site does with one path and which pattern, location,
`try_files` step or index decides it, as the server would, without fetching anything:

```
$ agensio ctl path-check cms.example.com /typo3conf/ext/news/Configuration/TypoScript/setup.typoscript
404: /typo3conf/ext/news/Configuration/TypoScript/setup.typoscript is refused by the site's refuse pattern '*.typoscript'
$ agensio ctl path-check cms.example.com /typo3/module/web/layout
runs /index.php (location /index.php (exact, fastcgi, from rules))
```

**Root additions to a managed site** (`sites.d/<domain>.root.toml`, 2026-10-02). A site the
control plane manages is regenerated by every `site-update`, so a location added to its file
by hand unmanages it (409 "hand-written or edited"). Root's freedom lives in a second file
beside it instead, which the control plane never writes or reads:

```toml
# sites.d/shop.example.com.root.toml   (root's, 0644)
site = "shop.example.com"

[[location]]
path = "/old-tracker/"
upstream = "http://127.0.0.1:9100"

[[location]]
path = "/downloads/"
alias = "/srv/downloads/"
add_headers = { "X-Robots-Tag" = "noindex" }
```

`site` names the managed site (its domain; the file name is the convention `site-show`
reports), and every `[[location]]` takes any key of section 6. The locations are parsed after
the site file's own and before the preset expands, so they count as hand-written: one at a
preset's path replaces the preset's, one with only `add_headers` joins it (section 5), and
one at a path the site file already has (a rule of this section, say) is a duplicate the
reload refuses, naming the file. `--explain` marks them `# from root:<file>`; `site-show`
reports `root_additions` (the file's path, present or not, the locations it added), so an
agent asked for what no field covers hands you this block instead of editing the managed
file. The file must be a regular file owned by the owner of the main configuration (root in
production) and writable by nobody else, or the load is refused with the line to run: the
server's own account, which writes the managed files, cannot add one. A file whose site is
disabled or deleted is kept and ignored with a warning (`-t`, the error log, health
`root_additions_orphan`); a plain `site-delete` renames it `.bak` beside the site file's
`.bak` (still root's; rename both back to return the site), and `site-delete --files`
moves it into the trash with the site, from where `site-restore` brings it back.

**What `site-task` enforces.** A task is a row of `src/services/tasks.cpp`: a preset, a
name, an interpreter (a runtime and a program in it), a fixed argument list, typed
parameters and a time limit. The caller names the task and gives parameters; no flag,
option or command comes from the caller, and a parameter that does not match its pattern
(`rails_new`'s `name`: a letter, then letters, digits and underscores; `gem_install_rails`'s
`version`: an exact 8.x release) is refused naming it, so `rails new -m URL` and every
other option are simply not expressible. The Rails rows:

| task | runs | notes |
|---|---|---|
| `gem_install_rails` | `gem install rails --no-document --version VERSION` (default `~> 8.0`) | into the account's own `<home>/gems`; downloads, compiles native extensions |
| `rails_new` | `ruby <home>/gems/bin/rails new . --name=NAME --database=sqlite3 --skip-git --skip-docker --skip-thruster --skip-ci` | the directory must be empty; installs the application's gems (Rails 8 skips its importmap, Hotwire and Solid installers without them); Kamal's files are kept because Rails 8.1 writes the production databases' paths only with them; downloads |
| `bundle_install` | `bundle install` | after a Gemfile change, or an application installed from an archive; downloads |
| `db_prepare`, `db_migrate` | `bundle exec rails db:prepare` / `db:migrate` | the production databases |
| `assets_precompile` | `bundle exec rails assets:precompile` | with `SECRET_KEY_BASE_DUMMY=1`, so an application without its master key compiles too |
| `database_config` | no program: writes `config/database.yml` from a fixed template | the database from `DATABASE_URL` in the site's environment (required first), `0600`, only when the file is missing |
| `gemfile_local` (redmine) | no program: writes `Gemfile.local` (`gem "puma"`) | only when missing |
| `load_default_data` (redmine) | `bundle exec rake redmine:load_default_data` with `REDMINE_LANG=LANG` | `lang` a language code (`en`, `pt-BR`) |
| `plugins_migrate` (redmine) | `bundle exec rake redmine:plugins:migrate` | after a plugin's install and `bundle_install` |

Every Rails task runs with `RAILS_ENV=production`, `BUNDLE_PATH=vendor/bundle` and
`BUNDLE_WITHOUT=development:test`: the gems of the application live in the project, only
the production groups are installed, and what the tasks prepared is what Puma loads with
the same environment (`docs/examples/puma.service`). `GEM_HOME` and `GEM_PATH` both name
the account's own `<home>/gems`, so a task sees the account's gems and Ruby's default gems
and never what root installed system-wide (before 0.1.0-alpha.26 a host-wide `gem install
rails` satisfied every dependency, `gem_install_rails` installed the meta-gem alone and
`rails_new` found no `rails` command; running `gem_install_rails` again completes an
account made then).

A task that needs an earlier task's result is refused before it runs, dry run included,
naming the missing file and what to run: `rails_new` needs the `rails` command
`gem_install_rails` writes into `<home>/gems/bin`, and the four bundle tasks need the
application's `Gemfile`. A task that exits 0 without leaving what the next one needs
(`gem_install_rails` without the `rails` command) answers 409 saying so, never ok.

The interpreter comes from `[control] runtimes` in root's file (`/usr/bin` by default):
the program, the file it resolves to and every directory above both must belong to root
and be writable by nobody else, and must lie outside `sites_root`; otherwise the task is
refused naming the component, so no site can put its own `ruby` in the way. A missing
interpreter is refused with the package command under `run_as_root` (Debian: `apt-get
install -y ruby ruby-dev ruby-bundler build-essential libyaml-dev`). What the interpreter
then loads from the site (the Gemfile, `vendor/bundle`, `bin/rails`) is the site's code
and runs as the site's account.

**A Ruby for one application.** An application whose Gemfile says `ruby file:
".ruby-version"` (Writebook and most applications made with Rails 7.1 or later) needs
exactly that version, and `bundle_install` stops at once with "Your Ruby version is 3.3.8,
but your Gemfile specified 3.4.7" otherwise (its answer's `hint` says what follows here).
`site-install` names the pinned version in its next steps. Root builds it once under
`/opt`, then points the key at it; a reload applies it, no restart:

```sh
apt-get install -y build-essential autoconf libssl-dev libyaml-dev zlib1g-dev libffi-dev libgmp-dev rustc
cd /usr/local/src
curl -fsSLO https://cache.ruby-lang.org/pub/ruby/3.4/ruby-3.4.7.tar.gz
sha256sum ruby-3.4.7.tar.gz                # compare with https://www.ruby-lang.org/en/downloads/
tar xzf ruby-3.4.7.tar.gz && cd ruby-3.4.7
./configure --prefix=/opt/ruby-3.4.7 --enable-shared --disable-install-doc
make -j"$(nproc)" && make install
# /etc/agensio/agensio.toml, [control]: runtimes = { ruby = "/opt/ruby-3.4.7/bin" }
agensio reload
```

`/opt/ruby-3.4.7` is root's and writable by root alone, which is what the interpreter rule
checks; `site-tasks NAME` then shows every task's interpreter under it with `ok: true`,
and the tasks run with that directory first on `PATH`, which matters because `bundle
exec rails` starts `bin/rails` through `#!/usr/bin/env ruby`. The Puma unit needs the same
directory first on its `PATH` and its `bundle` in `ExecStart` (`docs/examples/puma.service`).
`rustc` is only for YJIT; one runtime directory serves every site of the host, so sites
that pin different versions share the newest only when their Gemfiles allow it.

A task runs as the site's `user`, or for a site without one as the owner of the site's
directory when that is a site account or the server's own, the account rule of
`site-install`; never as root or a login account. With the provisioning helper the helper
looks the site up in the configuration on disk itself (its app, directory and user: the
server sends names and parameters only), creates the account's home when it is missing
(`<state_dir>/<user>`, `0700`, with `tmp/`) and runs the task in a child that has become
the account; without the helper it runs as the server's own account, in a directory that
account owns. The environment is built, never inherited: `PATH` (the runtime's directory
first), `HOME`, `TMPDIR`, `LANG=C.UTF-8`, the preset's variables, then the site's own from
its environment file (below), which never replace one of these. The working directory
is reached without following a symlink; stdin is `/dev/null`; the umask is `027` (files
`0640`, directories `2750` in the site's tree, readable by the server through its
group). Limits: `[control] task_limits` (`timeout`, 1200 s by default, after which the
task's process group gets SIGTERM and ten seconds later SIGKILL; `processes`, 512, the
`RLIMIT_NPROC` of the account while the task runs, threads included), 4096 open files,
no core files. When the program exits, whatever it left running in its process group is
killed. One task per site at a time. `[control] task_network = false` refuses the tasks
that download. The three keys apply on reload: the helper reads them from root's file for
every task (only the main file can hold `[control]`; included files carry sites alone).

After every run the credential sweep makes the preset's credential files the site's
alone: the hosting rule's list (for Rails `config/master.key`, `config/credentials/`,
`config/database.yml`, `storage/`, `.env`, `.git`) plus `config/credentials.yml.enc`,
`config/credentials/*.key`, `.env.*`, `.kamal/secrets*` and the SQLite files under `db/` and `storage/`;
files become `0600`, directories lose their group's read and write and everything for
others (`0710`: the kernel drops the set-gid bit when the account is not in the
directory's group), never through a symlink. Then the configuration is validated as for
`site-install`: a task whose result `agensio -t` would refuse answers `409` with the
validator's `errors`. The audit log gets one line before the task starts (the task and its
parameters) and one after, with the exact argv that ran, the account, the directory and
how it ended; the output stays out of it. A task keeps up to 1 MB of its output (its
first 256 KB and last 768 KB beyond that) in the server's memory until the site's next
task or a restart; `agensio ctl site-task-output NAME [--offset N] [--length N] [--raw]`
(admin, MCP `site_task_output`) reads it in slices of up to 64 KB, `next_offset` leading
to the next.

**Deleting a site with its files.** `site-delete NAME --files` (MCP `site_delete` with
`files: true`) moves everything of a site into `<sites_root>/.trash/<domain>-<date>-<time>/`,
a directory root owns alone (`0700`), so no account and not the server can read another
tenant's deleted files: the site's directory (the first directory below `sites_root` on its
root's path, `/var/www/example.com` for `/var/www/example.com/app`, unless another site's root
lies under it), the account's state directory `<state_dir>/<user>` (its gems, virtualenvs,
sessions; the site's virtualenv alone when another site shares the account), its access log
with its rotations, its environment file with its secrets, and the text of its site file in
the entry's `manifest.json`. Everything moves by rename, so nothing is copied; a piece on
another filesystem goes to a trash beside it (`<state_dir>/.trash`, `<logs>/.trash`) or, a
small file, is copied. The account is kept, because the files carry its uid and a restore
needs it; `trash` says when no site uses an account any more, for root's `userdel`. The
delete is refused while the site's application service runs (a process whose directory is
renamed keeps writing into the trash): the answer carries `systemctl disable --now` for root.
`site-restore ENTRY` puts every piece back and the site file with it, then reloads, but only
into an empty place: never over files that appeared since. Entries expire after `[control]
trash_keep` days (60 by default, applied to what is in the trash when it changes; 0 never),
removed by worker 0's hourly check or `trash-expire`; `trash-delete ENTRY` removes one now.
Without `--files` `site-delete` removes the configuration alone and leaves every file where
it is, as before. The whole is the provisioning helper's: a server started without it
answers 409 and the files are removed by hand.

**The site's environment.** An application reads settings and secrets from its
environment: a Rails application without credentials (every ONCE application such as
Writebook, every Kamal or twelve-factor deployment) reads `SECRET_KEY_BASE` there and
stops with "Missing secret_key_base" without it; others read `DATABASE_URL`, a mail
password or an API key; a Django project `DJANGO_SECRET_KEY` and its first admin's
`DJANGO_SUPERUSER_PASSWORD` (section 4e). A site with `app = "rails"`, `"redmine"`,
`"django"`, `"wagtail"`, `"node"` or `"proxy"` has one file for them,
`env/<site>.env` beside the main configuration (`/etc/agensio/env/ag6.example.com.env`),
in systemd's `EnvironmentFile` syntax (`NAME="value"` lines), which the site's tasks get
after the variables agensio sets and its application service loads
(`EnvironmentFile=-/etc/agensio/env/<site>.env` in `docs/examples/puma.service`). It is
written through the control plane (`site-env-set`, MCP `site_env_set`) and read back by an
admin (`site-env`, `site_env`) as names, lengths and fingerprints; a value is returned
only when asked for by name, because a value returned is in the agent's context and
transcript from then on:

```sh
agensio ctl site-env-set ag6.example.com --generate SECRET_KEY_BASE --set DATABASE_URL=sqlite3:storage/db/production.sqlite3 --yes --reason "Writebook"
agensio ctl site-env ag6.example.com                              # names, lengths, fingerprints
agensio ctl site-env ag6.example.com --reveal DATABASE_URL        # that one value, audited as REVEALED
systemctl restart agensio-app-ag6          # the application reads it at start; the tasks from their next run
```

The fingerprint is HMAC-SHA256 under a key kept beside the files (`env/.fingerprint.key`,
made on first use): two sites or two moments with the same fingerprint hold the same
value, and a weak password cannot be found from its fingerprint with a dictionary.

The file is root's, `0600`, in a directory root owns alone (`0700`), written and read by the
provisioning helper: systemd reads an `EnvironmentFile` as root, so a file the site's
account could replace would let it link any root-readable file into its own environment,
and the server itself cannot read it (a compromised server reads it through the helper,
as an admin can). A server started without the helper keeps the same file under its own
account instead. Names are upper-case letters, digits and `_`, never one agensio sets for a
task or one that changes which program runs or what it loads (`PATH`, `HOME`, `TMPDIR`,
`LANG`, `RAILS_ENV`, `SECRET_KEY_BASE_DUMMY`, `GEM_*`, `BUNDLE_*` other than a private gem
source's credentials such as `BUNDLE_GEMS__CONTRIBSYS__COM`, `LD_*`, `DYLD_*`, `RUBYOPT`,
`RUBYLIB`, `NODE_OPTIONS`, `NPM_CONFIG_*`, `PYTHON*`, `PIP_*`, `VIRTUAL_ENV`, `DJANGO_SETTINGS_MODULE`,
`AGENSIO_*`, `GIT_*`, `BASH_ENV`, the systemd socket variables; on a Node site also `HOST`,
`PORT` and `NODE_ENV`, which its unit sets);
values are one line of UTF-8, at most 4 KB, 128 variables in all. A file root edits by hand
is read the way systemd reads it (quoted or not, comments), but a line that goes on over
the next one or a name the rules refuse stops every task of the site with the reason. The
directory and the files must be root's: a directory open to others (a `mkdir -p` under a
lax umask) and a file others could only read are tightened by the helper, which says so
under `tightened`; a file others could write, one with a second hard link, or another
owner is refused with the `chown`/`chmod` line under `run_as_root`, and `health` reports
`site_env_unsafe`, for the directory and for each site's file (the helper checks the files
for it, read-only, since the server cannot look inside root's directory), and a deleted
site's file as `site_env_orphan`. A file others can read counts as a warning, with the
advice to rotate what it holds, when its directory is open to others too, and as info when
the directory is root's alone. Whatever closes an open directory (a task or `site_env` on
any site) makes every file in it that others could read 0600 in the same pass and records
its variables in `env/.exposed` (names and fingerprints, never values), so health keeps
warning "readable by others ... rotate them" for that site until each of those values has
changed (`site-env-set` with the new value, or `--unset` and `--generate`), and the
error log has the same warning. `site-env-set` answers `still_exposed` with what is still to
rotate; a deleted site's kept file with such values is a warning in health and named under
`exposed` in `site-delete`'s answer; entries of a name with neither a site nor a file are
pruned. Unsetting the last variable removes the file, and the
answer says so; `site-delete` names the file it keeps only when the site has one. `site-install` generates `SECRET_KEY_BASE` itself when a
Rails archive came without credentials (never for one with them: an environment value
would override the application's own secret and sign its users out); `--generate` never
replaces a value, and rotating one is `--unset NAME --generate NAME` in one call. The file
stays when the site is deleted, as the site's files do; `site-delete` names it and gives the
`rm -f` line.

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
`settings.php`, `settings.local.php`, `services.yml`; Rails' `config/master.key`,
`config/credentials/`, `config/database.yml`, `storage/`; `presets` shows them), the hosting
rule checks precisely those files plus `.env` and `.git` (Laravel: the project's `.env`,
`config/`, `storage/`), and `site-install` and `site-copy` create precisely those files
`0600` whatever the directory's pattern gives the rest, and take the group's read and
write and everything for others from those that are directories, listing both under
`secured` (before 2026-09-26 an archive that carried such a directory, `.git` for one,
could not be installed at all).
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
pools and reload php-fpm, restart the service after a change that needs one, run a
`site-install` or a `site-copy` in a child that has become the site's account (the helper
opens an upload as root, the child drops to the account before reading a byte), and run a
`site-task` the same way, after creating the account's home when it is missing. Programs
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
gets it, any other client gets HTTP/1.1 on the same port. A site may name its own
`protocols` when its listeners must differ from the server's (a TLS port kept at HTTP/1.1
next to one offering h2; the sites sharing an address must agree), and every HTTP/2
limit derives from keys you already know. The design, the
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
| `protocols` | `["h2", "h1"]` | what TLS listeners offer through ALPN, in order of preference (Caddy's names; `"http/1.1"`, the ALPN identifier, is accepted for `"h1"`). `"h2c"` in the list makes plain listeners accept HTTP/2 with prior knowledge (the connection preface; `curl --http2-prior-knowledge`, `h2load`, a backend behind a proxy). Browsers never use h2c, so it is off by default. `"h3"` adds HTTP/3 over QUIC on every TLS listener's port number, over UDP (section 17). |
| `http2.max_concurrent_streams` | 128 | streams a client may have open at once on one connection (`SETTINGS_MAX_CONCURRENT_STREAMS`, nginx's default); a stream beyond it is refused, the connection stays |
| `protocols` on a `[[site]]` | the server's | the same list for this site's listeners only: `protocols = ["h1"]` on a TLS site keeps that port at HTTP/1.1 while another offers h2, `["h2c", "h1"]` on a plain site accepts the preface there alone. Every site on an address must list the same, or `-t` refuses the file. |

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

## 17. HTTP/3

HTTP/3 (RFC 9114) over QUIC (RFC 9000) is agensio's own transport, with OpenSSL 3.5's
QUIC TLS API for the handshake and its ciphers for the packets; the design, the
comparison with the other servers and the threat model are in `docs/design-http3.md`,
the specifications in `docs/rfc/`. It is on where `protocols` lists `"h3"`, server-wide or
on a TLS site, and then every TLS listener of that list also answers on the same port
number over UDP, and every HTTP/1 and HTTP/2 answer of it carries `alt-svc` so browsers
switch on their next connection:

```toml
[server]
protocols = ["h2", "h1", "h3"]   # h2 and h1 over TCP through ALPN, h3 over QUIC on the same ports
```

What it needs from the host: UDP open on the listener's port in the firewall (the TCP
port alone gives a client nothing to reach), a build with OpenSSL 3.5 or later on Linux
(`-t` refuses `"h3"` on any other, so a configuration file moves between hosts
predictably); h2load and curl choose `--alpn-list=h3` / `--http3-only` directly, a
browser follows the `alt-svc` field. With `reuse_port` (Linux, the
default) every worker has its own UDP socket on the port and a classic BPF program on the
group delivers each packet to the worker that issued its connection id, so a connection
never changes worker (design 6.1); where the kernel refuses the program the 4-tuple hash
routes each connection to one worker instead. Without `reuse_port` one socket on worker 0
serves the listener.

The sockets ask the kernel for 4 MB receive and send buffers. Linux grants at most
`net.core.rmem_max` and `net.core.wmem_max`, 208 KB on an untuned host, and the startup
line (and the error log) then says so: `receive buffer 208 KB (raise net.core.rmem_max
for bursts of handshakes; 4 MB asked)`. A burst of handshakes larger than the buffer
loses Initials, which the clients retry after their probe timeout, one to three seconds
later (256 connections opening at once do that on loopback), so a server that expects
hundreds of connections to open together raises both limits as root and persists them:

```
sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608
printf 'net.core.rmem_max = 8388608\nnet.core.wmem_max = 8388608\n' > /etc/sysctl.d/90-agensio-quic.conf
```

The buffers are set when a socket opens: at start and at a reload that adds h3 to a
listener; a running socket keeps what it got.

Every HTTP/3 limit derives from keys you already know:

| HTTP/3 limit | comes from | value at the defaults |
|---|---|---|
| streams a client may have open on one connection (`initial_max_streams_bidi`, then `MAX_STREAMS` as they close) | `http2.max_concurrent_streams` | 128 |
| the field section limit (`SETTINGS_MAX_FIELD_SECTION_SIZE`) and a request stream's first window | `max_header_size` | 16 KB |
| the window a request body gets, and the connection's | `max_body_size`, or the site's own | up to 1 MB |
| the idle timeout (`max_idle_timeout`) and the handshake's bound | `idle_timeout` | 15 s |
| a body announced but not arriving | `body_timeout` | 60 s |
| the QPACK dynamic table a client's encoder may fill (`SETTINGS_QPACK_MAX_TABLE_CAPACITY`) and the field sections that may wait for it (`SETTINGS_QPACK_BLOCKED_STREAMS`) | fixed | 4 KB, 16 streams (each holding at most `max_header_size` of encoded section) |
| the QPACK dynamic table our answers use on the client's side (`server`, `date`, `content-type` as one index byte each after the first) | fixed, and at most what the client announces | 1 KB; none for a client that announces no table (curl) |
| the datagram size | 1,200 bytes until the path is probed after the handshake (a padded PING, outside the congestion window; acknowledged, the size is the probe's and the next probe doubles it; lost, the search stops); probed again when the client's address changes | 1,472 bytes over IPv4 and 1,452 over IPv6 on a 1,500-byte path; up to what the client announces (65,527 at most) on loopback or a jumbo-frame network |
| connection ids issued to a client, and accepted from it | fixed (RFC 9000 5.1) | 4 each; a retired id is replaced, at most 64 per connection |
| handshakes in progress per worker | fixed | 1,024; see `http3.retry` |
| stream resets a client may send per second (`RESET_STREAM`, `STOP_SENDING`) before the connection closes with `H3_EXCESSIVE_LOAD` | `http2.max_concurrent_streams` | 128 |
| protocol glitches (flow-control or stream credit that does not raise the limit) before `PROTOCOL_VIOLATION` | fixed | 100 |

The one key of its own:

```toml
[server]
http3 = { retry = "auto" }   # "auto" | "always" | "never"
```

| key | default | meaning |
|---|---|---|
| `http3.retry` | `"auto"` | whether a new client must first answer a Retry (RFC 9000 8.1.2): a stateless packet carrying a token bound to the client's address, the original connection id and the time, valid ten seconds, that the client repeats in its next Initial; the round trip proves the address before the server spends a TLS session on it. `"auto"` sends Retry once a worker has 512 handshakes in progress and drops further Initials at 1,024; `"always"` for a host under a handshake flood (every new connection pays one round trip); `"never"` for a benchmark that must not pay it. An Initial whose token does not open is answered with `INVALID_TOKEN` and forgotten |
| `http3.alt_svc` | `true` | every HTTP/1 and HTTP/2 answer of a TLS listener that also speaks h3 carries `alt-svc: h3=":port"; ma=86400`, which is how a browser learns to switch to HTTP/3 on its next connection (design 7.4); `false` removes the field, and clients that know the port (`curl --http3-only`, h2load) still connect over QUIC |

What else the transport does without a key: a client whose address changes (a NAT
rebinding) keeps its connection, the new path is validated with a `PATH_CHALLENGE`
before more than three times the bytes received on it are sent to it, and the previous
address is used again if the validation fails; a client that updates its keys (RFC 9001
6) is followed, a second update before the first is acknowledged is `KEY_UPDATE_ERROR`,
and the server updates its own keys at the AEAD's confidentiality limit; a packet for a
connection nobody here knows (a client of a server that restarted) is answered with a
stateless reset (RFC 9000 10.3), smaller than the packet, at most 1,000 per second per
worker, and the reset token of every id is derived from a per-process secret, so any
worker can answer for any id.

Requests over HTTP/3 are logged as `"GET /path HTTP/3.0"` and PHP sees
`SERVER_PROTOCOL=HTTP/3.0`; `agensio ctl status` lists `h3` among a listener's protocols.
A reload that removes h3 from a listener (or the listener itself) tells that listener's
HTTP/3 connections GOAWAY and closes them with H3_NO_ERROR, then closes its UDP sockets;
a reload that adds h3 to a TLS listener opens them. Not yet (the design's I1b to I4):
request bodies from unbuffered upstreams over h3, 0-RTT, ECN, NEW_TOKEN for later
connections.

## 18. Connection limits

**The server's part: a ceiling per worker.** `[server] max_connections` is the number of
connections one worker holds at once, TCP (HTTP/1, HTTP/2) and QUIC together. Unset (0),
it comes from the open-file limit the server raises at start: `(limit - 2048) / workers`,
never below 128, so a worker can never run itself out of descriptors (2048 are kept for the
cache's open files, the logs and the connections to php-fpm and origins). A connection
accepted above the ceiling is refused at once: a plain listener answers `503 Service
Unavailable` with `Retry-After: 2` and closes, a TLS listener closes before any handshake
work, so a flood buys no CPU. What happened is kept for whoever investigates, without a
shell: the error log line (once per worker per ten seconds) says how many connections the
worker holds and how many of those have been idle for two seconds or more, how many it
refused since the last line and since start, from which addresses (the most refused first)
and on which listener; `server_status` shows `max_connections`, `connections_refused`,
`connections_idle` and, per worker under `workers_detail`, the same addresses, listeners
and times; health reports `connections_refused` with a fix that follows from the shape:
most refusals from one address (the firewall's job, nothing to raise), workers full of
connections idle for two seconds or more (slow or stuck clients: compare with the access
log's request rate, lower `idle_timeout`), or many addresses with busy workers (raise the
limit). Set it when the derived value is wrong
for the host: smaller to cap memory (an idle HTTP/1 connection costs about 13 KB, HTTP/2
19 KB), larger only with a larger `LimitNOFILE`.

```toml
[server]
max_connections = 20000   # per worker; 0 = from the open-file limit
```

**What the server does not do: per-address limits.** Counting connections or requests per
client address across workers would cost on the accept path exactly where agensio saves
its microseconds, and the kernel already keeps that table. Put those limits where each
belongs:

- Connections and connection rate per address, SYN floods: the firewall. With nftables, a
  rule such as `tcp dport { 80, 443 } ct state new meter per-ip { ip saddr limit rate over
  30/second } drop` and `ct count over 200` per source address stop a single client before a
  byte reaches the server; your provider's DDoS protection or a CDN handles what fills the
  pipe.
- Brute force on logins and APIs (`wp-login.php`, `xmlrpc.php`, Kanboard's `jsonrpc.php`):
  fail2ban or CrowdSec reading the access log, whose combined format and escaping are
  nginx's so their stock filters apply, banning through the firewall for a while.
- Slow and idle clients, protocol abuse (HTTP/2 reset floods, QUIC address validation):
  agensio's own timeouts and budgets, which only the server can judge (sections 16 and 17).

**Shipped: the ruleset, the jails, and the check** (2026-10-02). agensio does not apply any of
this, but it renders both pieces for the host it runs on and reads back whether they are in
place. The administrator's guide to the fail2ban side, with what each application type gets
and what to add in the application, is `docs/fail2ban.md`. `agensio ctl protection` (the MCP tool `protection_show`, and `agensio protection -c
FILE` with no server running) answers with the files, root's commands and what the kernel
and fail2ban do now; `--nft`, `--jail`, `--unit` and `--filter NAME` print one file alone,
for root to redirect into place. The packaged copies under `/usr/share/agensio/` are the
rendering for ports 80 and 443 (`agensio protection --defaults`); nothing is installed into
the live firewall or into `/etc/fail2ban` by a package, ever.

*The firewall.* The ruleset lives in a table of its own, `table inet agensio`, with the
host's public ports (every listener not on loopback; QUIC's UDP port when `h3` is on): per
source address, more than 30 new connections a second are dropped (bursts of 60 allowed),
the 201st connection held is refused with a reset, and more than 50 QUIC handshakes a second
(long-header packets, the first byte's top two bits, RFC 9000 17.2) are dropped, while a
connection's data packets are never limited; IPv6 is counted per /64, one subscriber.
Nothing outside that table is touched, no other table, chain or policy, so the
distribution's firewall, a panel's rules, ufw and firewalld keep theirs and this keeps its
own, and `nft delete table inet agensio` removes every trace. Loading the file twice is
harmless (it deletes and recreates its own table). Root applies it the way network gear
does, commit-confirmed, so a mistake undoes itself:

```sh
agensio ctl protection --nft > /etc/agensio/firewall.nft          # the ruleset for this host's ports
nft -f /etc/agensio/firewall.nft                                     # in the kernel only; a reboot drops it
systemd-run --on-active=10min --unit agensio-firewall-trial /usr/sbin/nft delete table inet agensio
#   ... the site answers, this SSH session is alive, `agensio ctl protection` says covered ...
systemctl stop agensio-firewall-trial.timer                          # keep it: cancel the undo
systemctl enable --now agensio-firewall.service                      # and load it at every boot
```

`agensio-firewall.service` (packaged) is a oneshot that runs `nft -f /etc/agensio/firewall.nft`
after the distribution's firewall and before agensio; `--unit` renders it for a
configuration kept elsewhere. A manual `systemctl restart nftables` on Debian runs
`/etc/nftables.conf`, which usually begins with `flush ruleset`: `systemctl restart
agensio-firewall` puts the table back, or add `include "/etc/agensio/firewall.nft"` to that
file instead of the unit.

*fail2ban.* Jails over agensio's access logs (combined format; the filters do not read
JSON logs) and its error log, rendered for this host's logs, ports and sites: `agensio-login`
counts credentials posted to the sites' login paths, ten in ten minutes bans for an hour (a
failed and a successful login look alike in an access log, so this counts attempts: no one
types ten passwords in ten minutes, every tool does); `agensio-auth` the error log's `auth
failed` lines, the failed passwords on `[[site.auth]]` paths (section 19b), never a 401, which
is the challenge every browser meets first (until alpha.58 it counted every 401 and 403, and
so banned the people with a site's password; it needs the error log in a file at `warn`, the
package's default); `agensio-denied` bursts of 403 (an address outside an access rule, an
application refusing); `agensio-scan` bursts of 404 (forty in five minutes); `agensio-post` bursts of POST to any
path (120 in two minutes), the catch-all for a login nobody named, with an `ignore`
parameter for an API posted to that often (`filter = agensio-post[ignore="/api/|/jsonrpc\.php"]`).
Bans go through nftables into fail2ban's own table (`banaction = nftables-multiport`); a
host whose firewall is managed otherwise overrides that in a `jail.local`. The five filters
are static and shipped; the jail file carries what is the host's:

```sh
install -m 644 /usr/share/agensio/fail2ban/filter.d/agensio-*.conf /etc/fail2ban/filter.d/
agensio ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf     # this host's logs, ports, login paths
fail2ban-client reload
```

The login paths come from two places. A preset knows its application's: `wordpress`
`/wp-login.php` and `/xmlrpc.php` (one `system.multicall` tries hundreds of passwords; a
client that posts there more than ten times in ten minutes, the WordPress mobile application
without Jetpack, is banned for an hour), `drupal` `/user/login`, `laravel` `/login` and
`/cp/auth/login`, `grav` `/admin`, `redmine` `/login`, `django` and `wagtail` `/admin/login/`.
A site whose preset cannot know (`php`, `rails`, `node`, `proxy`, `static`) names its own
with `login_paths`, a `[[site]]` key the control plane also writes (`site_update`
`login_paths`, `agensio ctl site-update NAME --login-path /login`, `--no-login-paths`):
plain URL paths, at most 16, nothing served or refused by them, so an agent can set them
from the application's documentation after asking the user. An application that routes its
login through the query string is named with it, and the jail matches the query from its
start, whatever follows: Kanboard `/?controller=AuthController&action=check`, Roundcube
`/?_task=login`, phpBB `/ucp.php?mode=login`; the bare `/` is refused, since every form
post of such an application goes there. A query holds letters, digits and `._~/=&+:-`.
The jail matches each path in every spelling the server and the applications accept, since
the log holds the request as the client sent it (the alpha.44 and alpha.45 reports found
twenty spellings of the login URLs that reached the form and escaped a literal match): every
character literal or percent-encoded in either case's code, slashes and dots literal or
encoded, repeated slashes, `./` and `seg/../` segments, any case, for a PHP preset's path
an optional `/index.php` front controller before it and path info after a `.php` file, for
a Rails or Redmine path an optional `.format` suffix, and for a login routed through the
query string its parameters in any order with others allowed. Nothing more: `/index.php`
alone or with another query is no login, nor is `/admin.php` on a Grav site, so an
application's ordinary form posts are never counted. The grammar is unambiguous, so a 16 KB
request line of slashes or dot segments costs linear time whether the login path is plain or
routed through the query (the first grammars took seconds and minutes; fail2ban's regex
holds the daemon's lock while it matches, so every jail would have waited). The
rendered regex spells `%` as `\x25`, so the jail file never meets configparser's
interpolation; the separator grammar is written once, as the filter's `sep` variable that
every path refers to as `<sep>`, and a letter's two percent codes are one hex class, so a
path's entry is about a hundred characters. This is the attempt-counting tier that needs
nothing from the application.

*The failure tier.* An application that logs its own failed logins gives fail2ban the better
signal: failures, not attempts, with the client address in the line and no URL spelling to
match. Where a preset's application does, `agensio ctl protection --jail` renders a jail over
that log with the filter fail2ban or the application ships: WordPress through the WP fail2ban
plugin, which logs every failed login, form and XML-RPC, to the auth facility
(`/var/log/auth.log`, `/var/log/secure` on RHEL) and brings its own `wordpress-soft` and
`wordpress-hard` filters, rendered as `agensio-wordpress-soft` (five failures in ten minutes
ban for an hour) and `agensio-wordpress-hard` (what the plugin logs as hostile at the first
hit, a day); Drupal through its core Syslog module (`/var/log/syslog`, `/var/log/messages` on
RHEL) with fail2ban's own `drupal-auth` filter, `agensio-drupal-auth`. On a host where no
syslog daemon writes files (journald only, Debian 13's default; told by the daemons' pid
files under `/run`) the jail reads the journal instead, `backend = systemd` with a
`journalmatch` on each site account's uid (`_UID`, a field journald sets from the sender's
credentials, with Drupal's identity or the php-fpm unit beside it; never the identity alone,
which any process may claim, the alpha.49 report), so neither application needs rsyslog and
a stale file that nothing writes never passes for a log; a site without an account of its
own has no trusted field and is listed as `unidentified`, not read, until it gets one; an
account of an ordinary uid (1000 or above, a panel's web user) gets `backend =
systemd[journalflags=1]`, since journald files its lines under the user's journal, which
fail2ban reads only with that flag (`docs/fail2ban-ref/`). Each such jail is rendered enabled only when its filter file exists, and
with a syslog daemon its log too, since fail2ban refuses a configuration naming either when
missing; otherwise it is written disabled with its `needs`: the plugin installed and
activated from the WordPress admin panel and root's copy of its two filter files into
`/etc/fail2ban/filter.d/`, taken from the plugin's release rather than from the site's
directory, which the site's account can write; Drupal's Syslog module enabled under Extend;
then the jail rendered again. agensio installs no
plugin and changes no application: `site_install` of WordPress or Drupal puts those steps in
its `next_steps`, health reports `fail2ban_failures_unseen` while they are open, and
`protection_show` lists the jails under `failure_jails`. On a journald-only host, where a
jail is enabled before the application writes anything, the helper asks the journal for one
line matching the jail's own `journalmatch` from the last 30 days, `journalctl` with fixed
arguments, and the finding stays while there is none, with the application's step as
its fix (`journal_seen` in `protection_show`). The attempt tier keeps counting
meanwhile. There is one login jail per access log, `agensio-login` for the server-wide
log and `agensio-login-<site>` for a site's own, each with the login paths of the sites
writing that file, so one application's paths are not counted on another's log. `site_show` lists the effective ones. The jail file is
rendered from the sites that exist, so adding a site, a log or a login path makes the
installed file stale; health says so (`fail2ban_jail_stale`) and the two lines above
refresh it.

```toml
[[site]]
server_name = ["kanboard.example.com"]
app = "php"
login_paths = ["/?controller=AuthController&action=check"]   # where Kanboard's form posts
```

*The check.* On a host with a public listener, `health` asks the root helper (nft needs
`CAP_NET_ADMIN`, fail2ban's socket is root's) what is in place, with fixed arguments: `nft
-j list ruleset`, `systemctl show` of the two agensio units and the firewall services, and
`fail2ban-client status` per jail. The findings and their fixes: `firewall_limits_missing`
(no per-source limit on a public port in any table; a panel's or the administrator's own
counts as protection, so a host that already limits is never nagged), `firewall_limits_trial`
(loaded, the timer pending), `firewall_limits_unsaved` (loaded, not enabled at boot, or
unknowable without systemd), `firewall_quic_unlimited` (the table predates `h3`),
`fail2ban_missing` (not installed, not running, or no jail reads agensio's logs),
`fail2ban_jail_stale`, `fail2ban_filter_stale` (an upgrade changed a shipped filter and the
installed copy is the old one: the jails match what the older build matched, so the install
line comes first), `fail2ban_log_format` (JSON logs), `fail2ban_blind` (a site without
an access log), `protection_unchecked` (no helper). Nothing is reported for a host whose
listeners are all on loopback. `agensio ctl protection` shows the same with the detail: the
ports each table limits, each of agensio's rules with its hit counter, the jails with the
files they read and the addresses banned now and since start.

```toml
[control]
host_protection = "check"    # "external": a panel manages the firewall and fail2ban, findings
                             # are informational; "off": no probe, the files still render
```

*Hosting panels.* On a host a panel runs, the panel owns the firewall and fail2ban; agensio
behaves like any other service there: a jail drop-in with its filters, the shape Postfix,
Dovecot and sshd ship, which appears in the panel's fail2ban page; a firewall table that
coexists with the panel's rules; detection that counts the panel's own limits; the
renderer and the check reachable without the MCP bridge (`agensio ctl protection`, the
control API's `GET /v1/protection`, `agensio protection -c FILE` offline), so a panel that
writes the site files itself can script the install, trial step included; and
`host_protection = "external"` to say the panel has it.

## 19. Access by client address

A path, or a whole site, answered only to some client addresses: an administration area kept
to the office or the VPN, a staging copy kept to the team. Everyone else gets `403` with the
address the server saw.

```toml
[addresses]                      # top level of the main file: named sets, root's
office = ["203.0.113.7", "2001:db8:5::/64"]
vpn    = ["10.8.0.0/16"]

[[site]]
server_name = ["shop.example.com"]
app = "wordpress"
root = "/srv/www/shop.example.com/web"

[[site.access]]
path = "/wp-admin"               # /wp-admin, /wp-admin/ and everything below; never /wp-administrator
allow = ["@office", "@vpn"]

[[site.access]]
path = "/wp-login.php"
match = "exact"                  # this path alone
allow = ["@office", "@vpn"]
```

**What a rule covers.** A rule on a directory's index file holds at the directory too: `/`
answering with `/index.html` is judged as a request for `/index.html` (alpha.55). A prefix rule covers its path and everything below it on a segment
boundary, in any capitalisation (some filesystems and applications answer `/WP-ADMIN/` with
`/wp-admin/`); `match = "exact"` covers the path alone; `path = "/"` covers the whole site. The
longest rule that covers a path decides, and rules never merge: `allow = ["any"]` on a longer
path reopens it below a restricted one. Every rule is an allow list, so nothing is open by
omission, and an empty list is an error rather than "everyone" or "no one".

**Why it is not a location key.** The rules are checked on the normalised path after the site
is found and before any location is chosen, so whichever location would serve the request (a
`.php` suffix location, a proxy, a static file, a `try_files` fallback) is covered. In nginx,
`allow`/`deny` inside `location /wp-admin/` does not protect `/wp-admin/admin.php`, because the
`location ~ \.php$` regex wins that request; that trap cannot happen here. The other ways an
application may read the same path are judged too: a `;parameter` in a segment (Tomcat and
Jetty read `/x/..;/admin/` as `/admin/`), a percent sign left after decoding (an origin that
decodes twice), and the path after a script (`/index.php/admin` reaches the route `/admin` of
a front controller).

**WordPress.** Its public pages call `/wp-admin/admin-ajax.php` (search, carts, comment
forms), and the login page loads its styles, scripts and logo from `/wp-admin/css/`,
`/wp-admin/js/` and `/wp-admin/images/` (WordPress's `script-loader.php`; WooCommerce's
account page takes the password meter from there too), so when `/wp-admin` is restricted and
the whole site is not, the preset keeps that file and those three directories open to anyone
(`agensio -t --explain` shows the rules, `# from preset:wordpress`). They hold WordPress's own
static files, the same on every installation, and the preset runs no script there (section
4), so the openings serve files and nothing else. Write your own rule for one of those paths
to change that.

**Admin panels.** A site's administration is open to everyone by default, as WordPress and
Drupal ship it: their own login, the fail2ban jails (section 18) and the firewall's limits
protect it, and agensio never restricts it on its own. Keeping it to some addresses is the
site owner's choice, one field on a managed WordPress or Drupal site, `rules.admin` (section
15):

```json
"rules": {"admin": {"allow": ["@office", "2001:db8:5::/64"]}}
```

renders the preset's administration paths as `[[site.access]]` tables marked `# rules:
admin`. WordPress: the prefix `/wp-admin` (with the openings above), and with `"login": true`
the exact `/wp-login.php`. Drupal: the prefix `/admin`, the scripts `/update.php`,
`/core/install.php`, `/core/authorize.php` and `/core/rebuild.php`, and with `"login": true`
the prefix `/user/login`; `"languages": ["fr", "pt-br"]` adds `/fr/admin`, `/fr/user/login`
and so on for a site that negotiates the language by URL prefix, because Drupal answers its
routes under every prefix and a rule on `/admin` alone would leave `/fr/admin` open. `"mode":
"report"` tries it first. The presets catalogue (`agensio ctl presets`, MCP `presets_list`)
lists each preset's `admin_paths`, the login one marked. Two things the login rule does not
cover: WordPress also accepts a password at `/xmlrpc.php` (the mobile app and Jetpack use it;
restrict it with `rules.restricted` when nothing does), and a Drupal "User login" block placed
on public pages posts to those pages (remove the block when the login is restricted).

**Which address.** The connection's peer, or behind `[server] trusted_proxies` the forwarded
client (section 10). An IPv4 client of a `[::]` listener is matched as IPv4. Behind a CDN or
another proxy that is not in `trusted_proxies`, every request comes from the proxy: a rule
without its ranges refuses everyone, one with them admits everyone. Put the proxy in
`trusted_proxies` and allow the clients. "Only my CDN may reach this origin" is a different
need: the firewall's (section 18), on the peer, with authenticated origin pulls when it must
mean "through my account".

**The answer.** `403 Forbidden`, with `Cache-Control: no-store` (it differs per client) and a
line naming the address that was tested, so a user whose address changed can say which one the
server saw. The error log gets one `warn` line a second per worker, `access refused: site S
rule /wp-admin allows @office; client 198.51.100.4 GET /wp-admin/`; the refusals held back are
counted, `(N more refusals since the last such line, not written)`, written with the next line
or on its own once the second is over. The access log has every 403 with its client as usual,
and the `agensio-denied` fail2ban jail (section 18) bans an address that keeps hitting a
restricted path from outside.

**Trying a rule first.** `mode = "report"` serves everyone and logs `access would refuse:`
for each client the rule would refuse: every rule and client once a minute, whatever else is
refused, with the requests it made since its last line; past 16 new clients a second per worker
the rest are counted on a closing line. `agensio ctl access-check SITE PATH ADDRESS` (MCP
`access_check`) answers what the rules decide for one client without sending a request:
`refused by /wp-admin (allow @office): 198.51.100.4 is in none of its entries`. Check your own
address before you restrict a path you use.

**Managed sites.** `site_update` takes the same rules as `rules.restricted` (section 15):
`[{"path": "/wp-admin", "allow": ["@office"]}]`, with optional `"match": "exact"` and `"mode":
"report"`; `agensio ctl site-update SITE --restrict /wp-admin=@office,203.0.113.7` (and
`--restrict-exact`, `--no-restrict`) changes that list and keeps the site's other rules, and
`--restrict-admin @office,203.0.113.7` (with `--admin-login`, `--admin-language fr`,
`--no-restrict-admin`) does the same for `rules.admin`. A path in both lists is refused, and
together they hold at most 32 rules. `site_create` and `site_update` answer with the notes
`-t` would give for the new rules (`access: ...`). The
sets themselves are root's, in the main file; `config_reference` (MCP and `agensio ctl
reference`) shows each with its entries under the key `addresses`, and the trusted proxies'
ranges under `trusted_proxies`. The MCP server's instructions tell an agent to check the user's
own address with `access_check` before it applies a rule, and where refusals appear
(`logs_query`).

**What `-t` and health say.** An `allow` entry that holds a trusted proxy (a request the proxy
sends without `X-Forwarded-For` would pass), a loopback entry while no local proxy is trusted
(a tunnel such as cloudflared would make every client pass), a list of IPv4 addresses on a site
that listens on IPv6 too, a single IPv6 address (privacy addresses change daily: allow the
`/64`), and a whole site restricted (meant for staging). Refused outright, so the server does
not start or reload with them: an unknown key in `[[site.access]]` (a misspelt key would leave
the path open), an empty list, an unknown set, a zone id and an unnormalised path.

**Limits and cost.** At most 32 rules a site and 64 addresses a rule once the sets are
expanded; a longer list (a country, a cloud's ranges) belongs in the firewall, which keeps such
tables in the kernel. Deny lists are not offered: blocking one address is the firewall's and
fail2ban's job (section 18), and allow lists cannot be misread. A site without rules pays one
test per request; on a site with rules a path no rule can cover pays one bit test, and the
client's address is read only when a rule covers the path. Lists change with `agensio reload`,
which drops no connection.

A server older than 0.1.0-alpha.52 ignores `[[site.access]]` without a word: after an
upgrade, check with `agensio -t --explain` that the rules are listed.

## 19b. Passwords: `[[site.auth]]`

A password in front of a path: a staging site, an admin area, a tool without a login of its
own. The rules sit beside the access rules and are matched the same way, before any location
is chosen.

```toml
[addresses]
office = ["203.0.113.0/24"]

[[site]]
server_name = ["staging.shop.example"]
app = "wordpress"
root = "/srv/www/staging.shop.example/web"
tls = "auto"

[[site.auth]]
path = "/"                                              # the whole site
users = "/etc/agensio/auth/staging.shop.example.users"
realm = "Shop staging"
skip_for = ["@office"]                                  # the office gets in without a password

[[site.auth]]
path = "/api/health"
match = "exact"
open = true                                             # no password for the monitor
```

The user file is htpasswd's format, so a file made with `htpasswd -B` works as is, with two
optional fields after the hash:

```
anna:$y$j9T$...:expires=2026-10-22:note=Anna, Acme (client review)
dev:$2y$12$...:note=Our developer
old:!                                                   # a locked user
```

From the `expires` date (UTC) the user is refused even with the right password; `note` says
whose login it is, in `--explain`, `site_show` and the log lines. Accepted hashes: yescrypt
(`mkpasswd -m yescrypt`, Debian's default), bcrypt (`htpasswd -B -C 12`), sha512crypt,
sha256crypt, scrypt. Refused at load, with the command to use instead: MD5 (`$apr1$`, `$1$`,
htpasswd's old default), `{SHA}`, `{SSHA}`, `{PLAIN}` and DES. The file belongs to the owner
of the main configuration (root), is not writable by group or others and not readable by
others (`chmod 640`, the server's group may read it), and is read at load and at every
reload. On a WordPress site, a protected `/wp-admin` keeps `admin-ajax.php` and the login
page's own css, js and images open, as the access rules do. A build of agensio without
libxcrypt refuses a configuration with `[[site.auth]]` instead of leaving the paths open.

**Making a user file.** `agensio passwd anna >> /etc/agensio/auth/staging.users` asks for the
password twice at a terminal (or reads one line from stdin) and prints `anna:$y$...` (yescrypt;
`--method bcrypt --cost 12` or `--method sha512` for the others), so no Apache tools are
needed; append `:expires=` and `:note=` by hand.

**What a request meets.** The checks run in this order before any location: `refuse`, the
access rules, then the password. A client in `skip_for` goes on without one. Over plain HTTP
the browser would send the password in clear, so a request that is not on TLS, not from this
host and not forwarded as https by a trusted proxy is never asked: it gets `403` with a page
that says to use https, unless the rule says `plain_http = "allow"`. Otherwise:

- no `Authorization`: `401` with `WWW-Authenticate: Basic realm="...", charset="UTF-8"` and
  `Cache-Control: no-store`; the same page for a malformed, a wrong and an unknown login;
- a login this worker verified in the last five minutes (or until the user's expiry, if that
  comes first): served at once, for the cost of one HMAC;
- any other login: verified on a small pool of threads while the request waits, never on the
  worker's loop; at most eight at a time per worker, `503` with `Retry-After: 1` beyond. An
  unknown user is checked against a real entry of the file, so the answer takes the same
  time and does not tell which users exist. A failure is never remembered.

A changed password takes effect at the next reload; the old one stops working at once, since
what a worker remembers is keyed by the stored hash too.

**What the application and caches see.** PHP gets `REMOTE_USER` and `AUTH_TYPE = Basic`;
`credentials = "pass"` (the default on a site that runs PHP: WordPress's loopback calls need
it) also leaves `Authorization` in, `"strip"` (the default elsewhere) takes it out, so a
proxied application never receives the site's password. `forward_user = "X-Remote-User"` on a
proxy sends the verified name in that field, the client's own copy removed first. Every answer
on a protected path is one no shared cache may keep: a file agensio serves carries
`Cache-Control: private` in place of a preset's `public`; an answer of PHP, CGI or a proxied
application has `public`, `s-maxage` and `proxy-revalidate` removed from its `Cache-Control` and
`private` added, its other directives kept (`max-age`, `no-store`), and the fields only CDNs act
on dropped (`CDN-Cache-Control` and every `*-Cache-Control` targeted field, `Surrogate-Control`,
`Edge-Control`: a CDN follows those over `Cache-Control`, RFC 9213 2.2). This holds for a client
let in by `skip_for` too, whose request carries no `Authorization` and so gets no protection from
the cache's own rule for authenticated requests (RFC 9111 3.5).

**Logs.** The access log's user field (`%u`, the third field) is the verified user, `-`
otherwise, never a name a refused request claimed (JSON: `"user"`). Each failed login is one
`warn` line, the client first so a name the client chose cannot pass for another address:
`auth failed: client 198.51.100.4 site shop.example realm "Shop staging" user "anna" (wrong
password) GET /`. The reasons are `wrong password`, `unknown user`, `expired`, `locked user`
and `malformed credentials`; the challenge itself, which every browser meets before it sends
a login, writes nothing. The `agensio-auth` fail2ban jail (section 18, `docs/fail2ban.md` 2c)
counts these lines but `expired`, a right password: ten in ten minutes ban the address for an
hour; it reads the error log, so that must be a file at `warn` (the package's default; health
says `fail2ban_auth_unseen` otherwise). `status` reports `auth_verifications`, the hashes run
since the start.

**A managed site's users.** The control plane keeps one users file per managed site,
`<directory of the main configuration>/auth/<site>.users`: root's, the server's group, `0640`,
in a `0750` directory of root's, written by the provisioning helper through a temporary file
and a rename (a server started without the helper writes its own, under its own account). The
site's account can neither read it nor replace it, and the loader's checks above hold for it.

```sh
agensio ctl site-auth-user-set shop.example anna --generate --expires 2026-10-22 --note 'Anna, Acme' --yes --reason "client review"
agensio ctl site-auth-user-set shop.example bob --prompt --yes --reason "own password"   # asks here, sends only the hash
agensio ctl site-auth-user-set shop.example anna --lock --yes --reason "review over"     # --unlock gives the password back
agensio ctl site-auth-users shop.example                                                 # names, methods, expiry, notes; no hash
agensio ctl site-auth-user-delete shop.example bob --yes --reason "left"
```

A password never travels to the server. `--generate` has the server make one (sixteen
lower-case letters and digits in four groups, `xxxx-xxxx-xxxx-xxxx`, without `0`, `1`, `l` or
`o`: 80 bits, easy to read out) and answer it once; it is kept nowhere and a lost one is
replaced, never recovered. `--prompt` asks on the terminal where `agensio ctl` runs (twice, not
echoed; or one line of stdin), hashes it there with yescrypt and sends the hash. The MCP tools
`site_auth_users`, `site_auth_user_set` and `site_auth_user_delete` do the same for an agent,
which can only generate: it never receives a password the user typed, and the bridge drops a
hash it tries to send. Every call is admin only and audited with the user's name and what
changed, never a password or a hash. When a `[[site.auth]]` rule reads the file, a change
reloads the server, so it applies to the next request, and the last user of the file is kept
(lock it instead). A hand-written site is refused: its rules name their own files, which root
keeps with `agensio passwd`.

**A managed site's rule.** `site_update` with `rules.auth` (section 15) writes the rules into the
site file as `[[site.auth]]` tables reading the site's own users file:

```sh
agensio ctl site-auth-user-set shop.example anna --generate --yes --reason "staging"         # the first user
agensio ctl site-update shop.example --auth / --auth-realm "Shop staging" --auth-skip @office \
    --auth-open /health.html --yes --reason "staging behind a password"
agensio ctl path-check shop.example /cart        # names the rule; auth_note says what a request meets
agensio ctl site-update shop.example --no-auth --yes --reason "goes public"
```

The rule is refused until the site has a user: a rule whose users file is missing or empty
would make the next load refuse the whole configuration, so the answer names the command for
the first user instead. `site-create` refuses `rules.auth` altogether: a site gets its first
user, then its rule. `site_show` lists every rule in force (`auth`, with `from`: `rules`,
`preset:wordpress` or nothing for a hand-written one), its users file, `users_count` and
`usable` (who can log in now); the names are `site-auth-users`'. Deleting the site with its
files moves the users file into the trash with the rest, and a restore brings it back; deleting
it without its files leaves the file, which health then reports, and `site-create` under the
same name warns that it exists.

**What health says.** For every users file a rule reads (hand-written sites too):

| code | severity | when |
|---|---|---|
| `auth_users_unloadable` | error | the next load would refuse the file (gone, a symlink, another owner, a wrong mode, a line it cannot read): a reload is refused and a restart does not start the server, while the running one still asks with the users it loaded |
| `auth_no_valid_user` | warn | every user of the file is locked or expired: every login fails and the browser keeps asking |
| `auth_users_expired` | info | users past their `expires` |
| `auth_plain_http` | warn | a rule with `plain_http` on a listener the network reaches |
| `auth_users_orphan` | info | a file under `<config dir>/auth/` no site owns: a site created again under that name with a rule would let its users in |

The reference rows (`agensio ctl reference`, `docs/keys.md`) give every key; `docs/auth.md` is
the whole feature in one place, with its edge cases.

