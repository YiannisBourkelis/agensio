# Basics: static sites, HTTPS, headers, logs

Recipes for the first jobs on a new host: a site from a directory, HTTPS with a certificate
agensio obtains itself or one you bring, one canonical host name, cache and security headers,
several sites on one address, logs per site, larger uploads and pre-compressed files. Every
other recipe of the cookbook builds on these; the port-80 site that sends visitors to https,
which the other recipes leave out, is the one in the second recipe. The
[cookbook's index](../examples.md) says how a recipe is laid out and how to apply one.

## A static site

**When:** a directory of HTML, CSS, images and scripts, nothing that runs on the server. The
smallest configuration that serves something.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]   # one file per site

[server]
user = "agensio"               # started as root: bind the ports, open the logs, then run as this account

[log]
access = "/var/log/agensio/access.log"
error = "/var/log/agensio/error.log"
```

```toml
# /etc/agensio/sites.d/example.com.toml
[[site]]
server_name = ["example.com", "www.example.com"]   # the Host names this site answers
listen = ["0.0.0.0:80"]
root = "/var/www/example.com/web"

[[site.location]]
path = "/.well-known/"         # security.txt and app links: served although the name starts with a dot
hidden_files = true
```

**What it does.** A request for either name on port 80 is served from the root: `/` gets
`index.html` (the default `index`), `/docs` answers `301` to `/docs/`, a directory without an
index file is `403`, a missing file `404`. Files and directories whose name starts with a dot
(`.env`, `.git/`) are `404` whatever exists, which is why `/.well-known/` needs a location of
its own; the certificate validation under `/.well-known/acme-challenge/` does not, agensio
answers it itself. GET, HEAD and OPTIONS are served, anything else gets `405` with `Allow`.
Files up to 4 MB are held in memory and larger ones streamed, a changed file shows within a
second, and Range requests work. A Host no site lists gets `421` (see the catch-all recipe
below). The package installs this main file (with a `[control]` table for `agensio ctl`) and a
`sites.d/default.toml` that answers every other name on port 80 from `/var/www/html`; delete
that file once your own sites are in place.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml && agensio reload
curl -sI http://example.com/ | head -1                # 200
curl -sI http://example.com/.env | head -1            # 404, whatever exists
agensio ctl path-check example.com /docs              # 301 to /docs/: a directory
```

**On a managed site.** `site-create` writes the site file; with `--https auto` instead of
`none` it is the next recipe:

```sh
agensio ctl site-create --domain example.com --alias www.example.com --app static --root /var/www/example.com/web --user example --https none --yes --reason "new site"
```

**MCP:** `site_create` with `domain`, `aliases`, `app` `"static"`, `root`, `user` and `https`
`"none"`.

**Reference:** [Static site](../configuration.md#1-static-site),
[Locations](../configuration.md#6-locations-the-reference).

## HTTPS with a certificate agensio obtains itself

**When:** the site's names resolve to this host and port 80 is reachable from the internet.
This is the HTTPS every other recipe assumes, and the port-80 site below is the one each of
them leaves out.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }   # the CA's contact for expiry warnings; enables tls = "auto"
# while testing, the CA's staging service (no rate limits, a chain browsers do not trust):
# acme = { email = "admin@example.com", directory = "https://acme-staging-v02.api.letsencrypt.org/directory" }
```

```toml
# /etc/agensio/sites.d/example.com.toml
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https"             # 301 to the same host and path over https; needs no root

[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = "auto"                   # one certificate for every name above, obtained and renewed by agensio
```

**What it does.** On port 80 every request gets a `301` to `https://` with the same host (its
port dropped), path and query. The CA's validation requests, `/.well-known/acme-challenge/...`,
are answered by agensio before any site or location rule, so the redirect never gets in their
way. At the first start a self-signed placeholder lets the TLS listener come up and an order is
placed at once; the certificate replaces the placeholder through a reload, with no connection
dropped. Once an hour the certificates are checked and renewed when a third of their lifetime
is left; a failed order is logged with the CA's reason and tried again an hour later while the
current certificate keeps serving. No client to install, no cron job, no reload hook. The key
and the chain live in `/var/lib/agensio/acme/<first server_name>/`, the one tree to back up.
Easy to get wrong: every name in `server_name` must resolve here, since the CA fetches the
challenge for each; wildcard names and hosts without port 80 need DNS-01 or TLS-ALPN-01, which
this release does not have; adding a name orders a new certificate at the next reload. To keep
plain http serving the site too, give the port-80 site the same `root` instead of `redirect`.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml && agensio reload
agensio ctl logs --since 10m                          # "acme: certificate issued for example.com", or the CA's reason
agensio ctl sites                                     # each certificate: issuer, names, days left, still the placeholder or not
curl -sI 'http://example.com/a?b=1' | grep -i location   # https://example.com/a?b=1
agensio ctl health                                    # tls = "auto" without a port-80 site, no redirect, certificate problems
```

**On a managed site.** `site-create` writes both sites; `[server] acme` must already be in the
main file, root's, or `--https auto` is refused. `--no-redirect` keeps the plain site serving.

```sh
agensio ctl site-create --domain example.com --alias www.example.com --app static --root /var/www/example.com/web --user example --https auto --yes --reason "new site"
agensio ctl cert-renew example.com --yes --reason "order again after the DNS fix"
```

**MCP:** `site_create` with `https` `"auto"` (`redirect_http` false keeps plain http serving);
`sites_list` for the certificate's state; `cert_renew` to order again now.

**Reference:** [Automatic certificates](../configuration.md#automatic-certificates),
[HTTPS only](../configuration.md#https-only).

## HTTPS with certificate files you manage

**When:** the certificate comes from elsewhere: a commercial or company CA, an ACME client you
already run, a host without port 80.

```sh
install -d -m 750 -o root -g agensio /etc/ssl/example.com
cp fullchain.pem privkey.pem /etc/ssl/example.com/
chown root:agensio /etc/ssl/example.com/privkey.pem && chmod 640 /etc/ssl/example.com/privkey.pem
```

```toml
# /etc/agensio/sites.d/example.com.toml
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https"

[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = { cert = "/etc/ssl/example.com/fullchain.pem", key = "/etc/ssl/example.com/privkey.pem" }
```

**What it does.** A client that asks for one of the site's names gets this certificate;
`fullchain.pem` is the certificate first, then the intermediates, in PEM. `agensio -t` refuses
the configuration when either file is missing. The certificate must cover every name in
`server_name`: a request for a name it does not cover is answered `421`. Nothing watches the
files: a renewed certificate is read on the next `agensio reload`, which your ACME client's
renewal hook should run. That reload reads the files as the account the server runs as, not as
root, so a key only root can read works at start and then is not read again: each reload sets
the site aside and keeps serving the certificate loaded at start (`the certificate loaded before
keeps serving` in the error log, the file in health) until it expires, while the other sites'
changes apply; hence the group read above. Before 0.1.0-alpha.63 that refused every reload. Sites with automatic and with managed
certificates share one listener.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml && agensio reload
agensio ctl sites                                     # the site's certificate: issuer, names, days left
agensio ctl health                                    # warns 14 days before a managed certificate expires
openssl s_client -connect example.com:443 -servername www.example.com </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
```

**On a managed site.** The files must exist first:

```sh
agensio ctl site-create --domain example.com --alias www.example.com --app static --root /var/www/example.com/web --user example --cert /etc/ssl/example.com/fullchain.pem --key /etc/ssl/example.com/privkey.pem --yes --reason "certificate from our CA"
```

**MCP:** `site_create` or `site_update` with `https` = `{"cert": "/etc/ssl/example.com/fullchain.pem", "key": "/etc/ssl/example.com/privkey.pem"}`.

**Reference:** [TLS](../configuration.md#14-tls),
[Which site answers a request](../configuration.md#1b-which-site-answers-a-request).

## One canonical host

**When:** the site should live at one name, `www.example.com` here, and the other name should
send visitors and search engines there with a single redirect.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/example.com.toml
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https://www.example.com"   # a prefix: the path and query are appended

[[site]]
server_name = ["example.com"]
listen = ["0.0.0.0:443"]
tls = "auto"                           # browsers check the certificate before they follow any redirect
redirect = "https://www.example.com"

[[site]]
server_name = ["www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = "auto"
```

**What it does.** `http://example.com/x?y`, `http://www.example.com/x?y` and
`https://example.com/x?y` all answer `301` to `https://www.example.com/x?y`, one hop each. The
bare name's TLS site has a certificate of its own, since a browser verifies it before it reads
the redirect; it serves nothing else. Swap the names to make the bare name canonical. A domain
you moved away from takes the same two redirecting sites with the new host as the target.
`redirect = "https"` (same host) is refused on a TLS site because it would loop; a prefix
naming another host is fine there, and a prefix with a path (`https://www.example.com/blog`) is
refused. Browsers keep a `301`, so try the target before you publish the change.

**Check it.**

```sh
curl -sI 'http://example.com/x?y=1' | grep -i location      # https://www.example.com/x?y=1
curl -sI 'https://example.com/x?y=1' | grep -i location     # the same
curl -sI https://www.example.com/ | head -1                 # 200
```

**On a managed site.** No field makes a redirecting host. Create the canonical name as the
managed site, then write the bare name's two redirecting sites by hand in a file of their own,
`sites.d/example.com.toml`, its port-80 site listing `example.com` alone (the managed site
already redirects `http://www.example.com`):

```sh
agensio ctl site-create --domain www.example.com --app static --root /var/www/example.com/web --user example --https auto --yes --reason "canonical www"
```

**Reference:** [HTTPS only](../configuration.md#https-only), where the same shape is explained.

## Several sites on one address, and the catch-all

**When:** one host serves several domains on the same ports, and you decide what a request for
any other name, or for the bare IP address, gets.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/example.com.toml
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https"

[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = "auto"
```

```toml
# /etc/agensio/sites.d/docs.example.com.toml
[[site]]
server_name = ["docs.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https"

[[site]]
server_name = ["docs.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/docs.example.com/web"
tls = "auto"                   # a certificate of its own, chosen by the name the client asks for
```

```toml
# /etc/agensio/sites.d/default.toml: replaces the package's catch-all
[[site]]
server_name = ["*"]            # every Host no other site on this address lists, and requests by IP address
listen = ["0.0.0.0:80"]
redirect = "https://www.example.com"
```

**What it does.** A request goes to the site that lists its Host, compared without regard to
case and without the port. Each site on the TLS port presents its own certificate, picked by
the name the client sends (SNI). A name no site lists is not served by whichever site happens
to come first. On port 80 it reaches the catch-all, here a redirect to the main site, and
without a catch-all it gets `421` with `Cache-Control: no-store`, so forged Host headers never
reach an application. On port 443 the handshake for an unknown name ends with
`unrecognized_name` and no other site's certificate is ever shown; a connection opened for one
certificate's names answers `421` for any other Host. A catch-all is `server_name = ["*"]`, or
`default = true` on a site that also lists its names, one per address: a second catch-all, or a
name two files claim on one address, sets one of the files aside (the next recipe). The package's
`sites.d/default.toml` is one (it serves `/var/www/html`), which is why this file takes its
name. On the TLS port a catch-all serves only clients that send no name, since an unknown name
ends the handshake, and `tls = "auto"` cannot have `*`. Monitors that check the bare address
need a catch-all or the host name.

**Check it.**

```sh
agensio ctl status                                          # each listener and its catch-all site, or null
curl -sI http://203.0.113.10/ | grep -i location             # by address: https://www.example.com/
curl -sI -H 'Host: other.example.com' http://203.0.113.10/ | grep -i location   # the same
curl -sI https://docs.example.com/ | head -1                 # 200 with docs.example.com's own certificate
```

**On a managed site.** Each `site-create` writes one domain's file with both sites, and warns
when it adds the first site to a listener without a catch-all. A catch-all that redirects stays
a hand-written file: no field of `site-create` sets a redirect target.

**MCP:** `server_status` names each listener's catch-all site; `sites_list` marks it.

**Reference:** [Which site answers a request](../configuration.md#1b-which-site-answers-a-request).

## A mistake in one site's file

**When:** a host with many sites, one file each under `sites.d/`, and an edit to one of them
goes wrong: a misspelt key, a broken TOML line, a name another site already answers on the same
address, a root additions file left writable by its group. You want the other sites untouched
and the mistake named.

**What it does.** Each file under `sites.d/` loads on its own; the main file
(`agensio.toml`) is still all or nothing. A file that does not load is set aside with all its
sites, and everything else loads:

- at start its sites are not served and the server starts with the others, so a reboot never
  takes the whole host down for one file (the packaged unit runs `agensio -t` first, which
  warns and passes);
- on reload a file whose sites were being served keeps serving the version that loaded before,
  and the other files' changes apply, certificate renewals included; fix the file and reload;
- a site whose root additions file or password users file does not load is set aside whole,
  never served without the rule that protected part of it;
- a site with its own account (`user`) that breaks a hosting rule (a root others can write
  into, a credential file readable by others, a socket of another account) is set aside too;
  on reload it keeps its running version only when that version passes the rules, so a root
  opened to others while it serves takes that site down until it is fixed (health
  `hosting_rule`, with the `chown` or `chmod` to run);
- when two files claim one name (or both a catch-all) on one address, the one already serving
  keeps it and the other is set aside; at start the later file in alphabetical order yields;
- a name stays with its file while the file is set aside: a duplicate that yielded to it does
  not take the name over at the next start without its rules, the name answers `421` until the
  file loads.

Each file set aside is a line in the error log at every start and reload and an error in
health (`site_file_held_back`) with the loader's own message, for example `unknown key 'refsue'
(did you mean 'refuse'?)`, and whether the old version still serves.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml            # exit 0: "warning: ... set aside, its sites not loaded: ..."
agensio -t --strict -c /etc/agensio/agensio.toml   # exit 1 for the same, for scripts and CI
agensio ctl health                                 # site_file_held_back: the file, the error, what serves meanwhile
agensio ctl validate                               # held_back: what the next reload would set aside
```

**On a managed site.** The tools never leave a managed file set aside: `site-create`,
`site-update` and `site-enable` reload with their own file required to load, and when it would
not they undo the change (a new file removed, the previous version put back) and answer with
the loader's error. A hand-written file or a root additions file is fixed by root, then
`agensio reload`.

**MCP:** `health_check` and `config_validate` name each file set aside; `reload` lists them in
its answer.

**Reference:** [One broken site file never stops the others](../configuration.md#12c-one-broken-site-file-never-stops-the-others).

## Long cache lifetimes for assets, and HSTS

**When:** the site's build writes assets with a content hash in the name
(`app.3f9a1c2b.js`), so a browser may keep them for a year, and the site is on HTTPS for good.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/example.com.toml
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https"

[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = "auto"

[[site.location]]
path = "/"                     # path and add_headers only: joins the location the site already has here
add_headers = { "Strict-Transport-Security" = "max-age=31536000" }

[[site.location]]
path = "/assets/"              # a location's fields are its own: repeat HSTS here to keep it on every answer
add_headers = { "Strict-Transport-Security" = "max-age=31536000", "Cache-Control" = "public, max-age=31536000, immutable" }
```

**What it does.** The fields are added to the answers that serve a file, a `304` revalidation
included; error pages carry none. A request is served by one location, the longest prefix that
matches, and gets that location's fields only: without the repeat, files under `/assets/` would
carry no HSTS. `immutable` belongs only on names that change when the content does; give other
directories a short `max-age`, or nothing. HSTS is never added on its own: once a browser has
seen it, it refuses plain http for that host until `max-age` runs out, so add it when https is
known to work, and `includeSubDomains` only when every subdomain has https too. A location with
nothing but `path` and `add_headers` joins the location a preset (WordPress, Laravel, a proxy)
or the implicit `/` already has at that path, its fields added and a field of the same name
replaced (where the site has none, as for `/assets/` here, it is a location of its own with
the site's settings); add any other key to it and it replaces that location instead, front
controller and all.

**Check it.**

```sh
curl -sI https://example.com/ | grep -i strict-transport
curl -sI https://example.com/assets/app.3f9a1c2b.js | grep -i -e cache-control -e strict-transport
agensio ctl site example.com                          # every location with the headers it adds
```

**On a managed site.** `--hsts` puts HSTS on the `/` location as above; `--cache` makes a
directory served from disk with `Cache-Control: public, max-age=N` (no `immutable`), where
nothing runs. Each flag replaces its own part of the site's rules and keeps the others
(passwords, address rules, refused paths; before 0.1.0-alpha.61 `--cache` alone dropped them):

```sh
agensio ctl site-update example.com --hsts --cache /assets/=31536000 --yes --reason "long-lived assets, HSTS"
```

**MCP:** `site_update` with `hsts` true and `rules` = the site's current rules from `site_show`
with `"cache": [{"path": "/assets/", "max_age": 31536000}]` added: the tool replaces the whole
rules object, so a part left out is removed. A field no flag covers (`immutable`, another header
on one path) goes into the site's root additions file, root's.

**Reference:** [Locations](../configuration.md#6-locations-the-reference),
[Customising a preset](../configuration.md#5-customising-a-preset),
[HTTPS only](../configuration.md#https-only), [root additions](../configuration.md#15-control-socket).

## A single-page application

**When:** a client-side application (React, Vue, Svelte) routes on the browser, so
`/settings/profile` exists only for the script, and a reload on that URL must get the
application's shell.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/app.example.com.toml
[[site]]
server_name = ["app.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/app.example.com/dist"
tls = "auto"
try_files = ["$uri", "$uri/", "/index.html"]   # a file, a directory's index, else the shell

[[site.location]]
path = "/assets/"
try_files = ["$uri", "=404"]   # a missing script is a 404, not the shell
add_headers = { "Cache-Control" = "public, max-age=31536000, immutable" }
```

**What it does.** A path that is a file is served; any other path gets `/index.html` with
`200`, and the script draws the route. Without the `/assets/` location a missing or
mistyped bundle would get the shell too, HTML where the browser expects JavaScript, which
fails in the browser with a confusing error instead of a 404. The location gives `/assets/`
its own `try_files`, so a file missing there is `404`. The port-80 site that redirects to
https is the one in the second recipe.

**Check it.**

```sh
curl -s -o /dev/null -w '%{http_code} %{content_type}\n' https://app.example.com/settings/profile   # 200 text/html
curl -s -o /dev/null -w '%{http_code}\n' https://app.example.com/assets/missing.js                  # 404
agensio ctl path-check app.example.com /settings/profile                                            # the try_files steps to /index.html
```

**Reference:** [Static site](../configuration.md#1-static-site) (`try_files`),
[Locations](../configuration.md#6-locations-the-reference).

## An access log per site, and JSON logs

**When:** each site's traffic should be read on its own (by you, by the site's owner, by a
tool), or a log collector wants one JSON object per line.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }

[log]
access = "/var/log/agensio/access.log"   # every site without an access_log of its own
format = "json"                          # every access log; "combined", the default, is what fail2ban reads
error = "/var/log/agensio/error.log"
level = "warn"
```

```toml
# /etc/agensio/sites.d/example.com.toml
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https"
access_log = "/var/log/agensio/sites/example.com/access.log"   # the redirects in the same file

[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = "auto"
access_log = "/var/log/agensio/sites/example.com/access.log"
```

**What it does.** Each site writes the file its `access_log` names, or the server-wide one;
`access_log = "off"` writes nothing for that site. Lines are buffered per worker and written
every second. A JSON line has `time`, `remote`, `host`, `method`, `target`, `proto`, `status`,
`bytes`, `referer` and `user_agent`, plus `user` behind a password and `upstream` (the outcome
of a PHP or proxied request) when there is one; `host` is what lets a tool tell sites apart in
a shared file, which the combined format cannot. The format is one setting for every access
log, and the trade-off is fail2ban: its filters read the combined format, so with JSON no jail
can count login attempts (`agensio ctl health` says `fail2ban_log_format`). A site with its own
`user` gets its log made `agensio:<site group>` `0640` at start, so the account can read it.
The package's logrotate rule rotates `/var/log/agensio/*.log` and `/var/log/agensio/sites/*/*.log`
and sends `SIGUSR1`, which reopens every file; a log elsewhere needs a rule of its own with the
same `postrotate`.

**Check it.**

```sh
tail -f /var/log/agensio/sites/example.com/access.log
agensio ctl logs --site example.com --status all --since 10m     # read back, by site
agensio ctl logs-reopen --yes --reason "after moving a log"      # what SIGUSR1 does
```

**On a managed site.** A site created with a user gets its own log without asking:
`sites/<domain>.log` in the directory of `[log] access`, so `/var/log/agensio/sites/example.com.log`
with the package's main file. The format stays in the main file, root's.

**MCP:** `logs_query` with `site` and `status`; `logs_reopen` after a rotation.

**Reference:** [Logging](../configuration.md#8-logging),
[Hosting: one user per site](../configuration.md#11-hosting-one-user-per-site),
[fail2ban](../fail2ban.md).

## Larger uploads for one site

**When:** one site takes large uploads (a media library, attachments) and the rest of the host
should keep the small default of 1 MB per request body.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }
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
max_body_size = "64MB"         # this site only; the others keep [server] max_body_size (1MB)
```

**What it does.** A request body above the limit is answered `413` before the application sees
the request: up front when the client declares the length, as soon as the limit is passed when
it does not. The error log names the site, the size, the address and the limit
(`site blog.example.com: a request body of 80 MB from ... refused with 413: its max_body_size
is 64 MB`), the line to look for when someone says the upload "just fails". The limit holds on
HTTP/1.1, HTTP/2 and HTTP/3 alike. A body above 256 KB is spilled to an unlinked temporary file
on its way to PHP, so a large upload costs little memory. With `user` the site's
generated php-fpm pool takes the same value as `upload_max_filesize` and `post_max_size`:
`agensio pools` rewrites it and says when php-fpm needs a reload. A site on a php-fpm pool of
your own (`php = { socket = ... }`) needs those two raised in that pool as well.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml && agensio reload && agensio pools
agensio ctl settings blog.example.com                     # max_body_size: the value in force and where it comes from
agensio ctl logs --level warn --since 1d | grep 'refused with 413'
```

**On a managed site.** A site's limits are settings, raised up to the ceiling in
`[control] site_limits` (512 MB unless root changes it); the answer lists the site file, the
pool and the reloads it did:

```sh
agensio ctl site-update blog.example.com --set max_body_size=64MB --yes --reason "media uploads"
```

**MCP:** `site_settings_list` with `name` for the current value and the ceiling, then
`site_update` with `settings` = `{"max_body_size": "64MB"}`.

**Reference:** [Hosting: one user per site](../configuration.md#11-hosting-one-user-per-site),
[PHP and FastCGI options](../configuration.md#7-php-and-fastcgi-options),
[Control socket](../configuration.md#15-control-socket) (settings).

## Pre-compressed files for clients that accept them

**When:** the build writes `.br` and `.gz` copies of its scripts and styles (Vite, webpack, or
the `brotli` and `gzip` tools), and agensio should send them instead of compressing anything
per request.

```sh
cd /var/www/example.com/web
find assets -type f \( -name '*.js' -o -name '*.css' -o -name '*.svg' \) -exec brotli -k -f {} \; -exec gzip -k -f -9 {} \;
```

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }

[cache]
precompressed = true           # the default; false stops the lookup on every site
```

```toml
# /etc/agensio/sites.d/example.com.toml
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = "auto"
```

**What it does.** For a file that has `name.br` or `name.gz` beside it, a client whose
`Accept-Encoding` takes one gets it with `Content-Encoding` and `Vary: Accept-Encoding` (`br`
wins a tie, `q=0` refuses one); any other client gets the file itself, also with `Vary`. The
file itself must be there: a twin alone is never chosen. A twin older than its file is ignored,
since it is a build that was not redone, and adding, replacing or removing one shows within a
second. Only files up to `[cache] max_file_size` (4 MB) have their twins served; larger ones go
out as stored. Nothing is compressed at request time, so a file without twins is sent as it is.
Nothing to set on a managed site: the lookup is on for every site.

**Check it.**

```sh
curl -sI -H 'Accept-Encoding: br, gzip' https://example.com/assets/app.3f9a1c2b.js | grep -i -e content-encoding -e vary   # br
curl -sI https://example.com/assets/app.3f9a1c2b.js | grep -i content-encoding                                         # nothing
```

**Reference:** [Static site](../configuration.md#1-static-site) (pre-compressed files),
[keys](../keys.md#cache).
