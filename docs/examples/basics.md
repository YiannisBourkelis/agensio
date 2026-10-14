# Basics: static sites, HTTPS, headers, logs

Recipes for the first jobs on a new host: a site from a directory, HTTPS with a certificate
agensio obtains itself or one you bring, one canonical host name, cache and security headers,
several sites on one address, logs per site, larger uploads and pre-compressed files. Every
other recipe of the cookbook builds on these; a TLS site on port 443 sends plain HTTP visitors
to https by itself (its `http` key, the second recipe). The
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
```

**What it does.** A request for either name on port 80 is served from the root: `/` gets
`index.html` (the default `index`), `/docs` answers `301` to `/docs/`, a directory without an
index file is `403`, a missing file `404`. Files and directories whose name starts with a dot
(`.env`, `.git/`) are `404` whatever exists, except `/.well-known/` at the root, which is
public by definition (`security.txt`, app links) and served like any directory, while a dot
segment below it stays hidden; agensio answers its own certificate validation under
`/.well-known/acme-challenge/` itself. GET, HEAD and OPTIONS are served, anything else gets `405` with `Allow`.
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
This is the HTTPS every other recipe assumes; the plain port 80 comes with the TLS site.

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
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = "auto"                   # one certificate for every name above, obtained and renewed by agensio
# http is left out: "redirect", so the site also listens on 0.0.0.0:80 and sends plain HTTP to HTTPS
```

**What it does.** One block serves both schemes. On port 80 every request gets a `308` to
`https://` with the same name, path and query, kept by browsers for a day
(`Cache-Control: max-age=86400`), so a mistake is undone within one. The CA's validation
requests, `/.well-known/acme-challenge/...`, are answered by agensio before any site or location
rule, and a file there or under `/.well-known/pki-validation/` in the site's root is served over
plain HTTP too (certbot's webroot mode, a CA's file check), so the redirect never gets in their
way; only files: anything else under those two prefixes is a `404`, and no application runs over
plain HTTP. At the first start a self-signed placeholder lets the TLS listener come up and an order is
placed at once; the certificate replaces the placeholder through a reload, with no connection
dropped. Once an hour the certificates are checked and renewed when a third of their lifetime
is left; a failed order is logged with the CA's reason and tried again an hour later while the
current certificate keeps serving. No client to install, no cron job, no reload hook. The key
and the chain live in `/var/lib/agensio/acme/<first server_name>/`, the one tree to back up.
Easy to get wrong: every name in `server_name` must resolve here, since the CA fetches the
challenge for each; wildcard names and hosts without port 80 need DNS-01 or TLS-ALPN-01, which
this release does not have; adding a name orders a new certificate at the next reload. To keep
plain http serving the site too, `http = "serve"`; `http = "off"` opens no plain listener (port 80
belongs to something else on the machine). Before 0.1.0-alpha.76 this took a second `[[site]]` on
port 80 with `redirect = "https"`; that form is refused now, naming this one.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml && agensio reload
agensio ctl logs --since 10m                          # "acme: certificate issued for example.com", or the CA's reason
agensio ctl sites                                     # each certificate: issuer, names, days left, still the placeholder or not
curl -sI 'http://example.com/a?b=1' | grep -i location   # https://example.com/a?b=1
agensio ctl health                                    # tls = "auto" without port 80, no redirect, certificate problems
```

**On a managed site.** `site-create` writes the same one block; `[server] acme` must already be in
the main file, root's, or `--https auto` is refused. `--no-redirect` keeps plain http serving
(`http = "serve"`, refused with `--hsts`).

```sh
agensio ctl site-create --domain example.com --alias www.example.com --app static --root /var/www/example.com/web --user example --https auto --yes --reason "new site"
agensio ctl cert-renew example.com --yes --reason "order again after the DNS fix"
```

**MCP:** `site_create` with `https` `"auto"` (`redirect_http` false keeps plain http serving, `http = "serve"`);
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
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = { cert = "/etc/ssl/example.com/fullchain.pem", key = "/etc/ssl/example.com/privkey.pem" }
# port 80 beside it redirects to HTTPS (http, left out), as in the recipe above
```

**What it does.** A client that asks for one of the site's names gets this certificate;
`fullchain.pem` is the certificate first, then the intermediates, in PEM. `agensio -t` loads the
pair as the start does and names a site whose files do not load (missing, not PEM, a key that is
not the certificate's): its file is set aside, or for a site of the main file the configuration is
refused. The certificate must cover every name in
`server_name`: a request for a name it does not cover is answered `421`. The server checks the
files every hour and loads a renewed certificate by itself, without a reload; your ACME client's
renewal hook can run `agensio ctl cert-renew example.com --yes` to load it at once. It reads the
files as the account the server runs as, not as root, so a key only root can read works at start
and then is not read again: every later load keeps serving the certificate loaded at start (`the
certificate loaded before keeps serving` in the error log, `certificate_not_loaded` in health)
until it expires; hence the group read above. `agensio -t` and health (`tls_key_unreadable`) say so
ahead of time, with the `chgrp` and `chmod` lines for every directory and file on the way. Before
0.1.0-alpha.64 that refused every reload. Sites with automatic and with managed
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
[Which site answers a request](../configuration.md#1b-which-site-answers-a-request),
[TLS certificates](../tls.md#3-your-own-certificate-files).

## Certificates from certbot

**When:** certbot already manages the host's certificates, or a site needs a wildcard
certificate (`*.example.com`), which takes DNS-01: certbot does it with a plugin for your DNS
provider, agensio's own client does not. For names that resolve here with port 80 open,
`tls = "auto"` needs no certbot at all.

```sh
# A wildcard over DNS-01 (Cloudflare's plugin here; certbot has one for most DNS providers).
certbot certonly --dns-cloudflare --dns-cloudflare-credentials /root/.secrets/cloudflare.ini \
  -d example.com -d '*.example.com' --deploy-hook 'agensio ctl cert-renew example.com --yes --reason certbot'
# certbot makes live/ and archive/ 0700 and the key 0600; the server's account reads them after the start.
chmod 0755 /etc/letsencrypt/live /etc/letsencrypt/archive
chgrp agensio /etc/letsencrypt/live/example.com/privkey.pem && chmod 640 /etc/letsencrypt/live/example.com/privkey.pem
agensio -t -c /etc/agensio/agensio.toml   # names anything on the way still closed to it, with the line to run
```

```toml
# /etc/agensio/sites.d/example.com.toml
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = { cert = "/etc/letsencrypt/live/example.com/fullchain.pem", key = "/etc/letsencrypt/live/example.com/privkey.pem" }
```

```toml
# /etc/agensio/sites.d/shop.example.com.toml: another site under the same wildcard
[[site]]
server_name = ["shop.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/shop.example.com/web"
tls = { cert = "/etc/letsencrypt/live/example.com/fullchain.pem", key = "/etc/letsencrypt/live/example.com/privkey.pem" }
```

**What it does.** certbot proves the names through DNS and writes the certificate under
`/etc/letsencrypt/live/example.com/`, links to the current files in `archive/`. Both sites serve
it; a site lists its names exactly (`server_name` takes no `*.` pattern), and the wildcard covers
each of them. When certbot renews it points the links at new files, and agensio loads them by
itself within the hour; the deploy hook, which certbot runs after each renewal and keeps for the
next ones, makes it at once. One `cert-renew` loads the files for every site that names them.

Easy to get wrong: the server starts as root and then runs as `agensio`, and every load after
the start reads the files as `agensio`. With certbot's own modes it would serve the start's
certificate until it expired; the two commands above open the directories (certbot's own
documentation suggests `0755` for them) and give the key the server's group, which certbot keeps
on every renewal. `agensio -t` and health (`tls_key_unreadable`) name whatever is still closed.

An existing certbot that renews with `--webroot` works through agensio too: Let's Encrypt asks
over port 80, and the site's plain port serves `/.well-known/acme-challenge/` from the site before
it redirects anything else, so the file certbot wrote is answered there, also for a certificate
the site does not have yet. With `-w` pointing at the site's own root nothing more is needed; with
certbot's own directory a location maps it. agensio answers its own orders' tokens first, so this
never disturbs a `tls = "auto"` site.

```toml
# On each site the certificate covers, for: certbot renew --webroot -w /var/lib/letsencrypt/webroot
[[site.location]]
path = "/.well-known/acme-challenge/"
alias = "/var/lib/letsencrypt/webroot/.well-known/acme-challenge/"
```

**Check it.**

```sh
agensio ctl cert-renew example.com --yes     # "loaded the certificate valid until ...", or "unchanged"
certbot renew --dry-run                      # the renewal itself works
agensio ctl site shop.example.com            # tls.served: the certificate in memory, same_as_disk true
agensio ctl sites                            # every site's certificate at once, on disk and served
agensio ctl status                           # certificate_watch: the hourly check of the files, its last and next run
agensio ctl health                           # certificate_not_loaded or tls_key_unreadable if something waits
```

**On a managed site.** `site-create` with `--cert` and `--key` naming the files under
`/etc/letsencrypt/live/`; the webroot location goes into the site's root additions file
(`site-show` names it), since no field of `site-update` writes a location.

**MCP:** `site_create` with `https` = `{"cert": "/etc/letsencrypt/live/example.com/fullchain.pem",
"key": "/etc/letsencrypt/live/example.com/privkey.pem"}`; `cert_renew` loads renewed files at once;
`health_check` for what waits.

**Reference:** [TLS certificates](../tls.md#34-certbot), [TLS](../configuration.md#14-tls).

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
canonical = "www.example.com"          # the other names redirect here
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = "auto"                           # one certificate for both names: browsers check it before they follow a redirect
```

**What it does.** `https://example.com/x?y`, `http://example.com/x?y` and
`http://www.example.com/x?y` all answer `308` to `https://www.example.com/x?y`, one hop each (scheme
and host together), kept by browsers for a day so a wrong choice is undone within one; only
`https://www.example.com` serves the site. Swap the names to make the bare name canonical. Choose
once: search engines treat the two as separate hosts and rank neither higher, but changing the
choice later costs months of settling and logs every visitor out (cookies belong to a host). Tell
the application the same address (WordPress `home` and `siteurl`, Laravel `APP_URL`, Drupal
`$base_url`), or it redirects back and the two loop. With `hsts = true` a plain request for the
bare name goes to its own HTTPS first and then to `www`, so the bare name learns HSTS too. A domain
you moved away from entirely is another site with one rule from `/` to the new host (the recipe
below).

**Check it.**

```sh
curl -sI 'http://example.com/x?y=1' | grep -i location      # https://www.example.com/x?y=1
curl -sI 'https://example.com/x?y=1' | grep -i location     # the same
curl -sI https://www.example.com/ | head -1                 # 200
```

**On a managed site.** `--canonical` names the domain or one of its aliases:

```sh
agensio ctl site-create --domain example.com --alias www.example.com --canonical www.example.com --app static --root /var/www/example.com/web --user example --https auto --yes --reason "canonical www"
agensio ctl site-update example.com --canonical example.com --yes --reason "the bare name instead"
```

**MCP:** `site_create` or `site_update` with `canonical` = `"www.example.com"` (`""` clears it).

**Reference:** [HTTPS only](../configuration.md#https-only), where the same shape is explained,
and [redirects.md](../redirects.md) 3.

## Pages and sections that moved, and a domain that moved

**When:** addresses changed in a redesign or a move, and old links, bookmarks and search engines
should land on the new ones.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/example.com.toml
[[site]]
server_name = ["example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = "auto"

[[site.redirect]]
from = "/blog"                 # the section and everything below it: /blog/2024/x -> /news/2024/x
to = "/news"
status = 301

[[site.redirect]]
from = "/about-us"
match = "exact"                # this page alone
to = "/about"
status = 301

[[site.redirect]]
from = "/?p=123"               # WordPress's plain permalinks: the page was in the query
match = "exact"
to = "/2024/hello-world/"
status = 301

[[site.redirect]]
from = "/contact/send"         # a form handler that moved: 308 keeps the POST a POST
match = "exact"
to = "/api/contact"
status = 308

[[site.redirect]]
from = "/press-2019"
status = 410                   # gone, nothing replaces it
```

```toml
# /etc/agensio/sites.d/old-shop.com.toml: a domain that moved, kept for a year or more
[[site]]
server_name = ["old-shop.com", "www.old-shop.com"]
listen = ["0.0.0.0:443"]
tls = "auto"                   # its https:// links show the redirect, not a certificate error

[[site.redirect]]
from = "/"
to = "https://shop.example.com"
status = 301
```

**What it does.** `/blog/2024/x?y=1` answers `301` to `/news/2024/x?y=1`, `/blogger` is served (only
whole segments match), `/?p=123&utm_source=x` goes to `/2024/hello-world/` (the parameters a rule
names must be there, others are ignored, and the old query is dropped), a POST to `/contact/send`
is resent to `/api/contact`, and anything under `/press-2019` is `410 Gone`. The most specific rule
decides, never the order they are written in, and matching is case-sensitive. A plain-HTTP request
takes scheme and rule in one hop: `http://www.old-shop.com/item/7` answers `301` to
`https://shop.example.com/item/7`. Permanent redirects carry `Cache-Control: max-age=86400`, so a
mistake is undone within a day (`cache = "30d"` once the rule is right); use `302` or `307` while
testing. Easy to get wrong: a rule to a path another rule redirects again is a chain (`agensio
-t` names it); sending every old page to the home page (`from = "/"` with `remainder = "drop"`)
looks like a soft 404 to search engines.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml       # refuses loops and duplicates, notes chains
curl -sI 'https://example.com/blog/2024/x?y=1' | grep -iE '^(HTTP|location|cache-control)'
curl -sI 'http://www.old-shop.com/item/7' | grep -i location     # https://shop.example.com/item/7, one hop
```

**On a managed site.** The flags give the target and the status as the last two words; given
together they replace the site's rules. `path-check` with proposed rules is a preview that
changes nothing.

```sh
agensio ctl path-check example.com /blog/2024/x --redirect "/blog /news 301"          # the preview first
agensio ctl site-update example.com --redirect "/blog /news 301" --redirect-exact "/about-us /about 301" --gone /press-2019 --yes --reason "the redesign's moves"
agensio ctl site-update example.com --redirects-file moves.json --yes --reason "the old site's sitemap"   # [{"from": ..., "to": ..., "status": 301}, ...]
agensio ctl path-check example.com /blog/2024/x                                         # the rule, the Location, the one hop
```

**MCP:** `site_update` with `redirects` = `[{"from": "/blog", "to": "/news", "status": 301}, ...]`
(the list whole, `[]` clears it); `path_check` with `redirects` to preview; `site_show` lists them.

**Reference:** [Path redirects](../configuration.md#14b-path-redirects-siteredirect),
[redirects.md](../redirects.md) 5 and 6.

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
listen = ["0.0.0.0:443"]       # and 0.0.0.0:80, redirecting to HTTPS (http, left out)
root = "/var/www/example.com/web"
tls = "auto"
```

```toml
# /etc/agensio/sites.d/docs.example.com.toml
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

[[site.redirect]]
from = "/"
to = "https://www.example.com"
status = 302                   # for now: a catch-all's target may change
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
- a site whose certificate or key does not load (not PEM, a key that is not the certificate's,
  unreadable) is set aside too; on reload a served one keeps the certificate it loaded before;
- when two files claim one name (or both a catch-all) on one address, the one already serving
  keeps it and the other is set aside, at a restart too (the server keeps a record of the files
  it serves); between files neither served, the later in alphabetical order yields;
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
cat /var/lib/agensio/.server/served                # the site files served, by which a restart settles a conflict as the last reload did
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
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = "auto"
hsts = true                    # Strict-Transport-Security, a year, on every HTTPS answer of the site

[[site.response_headers]]
path = "/assets/"
when = "success"               # 2xx and 304 only: a missing asset's 404 is never kept for a year
set = { "Cache-Control" = "public, max-age=31536000, immutable" }
```

**What it does.** `hsts` puts `Strict-Transport-Security` on every answer the site gives over
HTTPS (pages, files, PHP, a proxied application, error pages and redirects), replacing one the
application sends itself, and never on a plain-HTTP answer. It is never on by default: once a
browser has seen it, it refuses plain http for that host until `max-age` runs out, so add it when
https is known to work; `hsts = { max_age = "2y", subdomains = true }` sets the lifetime and
`includeSubDomains`, the latter only when every subdomain has https too. A location's `add_headers`
cannot send HSTS (until 0.1.0-alpha.75 that was the way, and it reached neither the PHP pages nor
the errors). The `Cache-Control` rule is on every successful answer under `/assets/`, a `304`
revalidation included, whichever location serves it, and replaces a lifetime the application or a
preset sends there; a 404 carries none (a lifetime without `when = "success"` is refused at load).
`immutable` belongs only on names that change when the content does; give other directories a
short `max-age`, or nothing. A location's `add_headers` still works for the same purpose (the
managed `--cache` below writes one), but it reaches only that location's successful answers; the
rule reaches every answer of the path ([response headers](#security-fields-by-path)).

**Check it.**

```sh
curl -sI https://example.com/ | grep -i strict-transport
curl -sI https://example.com/assets/app.3f9a1c2b.js | grep -i -e cache-control -e strict-transport
agensio ctl site example.com                          # every location with the headers it adds
```

**On a managed site.** `--hsts` writes `hsts = true` as above; `--cache` makes a
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

**Reference:** [Response headers](../configuration.md#14c-response-headers-siteresponse_headers),
[Locations](../configuration.md#6-locations-the-reference),
[HTTPS only](../configuration.md#https-only), [root additions](../configuration.md#15-control-socket).

## Security fields by path

**When:** the site should send the same security fields on every answer, PHP pages and error
pages too, with one path that differs (a page other sites may frame), and drop what the
application discloses about itself.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/example.com.toml
[[site]]
server_name = ["example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
app = "php"
php = { socket = "unix:/run/php/php-fpm.sock" }
tls = "auto"

[[site.response_headers]]
path = "/"
set = { "Referrer-Policy" = "strict-origin-when-cross-origin", "X-Content-Type-Options" = "nosniff" }
default = { "X-Frame-Options" = "SAMEORIGIN" }   # the application's own wins where it sends one
remove = ["X-Powered-By"]

[[site.response_headers]]
path = "/embed/"
remove = ["X-Frame-Options"]                     # only this field changes below /embed/
```

**What it does.** Every answer of the site, a static file, a PHP page, agensio's own 404 or 403,
gets `Referrer-Policy` and `nosniff` (`set`: an application's own copy is replaced, so the browser
never sees two), `X-Frame-Options: SAMEORIGIN` where the application sent none (`default`), and no
`X-Powered-By`. Below `/embed/` the frame field is removed and the other two stay: per field the
most specific rule naming it decides, and the order of the rules does not matter, unlike nginx,
where an `add_header` in a nested block drops every field inherited from above. Easy to get wrong:
a `Content-Security-Policy` on an application site belongs in `default` (`set` would replace the
application's own policy, `-t` notes it), and a cache lifetime needs `when = "success"`.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml      # refuses a field the server owns, a variable, a lifetime on errors
curl -sI https://example.com/missing | grep -iE '^(referrer-policy|x-content-type-options|x-frame-options)'
curl -sI https://example.com/embed/w.html | grep -ic x-frame-options     # 0
```

**On a managed site.** Not a `site_update` field yet ([headers.md](../headers.md) 12, step 4); until
then the rules are a hand-written site file's.

**Reference:** [Response headers](../configuration.md#14c-response-headers-siteresponse_headers),
[headers.md](../headers.md) 2.

## Fields by kind of file

**When:** some kinds of file need a field of their own wherever they are: an uploaded SVG can hold
JavaScript that would run as the site if the file is opened directly, and web fonts must be
loadable from another of your origins. Shopware, Joomla and FreshRSS ship the first, PrestaShop,
TYPO3 and Craft the second.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/example.com.toml
[[site]]
server_name = ["example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
app = "php"
php = { socket = "unix:/run/php/php-fpm.sock" }
tls = "auto"

[[site.response_headers]]
path = "/"
endings = ["svg"]
set = { "Content-Security-Policy" = "script-src 'none'" }

[[site.response_headers]]
path = "/"
endings = ["woff", "woff2", "ttf", "otf"]
set = { "Access-Control-Allow-Origin" = "https://shop.example.com" }
```

**What it does.** Every SVG file agensio serves, under any directory, carries a policy that runs no
script, and every font a CORS field for the shop's origin. `endings` reads the file agensio
serves, after `try_files` and a directory's index, never the address: a page PHP makes is never
touched, whatever its URL ends with, and a missing file's 404 gets nothing. At one path a rule with
endings decides before one without, and a longer path before both. A rule's value is fixed text:
several allowed origins need the server to echo the request's `Origin` with `Vary: Origin`, which
is the application's, so a list in one field is refused, and so is `*` with credentials. Easy to
get wrong: `endings = ["php"]` on a PHP site is refused (PHP runs those files; a rule for PHP's
answers has no endings).

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml
curl -sI https://example.com/uploads/logo.svg | grep -i content-security-policy
curl -sI https://example.com/fonts/inter.woff2 | grep -i access-control-allow-origin
```

**On a managed site.** Not a `site_update` field yet ([headers.md](../headers.md) 12, step 4); until
then the rules are a hand-written site file's.

**Reference:** [Response headers](../configuration.md#14c-response-headers-siteresponse_headers),
[headers.md](../headers.md) 3.3.

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
its own `try_files`, so a file missing there is `404`. Plain HTTP on port 80 redirects to
https by itself (the second recipe).

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
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = "auto"
access_log = "/var/log/agensio/sites/example.com/access.log"   # the port-80 redirects in the same file
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
The package's logrotate rule rotates `/var/log/agensio/*.log` and the sites' own logs,
`/var/log/agensio/sites/*.log` (where `site-create` puts them) and `/var/log/agensio/sites/*/*.log`,
keeping each site log's group so the account goes on reading it, and sends `SIGUSR1`, which reopens
every file; a log elsewhere needs a rule of its own with the same `postrotate`.

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
