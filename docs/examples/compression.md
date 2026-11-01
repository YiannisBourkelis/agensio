# Compression: smaller answers for the browsers that take them

Recipes for `response_compression` ([configuration.md 20](../configuration.md#20-response-compression-response_compression)).
Compression is off until the configuration asks: a site's own `response_compression = true`, or
`enabled = true` in the main file's `[response_compression]` for every site. zstd, brotli and gzip
are built in; the browser's `Accept-Encoding` chooses among them; text, JavaScript, JSON, XML, SVG
and fonts are compressed, images, video and archives never; answers under 1 KB are left alone;
every answer compressed per request carries a few random bytes of padding against BREACH. A site
names only what differs from the main file, and every change applies at a reload.

The check is the same for every recipe: `Content-Encoding` names the coding the browser got,
`Vary: Accept-Encoding` is on every answer that could have been compressed, and the body decodes
to what was sent. `agensio -t --explain` prints each site's values and which are its own.

## Compress one site

**When:** PageSpeed or Lighthouse says "Enable text compression" for one site, or its pages,
CSS and JavaScript go out at full size.

```toml
# /etc/agensio/sites.d/shop.example.com.toml
[[site]]
server_name = ["shop.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/shop.example.com/web"
app = "wordpress"
php = { socket = "unix:/run/php/php8.4-fpm.sock" }
tls = { cert = "/etc/letsencrypt/live/shop.example.com/fullchain.pem", key = "/etc/letsencrypt/live/shop.example.com/privkey.pem" }
response_compression = true
```

**What it does.** Cached static files get brotli and gzip copies made once, in memory, on a
thread of their own (counted in `cache.max_size` with the file); a `.br` or `.gz` that the site's
build left beside a file is served instead and gets no copy. PHP's pages, a proxied
application's answers and CGI, their error pages included, are compressed as they are sent, with the
coding the browser takes: zstd for Chrome, Firefox and Edge, brotli for Safari, gzip for a tool
that knows nothing else. An answer the application compressed itself passes through untouched,
and so does one marked `Cache-Control: no-transform`. A browser sending no `Accept-Encoding` gets
the page as it is, with `Vary` so a cache in between keeps the two apart.

**Check it.**

```sh
curl -sS -o /dev/null -D - -H 'Accept-Encoding: zstd, br, gzip' https://shop.example.com/ | grep -i '^content-encoding\|^vary'
curl -sS --compressed https://shop.example.com/ | head -c 200       # decodes to the page
agensio -t --explain -c /etc/agensio/agensio.toml | grep response_compression
```

**On a managed site.** The control plane gets the site's own `response_compression` with step 7
of `docs/design-compression.md` 11. Until then a managed site follows the main file's
`[response_compression]` (next recipe), which root edits.

**Reference:** [Response compression](../configuration.md#20-response-compression-response_compression), [keys](../keys.md).

## Compress every site of the host, one kept off

**When:** the host serves many sites and all of them should be compressed, without an edit per
site, except one whose pages put what a visitor typed beside a token (a webmail, a support desk on
a framework that does not mask its CSRF token).

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[response_compression]
enabled = true          # every site that does not say otherwise
```

```toml
# /etc/agensio/sites.d/blog.example.com.toml: says nothing, so it is compressed
[[site]]
server_name = ["blog.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/blog.example.com/web"
app = "wordpress"
php = { socket = "unix:/run/php/php8.4-fpm.sock" }
tls = { cert = "/etc/letsencrypt/live/blog.example.com/fullchain.pem", key = "/etc/letsencrypt/live/blog.example.com/privkey.pem" }
```

```toml
# /etc/agensio/sites.d/help.example.com.toml: kept off
[[site]]
server_name = ["help.example.com"]
listen = ["0.0.0.0:443"]
app = "proxy"
upstream = "http://127.0.0.1:8200"
tls = { cert = "/etc/letsencrypt/live/help.example.com/fullchain.pem", key = "/etc/letsencrypt/live/help.example.com/privkey.pem" }
response_compression = false
```

**What it does.** The main file's `enabled = true` reaches every site that names no
`response_compression` of its own, managed sites included: their files carry no such key, so
they follow the main file. A site's `response_compression = false` keeps that site off whatever
the main file says. The shipped main file writes `enabled = false`, so a reader of it sees that
nothing is compressed until it changes.

**Check it.**

```sh
agensio -t --explain -c /etc/agensio/agensio.toml | grep -A1 'response_compression'   # each site: on or off, and from where
agensio reload
curl -sS -o /dev/null -D - -H 'Accept-Encoding: br' https://blog.example.com/ | grep -i '^content-encoding'   # br
curl -sS -o /dev/null -D - -H 'Accept-Encoding: br' https://help.example.com/ | grep -i '^content-encoding'   # nothing
```

**Reference:** [Response compression](../configuration.md#20-response-compression-response_compression).

## A shop: account and checkout pages left uncompressed

**When:** a WooCommerce shop, or a Laravel application, whose account, checkout and login pages
hold a form token beside what the visitor typed: the shape BREACH needs.

```toml
# /etc/agensio/sites.d/store.example.com.toml
[[site]]
server_name = ["store.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/store.example.com/web"
app = "wordpress"
php = { socket = "unix:/run/php/php8.4-fpm.sock" }
tls = { cert = "/etc/letsencrypt/live/store.example.com/fullchain.pem", key = "/etc/letsencrypt/live/store.example.com/privkey.pem" }

[site.response_compression]
enabled = true
exclude_paths = ["/my-account/", "/checkout/", "/cart/"]   # never compressed, whoever asks
```

**What it does.** Everything else of the site is compressed; a path under one of the prefixes
never is, for any visitor, so an attacker who gets input reflected there learns nothing from the
answer's length. A prefix covers whole segments (`/checkout` does not cover `/checkouts`). The
other pages of a shop carry no secret of that kind, and every compressed answer is padded besides.
On a Laravel site the same table names `/login`, `/register`, `/password/` and the account pages:
Laravel does not mask its CSRF token, while Django and Rails do. The site's other keys go above
`[site.response_compression]`: every key after that header belongs to it.

**Check it.**

```sh
curl -sS -o /dev/null -D - -H 'Accept-Encoding: zstd' https://store.example.com/ | grep -i '^content-encoding'             # zstd
curl -sS -o /dev/null -D - -H 'Accept-Encoding: zstd' https://store.example.com/my-account/ | grep -i '^content-encoding'   # nothing
```

**Reference:** [Response compression](../configuration.md#20-response-compression-response_compression), BREACH in the same section.

## Behind Cloudflare, CloudFront or Fastly: brotli first

**When:** one site sits behind a CDN while the host's others are served directly.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[response_compression]
enabled = true          # zstd, brotli, gzip: zstd first for browsers that come straight here
```

```toml
# /etc/agensio/sites.d/www.example.org.toml: behind the CDN
[[site]]
server_name = ["www.example.org"]
listen = ["0.0.0.0:443"]
root = "/var/www/www.example.org/web"
app = "static"
tls = { cert = "/etc/letsencrypt/live/www.example.org/fullchain.pem", key = "/etc/letsencrypt/live/www.example.org/privkey.pem" }
response_compression = { codings = ["br", "zstd", "gzip"] }
```

**What it does.** The order decides when a client takes several codings equally, as Chrome does
(`gzip, deflate, br, zstd`). The CDNs ask the origin for brotli and pass it on to visitors, and
ignore an origin's zstd, so brotli first is what reaches the visitor compressed.
The site's list replaces the main file's for that site alone; the other sites keep zstd first,
which costs a quarter of brotli's CPU for 1 to 8 % more bytes. The copies of the site's cached
files are its brotli and gzip whatever the order. A site behind a CDN usually wants
`trusted_proxies` too, so the logs show the visitor and not the CDN
([protection](protection.md#judge-the-real-client-behind-a-cdn-or-load-balancer)).

**Check it.**

```sh
curl -sS -o /dev/null -D - -H 'Accept-Encoding: gzip, deflate, br, zstd' https://www.example.org/ | grep -i '^content-encoding'   # br
```

**Reference:** [Response compression](../configuration.md#20-response-compression-response_compression) (the order).

## An application that compresses its own answers

**When:** Next.js, Ghost, Grafana or a PHP site with `zlib.output_compression` behind agensio;
they compress with gzip themselves.

```toml
# /etc/agensio/sites.d/app.example.com.toml
[[site]]
server_name = ["app.example.com"]
listen = ["0.0.0.0:443"]
app = "proxy"
upstream = "http://127.0.0.1:3000"
tls = { cert = "/etc/letsencrypt/live/app.example.com/fullchain.pem", key = "/etc/letsencrypt/live/app.example.com/privkey.pem" }
response_compression = true
```

**What it does.** agensio hands the browser's `Accept-Encoding` on to the application. An answer
the application compressed passes through untouched, with `Vary` merged; one it left plain
agensio compresses. To have agensio compress everything, with zstd or brotli and the padding,
switch the application's own compression off: `compress: false` in Next.js's `next.config.js` and
in Ghost's configuration, `enable_gzip = false` in Grafana, `zlib.output_compression = Off` for
PHP. Answers up to 256 KB are then compressed whole; larger ones go out plain until step 6 of
`docs/design-compression.md` 11 compresses streamed answers. `offload = true` will do the same
without touching the application, from that step on; it is accepted now and changes nothing yet.

**Check it.**

```sh
curl -sS -o /dev/null -D - -H 'Accept-Encoding: zstd, br, gzip' https://app.example.com/ | grep -i '^content-encoding\|^vary'   # gzip: the application's own; zstd once it is off there
```

**Reference:** [Response compression](../configuration.md#20-response-compression-response_compression), [Applications behind the proxy](../examples.md#applications-behind-the-proxy).

## A staging site behind a password, compressed anyway

**When:** a review copy behind `[[site.auth]]` holds no real accounts or tokens worth stealing,
and the team wants it as fast as production.

```sh
install -d -m 750 -o root -g agensio /etc/agensio/auth
agensio passwd anna >> /etc/agensio/auth/review.example.com.users     # asks twice, prints anna:$y$...
chown root:agensio /etc/agensio/auth/review.example.com.users
chmod 640 /etc/agensio/auth/review.example.com.users
```

```toml
# /etc/agensio/sites.d/review.example.com.toml
[[site]]
server_name = ["review.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/review.example.com/web"
app = "wordpress"
php = { socket = "unix:/run/php/php8.4-fpm.sock" }
tls = { cert = "/etc/letsencrypt/live/review.example.com/fullchain.pem", key = "/etc/letsencrypt/live/review.example.com/privkey.pem" }

[site.response_compression]
enabled = true
compress_signed_in = true    # the answers behind the password too

[[site.auth]]
path = "/"
users = "/etc/agensio/auth/review.example.com.users"
realm = "Review"
```

**What it does.** Without `compress_signed_in`, every answer behind the password stays
uncompressed: a browser replays a password on its own, which is the credential an attacker's
forged requests need, so agensio does not compress what it unlocks. The same holds for a path an
address rule of `[[site.access]]` admits, and for a request carrying Basic, Digest, Negotiate or
NTLM `Authorization`; a Bearer token is a script's and is compressed. `compress_signed_in = true`
compresses those answers too: right for a copy whose pages hold nothing an attacker wants, wrong
for a live site's admin pages, which reflect input beside their tokens.

**Check it.**

```sh
curl -sS -o /dev/null -D - -u anna -H 'Accept-Encoding: zstd' https://review.example.com/ | grep -i '^content-encoding'   # zstd
```

**Reference:** [Response compression](../configuration.md#20-response-compression-response_compression), [Passwords](../configuration.md#19b-passwords-siteauth).

## A type the built-in list leaves out

**When:** an API answers NDJSON, or a site serves YAML files (an OpenAPI description), and those
go out at full size. The built-in list already has every `+json` and `+xml` type.

```toml
# /etc/agensio/sites.d/api.example.com.toml
[[site]]
server_name = ["api.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/api.example.com/web"
tls = { cert = "/etc/letsencrypt/live/api.example.com/fullchain.pem", key = "/etc/letsencrypt/live/api.example.com/privkey.pem" }
mime_types = { "yaml" = "application/yaml", "ndjson" = "application/x-ndjson" }
response_compression = { enabled = true, extra_types = ["application/yaml", "application/x-ndjson"] }
```

**What it does.** `mime_types` gives the files their type (the built-in table has neither ending),
and `extra_types` makes the types compressible for this site, for its cached files and for the
answers of an application behind it alike. A site's `extra_types` adds to the main file's, which
any site that compresses shares. Matched on the type without parameters, so
`application/x-ndjson; charset=utf-8` counts.

**Check it.**

```sh
curl -sS -o /dev/null -D - -H 'Accept-Encoding: br' https://api.example.com/openapi.yaml | grep -i '^content-type\|^content-encoding'
```

**Reference:** [Response compression](../configuration.md#20-response-compression-response_compression), [Content types](../configuration.md#6c-content-types-mime_types).

## Fewer bytes or less CPU: the levels

**When:** a host pays for bandwidth and has CPU to spare, or the other way round.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[response_compression]
enabled = true
levels = { gzip = 1 }            # the few clients that take gzip alone: half of gzip 5's CPU
```

```toml
# /etc/agensio/sites.d/media.example.net.toml: paid by the byte
[[site]]
server_name = ["media.example.net"]
listen = ["0.0.0.0:443"]
root = "/var/www/media.example.net/web"
app = "static"
tls = { cert = "/etc/letsencrypt/live/media.example.net/fullchain.pem", key = "/etc/letsencrypt/live/media.example.net/privkey.pem" }
response_compression = { codings = ["br", "zstd", "gzip"], levels = { br = 4 } }
```

**What it does.** The levels are those of answers compressed per request; the copies of cached
files are made once at brotli 11 and gzip 9 and are not a setting. Measured on real pages
(`bench/results/compression-levels-20261030.md`): brotli 4 sends 5 to 7 % fewer bytes of HTML than
brotli 3 for 1.5 to 1.8 times its CPU (WordPress's home page 191 to 337 µs); gzip 1 sends 7 to 17 %
more than gzip 5 for half its CPU; zstd 3, the default for most browsers, is already within 2 % of
brotli 3's bytes at a quarter to a third of its CPU. A site names only the levels it changes; the
others come from the main file.

**Check it.**

```sh
agensio -t --explain -c /etc/agensio/agensio.toml | grep -A9 '^\[response_compression\]'   # the main file's levels
```

**Reference:** [Response compression](../configuration.md#20-response-compression-response_compression) (the levels), [keys](../keys.md).
