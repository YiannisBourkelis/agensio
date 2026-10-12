# HTTPS, canonical names, HSTS and redirects

> **Status: proposal (2026-10-12), not built.** Nothing in this document works in
> 0.1.0-alpha.72; it is the design, written as the guide it will become, so each use case could
> be checked against it before anything is built. The questions the use cases raised and the
> owner's decisions are in section 9, the check against the research in section 11, how it will
> be built and tested in section 12. The research behind it is
> `reports/Web server headers and redirects.md`; response headers (`[[site.headers]]`) get a
> document of their own.

## 1. The model

Four settings of a site decide where a request is sent before anything is served:

| setting | decides | default |
|---|---|---|
| `http` | what a request over plain HTTP gets | `"redirect"` for a TLS site on port 443; `"off"` for a TLS site elsewhere (or `{ listen = [...] }`, 2.2); `"serve"` for a site without TLS |
| `canonical` | which one of the site's names the others redirect to | none: every name serves |
| `hsts` | whether HTTPS answers tell the browser to use only HTTPS | off |
| `[[site.redirect]]` | rules that send a path somewhere else | none |

Every request meets them in this order, and each step is skipped when it does not apply:

1. **ACME challenges** (`/.well-known/acme-challenge/...`) are answered first, on every name and
   over plain HTTP, so no setting here can break a certificate's issue or renewal.
2. **Scheme**: over plain HTTP, `http` decides (redirect, serve, or no listener at all).
3. **Host**: a name of the site that is not `canonical` is redirected to it.
4. **Path**: the `[[site.redirect]]` rules, after the site's `refuse` patterns (a refused path is
   a 404 and is never redirected) and before its access and password rules (a redirect reveals no
   content, and its target meets its own rules).
5. The locations serve the request.

**One hop.** Steps 2 to 4 are resolved together: `http://www.example.com/blog/x` goes straight to
`https://example.com/news/x`, not through three redirects. The answer carries the path rule's
status when a rule took part, else `308`. The one exception is HSTS (section 4): with `hsts` on,
a plain-HTTP request for a name that is not canonical goes to HTTPS on the same name first, so
that name learns HSTS too; with `hsts` off there is nothing to learn, and one hop stays the rule.

**What a redirect answer carries.** The status, a `Location` that agensio writes byte by byte
(section 5.3), `Cache-Control: max-age=86400` on the permanent ones unless the rule says otherwise
(section 7), HSTS when it goes out over HTTPS and `hsts` is on, and a short HTML body naming the
target. The access log records it like any answer.

## 2. HTTPS for a site: `http`

### 2.1 The usual site

```toml
[[site]]
server_name = ["example.com"]
listen = ["0.0.0.0:443", "[::]:443"]
root = "/var/www/example.com/web"
tls = "auto"
```

`http` is left out, so it is `"redirect"`: agensio also listens on port 80 at the same addresses
(`0.0.0.0:80`, `[::]:80`) and answers every plain request with a permanent redirect to HTTPS.

| request | answer |
|---|---|
| `http://example.com/` | `308 → https://example.com/` |
| `http://example.com/shop/cart?id=7` | `308 → https://example.com/shop/cart?id=7` |
| `http://example.com/.well-known/acme-challenge/abc` | `200`, the challenge (step 1) |
| `https://example.com/shop/cart?id=7` | served |

Before this design the same site took two `[[site]]` blocks, one on port 80 with
`redirect = "https"`; that key goes away.

### 2.2 Serving plain HTTP too, or not listening on it

```toml
http = "serve"     # an internal site, a device that cannot do TLS: both schemes serve the site
http = "off"       # no plain listener: port 80 belongs to something else on this machine
```

`http = "serve"` with `hsts` on is refused: HSTS would make browsers use HTTPS only, which
contradicts serving plain HTTP on purpose.

A TLS site on another port has no plain listener by default; the form with `listen` names one,
and the redirect keeps the TLS port:

```toml
listen = ["0.0.0.0:8443"]
tls = "auto"
http = { listen = ["0.0.0.0:8080"] }   # plain requests there: 308 → https://example.com:8443/...
```

### 2.3 A site that is plain HTTP only

```toml
[[site]]
server_name = ["intranet.lan"]
listen = ["10.0.0.5:80"]
root = "/srv/intranet"
```

No `tls`, so `http` is `"serve"`: the site is served over plain HTTP as today. The one reason to
set `http = "redirect"` on a site without TLS is a proxy in front of it that holds the certificate
(2.4).

### 2.4 Behind a proxy or CDN that terminates TLS

When a load balancer or a CDN (Cloudflare's "Flexible" mode) holds the certificate, speaks HTTPS to
the visitor and plain HTTP to agensio, every request reaches agensio over plain HTTP, whatever the
visitor used. The site then has no `tls` of its own, and `http = "redirect"` means "redirect the
visitors who really used plain HTTP": the proxy says which scheme the visitor used in
`X-Forwarded-Proto`, and agensio believes that field only from the addresses in
`[server] trusted_proxies` (anyone can send it). A request the proxy marks `https` is served, with
the HSTS of section 4; one marked `http` is redirected to the same address over `https://`, which
the visitor then requests through the proxy again. Redirecting every request instead would loop
(the visitor's HTTPS request arrives as plain HTTP, is redirected to HTTPS, arrives as plain HTTP
again: "too many redirects"). Better still, when the proxy can, is TLS between it and agensio too
(Cloudflare's "Full (strict)" mode, with `tls = "auto"` or the proxy's origin certificate): the
site is then an ordinary TLS site (2.1) and the leg behind the proxy is encrypted.

```toml
[server]
trusted_proxies = ["173.245.48.0/20", "103.21.244.0/22"]   # the proxy's ranges

[[site]]
server_name = ["example.com"]
listen = ["0.0.0.0:80"]          # the proxy reaches agensio on port 80
root = "/var/www/example.com/web"
http = "redirect"                # redirect only clients that really used plain HTTP
```

| request (from the proxy) | answer |
|---|---|
| `X-Forwarded-Proto: https`, `/shop` | served |
| `X-Forwarded-Proto: http`, `/shop` | `308 → https://example.com/shop` |
| no `X-Forwarded-Proto` | `308 → https://...`, taken as plain HTTP; the error log and health name the proxy (2.5) |
| a client that is not a trusted proxy, sending `X-Forwarded-Proto: https` | `308 → https://...`: the field is not believed from it |

`trusted_proxies` is a key of `[server]`, so it lives in the main configuration file (root's); the
site itself can be in its own file under `sites.d/`. The key does not put the server behind the
proxy: it says to believe `X-Forwarded-For` and `X-Forwarded-Proto` from those addresses only, so
a site whose visitors connect directly is unaffected, and both share port 80, the site being chosen
by name as always:

```toml
# /etc/agensio/sites.d/example2.com.toml: visitors connect to this server directly
[[site]]
server_name = ["example2.com", "www.example2.com"]
canonical = "example2.com"
listen = ["0.0.0.0:443"]
root = "/var/www/example2.com/web"
tls = "auto"                     # its own http = "redirect" also listens on port 80
hsts = true
```

| request on port 80 | from | answer |
|---|---|---|
| `example.com`, `X-Forwarded-Proto: https` | the proxy | served |
| `example2.com` | a visitor | `308 → https://example2.com/...` |

A list of trusted proxies serves every site behind them: when example2.com moves behind the same
proxy, its requests come from the proxy's addresses and are trusted with nothing else changed.

A trusted proxy that sends no `X-Forwarded-Proto` makes every request look like plain HTTP, so
visitors who came over HTTPS would be redirected again and again. agensio still takes such a
request as plain (it never serves plain HTTP by mistake), and says why: the error log, once a
minute, and health (`proxy_scheme_missing`) name the proxy, "173.245.49.12 sends no
X-Forwarded-Proto; its requests are taken as plain HTTP", so the loop has a visible cause.

### 2.5 An application's own `http://` redirects

A proxied application that does not trust agensio as its proxy builds its redirects from what it
sees, plain HTTP: `Location: http://notes.example.com/login`. Every visitor would then take an
extra hop through the redirect of 2.1, and a form's POST would arrive as a GET. On a site that
redirects plain HTTP, agensio upgrades such a `Location` to `https://` when it names one of the
site's own names, for proxied, PHP and CGI answers alike (nginx's `proxy_redirect http://
https://`). Only the scheme of the site's own names changes; any other `Location` passes as the
application sent it. The application is still better told to trust the proxy (10.3).

## 3. One name: `canonical`

### 3.1 The bare domain, or `www`

```toml
[[site]]
server_name = ["example.com", "www.example.com"]
canonical = "example.com"
listen = ["0.0.0.0:443", "[::]:443"]
root = "/var/www/example.com/web"
tls = "auto"                      # one certificate covering both names
```

| request | answer |
|---|---|
| `https://www.example.com/about?x=1` | `308 → https://example.com/about?x=1` |
| `http://www.example.com/about` | `308 → https://example.com/about` (one hop: scheme and host) |
| `http://example.com/about` | `308 → https://example.com/about` |
| `https://example.com/about` | served |

For `www`, only the key changes: `canonical = "www.example.com"`.

Which one to choose: either, and for good (section 8). Search engines treat the two as separate
hosts and rank neither higher; what hurts is serving the same pages under both, or changing the
choice later (rankings take months to settle, and visitors are logged out, since cookies belong
to a host).

### 3.2 Several names to one

Other top-level domains, a former brand, the mobile site of old:

```toml
server_name = ["example.com", "www.example.com", "example.net", "www.example.net", "m.example.com"]
canonical = "example.com"
```

Every listed name but `example.com` redirects there, path and query kept. A former domain whose
pages moved to different paths, not just a new host, is a site move with its own rules (section 6).

A wildcard name redirects too, every name it matches:

```toml
server_name = ["shop.example.com", "*.oldshop.com"]
canonical = "shop.example.com"     # must be an exact name of the site, never a wildcard
```

### 3.3 What is checked

- `canonical` must be one of the site's `server_name` entries: it never points at another site.
- With `tls = "auto"` the certificate covers every name. With a certificate of your own, `-t` and
  health warn about each redirecting name it does not cover: its visitors would see a certificate
  error instead of the redirect.
- Only the names the site lists redirect. A request by IP address, or with a Host no site lists,
  is answered as today (the catch-all, or 421), so a monitor checking the IP is not redirected.
- A WebSocket handshake on a name that is not canonical gets the redirect like any request, and
  fails: browsers do not follow a redirect there. Socket.IO and most clients connect to the
  page's own origin, which is the canonical name, so this meets only a client given the other
  name by hand.

### 3.4 The application must agree

WordPress (`home` and `siteurl`), Drupal (`$base_url`), Laravel (`APP_URL`) and most applications
redirect to the host they are configured with. If that is the other name, the two redirects loop.
Set the application's address to the canonical one when you set `canonical`; the agent does it
with the user, and `site_install` names the setting for the presets it knows. A new installation
gets it right by itself: the other names never reach the application, so its installer records
the canonical address from the first visit.

Health checks it for every site with `canonical`: it asks the site once, over loopback, for its
canonical home page, and if the answer redirects to another of the site's names it reports
`app_redirects_elsewhere` with the setting to change (WordPress's `home`, Laravel's `APP_URL`,
Drupal's `$base_url`).

## 4. HSTS: `hsts`

### 4.1 On

```toml
hsts = true        # Strict-Transport-Security: max-age=31536000 (a year), this host only
```

The field goes on every answer the site gives over HTTPS: pages, files, PHP, a proxied
application, errors and redirects. It is never sent over plain HTTP, where browsers must ignore it
anyway (RFC 6797 7.2, 8.1). An application that sends its own is replaced, so the browser never
sees two.

### 4.2 When health suggests it, and what `false` means

HSTS is a commitment: for its whole `max-age`, browsers that saw it refuse plain HTTP and refuse a
certificate problem with a hard error and no "continue anyway". So it is off until written, and
health suggests it once HTTPS has proven itself:

- **`hsts_suggested`** (info): a TLS site with no `hsts` line, not `http = "serve"`, that has served
  a real certificate (not the startup placeholder) for at least 7 days with no certificate finding
  open. The fix is `hsts = true` (`site_update` with `hsts: true` for a managed site), with what it
  commits to. Not raised for a site without TLS of its own (a proxy in front may set HSTS itself).
- **No line means "not decided", `hsts = false` means "decided: off"**: health stays quiet about a
  site that says `false`. The agent writes it when the user declines, so the suggestion does not
  come back.
- **With `hsts` on, certificate findings rise one level** (`certificate_expiring`,
  `acme_renewal_failed`), and say why: a visitor can no longer click past an expired certificate.

The agent never turns HSTS on by itself; it asks the user.

### 4.3 The bare domain learns it too

A host records HSTS only from its own HTTPS answers. With `hsts` on, a plain request for a name
that is not canonical therefore goes to HTTPS on the same name first:

| request (`canonical = "www.example.com"`, `hsts = true`) | answer |
|---|---|
| `http://example.com/x` | `308 → https://example.com/x` |
| `https://example.com/x` | `308 → https://www.example.com/x`, with HSTS |
| `http://www.example.com/x` | `308 → https://www.example.com/x` |
| `https://www.example.com/x` | served, with HSTS |

Without that hop the browser would never visit `https://example.com`, so every typed
`example.com` would start over plain HTTP, open to a network attacker on public Wi-Fi. The extra
hop only meets plain requests for the other name (old links, typing), not the site's own links or
what search engines crawl. It also matches the redirect rule of the browsers' HSTS preload list.
Without `hsts`, a plain request for the other name goes there in one hop (section 1).

### 4.4 Subdomains

```toml
hsts = { max_age = "2y", subdomains = true }
```

Every subdomain of the site's names is then HTTPS-only in browsers that saw it, for two years.
`-t` and health list the other sites of this server that it binds, and warn about any of them
without TLS: they would become unreachable.

### 4.5 Turning it off

Browsers keep HSTS for its `max-age`. Removing `hsts` therefore changes nothing for visitors who
have it; to tell them to forget it, send `max_age = 0` for a while first (RFC 6797 6.1.1):

```toml
hsts = { max_age = 0 }   # "forget this host's HSTS": keep it for as long as the old max-age, then remove
```

### 4.6 Preload is not offered

The preload list (hstspreload.org) is built into browsers and protects even a first visit, but it
is the Chromium project's list, not an RFC, it binds every subdomain of the domain, and leaving it
takes months. For hosted sites the risk outweighs the gain; a site that needs it is a decision for
its owner outside agensio.

## 5. Path redirects: `[[site.redirect]]`

### 5.1 Fields

| field | values | default |
|---|---|---|
| `from` | a normalised path (`/old`, `/blog/`); an exact rule may add the query parameters it requires (`/index.php?page=about`) | required |
| `match` | `"prefix"` (whole segments) or `"exact"` | `"prefix"` |
| `to` | a path on this site, or an `https://` or `http://` URL | required, except with `410` |
| `status` | `301`, `302`, `307`, `308`; or `410` for a page that is gone, with no `to` | required |
| `remainder` | `"keep"` or `"drop"` (prefix rules) | `"keep"` |
| `query` | `"keep"` or `"drop"` | `"keep"`; `"drop"` for a rule whose `from` names query parameters |
| `cache` | a duration, or `"none"` (permanent statuses only) | `"1d"` |

A prefix covers whole segments in any capitalisation: `from = "/blog"` matches `/blog`, `/Blog/`
and `/blog/2024/post`, never `/blogger`. **When several rules match, the most specific decides,
never the order they are written in**: the longest `from`, as for access rules, and an exact rule
before a prefix of the same path. Two rules with the same `from` are an error. Agents and people
used to other platforms expect "first match wins": it does not apply here.

A `from` with query parameters matches when every parameter it names is present with that value,
in any order; other parameters are ignored. Only exact rules can name them.

### 5.2 Examples

A page that moved:

```toml
[[site.redirect]]
from = "/about-us"
match = "exact"
to = "/about"
status = 301
```

| request | answer |
|---|---|
| `/about-us` | `301 → /about` |
| `/about-us?ref=mail` | `301 → /about?ref=mail` |
| `/about-us/team` | served as before (exact rule) |

A section that moved:

```toml
[[site.redirect]]
from = "/blog"
to = "/news"
status = 301
```

| request | answer |
|---|---|
| `/blog` | `301 → /news` |
| `/blog/2024/post?x=1` | `301 → /news/2024/post?x=1` |
| `/blogger` | served (not the segment `blog`) |

A whole section to one page, without the old tracking parameters:

```toml
[[site.redirect]]
from = "/catalog"
to = "/shop"
status = 301
remainder = "drop"
query = "drop"
```

| request | answer |
|---|---|
| `/catalog/item/77?utm_source=x` | `301 → /shop` |

A section that became its own host:

```toml
[[site.redirect]]
from = "/docs"
to = "https://docs.example.com"
status = 301
```

| request | answer |
|---|---|
| `/docs/install?v=2` | `301 → https://docs.example.com/install?v=2` |

A form whose handler moved: 301 and 302 make browsers resend a POST as a GET, 307 and 308 keep it:

```toml
[[site.redirect]]
from = "/contact/send"
match = "exact"
to = "/api/contact"
status = 308
```

A campaign address, temporary, so browsers do not keep it:

```toml
[[site.redirect]]
from = "/summer"
match = "exact"
to = "/offers/summer-2026"
status = 302
```

Old addresses of a site that put the page in the query (an old PHP site, WordPress's plain
permalinks):

```toml
[[site.redirect]]
from = "/index.php?page=about"
match = "exact"
to = "/about"
status = 301

[[site.redirect]]
from = "/?p=123"
match = "exact"
to = "/2024/hello-world/"
status = 301
```

| request | answer |
|---|---|
| `/index.php?page=about` | `301 → /about` (the old query is dropped) |
| `/index.php?lang=el&page=about` | `301 → /about` (any order; other parameters ignored) |
| `/index.php?page=contact` | served as before (no rule names it) |

Pages that are gone for good, with no new home (search engines drop a `410` sooner than a
`404`):

```toml
[[site.redirect]]
from = "/press-2019"
status = 410                       # every address under it: 410 Gone, no Location
```

Only the home page, nothing below it:

```toml
[[site.redirect]]
from = "/"
match = "exact"
to = "/en/"
status = 302
```

A target with its own query and a fragment:

```toml
[[site.redirect]]
from = "/help"
match = "exact"
to = "/support?tab=faq#contact"
status = 301
```

| request | answer |
|---|---|
| `/help?lang=el` | `301 → /support?tab=faq&lang=el#contact` (the target's query first, then the client's) |

### 5.3 How `Location` is written

agensio writes every byte of it; nothing from the request is copied unencoded:

- a target on the site stays relative (`/news/2024/post`), so it never depends on the Host the
  client sent;
- the remainder comes from the normalised path (no `.`, `..` or repeated slashes) and is
  percent-encoded again; a backslash becomes `%5C`;
- the join puts exactly one `/` between the target and the remainder, so `from = "/old/"` and
  `to = "/"` send `/old/x` to `/x`, never `//x`;
- the result is checked: a `Location` that would start with `//` or `/\` (which browsers read as
  another host) is never sent, and an absolute one must name the host of `to`;
- a path holding an encoded separator (`%2F`, `%5C`) is not redirected by a prefix rule;
- the query is copied with every byte outside what a query may hold percent-encoded, and the
  remainder's tab, CR and LF can never appear raw (browsers delete them before parsing, which
  would join `/` and `/evil`);
- a fragment in `to` is sent; without one, the browser keeps the fragment of the address it was
  given (RFC 9110 10.2.2), so `/help#billing` sent to `/support` arrives at `/support#billing`.

### 5.4 What redirects do not do

- **Patterns with captures** (`/blog/*.html` to `/blog/*`) are not in the first step; the agent
  writes one exact rule per page from the old sitemap (6.3). A single `*` within one segment is
  the candidate if a real case needs it.
- **A site-wide form for every address** (a trailing slash or none, lowercase, `/index.html` to
  `/`) is not offered: it fights the applications' own rules (WordPress adds the slash, Laravel
  removes it). Exact rules where needed; agensio still adds the slash to a real directory.
- **Language, country or device** (`/` to `/en/` by the browser's language) is the application's
  job: it knows the content and the visitor's choice.
- **`303`** is an application's answer after a POST, not a configuration's.
- **Maintenance** is a `503` with `Retry-After`, never a redirect (section 7).

## 6. Site moves

### 6.1 A whole domain to another

The old domain keeps its own site, which only redirects; it needs no `root`, and with
`tls = "auto"` it keeps a certificate, without which its `https://` links would show an error
instead of the redirect:

```toml
[[site]]
server_name = ["old-shop.com", "www.old-shop.com"]
listen = ["0.0.0.0:443", "[::]:443"]
tls = "auto"

[[site.redirect]]
from = "/"
to = "https://shop.example.com"
status = 301
```

| request | answer |
|---|---|
| `http://www.old-shop.com/item/7?c=2` | `301 → https://shop.example.com/item/7?c=2` (no `hsts`: scheme and rule in one hop, with the rule's status) |
| `https://www.old-shop.com/item/7?c=2` | `301 → https://shop.example.com/item/7?c=2` |

Keep it for at least a year; search engines move their records over that time.

### 6.2 A domain move where the paths changed too

The old site's addresses are listed, longest first in effect (the longest `from` decides), with a
catch-all for the rest:

```toml
[[site.redirect]]
from = "/products/shoes"
to = "https://shop.example.com/c/shoes"
status = 301

[[site.redirect]]
from = "/about-us"
match = "exact"
to = "https://shop.example.com/about"
status = 301

[[site.redirect]]
from = "/"
to = "https://shop.example.com"
remainder = "drop"           # anything else to the new home page: -t warns (search engines read it as a soft 404)
status = 301
```

### 6.3 Many redirects after a migration

A redesign can leave thousands of old addresses. Exact rules are looked up in a hash table, so
their number does not slow a request. A site file holds at most 1,000 rules (the site file is
what the agent rewrites on every change); a larger migration list would get a data file of its
own in a later step.
The agent builds the list from the old site's sitemap or the user's spreadsheet and sends it
through `site_update`; `path_check` answers for any one of them. A page that moved with its
pattern (`/blog/x.html` to `/blog/x`) is one exact rule per page for now (5.4).

## 7. Which status to use

| status | meaning | method kept | browsers keep it | search engines |
|---|---|---|---|---|
| `301` | moved for good | no (POST becomes GET) | yes: agensio bounds it with `Cache-Control` | strong signal |
| `308` | moved for good | yes | yes, bounded the same way | strong signal |
| `302` | for now | no | no | weak signal: the old address may stay indexed |
| `307` | for now | yes | no | weak signal |
| `410` | gone, no new address | (not a redirect) | as any error | dropped sooner than a `404` |

- Use `301` or `308` when the move is final, `302` or `307` while testing or for something
  temporary. Permanent redirects carry `Cache-Control: max-age=86400` unless `cache` says
  otherwise: without it, Chromium keeps a 301 or 308 forever, and a mistake could never be undone
  for the visitors who saw it.
- `http` and `canonical` redirects are `308`. On a catch-all site, the HTTPS redirect for a name
  the site does not list (the client chose it) carries no cache lifetime, so no shared cache
  keeps a redirect for a name this server does not know.
- A maintenance window is not a redirect: search engines want `503` with `Retry-After`. That is
  a setting of its own for a later step (`maintenance = { until = ..., allow = ["@office"] }`).

## 8. What `-t`, health and `path_check` say

- **Refused at load:** a rule whose `to` falls under its own `from` with the remainder kept (it
  would redirect forever), case included (`/About` to `/about`); rules that send each other
  round in a cycle; a rule no request can reach because a `refuse` pattern covers its whole
  `from`; two rules with the same `from`; `canonical` not among the names, or a wildcard;
  `http = "serve"` with `hsts`; a `to` with user information, a scheme other than http(s), or
  control characters.
- **Warned:** a chain (a rule's target is itself redirected by this site), with the direct
  target suggested; a rule from `/` with `remainder = "drop"` (every old page to one: a soft 404
  to search engines); a redirecting name the certificate does not cover; `hsts` subdomains binding
  sites without TLS; a redirect whose `from` lies under a password or access rule (the redirect
  answers before them, so its target is visible to anyone).
- **Suggested (info):** `hsts_suggested` for a TLS site with no `hsts` line whose real certificate
  has served for a week without a finding (section 4.2).
- **Health, from the outside in:** `app_redirects_elsewhere` (the application's own address is
  another name, 3.4); `proxy_scheme_missing` (a trusted proxy sends no `X-Forwarded-Proto`, 2.4).
- **`path_check`** names every step a request meets, with the exact `Location` and its cache
  lifetime: `http://www.example.com/blog/x: scheme (http = redirect), host (canonical
  example.com), rule /blog (301): 301 → https://example.com/news/x, cached 1 day`.
- **A preview before rules apply:** `path_check` takes proposed `redirects` and answers as if they
  were in place, without changing the site, so a migration list is checked before it goes live.

## 9. Decisions on the questions the use cases raised (2026-10-12)

1. **Old addresses with a query:** an exact rule may name the query parameters it requires, in
   any order, other parameters ignored; such a rule drops the query by default (5.1, 5.2).
2. **Many addresses that share a pattern:** one exact rule per page for now, written by the agent
   from the old sitemap; a single capturing `*` within one segment when a real case needs it (5.4).
3. **Everything to the new home page:** `-t` warns about a rule from `/` with
   `remainder = "drop"`, a soft 404 to search engines (8).
4. **Maintenance:** a `503` with `Retry-After` in a setting of its own, later; never a redirect (7).
5. **Trailing slash, lowercase, `index.html`:** no site-wide policy; exact rules where needed (5.4).
6. **A TLS port other than 443:** `http = { listen = [...] }` names the plain listener, and the
   redirect keeps the TLS port (2.2).
7. **Language, country, device:** the application's job, not offered (5.4).
8. **A trusted proxy without `X-Forwarded-Proto`:** taken as plain HTTP and redirected; the error
   log and health (`proxy_scheme_missing`) name the proxy (2.4).
9. **Wildcard names:** allowed with `canonical`, which must be an exact name (3.2).
10. **The same-host hop without `hsts`:** one hop (1, 4.3).
11. **`303`:** not offered (5.4).
12. **An application's own `http://` redirects:** upgraded to `https://` when they name one of the
    site's names, on a site that redirects plain HTTP (2.5).
13. **WebSockets on a name that is not canonical:** redirected like any request; clients use the
    page's own origin (3.3).
14. **An application that disagrees with `canonical`:** health asks the site once over loopback
    and reports `app_redirects_elsewhere` with the setting to change (3.4).
15. **Applications with many host names:** they keep `server_name` lists or wildcards without
    `canonical`; nothing more is needed (10.1).

## 10. Applications: what the new settings simplify

Every preset gains the same four things:

- **One block instead of two.** `site_create` with HTTPS renders one `[[site]]`; the second
  block on port 80 (`redirect = "https"`) goes, and so does today's duplication of the whole site
  body when plain HTTP is served too.
- **The application sees only the canonical name, over HTTPS.** Scheme and host are redirected
  before PHP or the proxy, so the application's own "force HTTPS" and "www" logic has nothing left
  to do. Its configured address must be the canonical `https://` one, or the two redirect each
  other (section 3.4).
- **HSTS on every answer.** Today a managed site's `hsts: true` is a `[[site.location]]` at `/`
  with `add_headers`: on a PHP site it reaches neither the PHP pages (another location) nor any
  error answer; on a proxied site it joins the proxy location, so it reaches the application's
  successful and redirect answers but not its errors. As a site setting it reaches all of them,
  and an HSTS the application sends itself is replaced, so browsers see one.
- **The application learns the scheme as today:** PHP gets `HTTPS=on` and `REQUEST_SCHEME=https`;
  a proxied application gets `X-Forwarded-Proto: https` and must trust it from `127.0.0.1`.

### 10.1 WordPress

Today, as `site_create` renders a WordPress site with HTTPS, a redirect and HSTS:

```toml
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https"

[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
app = "wordpress"
user = "example"
tls = "auto"

[[site.location]]
path = "/"
add_headers = { "Strict-Transport-Security" = "max-age=31536000" }
```

With the new settings:

```toml
[[site]]
server_name = ["example.com", "www.example.com"]
canonical = "example.com"
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
app = "wordpress"
user = "example"
tls = "auto"
hsts = true
```

| request | answer |
|---|---|
| `http://www.example.com/shop/?p=12` | `308 → https://www.example.com/shop/?p=12` (the HSTS hop, 4.3) |
| `https://www.example.com/shop/?p=12` | `308 → https://example.com/shop/?p=12`, with HSTS |
| `https://example.com/wp-login.php` | WordPress's login page, with HSTS (missing today: a PHP page) |
| `https://example.com/no-such-page` | WordPress's 404, with HSTS (missing today: an error answer) |

What WordPress needs: `home` and `siteurl` (Settings, General) set to `https://example.com`.
WordPress's own canonical redirect then never meets `www`. Plugins that force HTTPS or add HSTS
(Really Simple SSL and the like) have nothing left to do and are better removed: two layers
answering the same question is where loops come from. WordPress keeps redirecting a post whose
slug changed by itself; `[[site.redirect]]` is for what WordPress does not know about, such as a
section renamed by hand:

```toml
[[site.redirect]]
from = "/shop"                     # WooCommerce's shop base renamed to /store
to = "/store"
status = 301
```

A redirect rule costs no database query; a redirect plugin runs PHP and asks the database on
every request it checks.

Behind Cloudflare in "Flexible" mode (2.4), the same site has no `tls` and listens on port 80;
WordPress still sees `HTTPS=on` through `trusted_proxies`:

```toml
[[site]]
server_name = ["example.com", "www.example.com"]
canonical = "example.com"
listen = ["0.0.0.0:80"]
root = "/var/www/example.com/web"
app = "wordpress"
user = "example"
http = "redirect"
hsts = true                        # sent on the answers the proxy marks https
```

A WordPress multisite on subdomains has a host name per site: it keeps its names in
`server_name` (or `*.example.com`) without `canonical`.

### 10.2 Laravel, Drupal, Grav and other PHP applications

```toml
[[site]]
server_name = ["app.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/app.example.com"
app = "laravel"
user = "app"
tls = "auto"
hsts = true
```

- **Laravel:** `APP_URL=https://app.example.com`. `URL::forceScheme('https')` and the
  `TrustProxies` middleware are not needed for the scheme: agensio hands PHP `HTTPS=on` itself.
- **Drupal:** with `canonical`, `trusted_host_patterns` needs only the canonical name
  (`'^example\.com$'`), since the other names are redirected before PHP; `$base_url` can stay
  unset.
- **Grav, Kanboard, any `app = "php"` site:** the same pattern; set the application's base URL,
  if it has one, to the canonical `https://` address.

### 10.3 Node and other proxied applications

```toml
[[site]]
server_name = ["notes.example.com", "www.notes.example.com"]
canonical = "notes.example.com"
listen = ["0.0.0.0:443"]
tls = "auto"
hsts = true
app = "node"
root = "/var/www/notes.example.com/app"
entry = "server.js"
user = "notes"
upstream = "http://127.0.0.1:3000"
```

| request | reaches the application? |
|---|---|
| `http://notes.example.com/` | no: `308 → https://notes.example.com/` |
| `https://www.notes.example.com/api/x` | no: `308 → https://notes.example.com/api/x` |
| `https://notes.example.com/api/x` | yes, with `Host: notes.example.com` and `X-Forwarded-Proto: https` |

What the application needs:

- **Trust the proxy** for the scheme and the client's address: Express
  `app.set("trust proxy", "loopback")`; Fastify `trustProxy: true`; Koa `app.proxy = true`.
- **Its public address** where it has one (Ghost's `url`, Rocket.Chat's `ROOT_URL`, Strapi's
  `url`): `https://notes.example.com`.
- **No HTTPS redirect or HSTS of its own** (`helmet`'s `hsts` can stay: agensio's replaces it, so
  browsers see one).
- **WebSockets on the canonical name:** a browser does not follow a redirect on a WebSocket
  handshake (3.3). Socket.IO and most clients connect to the page's own origin, which is the
  canonical one.

An application that builds `http://` addresses because it does not trust the proxy gets its
`Location` upgraded to `https://` by agensio (2.5), but its links in pages stay `http://`: trust
the proxy.

### 10.4 Rails and Redmine

```toml
[[site]]
server_name = ["tracker.example.com"]
listen = ["0.0.0.0:443"]
tls = "auto"
hsts = true
app = "redmine"
root = "/var/www/tracker.example.com/redmine"
user = "tracker"
upstream = "http://127.0.0.1:3001"
```

- **Rails:** `config.assume_ssl = true` (Rails 7.1 and later) tells Rails every request is HTTPS
  behind the proxy. `config.force_ssl = true` would redirect and add HSTS a second time: agensio
  already does both, and its HSTS replaces Rails' copy, so `force_ssl` can be left off.
- **Redmine:** Administration, Settings, General: Host name `tracker.example.com`, Protocol
  `HTTPS`, so the links in its notification mails are right.

### 10.5 Django and Wagtail

```toml
[[site]]
server_name = ["example.org", "www.example.org"]
canonical = "example.org"
listen = ["0.0.0.0:443"]
tls = "auto"
hsts = true
app = "wagtail"
project = "mysite"
root = "/var/www/example.org/mysite"
user = "mysite"
upstream = "http://127.0.0.1:8000"
```

The preset's `agensio_settings.py` already sets `SECURE_PROXY_SSL_HEADER`, `ALLOWED_HOSTS` and
`CSRF_TRUSTED_ORIGINS` from the site's names. With `canonical` they can narrow to
`example.org` and `https://example.org`, since `www` never reaches Django. Django's own
`SECURE_SSL_REDIRECT` and `SECURE_HSTS_SECONDS` stay off: agensio does both.

### 10.6 A static site

```toml
[[site]]
server_name = ["example.net", "www.example.net"]
canonical = "example.net"
listen = ["0.0.0.0:443"]
root = "/var/www/example.net/public"
app = "static"
tls = "auto"
hsts = true

[[site.redirect]]
from = "/old-landing.html"
match = "exact"
to = "/"
status = 301
```

## 11. Checked against the research (2026-10-12)

What the research (`reports/Web server headers and redirects.md`, its notes on nine servers, the
panels, the administrators' complaints and the standards) asked of redirects and HSTS, and where
this design stands. Response headers are left to their own document.

### 11.1 Covered

| what administrators and site owners need | evidence | here |
|---|---|---|
| no regex, no variables; exact or whole-segment prefix | nginx's 2026 regex CVEs, mod_rewrite's record, Kinsta's anchoring loops | 5.1 |
| the most specific rule decides, never the order | Apache `<Location>` order, Netlify/Kinsta/WP Engine first-match pitfalls, Traefik #12195 | 5.1, stated in the agent's texts |
| the status is required | every server defaults differently (302, 301, 307/308, by method) | 5.1 |
| path remainder and query kept; a named opt-out | Apache, h2o, OpenLiteSpeed, HAProxy `prefix`; IIS `exactDestination` confusion | 5.1 |
| old query-string addresses after a migration | WordPress `?p=`, old PHP sites; Netlify's query matching | 5.1, 5.2 |
| a mistaken 301 must not stay forever | Chromium keeps 301/308 forever, WebKit a year; SO 9130422 (550 votes) | 7: one day by default |
| loops and chains caught before they go live | IIS `childOnly`, Kinsta's loops, Google's 10 hops | 8 |
| `www` or not, in one setting | Plesk "Preferred domain", ISPConfig "SEO Redirect", Netlify/Vercel primary domain | 3 |
| HTTP to HTTPS in one hop, no loop behind a CDN | Cloudflare Flexible loops, `X-Forwarded-Proto` threads | 2.1, 2.4 |
| HSTS on every HTTPS answer, never over HTTP, one copy | nginx `always`, Apache's tables, Plesk duplicates, RFC 6797 7.2 and 8.1 | 4.1 |
| HSTS mistakes that cannot be undone | preload removal takes months, `includeSubDomains` by mistake | 4.4 to 4.6 |
| no open redirect from a joined path | Django, Tomcat, fastify-static, Astro, MCP Registry CVEs; the URL parser's `\`, tab, CR, LF | 5.3 |
| POST kept on moved form handlers | Fetch turns POST into GET on 301/302 | 5.2, 7 |
| SEO-safe moves: permanent, direct, a year, not all to the home page | Google Search Central | 6, 7, 8 |
| "which rule fired?" and testing without guessing | SO 18450310, Cloudflare's trace, the `curl -I` habit | 8 (`path_check`), `docs/online-checks.md` |
| redirects without a shell or a support ticket | cPanel's append-only `.htaccess`, WP Engine's bulk imports by ticket | the agent's `site_update` |
| no cost for redirects a request does not meet | nginx `map` hash, HAProxy's trees, redirect plugins' database cost | exact rules hashed, prefixes behind a first-byte test |

### 11.2 Added by this check

- A rule whose whole `from` a `refuse` pattern covers is refused: no request can reach it (8).
- Cycles between rules and case-only loops are refused, not only a rule under its own `from` (8).
- The query is copied encoded, tab, CR and LF can never appear raw, and the fragment rule is
  stated (5.3).
- The agent's texts and `agensio ctl` help say what other platforms do differently: the most
  specific rule decides, not the first; the query is kept (Cloudflare's and Vercel's bulk lists
  drop it); `302` or `307` while testing, then `301` or `308`; `307` or `308` for paths that take
  a POST; Google's rules for moves.

### 11.3 Decided after the check (2026-10-12)

1. **Preview:** `path_check` takes proposed `redirects` and answers as if they applied (8).
2. **`410 Gone`:** a rule with `status = 410` and no `to` (5.1, 5.2, 7).
3. **A catch-all's unknown names:** their HTTPS redirect carries no cache lifetime (7).
4. **A fuzz target for `Location`:** `fuzz_redirect`, part of the build (12).
5. **How many rules:** 1,000 per site file; a data file for larger lists later (6.3).

### 11.4 Left to the headers design

The research's rows on response headers (the verbs, per-field resolution, `when = "success"`,
the refused names, CORS, the baseline per preset, `add`/`merge`, retiring `add_headers`) belong to
`[[site.headers]]` and the per-preset security headers, which get a document of their own.

## 12. How it will be built and tested

Each step is its own commit, with tests that fail on the code before it, and an A/B where the
request path changes (`bench/ab.sh <base> -A` with new rows: a site with 1,000 exact redirects on
a path that meets none, a redirect hit, and a TLS site with `hsts` against one without).

1. **The HSTS bug first:** a managed PHP site with `hsts: true` sends HSTS on its PHP pages and its
   404s (fails today); `hsts` becomes a site setting.
2. **`http` and `canonical`:** one block for HTTP and HTTPS; `redirect = "https"` goes; the managed
   files are rendered the new way.
3. **`[[site.redirect]]`:** exact (with query parameters) and prefix rules, `410`, the checks of
   section 8, the preview, and `fuzz_redirect` over (`from`, `to`, path, query) asserting the
   `Location` is relative or names exactly the origin of `to`, never `//` or `/\`, never a
   control character.
4. **Health:** `hsts_suggested`, `app_redirects_elsewhere`, `proxy_scheme_missing`, and the
   certificate findings raised a level with `hsts`.
5. **The agent's side:** `site_update` fields, `agensio ctl` flags, the MCP texts of 11.2, the
   reference rows, the cookbook recipes linking here; this document installed with the others.

Sites without `http` redirects, `canonical`, `hsts` or `[[site.redirect]]` keep today's request
path: one test of an empty site field, measured flat.
