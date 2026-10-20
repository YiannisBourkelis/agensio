# HTTPS, canonical names, HSTS and redirects

> **Status: built, 0.1.0-alpha.75 to alpha.87** (section 13 says which step came in which
> release). It was written first as the design, in the form of the guide it became, so each use
> case could be checked against it before anything was built. The questions the use cases raised
> and the owner's decisions are in section 9, the check against the research in section 11, the
> check against the applications' own configurations in section 12. Not built yet: a data file for
> more than 1,000 rules (6.3), the maintenance setting (7), a placeholder inside a target (12.3).
> The research behind it is `reports/Web server headers and redirects.md` and
> `research_notes/Official configs vs redirects and headers/`; response headers
> (`[[site.response_headers]]`, the security baseline per preset, and the mechanism `hsts` uses)
> are in `docs/headers.md`.

## 1. The model

Four settings of a site decide where a request is sent before anything is served:

| setting | decides | default |
|---|---|---|
| `http` | what a request over plain HTTP gets | `"redirect"` for a TLS site on port 443; `"off"` for a TLS site elsewhere (or `{ listen = [...] }`, 2.2); `"serve"` for a site without TLS |
| `canonical` | which one of the site's names the others redirect to | none: every name serves |
| `hsts` | whether HTTPS answers tell the browser to use only HTTPS | off |
| `[[site.redirect]]` | rules that send a path somewhere else | none |

Every request meets them in this order, and each step is skipped when it does not apply:

1. **Certificate validation** (`/.well-known/acme-challenge/` and `/.well-known/pki-validation/`)
   is answered first, on every name and over plain HTTP: agensio's own ACME tokens, else the site's
   files there (a certificate tool that writes into the root, a CA checking a file), so no setting
   here can break a certificate's issue or renewal, whoever obtains it. Only its files: a regular
   file under the root, else `404`, nothing run and no fallback, so no application answers plain
   HTTP there (alpha.77, the alpha.76 report: the first build sent those requests through the
   site's locations, into a front controller or a proxied application).
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
target. The access log records it like any answer. The static handler's `301` for a directory
asked for without its slash is written the same way, the query kept and a day's lifetime
(0.1.0-alpha.100; before, the decoded path went out as it was, without the query or a lifetime).

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

`http = { listen = [...], mode = "serve" }` serves the site on those addresses instead (added when
the step was built, alpha.76: a managed site with `redirect_http` false on ports of its own needs
it).

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
| no `X-Forwarded-Proto` | `308 → https://...`, taken as plain HTTP; the error log and health name the proxy (below) |
| a client that is not a trusted proxy, sending `X-Forwarded-Proto: https` | `308 → https://...`: the field is not believed from it |

`trusted_proxies` is a key of `[server]`, so it lives in the main configuration file (root's); the
site itself can be in its own file under `sites.d/`, and can narrow the list for itself (below). The key does not put the server behind the
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
hsts = "1y"
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

#### Sites behind different proxies: a site's own `trusted_proxies` (decided 2026-10-13, built in alpha.73)

One list for the server means every site believes every proxy on it. With two sites behind two
CDNs, `example.com` would believe CDN B too. A CDN's addresses are shared by all its customers:
anyone can open an account with CDN B, point it at this server's address and send requests for
`example.com`, and agensio would believe what they carry: the scheme, and the client address that
access rules, password exceptions (`skip_for`), the logs, fail2ban and PHP's `REMOTE_ADDR` rely
on. agensio takes the rightmost address it does not trust from `X-Forwarded-For`, so a field a
client forged is ignored; what remains is a CDN that lets its customers' own edge code write those
fields, and each CDN on the list adds its customers to everyone a site believes. So a site names
the proxies that speak for it:

```toml
[addresses]
cdn_a = ["173.245.48.0/20", "103.21.244.0/22"]
cdn_b = ["198.51.100.0/24"]

[server]
trusted_proxies = ["@cdn_a", "@cdn_b"]      # every proxy allowed in front of this server

[[site]]
server_name = ["example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/example.com/web"
http = "redirect"
trusted_proxies = ["@cdn_a"]                # only CDN A speaks for this site
```

```toml
# /etc/agensio/sites.d/example2.com.toml
[[site]]
server_name = ["example2.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/example2.com/web"
http = "redirect"
trusted_proxies = ["@cdn_b"]                # only CDN B
```

| request | from | answer |
|---|---|---|
| `example.com`, `X-Forwarded-Proto: https` | CDN A | served; the client is the one CDN A names |
| `example.com`, `X-Forwarded-Proto: https` | CDN B | `308 → https://example.com/...`: CDN B does not speak for this site, so the request is an ordinary visitor's, CDN B's address its client |
| `example2.com`, `X-Forwarded-Proto: https` | CDN B | served |

Without the key a site believes the server's whole list, as today; `trusted_proxies = []` makes a
site whose visitors connect directly believe no proxy at all.

1. **A site's list narrows, never widens.** Each entry must lie within the server's list; one that
   does not is refused at load, naming it. Root decides in the main file which proxies may be
   believed at all; a site, in its own file or through `site_update`, only picks among them. A
   site that could add ranges would let whoever manages it make the server believe forged
   addresses for it, and those would reach its access log, where fail2ban, whose bans hold for the
   whole host, could be steered to ban anyone.
2. **Named sets**: `trusted_proxies`, in `[server]` and in a site, takes the `[addresses]` sets the
   access rules use (`@cdn_a`) beside ranges, so a CDN's published ranges live in one place and one
   edit follows its changes.
3. **Cost only where used**: a site without its own list keeps today's path, trust decided once per
   connection from the server's list. A site with one adds one range check per request once the
   site is known; the server's list still decides what is answered before a site is known (a
   malformed request, a 421).

Two rules come with it:

- **No jail bans a trusted proxy.** The fail2ban jails agensio renders carry every range of
  `[server] trusted_proxies` in `ignoreip` (jail.conf(5)). A proxy's own address reaches the log
  when it sends a request without `X-Forwarded-For` and when a site does not trust it, and a ban in
  the host's firewall would cut off every visitor that proxy carries, for every site behind it.
  Built in alpha.73, with the server's list (`docs/fail2ban.md` 2a, 4).
- **What a site believes is visible.** `site_show` lists the proxies a site trusts; health notes, on
  a server whose list names more than one set, the sites that name none of their own
  (`site_trusts_every_proxy`, info), with the line to add. (`access_check` and `path_check` take a
  client address or none, so the list does not enter them.)

### 2.5 An application's own `http://` redirects

A proxied application that does not trust agensio as its proxy builds its redirects from what it
sees, plain HTTP: `Location: http://notes.example.com/login`. Every visitor would then take an
extra hop through the redirect of 2.1, and a form's POST would arrive as a GET. On a site that
redirects plain HTTP, agensio upgrades such a `Location` to `https://` when it names one of the
site's own names, for proxied, PHP and CGI answers alike (nginx's `proxy_redirect http://
https://`). Only the scheme of the site's own names changes; any other `Location` passes as the
application sent it. The application is still better told to trust the proxy (10.3). Built in
alpha.79: a name of the site without a port, with port 80 or with its TLS port (the Host the
application was given) becomes `https://` on the TLS port; another port is another service and
passes.

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

(As built in alpha.81 only exact names redirect: the router matches a site by its exact names, so
a `*.` entry takes no requests by itself yet. Wildcard routing is a step of its own.)

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
`app_redirects_elsewhere` with the setting to change (WordPress's `home` and `siteurl`, Laravel's
`APP_URL`, Drupal's `$base_url`, Grav's `custom_base_url`, Redmine's host name). The request is
`GET /` with the canonical name as Host (and as SNI over TLS), `Connection: close`, at most three
seconds per step, on a thread of its own and never on a worker, which may be the one that has to
answer it (built in alpha.84). A site that does not answer gives no finding here.

## 4. HSTS: `hsts`

### 4.1 On

```toml
hsts = "1y"        # Strict-Transport-Security: max-age=31536000 (a year), this host only
```

The value is the lifetime itself, the commitment browsers make (RFC 6797 11.2 asks that a deployer
set it willfully, never by default): a duration (`"5m"`, `"1w"`, `"1y"`, `"2y"`; s, m, h, d, w, y)
or seconds (`604800`, the form applications publish), at most ten years in a site file and two
through the control plane; `hsts = 0` has browsers forget it (4.5); a table adds subdomains (4.4).
`hsts = true`, which named no lifetime and meant a year, is refused since 0.1.0-alpha.101, naming
the form to write. A managed file an earlier version wrote with it is set aside like any file that
does not load, and every change to it is refused until the change names a lifetime; health's
`site_file_held_back` names the one that keeps what browsers were told, `agensio ctl site-update NAME
--hsts 1y --yes` (`site_update` with `hsts: "1y"`), which writes the file in this version's form and
serves the site again.

`site_show` (`agensio ctl site NAME`) shows a site's `hsts`: its `state` (`on`, `clearing`, `cleared`,
`application`, `none`, `undecided` for no line; 4.2), the field it sends with `max_age` and `subdomains`, and on
a managed site the `lifetime` as written, `since` when it has been sent (4.4), and `until`, a clearing's
end (4.5), or `held_until`, the end of a longer lifetime browsers may still hold after it was lowered;
`application` is the application's own field when one was seen since the start (0.1.0-alpha.103).

The field goes on every answer the site gives over HTTPS: pages, files, PHP, a proxied
application, errors and redirects. It is never sent over plain HTTP, where browsers must ignore it
anyway (RFC 6797 7.2, 8.1). An application that sends its own is replaced, so the browser never
sees two. The setting decides even when the application's value is stronger (a longer `max-age`,
`includeSubDomains`: Mastodon, GitLab, Keycloak and Umami send one), so `max_age = 0` can always
clear it. When the server replaces an application's value that was stronger, it notes the value
once per site, and health reports `hsts_narrows_application` with it, so nobody weakens it
unknowingly.

### 4.2 When health suggests it, and the two decisions without a lifetime

HSTS is a commitment: for its whole `max-age`, browsers that saw it refuse plain HTTP and refuse a
certificate problem with a hard error and no "continue anyway". So it is off until written, and
health suggests it once HTTPS has proven itself:

- **`hsts_suggested`** (info): a TLS site with no `hsts` line, not `http = "serve"`, that has served
  a real certificate (not the startup placeholder) for at least 7 days with no certificate finding
  open. The fix is `hsts = "1y"` (`site_update` with `hsts: "1y"` for a managed site, `"1w"` first when
  the user is less sure), with what it
  commits to. Not raised for a site without TLS of its own (a proxy in front may set HSTS itself).
- **An application that sends its own** (Kanboard's `ENABLE_HSTS`, Rails' `force_ssl`, Mastodon):
  on a site with no `hsts` line its field goes out as it is, and health says so instead of the
  suggestion (`hsts_from_application`, info, with the value; built in alpha.87, the alpha.86 report).
  Health learns it from its own request for the site's home page, by its canonical name, off the
  workers (alpha.91, the alpha.87/88 report's note): since 0.1.0-alpha.104 no answer is watched for it,
  so a field the application sends on other pages only is not seen. `hsts = "1y"` would replace it,
  and with a weaker one when the application's commits to more, which `hsts_narrows_application` would
  then report; the fix says `hsts = "application"` records that the application's is the one, or
  gives the `{ max_age, subdomains }` that matches it.
- **No line and the two decisions without a lifetime** (0.1.0-alpha.104). No line is not decided: the
  application's own field goes out unchanged (`site_show` says `undecided`) and health suggests HSTS.
  Health stays quiet about a site that says either decision:

  | Value | agensio sends | The application's own field | For |
  |---|---|---|---|
  | `hsts = "application"` | nothing | goes out unchanged, not looked at | an application that sets HSTS itself: Rails' `force_ssl`, Kanboard's `ENABLE_HSTS`, Writebook |
  | `hsts = "none"` | nothing | removed, on every answer | no HSTS, guaranteed: a site that must stay reachable over plain HTTP (a staging copy, an intranet name), or whose application would add one unasked (Rails' `force_ssl` turns it on by default) |

  The agent writes one of them when the user declines, so the suggestion does not come back.
  Removing the application's field costs `"none"` sites one header-name compare per application
  header, as replacing it costs a site with a lifetime; no line and `"application"` cost nothing.
  `hsts = false` is refused since 0.1.0-alpha.104, naming `"application"`: it sent none of agensio's
  and let the application's field through, which read as a promise of none at all. A managed site
  that decided no before is read as `"application"`, so its next rendering, or health's repair of its
  file set aside (`agensio ctl site-update NAME --yes`), writes what it did.
- **With `hsts` on, certificate findings rise one level** (`certificate_expiring`,
  `acme_renewal_failed`), and say why: a visitor can no longer click past an expired certificate.

The agent never turns HSTS on by itself; it asks the user.

### 4.3 The bare domain learns it too

A host records HSTS only from its own HTTPS answers. With `hsts` on, a plain request for a name
that is not canonical therefore goes to HTTPS on the same name first:

| request (`canonical = "www.example.com"`, `hsts = "1y"`) | answer |
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
`max_age` is a duration (`"1d"`, `"2y"`) or plain seconds (`63072000`), the form applications
publish.
`-t` and health list the other sites of this server that it binds, and warn about any of them
without TLS: they would become unreachable.

Subdomains on other servers are not seen, and a mistake binds them for the whole lifetime, so
`includeSubDomains` is best raised in stages, each run for its whole lifetime before the next
(hstspreload.org's deployment advice): five minutes, a week, a month, then a year or more. On a
managed site the spec records since when the current lifetime has been sent (`hsts_since`), and
health's `hsts_ramp` (info) names the next stage once a stage has run its lifetime with no
certificate finding, with the `site_update` and `agensio ctl` lines for it, so the agent asks the
user whether anything broke before raising it (0.1.0-alpha.102). Turning `subdomains` on with more
than five minutes says so in the answer's `hsts_note`. A site file written before that has no date,
and gets the finding once its next change of `hsts` records one. A host-only lifetime has no finding
of its own: a week first when unsure, then a year, is the advice of the texts (4.1).

```toml
hsts = { max_age = "5m", subdomains = true }    # then "1w", "30d", "1y", each after the one before ran out
```

### 4.5 Turning it off

Browsers keep HSTS for its `max-age`, counted from the last answer that carried the field; an
answer without it changes nothing (RFC 6797 8.1). Removing `hsts` therefore changes nothing for visitors who have it: they
keep refusing plain HTTP and any certificate problem until their lifetime ends, and a site that
stops sending the field has no way left to end it sooner. To tell them to forget it, send `max-age=0`
(6.1.1, 8.1): a browser that sees it drops the host at once. Keep sending it for as long as the longest
lifetime sent before, so that every browser that comes back in that time gets it; one that never
comes back forgets the host when its own lifetime ends.

```toml
hsts = 0   # "forget this host's HSTS": keep it for as long as the old max-age, then hsts = "none" or "application"
```

**A managed site does this by itself** (0.1.0-alpha.102). `"none"` (`site_update` with `hsts: "none"`,
`agensio ctl site-update NAME --no-hsts`; `false` before 0.1.0-alpha.104) on a site whose answers carry HSTS, agensio's own lifetime or
(since 0.1.0-alpha.104) the application's, renders `hsts = 0` instead, which replaces the application's
field too,
and the site file's first line records the latest moment a browser may still hold what the site
sent: each change of `hsts` raises it to the change's time plus the lifetime sent until then, so a
site that went from `"1y"` to `"1w"` last month still waits for the year. The answer's `hsts_note`
names that date, the file's comment repeats it, and health says `hsts_clearing` until then and
`hsts_cleared` after it. A second `"none"` before the date is refused, naming it: turned off early,
nothing would end the HSTS of the browsers that have not come back. After the date `"none"` writes
`hsts = "none"`, none on any answer. A lifetime given during the clearing sends one again and ends it;
`"application"` ends it too, at once. Until the date the
certificate findings stay errors (4.2), since those browsers still refuse a click past a certificate
error; after it they are warnings again.

Handing over to an application that sends its own `Strict-Transport-Security` (Rails' `force_ssl`,
Kanboard's `ENABLE_HSTS`) is `hsts = "application"` (`site_update` with `hsts: "application"`, `agensio
ctl site-update NAME --hsts application`), at once, during a clearing too: the application's field goes
out unchanged, `hsts_note` says what it sends, and from then on its lifetime counts for a later
clearing. A clearing waits for what browsers received, each holding the field it got last over HTTPS
for that field's `max-age` from then on (RFC 6797 8.1): agensio's own lifetime up to the change, and
the application's only for the time its field went out (no line, `"application"`), counted from the
change that ended it; behind agensio's own lifetime, or removed by `"none"`, the application's never
reached a browser, and a field browsers ignore (no valid `max-age`) counts for nothing (0.1.0-alpha.105,
the alpha.104 report: a site at `"2s"` whose application sent two years cleared for two years). When the
application sends none, the note says that browsers keep the site's old lifetime until its date, with
nothing renewing it, and that `hsts: 0` ends it sooner. agensio knows the application's field from what
the request path saw where it replaced or removed it, or, when nothing was seen since the start (after
every restart), from the control plane's own request for `/` through the site's listener, off the
workers, as health's probe does (0.1.0-alpha.103, the alpha.102 report). Before 0.1.0-alpha.104 the
hand-over was `false`'s; `false` is refused now, naming `"application"`, what it did (4.2).

A hand-written `hsts = 0` has no history: agensio sends it for as long as the file says, and health
says nothing about it.

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

A prefix covers whole segments: `from = "/blog"` matches `/blog`, `/blog/` and `/blog/2024/post`,
never `/blogger`. **Matching is case-sensitive**, as on every hosting platform: `/Blog` is another
address, so a rule that only fixes the case (`/iOS/x` to `/ios/x`) is allowed. (Access and
response-header rules match any capitalisation instead, because a missed spelling there weakens a
protection.) An exact rule matches its own path only: `/docs` exact does not match `/docs/`, so a
rule from exact `/docs` to `/docs/` is legal and is not a loop. Rules match the path the client
asked for, normalised once, never a target that `try_files` or a directory's index reached
internally: a rule from `/index.html` to `/` cannot catch a single-page application's fallback to
its shell. **When several rules match, the most specific decides,
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
- a `to` with its own query keeps it: the remainder joins the path of `to`, and the request's query
  follows after `&` (`from = "/old"`, `to = "/new?src=old"`: `/old/x?a=1` goes to
  `/new/x?src=old&a=1`);
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
  the site does not list (the client chose it) carries no cache lifetime but `Cache-Control:
  no-store` (a `308` is cacheable by default), so no cache keeps a redirect for a name this server
  does not know.
- A maintenance window is not a redirect: search engines want `503` with `Retry-After`. That is
  a setting of its own for a later step (`maintenance = { until = ..., allow = ["@office"] }`).

## 8. What `-t`, health and `path_check` say

- **Refused at load:** a rule whose `to` falls under its own `from` with the remainder kept (it
  would redirect forever; an absolute `to` on the site's own names is compared as a path); rules
  that send each other
  round in a cycle; a rule no request can reach because a `refuse` pattern covers its whole
  `from`; two rules with the same `from`; `canonical` not among the names, or a wildcard;
  `http = "serve"` with `hsts`; a `to` with user information, a scheme other than http(s), or
  control characters; a site's `trusted_proxies` entry outside the server's list (2.4).
- **Warned:** a chain (a rule's target is itself redirected by this site), with the direct
  target suggested; a rule from `/` with `remainder = "drop"` (every old page to one: a soft 404
  to search engines); a redirecting name the certificate does not cover; `hsts` subdomains binding
  sites without TLS; a redirect whose `from` lies under a password or access rule (the redirect
  answers before them, so its target is visible to anyone); a `from` that covers
  `/.well-known/acme-challenge/` or `/.well-known/pki-validation/` (the rule skips them, 1). The
  answer of the `site_create` or `site_update` that made one carries the same list
  (`redirect_notes`, as the reload judged it; alpha.85), so the agent tells the user at once.
- **Suggested (info):** `hsts_suggested` for a TLS site with no `hsts` line whose real certificate
  has served for a week without a finding (section 4.2).
- **Health, from the outside in:** `app_redirects_elsewhere` (the application's own address is
  another name, 3.4); `proxy_scheme_missing` (a trusted proxy sends no `X-Forwarded-Proto`, 2.4);
  `hsts_narrows_application` (the server replaced a stronger HSTS the application sent, 4.1);
  `site_trusts_every_proxy` (a site believes every proxy of a server that lists several, 2.4).
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
hsts = "1y"
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
hsts = "1y"                        # sent on the answers the proxy marks https
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
hsts = "1y"
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
hsts = "1y"
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
hsts = "1y"
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
hsts = "1y"
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
hsts = "1y"

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
- Cycles between rules are refused, not only a rule under its own `from` (8). (Case-only loops were
  refused too while matching ignored case; since matching is case-sensitive, section 12, a rule
  that only fixes the case is allowed.)
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
4. **A fuzz target for `Location`:** `fuzz_redirect`, part of the build (13).
5. **How many rules:** 1,000 per site file; a data file for larger lists later (6.3).

### 11.4 Left to the headers design

The research's rows on response headers (the verbs, per-field resolution, `when = "success"`,
the refused names, CORS, the baseline per preset, `add`/`merge`, retiring `add_headers`) belong to
`[[site.response_headers]]` and the per-preset security headers: `docs/headers.md`.

## 12. Checked against the applications' own configurations (2026-10-13)

Three reviews read what applications and hosting platforms publish as their web server
configuration, every redirect and response-field directive in it, and classified each against this
design and `docs/headers.md` (notes, with every directive verbatim and its source:
`research_notes/Official configs vs redirects and headers/`):

- the official configurations of 21 PHP applications (Nextcloud, Magento, Shopware, PrestaShop,
  Matomo, MediaWiki, Moodle, Joomla, Symfony, Craft, Kirby, Roundcube, FreshRSS, phpMyAdmin,
  WordPress, Drupal, TYPO3, Grav, Kanboard, Laravel, Statamic): 151 directives;
- the reverse-proxy configurations of 25 applications (Mastodon, Discourse, Ghost, GitLab, Gitea,
  Forgejo, Grafana, Matrix Synapse and Element, Jellyfin, Home Assistant, Vaultwarden, Keycloak, n8n,
  Plausible, Umami, Uptime Kuma, Rocket.Chat, Nextcloud AIO, Immich, Paperless-ngx, BookStack,
  Outline, Metabase, Mattermost);
- the redirect and header files of 8 static hosting platforms and the deployment guides of 16 site
  generators and single-page frameworks, with about 6,000 real files from public repositories
  (2,512 `_redirects` holding 47,025 rules, 610 `_headers`, 1,913 `netlify.toml`, samples of
  `vercel.json` and `firebase.json`).

### 12.1 What it confirmed

- **Every redirect fits the model.** In the applications' configurations, each is plain HTTP to
  HTTPS, a host, an exact path, or a whole-segment prefix that keeps the rest. In the real
  `_redirects` files: exact moves 38.3 %, a section moved with the rest of its path 20.3 %, a section
  to one page 6.8 %, `www`, another domain or HTTPS 10.1 %.
- **Captures are rare.** A capture placed inside the target appears in 1 to 2.7 % of `_redirects`
  lines; among the applications only WordPress multisite in subdirectories needs one, and it issues
  that redirect itself. The single `*` within one segment stays the later step (5.4).
- **No regex, no preload, no variables.** Six applications show `preload` and none needs it; the
  only variables in redirects are the request's own path and query, which a prefix rule keeps.
- **Conditions** on the browser's language or country appear in 0.4 % and 0.1 % of `_redirects`
  files; on a user agent or a client address, in one application each (Nextcloud's WebDAV client,
  Vaultwarden's admin), which work without them or have `[[site.access]]`.

### 12.2 What it changed (decided 2026-10-13)

1. **Matching is case-sensitive** (5.1), as on every hosting platform; a rule that only fixes the
   case is allowed (0.5 % of `_redirects` lines).
2. **Certificate validation is never redirected** (1): `/.well-known/acme-challenge/` and
   `/.well-known/pki-validation/` are answered before the scheme, host and path steps, from agensio's
   ACME manager or the site's files. Before this, the promise held only for `tls = "auto"`: a
   certificate tool writing into the root, or Nextcloud's catch-all for `/.well-known/` copied as a
   redirect, would have sent the CA elsewhere.
3. **`hsts` replaces the application's own and health names a stronger one** (4.1): eight of the
   proxied applications can send HSTS, and four send more than a year for this host does.
4. **`max_age` takes plain seconds** (4.4): Mattermost, Paperless-ngx, Jellyfin and n8n publish
   theirs that way.
5. **An exact rule matches its own path only**, so exact `/x` to `/x/` is legal (5.1): Grafana,
   BookStack and Jellyfin under a sub-path need it.
6. **A `to` with a query keeps it**, the request's query after `&` (5.3).
7. **Rules never match an internal target** (5.1): 28 of the `_redirects` files send `/index.html`
   to `/`, which would break every route of a single-page application if it met the fallback.

### 12.3 For the agent: rules imported from another platform

The agent's texts carry what other platforms do differently, since a migration brings their files:

- the same `_redirects` line without a status is a 301 on Netlify, a 302 on Cloudflare and a 308 on
  Vercel (13.4 % of the files omit it): agensio requires the status, so the agent asks;
- Netlify skips a rule whose path exists as a file unless the line ends in `!`; agensio always
  applies a rule;
- Netlify's `/old` matches `/old/` too; here an exact rule matches one spelling, so the agent writes
  both when the old site answered both;
- a placeholder at the end of the target (`/blog/* /news/:splat`) is a prefix rule; one in the
  middle is not offered yet;
- a line with status `200` is a rewrite, not a redirect: `try_files`, the front controller or the
  single-page fallback;
- the `/index.php/...` to `/...` redirect of Shopware, Symfony and Drupal's nginx recipe is a prefix
  rule (a cookbook recipe).

### 12.4 Found outside this design

These are not redirects or response fields, but the reviews met them, and each is a step of its own:

- **A client chooses the address a proxied application sees** (a bug): agensio passes a client's
  own `X-Real-IP`, `CF-Connecting-IP` or `True-Client-IP` through to the origin unless the site
  sets the field itself (`src/handlers/proxy.cpp`), and Vaultwarden (its login rate limits),
  Rocket.Chat, Grafana, Discourse's container, Plausible and Umami read one of them first. 17 of
  the 25 official configurations set `X-Real-IP` to the client's address. The fix follows a site's
  own `trusted_proxies` (2.4): "from a trusted proxy" means trusted for that site.
- **Error pages with their status**: `error_page = { 404 = "/404.html" }`. Ten of the 16 site
  generators make a `404.html` and every platform serves it with a 404; here a `try_files`
  fallback to it answers 200, a soft 404.
- **Clean addresses**: `try_files` steps `$uri.html` and `$uri/index.html` (`/x` from `x.html`, or
  from `x/index.html` without the hop to `/x/`), which eight and five generators ask for.
- **The single-page fallback on a managed static site**: `rules.front_controller` naming an `.html`
  file on `app = "static"`. It is the commonest rule of all (45.5 % of `_redirects` files) and needs a
  root additions file today.
- **A type table per site**: extensionless `.well-known` files, `.svgz` with its encoding
  (Nextcloud, Drupal, TYPO3). There is only the built-in table today.
- **Upstreams by host name**: three applications, and 3.8 % of `_redirects` files proxy a path to a
  named host; `upstream` takes an address only.
- **Internal rewrites that drop a segment**: Magento's versioned static addresses, PrestaShop's
  image addresses, WordPress multisite in subdirectories.
- **Recipes that work today**: Matrix's `/.well-known/matrix/server` and `client` as JSON files
  through an exact location (tested on alpha.72), with `Access-Control-Allow-Origin` once rules
  exist.

## 13. How it will be built and tested

Each step is its own commit, with tests that fail on the code before it, and an A/B where the
request path changes (`bench/ab.sh <base> -A` with new rows: a site with 1,000 exact redirects on
a path that meets none, a redirect hit, and a TLS site with `hsts` against one without).

1. **The HSTS bug first** (built in alpha.75): a managed PHP site with `hsts: true` sends HSTS on its PHP pages and its
   404s (fails today); `hsts` becomes a site setting, through the mechanism of `docs/headers.md`,
   replacing an application's own HSTS and noting a stronger one.
2. **`http` and `canonical`:** one block for HTTP and HTTPS; `redirect = "https"` goes; the managed
   files are rendered the new way; certificate validation is answered before both, from the site's
   files too (the failing test first: a file under `/.well-known/acme-challenge/` on a site with
   `http = "redirect"` is served over plain HTTP, not redirected). `http` built in alpha.76 (2a),
   the application's own `http://` Location (2.5) in alpha.79, `canonical` (2b) in alpha.81 with
   its `site_update` field and `ctl` flag (pulled forward from step 5 for the cookbook's managed
   recipe).
3. **`[[site.redirect]]`** (3a built in alpha.82: the rules, the one hop, the load checks and
   notes, `fuzz_redirect`, the string key `redirect` gone; 3b in alpha.83: `site_update`'s
   `redirects` and the `ctl` flags, pulled forward from step 5 with the MCP texts of 11.2 and 12.3,
   `path_check` naming the rule and its preview): exact (with query parameters) and prefix rules, case-sensitive, `410`,
   the checks of
   section 8, the preview, and `fuzz_redirect` over (`from`, `to`, path, query) asserting the
   `Location` is relative or names exactly the origin of `to`, never `//` or `/\`, never a
   control character.
4. **Health:** `hsts_suggested`, `hsts_narrows_application`, `app_redirects_elsewhere`,
   `proxy_scheme_missing`, and the certificate findings raised a level with `hsts`. 4a built in
   alpha.84: `hsts_suggested` (with `hsts = false` rendered for a managed site's decided no and
   `ctl --no-hsts`), the two certificate findings raised, `app_redirects_elsewhere`; 4b in
   alpha.86: `proxy_scheme_missing` (noted on the redirect of a trusted proxy's request without
   `X-Forwarded-Proto`, each worker at most once a minute per site) and `hsts_narrows_application`
   (noted on the first stronger application value per generation of the site), both through
   `core/site_notices.hpp` to health and the error log, with the A/B of the request path.
5. **The agent's side:** `site_update` fields, `agensio ctl` flags, the MCP texts of 11.2 and 12.3,
   the reference rows, the cookbook recipes linking here; this document installed with the others.
   The fields, flags and texts came with their steps (alpha.81 to alpha.86); alpha.87 adds the
   cookbook's `/index.php/` recipe of 12.3 and installs this document.

Sites without `http` redirects, `canonical`, `hsts` or `[[site.redirect]]` keep today's request
path: one test of an empty site field, measured flat.

A site's own `trusted_proxies` (2.4) did not wait for these steps. It was built in alpha.73, after
the client-address fix of 12.4, which reads the same per-request trust and so follows a site's
list: the key and its narrowing check, the named sets in both lists, the site's list applied once
the site is known, `ignoreip` in the rendered jails, `site_show`, health, the `site_update` field
and `ctl` flags, the reference rows, the cookbook recipe and the MCP texts, with `bench/ab.sh
<base> -A` for the routing step.
