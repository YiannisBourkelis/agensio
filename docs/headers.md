# Response headers: `[[site.response_headers]]` and the security baseline

> **Status: built.** `hsts` (section 5) since 0.1.0-alpha.75; `[[site.response_headers]]` (section
> 2) since 0.1.0-alpha.89, its `endings` since alpha.90, `path_check`'s fields and preview (section 7)
> since alpha.92; the baseline per preset and `response_headers_baseline` (section 4), the managed
> sites' fields, `agensio ctl`'s flags and `path_check`'s `response_headers_offer` (sections 6 and 7)
> since alpha.94, with health's `response_headers_suggested` and `response_headers_offer_declined`
> (section 7). Health's checks marked "later" in section 7 and section 11.3 are not built.
> The rest is the design, written as the guide it will become. It is the companion of `docs/redirects.md`, whose
> `hsts` setting uses the mechanism described here. The research behind it is
> `reports/Web server headers and redirects.md` (nine servers, the panels, the administrators'
> complaints, the standards) and `research_notes/App default security headers/` (what each
> application sends itself) and `research_notes/Official configs vs redirects and headers/` (what
> applications' official configurations ask for). Section 10 has the owner's decisions
> (2026-10-13), section 11 the check against those configurations, section 12 how it will be built
> and tested.

## 1. The model

The header fields of a site's answers come from the handler that made the answer (the
application, or agensio for a file and its own pages), and three settings of the site can
change them:

| setting | decides | default |
|---|---|---|
| the preset's baseline | what is safe without asking: `Referrer-Policy` where the application sent none, `nosniff` on the files and error pages agensio serves, the framework's `X-Powered-By` removed; on a static site, `no-cache` on its HTML (section 4) | on for a site with `app`; `response_headers_baseline = false` turns it off |
| `hsts` | `Strict-Transport-Security` on every HTTPS answer (`docs/redirects.md` 4) | off |
| `[[site.response_headers]]` | fields the administrator sets, defaults or removes, by path | none |

All three are resolved together, per field, when the configuration loads, and applied at one point:
as the answer leaves. That point sees **every answer the site gives**: a static file, a PHP page, a
CGI script, a proxied application, agensio's own error pages (404, 403, 405, 413, 502, 504...), the
password prompt (401), a redirect, an `OPTIONS` answer, a `304`. A request takes the same fields
whichever location answered it and whatever internal hops (`try_files`, a directory's index) it
made, because rules match the path the client asked for, normalised once, never an internal target.

Not covered, because no site is known yet or because the answer is not a site's: a request the
server refuses before routing (`400` for a malformed request, `421` for a name the listener or
certificate does not serve, `431`, the connection ceiling's `503`), an ACME challenge, a `1xx`, and
the bytes of a WebSocket tunnel.

Inside one answer the order is fixed:

1. **The handler's fields**: the application's (PHP, CGI, proxied), or agensio's own (a file's
   `Content-Type`, `ETag` and `Last-Modified`, an error page's, a location's `add_headers`).
2. **The site's decisions, field by field**: `remove`, `set`, `default` (section 2.3).
3. **The guards**, which no rule can loosen: an answer behind a password (`[[site.auth]]`) is never
   one a shared cache may keep (`Cache-Control: private`, the CDN fields dropped), and the answers
   agensio marks `Cache-Control: no-store` (401, 403, 421) keep it.
4. **Framing**, which is the server's alone: `Content-Length`, `Transfer-Encoding`, `Connection`.

## 2. `[[site.response_headers]]`

### 2.1 Fields

| field | values | default |
|---|---|---|
| `path` | a normalised URL path (`/`, `/assets/`, `/embed/widget.html`) | required |
| `match` | `"prefix"` (whole segments) or `"exact"` | `"prefix"` |
| `set` | a table of field names and values: the field is sent with this value, replacing every copy the answer had | none |
| `default` | a table of field names and values: the field is sent only when the answer has none | none |
| `remove` | a list of field names: every copy is deleted | none |
| `when` | `"always"` or `"success"` (2xx and 304) | `"always"` |
| `endings` | a list of file endings (`["svg"]`, `["woff", "woff2"]`): the rule applies only to files agensio serves from disk whose name ends so | none: every answer |

A rule needs at least one of `set`, `default`, `remove`, and names a field in only one of them. A
prefix covers whole segments in any capitalisation, as the access rules do: `path = "/admin"` covers
`/admin`, `/Admin/` and `/admin/users`, never `/administrator`. At most 64 rules and 64 distinct field
names per site.

**`endings` reads the file agensio serves, not the address.** A rule with `endings` applies to an
answer agensio makes from a file on disk, after `try_files` and a directory's index, when that
file's name ends with one of them, in any case; it never applies to an application's answer. So
`/about/`, served from `about/index.html`, is an `.html` answer, and so is a single-page
application's route served from its shell; and a `/sitemap.xml` that PHP generates (WordPress with
Yoast, Shopware) is the application's, untouched by a rule meant for `.xml` files on disk. That is
how nginx behaves too: a `location ~ \.xml$` loses its fields when the request falls back to PHP.

```toml
[[site.response_headers]]
path = "/"
set = { "Referrer-Policy" = "strict-origin-when-cross-origin" }
default = { "X-Frame-Options" = "SAMEORIGIN" }
remove = ["X-Powered-By"]
```

### 2.2 Which rule decides: per field, the longest

**For each field, the most specific rule that names it decides; rules that name different fields
all apply.** The most specific is the one with the longest path; at the same path, an exact rule
before a prefix, and a rule whose `endings` the served file has before one without `endings`. The
order the rules are written in never matters, and nothing is inherited or dropped as a block: a
deeper rule changes the fields it names and no others.

```toml
[[site.response_headers]]
path = "/"
set = { "Referrer-Policy" = "strict-origin-when-cross-origin", "X-Content-Type-Options" = "nosniff" }
default = { "X-Frame-Options" = "SAMEORIGIN" }

[[site.response_headers]]
path = "/embed/"
remove = ["X-Frame-Options"]

[[site.response_headers]]
path = "/embed/"
when = "success"
set = { "Cache-Control" = "public, max-age=3600" }
```

| request | `Referrer-Policy` | `X-Content-Type-Options` | `X-Frame-Options` | `Cache-Control` |
|---|---|---|---|---|
| `/page` | set (rule `/`) | set (rule `/`) | `SAMEORIGIN` unless the application sent one (rule `/`) | the application's |
| `/embed/w.html`, found | set (rule `/`) | set (rule `/`) | removed, the application's too (rule `/embed/`) | `public, max-age=3600` (rule `/embed/`) |
| `/embed/gone`, a 404 | set (rule `/`) | set (rule `/`) | removed (rule `/embed/`) | none: the `success` rule does not apply |

This is the answer to the trap behind the most-viewed questions about nginx (`add_header` in a
nested block drops every inherited field) and about Caddy and Apache (a later or broader rule
silently wins): here a field is decided by the most specific rule that mentions it, and `path_check`
names that rule (section 7).

### 2.3 `set`, `default`, `remove`

- **`remove`** deletes every copy of the field, whoever put it there: the application, a location's
  `add_headers`, the preset's baseline.
- **`set`** deletes every copy and sends one, with the rule's value. The browser never sees two
  `X-Frame-Options` or two `Access-Control-Allow-Origin`, the duplicates every server that only
  appends produces when the application sends the field too.
- **`default`** sends the field only when, after the application's fields and agensio's own are in
  place, the answer has no copy of it (a copy a proxy location's `hide` drops is none). The application's own value wins. This is the verb for a
  site-wide policy over an application that may know better on some pages: WordPress's admin sends
  its own `X-Frame-Options`, Django its own `Referrer-Policy`.

Field names are matched in any case and written as given (lowercased over HTTP/2 and HTTP/3).

**A Content-Security-Policy is the one field where `set` can weaken a site**: a second policy only
narrows what the first allows, but `set` replaces the application's policy with the rule's. On an
application site, use `default` for a CSP, so a policy the application sends stays.

### 2.4 Cache fields: `when = "success"`, and what the application says

A rule with `when = "success"` applies to `2xx` and `304` answers only; the others (`"always"`, the
default) to every answer. A cache lifetime belongs on success only: a year-long `immutable` on a 404
keeps the error in every browser and CDN for a year (reported against Caddy on a Kirby site). So a
`Cache-Control` or `Expires` that grants freshness (`max-age` above 0, `s-maxage`, `public`,
`immutable`, a future date) is refused in a rule without `when = "success"`; `no-store`, `no-cache`,
`private` and `max-age=0` are accepted anywhere.

**A rule never makes an application's answer one a cache may hand to another visitor** (2026-10-17,
the review's D4). nginx's `add_header` appends, so a configuration translated from nginx meant the
application's own `Cache-Control` to stay, and a `set` replaces it. Two guards, for an application's
answer (PHP, a proxied application, CGI):

- **Its restrictions stand.** Where the application's `Cache-Control` says `no-store` (no cache keeps
  the answer, RFC 9111 5.2.2.5), `private` (no shared cache does, 5.2.2.7) or `no-cache` (none reuses
  it without asking, 5.2.2.4), a rule's `set` or `remove` of the field applies only when its own value
  holds those restrictions too (`no-store` holds all three); otherwise the application's copies go
  out as they are and the rule's line is left out. So `set = { "Cache-Control" = "no-store" }` still
  replaces an application's `private, max-age=600`, while `public, max-age=3600` leaves PHP's session
  answer (`no-store, no-cache, must-revalidate`) and WordPress's signed-in pages (`no-cache,
  must-revalidate, max-age=0, no-store, private`) as they are.
  - **The fields only shared caches read** (`CDN-Cache-Control` and its vendor forms,
    `Surrogate-Control`, `Edge-Control`): a CDN reads the first such field on its own list and then
    ignores `Cache-Control` and the others (RFC 9213 2.2). Lists differ: Cloudflare reads its own
    field and `CDN-Cache-Control`, Fastly and Varnish read `Surrogate-Control` (Varnish's built-in
    rules no longer look for `private` in `Cache-Control` once it is there), Akamai `Edge-Control`. So
    the application's restriction in any one of them holds for all of them: a rule's lifetime in such
    a field is left out where any of the application's says `no-store`, `private` or `no-cache`
    (`CDN-Cache-Control: no-store` stops a rule's `Surrogate-Control`), and, where the application
    sends none of the rule's field, where its `Cache-Control` restricts (0.1.0-alpha.100, the alpha.99
    report; before, each field was judged alone).
  - **`Expires`**: a rule's is left out wherever the application's `Cache-Control` or one of its CDN
    fields restricts. Its `max-age` or `s-maxage` overrides `Expires` anyway (5.3), and `no-store` and
    `no-cache` leave it no say; but over a bare `private` a rule's date gave the browser a lifetime the
    application did not give (alpha.100). Akamai's own "honor origin" mode ignores `Expires` in the same
    cases.
- **An answer that is one user's gets no shared lifetime from a rule.** `Set-Cookie` does not stop a
  cache (RFC 9111 7.3): a CDN that keeps the answer hands the cookie, a session, to the next visitor.
  One user's answer is one that:
  - sets a cookie;
  - varies on `Cookie` or `Authorization`, or is `Vary: *` (alpha.100, the alpha.99 report): the
    application says the answer depends on who asks (RFC 9110 12.5.5), or that no cache can reuse it
    (RFC 9111 4.1). Django's session middleware sends `Vary: Cookie` and no `Cache-Control` on every
    page that read the session; a CDN that does not key its cache on `Cookie` would hand a signed-in
    page to the next visitor (Cloudflare honours `Vary` per field as its cache rules configure it,
    and never caches `Vary: *`; neither does Varnish);
  - answers a request with `Authorization`, which a shared cache may reuse only when the answer says
    `public`, `s-maxage` or `must-revalidate` (3.5).

  Such an answer gets a rule's `Cache-Control` lifetime as `private` with the browser's directives kept
  (`public, max-age=3600, immutable` goes out as `private, max-age=3600, immutable`, the password guard's
  form), and no rule's `Expires` or lifetime in a field only shared caches read. Where the rules leave
  it without `Cache-Control`, by leaving a lifetime out or by a `remove` of the application's (whether
  it sent one or not), it carries `Cache-Control: private`: without one a `200` is heuristically
  cacheable (4.2.2), and 7.3 asks the server to say what such an answer may become (the `remove` case
  since alpha.100). Varnish and Fastly do not cache an answer with `Set-Cookie` by default either; this
  holds where the cache in front does. A lifetime is `public`, a shared freshness above 0 (`s-maxage`,
  else `max-age`) or `stale-while-revalidate` / `stale-if-error` above 0 (RFC 5861), in a value without
  `no-store`, `private` or `no-cache`; any value of a field only shared caches read without those
  three counts as one.

What neither guard sees: a page the application marks with nothing that still shows a visitor's
data (read from the request's cookie, without setting one). So a `set` of a lifetime over an
application site is noted at load (`header_cache_set`, section 7): use `default`, so the
application's own `Cache-Control` stands, on the paths of public pages only. agensio's own answers
(files, error pages, redirects) carry no visitor's data and get a rule's value as written; behind a
password (`[[site.auth]]`) the guard decides every answer's cache fields (`docs/auth.md`).

### 2.5 What is set elsewhere

Some fields are the server's to write, or belong to a setting that does it right. A rule naming one
is refused at load, and the message names the setting to use:

| fields | why | instead |
|---|---|---|
| `Connection`, `Keep-Alive`, `Proxy-Connection`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `Content-Length`, `Content-Range` | framing: a wrong value breaks the connection or splits responses; HTTP/2 and HTTP/3 forbid the connection fields | the server writes them |
| `Content-Type`, `Content-Encoding`, `ETag`, `Last-Modified`, `Accept-Ranges`, `Age`, `Date`, `Vary` | the representation's own description, prebuilt into cached files and kept consistent with them | the built-in type table (by file extension) and the cache |
| `Location`, `Refresh` | redirects; a `remove` too, since agensio's own redirects carry them (a directory without its slash, a `[[site.redirect]]` answer) and a 301 without `Location` has no target | `[[site.redirect]]` (`docs/redirects.md`) |
| `Strict-Transport-Security` in `set` or `default` | sent over HTTPS only, once, with a checked value | `hsts` (`remove` is accepted, to strip an application's own) |
| `Server` | server-wide and agensio's own, on every answer: a `remove` did nothing (until 0.1.0-alpha.99 it loaded and `path_check` called it removed) | `[server] server_header` (`""` sends none) |
| `Alt-Svc` | can send browsers to another server for the whole origin | `[server] protocols`, `http3.alt_svc` (`remove` strips an application's own; agensio's stays) |
| `Set-Cookie`, `Clear-Site-Data`, `Service-Worker-Allowed` | reach beyond the site on a shared host: a cookie for a parent domain, clearing a whole registrable domain's data, lifting a service worker's path limit | the application's |
| `WWW-Authenticate`, `Proxy-Authenticate`, `Authentication-Info` | the password protocol | `[[site.auth]]` |
| `Expect-CT`, `Public-Key-Pins`, `Public-Key-Pins-Report-Only` | obsolete; pinning can lock visitors out | none |

`remove` takes any other name, and `Strict-Transport-Security` and `Alt-Svc` too, for an
application's own copy: agensio's own (the site's `hsts`, the `alt-svc` of HTTP/3) stays, and
`path_check` says so ("removed from an application's answer only").

### 2.6 Values

A value is fixed text: printable ASCII with inner spaces, no leading or trailing space, no control
character (RFC 9110 5.5), at most 4 KB, and 16 KB for all of a site's rules together. It is checked
once, at load, so no request can put a line break into an answer. There are no variables: a `$` in a
value is refused with a pointer to `proxy = { request_headers }`, which is where request fields with
variables go to an origin. A few values are checked for meaning too: `X-Frame-Options` is `DENY` or
`SAMEORIGIN` (`ALLOW-FROM` is ignored by every current browser); `Access-Control-Allow-Origin` is one
origin or `*`, never `*` together with `Access-Control-Allow-Credentials: true`, and never `null`:
it is the origin of sandboxed frames, `data:` URLs and local files, which any page can claim, so any
site could read the answers, with credentials a signed-in visitor's (MDN's warning; 0.1.0-alpha.99);
`X-XSS-Protection` other than `0` gets a warning (the filter it turned on could itself be abused
against pages, and Chrome, Edge and Firefox have none).

## 3. Examples

### 3.1 Security fields on a hand-written site

A site without `app` gets no baseline (`response_headers_baseline = true` gives it the `static` preset's).
The usual three by hand, on a site whose pages no other site embeds and whose application serves
every script with its right type, with the application's own values winning where it sends them:

```toml
[[site.response_headers]]
path = "/"
default = { "X-Content-Type-Options" = "nosniff", "Referrer-Policy" = "strict-origin-when-cross-origin", "X-Frame-Options" = "SAMEORIGIN" }
```

### 3.2 A page another site may frame

A rule at `/` sends `X-Frame-Options: SAMEORIGIN` (section 3.1); one directory is meant to be
embedded by a partner:

```toml
[[site.response_headers]]
path = "/embed/"
remove = ["X-Frame-Options"]
default = { "Content-Security-Policy" = "frame-ancestors 'self' https://partner.example" }
```

### 3.3 Fields by kind of file: SVG that runs no script, fonts for another origin

An SVG file can hold JavaScript, and an uploaded one opened directly would run it as the site.
Shopware, Joomla and FreshRSS ship this field on every SVG for that reason; PrestaShop, TYPO3 and
Craft let other origins load the fonts:

```toml
[[site.response_headers]]
path = "/"
endings = ["svg"]
set = { "Content-Security-Policy" = "script-src 'none'" }

[[site.response_headers]]
path = "/"
endings = ["woff", "woff2", "ttf", "otf"]
set = { "Access-Control-Allow-Origin" = "*" }
```

Both apply to files agensio serves wherever they are; an application's answer is never touched
(2.1). A fixed value (`*`, or one origin) is all a rule can say. Several allowed origins need the
server to echo the request's `Origin` and add `Vary: Origin`, and credentials need more checks: that
is the application's, or a typed `cors` setting later (section 10), never a list in one field,
which browsers reject.

### 3.4 A staging copy kept out of search engines

```toml
[[site]]
server_name = ["staging.example.com"]
# ...

[[site.response_headers]]
path = "/"
set = { "X-Robots-Tag" = "noindex, nofollow" }
```

The rule belongs to the staging site's own block, so it cannot reach production through a shared
setting. Copying the block to the production site would carry it along, which a later health finding
is meant to catch (section 7).

### 3.5 Long cache lifetimes for fingerprinted files

```toml
[[site.response_headers]]
path = "/assets/"
when = "success"
set = { "Cache-Control" = "public, max-age=31536000, immutable" }
```

Only for files whose names change with their content (`app.3f9a1c.js`); otherwise a browser keeps
the old file for a year. A managed site has this as `rules.cache` with `immutable: true`
(`docs/configuration.md` 15). The same by kind of file, for themes and plugins whose names do not
change, with a shorter lifetime:

```toml
[[site.response_headers]]
path = "/wp-content/"
endings = ["css", "js", "png", "jpg", "webp", "svg", "woff2"]
when = "success"
set = { "Cache-Control" = "public, max-age=2592000" }
```

On a single-page application, keep the year-long rule off the paths its fallback answers: a route
that falls back to the shell under `/assets/` would cache the shell for a year. `-t` warns about
such a rule (section 7).

### 3.6 What an application discloses

```toml
[[site.response_headers]]
path = "/"
remove = ["X-Powered-By", "X-Generator"]
```

### 3.7 A Content-Security-Policy, carefully

A policy written for a site without testing it breaks the site: inline scripts, an analytics tag, a
payment widget. The safe path is the report-only field first, which browsers evaluate and report
without enforcing:

```toml
[[site.response_headers]]
path = "/"
default = { "Content-Security-Policy-Report-Only" = "default-src 'self'; img-src 'self' data:; frame-ancestors 'self'" }
```

then, once the browser's console stays clean, the same value as `Content-Security-Policy`, in
`default` so an application that sends its own policy keeps it.

### 3.8 What rules do not do

- **Conditions** on method, query, client address or country: none. The answer depends on the path
  and on success or not, nothing else.
- **Variables and regular expressions**: none, for the same reasons as in redirects (the record of
  CVEs in rewrite engines, and the "which rule fired" question).
- **Cookie flags** (`Secure`, `HttpOnly`, `SameSite` on the application's cookies): not by editing
  `Set-Cookie`; a typed setting later if a real case needs it.
- **Appending to a list field** (a second `Link`, a second, narrowing CSP): not in the first step.

## 4. The security baseline per preset

### 4.1 What it holds, and what it leaves to the owner

The baseline holds only what is safe to add without asking: **nothing in it can break a page that
works today**. Three things meet that bar:

| field | on which answers | why it cannot break a page |
|---|---|---|
| `Referrer-Policy: strict-origin-when-cross-origin`, as `default` | every answer | it is what browsers do without the field (Chrome and Edge since 85, Firefox since 87, Safari since 15), so a current browser behaves as before; older browsers and scanners are told the same; an application's stricter value (Django's `same-origin`) wins |
| `X-Content-Type-Options: nosniff` | agensio's own answers only: the files it serves and its error pages | agensio set their `Content-Type` itself, from a table that knows `.js`, `.mjs`, `.css`, `.wasm`; Drupal's and TYPO3's own `.htaccess` files add the same field to every file Apache serves |
| `X-Powered-By` removed | the application's answers | no client reads it; PHP's own is already off in the pools agensio writes (`php_admin_flag[expose_php] = off`), so what is left is a framework's (`Express`, `Statamic`) |

On `app = "static"`, where agensio serves every page itself, the baseline also sends
`Cache-Control: no-cache` on the HTML files it serves (an `.html` file, a directory's
`index.html`, a single-page application's shell). Today agensio sends no `Cache-Control` on a file,
so browsers keep an HTML page for a guessed time (a tenth of its age since it last changed) and
show an old version after a deploy; with `no-cache` they ask each time and get a `304` when nothing
changed, as Netlify and Cloudflare do by default and Vite, VitePress and Gatsby ask for. It cannot
break a page; it costs a conditional request per page view. A rule's own `Cache-Control` decides
instead.

Left out, because each one can break a working page and only the site's owner knows whether it
does:

| field | what it breaks when added to an application that sent none | applications that send it themselves |
|---|---|---|
| `X-Frame-Options`, or `frame-ancestors` in a CSP | every legitimate embedding: WordPress post embeds on other sites (its `/embed/` pages carry no frame field on purpose), an Uptime Kuma status page whose owner switched Kuma's own field off, a dashboard or a booking widget meant for other sites, a headless front end in Wagtail's preview panel, TYPO3's preview across domains. "Only when absent" cannot tell an application that never thought about framing from one that left the field out to allow it | WordPress (admin and login), Drupal, Rails, Redmine, Django, Wagtail, Kanboard, TYPO3's backend, Uptime Kuma |
| `nosniff` on the application's answers | a script the application serves with the wrong type: PHP printing JavaScript under its default `text/html`, JSONP sent as `application/json`, a script with no type (reported for Joomla, PulseCMS, Chameleon, eXeLearning) | Drupal, Rails, Django, Kanboard, TYPO3's backend; WordPress on its REST API |
| `Content-Security-Policy` | whatever the policy did not foresee: inline scripts, an analytics tag, a payment form | Kanboard, TYPO3's backend |
| `Permissions-Policy` | a feature the site uses (the camera for a video call, geolocation for a store finder) | none of these |
| `Strict-Transport-Security` | plain HTTP, and clicking past a certificate warning, for its whole `max-age` | Kanboard and TYPO3 when switched on; here it is `hsts` (section 5) |

Those are decisions the agent takes with the user, one at a time and with what each would break
(section 6). The baseline is not meant to raise a scanner's grade, and does not by much: on
2026-10-12 securityheaders.com graded a page without its six fields F, with `nosniff`,
`Referrer-Policy` and a frame field C, adding HSTS B, Permissions-Policy A, and a CSP A+; the MDN
Observatory takes 25 points for a missing CSP and 20 each for a missing HSTS and frame field. A
grade comes from those decisions, not from a default.

### 4.2 Per preset

What each application sends itself was read in its 2026 releases' source
(`research_notes/App default security headers/notes.md` has the files and lines):

| `app` | the application sends itself | the baseline adds | the agent offers, after asking |
|---|---|---|---|
| `wordpress` | on wp-admin, wp-login, admin-ajax and admin-post: `X-Frame-Options: SAMEORIGIN`, `frame-ancestors 'self'` (6.9 on), `Referrer-Policy`; `nosniff` on the REST API and admin-ajax; nothing on front-end pages | `Referrer-Policy` on the front end; `nosniff` on uploads, themes' and plugins' files and error pages | a frame field on the front end, only when no other site embeds the posts (WordPress's own embeds need framing, and their address is a suffix, `/post/embed/`, that a path rule cannot exempt) |
| `drupal` | on every Drupal answer: `nosniff`, `X-Frame-Options: SAMEORIGIN` (only if not set), `X-Generator` | `Referrer-Policy`; `nosniff` on files, as Drupal's `.htaccess` does under Apache | `X-Generator` removed; a CSP through Drupal (Seckit) or a report-only rule |
| `laravel` | nothing (`FrameGuard` exists, not registered); Statamic `X-Powered-By: Statamic` | `Referrer-Policy`; `nosniff` on files; Statamic's `X-Powered-By` removed | a frame field, unless the application is embedded elsewhere |
| `grav` | the 1.7 admin plugin: `X-Frame-Options: DENY` on admin pages; core nothing | `Referrer-Policy`; `nosniff` on files | a frame field on the front end |
| `php` (TYPO3, Kanboard, any other) | TYPO3 13 and 14: the backend sends a frame field, `nosniff`, `Referrer-Policy` and a CSP, the front end nothing; Kanboard: a CSP, `nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block` on every answer | `Referrer-Policy` where the application sends none; `nosniff` on files, as TYPO3's `.htaccess` does | TYPO3's front end: a frame field, unless pages are embedded elsewhere |
| `rails`, `redmine` | on every controller answer: `X-Frame-Options: SAMEORIGIN`, `nosniff`, `Referrer-Policy`, `X-Permitted-Cross-Domain-Policies: none`, `X-XSS-Protection` (`0` on Rails 7.1 and later, `1; mode=block` on Redmine, which keeps the older defaults); `public/` files through Rails' own file server, with none of them | `nosniff` on agensio's error pages; `Referrer-Policy` where Rails sends none (the `public/` files its own file server answers) | `config.action_dispatch.default_headers` is the application's; nothing more |
| `django`, `wagtail` | `nosniff`, `Referrer-Policy: same-origin`, `Cross-Origin-Opener-Policy: same-origin`, `X-Frame-Options: DENY`, each only if absent; Wagtail's previews `SAMEORIGIN` | `nosniff` and `Referrer-Policy` on `/static/` and `/media/`, which agensio serves (the preset's `/media/` CSP and `nosniff` stay) | Django's settings are the place; nothing more |
| `node` | Express: `X-Powered-By: Express` on everything, `nosniff` only on its own error pages; Uptime Kuma: `X-Frame-Options: SAMEORIGIN` unless its owner switched it off, no `X-Powered-By` | `Referrer-Policy`; `X-Powered-By` removed | a frame field, unless the application is embedded elsewhere (Uptime Kuma decides for itself) |
| `proxy` | the application's | `Referrer-Policy`; `X-Powered-By` removed | depends on the application |
| `static` | (agensio answers everything) | `Referrer-Policy` and `nosniff` on every answer; `Cache-Control: no-cache` on HTML files | a frame field and a CSP, both safe to try on a site agensio serves alone |

A `[[site.response_headers]]` rule overrides the baseline field by field (a `set` of another value,
a `remove`), and `response_headers_baseline = false` turns the whole baseline off; `path_check` names the
baseline as the source of each field it adds.

## 5. HSTS through the same path

`hsts` (`docs/redirects.md` 4) is a `set` of `Strict-Transport-Security` at `/`, applied only to
answers sent over TLS (HTTP/1 over TLS, HTTP/2 and HTTP/3; never over plain HTTP or `h2c`, RFC 6797
7.2). Being on the same path as the rules, it reaches every answer of the site, PHP pages and errors
included, which today's managed `hsts: true` does not: it is rendered as a `[[site.location]]` at `/`
with `add_headers`, which reaches neither the PHP pages (another location) nor any error answer. And
as a `set`, it replaces an HSTS the application sends itself (a WordPress plugin, Drupal's Seckit),
so browsers see one, as RFC 6797 8.1 requires. The setting decides even over a stronger value
(Mastodon, GitLab, Keycloak and Umami send a longer `max-age` or `includeSubDomains`), so
`max_age = 0` can always clear it; when it replaces a stronger one, the server notes the
application's value once per site and health reports `hsts_narrows_application`.

## 6. Managed sites and the agent

- `site_create` and `site_update` take `response_headers_baseline: false` (the baseline off; `true`
  or `null` back on) and `response_headers`, a list of rules with the fields of section 2.1, sent
  whole like `redirects` (the list replaces the site's; `[]` clears it), judged by the load's own
  parse and checks (`load_response_header_rules`, as `path_check`'s preview is). They are rendered as
  `[[site.response_headers]]` in the managed file; `site_show` lists them in the same form, and the
  change's answer carries `response_header_notes`. (The key was first named `security_headers`, which
  did not say which direction it covers; renamed before release.)
- `agensio ctl site-update NAME --response-header "PATH set|default NAME=VALUE"` (the value may hold
  spaces), `--response-header-remove "PATH NAME"`, `--response-headers-file FILE` (a JSON list, for
  `match`, `when` and `endings`), `--no-response-headers`, `--no-response-headers-baseline` and
  `--response-headers-baseline`; the flags of one command make the whole list, the flags naming one
  path one prefix rule, as `--redirect` does; the site's other settings are kept.
- **The fields the baseline leaves out are offered, not applied.** After `site_install`, and when the
  user asks about security headers or a scanner's grade, the agent goes through them one at a time
  with what each would break (section 4.1): a frame field only after asking whether any other site
  embeds the pages (WordPress post embeds, a status page, a widget); a CSP as
  `Content-Security-Policy-Report-Only` first, enforced only once the browser's console stays
  clean; `hsts` when health suggests it. Where the application's own documentation configures a
  field on every answer (Laravel's nginx page sends `X-Frame-Options` and `nosniff`; Joomla, Craft,
  Nextcloud and Matomo do the same), the agent offers that value and names the page. `nosniff` on an
  application's answers leaves out `204`, which iOS Safari otherwise offers as a download (Ghost).
  It checks the result with `path_check` and, from outside, with the services of
  `docs/online-checks.md`.
- The MCP texts state what other servers do differently, because an agent brings their habits: the
  most specific rule decides, never the order; `set` replaces the application's field instead of
  adding a second; `default` is the verb for a CSP on an application site; cache lifetimes need
  `when = "success"`; a `noindex` belongs on a staging site only. Before applying, `path_check` with
  proposed `response_headers` shows the fields a path would get; after, the same call confirms them.

## 7. What `-t`, health and `path_check` say

- **Refused at load**: a name of section 2.5; a value outside section 2.6; a freshness-granting cache
  field without `when = "success"`; two rules with the same `path`, `match` and `endings` naming the
  same field; a field named in two verbs of one rule; an ending agensio never serves as a file
  (`php` on a PHP site, an ending the preset refuses); more than 64 rules or names, or 16 KB of
  values.
- **Warned**: a `set` of `Content-Security-Policy` on a site with `app` other than `static` (the
  application may send its own: use `default`); a `set` of a `Cache-Control` lifetime on such a site
  (`header_cache_set`: the guards of 2.4 keep the application's restrictions and a cookie's answer,
  not a page it marks with nothing; use `default`, on public pages' paths); `X-XSS-Protection` other
  than `0`; a year-long
  `Cache-Control` on a path the site's single-page fallback can answer (the shell would be kept
  under an asset's address for a year).
- **`path_check`** lists every field the site decides for the path, with its value and where the
  decision came from: `referrer-policy: strict-origin-when-cross-origin (baseline wordpress,
  default: the application's own wins)`, `x-content-type-options: nosniff (baseline, on the files
  and error pages agensio serves)`, `cache-control: public, max-age=3600 (rule /embed/, success
  only)`, `strict-transport-security: max-age=31536000 (hsts, over HTTPS)`, `x-powered-by: removed
  (baseline)`, `x-frame-options: removed (rule /embed/)`. It also takes proposed `response_headers`
  and answers as if they applied, and says which fields of section 4.1 the site does not send, for
  the agent to offer.
- **Health: `response_headers_suggested`** (info, alpha.94, asked for by the test host): for a live
  HTTPS site (TLS, an `app`, a real certificate served for a week, as for `hsts_suggested`) health
  asks the home page once, over loopback on its own thread, and names the fields of 4.1 the answer
  goes without: a frame field (`X-Frame-Options`, or `frame-ancestors` in a CSP), a CSP (a
  `Content-Security-Policy-Report-Only` counts), `Permissions-Policy`, `nosniff`. It reads the real
  answer, so an application that sends its own (Uptime Kuma, Django) gets no finding; a redirect or
  an error is not judged; HSTS stays `hsts_suggested`'s. The fix sends the agent to offer them one at
  a time with `path_check`'s `response_headers_offer`. What the owner refuses is recorded in
  `response_headers_offer_declined` (the four field names, any case; managed: the `site_update`
  field, `agensio ctl --decline-response-header NAME`), which this finding and `path_check`'s offer
  then leave out; it sends and removes nothing. That request also notes an application's own HSTS,
  so such a site needs no separate HSTS probe.
- **Health, later** (from the research's list): a security field the application sends twice; a
  rule's `X-Robots-Tag: noindex` on a site that looks live (no access or password rule at `/`, real
  visitors in its log). Only a rule is judged, never an application's own: Nextcloud, Roundcube and
  phpMyAdmin send `noindex` on purpose.

## 8. `add_headers` and the presets' own fields

`add_headers` on a location stays, for the presets that use it (Laravel's `/build/` lifetime,
Django's `/static/` and `/media/` fields, `rules.cache`) and for hand-written files that have it. It
adds its fields to successful answers of that location only, so it suits cache lifetimes and nothing
else; the documentation sends administrators to `[[site.response_headers]]`, and the managed
renderer stops using `add_headers` for `hsts`. A rule can still override a location's field: `set`
and `remove` act on every copy, `add_headers`' included, and `path_check` names both. Retiring
`add_headers` (moving the presets' fields to `when = "success"` rules) is a later step, once one
mechanism has proven itself.

## 9. Cost

A site with no `app`, no `hsts` and no `[[site.response_headers]]` keeps today's request path: no
lookup, one test of an empty pointer where the answer leaves, measured flat. With fields:

- **Which rules apply** is found once per request, when the site is known: a site whose rules are all
  at `/` (the baseline, `hsts`, a `/` rule) uses its resolved list directly; deeper rules sit behind a
  first-byte bitmap like the access rules' and a longest-prefix search over at most 64 paths. The
  result is carried on the request, not the response, so an error page made later keeps it. Rules
  with `endings` add one lookup by the served file's ending, made when agensio picks the file, on
  sites that have such rules.
- **HTTP/1**: the resolved fields are one prebuilt text block per path and kind of answer (success
  or not; agensio's own or the application's, for the baseline's `nosniff`), appended to the head,
  borrowed without a copy when nothing else is added, as the listener's `alt-svc` line is today.
- **HTTP/2 and HTTP/3**: each field goes through the connection's dynamic table, as `server`, `date`
  and `alt-svc` do: the first answer on a connection inserts it, every later one sends an index of
  one or two bytes.
- **An application's answer**: `set`, `remove` and the presence test of `default` are folded into the
  loop that already reads every field the application sent; a site without rules pays nothing more
  there. Where a rule decides a cache field or sends a lifetime (2.4), the answer's fields are read
  once more before that loop, for its `Cache-Control`, its fields for CDNs and `Set-Cookie`, and the
  request for `Authorization`: only on those paths.
- **The gate**: `bench/ab.sh <base> -A` with two new rows (a site with `app = "static"` and its
  baseline, serving a cached 1 KB file; a site with a rule at `/` and a deeper one, on a path under
  the deeper one), `-2` and `-3` for the HTTP/2 and HTTP/3 writers, `-P` for a proxied answer with
  `set` and `remove` rules (`proxy-hdr`) and with a `Cache-Control` set too (`proxy-cache`, the read
  of 2.4's guards).

## 10. Decisions (2026-10-13)

1. **The name**: `[[site.response_headers]]`, so that nothing in its name overlaps with
   `proxy = { request_headers }`, the request fields sent to an origin; a `$` variable in a response field,
   the one confusion left, is refused with a pointer there. The managed field and the `agensio ctl`
   flags follow it (`response_headers`, `--response-header`).
2. **The baseline holds only what cannot break a page** (section 4.1): `Referrer-Policy` as
   `default` on every answer, `nosniff` on agensio's own answers, `X-Powered-By` removed from the
   application's. This narrows what was discussed on 2026-10-12 (`nosniff` everywhere, and
   `X-Frame-Options: SAMEORIGIN` on the presets with a login): the application sources show that
   the applications that need a frame field send it already, and that adding one where it is absent
   breaks the embeddings an application left it out for (WordPress post embeds, Uptime Kuma's
   switch, widgets), silently, on a path nobody connects to a header. `nosniff` on application
   answers has the same record with scripts of the wrong type. Both are offered by the agent
   instead, after asking (section 6).
3. **Sites without `app` get no baseline**: hand-written minimal sites and the benchmark templates
   stay as they are; `response_headers_baseline = true` gives such a site the `static` preset's baseline.
4. **`X-Powered-By`**: removed by the baseline from the application's answers; PHP's own is already
   off in the pools agensio writes. `X-Generator` (Drupal) stays unless a rule removes it: it names
   the application, which a scanner learns from the pages anyway.
5. **CORS with several origins**: not in rules; a typed `cors` setting later, when a real case asks
   for it.
6. **`add_headers`**: kept for presets and hand-written files, no longer advertised; retired later.
7. **Before building**: more use cases are checked against this design and `docs/redirects.md`
   first; done, section 11.
8. **`endings` reads the file agensio serves** (2.1), never the address and never an
   application's answer; at the same path a rule with matching `endings` decides before one
   without.
9. **`no-cache` on HTML in the `static` baseline** (4.1).
10. **`hsts` replaces an application's own HSTS even when it is stronger**, and health reports
    `hsts_narrows_application` (section 5).

## 11. Checked against the applications' own configurations (2026-10-13)

The reviews of `docs/redirects.md` section 12 (the official configurations of 21 PHP applications
and 25 proxied ones, 8 static hosting platforms and 16 site generators with about 6,000 real rule
files) read every response-field directive too; the notes are in
`research_notes/Official configs vs redirects and headers/`.

### 11.1 What it confirmed

- **No frame field in the baseline**: 21 of the 25 proxied applications decide framing themselves,
  and Vaultwarden's own wiki shows an `X-Frame-Options: DENY` that would break its WebAuthn and Duo
  pages.
- **A CSP as `default`**: 20 of the 25 send their own policy, 10 with nonces or hashes that a `set`
  would break; FreshRSS's guide asks the server not to overwrite its CSP.
- **`Referrer-Policy` as `default`**: a site-wide `no-referrer` breaks Paperless-ngx's login, and
  TYPO3's backend checks the referrer.
- **Fixed values only**: no configuration needs the server to echo `Origin`; the only variables in
  response fields are cache-debugging ones (Mastodon's `X-Cached`) and Mattermost's `X-Early-Data`.
- **`set` replaces**: Drupal's and Nextcloud's Apache files pair `Header onsuccess unset` with
  `Header always set` for one field, which is what `set` does in one step.
- **How common the fields are**: security fields on every answer in 36.4 % of `_headers` files;
  the commonest value of all is `public, max-age=31536000, immutable` (456 lines).
- **Not needed**: ETag removal (TYPO3, PrestaShop and FreshRSS do it; it only costs revalidation),
  `merge` or `append` verbs, `preload`, `Set-Cookie`, HPKP (commented examples only).

### 11.2 What it changed (decided 2026-10-13)

1. **`endings`** (2.1): 14 of the 21 PHP applications attach fields to file endings: a CSP on SVG
   and PDF files (Shopware, Joomla, FreshRSS, MediaWiki, TYPO3), CORS on fonts and images
   (PrestaShop, TYPO3, Craft), `no-store` on archives and previews (Magento, Matomo), lifetimes on
   assets; so do 8.9 % of `_headers` and 8.7 % of `firebase.json` files. Five (Drupal, TYPO3,
   PrestaShop, FreshRSS, Shopware's Caddy example) keep those fields off what PHP answers, which
   the served-file reading does by itself.
2. **`no-cache` on HTML in the `static` baseline** (4.1): 12.1 % of `_headers` files; Vite,
   VitePress and Gatsby ask for it; Netlify and Cloudflare do it by default.
3. **`immutable` in `rules.cache`** (3.5).
4. **`hsts` over a stronger application value** (section 5).
5. **The agent's offers follow the application's documentation** where it configures a field on
   every answer: eight of the PHP applications' configurations send `nosniff`, five a frame field
   (section 6).

### 11.3 Left for later

- **Path patterns** in a rule's `path` (`**/_app/immutable/` for Grav, `/js/container_*_preview.js`
  for Matomo): two applications.
- **Conditions on the query** (`immutable` only with `?v=`: Nextcloud, FreshRSS) and on statuses
  beyond success (Ghost's `204`).
- **A second, narrowing CSP** (BookStack and Gitea invite it; none needs it).

What the reviews found outside both designs (the client-address fields passed to proxied
applications, error pages with their status, clean addresses, a type table per site) is listed in
`docs/redirects.md` 12.4.

## 12. How it will be built and tested

Each step is its own commit, with tests that fail on the code before it, and the A/B of section 9
where the request path changes.

1. **The mechanism, with `hsts` as its first user** (built in alpha.75; the HSTS bug, `docs/redirects.md` 13.1): the
   failing test first, a managed WordPress fixture over TLS whose PHP page, static file and 404
   carry one `Strict-Transport-Security`, with an application's own replaced, and none over plain
   HTTP; then the resolved list on the request, the three writers, the upstream loop.
2. **`[[site.response_headers]]`** (2a built in alpha.89: the fields, per-field resolution, `when`,
   the refused names and the value checks, applied on every answer; 2b `endings` in alpha.90, an
   ending inside another counting for it (`gz` in `tar.gz`); 2c in alpha.92, `path_check` naming each
   field's decision and previewing proposed rules): the fields,
   `endings` on the served file, per-field resolution,
   `when`, the refused names and the value checks, `path_check` with its preview. A property test
   checks the resolution against a brute-force reading of the rules (for random rule sets and paths,
   every field's decision equals the most specific rule naming it), and the HTTP/1, HTTP/2 and
   HTTP/3 heads of one answer are compared field by field.
3. **The baseline per preset** (with `no-cache` on a static site's HTML) and `response_headers_baseline`,
   with the fixture sites of the integration suite checked for the fields and for an application's
   own value winning (built in alpha.94: the baseline is rules at `/` marked as the baseline's, below
   every written rule at their path, its `endings` rule included, so a written rule naming a field
   decides; `nosniff` and `no-cache` are `default`s, so a location's `add_headers` copy stands, and
   `nosniff` is marked for agensio's own answers, which the upstream loop leaves alone; a managed
   static site's file names `app = "static"`, which the renderer left out before; the baseline and
   the site's rules name at most 64 fields together).
4. **The agent's side**: `site_update` fields, `agensio ctl` flags, the MCP texts of section 6, the
   reference rows, the cookbook recipes linking here; this document installed with the others (built
   in alpha.94, asked for by the test host: a managed WordPress site graded D on securityheaders.com
   and had no way to carry rules; `path_check`'s `response_headers_offer` lists, for a page, the
   fields of 4.1 nothing the site decides sends there, each with what it could break).
