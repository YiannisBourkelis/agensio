# Redirects, HSTS and response headers: review of what is built (2026-10-14)

What 0.1.0-alpha.75 to alpha.94 built (`http`, `canonical`, `hsts`, `[[site.redirect]]`,
`[[site.response_headers]]` with `endings`, the per-preset baseline, the managed fields, `path_check`,
health's findings), checked against the research the designs came from:

- **What administrators need and complain about**: `reports/Web server headers and redirects.md` and
  its notes (admin complaints, panels and site owners, standards): 98 needs.
- **What other servers offer and where they trip administrators up**: nginx, Apache, Caddy,
  Traefik, HAProxy, LiteSpeed, h2o, IIS: 62 capabilities, 45 pitfalls.
- **What applications' official configurations ask for**: 21 PHP and 25 proxied applications, 8
  static platforms, 16 site generators, and what each application sends itself.

The detailed tables, with every source, are in `research_notes/Redirects headers and HSTS review/`
(`admin_needs.md`, `other_servers.md`, `app_configs.md`; `built.md` is the feature list they were
judged against). The defects below were confirmed in the code, two of them on a running server.

## 1. Verdict

The design holds. The problems administrators report most (fields that vanish in a nested block,
fields missing on error answers, duplicate fields from the panel and the application, rules whose
order decides, a redirect status chosen silently, a mistaken 301 cached forever, open redirects
from a path join, loops, HSTS twice or on plain HTTP, redirects that a support ticket or a shell is
needed for) are all covered, most of them by construction. Of the 45 pitfalls documented for the
other servers, agensio avoids all but two. No conflict was found between the per-preset baseline
and what any of the 46 applications sends itself.

What is missing falls in three groups: a handful of defects in what was built (section 2), managed
HSTS values (section 3), and features the static sites and migrations need that were left for later
(section 4).

## 2. Defects in what is built

Small, each a fix with its test; the first five have no request-path cost.

| # | defect | how it shows | fix |
|---|---|---|---|
| D1 | **`remove = ["Location"]` is accepted** | agensio's own redirects (a directory without its slash, a `[[site.redirect]]` answer) go out as a 301 with no target; checked on a running server | refuse `Location` and `Refresh` in `remove` too, naming `[[site.redirect]]` |
| D2 | **`remove = ["Server"]` is accepted and does nothing**, and `path_check` says "removed" | `Server: agensio` stays on every answer; checked on a running server. Three application translations would use it (Vaultwarden, Paperless, Nextcloud AIO) | refuse it with the pointer to `[server] server_header`; `remove = ["Alt-Svc"]`: say in `path_check` that only an application's copy goes |
| D3 | **`Access-Control-Allow-Origin: null` is accepted, also with `Allow-Credentials: true`** | MDN: "any origin can create a hostile document with a null origin"; with credentials, any page reads credentialed answers | refuse `null` (the research's own table said so) |
| D4 | **A rule's `set` of a lifetime replaces an application's `private` or `no-store`** | `set = { "Cache-Control" = "public, max-age=3600" }` over a PHP path makes logged-in pages storable by a CDN; nginx's `add_header` appends instead, so a translated configuration is the risk | keep an application's `private`/`no-store`, as the password guard keeps `private`, and note such a `set` at load (suggest `default`) |
| D5 | **The directory redirect (`StaticHandler::redirect_slash`) bypasses the redirect writer** | no `Cache-Control` (Chromium keeps a 301 forever; the rules get a day), the query dropped (nginx keeps it), the decoded path not re-encoded (spaces, `#`, `?` garble it; a directory named with a leading `\` would give `Location: /\name/`, the class of Tomcat CVE-2018-11784, unlikely since the directory must exist) | build it with the redirect writer: encode, check, keep the query, a day's lifetime |
| D6 | **`.svgz` is served without `Content-Encoding: gzip`** | browsers cannot render it; no rule can fix it (`Content-Encoding` is the representation's, refused). Nextcloud, Drupal and TYPO3 declare it | add the encoding for `svgz` in the built-in table |
| D7 | **A CORS preflight on a password-protected path gets 401** | a preflight never carries credentials; the password check runs before the `OPTIONS` answer (`dispatch.cpp`) | answer a static location's `OPTIONS` before the password rule, as the research's secondary guidance says (it reveals only the methods). For an application path behind a password (a protected API), passing an unauthenticated preflight to the application is a design question: the `cors` setting of gap 10, which answers it without the application, is the cleaner answer |
| D8 | **Docs that promise what is not built** | `docs/headers.md` 3.5 and 11.2 promise `rules.cache` with `immutable` (decided 2026-10-13, never built); `docs/examples/basics.md` still sends `immutable` to a root additions file (a `response_headers` rule does it now); CLAUDE.md says the MIME table is "overridable from config" (it is not); headers.md 7's `-t` warning for a year-long `Cache-Control` over a path the single-page fallback answers is not built | build `immutable` and the warning, correct the rest |

Lower: `http` and `canonical` always answer 308 (RFC 9110 notes old clients may not know it; no
reported failure; a sentence in the docs). A fragment in a redirect's `to` is sent (legal; the
research advised refusing it).

## 3. Managed HSTS: the most important gap in what is built

The managed `hsts` field is a boolean. A managed site can turn on a year of HSTS and cannot:

- **take it back**: `hsts: false` stops the field, and browsers keep the policy for up to a year.
  RFC 6797 and the most-viewed HSTS questions (SF 1011861, SO 33268264, 329k views) say the cure is
  `max-age=0` for a while; `docs/redirects.md` 4.5 prescribes it, and the managed path cannot send it.
  The research calls HSTS "the field administrators most regret".
- **ramp up** (a week, then a year), as hstspreload advises.
- **match the application**: 15 of the applications document a value of their own (Mastodon and
  GitLab two years, Keycloak and Home Assistant `includeSubDomains`). For the four that send a
  stronger value themselves, `hsts: true` narrows it (health warns) and `hsts: false` is the only
  managed answer.

Suggestion: the managed field takes `{ max_age, subdomains }` as the site file does; `hsts: false`
on a site that had it renders `max_age = 0` and records when; health reports `hsts_clearing` until
the old lifetime has passed, then gives the line that removes it; the MCP text proposes the
application's documented value and asks before `subdomains`. No request-path cost.

## 4. Gaps, ranked by the weight of the evidence

| rank | gap | evidence | suggestion (agensio's style: typed keys, fixed values, no regex, cost only where used, managed) |
|---|---|---|---|
| 1 | **Error pages served with their status** | 17 applications and every static platform (10 generators make a `404.html`; Mastodon, Discourse, GitLab, Paperless want a page when the origin is down); all 7 servers with an error-page feature have one. Today a `try_files` fallback answers 200, a soft 404 | `error_pages = { 404 = "/404.html", 503 = "/busy.html" }`: a file of the root, served as a file with the status kept, never run; for proxied sites the answers agensio makes when the origin fails, never replacing an application's own body; managed field, `path_check`, `-t` for a missing file |
| 2 | **Clean addresses** | 11 generators and every platform: `/about` from `about.html` (Next.js export, SvelteKit, VitePress, Astro write them), or from `about/index.html` without the hop | two fixed `try_files` steps, `$uri.html` and `$uri/index.html`; `rules.clean_urls` on managed static sites |
| 3 | **Maintenance** | Google's guidance: a 503 with `Retry-After` for a few days, never a redirect or `noindex`, `robots.txt` still answered. Owners and agents reach for a 302 or `noindex` without it. Designed (redirects.md 7), not built | `maintenance = { until, allow = ["@office"], page }`; one flag where the site is known; health past a few days |
| 4 | **The single-page fallback on a managed static site** | 7 tools; 45.5 % of `_redirects` files; needs a root additions file today | `rules.front_controller` naming an `.html` file on `app = "static"`; a missing asset stays 404, never the shell |
| 5 | **Migrations from Apache hosting: `.htaccess` ignored without a word** | cPanel writes its redirects and the owner's `Header` lines there; after a move they vanish, with no finding (the install scan reads only whole-directory denials) | a read-only scan at install and in health naming the ignored `Redirect`, `RewriteRule [R]`, `Header`, `ErrorDocument` lines, and an MCP text on translating them |
| 6 | **A redirect cannot leave a path out** | nginx's `location / { return 301 ...; }` beside `location /api/ { proxy_pass ... }` keeps the API; here a rule from `/` takes `/api/` and webhooks too (with 301 their POSTs become GETs), with no note | a rule with `serve = true` (not redirected below it), and a load note when a redirect covers a location that runs or proxies |
| 7 | **The commonest HTTPS loop goes undetected**: a CDN not in `trusted_proxies` | "in my case it was Cloudflare" (SO 46413494's top answer), Cloudflare's own troubleshooting page, the ELB threads | note, on the redirect path only, a request from an untrusted address carrying `X-Forwarded-Proto: https`; health `proxy_untrusted_https` naming the address and the fix |
| 8 | **A type table per site** | 9 applications (`.svgz`, extensionless `.well-known` files, Matrix's JSON, text defaults) | after D6, `types = { "ending" = "type", "/exact/path" = "type" }`, prebuilt into the cache entry |
| 9 | **"Which layer set this field", and redirect chains across sites** | the most-viewed header threads; the research names it one of two questions no server answers | `path_check` with `fetch: true`: one loopback request, off the workers, listing each field received with its origin, duplicates flagged, a 3xx followed across this server's sites |
| 10 | **CORS beyond a fixed value** | the largest questions in the whole evidence (2.57 M views on a preflight, 1.30 M on several origins); proxied APIs where Traefik answered preflights itself | a typed `cors` (path, origins, methods, headers, credentials, max_age) answering preflights before the application; decided "when a real case asks" (headers.md 10.5): the evidence is that case for preflights |
| 11 | **Staging and indexing** | a `noindex` left on a launched site "can deindex an entire site", found days later; several sources, secondary | a managed `staging` flag rendering the rule, and the planned health finding for a rule's `noindex` on a live site |
| 12 | **Large redirect lists** | platforms sell 10,000 to 1,000,000 rows; Kinsta imports 5,000 per CSV; WP Engine's 1,000 limit sends owners back to plugins | a per-site data file of exact rules beyond 1,000, same checks and index; CSV accepted by `--redirects-file` |
| 13 | **Nothing suggests `canonical`** | every panel puts the www/bare choice first (Plesk warns rankings split) | health info for a site listing a name and its `www.` twin without `canonical`, with a recorded "both serve" |
| 14 | **An application's own duplicate security fields** | the second most reported header problem; Safari and Chrome cases that broke WordPress admin | the planned health finding, noted in the upstream loop (needs the `-P` A/B) |

Each of these is single-digit or weaker in the evidence: case-insensitive matching as an opt-in for lists
imported from Caddy or nginx `map`; `*`/`**` in a header rule's `path` (Grav, Matomo, Element);
internal rewrites that drop a segment (Magento, PrestaShop, WordPress multisite); upstreams by host
name (Ghost, Mastodon, Plausible); a lifetime for every served file without listing endings (six PHP
applications' `ExpiresDefault`); a prefix location ending in `/` that does not redirect the bare path as
nginx does; cookie attributes (LiteSpeed's `ForceSecureCookie`); revalidation of the version and
manifest files a static deploy changes in place.

## 5. What the evidence says about the decisions

Kept: no regex or rewrite engine, no variables in response fields, no `merge`/`append`, no
site-wide trailing-slash or lowercase policy, no request-field conditions, the narrow baseline (no
frame field: 21 of 25 proxied applications decide framing themselves, and adding one breaks embeds),
`default` for a CSP, a required redirect status, a bounded lifetime on permanent redirects.

Worth revisiting:
- **Several-origin CORS** is the second-largest question in the evidence, though no official
  application configuration needs it. Preflight answering (gap 10) is the part with a real case.
- **Case-sensitive redirects** are justified "as on every hosting platform", but nginx `map` and
  Caddy's matchers ignore case. An opt-in per rule for imported lists, not a change of default.
- **Preload** stays out. One narrow case has some support: domains already on the list.

## 6. Suggested order

1. **The defects (D1 to D8)**, in two or three commits: they are small, and D3, D4, D5 touch
   safety.
2. **Managed HSTS values and the way back** (section 3).
3. **Static sites**: error pages with their status, clean addresses, the single-page fallback on a
   managed site (gaps 1, 2, 4), designed together since they share `try_files` and the static
   handler.
4. **Maintenance** (gap 3), already designed.
5. **Migrations**: the `.htaccess` scan, redirect exemptions, large lists, chains across sites (gaps
   5, 6, 12, 9).
6. Then CORS preflights, the type table, the CDN loop finding, staging, and the health findings.

Each needs its own short design for the owner first, except the defects.
