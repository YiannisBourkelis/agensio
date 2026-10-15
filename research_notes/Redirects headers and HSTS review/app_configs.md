# Official application configurations against agensio as built (0.1.0-alpha.94), 2026-10-14

Scope: every directive in the three research notes (`research_notes/Official configs vs redirects
and headers/php_apps.md`, `proxied_apps.md`, `static_and_spa.md`) that concerns redirects,
HTTPS/HSTS, canonical hosts, response fields (security, CORS, lifetimes, types by ending), error
pages, single-page fallbacks and clean addresses, judged against what the code does today, plus
the per-preset baseline against `research_notes/App default security headers/notes.md`.

The notes were written on 2026-10-13 against the designs, before `endings` (alpha.90), the
managed `response_headers` (alpha.94), case-sensitive redirects and the client-address fix
(alpha.74). Their "N (change 1)", "N (change 1a)" and "N (change 2)" rows (endings, endings before
a prefix at one path, files only) are **built** now and are reclassified below.

Status codes used in the tables:

| code | meaning |
|---|---|
| EXPR | EXPRESSIBLE as built, with the key named |
| AWKWARD | EXPRESSIBLE-AWKWARDLY: works, but needs a root additions file, many rules, a second site, or loses something |
| NOT-EXPR | NOT-EXPRESSIBLE: what is missing is named |
| NOT-NEEDED | agensio does it by default, or the directive is obsolete or a no-op |
| DECIDED-OUT | left out on purpose (built.md "Decided out", redirects.md 5.4 and 12.1, headers.md 2.5 and 10) |

"site file" means a hand-written `sites.d/*.toml`; "managed" means a site written by
`site_create`/`site_update` (MCP), whose file the agent must never edit.

## 0. Facts checked in the code for this review

These decide many rows and correct or extend the earlier checks (redirects.md 12, headers.md 11):

1. **A managed site's `hsts` is a boolean.** `SiteSpec::hsts` is `bool` (`src/control/sites.hpp`
   L23), parsed with `.boolean()` (`src/control/sites.cpp` L104, L680-682) and rendered only as
   `hsts = true` or `hsts = false` (L1130-1131); the MCP schema declares it `boolean`
   (`src/control/mcp.cpp`, `"hsts", prop("boolean", ...)`). A root additions file holds only
   `site` and `[[location]]` (`src/config.cpp` L1298-1313). So a managed site cannot send any
   `max-age` but 31536000, nor `includeSubDomains`. The site-file table form exists (`hsts_age`,
   config.cpp L1859-1908: seconds or units, at most 315360000). **Not noted by either earlier check.**
2. **The `-t` warning for a year-long `Cache-Control` on a path the single-page fallback answers**
   (headers.md 7 "Warned", and 3.5: "`-t` warns about such a rule") **is not built**: the loader's
   only header notes are `header_xss_protection` and `header_csp_set` (config.cpp L1568-1571).
3. **`rules.cache` has no `immutable`** (sites.cpp L537-554, rendered at L1067-1073 as
   `public, max-age=N`), although headers.md 3.5 says "A managed site has this as `rules.cache` with
   `immutable: true`" and headers.md 11.2 item 3 lists it as decided. Since alpha.94 managed
   `response_headers` covers the need, but `docs/examples/basics.md` L629 still sends `immutable` to
   the root additions file.
4. **`endings` match only after a dot in the file name** (`src/core/response_rules.hpp`
   L107-113), at most 16 per rule (config.cpp L1535), letters, digits, `.`, `-`, `_` (L1532). A name
   pattern such as `container_*_preview.js` cannot be written as an ending.
5. **Rules reach 204 answers**: `when` is `always` or `success` (2xx and 304) only; nothing keeps a
   field off a 204 (headers.md 11.3 "statuses beyond success" left for later).
6. **No `error_page`, no type table, no `$uri.html` step, no FastCGI parameter key**: no such key in
   `src/control/reference.cpp` or `config.cpp`; `src/mime.hpp` is a compiled table only (CLAUDE.md's
   "overridable from config" is untrue). `svgz` maps to `image/svg+xml` with no `Content-Encoding`;
   `sh`, `ps1`, `cjs`, `ttc`, `cur`, `gzip`, `swf`, `ics` are absent, so `application/octet-stream`.
7. **Upstreams are IP literals** (`src/upstream/client.cpp` L97).
8. **`rules.front_controller` is PHP-only** (sites.cpp L561-562) and a managed site has no
   `try_files`; a `rules.cache` location inherits the site's `try_files` (config.cpp L513).
9. **Client-address fields are fixed**: `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP`,
   `X-Plausible-IP`, `B-Forwarded-For`, Umami's list and others are dropped from untrusted peers
   (`src/handlers/proxy.cpp` L57-73). proxied_apps.md 26.3 is closed.
10. **An application's HSTS over plain HTTP passes as sent** (`src/handlers/upstream_common.cpp`
    L172-198 replace it only when the site's HTTPS fields are set), so proxied_apps.md 28.2's last
    point (Metabase on an `http = "serve"` site) is still open; browsers ignore it there.
11. Accepted in rules (not refused): `Content-Disposition`, `Link`, `X-Robots-Tag`, COOP/COEP/CORP,
    `Permissions-Policy`. `[server] server_header = ""` sends no `Server`, server-wide, root's
    file only (reference.cpp L27); `remove = ["Server"]` is accepted but leaves agensio's own
    (built.md "rough edges").

## 1. Per application

### 1A. PHP applications (php_apps.md)

**Nextcloud 35** (php_apps.md §1; proxied_apps.md §19c)

| directive | status | how / missing |
|---|---|---|
| NC-1 `return 301 https://$server_name...` | EXPR | `http = "redirect"` (308), `canonical` for several names |
| NC-2 HSTS `1y; includeSubDomains` (commented, preload) | EXPR site file; NOT-EXPR managed | `hsts = { max_age = "1y", subdomains = true }`; managed sites get only `hsts: true` (§0.1); preload DECIDED-OUT |
| NC-3/NC-11 five fields on every answer (`Referrer-Policy no-referrer`, nosniff, XFO, X-Permitted-Cross-Domain-Policies, X-Robots-Tag) | EXPR | one `/` rule, `default` (Nextcloud's PHP sends them itself; agensio cannot pass `modHeadersAvailable`, harmless) |
| NC-4 `fastcgi_hide_header X-Powered-By` | NOT-NEEDED | baseline, and `expose_php = off` in agensio's pools |
| NC-5 DavClnt User-Agent 302 at `/` | DECIDED-OUT | no request-field conditions (redirects.md 12.1) |
| NC-6 `/.well-known/caldav`, `carddav` 301 | EXPR | two exact `[[site.redirect]]` (`query = "drop"` matches nginx) |
| NC-7 other `/.well-known/*` to `index.php` | EXPR | front controller (`try_files ... /index.php$request_uri`, or `rules.front_controller`); copied as a redirect, the validation paths are never redirected (redirects.md 12.2 item 2) |
| NC-8 `/remote` → `/remote.php$request_uri` | EXPR | prefix rule `/remote` → `/remote.php/remote` |
| NC-9 asset `Cache-Control` by ending | EXPR | `endings = [css, js, mjs, svg, ...]`, `when = "success"` (files only by construction) |
| NC-9 `immutable` only with `?v=` | NOT-EXPR | no query condition on rules (headers.md 11.3, open); assets revalidate by ETag |
| NC-10 fonts `expires 7d` | EXPR | `endings = ["otf", "woff", "woff2"]` |
| NC-12 `Referrer-Policy: same-origin` on `/login` | EXPR | exact rules `/login`, `/index.php/login`, `set` |
| NC-13 `AddEncoding gzip svgz` | NOT-EXPR | type table with an encoding; agensio sends `.svgz` without `Content-Encoding` (§0.6) |
| `types { text/javascript mjs; application/wasm wasm; }` (19d) | NOT-NEEDED | built-in table |
| `fastcgi_param front_controller_active true` (19d; makes Nextcloud write URLs without `index.php`) | NOT-EXPR | no key for extra FastCGI parameters (clean addresses) |
| NC-14 `server_tokens off` | EXPR | `[server] server_header`, server-wide |

**Matomo 5** (§2)

| directive | status | how / missing |
|---|---|---|
| MT-1 301 to https | EXPR | `http = "redirect"` |
| MT-2 HSTS `max-age=15768000` (commented) | EXPR site file; NOT-EXPR managed | `hsts = { max_age = 15768000 }` (seconds accepted, config.cpp L1859); managed: one year only |
| MT-3 `Referrer-Policy origin` always | EXPR | `/` `set` (one field instead of nginx's two) |
| MT-4 nosniff | EXPR | `/` rule |
| MT-5 `X-XSS-Protection 1; mode=block` | EXPR | noted by `-t` |
| MT-6 `/js/container_*_preview.js` no-store | AWKWARD | no `*` in rule paths, and the variable part is not a dot ending (§0.4); `/js/` + `endings = ["js"]` + `no-store` reaches every script there |
| MT-7 asset endings 1 h (`Pragma` obsolete) | EXPR | `endings`, `when = "success"` |
| MT-8 `.md`, `LICENSE` as `text/plain` | NOT-EXPR | type table (harmless: `text/markdown` and octet-stream) |

**MediaWiki 1.46** (§3)

| directive | status | how / missing |
|---|---|---|
| MW-1 `/w/images` nosniff | NOT-NEEDED | baseline (files agensio serves) |
| MW-1 `types { text/plain html htm ... }` in uploads | NOT-EXPR | per-path type table; MW-6's `sandbox` CSP or `deny_suffixes` covers the risk |
| MW-2 `/w/resources/{assets,lib,src}` 7 d | EXPR | three prefix rules, `when = "success"` |
| MW-3 skins/extensions assets by ending 7 d | EXPR | `/w/skins/`, `/w/extensions/` with `endings` |
| MW-4 `/favicon.ico` 7 d | EXPR | exact rule (exact `alias` location) |
| MW-5 `/` → `/wiki/Main_Page` | EXPR | exact rule from `/`, 301 |
| MW-6 uploads CSP, a different one for `*.pdf` | EXPR | `/w/images/` `default`, plus a rule at the same path with `endings = ["pdf"]` (decides first) |
| MW-7 `/wiki/` → `/w/index.php` | EXPR | location `try_files = ["/w/index.php?$query_string"]` |
| MW-8 `return 404` elsewhere | EXPR | `refuse` / `handler = "deny"` |

**phpMyAdmin 5.2** (§4)

| directive | status | how / missing |
|---|---|---|
| PMA-1 pretty URLs, captures into the query | DECIDED-OUT | no captures (built.md) |
| PMA-2 Traefik trailing-slash regex | DECIDED-OUT | no slash policy |
| PMA-3 User-Agent `[F]` | DECIDED-OUT | no request-field conditions |
| its own XFO, CSP, `X-Robots-Tag` | NOT-NEEDED | the application's |

**Magento 2.4.9** (§5)

| directive | status | how / missing |
|---|---|---|
| M2-1 `X-UA-Compatible`, unset on non-HTML | NOT-NEEDED | obsolete (EXPR with `set` and an `endings` `remove` if wanted) |
| M2-2 XFO `SAMEORIGIN` everywhere | EXPR | `/` `default` (Magento's PHP sends its own) |
| M2-3 `/static/` year `immutable` by ending | EXPR | `/static/` with `endings`, `when = "success"` |
| M2-4 archives `no-store` | EXPR | `endings = ["zip", "gz", "gzip", "bz2", "csv", "xml"]` |
| M2-5 `/media/` year by ending | EXPR | `/media/` with `endings` |
| M2-6 `ExpiresByType` lists in `pub/static`, `pub/media` | AWKWARD | each type translated to endings by hand, 16 per rule (§0.4) |
| M2-8 `moxieplayer.swf` query self-redirect | DECIDED-OUT | `refuse = ["moxieplayer.swf"]` gives the protection |
| M2-9 TRACE `R=405` | NOT-NEEDED | built in |
| M2-10 `/static/version<N>/` strip, `static.php?resource=` | NOT-EXPR | internal rewrite with a capture; works only with static signing off |
| M2-11 `error_page 404 403 = /errors/404.php` | NOT-EXPR | no `error_page` (agensio's own 404 page) |
| M2-12 root to `/pub/` | EXPR | `root` |

**PrestaShop 9.2** (§6)

| directive | status | how / missing |
|---|---|---|
| PS-1 HSTS `2y; includeSubDomains` (commented) | EXPR site file; NOT-EXPR managed | `hsts = { max_age = "2y", subdomains = true }`; preload DECIDED-OUT |
| PS-2..4 XSS, XFO, nosniff (commented) | EXPR | `/` rule |
| PS-5 `add_header Set-Cookie` | DECIDED-OUT | refused name |
| PS-6 `/fr` → `/fr/` | EXPR | exact rule (legal since 12.2 item 5) |
| PS-7 language strip rewrites (commented) | NOT-EXPR | internal rewrite with capture |
| PS-8 friendly image URLs, `/api/` | NOT-EXPR | internal rewrites with captures into a query; images 404 with friendly URLs on |
| PS-9 `error_page 404 /index.php?controller=404` | NOT-EXPR | no `error_page` |
| PS-10 multishop `^shop2$` → `/shop2/`; strip | EXPR; NOT-EXPR | exact rule; the strip is a rewrite |
| PS-11 fonts and SVG `Access-Control-Allow-Origin *` | EXPR | `endings` |
| PS-12 "Apache optimization" `ExpiresByType` | AWKWARD | endings by hand |
| PS-13 `Header unset Etag` | DECIDED-OUT | ETag kept |
| PS-14/15 endings `Cache-Control`, `.php` excepted | EXPR | `endings` never reach PHP answers |

**Shopware 6.7** (§7)

| directive | status | how / missing |
|---|---|---|
| SW-1 `^index\.php(/…)` → 301 `/…` | EXPR | prefix rule `/index.php` → `/` (rules never meet the front controller hop) |
| SW-2 `RedirectMatch 302 ^/$ /index.php/` | NOT-NEEDED | `try_files` routes |
| SW-3 SVG `script-src 'none'` (Apache, nginx, Caddy `file`) | EXPR | `endings = ["svg"]`; no CSP note for an endings rule (config.cpp L1570) |
| SW-4 nine asset directories a year | EXPR | prefix rules, `when = "success"` |
| SW-5 asset endings a year, PHP fallback untouched | EXPR | `endings` |
| SW-6 Caddy XFO DENY, Referrer-Policy | EXPR | `/` rule |
| SW-7 `RedirectMatch 404` | EXPR | `refuse` |

**Joomla 6.1** (§8)

| directive | status | how / missing |
|---|---|---|
| J-1 nosniff on every answer, PHP included | EXPR | `/` `set` (an offer; the baseline covers files only) |
| J-2 CORP / COEP (commented) | EXPR | rule |
| J-3 SVG `script-src 'none'` | EXPR | `endings = ["svg"]` |
| J-4 query exploit filter `[F]` | NOT-EXPR | refusal by query (outside these designs; defence in depth) |
| J-5 `RedirectMatch 302 ^/$ /index.php/` | NOT-NEEDED | |
| J-6 `.css.gz` / `.js.gz` with `Content-Encoding` | NOT-NEEDED | pre-compressed twins |
| J-7 www placeholder | EXPR | `canonical` |
| J-8 nginx nosniff; endings 1 y / 14 d | EXPR | rule; `endings` |

**Moodle 5** (§9)

| directive | status | how / missing |
|---|---|---|
| MO-1/2 `try_files ... /r.php`, `FallbackResource`, `[R=404]` lines | EXPR | front controller `/r.php` (entry point), `refuse` |

**Roundcube 1.7** (§10)

| directive | status | how / missing |
|---|---|---|
| RC-1 favicon → `static.php/...` | EXPR | exact location `try_files` |
| RC-2 `ExpiresDefault` 1 month | AWKWARD | `/` `default` `max-age=2592000`, `when = "success"` (reaches PHP answers without their own), or endings by hand |
| RC-3 `FileETag MTime Size` | NOT-NEEDED | agensio's ETag |
| RC-4 `X-Robots-Tag noindex, nofollow` | EXPR | `/` rule |
| RC-5 `Header merge` with `env=` | DECIDED-OUT | no merge, no conditions |
| RC-6 HSTS `env=HTTPS` (preload) | EXPR | `hsts = true`; preload DECIDED-OUT |
| RC-7 HPKP | DECIDED-OUT | refused |
| RC-8/9 XFO ("set by php"), nosniff | EXPR | `default` |
| RC-10 `use_secure_urls` token strip | NOT-EXPR | rewrite dropping a variable first segment (opt-in) |

**FreshRSS 1.30** (§11)

| directive | status | how / missing |
|---|---|---|
| FR-1 `FileETag None` | DECIDED-OUT | |
| FR-2 `ExpiresDefault` 1 month, `.php` off | AWKWARD | endings by hand, or `default` at `/` |
| FR-3 endings `public` | EXPR | `endings`, full `set` value (no merge) |
| FR-3 `immutable` on a numeric query | NOT-EXPR | query condition (open) |
| FR-4 themes 1 month | EXPR | prefix `/themes/` |
| FR-5 themes SVG CSP | EXPR | `/themes/` with `endings = ["svg"]` |
| FR-6 Caddy `redir /subfolder /subfolder/` | EXPR | exact rule |
| FR-7 "do not overwrite the CSP" | EXPR | `default` (and the `-t` note on `set`) |
| FR-8 `/p/i` expires off | NOT-NEEDED | `endings` are files only |

**Kirby 5** (§12)

| directive | status | how / missing |
|---|---|---|
| K-1/K-3 `text/plain` for unknown types, `default_type text/plain` | NOT-EXPR | type table (harmless: octet-stream is not rendered either) |
| K-2 nosniff (Apache, nginx) | EXPR | `/` rule |
| K-4 internal rewrites to `/error`, `/index.php`; Caddy auto-HTTPS | EXPR | `refuse`, front controller; `http = "redirect"` |

**Craft CMS 5** (§13)

| directive | status | how / missing |
|---|---|---|
| CR-1 front controller | EXPR | preset / `try_files` |
| CR-2 XFO, XSS, nosniff, Referrer-Policy always; CSP (commented) | EXPR | `/` rule (CSP as `default`) |
| CR-3 asset endings 7 d (about 25 endings) | EXPR | two `endings` rules (16 each) |
| CR-4 fonts and `svgz?` with ACAO `*` | EXPR | `endings`; `.svgz` itself is broken by the type table (NC-13) |

**Symfony** (§14)

| directive | status | how / missing |
|---|---|---|
| SY-1 `^index\.php(/…)` → 308 | EXPR | prefix rule, 308 |
| SY-2 `RedirectMatch 307 ^/$ /index.php/` | NOT-NEEDED | |
| SY-3 front controller, `return 404` | EXPR | `rules.entry_points` |

**WordPress** (§15; notes.md §1, §4.3)

| directive | status | how / missing |
|---|---|---|
| WP-1 `server_name _` → 302 main site | EXPR | `canonical` for listed names; unknown names get 421 over TLS by design |
| WP-2 `expires max` on asset endings | EXPR | `/wp-content/` with `endings` (headers.md 3.5 recipe) |
| WP-3 multisite subdir `/<site>/wp-admin` → slash | DECIDED-OUT | capture in the target; WordPress redirects itself |
| WP-4 multisite internal strip rewrites | NOT-EXPR | rewrite dropping the subsite segment |
| WP-5 `^wp-admin$` → `wp-admin/` | NOT-NEEDED | directory slash built in |
| WP-6 HSTS `includeSubDomains` | EXPR site file; NOT-EXPR managed | §0.1 |
| WP-7 pre-3.5 multisite `files/` | NOT-NEEDED | legacy |
| WP-8 `Header set X-Pingback`, `Content-Language` | EXPR | `set` |
| WP-9 `Header unset Pragma`, `WP-Super-Cache`, `X-Pingback` | EXPR | `remove` |
| WP-10 admin-only HTTPS by scheme | DECIDED-OUT | `http = "redirect"` for the whole site |
| WP-11 core `.htaccess` block | EXPR | preset |
| a frame field on the front end with `/embed/` exempt (the offer, notes.md §4.3) | NOT-EXPR | the embed address is a suffix (`/post/embed/`); path rules cannot exempt it |

**Drupal 11** (§16)

| directive | status | how / missing |
|---|---|---|
| DR-1 `AddEncoding gzip svgz` | NOT-EXPR | type table with encoding |
| DR-2 `ExpiresDefault` 1 year, `.php` off | AWKWARD | endings by hand, or `/` `default` with `when = "success"` |
| DR-3 www / non-www (commented) | EXPR | `canonical` |
| DR-4 `install.php`, `rebuild.php` → `/core/` | EXPR | two exact rules |
| DR-5 `install.php?rewrite=ok` | NOT-NEEDED | preset |
| DR-6 `.css.gz` / `.br` | NOT-NEEDED | twins |
| DR-7 `onsuccess unset` + `always set` nosniff | NOT-NEEDED | baseline on files, Drupal's own on pages |
| DR-8 `RequestHeader unset Proxy` | NOT-NEEDED | not forwarded to FastCGI |
| DR-10 recipe endings `expires max` | EXPR | `endings` |
| DR-11 recipe `index.php/` → 307 | EXPR | prefix rule, 307 |
| `X-Generator` (notes.md §1) | EXPR | `remove` (offered) |

**TYPO3 14** (§17)

| directive | status | how / missing |
|---|---|---|
| T3-1 `ExpiresByType` list, `index.php` off | AWKWARD | endings by hand |
| T3-2 images ACAO `*` (if `Origin`) | EXPR | `endings`, unconditional |
| T3-3 fonts ACAO `*` | EXPR | `endings` |
| T3-4 versioned file names `name.123.js` | NOT-EXPR | rewrite with capture (only with `versionNumberInFilename`) |
| T3-5 `RedirectMatch 404` VCS | NOT-NEEDED | hidden files |
| T3-6 `X-UA-Compatible` | NOT-NEEDED | obsolete |
| T3-7 nosniff on everything, frontend PHP included | EXPR | `/` `set` (offer; baseline covers files) |
| T3-8 `Header unset ETag` | DECIDED-OUT | |
| T3-9 / T3-13 `fileadmin` CSP: PDF, SVG, everything else | EXPR | `/fileadmin/` `default` plus `endings = ["pdf"]` and `["svg"]` rules at the same path |
| T3-10 `.js.gzip` / `.css.gzip` with `Content-Encoding` | NOT-EXPR | type table with encoding; switch TYPO3's compression off |
| T3-11 `/typo3` → `/typo3/` | NOT-NEEDED | directory slash, `front_controller` |
| T3-12 WebP by `Accept` | NOT-EXPR | variant choice by `Accept` (only `Accept-Encoding` twins) |

**Grav 2.2** (§18)

| directive | status | how / missing |
|---|---|---|
| G-1 `**/_app/immutable/` a year, at any depth | NOT-EXPR (AWKWARD per known plugin path) | path patterns in rule paths (headers.md 11.3, open) |
| G-2 media endings 30 d | EXPR | `endings` |
| G-3 query filter `[F]` | NOT-EXPR | refusal by query (outside these designs) |
| G-4 `[F]`, Caddy auto-HTTPS | EXPR | preset; `http = "redirect"` |

**Kanboard 1.2** (§19)

| directive | status | how / missing |
|---|---|---|
| KB-1 force HTTPS (commented) | EXPR | `http = "redirect"` |
| KB-2 asset endings 7 d | EXPR | `endings`, or `rules.cache /assets/` on a managed site |
| its own CSP, XFO DENY, nosniff, HSTS | NOT-NEEDED | the application's |

**Laravel 13** (§20)

| directive | status | how / missing |
|---|---|---|
| LV-1 XFO `SAMEORIGIN`, nosniff at server level (PHP answers too) | EXPR | `/` `set` (offer, headers.md 11.2 item 5) |
| LV-2 `error_page 404 /index.php` | NOT-EXPR | `error_page` (only agensio's own 404s, e.g. refused paths, are affected; cosmetic) |
| LV-3 `fastcgi_hide_header X-Powered-By` | NOT-NEEDED | baseline |
| LV-4 remove trailing slash 301 | DECIDED-OUT | Laravel's router ignores the slash |

**Statamic 6** (§21)

| directive | status | how / missing |
|---|---|---|
| ST-1 remove trailing slash | DECIDED-OUT | as LV-4 |
| ST-2 full-measure static cache (`try_files` with the query in a name) | NOT-EXPR | opt-in feature; half measure needs nothing |
| ST-3 `X-Powered-By: Statamic` | NOT-NEEDED | baseline removes it |

### 1B. Proxied applications (proxied_apps.md)

**Mastodon 4.7** (§1)

| directive | status | how / missing |
|---|---|---|
| port-80 `return 301 https://$host...` | EXPR | `http = "redirect"` |
| HSTS `63072000; includeSubDomains` (nginx and Rails `force_ssl`) | EXPR site file; NOT-EXPR managed | managed `hsts: true` narrows Rails' value and health warns `hsts_narrows_application`, whose only managed fix is `hsts: false` |
| `Cache-Control` on 7 static prefixes | EXPR | prefix rules, `when = "success"` (reach Rails' answers too) |
| `/system/` immutable, nosniff, CSP `default-src 'none'` | EXPR | two `/system/` rules |
| `proxy_pass_header Server`, `X-Cached $upstream_cache_status` | DECIDED-OUT | `Server` is agensio's; no variables |
| apex `/.well-known/webfinger` 301 with ACAO `*` | EXPR | exact redirect + exact header rule (rules reach redirects) |
| ACAO `*` on the CDN host | EXPR | `/` rule on that site |
| object-storage proxy: `proxy_hide_header` × 10; `expires 1y`, ACAO, nosniff, CSP | EXPR | `proxy.hide`, rules |
| object-storage proxy to `https://BUCKET.S3HOST` | NOT-EXPR | upstream by host name (§0.7) |
| migrate `/system/` to the files host | EXPR | prefix redirect |
| `try_files $uri @mastodon` (disk first, then Rails) | AWKWARD | no fallback to a proxy: one `alias` location per prefix (root additions on a managed site), or leave it to Rails |
| `error_page 404 500 501 502 503 504 /500.html` | NOT-EXPR | `error_page` |
| frame field offer: `/@user/:id/embed` deletes XFO | NOT-EXPR | a `default` frame field would re-add it on a suffix path rules cannot exempt |

**Discourse** (§2)

| directive | status | how / missing |
|---|---|---|
| outer proxy needs `X-Real-IP` | NOT-NEEDED | set to the believed client since alpha.74 (§0.9) |
| container: `return 301 https://${DISCOURSE_HOSTNAME}` | EXPR | `http = "redirect"` + `canonical` |
| container: HSTS `31536000` | EXPR | `hsts = true` (managed too) |
| container: any other Host → canonical | EXPR listed / DECIDED-OUT unlisted | `canonical`; an IP or unknown Host is not redirected |
| inner: `etag off`, `add_header ETag ""` | DECIDED-OUT | |
| inner: `/assets/`, `/plugins/`, `/javascripts/`, `/images/emoji/`, `/uploads/` lifetimes and ACAO | EXPR | prefix rules |
| inner: fonts and images by extension; `.svg` `Content-Disposition: attachment` | NOT-NEEDED behind the container (its inner nginx does it); EXPR if agensio served them from disk | `endings` apply only to files agensio serves, never to proxied answers |
| container offline page `error_page 502` | NOT-EXPR | `error_page` for an origin that is down |

**Ghost 6** (§3)

| directive | status | how / missing |
|---|---|---|
| Ghost-CLI nosniff on every answer except 204 (`map $status`, #1858) | NOT-EXPR | no status condition (§0.5); matters only when nosniff is offered on app answers |
| Ghost-CLI HSTS `2y; includeSubDomains; preload` | EXPR site file; NOT-EXPR managed; preload DECIDED-OUT | |
| Ghost-CLI XFO `SAMEORIGIN` | EXPR | `default` (blocks a separate admin domain's previews) |
| `proxy_redirect off` | EXPR | `proxy.redirects = "pass"` |
| ghost-docker HSTS 1y, XSS, nosniff, Referrer, CSP `frame-ancestors 'self' <admin>` | EXPR | rules (CSP `default`) |
| ghost-docker www ↔ apex `redir` | EXPR | `canonical` |
| ActivityPub `webfinger`, `nodeinfo`, `/.ghost/activitypub/` to `ap.ghost.org` | NOT-EXPR | upstream by host name (local service: EXPR) |

**Plausible CE** (§4)

| directive | status | how / missing |
|---|---|---|
| Caddy implicit HTTPS redirect | EXPR | `http = "redirect"` |
| `ProxyPassReverse` | EXPR | `proxy.redirects` |
| script guide `X-Cache $upstream_cache_status` | DECIDED-OUT | variables |
| tracking-script proxy to `plausible.io` | NOT-EXPR | upstream by host name |
| forged `X-Plausible-IP` / `CF-Connecting-IP` | NOT-NEEDED | dropped from untrusted peers (§0.9) |

**Umami 3.4** (§5)

| directive | status | how / missing |
|---|---|---|
| `/stats/_next/static/` from disk, `expires max` | EXPR site file; AWKWARD managed | `alias` location (root additions on managed) + rule `when = "success"` |
| heatmaps: tracked site CSP `frame-ancestors`, remove XFO | EXPR | `default` CSP + `remove` |
| app HSTS with `preload` (`FORCE_SSL`) | EXPR | `hsts` replaces it (narrowing noted by health); `hsts = false` lets it through |

**Gitea 28** (§6)

| directive | status | how / missing |
|---|---|---|
| CDN host `location / { return 404; }` | EXPR | `handler = "deny"` |
| static split `alias` (no lifetime in the docs) | EXPR | `alias` + optional `when = "success"` rule |
| IIS outbound HTML link rewrite | NOT-NEEDED | `ROOT_URL` |
| code invites a second, narrowing CSP | DECIDED-OUT | no append (built.md) |

**Forgejo 16** (§7)

| directive | status | how / missing |
|---|---|---|
| nginx / Apache / HAProxy / Puppet HTTP → HTTPS | EXPR | `http = "redirect"` |
| CSP at the proxy suggested | EXPR | `default` (`set` would replace the raw-file sandbox) |

**GitLab 19.4** (§8)

| directive | status | how / missing |
|---|---|---|
| Omnibus / source `return 301 https://...` | EXPR | `http = "redirect"` |
| 8 monitoring paths served over plain HTTP despite the redirect | AWKWARD | no exempt paths: a second site on an internal plain address, or probe over HTTPS |
| HSTS `63072000[; includeSubdomains]` always | EXPR site file; NOT-EXPR managed | narrowing noted by health |
| `proxy_hide_header Referrer-Policy` + `add_header` | EXPR | `set` |
| CORP `cross-origin` (Mermaid) | EXPR | `set` |
| Passenger `/assets` `expires max` + `public` | EXPR | rule `when = "success"` |
| static error pages, `proxy_intercept_errors` | NOT-EXPR | `error_page` for agensio's own 502/504 |

**Mattermost 11** (§9)

| directive | status | how / missing |
|---|---|---|
| `return 301 https://$server_name...` (docs, Docker, certbot) | EXPR | `http = "redirect"` (+ `canonical`) |
| HSTS `15768000` / `63072000` always | EXPR site file; NOT-EXPR managed | seconds accepted |
| `X-Early-Data $tls1_3_early_data` | DECIDED-OUT | variables; no 0-RTT |
| `proxy_set_header X-Frame-Options` (a request field) | NOT-NEEDED | no effect |
| Docker: XFO, XSS, nosniff, `Referrer-Policy no-referrer`, `Permissions-Policy`, `X-Robots-Tag` | EXPR | rules (XFO `default`) |

**Rocket.Chat 8.9** (§10)

| directive | status | how / missing |
|---|---|---|
| `return 301`, Traefik entrypoint, Caddy implicit | EXPR | `http = "redirect"` |
| post-quantum page HSTS 2y always, XFO, nosniff | EXPR (HSTS managed NOT-EXPR) | rules, XFO `default` |
| federation `/.well-known/matrix/server` JSON | AWKWARD | the file renamed `server.json` + exact location `try_files` (tested alpha.72); a location, so root additions on a managed site |
| `X-Real-IP` read first | NOT-NEEDED | §0.9 |

**Matrix Synapse 1.162** (§11)

| directive | status | how / missing |
|---|---|---|
| `.well-known/matrix/server` and `client` as fixed JSON (nginx `return 200`, Caddy `respond`, HAProxy) | AWKWARD | `.json` files + exact locations (root additions on managed); or proxy to Synapse |
| `Content-Type application/json` | NOT-NEEDED | from the `.json` name |
| ACAO `*` (+ methods, headers) on `/.well-known/matrix` | EXPR | prefix rule |
| lighttpd HTTP → HTTPS | EXPR | `http = "redirect"` |

**Element Web 1.12** (§12)

| directive | status | how / missing |
|---|---|---|
| XFO `SAMEORIGIN`, nosniff, XSS, CSP `frame-ancestors 'self'` | EXPR | `/` rule (`app = "static"`: no CSP note) |
| `no-cache` on `/` and `/index.html` | NOT-NEEDED | static baseline (`.html` served files) |
| `no-cache` on `/version`, `/i18n/` | EXPR | exact and prefix rules |
| `no-cache` on `/config.json`, `/config.<name>.json` (nginx `location /config`) | AWKWARD | one exact rule per site name (no character prefix or `*`) |
| `home.html` ACAO `*` | EXPR | exact rule |
| `error_page 500 502 503 504 /50x.html` | NOT-NEEDED | nginx's stock page |

**Keycloak 26.8** (§13)

| directive | status | how / missing |
|---|---|---|
| none; exposed-path filtering | EXPR | `[[site.access]]` |
| app HSTS `1y; includeSubDomains` | EXPR site file; NOT-EXPR managed | `hsts = true` drops `includeSubDomains` (health warns); managed: `hsts: false` only |

**Vaultwarden 1.37** (§14)

| directive | status | how / missing |
|---|---|---|
| Caddy redirect `/admin*` to `/` unless private | DECIDED-OUT | `[[site.access]]` 403 instead |
| HSTS `31536000` | EXPR | `hsts = true` |
| `X-XSS-Protection 0`, `X-Robots-Tag`, nosniff | EXPR | rules (redundant: the app sends them) |
| `-X-Powered-By` | NOT-NEEDED | baseline |
| XFO `DENY` | EXPR, harmful | breaks the WebAuthn/Duo connector pages; exempting them needs exact `remove` rules per page (names unverified): AWKWARD |
| `-Server` | AWKWARD | server-wide `server_header = ""` in root's file; a per-site `remove = ["Server"]` is accepted and does nothing to agensio's own (§0.11) |
| `-Last-Modified` | DECIDED-OUT | |
| `return 301`, Traefik, NixOS, Istio, Pound | EXPR | `http = "redirect"` |
| only `/vault/` to HTTPS, rest of the domain plain | EXPR | plain site with a prefix redirect |
| old host → new host, path kept; `https-remap` | EXPR | redirect from `/`; Location upgrade (alpha.79) |

**n8n 2.42** (§15)

| directive | status | how / missing |
|---|---|---|
| Traefik entrypoint redirect; `SSLRedirect` | EXPR | `http = "redirect"` |
| `STSSeconds=315360000`, `STSIncludeSubdomains` | EXPR site file; NOT-EXPR managed | exactly the maximum (config.cpp L1862) |
| `STSPreload`, `forceSTSHeader` | DECIDED-OUT | |
| `browserXSSFilter`, `contentTypeNosniff` | EXPR | rules |
| `SSLHost` | NOT-NEEDED | removed in Traefik v3 |

**Jellyfin 12.2** (§16)

| directive | status | how / missing |
|---|---|---|
| nosniff, `Permissions-Policy`, active CSP | EXPR | rules (CSP `default`) |
| HTTP → HTTPS (nginx, Apache, HAProxy, Traefik) | EXPR | `http = "redirect"` |
| Caddy `redir /jellyfin /jellyfin/` | EXPR | exact rule (the server also does it) |
| Apache `Cache-Control no-store...` (commented) | EXPR | rule |
| Traefik STS 315360000 + subdomains | EXPR site file; NOT-EXPR managed | |
| Traefik `frameDeny` | EXPR, discouraged | the nginx docs removed it for webOS |
| `ALLOW-FROM`; plain and TLS on one port; `preload`, `forceSTSHeader` | DECIDED-OUT | |

**Home Assistant 2026.10** (§17)

| directive | status | how / missing |
|---|---|---|
| add-on `return 301` (port 80 off by default) | EXPR | `http = "redirect"` or `"off"` |
| HSTS option `1y; includeSubDomains` always | EXPR site file; NOT-EXPR managed | |
| `proxy_redirect http:// https://` | EXPR | Location upgrade for the site's names (alpha.79) |
| `Alt-Svc`; `return 444` / `ssl_reject_handshake` | NOT-NEEDED | `protocols` h3; 421 and handshake refusal |

**Immich 3.3** (§18)

| directive | status | how / missing |
|---|---|---|
| `proxy_redirect off`, `ProxyPassReverse`, `/.well-known/immich` proxied | NOT-NEEDED | defaults |

**Nextcloud All-in-One 14.2** (§19a)

| directive | status | how / missing |
|---|---|---|
| HTTP → HTTPS (Apache, nginx `$scheme` and `X-Forwarded-Proto`, Traefik, IIS) | EXPR | `http = "redirect"` (+ `trusted_proxies`) |
| Traefik `referrerPolicy: same-origin` | EXPR | `default` (in practice nothing needed) |
| `Alt-Svc`; NPM `proxy_hide_header Upgrade` | NOT-NEEDED | `protocols`; h2/h3 writers drop `Upgrade` |
| inner Caddy `-Server -X-Powered-By -Via` | NOT-NEEDED behind AIO; AWKWARD if copied | `Via` by `remove`; `Server` as for Vaultwarden |

**Paperless-ngx 3.3** (§20)

| directive | status | how / missing |
|---|---|---|
| `Referrer-Policy same-origin` on `/accounts/{login,signup,2fa}`, `no-referrer` elsewhere | EXPR | longest-path rules |
| Apache HTTP → HTTPS except ACME | EXPR | `http = "redirect"` |
| HSTS `15552000; preload` / `31536000; includeSubdomains` | EXPR site file; NOT-EXPR managed; preload DECIDED-OUT | |
| nosniff, `X-Robots-Tag`, XSS, XFO, `Permissions-Policy`, CSP, P3P | EXPR | rules (CSP `default`) |
| XFO `ALLOW-FROM`; `-Server` | DECIDED-OUT; AWKWARD | |
| `ErrorDocument 503` offline page | NOT-EXPR | `error_page` for an origin that is down |
| Caddy CORS preflight 204 + Origin echo | DECIDED-OUT | the app does CORS |

**Grafana 13.2** (§21)

| directive | status | how / missing |
|---|---|---|
| nginx `/grafana/`: implicit 301 from `/grafana` | EXPR | exact rule |
| `rewrite ... break`, HAProxy `set-path`, IIS rewrite; `ProxyPassReverse` | EXPR | `upstream` URI part; `proxy.redirects` |

**Uptime Kuma 2.5** (§22)

| directive | status | how / missing |
|---|---|---|
| Caddy / certbot / https-portal implicit redirect | EXPR | `http = "redirect"` |
| OpenLiteSpeed "Header Operations" `Upgrade`/`Connection`; Apache `[P]` | NOT-NEEDED | automatic upgrade |

**BookStack 26.09** (§23)

| directive | status | how / missing |
|---|---|---|
| trailing-slash removal (Apache, `.htaccess`, `web.config`, install scripts) | DECIDED-OUT | Laravel's router ignores it |
| nginx sub-path `/bookstack` → `/bookstack/` | EXPR | exact rule |
| docs: the server may add a second CSP | DECIDED-OUT | no append |

**Outline 1.11** (§24)

| directive | status | how / missing |
|---|---|---|
| HTTPS by the app (`FORCE_HTTPS`) or https-portal | EXPR | `http = "redirect"` |
| `proxy_redirect off` | EXPR | `proxy.redirects` |

**Metabase 0.64** (§25)

| directive | status | how / missing |
|---|---|---|
| Beanstalk `if ($http_x_forwarded_proto != "https") rewrite ... permanent` | EXPR | `http = "redirect"` + `trusted_proxies` |
| the app's redirect exempts `/api/health`, `/livez`, `/readyz` | AWKWARD (marginal) | no exempt paths; only if probes cross agensio over plain HTTP |

### 1C. Static sites (static_and_spa.md)

**Platform rule files an imported site brings** (§2, §4). Grouped by feature, since the eight
platforms share them; the platforms using each are named.

| feature (platforms) | status | how / missing |
|---|---|---|
| SPA fallback `/* /index.html 200` (Netlify, Cloudflare automatic, Vercel, Firebase, Azure `navigationFallback`, Amplify, Render) | EXPR site file; AWKWARD managed | `try_files = ["$uri", "$uri/", "/index.html"]`; managed static: root additions (§0.8) |
| assets kept out of the fallback (Azure `exclude`, Amplify regex, Firebase `!`, Netlify self-rewrites) | EXPR | location `try_files = ["$uri", "=404"]`, or a suffix location |
| `404.html` served with 404 (all) | NOT-EXPR | `error_page` |
| per-language 404 by pattern (Netlify `/fr/* /fr/404.html 404`) | NOT-EXPR | `error_page` per location |
| clean URLs `/x` from `x.html` (Netlify Pretty URLs, Cloudflare, Vercel/Firebase `cleanUrls`, Azure `auto`, Amplify, GitHub Pages) | NOT-EXPR | no `$uri.html` step |
| `/x` from `x/index.html` | AWKWARD | agensio's 301 to `/x/` (one hop) |
| `.html` → clean URL redirect site-wide (`cleanUrls`, Cloudflare) | DECIDED-OUT site-wide; EXPR per page | exact rules |
| `trailingSlash` policy (Vercel, Firebase, Azure, Workers) | DECIDED-OUT | redirects.md 5.4 |
| exact, section, section-to-page, 410 redirects | EXPR | `[[site.redirect]]` (status required, case-sensitive like the platforms) |
| splat inside the target, mid-path splat, reordered placeholders (1-2.7 %) | DECIDED-OUT | later step (5.4) |
| first-segment `/:lang/` placeholder carried (MUI) | AWKWARD | one rule per language, may pass the 1,000 cap |
| query captured and renamed | DECIDED-OUT | rare (0.6 %) |
| conditions `Language`, `Country`, `Header`, `Cookie` (Netlify, Vercel `has`, Firebase i18n, Amplify) | DECIDED-OUT | roles → `[[site.auth]]` (EXPR) |
| domain-level `from` (Netlify, Vercel `has: host`) | EXPR | `canonical`, redirect-only site |
| proxy 200 to another host (Netlify, Vercel, Cloudflare) | NOT-EXPR | upstream by host name |
| internal rewrite of one path; with a capture | EXPR; NOT-EXPR | exact location `try_files`; capture needs `$uri.html` + `alias` |
| more than 1,000 rules (0.3 %) | NOT-EXPR | the data file of redirects.md 6.3 (later) |
| header rules by path, exact, `/*` | EXPR | `[[site.response_headers]]` |
| header rules by extension glob (`/*.js`, `**/*.@(js|css)`, Render `/**/*.css`) | EXPR | `endings` (files agensio serves) |
| other globs (`/workbox-*`, `/oklch-color-picker-*`) | NOT-EXPR | path patterns |
| host-specific header rules, `Refresh` as a redirect | NOT-NEEDED | `canonical` |
| `! Field` detach | EXPR | `remove` (by ending too) |
| concatenated values of several rules (Cloudflare) | NOT-NEEDED | the longest rule decides |
| default `public, max-age=0, must-revalidate` on every file (Netlify, Cloudflare) | EXPR | `/` `set = { Cache-Control = "no-cache" }` with deeper rules; the baseline does HTML only |
| default nosniff + `strict-origin-when-cross-origin` (Cloudflare) | NOT-NEEDED | static baseline |
| default HSTS `63072000` (Vercel) | EXPR site file; NOT-EXPR managed | |
| `Content-Type` in `_headers`, Azure `mimeTypes` | NOT-EXPR | type table |
| `Basic-Auth`, `allowedRoles` | EXPR | `[[site.auth]]` |
| `Service-Worker-Allowed` | DECIDED-OUT | refused name |

**Generators and frameworks** (§3)

| tool | directive (what it asks) | status | how / missing |
|---|---|---|---|
| Hugo | `404.html` with 404, `404.de.html` | NOT-EXPR | `error_page` (per location for languages) |
| Hugo | pretty URLs `/x/`; `aliases` meta-refresh pages; `_redirects` output | NOT-NEEDED; EXPR | directory index; import as exact rules |
| Hugo | `hugo deploy` lifetimes by `^.+\.(js|css|svg|ttf)$`; fingerprints beside unhashed files | EXPR; AWKWARD | `endings`; `immutable` only on hashed names needs exact rules (no hashed-name test) |
| Jekyll | `error_page 404 /404.html` | NOT-EXPR | `error_page` |
| Jekyll | extensionless permalinks (`about.html` for `/about`) | NOT-EXPR | `$uri.html` |
| Jekyll | jekyll-redirect-from pages, `redirects.json` | EXPR | exact rules from the JSON |
| Eleventy | 404 page | NOT-EXPR | `error_page` |
| Eleventy | `.html` recipe (opt-in); extensionless permalinks need a type | NOT-EXPR | `$uri.html`; type table |
| Eleventy | i18n by `Accept-Language` | DECIDED-OUT | |
| Astro | `error_page 404 /404.html`; `build.format: 'file'` | NOT-EXPR | `error_page`; `$uri.html` |
| Astro | Docker recipe `try_files $uri $uri/index.html =404` | AWKWARD | 301 hop |
| Astro | `/_astro/` immutable; `<meta>` CSP needs `frame-ancestors` by header | EXPR | prefix rule; `/` rule |
| Docusaurus | localised 404 | NOT-EXPR | `error_page` per location |
| Docusaurus | `trailingSlash: false` (`.html`); default `x/index.html` without 301 | NOT-EXPR; AWKWARD | `$uri.html`; hop |
| Docusaurus | `/assets/` lifetime; client redirects; locale detection | EXPR; EXPR; DECIDED-OUT | |
| VitePress | `cleanUrls` "without a redirect" | NOT-EXPR | `$uri.html` |
| VitePress | `error_page 404 /404.html` | NOT-EXPR | |
| VitePress | nginx `/assets/` immutable, `default "no-cache"`; nosniff, SAMEORIGIN, Referrer always | EXPR | rules; baseline covers HTML no-cache, nosniff and Referrer |
| VitePress | `/` → `/en/` by language | DECIDED-OUT | |
| MkDocs / Material | 404 page | NOT-EXPR | `error_page` |
| MkDocs / Material | `/x/` URLs; `/assets/`; mkdocs-redirects | NOT-NEEDED; EXPR; EXPR | |
| Next.js export | default `/blog/post-1.html` for `/blog/post-1`; `rewrite ^/blog/(.*)$ /blog/$1.html` | NOT-EXPR | `$uri.html` (every page but `/` is 404 without `trailingSlash: true`) |
| Next.js export | `error_page 404 /404.html; location = /404.html { internal; }` | NOT-EXPR | `error_page` |
| Next.js export | `/_next/static/` year immutable | EXPR | prefix rule |
| Nuxt generate | `200.html` SPA fallback | EXPR site file; AWKWARD managed | `try_files` to `/200.html` |
| Nuxt generate | `404.html` "keep a 404 status" | NOT-EXPR | `error_page` |
| Nuxt generate | `about/index.html` (autoSubfolderIndex) | AWKWARD | hop |
| Nuxt generate | `/_nuxt/` immutable with `builds/latest.json` exempt | EXPR | longest rule decides |
| SvelteKit static | `fallback` `200.html` | EXPR site file; AWKWARD managed | |
| SvelteKit static | default `a.html` for `/a` | NOT-EXPR | `$uri.html` (or `trailingSlash: 'always'`, then a hop) |
| SvelteKit static | `/_app/immutable/` year; `/_app/version.json` revalidated | EXPR | prefix + exact rules |
| Angular | `index.html` fallback | EXPR site file; AWKWARD managed | |
| Angular | i18n `rewrite ^/$ /$accept_language permanent` | DECIDED-OUT | |
| Angular | root `chunk-HASH.js` immutable; `autoCsp` header part | EXPR | `endings` at `/` + exact `no-cache` for `ngsw-worker.js`; `/` rule |
| React Router / Vite | `/* /index.html 200` or `__spa-fallback.html` | EXPR site file; AWKWARD managed | |
| React Router / Vite | prerendered `x/index.html`; `/assets` immutable; HTML `no-cache` | AWKWARD; EXPR; NOT-NEEDED | hop; rule; static baseline |
| Vue Router | `try_files $uri $uri/ /index.html`; Azure `exclude` | EXPR site file (AWKWARD managed); EXPR | |
| Gatsby | client-only routes `/app/*` → `/app/[...]/index.html` | EXPR | location `try_files` |
| Gatsby | 404 "custom rule to serve this file" | NOT-EXPR | `error_page` |
| Gatsby | HTML, `page-data/`, `app-data.json` revalidate; `static/` + root JS/CSS immutable, `/sw.js` excepted | EXPR | rules: prefix, `endings` at `/`, exact `/sw.js` |
| Gatsby | defaults XFO DENY, XSS `1; mode=block`, nosniff, `same-origin` | EXPR | `/` rule (XSS noted) |
| Gatsby | `trailingSlash: "never"` (`/about/` redirects); default `always` | DECIDED-OUT; NOT-NEEDED | agensio's directory 301 matches `always` |
| Gatsby | `createRedirect` with language/country | DECIDED-OUT | |
| Hexo | `pretty_urls.trailing_html: false` | NOT-EXPR | `$uri.html` |
| Hexo | hexo-generator-alias pages | EXPR | exact rules |

## 2. Counts

Distinct applications (tools and applications; platforms listed separately) whose official
configuration needs each capability marked NOT-EXPR or AWKWARD above, ranked.

| rank | capability | status | apps | which (source) |
|---|---|---|---|---|
| 1 | a site file served as an error page with its status (`error_page`) | NOT-EXPR | 17 | 404 page: Hugo, Jekyll, Eleventy, Astro, Docusaurus, VitePress, MkDocs, Next.js, Nuxt, Gatsby (static SR-4); origin-down page: Mastodon, Discourse, GitLab, Paperless (proxied 26.3); 404 to the application: Magento, PrestaShop, Laravel (php M2-11, PS-9, LV-2). Plus every platform (Netlify, Cloudflare, Vercel, Firebase, GitHub Pages, Azure, Amplify) |
| 2 | `hsts` with `max_age`/`subdomains` on a **managed** site | NOT-EXPR (managed) | 15 | Nextcloud, Matomo, PrestaShop, WordPress, Mastodon, Ghost, GitLab, Mattermost, Rocket.Chat, Keycloak, n8n, Jellyfin, Home Assistant, Paperless, Umami (+ Vercel's default). For Mastodon, GitLab, Keycloak and Umami, which send their own stronger value, managed `hsts: true` narrows it (health warns) and `hsts: false` is the only managed fix (§0.1) |
| 3 | clean URLs: `/x` from `x.html` (NOT-EXPR, 8) or from `x/index.html` without a hop (AWKWARD, 5) | NOT-EXPR / AWKWARD | 11 | `$uri.html`: Next.js export, SvelteKit, VitePress, Docusaurus, Astro, Jekyll, Eleventy, Hexo; `$uri/index.html`: Docusaurus, Nuxt, React Router, Gatsby `never`, Astro (static SR-5, SR-6). Plus every platform |
| 4 | a site type table (`Content-Type` by ending or exact path, `Content-Encoding` for `svgz`) | NOT-EXPR (7) / AWKWARD (2) | 9 | Nextcloud, Drupal, TYPO3 (`svgz`; TYPO3 `.gzip`), MediaWiki (uploads as text), Matomo, Kirby (text/plain defaults), Eleventy (extensionless permalinks); AWKWARD: Synapse, Rocket.Chat (Matrix JSON via a renamed file and an exact location). Plus `_headers` (17 %) and Azure `mimeTypes` (13.8 %) |
| 5 | the SPA fallback on a **managed** static site | AWKWARD (managed) | 7 | Angular, Vue Router, React Router, Vite, Nuxt, SvelteKit, Gatsby (static SR-1; 45.5 % of `_redirects`) |
| 6 | internal rewrites that drop or capture a segment | NOT-EXPR | 6 | Magento (signed static), PrestaShop (images, `/api/`), WordPress multisite (subdirectories); opt-in: Roundcube, TYPO3, Statamic (php §24.10) |
| 7 | a lifetime on every file agensio serves without listing endings (`ExpiresDefault`, `ExpiresByType`) | AWKWARD | 6 | Drupal, TYPO3, FreshRSS, Roundcube, Magento, PrestaShop |
| 8 | upstreams by host name | NOT-EXPR | 3 | Ghost (ActivityPub), Mastodon (object storage), Plausible (script proxy); plus 3.8 % of `_redirects` |
| 9 | `*` / `**` path patterns in a header rule's `path` | NOT-EXPR / AWKWARD | 3 | Grav (`**/_app/immutable/`), Matomo (`container_*_preview.js`), Element (`config.<name>.json` per name); plus 3.6 % of `_headers` |
| 10 | exempting a path suffix from an offered frame field | NOT-EXPR (2) / AWKWARD (1) | 3 | WordPress `/post/embed/`, Mastodon `/@user/:id/embed`; Vaultwarden `*connector.html` (exact `remove` rules) (notes.md §4.3; proxied §1, §14) |
| 11 | dropping `Server` per site (`-Server`) | AWKWARD | 3 | Vaultwarden, Paperless, Nextcloud AIO's inner Caddy: only server-wide `server_header = ""`, root's file; a rule's `remove` is a silent no-op |
| 12 | disk first, then the proxied application (`try_files $uri @app`), and `alias` on a managed proxy site | AWKWARD | 3 | Mastodon, Discourse (fallback); Umami (`alias` on managed) |
| 13 | a query condition on header rules (`immutable` with `?v=`) | NOT-EXPR | 2 | Nextcloud, FreshRSS (cosmetic) |
| 14 | exact paths exempt from `http = "redirect"` | AWKWARD | 2 | GitLab (8 health paths), Metabase (marginal) |
| 15 | keeping a field off 204 answers | NOT-EXPR | 1 | Ghost (#1858; offers only) |
| 16 | extra FastCGI parameters | NOT-EXPR | 1 | Nextcloud `front_controller_active` (its URLs keep `index.php`) |
| 17 | a hashed-name test for `immutable` | AWKWARD | 1 | Hugo (fingerprints beside unhashed files) |

Not counted as gaps: everything DECIDED-OUT (trailing-slash policy: Laravel, Statamic, BookStack,
phpMyAdmin, Gatsby; captures: WordPress multisite, phpMyAdmin; request-field conditions: Nextcloud,
Vaultwarden, Mattermost and six static tools' language detection; ETag removal: PrestaShop, TYPO3,
FreshRSS, Discourse; preload: 10 applications; variables: Mastodon, Mattermost, Plausible;
`ALLOW-FROM`: Jellyfin, Paperless; append/merge: Roundcube, FreshRSS, BookStack, Gitea).
The language redirect is decided out on "the application's job" (redirects.md 5.4), a reason
static_and_spa.md SR-19 calls weak for static sites, where six of sixteen tools ask the server.

## 3. Baseline conflicts

None of the baseline's four parts breaks, duplicates or overrides what an application sends, which
the design guarantees by construction (`default` and `remove` only, nosniff on agensio's own
answers): Referrer-Policy `strict-origin-when-cross-origin` is safe on all 25 proxied applications
(proxied_apps.md 26.2) and on every application of notes.md §4.2 (Django's `same-origin`, Home
Assistant's and Keycloak's `no-referrer` win); no application relies on `X-Powered-By`; no frame
field is added (21 of 25 proxied applications decide framing themselves, proxied_apps.md 26.2;
WordPress embeds, notes.md §4.3); the static `no-cache` on HTML matches Vite, VitePress, Gatsby,
Element (static_and_spa.md SH-4; proxied §12). nosniff on files agensio serves cannot break a script
it types itself (`js`, `mjs`, `wasm`, `json`, `css` are in the table); the two cases that are
broken under agensio (TYPO3's `.js.gzip` scripts, `.svgz` images) are broken by the missing type
table with or without the field.

Four divergences worth knowing, none breaking:

1. **The SPA shell can lose the baseline's `no-cache`.** A user rule at a longer path naming
   `Cache-Control` without `endings` (`/assets/` a year, `immutable`) decides over the baseline's
   `/` HTML default, so a missing asset that falls back to the shell caches the shell for a year
   (static_and_spa.md SR-2; headers.md 3.5). The documented `-t` warning for it is not built (§0.2).
   Writing asset rules with `endings` avoids it, since the shell's served file ends in `html`.
2. **Files agensio serves get a weaker Referrer-Policy than some vendors document.** Nextcloud's
   `.htaccess` and nginx sample send `no-referrer` on every answer (php_apps.md NC-3, NC-11), Matomo
   `origin` (MT-3); the baseline puts `strict-origin-when-cross-origin` on their static files and
   on agensio's error pages (Nextcloud's setup check accepts it, proxied_apps.md §19c). On
   `django`/`wagtail` the same value reaches `/static/` and `/media/` while Django's pages send
   `same-origin` (headers.md 4.2). Harmless (a stylesheet's policy governs only what it loads); a
   `/` `default` rule restores the vendor's value.
3. **Health's `response_headers_suggested` asks for what some vendors removed on purpose**: a frame
   field and `Permissions-Policy` on Jellyfin, whose nginx docs dropped XFO and `frame-ancestors` for
   the LG webOS client and flag Permissions-Policy as risky (proxied_apps.md §16 history); a frame
   field on Uptime Kuma, Grafana and Home Assistant when embedding is switched on (§21, §22, §17).
   `response_headers_offer_declined` and the MCP texts handle it; for Jellyfin the cookbook or the
   preset-free proxy texts should say so up front.
4. **The baseline leaves applications' own `X-XSS-Protection: 1; mode=block` alone** (Redmine,
   Kanboard, Grafana, GitLab, Rocket.Chat's `1`; notes.md §1, proxied §8, §10, §21) while `-t` notes
   the same value in a rule. Consistent with "never an application's own", but health could name it
   (headers.md 7 "later").

What a preset needs that the baseline leaves out by default:

- **`static`: revalidation of the non-HTML files a deploy changes in place.** Element's README
  requires `/version`, `/i18n/` and `/config*.json` uncached (proxied_apps.md §12); Gatsby asks
  `max-age=0, must-revalidate` on `page-data/` and `app-data.json` and revalidation of `/sw.js`;
  Nuxt's `/_nuxt/builds/latest.json` and SvelteKit's `/_app/version.json` must revalidate
  (static_and_spa.md 3.1). Without a field these get heuristic freshness. Netlify and Cloudflare
  send `public, max-age=0, must-revalidate` on every file (static_and_spa.md 2.1, 2.2): the same
  "cannot break a page" bar the HTML default meets, at the cost of a 304 per unhashed file.
- No other preset needs more. The vendors' nosniff and frame fields on application answers
  (Laravel, Drupal, TYPO3, Joomla, Kirby, Craft, Nextcloud, Matomo; php_apps.md §22.11) are the
  agent's offers by decision (headers.md 11.2 item 5), and the evidence for leaving frame fields out
  stands.

## 4. Top gaps

Ranked by the counts of section 2. Each suggestion keeps agensio's habits: typed keys with fixed
values, no regex, one prebuilt decision where possible, no cost to a request that does not use it,
and a managed field with `path_check` support.

1. **`error_page` (17 applications, every platform).** A site and location key mapping a status to
   a file of the root: `error_page = { 404 = "/404.html", 410 = "/410.html" }`; per location for
   localised pages (`/fr/` → `/fr/404.html`). The static handler's own 404 (and 403, 410) serves that
   file with the status kept (so no `when = "success"` lifetime reaches it); only a regular file,
   never run, never a `try_files` hop; the built-in page when it is missing. A second
   set for the answers agensio makes when an origin fails, `error_page = { 502 = "/offline.html", 503
   = ..., 504 = ... }`, served from disk on proxied sites (Mastodon, Discourse, GitLab, Paperless),
   never replacing an application's own error body (unlike nginx's `proxy_intercept_errors`). The
   file's bytes come from the cache, so the cost is on the error path only. Managed: `site_update`
   `error_pages`; `path_check` names the page; `-t` refuses a target that `refuse` or a deny location
   covers; health says when the file is missing. The PHP case (agensio's 404 handed to `index.php`:
   Magento, PrestaShop, Laravel) stays out: it would run the application on a refused path.
2. **`hsts` table on managed sites (15 applications).** Accept `hsts: { max_age, subdomains }` in
   `site_create`/`site_update`, judged by the loader's `hsts_age` (seconds or units, at most ten
   years) and rendered as the table; `ctl --hsts-max-age 63072000 --hsts-subdomains`. The MCP text:
   take the application's documented value (Mastodon and GitLab two years, Keycloak and Home
   Assistant `includeSubDomains`), ask before `subdomains` and list the other hosts it binds. Health's
   `hsts_narrows_application` fix then names a managed field instead of only `hsts: false`. No
   request cost (the field is prebuilt in `SiteFields`).
3. **Clean URLs (11 tools, every platform).** Two fixed `try_files` steps, `$uri.html` and
   `$uri/index.html`, and nothing more general: they are the nginx lines Next.js, VitePress and Astro
   document. A miss costs one more lookup on the miss path only. On a managed static site, a typed
   `rules.clean_urls = true` rendering `try_files = ["$uri", "$uri.html", "$uri/", ...]`. Optional
   companion (static_and_spa.md change 2): an exact 308 from `/x.html` to `/x` for files that exist,
   so a page has one address, as Vercel's and Firebase's `cleanUrls` do.
4. **A site type table (9 applications).** First, a fix in the compiled table: `svgz` with
   `Content-Encoding: gzip` (Nextcloud, Drupal and TYPO3 all declare it; agensio's answer cannot be
   rendered today). Then `types = { "sh" = "text/plain; charset=utf-8", "/.well-known/apple-app-site-association"
   = "application/json" }`: endings and exact paths only, values checked as `type/subtype` with
   optional `charset`, prebuilt into the cache entry so a hit pays nothing; managed `types`. That
   also makes the Matrix delegation a plain file instead of a renamed one plus a location.
5. **The SPA fallback on managed static sites (7 tools).** Accept `rules.front_controller` naming an
   `.html` file on `app = "static"` (`/index.html`, `/200.html`), rendered as the site's `try_files`
   line; render every `rules.cache` directory with `try_files = ["$uri", "=404"]` when a fallback
   exists, so a missing bundle is a 404 and never the shell (SR-2). Build the documented `-t`
   warning for a freshness rule without `endings` over a prefix the fallback answers (§0.2).
6. **Internal path aliases that drop one segment (6 applications, 3 with a default feature).** A
   prefix location whose `path` has one `*` segment, with `alias`: `path = "/static/version*/"`,
   `alias = "<root>/static/"` (Magento), `path = "/*/wp-admin/"` (WordPress subdirectory multisite,
   with the subsite's scripts), a 16-character token segment for Roundcube. One wildcard, whole
   segment, no capture reused elsewhere; matched after exact and literal prefixes. Captures into a
   query (PrestaShop's images, Magento's `static.php?resource=`) stay out.
7. **A rule for every file agensio serves (6 PHP applications).** `endings = ["*"]` (or a boolean
   `files = true`), the same served-file test `endings` already makes, without listing endings: the
   one-line translation of `ExpiresDefault` with `.php` off (Drupal, TYPO3, FreshRSS, Roundcube) and
   the base under Magento's and PrestaShop's per-type lists. Same cost as `endings` today (one
   comparison when agensio picks a file).
8. **Upstreams by host name (3 applications, 3.8 % of static sites' rules).** Resolve names at load
   and reload (and on a slow timer), pin the addresses in the generation, default
   `proxy.tls.server_name` and SNI to the name, health when a name stops resolving. Outside these
   designs, but it blocks the object-storage, ActivityPub and script-proxy recipes.
9. **Path patterns in header rule paths (3 applications).** Reuse the `refuse` grammar (`*` within a
   segment, one `**`) for `[[site.response_headers]] path`, precedence exact, then pattern, then
   prefix, by literal length; behind the existing first-byte test, so a site without patterns pays
   nothing. Covers Grav's `**/_app/immutable/`, Matomo's preview containers and Element's
   `/config*.json`.
10. **Preset rows for the embed exceptions (3 applications).** Rather than suffix paths, a fixed
    per-preset list of addresses a frame-field offer must exempt, applied by `path_check`'s offer and
    the agent: WordPress answers carrying `X-WP-embed: true` (the marker notes.md §4.3 cites),
    Vaultwarden's connector pages. Smaller and cheaper than a general suffix match, and only used
    when the owner accepts a frame field.

Smaller items found on the way, each a one-line fix or a doc correction: `remove = ["Server"]` should
be refused with the `server_header` advice, or remove agensio's own per site (Vaultwarden,
Paperless, AIO translate `-Server` to it; built.md "rough edges"); headers.md 3.5 and 11.2 item 3
promise `rules.cache` `immutable`, which is not built, and basics.md L629 still sends `immutable` to
root additions; CLAUDE.md's "MIME ... overridable from config" is untrue; exact paths exempt from
the scheme redirect (`http = { mode = "redirect", serve = ["/-/health"] }`, GitLab) and no nosniff on
a rule's 204 (Ghost) are single-application needs.
