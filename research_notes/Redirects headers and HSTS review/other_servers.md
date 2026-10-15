# Redirects, HSTS and response headers: agensio against eight other servers

Reviewed 2026-10-14 against `built.md` (alpha.75 to alpha.94), `docs/configuration.md` 14, 14b, 14c,
`docs/redirects.md` 5 to 12, `docs/headers.md` 2, 3.8, 10, 11, and the source where a claim needed it.

**Sources and abbreviations.** The four notes in
`research_notes/Web server headers and redirects/`:

- **NG** = `nginx.md`, sections §1 to §7 as numbered there.
- **AP** = `apache.md`, by heading: *actions* (mod_headers actions), *tables* (onsuccess vs always),
  *merging* (processing time and merging), *Server* (X-Powered-By and Server), *mod_alias*,
  *mod_rewrite*, *alias/rewrite order*, *auth order* (order against authentication), *301*
  (status and 301 caching).
- **CTH** = `caddy_traefik_haproxy.md`: *Caddy header*, *Caddy handle_errors* (matchers, order,
  handle_errors), *Caddy redir*, *Traefik headers*, *Traefik redirects*, *HAProxy after-response*,
  *HAProxy redirects*, *summary*.
- **LHI** = `litespeed_h2o_iis.md`: *OLS headers*, *OLS redirects*, *h2o headers*, *h2o redirect*,
  *IIS headers*, *IIS redirects*, *summary*.

Two rows also cite notes outside the brief: `panels_and_site_owners.md` (maintenance) and
`standards_security.md` (preload). They are marked where used.

**How use is weighed.** The evidence column starts with a weight:
- **[strong]**: issue threads, mailing-list or forum reports, a vendor workaround, a panel that
  writes the rule, or field data.
- **[medium]**: an official recommendation or a documented example.
- **[weak]**: the directive only exists.

Statuses:
- **COVERED**: built.
- **PARTIAL**: built in part; what is missing is named.
- **MISSING**: not built.
- **DECIDED-OUT**: built.md or the design records a decision against it.

## 1. Capabilities

### A. HTTPS and HSTS

| # | capability | servers that have it | evidence of use (file, section) | status in agensio | note |
|---|---|---|---|---|---|
| A1 | HTTP to HTTPS redirect as one setting | nginx (`return 301` in the :80 server), Apache (Redirect in a plain vhost; mod_md `MDRequireHttps`), Caddy (automatic, 308), Traefik (entry-point `redirections`, `redirectScheme`), HAProxy (`redirect scheme`), OLS (`RewriteRule ... [R=301,L]`) | [strong] AP *mod_alias* ("a Redirect in a dedicated HTTP virtual host is the cleanest approach"; MDRequireHttps); CTH *Caddy redir* (automatic 308); CTH *Traefik redirects* (entry-point redirection, `permanent` defaults to true); LHI *OLS redirects* (docs' HTTPS examples) | COVERED | `http = "redirect"` is the default for TLS on 443: a 308 cached for a day. ACME and pki-validation paths are never redirected, while the AP *mod_alias* note says a hand-written Redirect must exclude `/.well-known/` itself. |
| A2 | The scheme decided behind a TLS-terminating proxy | Traefik (`redirectScheme` trusts `X-Forwarded-Proto` from a trusted hop; `sslProxyHeaders`) | [medium] CTH *Traefik redirects* | COVERED | The trusted proxy's `X-Forwarded-Proto` decides. When a trusted proxy sends none, health reports `proxy_scheme_missing` (loop risk). |
| A3 | One canonical host (`www` or bare) | cPanel on Apache or LiteSpeed ("Redirect with or without www"); nginx `return 301 $scheme://www...$request_uri`; OLS host RewriteRule | [strong] NG §3 (NGINX blog: the recommended domain-move form); LHI *OLS redirects* (cPanel's www options) | COVERED | `canonical`: a 308 that keeps path and query, scheme and host in one hop. Health reports `app_redirects_elsewhere` when the application disagrees. |
| A4 | HSTS on every HTTPS answer, errors and redirects included, one copy | nginx (`add_header ... always`), Apache (`Header always`), HAProxy (`http-after-response`), Traefik (`stsSeconds`), mod_md | [strong] AP *tables* (the security-header best practice "amounts to use always"); CTH *HAProxy after-response* (the manual's STS example; the ruleset was added so generated answers get headers); CTH *Traefik headers* | COVERED | `hsts` is never sent over plain HTTP. It replaces the application's own copy; health reports `hsts_narrows_application` when that copy was stronger. |
| A5 | `includeSubDomains` | Traefik `stsIncludeSubdomains` | [medium] CTH *Traefik headers* | COVERED | `subdomains`; `-t` warns about sibling sites without TLS. |
| A6 | `preload` | Traefik `stsPreload` | [weak] CTH *Traefik headers* (the option exists); AP *301* (mod_md: "you cannot simply take it back") | DECIDED-OUT | The four notes show only that the option exists; they give no reason to revisit. One narrow case: a domain already preloaded whose token came from the old server (Traefik, an nginx `add_header`) cannot keep sending it. `set` and `default` refuse STS, and only the application's own copy passes, and only with `hsts` unset or `false`. If revisited, accept `preload` only with `max_age` of at least a year and `subdomains` (`standards_security.md`, "HSTS" section, outside the brief). |
| A7 | HSTS when TLS ends upstream (`forceSTSHeader`) | Traefik | [weak] CTH *Traefik headers* | COVERED | HSTS is sent on answers a trusted proxy marks https, never on genuine plain HTTP. |
| A8 | Rewriting an application's `http://` Location | nginx `proxy_redirect` (on by default) | [medium] NG §2 | COVERED | `proxy.redirects` handles origin rewriting; `upgrade_location` sends a Location naming the site as `https://` (alpha.79). |

### B. Redirects

| # | capability | servers that have it | evidence of use (file, section) | status in agensio | note |
|---|---|---|---|---|---|
| B1 | One page moved (exact) | nginx `location =` plus `return`; Caddy `redir /about-us /about` (path matchers are exact); IIS `<location>` per file; HAProxy map; h2o cannot | [strong] CTH *Caddy redir* (the docs' example); LHI *IIS redirects* (a single-file redirect under `<location>`); LHI *h2o redirect* (no exact form) | COVERED | `match = "exact"`. |
| B2 | A section moved, rest of the path kept | Apache Redirect; OLS Redirect context; h2o `redirect`; IIS httpRedirect (by default); HAProxy `prefix`; cPanel "Wild Card Redirect" | [strong] AP *mod_alias* ("Remember that Redirect preserves path information"); LHI *OLS redirects* (cPanel); LHI *summary* | COVERED | The remainder is kept by default and prefixes cover whole segments. One `/` at the join, so Apache's `twoa` slash trap cannot happen. |
| B3 | A section to one page (drop the rest) | IIS `exactDestination`; Caddy (target as written); HAProxy `location` | [medium] LHI *IIS redirects*; CTH *Caddy redir* | COVERED | `remainder = "drop"`; a rule from `/` with drop is noted as a soft 404. |
| B4 | Query kept, dropped or replaced | nginx rewrite (appended; a trailing `?` drops it); Apache Redirect (kept unless the target has `?`); mod_rewrite QSA/QSD; HAProxy `drop-query`, `keep-query` (3.1); IIS `appendQueryString`; OLS (kept unless the target has `?`) | [medium] CTH *HAProxy redirects* (`keep-query` arrived only in 3.1; a crash fix 2026-08); NG §3; AP *mod_alias*, *mod_rewrite* | COVERED; one semantic differs | A `to` with its own query keeps it and the client's follows after `&`, as nginx rewrite and HAProxy `keep-query` do. Apache Redirect and OLS drop the client's query in that case (see M6). |
| B5 | Matching old query-string addresses (`/?p=123`) | nginx `map $request_uri` (includes the query); Traefik redirectRegex (the query is in the matched text) | [medium] NG §3 (map recipe is folklore, gaps); CTH *Traefik redirects* | COVERED | Exact rules only, parameters in any order, other parameters ignored. |
| B6 | A whole domain moved | nginx `return 301 $scheme://new$request_uri`; Apache `Redirect /` | [strong] NG §3 (the NGINX blog's recommended form) | COVERED | A rule from `/`; the site needs no root; `tls = "auto"`. |
| B7 | Redirect everything but some paths (a section still served under a catch-all redirect) | nginx (a `location` without `return` beside `location / { return 301 ... }`); h2o (official example: `/` redirected, `/rss` served); Caddy (matchers, or `route` so a `file_server /specific.html` wins); HAProxy and Traefik (`unless` ACLs, chain order) | [medium] LHI *h2o redirect* (the docs' own example); CTH *Caddy redir* ("A catch-all redir with a specific file_server /specific.html needs a route block"); NG §5 (location selection) | MISSING | Rules stand before the locations (configuration.md 14b, "Where rules stand"). No rule can say "not redirected": `status` must be 301, 302, 307, 308 or 410 (`src/config.cpp` near line 1927), and a rule to itself is refused as a loop. See M2 and G3. |
| B8 | Bulk redirect lists (thousands to 100k) | nginx `map` (hashed); HAProxy map files (exact keys in a tree, `map_beg` longest prefix); IIS rewrite maps; Caddy `map` (linear) | [strong] CTH *HAProxy redirects* (discourse: 0, 10k and 100k entries "negligible" difference; maintainer: "that is the use-case for map files"); LHI *IIS redirects* (maps "particularly useful when you have a large set"); NG §5 | PARTIAL | The structure is right: exact rules hashed, prefixes behind a first-byte test. The count is capped at 1,000 per site file; a data file is "a later step" (redirects.md 6.3). See G4. |
| B9 | Regex or capture redirects (RedirectMatch, rewrite, redirectRegex, URL Rewrite, OLS `exp:`) | nginx, Apache, Traefik, IIS, OLS, HAProxy (`regsub`) | [strong use, strong cost] AP *mod_rewrite* (Apache's docs: "a last resort"); NG §3 (three 2026 heap overflows in rewrite and map captures); CTH *Traefik redirects* (`${1}` escaping, #10690) | DECIDED-OUT | The notes support keeping it out. What remains is a capture inside the target (1 to 2.7 % of `_redirects` lines, redirects.md 12.1), which the planned single `*` per segment answers. |
| B10 | A status that must be chosen (no silent default) | No server requires one, except h2o in mapping form. Defaults: nginx 302 or 301; Apache, Caddy and HAProxy 302; OLS 302 or an internal rewrite; IIS 302 (httpRedirect) and 301 (URL Rewrite); Traefik by method | [strong] LHI *summary*; CTH *summary* | COVERED | Required: 301, 302, 307, 308 or 410. |
| B11 | 303 See Other | Apache `seeother`, HAProxy, Caddy (any 3xx), IIS URL Rewrite | [weak] AP *mod_alias* | DECIDED-OUT | No use evidence in the notes; the decision holds. |
| B12 | 410 Gone | Apache `Redirect gone`; OLS Redirect context (any code of 400 or more) | [medium] AP *mod_alias*; LHI *OLS redirects* (source) | COVERED | `status = 410` with no `to`. |
| B13 | Method-keeping redirects (307, 308) and the POST-to-GET warning | Traefik (status chosen by method); Caddy's docs; Apache ("POSTs will be discarded") | [medium] CTH *Traefik redirects*; CTH *Caddy redir*; AP *mod_alias* | COVERED | 307 and 308 are offered, and the docs and MCP texts tell the agent to ask. Nothing detects at load that a path takes a POST. |
| B14 | Bounding how long browsers keep a permanent redirect | None built in; Apache's docs say test with 302 and add headers with `Header always` | [strong] AP *301* ("allowed to cache that response indefinitely ... use [R=302]"); NG §4 (SO 9130422); LHI *OLS redirects* (cPanel warns that browsers cache redirects) | COVERED | `cache` defaults to a day: ahead of every server in the notes. |
| B15 | Relative Location, no leaked internal port | nginx `absolute_redirect`, `port_in_redirect`, `server_name_in_redirect`; Apache `RedirectRelative` (2.4.58+), `UseCanonicalName` | [medium] NG §3 (hence "port_in_redirect off and absolute_redirect off in many configs") | COVERED | A target on the site stays relative; an absolute Location names only `to`'s origin. |
| B16 | Trailing-slash redirect for a directory | nginx static module (301); Apache mod_dir | [medium] NG §3 (escaping bug fixed in 1.21.0) | COVERED | A 301 to the slash form (configuration.md, `try_files` rules). |
| B17 | Automatic `/app` to `/app/` for a proxied prefix ending in `/` | nginx (`proxy_pass`, `fastcgi_pass`, ... locations) | [medium] NG §3 (core `location` docs) | MISSING | `Router::location` is a byte prefix (`src/core/router.hpp:46`), so `/app` falls to another location; an exact `[[site.redirect]]` is needed (redirects.md 12.2.5). See M7. |
| B18 | Loop protection (`to` under `from`) | IIS (`childOnly`, which the IIS team calls a safeguard) | [strong] LHI *IIS redirects* (the IIS team's pitfalls: inherited destinations loop) | COVERED | Refused at load: `to` under `from` with the remainder kept, and cycles. Chains are noted. |
| B19 | Redirects answered before access and password checks | nginx (rewrite phase first); Apache vhost level (before) vs `.htaccess` (after); Caddy (`redir` before `basic_auth`); OLS (before); IIS URL Rewrite (before) vs httpRedirect (after); HAProxy and Traefik (declaration order) | [medium] NG §3 (mailing-list threads: operators surprised); AP *auth order* | COVERED | A fixed order, plus the load note "a rule under an access or password rule". |
| B20 | Redirect only after login | Apache (`.htaccess` placement), IIS httpRedirect, h2o (handler order) | [weak] AP *auth order* ("an edge case"); NG §3 (the `try_files @redir` workaround) | MISSING (not needed) | The notes call it an edge case. |
| B21 | The wildcard part of the host substituted into the target | h2o (`*`) | [weak] LHI *h2o redirect* | MISSING | No use evidence. |
| B22 | A browser-only redirect page (HTML/JS, meta refresh) | Caddy `redir html`; nginx `msie_refresh` | [weak] CTH *Caddy redir*; NG §4 | MISSING (not needed) | |
| B23 | Case-insensitive redirect matching | nginx `map` ("Strings are matched ignoring the case"); Caddy path matchers ("exact but case-insensitive"); HAProxy lists used with `path,lower`; Traefik `(?i)` | [medium] NG §3; CTH *Caddy handle_errors* (path matcher); CTH *HAProxy redirects* (the field config uses `path,lower,map`) | DECIDED-OUT (case-sensitive, redirects.md 12.2.1) | The stated reason, "as on every hosting platform", does not hold for Caddy or nginx `map`. nginx `location`, Apache Redirect and Traefik `PathPrefix` are case-sensitive. See M3 and G8. |
| B24 | Internal rewrite (not a redirect) | nginx `rewrite ... last`; OLS internal redirect; h2o `internal: YES`; IIS Rewrite; Apache `FallbackResource` | [strong] AP *mod_rewrite* (`FallbackResource` is "simpler") | PARTIAL (out of scope here) | `try_files /path` and the front controller cover it. Rewrites that drop a segment are open (redirects.md 12.4). |

### C. Response headers

| # | capability | servers that have it | evidence of use (file, section) | status in agensio | note |
|---|---|---|---|---|---|
| C1 | Set, replacing the application's copy | Traefik `customResponseHeaders`; HAProxy `set-header`; headers-more `more_set_headers`; h2o `header.set`; Caddy `>`/`defer`; Apache only as `onsuccess unset` plus `always set` | [strong] CTH *Caddy header* (#6275 duplicate Server; thread 8146 duplicate cache-control); AP *tables* (PHP-FPM duplicates; PR 64646); NG §1 (forum thread 676) | COVERED | `set`. |
| C2 | Default: only when the answer has none | Caddy `?`; Apache `setifempty`; h2o `setifempty`; nginx and HAProxy only by idiom; Traefik, OLS and IIS none | [medium] CTH *Caddy header* (it has its own prefix); LHI *summary* | COVERED | `default`. |
| C3 | Remove a field, the application's included | headers-more; Caddy `-`; HAProxy `del-header`; Traefik (empty value); h2o `unset`; Apache `unset` (fails under PHP-FPM without `always`); nginx `*_hide_header` (upstream fields only) | [strong] AP *Server* (Plesk KB: `Header always unset "X-Powered-By"`); NG §2 | COVERED | `remove`, by exact name. |
| C4 | Removal by name pattern (`X-Hidden-*`) | headers-more; Caddy (`-Some-*`); HAProxy `del-header -m beg/reg` | [weak] NG §2; CTH *Caddy header*; CTH *HAProxy after-response* | MISSING | No use evidence beyond the docs. |
| C5 | Add, append, merge (Cache-Control, Link, Vary lists) | Apache, h2o, OLS, HAProxy `add-header`, Caddy `+`; nginx appends Cache-Control and Link by itself | [weak to medium] AP *actions* (the merge example; the warning on `add`); CTH *summary* (Link, Vary, Set-Cookie: an inference) | DECIDED-OUT | The notes show no use agensio needs. But nginx's silent append is why M5 exists. |
| C6 | Regex edit of a value (`Header edit`, `replace-header`, `replace-value`, Caddy's three-argument form) | Apache, HAProxy, Caddy | [medium, for cookies] LHI *OLS headers* (LiteSpeed lists `Header always edit Set-Cookie (.*) "$1;HTTPOnly;Secure;SameSite=none"` as unsupported and ships `ForceSecureCookie` instead) | DECIDED-OUT (no regex); cookie flags deferred (headers.md 3.8) | See C19 and G10. |
| C7 | Headers on every answer: errors, redirects, 401, 304, proxied, PHP | nginx needs `always`; Apache needs `always` (and `onsuccess unset`); Caddy needs `handle_errors` (deferred operations are lost); HAProxy needs `http-after-response`; Traefik depends on the chain; h2o and OLS do it structurally | [strong] NG §6 (trac #1122; the 2009 and 2011 list threads); CTH *Caddy handle_errors* (#6689); CTH *HAProxy after-response*; AP *tables* (Nottingham: CORS headers missing on 304) | COVERED | Not on 400, 421 or 431 before routing, the same exception as HAProxy's early mux errors and h2o's broken requests. |
| C8 | A status condition | Apache `expr=%{REQUEST_STATUS}`; headers-more `-s`; Caddy `match status`; HAProxy's `http-response` scope | [medium] CTH *Caddy header* (the example deletes Cache-Control on 500 "to prevent caching of error responses"); AP *tables* (the `expr` status example) | COVERED, two classes; PARTIAL beyond | `when = "always"` or `"success"`; freshness is refused without success. Specific statuses (Ghost's 204) are open (headers.md 11.3). |
| C9 | A condition by file ending or content type | headers-more `-t` (content type); Caddy named matcher `@html path *.html`; h2o extension level; Apache `<Files>`/`<FilesMatch>` | [medium] CTH *Caddy header* (thread 13858: users want `*.html` and trip on the inline matcher); LHI *h2o headers*; AP *merging* | COVERED for files on disk (`endings`); PARTIAL for application answers | There is no content-type condition on an application's answer; a deliberate choice (headers.md 10.8). |
| C10 | Deterministic combining across path levels | nginx (a level drops its parent's set, `merge` only since 1.29.3); Apache (`<Directory>` shortest first, `<Location>` in file order); Caddy (immediate: the general one wins; deferred: the specific one); Traefik and HAProxy (the outer one wins); OLS (parent first, `NONE`); h2o (longest path only); IIS (collections parent to child) | [strong] NG §1 (Gixy's `add_header_redefinition`; eleven years to `add_header_inherit`); CTH *Traefik headers* (#12195); CTH *Caddy handle_errors* (thread 8146) | COVERED | Per field, the most specific rule decides. |
| C11 | Opting out of an inherited rule without touching the field | OLS `NONE`; IIS `<clear/>` and `<remove>`; nginx `add_header_inherit off` | [weak] LHI *OLS headers*, *IIS headers*; NG §1 | PARTIAL | A deeper rule can `remove` (the application's copy goes too) or `default` (which adds a value when absent). No verb says "no rule here; the answer's own copy stands". |
| C12 | Server header control | nginx `server_tokens` (an empty string is commercial-only); Apache `ServerTokens` (Prod at least, never removed); OLS "Hide Full Header"; IIS `removeServerHeader`; h2o refuses it; Caddy (Via on proxy) | [medium] NG §2 (headers-more as the standard answer); AP *Server*; LHI *IIS headers* (the outbound-rule workaround); CTH *Caddy header* (#6275) | COVERED (server-wide) | `[server] server_header = ""`. Rough edge: `remove = ["Server"]` is accepted with no effect, and `path_check` reports "removed" (built.md). |
| C13 | X-Powered-By removed under PHP-FPM | Apache (`Header always unset`, Plesk KB); IIS (`<remove>` of its own default entry) | [strong] AP *Server* (a plain `unset` silently fails under FPM) | COVERED | The baseline removes it from every answer; PHP's own is off in the pools agensio writes. |
| C14 | Hide or replace upstream fields only | nginx `proxy_hide_header`; Caddy `header_down`; HAProxy `http-response` | [medium] NG §2; CTH *Caddy header* (Matt Holt's advice) | COVERED | `remove` and `set` act on the application's fields; `proxy.hide`. |
| C15 | Request fields to the upstream | Apache `RequestHeader`; Caddy `header_up`; OLS `RequestHeader`; headers-more input; nginx `proxy_set_header` | [medium] AP *actions*; CTH *Caddy header* | COVERED (out of scope) | `proxy = { request_headers }`, with `$` variables. |
| C16 | Fields no rule may touch (framing, Date, Server) | h2o refuses Connection, Content-Length, Transfer-Encoding, Date, Server; headers-more cannot remove Connection | [medium] LHI *h2o headers*; NG §2 | COVERED | Refused, each with a pointer to the setting to use (headers.md 2.5). |
| C17 | Typed security fields (frame, nosniff, referrer, permissions, CSP, CSP report-only) | Traefik (unrolled/secure) | [medium] CTH *Traefik headers* | COVERED (rules, baseline, offers) | Values are checked: XFO only DENY or SAMEORIGIN; notes for X-XSS-Protection and for a CSP `set`. |
| C18 | A host-wide header policy (every site) | nginx `http`-level `add_header`; Apache server config; IIS `applicationHost.config`; Traefik entry-point middleware; HAProxy frontend and `defaults` | [medium] CTH *Traefik headers* (entry-point middlewares "prepended" to every router); LHI *IIS headers* (the applicationHost default) | PARTIAL | Rules are per site, plus the per-preset baseline. A host-wide policy is written into each site (the agent can do it). |
| C19 | Cookie attributes enforced (Secure, HttpOnly, SameSite) | LiteSpeed `ForceSecureCookie` (and LSWS adds `secure` over HTTPS by itself); Apache `Header edit Set-Cookie` | [medium] LHI *OLS headers* | MISSING (deferred: "a typed setting later if a real case needs it", headers.md 3.8) | G10. |
| C20 | Headers on 1xx / Early Hints | h2o (`when: early`) | [weak] LHI *h2o headers* | MISSING (not needed) | |

### D. CORS

| # | capability | servers that have it | evidence of use (file, section) | status in agensio | note |
|---|---|---|---|---|---|
| D1 | A fixed Access-Control-Allow-Origin (fonts, JSON, a public API) | All, through their generic header directive | [medium] AP *tables* (Nottingham: the field missing from Apache's 304s) | COVERED | Rules, with `endings` for files. They reach 304 and OPTIONS answers. One origin, `*` or `null`; `*` with credentials is refused. |
| D2 | Several origins, Origin echoed, `Vary: Origin` | Traefik (`accessControlAllowOriginList`, `...Regex`, `addVaryHeader`) | [weak to medium] CTH *Traefik headers* | DECIDED-OUT (a typed `cors` "when a real case asks", headers.md 10.5) | The notes show one product's typed option, and agensio's own configuration review found no application needing an echoed Origin (headers.md 11.1). The decision holds, apart from D3. |
| D3 | Preflights answered by the server | Traefik ("the middleware does not pass preflight requests to any service") | [medium] CTH *Traefik headers* | PARTIAL | agensio answers OPTIONS itself only on static locations (`src/handlers/dispatch.cpp:703`); PHP and proxied applications get the preflight. See M4 and G5. |

### E. Cache headers

| # | capability | servers that have it | evidence of use (file, section) | status in agensio | note |
|---|---|---|---|---|---|
| E1 | Lifetimes by path or file type | nginx `expires`/`add_header`; Apache mod_expires and Header; OLS "Expires By Type"; h2o extension level; Caddy | [medium] LHI *OLS headers* (typed Expires settings at three levels); AP *tables* (PR 52523: mod_expires fields on redirects that cannot be removed) | COVERED | Rules with `endings`, `rules.cache`, and the static baseline's `no-cache` on HTML. |
| E2 | Long lifetimes kept off errors | Apache (the onsuccess default); HAProxy (`http-response` scope); Caddy (the documented example) | [medium] CTH *Caddy header* (the example); CTH *HAProxy after-response* (inference); AP *tables* (inference) | COVERED | A freshness-granting value is refused without `when = "success"`. |
| E3 | Cache fields on 304 | Apache misses them on core 304s | [medium] AP *tables* | COVERED | |
| E4 | Appending to an application's Cache-Control | nginx (`add_header Cache-Control` appends to the list); Apache `append`/`merge` | [medium] NG §1 (the special handler); AP *actions* (the merge example) | DECIDED-OUT (no append) | `set` replaces the application's `private`: M5. |
| E5 | A lifetime on redirects | Apache (`Header always` on a 301) | [medium] AP *301* (inference) | COVERED | `cache`. |

### F. Error pages and maintenance

| # | capability | servers that have it | evidence of use (file, section) | status in agensio | note |
|---|---|---|---|---|---|
| F1 | Custom error pages, served with their status | nginx `error_page`; Apache `ErrorDocument`; Caddy `handle_errors` (by status, `5xx`); Traefik `errors` middleware; HAProxy `errorfile`/`http-error`; OLS "Customized Error Pages"; IIS `httpErrors` | [strong] NG §6 (trac #1122, Drupal's `error_page 404 = /index.php`; changelog fixes in 1.13.6, 1.15.4, 1.23.0); AP *auth order* (ErrorDocument pitfalls); CTH *Caddy handle_errors*; CTH *Traefik headers* (#11957, PR #12858); CTH *HAProxy redirects* (`auth` uses `errorfile`/`http-error`); LHI *OLS headers* (VH General) | MISSING | Open (redirects.md 12.4). Today a `try_files` fallback to `/404.html` answers 200, a soft 404 (M8). See G1. |
| F2 | Replacing an application's error answers | nginx `proxy_intercept_errors`/`fastcgi_intercept_errors`; Apache `ProxyErrorOverride`; Traefik `errors` | [medium] NG §6; AP *tables* (ProxyErrorOverride with a 401); CTH *Traefik headers* (#11957) | MISSING | Part of G1, as an opt-in for 5xx only. |
| F3 | Which header rules an error page gets | nginx: the error location's rules; OLS: the error URL's context | [strong] NG §6 (inference from source); LHI *OLS headers* (inference) | COVERED | Rules match the client's path. |
| F4 | A maintenance 503 with Retry-After and an allow list | nginx `return 503`, Caddy `respond`/`error`, HAProxy `return`: generic tools; none of the four notes shows a typed form | [weak in the four notes]; `panels_and_site_owners.md` (outside the brief: Google wants a 503 with Retry-After for "a few days at most", robots.txt still served) | MISSING (planned: redirects.md 7, 9.4) | G7. |
| F5 | A fixed answer with a body (`return 200 "text"`, `respond`) | nginx, Caddy, HAProxy | [weak] NG §3; CTH *Caddy handle_errors* (the order list) | MISSING | Low. |

### G. Testing and debugging

| # | capability | servers that have it | evidence of use (file, section) | status in agensio | note |
|---|---|---|---|---|---|
| G1 | "Which rule fired", and linting | Apache rewrite trace (slows the server "dramatically"); Gixy for nginx | [medium] AP *mod_rewrite*; NG §1, §3 (Gixy's `add_header_redefinition` and `http_splitting`) | COVERED | `path_check` names the deciding rule for a redirect and for each field; `-t` gives the notes; `--explain`. |
| G2 | A preview before going live | None of the servers. Apache: test with 302 first | [strong] AP *301* ("While debugging redirect rules, use [R=302]") | COVERED (ahead of all) | `path_check` with proposed `redirects` or `response_headers`. |
| G3 | A live fetch through the whole stack, the application's own redirects included | None of the servers (the `curl -I` habit). cPanel warns that WordPress may defeat a redirect | [medium] LHI *OLS redirects* (cPanel: "third-party applications such as WordPress may make the redirect fail") | PARTIAL | `path_check` describes and does not fetch (built.md). Health probes only `GET /` (`app_redirects_elsewhere`, `response_headers_suggested`). G6. |
| G4 | Static checks: loops, chains, CRLF-safe targets | IIS `childOnly`; Gixy `http_splitting` | [strong] NG §3 (Gixy, Acunetix: `$uri` in Location); LHI *IIS redirects* | COVERED | Refused or noted at load; `fuzz_redirect`. |
| G5 | Rules from `.htaccess` and from panels | LiteSpeed Enterprise reads `.htaccess` mod_headers and rewrite rules; OLS reads only rewrite rules (after a restart); cPanel writes its Redirects into `.htaccess` | [strong] LHI *OLS headers* (LSWS reads Apache config and `.htaccess`); LHI *OLS redirects* (cPanel "places redirect rules at the bottom of the .htaccess file"; "on cPanel/LiteSpeed shared hosting, the practical mechanism ... is .htaccess") | MISSING | agensio never reads `.htaccess` when serving. The install scan only looks for whole-directory denials (`src/services/install.cpp` near 485 to 535, `src/control/handler.cpp:1336`). See M1 and G2. |

## 2. Pitfalls of other servers, and whether agensio avoids them

| # | pitfall (server) | evidence | agensio | verdict |
|---|---|---|---|---|
| P1 | A nested `add_header` drops every inherited field (nginx) | NG §1 (docs; Gixy check; `add_header_inherit` only in 1.29.3; Angie refuses it) | Per field, the most specific rule; a deeper rule changes only the fields it names (headers.md 2.2) | avoided |
| P2 | `add_header` skips 4xx and 5xx without `always`, application 404s included (nginx) | NG §6 (trac #1122 closed invalid; 2009 and 2011 list threads) | Every answer by default; `when = "success"` is the opt-in | avoided |
| P3 | `add_header` appends beside the upstream's copy, with special cases: Cache-Control and Link appended, ETag and Last-Modified replaced (nginx) | NG §1 (source; forum 676) | `set` replaces, `default` fills, one semantic for every field | avoided (but see M5 for the reverse surprise) |
| P4 | Two tables: `Header set` misses error pages, redirects, core 304s and PHP-FPM's fields, and duplicates FPM's fields (Apache) | AP *tables* (docs' FPM example, PR 64646, source) | One rule set acting on the final answer of every handler | avoided |
| P5 | `Header unset X-Powered-By` silently fails under PHP-FPM (Apache) | AP *Server* (Plesk KB) | `remove` and the baseline act on the application's fields | avoided |
| P6 | `<Location>` sections apply in file order, not by length (Apache) | AP *merging* | Order never matters | avoided |
| P7 | Redirect: the first match in file order wins, "list the most specific first" (Apache) | AP *mod_alias* | The longest `from` decides; a duplicate `from` is refused | avoided |
| P8 | mod_alias against mod_rewrite: order depends on context, and the docs contradict the source (Apache) | AP *alias/rewrite order* | One mechanism at one fixed point | avoided |
| P9 | The same Redirect falls behind auth when moved into `.htaccess` (Apache) | AP *auth order* | Always before access and password rules, with a load note | avoided; documented |
| P10 | The remainder is joined blindly: `/one/` to `http://x/two` gives `twoa` (Apache) | AP *mod_alias* (source reading) | Exactly one `/` at the join (configuration.md 14b) | avoided. Same as Apache: `from = "/one/"` does not cover `/one` (`src/core/redirect.hpp:213`). The MCP text says so; `-t` says nothing. |
| P11 | A silent default status, different on every server; two in one product (IIS) | LHI *summary*; CTH *summary* | Required | avoided |
| P12 | A 301 kept forever by browsers (Apache docs, cPanel's warning) | AP *301*; LHI *OLS redirects*; NG §4 | `Cache-Control: max-age=86400` by default on 301, 308, `http` and `canonical` | avoided |
| P13 | 301 and 302 turn POST into GET ("POSTs will be discarded") | AP *mod_alias*; CTH *Caddy redir*; NG §4 (RFC 9110 15.4) | 307 and 308 offered; the docs and MCP texts say to ask | mitigated (no load-time detection) |
| P14 | CRLF injection through `$uri` in a Location (nginx) | NG §3 (Gixy, Acunetix) | Location written byte by byte, re-encoded, fuzzed | avoided |
| P15 | Double decoding in `rewrite` (nginx trac #1460) | NG §3 | No rewrite; normalised once, then re-encoded | avoided |
| P16 | Heap overflows in rewrite and map regex captures (nginx 2026); `AllowAnyURI` CVEs (Apache) | NG §3; AP *mod_rewrite* | No regex | avoided |
| P17 | An absolute Location built from the local port or Host behind proxies (nginx `port_in_redirect`) | NG §3 | A target on the site stays relative; `canonical` keeps the port the Host names | avoided |
| P18 | Caddy's plain `header` duplicates the upstream's field; `>` or `defer` needed | CTH *Caddy header* (#6275, thread 8146) | `set` acts on the final answer | avoided |
| P19 | Deferred operations lost on error answers; policies written twice in `handle_errors` (Caddy) | CTH *Caddy handle_errors* (#6689) | Error answers take the same rules | avoided |
| P20 | Immediate sets: the general rule wins; deferred ones flip it (Caddy) | CTH *Caddy handle_errors* (sorting; thread 8146) | Deterministic per field | avoided |
| P21 | An inline `*.html` is parsed as a field name (Caddy) | CTH *Caddy header* (thread 13858) | A typed `endings` key | avoided |
| P22 | `redir` drops path and query unless `{uri}` is written (Caddy) | CTH *Caddy redir* | Both kept by default | avoided |
| P23 | `redir` sorts before `file_server`; a catch-all needs `route` for exceptions (Caddy) | CTH *Caddy redir* | Rules stand before locations, and no exemption exists | **not avoided**: the same trap, with no way out (B7, M2) |
| P24 | An entry-point middleware's field beats the router's (Traefik #12195) | CTH *Traefik headers* | The most specific path wins | avoided |
| P25 | Headers only on answers written downstream of the middleware (Traefik) | CTH *Traefik headers* (inference from source) | Fixed: every answer of the site | avoided |
| P26 | `PathPrefix(/products)` also matches `/products-for-sale` (Traefik) | CTH *Traefik redirects* | Whole segments, for redirects and header rules alike | avoided |
| P27 | redirectRegex sees the query; `$1x` means `${1x}`; HEAD gets 307/308 (Traefik) | CTH *Traefik redirects* | No regex; the query is handled by `query` | avoided |
| P28 | The `errors` middleware drops `WWW-Authenticate` (Traefik #11957) | CTH *Traefik headers* | No error-page step; agensio's 401 keeps its fields | n/a today; G1 must keep it so |
| P29 | `http-response` does not reach HAProxy's own redirects and errors; `http-after-response` needed | CTH *HAProxy after-response* | One scope | avoided |
| P30 | Frontend rules run after backend rules: the broader one wins (HAProxy) | CTH *HAProxy after-response* | The most specific wins | avoided |
| P31 | A `location` redirect drops the query unless `keep-query` (3.1+) (HAProxy) | CTH *HAProxy redirects* | Kept by default | avoided |
| P32 | No status gives a 302, or an internal rewrite for a `/` target (OLS) | LHI *OLS redirects* (source) | Required | avoided |
| P33 | Realm and Access settings on a Redirect context never take effect (OLS) | LHI *OLS redirects* (source reading) | Documented, with a load note | avoided |
| P34 | `Header` lines in `.htaccess` are silently ignored (OLS) | LHI *OLS headers* (OLS docs; CyberPanel KB) | agensio ignores `.htaccess` entirely and says nothing | **not avoided** (M1) |
| P35 | Only the longest path's block applies; siblings are not combined (h2o) | LHI *h2o headers* (source) | Per-field combination | avoided |
| P36 | `customHeaders` adds and cannot replace the application's field; `<remove>` removes a configuration entry, not a field (IIS) | LHI *IIS headers* | `set` and `remove` act on the answer | avoided |
| P37 | httpRedirect inherited into child folders loops (`childOnly`); `exactDestination` is a negatively named switch (IIS) | LHI *IIS redirects* | Loops refused; `remainder = "keep"` or `"drop"` | avoided |
| P38 | URL Rewrite has no 308 and defaults differ (IIS) | LHI *IIS redirects* | All four statuses, required | avoided |
| P39 | Distributed rules see a relative path with no leading `/`, and never the query (IIS) | LHI *IIS redirects* | An absolute `from`, query parameters in exact rules | avoided |
| P40 | `setifempty` against server-derived fields such as Content-Type (Apache) | AP *actions* | Representation fields are refused | avoided |
| P41 | `Server` cannot be removed (Apache, headers-more's hedging; nginx: commercial) | AP *Server*; NG §2 | `server_header = ""` | avoided. `remove = ["Server"]` is accepted with no effect and misreported by `path_check` (built.md): fix by refusing it with the pointer, as `set` does. |
| P42 | A long Cache-Control on 404 and 5xx answers (Caddy example, Apache's onsuccess rationale) | CTH *Caddy header*; AP *tables* | Refused without `when = "success"` | avoided |
| P43 | Error answers get the error location's rules, not the original path's (nginx `error_page`; OLS custom error URL) | NG §6; LHI *OLS headers* | Rules match the client's path | avoided; G1 must keep it so |
| P44 | A redirect inside a protected location answers without a password (nginx) | NG §3 (mailing list 2016, 2014) | Same order; noted at load | same behaviour, but announced |
| P45 | Matching case: nginx `map` and Caddy ignore case, nginx `location` and Apache do not | NG §3; CTH *Caddy handle_errors*; AP *mod_alias* | Redirects case-sensitive; header, access and refuse rules case-insensitive | a deliberate choice; differs from Caddy and `map` (M3) |

## 3. Migration risks

Each row is a case where an administrator coming from the named server would reasonably expect
other behaviour, and where the difference can break a site **without any load error, note or
health finding**. Severity weighs how common the source setup is in the notes against the damage.

| # | coming from | what they expect | what agensio does | how it breaks | evidence | severity | fix |
|---|---|---|---|---|---|---|---|
| M1 | cPanel or Plesk on Apache or LiteSpeed; OLS sites with Apache files | Their `.htaccess` `Redirect`, `RewriteRule ... [R=301]` and `Header set` lines keep working: on these hosts that is where the panel and the user put them | `.htaccess` is never read when serving. The install scan looks only for whole-directory denials. No finding names the ignored lines | Every redirect the owner or the panel made becomes a 404 (or the front controller's page), and the security fields set there disappear, with nothing said | LHI *OLS redirects* (cPanel writes its Redirects into `.htaccess`; "the practical mechanism for both headers and redirects is .htaccess"); LHI *OLS headers* (LSWS reads `.htaccess` mod_headers; even OLS users are told to move Header lines); `src/services/install.cpp` 485-535 | high, for any shared-hosting migration | G2 |
| M2 | nginx, h2o, Caddy | `location / { return 301 https://new$request_uri; }` beside `location /api/ { proxy_pass ...; }` (or h2o's `/` redirected with `/rss` served) leaves `/api/` working | A `[[site.redirect]] from = "/"` answers before the locations (14b, "Where rules stand"), and no load note names a location the rule covers | API clients, webhooks and feeds are sent to the new host. With 301, their POSTs become GETs | NG §3 (return runs in the location's rewrite phase), NG §5 (location selection); LHI *h2o redirect* (the docs' example); CTH *Caddy redir* (the `route` workaround) | medium-high | G3 |
| M3 | Caddy; nginx bulk lists built on `map`; HAProxy lists with `path,lower` | A rule for `/old-page` also takes `/Old-Page` | Case-sensitive. redirects.md 5.1 says "as on every hosting platform", but these servers ignore case | Inbound links with another capitalisation 404 instead of redirecting | NG §3 ("Strings are matched ignoring the case"); CTH *Caddy handle_errors* ("exact but case-insensitive"); CTH *HAProxy redirects* (the field config) | low-medium | G8; the MCP redirect text should name Caddy and `map` as case-insensitive sources |
| M4 | Traefik with its `headers` CORS options | Preflights are answered by the proxy; the backend never sees OPTIONS | Static locations answer OPTIONS; PHP and proxied applications receive the preflight (`src/handlers/dispatch.cpp:703`), and the rules only add ACAO to whatever the application answers | A backend that answers OPTIONS with 404 or 405 fails every browser preflight. Cross-origin calls stop; same-origin pages and `curl` look fine | CTH *Traefik headers* ("does not pass preflight requests to any service") | medium, for proxied APIs | G5 |
| M5 | nginx `add_header Cache-Control ...`; Apache `Header append`/`merge` | The rule's value is added beside the application's (nginx appends Cache-Control to the list), so an application's `private` or `no-store` still reaches caches | `set` replaces every copy, the application's included. `when = "success"` is the only check (`src/config.cpp` near line 1556); only `[[site.auth]]` paths keep `private` | Translated one to one, a `set` of `public, max-age=...` over an application's paths makes personalised answers storable by shared caches and CDNs | NG §1 (Cache-Control appended by `ngx_http_add_multi_header_lines`); AP *actions* (the `merge` example); configuration.md 14c (`set` replaces) | medium (data exposure) | Never let a rule's freshness-granting `set` replace an application's `private` or `no-store` (keep them, as the auth guard does), or note at load any such `set` that covers application answers and suggest `default`; `path_check` shows it |
| M6 | Apache `Redirect`; OLS Redirect context | `Redirect /old /new?src=old` sends `/new?src=old`: the client's query is dropped when the target has its own | The client's query follows after `&` (redirects.md 5.3) | Duplicated or conflicting parameters reach the target (`?lang=` twice); usually harmless | AP *mod_alias* (source: query appended only "if the config didn't supply its own"); LHI *OLS redirects* (`memchr(pDestURI, '?')`) | low | The MCP import text: Apache and OLS rules whose target holds `?` translate with `query = "drop"` |
| M7 | nginx | `location /app/ { proxy_pass ...; }` answers `/app` with a 301 to `/app/` | No automatic redirect: `/app` goes to another location (`src/core/router.hpp:46`), the main application's page or a 404, with no note | Visitors and bookmarks without the slash miss the sub-path application | NG §3 (the core `location` doc); redirects.md 12.2.5 (Grafana, BookStack and Jellyfin need the exact rule) | low-medium | A `-t` note on a proxy or FastCGI prefix location ending in `/` when no exact rule covers the bare path, or the 308 added at load as nginx does |
| M8 | nginx `error_page 404 /404.html`; Apache `ErrorDocument`; OLS custom pages | The page is shown with status 404 | There are no error pages; the one way to show the page is a `try_files` fallback, which answers 200 | Search engines index missing addresses; monitors and link checkers see 200 | NG §6; AP *auth order*; redirects.md 12.4 (agensio's own statement of the soft 404) | medium | G1, and a `-t` or health note when `try_files` ends in a name like `/404.html` |

Silent weakening rather than breakage, for completeness:

- **W1.** nginx and IIS add a server CSP beside the application's, so browsers enforce both: the
  intersection is stricter (NG §1, generic `add_header` appends; LHI *IIS headers*, customHeaders
  "added", duplicates UNVERIFIED there).
- In agensio, `default` keeps only the application's policy, and `set` replaces it (the `set` is
  noted at load).
- A migrated site that relied on the second policy loses the narrowing, and nothing says so. "A
  second, narrowing CSP" is listed for later (headers.md 11.3); until then the MCP text could say
  that an nginx `add_header Content-Security-Policy` over an application's own policy has no
  equivalent here.

## 4. Top gaps

Ordered by evidence of use. Each fix follows agensio's style: typed site keys, fixed values, no
regex, a cost only on sites that use it, and managed through `site_update`, `agensio ctl` and
`path_check`.

1. **Error pages with their status (F1, F2, M8).** All seven servers with an error-page feature
   have one, and the issue trackers are full of it (NG §6, CTH *Caddy handle_errors*, CTH
   *Traefik headers* #11957).
   - Site key `error_pages = { 404 = "/404.html", 410 = "/gone.html", 503 = "/busy.html" }`: a
     status (403, 404, 410, 5xx; never 401, which keeps the prompt, AP *auth order*) mapped to a file
     of the root.
   - The file is served as a static file is: a cached entry, never run, no `try_files`, no PHP, no
     proxy, as the validation paths are served today. It keeps the status, takes the client path's
     header rules, and goes out with `no-store`.
   - Opt-in `intercept = [502, 503, 504]` for an application's own 5xx; never its 4xx, whose pages
     carry content.
   - `-t` warns when a file is missing. Health notes a soft 404 (a `try_files` ending in
     `/404.html`).
   - Managed: `site_update error_pages`, `agensio ctl site-update NAME --error-page
     404=/404.html`. `path_check` says "404, page /404.html".
   - Cost: only on error answers of sites that set it.
2. **`.htaccess` rules found and named (G5, M1).**
   - A read-only scan, at `site_install` (in `facts`) and by health for trees that hold
     `.htaccess` files, bounded like the existing deny-all reader.
   - It lists `Redirect*`, `RedirectMatch`, `RewriteRule` lines with `[R`, `Header` and
     `ErrorDocument`, as file:line with a count, under a finding `htaccess_rules_ignored` (warn
     when there are redirects).
   - The MCP text tells the agent how to translate:
     - Redirect is a whole-segment prefix that keeps the rest; it has a 302 default, so ask the
       status.
     - A target with `?` takes `query = "drop"` (M6).
     - `Header set` → `set`, `setifempty` → `default`, `unset` → `remove`.
     - `always` is implied.
     - Preview everything with `path_check` `redirects` and `response_headers`.
   - Never read on a request.
3. **"Not redirected here" (B7, M2, P23).**
   - A redirect rule with `serve = true` and no `to` or `status`: the path (prefix or exact) and
     below are not redirected. The most specific rule decides, as now; it is one more entry in the
     same index, so a request pays nothing new.
   - Refused when no redirect rule covers it.
   - A load note (and `redirect_notes`) when a redirect covers a hand-written location or a PHP or
     proxied location's path: "rule / (301) answers before location /api/ (proxy); add a serve rule
     if it should stay".
   - `ctl --redirect-keep /api/`; `path_check` names it.
4. **Lists beyond 1,000 rules (B8).** HAProxy's field data shows 100k-entry maps at negligible cost,
   and IIS documents rewrite maps for large sets.
   - A per-site data file (`redirects_file`, JSON or TSV of `from to status`), written by the
     control plane when `--redirects-file` exceeds the inline limit.
   - Judged by the same `load_redirect_rules` parse and checks, loaded at reload into the same hash
     and prefix index, with a cap around 100,000. The cycle check stays a walk over the rules.
   - Request cost unchanged; memory only for sites that use it.
5. **Preflights for applications (D3, M4).**
   - A typed site key `cors = { path = "/api/", origin = "https://app.example.com", methods =
     ["GET", "POST"], headers = ["Content-Type", "Authorization"], credentials = false, max_age =
     "10m" }`.
   - agensio answers a preflight (OPTIONS with `Origin` and `Access-Control-Request-Method`) under
     that path with a 204 and the fixed fields, without reaching the application, and adds ACAO to
     the actual answers.
   - One origin at first, consistent with today's single-ACAO rule. The several-origins list stays
     decided out until a case asks (D2); the Traefik migration is the case for preflights.
   - Cost: one test on OPTIONS requests of sites that set it.
6. **A live redirect check (G3).**
   - `path_check` with `fetch: true`, or a `redirect_check` tool and `agensio ctl redirect-check
     NAME --url ... --file old-urls.txt`.
   - Run over loopback off the workers, as health's probes and `fetch_heads` already are: each URL
     followed for up to 10 hops.
   - Reported per hop: status, Location, cache lifetime, and who answered (scheme, canonical, a
     rule, or the application).
   - A verdict per URL: one hop to a 200, a chain, a loop, or the application redirecting after
     agensio's rule (the cPanel warning in LHI *OLS redirects*). Capped, with bounded parallelism.
   - Nothing on the request path.
7. **Maintenance (F4).** Already planned (redirects.md 7, 9.4).
   - `maintenance = { until = "2026-10-20T06:00:00Z", allow = ["@office"], page = "/maintenance.html"
     }`: a 503 with `Retry-After` (to `until`, capped) and `no-store`.
   - `robots.txt` and the validation paths still answer; the `allow` set sees the site.
   - Health `maintenance_long` past a few days (Google's guidance in `panels_and_site_owners.md`,
     outside the brief).
   - `site_update maintenance`, `agensio ctl site-update NAME --maintenance-until 2h --allow
     @office`.
   - One flag in `before_routing`, set only during maintenance.
8. **Case-insensitive rules as an opt-in (B23, M3).**
   - `case = "any"` on a rule, for lists imported from Caddy or an nginx `map`. Exact rules of that
     kind go in a second hash keyed by the lowered path, prefixes are compared lowered, and the
     duplicate and cycle checks compare lowered.
   - Only sites with such rules pay the lowering.
   - The MCP import text names the sources that ignore case and tells the agent to ask.
9. **No rule loosens an application's `private` (M5).**
   - A rule's `set` of a freshness-granting `Cache-Control` (or a shared-cache field) leaves an
     answer whose application said `private` or `no-store` as the application sent it, the way the
     `[[site.auth]]` guard keeps `private`.
   - Noted at load when such a `set` covers application answers, with `default` suggested.
     `path_check` lists the exception.
   - Cost: one look at the application's Cache-Control on answers that rule covers.
10. **Cookie attributes (C19, C6).**
    - `cookies = { secure = true, samesite = "lax", httponly = false }`: adds a missing attribute
      to each `Set-Cookie` of an application's HTTPS answer; never removes or rewrites one.
    - `secure` is refused with `http = "serve"`, where plain-HTTP sessions would break.
    - Evidence: LiteSpeed built `ForceSecureCookie` because `Header always edit Set-Cookie` was the
      habit it could not support (LHI *OLS headers*).
    - Cost: only on answers that carry `Set-Cookie`, on sites with the key.

Smaller items:
- **M7:** a `-t` note, or an automatic 308, for a proxied prefix ending in `/`.
- **P41:** refuse `remove = ["Server"]` with the `server_header` pointer.
- **C11:** a `keep` verb ("no rule's value; the answer's own copy stands").
- **C18:** a host-wide `[response_headers]` default for many-site hosts.
- **A6:** preload only for already-listed domains.

The notes give weaker evidence for all of these.
