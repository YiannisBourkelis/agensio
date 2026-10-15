# Redirects, HSTS and response headers: administrators' needs against agensio (alpha.94)

Sources, abbreviated in the table:

- **[R]** `reports/Web server headers and redirects.md`
- **[AC n]** `research_notes/Web server headers and redirects/admin_complaints.md`, section n
- **[PS n]** `research_notes/Web server headers and redirects/panels_and_site_owners.md`, section n
- **[SS]** `research_notes/Web server headers and redirects/standards_security.md`, named section

Stack Exchange numbers are given as "score / views", as in the notes. "Search summary" means the notes
could only read a search engine's summary of the page. What agensio does comes from `built.md`,
`docs/redirects.md`, `docs/headers.md`, `docs/configuration.md` 14 to 14c, and, where they were unclear,
the source: `src/handlers/static.cpp` (`redirect_slash`), `src/handlers/dispatch.cpp`,
`src/config.cpp` (`cors_origin`, `parse_response_headers`), `src/control/sites.cpp`, `src/control/mcp.cpp`.

## 1. Needs, complaints and requirements

### A. How response header rules behave

| # | Need or complaint | Evidence | Status | What agensio does / what is missing |
|---|---|---|---|---|
| 1 | A site-wide field must not vanish because a deeper block sets fields of its own (nginx `add_header` inheritance) | [AC 1]: SO 18450310 (90 / 176,126), SF 400197 (23,841), SF 859626, SF 670609, Arch Linux MR 859 "missing HSTS", gixy has a check for this trap alone; [R] "Headers that vanish". The most reported header problem | COVERED | For each field, the most specific rule that names it decides. A deeper rule changes only the fields it names (headers.md 2.2) |
| 2 | Fields must not depend on which internal location answered (`try_files` into PHP, `error_page`) | [AC 1] SO 18450310 second cause, SF 785251 (7,490); [R] conclusion: "they attach header operations to wherever the request ends up" | COVERED | Rules match the path the client asked for, normalised once, never an internal target |
| 3 | Security fields on error answers too (nginx `always`) | [AC 1] SF 418709 (18,351; the 73-vote answer is "use always"), nginx trac #1122 closed invalid, MDN's examples use `always` without explaining it; [R] row 1 | COVERED | Applied to every answer: files, PHP, CGI, proxied, agensio's 404/403/405/413/502/504, 401, redirects, OPTIONS, 304. Not applied before routing (400/421/431), the same exception h2o makes |
| 4 | Replace the application's field instead of adding a second copy | [AC 1] SF 928912 (42 / 160,154), SF 751678 (46,562), Apache's own FPM example, DirectAdmin thread; [R] "Duplicates" | COVERED | `set` deletes every copy and sends one; names compared in any case (the Netlify case-sensitivity trap, [AC 1]) |
| 5 | An "only if absent" verb, so the application's own value wins | [R] summary: only Apache, Caddy and h2o have one; [PS 1] inference; [SS] multi-tenant: "`default` is the safe verb" | COVERED | `default`, judged after the application's and agensio's own fields |
| 6 | Remove a field from every answer, the application's included | [AC 5]; [PS 1] WP Engine "Unset", Cloudflare "Remove" | COVERED | `remove`, any name but the framing and representation fields (but see Contradictions 2 and 3) |
| 7 | Cache lifetimes must NOT go on errors | [AC 1, 4] Caddy 26158 (Kirby: a year-long `immutable` on 404s); [PS 1] WP Engine "Only on successes / All responses"; RFC 9110: 404 is heuristically cacheable | COVERED | `when = "success"`; a freshness-granting Cache-Control or Expires is refused without it |
| 8 | Rule order must not matter; the more specific rule must win | [R] Apache `<Location>` file order, Caddy's sorting, Traefik #12195; [PS 2] Netlify, Kinsta and WP Engine all document first-match-wins | COVERED | Specificity only; the MCP texts and ctl help say so to agents used to first-match |
| 9 | Sibling prefixes combine (h2o applies only the single longest `paths:` entry) | [R] h2o paragraph | COVERED | Rules naming different fields all apply |
| 10 | Server-owned names refused, with the reason and the setting to use | [PS 1] inference (Netlify, WP Engine, Cloudflare deny-lists); [SS] refuse table; [R] row 12 | COVERED | headers.md 2.5: framing, representation, Location/Refresh, Server, Alt-Svc, Set-Cookie, Clear-Site-Data, Service-Worker-Allowed, password fields, HPKP/Expect-CT, STS in set/default; each refusal names the setting to use |
| 11 | Append or merge list fields (`Vary: Origin`, a second `Link`, a second narrowing CSP) | [AC 1] a Traefik user could not add a second CSP, Traefik PR 6893 closed; [SS] "Vary: allow append only"; [R] L4 | DECIDED-OUT | `merge`/`append` decided out; a second, narrowing CSP left for later (headers.md 11.3). The evidence is one forum user and spec reasoning: no reason to revisit |
| 12 | Notice when the application itself sends a singleton security field twice | [AC 1] proposal check; [R] L7; HestiaCP/Seckit, Roots (`SAMEORIGIN, SAMEORIGIN` in Safari), DigitalOcean (Chrome fell back to DENY and broke WordPress admin, search summary) | MISSING | Health "later" (headers.md 7). A `set` rule fixes it once someone knows; nothing tells them |
| 13 | Header rule paths match any capitalisation | [R] "Case handling": "clearly right for headers, where missing a spelling weakens a protection" | COVERED | Header and access rules ignore case; redirects do not (row 69) |
| 14 | Per-site settings survive panel rebuilds; one place to set a field | [AC 7] cPanel files "rebuilt every few days", HestiaCP "overwritten", Plesk directives overwrite (search summaries) | COVERED | The managed file is rendered from the spec; root additions persist; a rule overrides a location's `add_headers` |
| 15 | A host-wide default that is not lost when a site customises | [AC 7] inference ("any future server-wide header default: make it a `default`"); Plesk's host-wide `conf.d` | MISSING | Per-site rules only; the per-preset baseline is the nearest thing. Weak evidence |
| 16 | One mechanism, not two (retire location-bound `add_headers`) | [R] conclusion and L10 (Apache: "choose one module for a given task") | PARTIAL | `add_headers` stays, success-only and bound to its location (the nginx trap) for presets and hand-written files; no longer advertised; retiring it is "later" |

### B. Security headers and HSTS

| # | Need or complaint | Evidence | Status | What agensio does / what is missing |
|---|---|---|---|---|
| 17 | HSTS never over plain HTTP | [AC 2] SO 24144552 (97 / 100,387); [SS] RFC 6797 7.2 MUST NOT | COVERED | Never over plain HTTP or h2c |
| 18 | One HSTS line when the panel and the application both send one | [AC 1] Netlify 28179, HestiaCP 12283, F5 (search summary); [PS 1, 3] Plesk "HSTS appearing twice"; RFC 6797 8.1 | COVERED | `hsts` replaces the application's own |
| 19 | HSTS on every HTTPS answer, PHP pages, errors and HTTPS redirects included (a preload requirement) | [R] alpha.72 finding (managed `hsts` missed PHP pages and 404s); [SS] hstspreload: "Any redirect served from the HTTPS site must also carry the HSTS header" | COVERED | Fixed in alpha.75; HSTS goes on redirects over HTTPS too |
| 20 | Undoing HSTS: send `max-age=0` for a while instead of just stopping, and propose it when HSTS is turned off | [AC 2] SF 1011861 (14,958: removing the header "doesn't remove the policy from the cache"), SF 890858 (5,286), SO 33268264 (280 / 329,630); RFC 6797 6.1.1; [R] L2: "`max-age=0` proposed on removal". [R] calls HSTS "the field administrators most regret" | PARTIAL | A site file can say `hsts = { max_age = 0 }` (redirects.md 4.5). The managed field is a boolean: `true` is a year, `false` sends nothing. A managed site cannot send `max_age = 0`, and no tool proposes it (Contradiction 4) |
| 21 | Ramp HSTS up (five minutes, a week, a month), or at least warn when the first value is a year | [AC 2] hstspreload's ramp ("wait the full max-age of the stage before you move on"); [R] L2 | PARTIAL | `hsts_suggested` waits for 7 days on a real certificate with no finding, and certificate findings become errors under HSTS, but `hsts = true` commits a year at once. A managed site has no shorter value |
| 22 | `includeSubDomains`: warn, naming the subdomains it would cut off | [SS] HSTS inference (sibling tenants); [AC 2] Chromium removal CLs ("added by mistake", subdomains CNAMEd to third-party services, search summary); RFC 6797 14.5 | COVERED | `-t` and health list this server's sites it binds and warn about those without TLS. Subdomains hosted elsewhere cannot be seen; the reference text says so. Not offered on managed sites at all (safer) |
| 23 | A preload option | [PS 1, 3] Plesk SSL It! has no preload, so users add it by hand (search summary); [AC 2] Web Almanac: `preload` on 18 % of HSTS responses; OWASP cheat sheet includes it; hstspreload: "not include the preload directive by default", removal "takes months"; [R] L2: preload behind `user_confirm` | DECIDED-OUT | Not offered (redirects.md 4.6). An STS rule is refused, and `hsts` replaces an application's own, so only an application's own `preload` survives, and only with no `hsts` line. The evidence shows real minority demand; it supports offering preload only behind an in-person confirmation, not forbidding it. Low urgency |
| 24 | The server must not silently weaken a stronger application HSTS | [R] row 14 (the panel's value should replace the application's) | COVERED | Replaces it, notes it, health `hsts_narrows_application` names the application's value |
| 25 | Certificate trouble is fatal under HSTS (no click-through) | [AC 2] SF 890858, SO 33268264 | COVERED | `certificate_expiring` and `acme_renewal_failed` become errors with `hsts` |
| 26 | CSP: start with report-only; the server must not loosen the application's policy | [AC 2] SO 31211359 (258 / 1,087,437), SO 37298608 (580,405), SO 17766817 (374,207); Web Almanac: 91 % of policies keep `unsafe-inline`; [SS] CSP3 8.1 | COVERED | The agent offers `Content-Security-Policy-Report-Only` first, then `default`; a `set` CSP on an application site gets a load note |
| 27 | X-Frame-Options: only DENY or SAMEORIGIN, a per-path exception, no conflicting duplicates | [AC 2] SO 20498831 (372 / 1,246,505), SO 10205192 (279,712), SO 28647136 (224,052); ALLOW-FROM on 0.6 % of hosts; [SS] table | COVERED | Value checked; a deeper `remove` plus `frame-ancestors` (headers.md 3.2); `set` replaces. Not in the baseline (breaks embeds), offered by the agent |
| 28 | Set security fields once per site, because scanners ask for them | [AC 2] securityheaders.com (250 M scans), MDN Observatory rescoring in 2024; [R] "Scanners drive most of this work" | COVERED | Rules at `/`, the per-preset baseline, health `response_headers_suggested`, `path_check`'s `response_headers_offer`, and refusals recorded in `response_headers_offer_declined` |
| 29 | A maintained list of deprecated fields and values | [AC 2] inference (X-XSS-Protection dropped in 2019, Feature-Policy renamed, Observatory rescored); [SS] OWASP: Expect-CT and HPKP "Do not use" | PARTIAL | X-XSS-Protection other than `0` is warned; Expect-CT and HPKP refused. `Feature-Policy` (now Permissions-Policy) is accepted with no note |
| 30 | Do not invite copying OWASP's "add" list site-wide (`Clear-Site-Data`, `Cache-Control: no-store`, COEP `require-corp`, COOP `same-origin`) | [SS] OWASP inference ("would log every visitor out and defeat caching"; COEP/COOP "break cross-origin embeds and OAuth popups"); [SS] warn table; [R] "Copy-pasting either list site-wide is a mistake" | PARTIAL | Clear-Site-Data refused. `no-store` at `/` and COEP/COOP are accepted with no note |
| 31 | Fields that reach other tenants refused (Set-Cookie with a parent Domain, Clear-Site-Data, Alt-Svc, Service-Worker-Allowed) | [SS] multi-tenant section (RFC 6265 8.6, Clear Site Data, RFC 7838 9, SW 6.5); [R] | COVERED | All refused in rules |
| 32 | Typed cookie flags (Secure, HttpOnly, SameSite) on application cookies | [AC 1] SF 1043924 (12,235); [R] L9 (LiteSpeed `ForceSecureCookie`) | DECIDED-OUT | "A typed setting later if a real case needs it" (headers.md 3.8). The evidence is thin; no reason to revisit |

### C. CORS

| # | Need or complaint | Evidence | Status | What agensio does / what is missing |
|---|---|---|---|---|
| 33 | No duplicate `Access-Control-Allow-Origin` ("contains multiple values", `*, *`) when the framework and the server both set it | [AC 3] SO 22343384 (157 / 474,030), SO 29524036 (88,580), nginx, Laravel and Spring variants; Plesk KB "three places" (search summary) | COVERED | `set` replaces the application's |
| 34 | ACAO is one value; `*` never with credentials | [SS] Fetch 3.3.4 and 3.3.5; [AC 3] MDN | COVERED | One origin, `*` or `null`; `*` together with `Allow-Credentials: true` refused |
| 35 | Avoid the `null` origin ("any origin can create a hostile document with a null origin") | [AC 3] MDN; [SS] CORS inference "warn on null"; [R] L1 "no `null`" | PARTIAL | Accepted with no note, and `null` together with `Allow-Credentials: true` is not refused (Contradiction 5) |
| 36 | Several allowed origins: echo the matching `Origin` and add `Vary: Origin` | [AC 3] SO 1653308 (1,433 / 1,304,026), SO 25309318 (85,861); MDN: the server "must return the origin for the specific client"; [SS] Fetch "CORS protocol and HTTP caches"; [R] L1 | DECIDED-OUT | A typed `cors` setting "later, when a real case asks" (headers.md 10.5). agensio's own review found no application configuration that needs it, but this is the second-largest question in the whole evidence (Top gap 6) |
| 37 | A preflight must get an ok status with the headers, even where the location would give 405 or ask for a password | [AC 3] SO 35588699 (741 / 2,566,021, the largest question in the evidence), SO 53298478 (763,938), SO 57901808, SO 67860273, SO 79856763 (2025); secondary guidance (search summary): answer preflights before `auth_basic`, since they carry no credentials; [SS] Fetch 3.3.3 | PARTIAL | Static locations answer OPTIONS with 204 + Allow, and rules apply to it, so a fixed ACAO/Allow-Methods rule works for files. PHP and proxied paths hand OPTIONS to the application. On a `[[site.auth]]` path the preflight, which carries no credentials, gets 401 (`dispatch.cpp`: auth runs before the OPTIONS answer) |
| 38 | CORS per path or per file type (web fonts for another origin) | [AC 3] SF 186965 (63,730), SF 785251 | COVERED | Path rules and `endings = ["woff2", ...]` |

### D. Caching, staging and indexing

| # | Need or complaint | Evidence | Status | What agensio does / what is missing |
|---|---|---|---|---|
| 39 | Long `immutable` lifetimes only for content-hashed assets, short or `no-cache` for HTML | [AC 4] SF 269420 (97 / 115,867), SO 19002567 (45,061); [R] | COVERED | `when = "success"` rules, `rules.cache` with `immutable`, the static baseline's `no-cache` on HTML, `hashed_headers` for Django's `/static/` |
| 40 | A staging `X-Robots-Tag: noindex` scoped to the staging host | [PS 1] Vercel "use host-scoped X-Robots-Tag: noindex"; [PS 3] GeoRadar, Polemic Digital (search summaries); [AC 4] pagecrawl.io (vendor, unverified), stackharbor, TYPO3's environment extension; [R] "Fifth" owner need | PARTIAL | A `/` rule in the staging site's own block is host-scoped by construction (headers.md 3.4); the MCP texts say noindex belongs on staging only. No staging flag (row 42) |
| 41 | Warn when a live site serves `noindex` (the launch mistake: "can deindex an entire site", found only as lost traffic days later) | [AC 4] proposal check; [PS 3] inference; [R] L7 | MISSING | Health "later" (headers.md 7) |
| 42 | A typed `staging` flag implying noindex, shown in `site_show`, removed with one field | [AC 4] proposal check | MISSING | Not built; the rule is a free-form field the agent must remember to delete |
| 43 | noindex as a header, not a robots.txt block (robots.txt hides the noindex from Google) | [PS 4] Google "Block indexing"; [PS 3] Polemic Digital | COVERED | The rule form is the header; the MCP text points to it |

### E. Fields that disclose software

| # | Need or complaint | Evidence | Status | What agensio does / what is missing |
|---|---|---|---|---|
| 44 | Remove `X-Powered-By` without editing php.ini or the framework | [AC 5] SO 2661799 (179 / 160,163), SO 10717685 (124,092), SO 2318806 (76,996), SO 962230 (67,633); OWASP removal list | COVERED | The baseline removes it from application answers; managed pools set `expose_php = off` |
| 45 | Neutralise or remove `Server` without rebuilding the server | [AC 5] SF 991045 (44 / 176,730), SO 52452194 (63,784), SO 55722738 (22,621); OWASP "remove or set non-informative values"; RFC 9110 17.12 | COVERED | `[server] server_header` (`""` sends none), reload; the default is `agensio` with no version. See Contradiction 3 for `remove = ["Server"]` |
| 46 | Remove the other disclosure fields (`X-Generator`, `X-Redirect-By`, `X-AspNet-Version`, ...) | [SS] OWASP `headers_remove.json` (about 90 names) | PARTIAL | Possible with a `remove` rule; only `X-Powered-By` is removed by default. Decided: `X-Generator` stays unless a rule removes it (headers.md 10.4) |

### F. HTTPS, canonical names, proxies and CDNs

| # | Need or complaint | Evidence | Status | What agensio does / what is missing |
|---|---|---|---|---|
| 47 | HTTP to HTTPS for every name, keeping subdomain, path and query | [AC 6] SF 67316 (557 / 634,175, the most-voted SF rewrite question); [PS 1] cPanel "Force HTTPS", Plesk "SEO-safe 301" | COVERED | `http = "redirect"` by default on a TLS site on 443: one block, a 308, a day's cache, ACME and pki-validation answered first |
| 48 | Force HTTPS in one layer only; no loop behind a CDN or load balancer | [AC 6] SO 46413494 (29 / 77,012; the 113-vote answer is "In my case it was Cloudflare"), SF 653976 (22,713), Cloudflare's own troubleshooting page, SF 304621 (37,222, ELB), SO 42715718 (32,948), SO 26620670 (52,370); [PS 3] cPanel forced HTTPS plus an SSL plugin | PARTIAL | Behind `trusted_proxies`, X-Forwarded-Proto decides, so there is no loop, and `proxy_scheme_missing` names a trusted proxy that sends no X-Forwarded-Proto. Nothing detects the commonest case: a CDN that is not in `trusted_proxies`, whose `X-Forwarded-Proto: https` is ignored, so every request is redirected (Top gap 2) |
| 49 | Application-side loops (Rails `force_ssl`, Laravel, WordPress HTTPS plugins, multisite) | [AC 6] SO 9448168 (20,356), SO 46435866 (25,559), SO 28518723 (18,953), SO 77635105 (2023) | COVERED | PHP gets `HTTPS=on`; proxied applications get X-Forwarded-Proto; an application's `http://` Location naming the site is upgraded; docs tell each preset to drop its own force-HTTPS; `app_redirects_elsewhere` for `canonical` |
| 50 | www or bare domain in one setting, since serving both splits rankings | [PS 1] Plesk "Preferred domain" (None: "search engines will treat both URL versions ... as URLs of different sites", search snippet), cPanel www options, ISPConfig "SEO Redirect" | PARTIAL | `canonical` does it in one hop and the MCP text says to ask the user. Nothing suggests it for a site that lists both `example.com` and `www.example.com` without one (Top gap 9) |
| 51 | HTTP to HTTPS on the same host first, then to the other name (HSTS and preload) | [SS] hstspreload "on the same host"; [AC 6] SF 930368 "HSTS and double redirect" | COVERED | With `hsts`, the same name's HTTPS first (redirects.md 4.3); one hop otherwise |
| 52 | The administrator's chosen status must hold on `http://` (HestiaCP's hard-coded 301 overrode a chosen 302) | [PS 1] HestiaCP forum | COVERED | A path rule's status is used in the one hop from plain HTTP |
| 53 | 308 support in old clients | [SS] RFC 9110 15.4.9: 308 "might not be recognized everywhere"; a client that does not know it treats it as 300 | COVERED (low risk) | `http` and `canonical` redirects are always 308, with no 301 option. The evidence names the risk but no reported failure |
| 54 | Redirect Locations must not leak an internal host or port behind a proxy (`absolute_redirect off`) | [AC 6] SO 15555428 (113 / 83,074) | COVERED | Path targets and the directory slash redirect are relative; `http`/`canonical` name the site's own spelling of the name |
| 55 | A Host header chosen by the client must not be cached into a redirect | [SS] Location inference (catch-all sites) | COVERED | A name only a catch-all took is redirected with `Cache-Control: no-store` |

### G. Path redirects

| # | Need or complaint | Evidence | Status | What agensio does / what is missing |
|---|---|---|---|---|
| 56 | No silent default status | [R] defaults table (302, 301, 307/308, by method); [PS 2]; [SS] RFC 9110 inference "Required status is the right call" | COVERED | `status` is required (301, 302, 307, 308, 410) |
| 57 | Test with 302/307, then go permanent | [AC 6] Linode, Vivaldi, HackerNoon threads; [PS 3] Forge ("bad practice to change a permanent redirect"), cPanel, stackharbor; [PS 4] inference | COVERED | MCP and ctl texts say so; preview through `path_check` |
| 58 | A mistaken permanent redirect must not stay in browsers forever | [SS] Chromium `TimeDelta::Max()`, WebKit a year, Firefox revalidates since April 2025; [AC 6] SO 9130422 (550 / 335,479), SO 16154672 (39,593); [R] row 17 | COVERED | `cache = "1d"` by default on 301/308 rules, `http` and `canonical`. Not on the static handler's directory slash 301 (Contradiction 1) |
| 59 | Warn when a permanent rule's target is changed (cached-301 hazard) | [PS 3] inference; Forge's warning | MISSING | No such note; the one-day default defuses most of it |
| 60 | 307/308 for paths that take a POST (301/302 turn POST into GET) | [SS] RFC 9110 15.4.2, Fetch 4.5; [AC 6] SO 13628831 (55,866), Apache "POSTs will be discarded" | PARTIAL | Docs and MCP text say so. No load note for a 301/302 over a path the preset knows takes POST (`wp-login.php`, `xmlrpc.php`, entry points) |
| 61 | 303 | [SS] inference "low-priority addition"; [PS 2] DirectAdmin and Vercel offer it | DECIDED-OUT | "An application's answer after a POST" (redirects.md 5.4). The evidence agrees it is low priority |
| 62 | Keep the rest of the path, on whole segments only (`/old` never takes `/oldies`) | [PS 1] cPanel "Wild Card Redirect"; [AC 6] Apache "Only complete path segments"; [R] Traefik `/products-for-sale`, Kinsta's anchoring | COVERED | Prefix rules on whole segments, `remainder = keep/drop` |
| 63 | The query kept, droppable, never doubled | [AC 6] SO 21118511 (72,212), nginx's `?` rule; [PS 2] defaults split (Netlify keeps, Cloudflare/Vercel bulk drop) | COVERED | `query = keep/drop`; a `to` with its own query gets the client's after `&` |
| 64 | Old query-string addresses as sources (`/?p=123`), which Kinsta and WP Engine cannot match | [PS 1] Kinsta "You cannot use Redirects ... to redirect query strings"; WP Engine | COVERED | An exact `from` may require parameters, in any order |
| 65 | `Location` never built from the decoded path (CRLF injection) | [AC 6] Detectify on about 50,000 nginx configurations, Acunetix, CVE-2019-10098, CVE-2020-1927; [SS] RFC 9112 11.1, CWE-113 | COVERED for rules | Written byte by byte, re-encoded, checked, fuzzed (`fuzz_redirect`). The static slash redirect copies the decoded path unencoded; the normaliser refuses control characters, so no CRLF, but see Contradiction 1 |
| 66 | No open redirect from a join (`//host`, `/\host`) | [AC 6] Django CVE-2018-14574, Tomcat CVE-2018-11784 (a directory slash redirect), fastify-static CVE-2021-22963, Astro CVE-2025-54793, MCP Registry CVE-2026-44427, the 2026 backslash advisories (search summary); [SS] URL Standard relative-slash state | COVERED for rules; RISK for the slash redirect | Rules: never `//` or `/\`, an absolute Location names exactly the host of `to`. The directory slash redirect does not go through that check (Contradiction 1) |
| 67 | `to` hygiene: no userinfo, http(s) only, no fragment unless asked | [SS] OWASP redirects cheat sheet, CWE-601; [R] row 16 | COVERED (one deviation) | Userinfo, other schemes and control characters refused. A fragment in `to` is sent: legal (RFC 9110 10.2.2), but the research advised refusing it |
| 68 | Warn when the query goes to another host (it may carry tokens); optional fragment drop for cross-site targets | [SS] RFC 9110 17.9 and 17.11 inferences | MISSING | Low weight: standards inference only |
| 69 | Case: one model for agents, and no loops from case-only rules | [R] "Case handling", evidence both ways (Vercel `caseSensitive` false; Apache, Netlify, Kinsta sensitive) | COVERED (decided) | Case-sensitive, so a rule that only fixes the case is allowed; documented as differing from header and access rules |
| 70 | Loops caught before they go live | [AC 6] SF 505098 (116 / 253,996), nginx's ten-cycle 500; [PS 2] Kinsta's missing `$`; [R] IIS `childOnly`, row 19 | COVERED | A `to` under its own `from` and cycles are refused, across the site's names and ports |
| 71 | Chains flagged, the final target suggested (Google follows 10 hops and says to redirect "to the final destination directly") | [PS 4] Google site moves; [AC 6] frontendchecklist, Mueller "less than 5 hops" | PARTIAL | Warned within one site. Not across this server's sites: an old domain's site whose rule points at a URL the new site redirects again goes unnoticed |
| 72 | Never send every old page to the home page (soft 404) | [PS 3] The Drum, SEOZoom (search summaries); [PS 4] Google | COVERED | A rule from `/` with `remainder = "drop"` is warned |
| 73 | Keep moves at least a year | [PS 4] Google | COVERED | Docs and MCP text ("kept a year") |
| 74 | A stated order: ACME, refused paths, redirects, then access and password rules; say that a redirect reveals its target | [R] order section (nginx list 2016, Caddy, OpenLiteSpeed, Apache vhost); [AC 6] proposal check | COVERED | redirects.md 1; a redirect under an access or auth rule gets a load note |
| 75 | Redirects that work whatever the application's own rewrites do (cPanel writes them at the bottom of `.htaccess`, after WordPress's `[L]`) | [PS 1, 3] cPanel docs ("Some third-party applications will ignore your rules"), InMotion, Krystal, feature requests to prepend | COVERED | Server-side, before the application |
| 76 | No regex: anchoring loops, unreadable rules, the CVE record | [R] nginx's three 2026 CVEs, mod_rewrite CVEs; [PS 2] Kinsta, WP Engine, Forge pitfalls; [AC 6] SO 9632852 (257,383), SF 333048 (110,534) | COVERED (decided) | Exact and prefix only |
| 77 | Splats and placeholders (`/news/* /blog/:splat`) | [PS 2] Netlify, Vercel | PARTIAL | A trailing splat is a prefix rule; a capture in the middle of a target is not offered ("a single `*` within one segment when a real case needs it") |
| 78 | Conditions: country, city, language, method, request headers | [PS 1] Kinsta country/city, WP Engine conditions; [PS 2] Vercel `has`/`missing` | DECIDED-OUT | "The application's job" (redirects.md 5.4; headers.md 3.8). No complaint in the evidence asks for it |
| 79 | A rule for one of the site's names only (Kinsta and WP Engine "Domain: all or one"; Cloudflare `include_subdomains`) | [PS 1, 2] | MISSING | Rules apply to every name. With `canonical` the other names are redirected first; otherwise the workaround is a separate site. Low |
| 80 | Bulk import after a migration, and export for the next move | [PS 2] Kinsta CSV (5,000 per import, export), WP Engine import only through support, Vercel CSV/JSON/JSONL, Cloudflare lists; [PS 3] inferences | PARTIAL | A JSON list through `site_update` or `--redirects-file`, previewed by `path_check`; `site_show` lists the rules back (export). No CSV; the agent converts |
| 81 | Large tables: thousands of exact rows at no cost | [PS 2] Cloudflare 10,000 free up to 1,000,000, Vercel 1,000 to 1,000,000, WP Engine "about 1000" then a plugin; [AC 6] nginx `map`, Adobe "thousands of redirects"; [R] "Scale favours exact tables" | PARTIAL | Exact rules hashed, but at most 1,000 per site file; a data file is "later" (redirects.md 6.3) |
| 82 | Duplicate sources refused | [PS 2] Cloudflare lists | COVERED | Two rules with the same `from` are an error |
| 83 | Editable redirects (cPanel: delete and recreate only) | [PS 1] cPanel docs | COVERED | The list is replaced through `site_update` |
| 84 | Redirects without a support ticket or a shell | [PS 3] WP Engine bulk by ticket, Kinsta query redirects by ticket, Plesk shared hosting directives by ticket | COVERED | MCP tools and `agensio ctl` |
| 85 | No per-request database or PHP cost (redirect plugins) | [PS 3] Redirection plugin's 5,142,793 log rows (search summary), woorkup, WPJohnny (opinion) | COVERED | Hash lookup in the server; the access log records the answer |
| 86 | Forward a whole domain without hosting a site (Plesk's "Forwarding" type deletes the site's data) | [PS 1] Plesk | COVERED | A rule from `/` needs no root and keeps a certificate |
| 87 | Netlify-style status 200 rewrites, a custom 404 page served with 404, `!` force | [PS 2] Netlify's status options | PARTIAL | Rewrites are `try_files` or a front controller; the MCP text explains `!`. A page served with its own error status (`error_page`) is open (redirects.md 12.4) |
| 88 | Short HTML body, Date and HSTS on redirect answers | [SS] "Further redirect additions" | COVERED | redirects.md 1 |

### H. Trailing slashes

| # | Need or complaint | Evidence | Status | What agensio does / what is missing |
|---|---|---|---|---|
| 89 | A location or rule that works with and without the trailing slash | [AC 6] SF 376162 (83 / 157,477) | COVERED | A prefix covers `/x` and `/x/`; an exact rule matches one spelling, so the agent writes both (MCP text) |
| 90 | The automatic directory redirect must be relative and must not break proxies | [AC 6] SO 15555428 (83,074), SF 759762 (23,933) | COVERED (see risk) | Relative `Location`; but no cache bound, the query is dropped, and the path is not re-encoded (Contradiction 1) |
| 91 | A site-wide trailing-slash, lowercase or `index.html` policy | [AC 6] SF 597302 (85,679); [PS 2] Netlify cannot either | DECIDED-OUT | "Fights the applications' own rules" (redirects.md 5.4, decision 5). The decision holds; exact rules where needed |

### I. Testing and debugging

| # | Need or complaint | Evidence | Status | What agensio does / what is missing |
|---|---|---|---|---|
| 92 | Which redirect rule fired, and what exact Location comes out | [AC 6] SO 9632852 (257,383), SF 333048 (110,534); [PS 2] Cloudflare "Trace a request", Vercel's `curl -I` check; [R] | COVERED | `path_check` names every step (scheme, host, rule), the exact Location and its cache lifetime |
| 93 | Which layer set this header field | [AC 1] inferences ("people learn it from a browser console, securityheaders.com or a scanner report"); [AC 7] Plesk's three or four layers; [R]: "which layer set this field, and which rule fired. No server answers either question directly" | PARTIAL | `path_check` names the source of every field agensio decides (baseline, `hsts`, a rule, `add_headers`). It describes and does not fetch, so the application's own fields, and any duplicates it sends, never appear; health fetches only the home page (Top gap 5) |
| 94 | Follow the chain server-side, past the browser's cache (the `curl -sIL`, private window and "Disable cache" routine) | [AC 6] testing habits, SO 16154672; [R] L6 | PARTIAL | `path_check` per site; the agent suggests httpstatus.io (`docs/online-checks.md`). Nothing follows a chain across this server's sites |
| 95 | Stage, then publish (Vercel's staged bulk changes, RunCloud's "Test Template") | [PS 2] Vercel; [PS 1] RunCloud | COVERED | `path_check` with proposed `redirects`/`response_headers`; `site_update` with `dry_run` |

### J. Maintenance

| # | Need or complaint | Evidence | Status | What agensio does / what is missing |
|---|---|---|---|---|
| 96 | Maintenance as `503` + `Retry-After` for a few days at most, never a redirect or `noindex`; `robots.txt` not a 503; the owner still gets in | [PS 4] Google "Pause or disable a website" (official); [R] L11; [PS 4] inference: exempt `/robots.txt` and the ACME path | MISSING | Designed (`maintenance = { until, allow }`, redirects.md 7), not built (Top gap 3) |

### K. Field grammar and limits

| # | Need or complaint | Evidence | Status | What agensio does / what is missing |
|---|---|---|---|---|
| 97 | Values are `field-content` (no CTL, no leading or trailing space, ASCII); names are tokens, lowercased on HTTP/2 and HTTP/3; caps fit a real CSP or Permissions-Policy | [SS] RFC 9110 5.5, RFC 9113 8.2.1, RFC 9112 11.1; OWASP's Permissions-Policy is 478 bytes; [R] row 13 | COVERED | Checked once at load, no `$` variables, 4 KB per value, 16 KB per site. Underscores in names are not warned (RFC 9110 17.10); minor |
| 98 | Never remove `Vary: Accept-Encoding` from a precompressed answer (cache poisoning) | [SS] refuse table | COVERED | `Vary` refused in `set`, `default` and `remove` |

## 2. Contradictions or risks

1. **The static handler's directory redirect bypasses everything the redirect rules guarantee.**
   `StaticHandler::redirect_slash` (`src/handlers/static.cpp`) answers `301` with
   `Location: <decoded, normalised path>/`, built as `r.scratch.assign(ws.path).push_back('/')`, and the
   canned 301 page's headers.
   - **It carries no `Cache-Control`.** Chromium treats a 301 without freshness as fresh forever
     ([SS] browser caching section, `TimeDelta::Max()`; WebKit a year). agensio's own reason for
     `cache = "1d"` on rules (redirects.md 7) applies here word for word. A plausible failure: a
     static site's `/about/` directory becomes a Laravel or Next.js route `/about`, whose framework
     redirects `/about/` to `/about`, and every returning Chromium visitor loops for good. A rule
     cannot bound it either: a freshness-granting Cache-Control without `when = "success"` is refused,
     and a 301 is not a success.
   - **The query is dropped.** nginx keeps the arguments on its slash redirect; "queries lost" is a
     recurring complaint ([AC 6] SO 21118511, 72,212 views).
   - **The path is not re-encoded or checked.** The normaliser refuses control characters (so no
     CRLF), and an encoded `%5C` is a 404. But a raw `\` survives normalisation on Linux
     (`src/path.cpp` flags only the encoded form), so a directory whose name begins with `\` would
     produce `Location: /\name/`, which browsers read as another host ([SS] URL Standard; [AC 6] the
     2026 backslash advisories). That is unlikely, since such a directory must exist under the root.
     It is the exact class of Tomcat CVE-2018-11784 (a directory slash redirect) and the MCP Registry
     CVE-2026-44427 (a trailing-slash middleware). Spaces, `#` and `?` in a directory name also go out
     raw, which garbles the target.
   - Fix: build it with the redirect writer of redirects.md 5.3 (encode, check, keep the query,
     `Cache-Control: max-age=86400`).

2. **`remove = ["Location"]` is accepted and strips agensio's own redirect targets** (built.md
   "rough edges"). A 301/308 then goes out without a target: RFC 9110 15.4.2 says the server "SHOULD
   generate a Location", and with several or none "recovery ... is difficult" (10.2.2). [SS] (refuse
   table: "Location | refuse | The redirect rules own it") and [R] row 12 both put Location on the
   refused list for every verb. Fix: refuse it (and `Refresh`) in `remove` too, naming
   `[[site.redirect]]`.

3. **`remove = ["Server"]` is accepted, does nothing to agensio's own `Server`, and `path_check` says
   "removed".** The tool then tells the administrator something false, on the exact question the
   evidence says no server answers well ("which layer set this field", [R]). Server removal is a
   heavily requested compliance item ([AC 5] SF 991045, 176,730 views). Fix: refuse `Server` in
   `remove` with the pointer to `[server] server_header`, as `set` already does, or make `path_check`
   say it removes only an application's copy. The same rough edge holds for `remove = ["Alt-Svc"]`,
   which strips only an application's copy.

4. **A managed site can turn HSTS on for a year but cannot take it back properly.** The managed field
   is a boolean (`src/control/sites.cpp`: `spec.hsts = body["hsts"].boolean()`; the renderer writes
   only `hsts = true` or `hsts = false`). Root additions take only `[[location]]` tables, and the
   managed file must not be edited, so a managed site cannot send `max_age = 0`. Turning HSTS off
   (`hsts: false`) just stops the field, and browsers keep the policy for up to a year. RFC 6797 6.1.1
   and [AC 2] (SF 1011861: removing the header "doesn't remove the policy from the cache") say the
   cure is `max-age=0` for a while. agensio's own guide prescribes that step (redirects.md 4.5, and
   the reference row for `max_age`), but the managed path cannot take it, and the MCP `hsts`
   description does not mention it. [R] calls HSTS "the field administrators most regret".

5. **`Access-Control-Allow-Origin: null` is accepted, even with `Access-Control-Allow-Credentials: true`.**
   `cors_origin` in `src/config.cpp` treats `null` like `*`, but the credentials check refuses only
   `*`. MDN ([AC 3]): `null` "should be avoided", because "any origin can create a hostile document
   with a null origin" (sandboxed iframes, `data:` and `file:`). [SS] says to warn on `null`, and
   [R] L1 says "no `null`". With credentials it gives any page credentialed cross-origin reads.
   Fix: refuse `null` with credentials, and note `null` alone.

6. **Low: `http` and `canonical` always answer 308.** RFC 9110 15.4.9 notes 308 "might not be
   recognized everywhere", and an unknown 3xx is treated as 300 ([SS]). The evidence reports no actual
   failure, and Google treats 308 like 301 ([PS 4]). Worth one sentence in the docs, not a change.

7. **Low: a fragment in `to` is sent.** This is legal (RFC 9110 10.2.2). [SS] and [R] row 16 advised
   refusing it unless asked; it deviates from the research's advice, not from a standard.

## 3. Top gaps

1. **HSTS has no managed way back and no ramp** (rows 20, 21; Contradiction 4). In the evidence,
   HSTS is the one header whose mistakes outlive the configuration: SF 1011861, SF 890858, SO 33268264
   (329,630 views of "The website uses HSTS ... this page will probably work later"), SO 44650854
   (71,287), the Chromium removal batches, and hstspreload's own ramp advice. agensio waits a week of
   good certificates before suggesting HSTS, which helps. But the one value a managed site can choose
   is a full year, and turning it off strands visitors for that year. Suggestion: let the managed
   `hsts` take `{ max_age }` with fixed steps the agent proposes (`"1w"`, then `"1y"` once health has
   seen a week), and make `hsts: false` on a site that had it render `hsts = { max_age = 0 }`, recording
   when HSTS was turned off. Health `hsts_clearing` then reports until the old `max_age` has passed and
   gives the line that removes it. The MCP `hsts` text should say this. No request-path cost: it is
   the same prebuilt field.

2. **The commonest HTTPS loop goes undetected: a CDN or load balancer not in `trusted_proxies`**
   (row 48). The evidence is large and from many sources: SO 46413494 (top answer "it was
   Cloudflare"), SF 653976, Cloudflare's own troubleshooting page, two AWS ELB threads (37k and 33k
   views), SO 26620670 (52k), and cPanel plus plugin loops. agensio already notes the trusted-proxy
   variant (`proxy_scheme_missing`). Suggestion: on the redirect path only (`redirect_https`, where the
   cost already lives), note a plain request from an address that is not trusted for the site but
   carries `X-Forwarded-Proto: https` (or Cloudflare's `CF-Visitor`). Rate-limit it per worker and
   site like `proxy_scheme_missing`, then report health `proxy_untrusted_https` naming the address
   and the two fixes: add its ranges to `[server] trusted_proxies` (an `[addresses]` set), or use TLS
   to the origin. No cost on sites that do not redirect.

3. **No maintenance setting** (row 96). Google's official guidance is a 503 with `Retry-After` for a
   few days at most. It also says not to block with 403/404/410 or `noindex`, and not to 503
   `robots.txt`. Without a setting, owners and agents reach for a 302 to a maintenance page or a
   noindex, both of which that guidance names as harmful. agensio has already designed it.
   Suggestion: build `maintenance = { until = "<date>", allow = ["@office"] }` as a typed site key and
   managed field: a prebuilt 503 page with `Retry-After` computed from `until`, `/robots.txt` and
   certificate validation exempt, the `allow` addresses served normally through the existing access
   matcher, and health warning while it is on and once `until` has passed. Cost: one flag test where
   the site is known.

4. **Staging `noindex` has no guard rail** (rows 40 to 42). The failure is silent and costly ("can
   deindex an entire site"; recovery takes weeks). The sources are several, though secondary (Vercel's
   docs, GeoRadar, Polemic Digital, pagecrawl.io, stackharbor, TYPO3's environment extension), and
   [R] lists it as the fifth owner need. agensio has the rule form and the right MCP sentence, but the
   health check is "later" and no flag marks a site as staging. Suggestion: a managed `staging: true`
   that renders the `X-Robots-Tag: noindex, nofollow` rule marked as staging's (shown so in `site_show`
   and `path_check`). Add the planned health finding `noindex_on_live_site` for a written rule (never
   an application's own) sending noindex at `/` on a site with a real certificate, no access or auth
   rule at `/`, and visitors in its log. Cost: none on the request path.

5. **"Which layer set this field" is answered for agensio's layers only** (rows 93, 94). These are
   the most-viewed header threads (SO 18450310, 176k; SF 928912, 160k; Plesk's "three places"), and
   [R] names it as one of the two questions no server answers. `path_check` describes agensio's
   decisions well, but cannot show what the application actually sent, and does not follow a redirect
   chain beyond the site. Suggestion: a `fetch: true` option on `path_check` that makes one loopback
   request off the workers, as health's probes already do (`fetch_heads`). It lists each received
   field with its origin: the application's, kept; replaced by a rule (with the application's
   value); defaulted; baseline; `hsts`. It flags a field the application sent twice. For a 3xx it
   follows the chain across this server's sites, giving each hop's status and cache lifetime. It is
   read-only, at viewer level, with no request-path cost.

6. **CORS stops at a fixed value** (rows 35 to 37; Contradiction 5). CORS holds the largest
   questions in the whole evidence: 2.57 M views on a preflight, 1.30 M on several origins, 764k on
   another preflight. Much of that is application-side, and agensio's `set` already removes the
   474k-view "multiple values" class. What remains needs the server: several allowed origins with
   `Vary: Origin`, and a preflight that gets 401 on a password-protected path. The decision "when a
   real case asks" is defensible, since agensio's own review of application configurations found none.
   But the `null` hole should be closed now. Suggestion: refuse `null` with credentials today; later, a
   typed `[[site.cors]]` (`path`, `origins` as a list of exact origins without `null`, `credentials`,
   `methods`, `headers`, `max_age`). It would echo a matching `Origin` with `Vary: Origin` and answer
   a preflight with 204 before the password rules and the method policy (never before `refuse` or the
   access rules). Cost only on paths with a rule, behind the first-byte bitmap the other rules use.

7. **An application's own duplicate security fields** (row 12). Duplicates are the second most
   reported header problem ([AC 1]). Most of them come from a panel plus the application, which
   `set` fixes, but the Roots and DigitalOcean cases show duplicates that break WordPress admin, and
   nothing tells the owner which field or how. Suggestion: the planned health finding. In the
   upstream loop that already reads every field, count a second copy of a short fixed list
   (Strict-Transport-Security, X-Frame-Options, Access-Control-Allow-Origin, X-Content-Type-Options)
   on sites with `app`. Note it once per generation through `site_notices`, as
   `hsts_narrows_application` is noted, with the fix "a `set` rule, or remove it in the application".
   This touches the hot path, so it needs the `-P` A/B. If it costs, gate it behind a site flag that
   health sets while it looks.

8. **Large migrations hit the 1,000-rule cap, and there is no CSV** (rows 80, 81). Platforms sell
   10,000 to 1,000,000 static rows (Cloudflare, Vercel) and Kinsta 5,000 per CSV import. WP Engine's
   1,000 soft limit pushes owners back to PHP plugins whose database tables the evidence shows growing
   to millions of rows. Suggestion: the planned data file, a managed `redirects_file` holding exact
   rules only (hashed, so no request cost beyond today's lookup), written by the helper, previewed and
   checked by the same loader (chains, loops, soft 404s). `--redirects-file` would also accept a
   three-column CSV (`from,to,status`), and `site_show` would offer the same export.

9. **Nothing suggests `canonical`** (row 50). Every panel puts the www/bare choice up front: Plesk's
   "Preferred domain" (whose "None" warns that rankings split), cPanel's www options, ISPConfig's "SEO
   Redirect". agensio has the right setting, but a site listing both `example.com` and
   `www.example.com` without one serves duplicate hosts silently. Suggestion: health info
   `canonical_suggested` for a site whose names include a name and its `www.` twin with no
   `canonical`, with the managed fix (`site_update` with `canonical`) and the application setting to
   change with it. The owner's "both names serve" needs a recorded decided no, as `hsts: false`
   records one (today `canonical: ""` means only "none", so the finding could not be silenced). No
   request cost.
