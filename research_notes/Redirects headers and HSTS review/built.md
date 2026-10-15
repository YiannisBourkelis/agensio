# What agensio has built for redirects, HSTS and response headers (0.1.0-alpha.75 to alpha.94)

Authoritative user docs: /home/yiannis/projects/agensio/docs/configuration.md sections 14 (TLS, http),
14b (redirects), 14c (response headers); design: docs/redirects.md, docs/headers.md (sections 9-13 list
decisions). Summary below; verify against those docs when unsure.

## HTTPS and HSTS
- `hsts = true | false | { max_age, subdomains }` on a site. Sent on every HTTPS answer (static
  files, PHP, CGI, proxied apps, agensio's own error pages, redirects), never over plain HTTP or h2c.
  `preload` is NOT offered (decided: not an RFC, hard to undo). A site's hsts REPLACES an application's
  own Strict-Transport-Security, even a stronger one; health `hsts_narrows_application` (warn) then
  names the application's value. Managed site field `hsts` (and `hsts: false` = a decided no).
- Health: `hsts_suggested` (info) once a real certificate has served 7 days with no certificate
  finding and no hsts line; `hsts_from_application` (info) when the application sends its own (found
  via one probe GET / before any visitor); with hsts on, `certificate_expiring` and
  `acme_renewal_failed` rise to error (visitors cannot click past).
- `http = "redirect" | "serve" | "off" | { listen, mode }`: one site block for both schemes; a TLS
  site on 443 also listens on port 80 and redirects there by default with a 308 (cache a day; no-store
  for a name only a catch-all took; keeps a non-443 TLS port). ACME and /.well-known/pki-validation/
  paths are served from the site's files over plain HTTP, never redirected. Behind a trusted proxy
  X-Forwarded-Proto decides; health `proxy_scheme_missing` (warn) when a trusted proxy sends none
  (loop risk). An application's own `http://` Location naming the site is rewritten to `https://`
  on an HTTPS request.
- `canonical = "<one of server_name>"`: the site's other names 308 to it, path and query kept; from
  plain HTTP scheme and host in one hop (with hsts: the same name's HTTPS first so each host learns
  HSTS). Health `app_redirects_elsewhere` (warn): probes GET / and detects the application
  redirecting the canonical home page to another of the site's names (a loop), naming the app's
  setting (WordPress home/siteurl, Laravel APP_URL, Drupal $base_url, Grav custom_base_url).
- Per-site `trusted_proxies` (narrows the server's; `[addresses]` sets); a client's own
  X-Real-IP/CF-Connecting-IP/True-Client-IP/X-Forwarded-* are not passed to proxied apps from
  untrusted peers; X-Real-IP set to the believed client.

## Path redirects: `[[site.redirect]]`
- `from` (a path; prefix covers whole segments; `match = "exact"` for one path, and an exact `from`
  may require query parameters, e.g. `/?p=123` or `/index.php?page=about`), `to` (a path of the site
  or an https:// URL; none with 410), `status` REQUIRED (301, 302, 307, 308, 410), `remainder`
  keep|drop and `query` keep|drop (both keep by default), `cache` (a lifetime for permanent ones).
  Case-sensitive matching. The most specific rule decides, never the order. No regex, no
  placeholders in the middle of a target, no variables (decided). At most 1,000 rules.
- Evaluated after `refuse` (paths answered 404) and BEFORE address (`[[site.access]]`) and password
  (`[[site.auth]]`) rules; the load notes a rule answering before such a protection.
- Load checks and notes (-t, the error log, health, the change's answer): redirect circles and
  chains followed across the site's names and ports, duplicates refused, a rule over certificate
  validation paths, a "soft 404" (everything to the home page) noted.
- `redirects_all`: a rule from "/" means a whole domain moved; such a site needs no root.
- Managed: `site_update` field `redirects` (the list whole), `agensio ctl --redirect "FROM TO STATUS"`,
  `--redirect-exact`, `--gone FROM`, `--redirects-file F.json` (a migration's list), `--no-redirects`.
  `path_check` (MCP + ctl) names the deciding rule and previews proposed rules before applying.
  MCP texts explain other platforms' habits (Netlify/Cloudflare/Vercel default statuses, Netlify's
  `!`, splats) for imported rule lists.
- Fuzzed (`fuzz_redirect`): Location relative or exactly the origin of `to`, never `//` or `/\`,
  never a control character (open-redirect and header-injection safety).

## Response headers: `[[site.response_headers]]`
- Keys: `path`, `match` (prefix|exact), `set` (replace every copy, the application's included),
  `default` (only when absent: the application's own wins), `remove` (every copy), `when`
  (always|success: 2xx and 304), `endings` (only files agensio serves from disk by their ending:
  svg, woff2, html; never an application's answer). Per field the most specific rule decides
  (longest path, exact before prefix, at one path an endings rule before one without), order never
  matters, a deeper rule changes only the fields it names (the opposite of nginx add_header
  inheritance). Applied to EVERY answer of the path: files, PHP, CGI, proxied, agensio's own error
  pages (404, 403, 405, 413, 502, 504), 401, redirects, OPTIONS, 304. Not: 400/421/431 before
  routing, ACME challenge, 1xx, WebSocket bytes.
- Refused names (naming the setting to use): framing (Connection, Transfer-Encoding,
  Content-Length...), representation (Content-Type, ETag, Last-Modified, Vary, Date...),
  Location/Refresh ([[site.redirect]]), Strict-Transport-Security in set/default (hsts; remove
  allowed), Server (server_header), Alt-Svc, Set-Cookie, Clear-Site-Data, Service-Worker-Allowed, the
  password fields, HPKP/Expect-CT. `remove` accepts any name except framing/representation.
- Values: printable ASCII, no CR/LF, no `$` variables (fixed text only), at most 4 KB each, 16 KB per
  site; 64 rules and 64 field names. X-Frame-Options only DENY or SAMEORIGIN; Access-Control-Allow-Origin
  one origin, `*` or `null` (never several; `*` with credentials refused). A freshness-granting
  Cache-Control/Expires needs `when = "success"` (no year-long cache on a 404).
- Notes: a `set` of Content-Security-Policy on an application site (use default); X-XSS-Protection
  other than 0.
- Guards: behind a password, the cache fields belong to the guard (Cache-Control: private, CDN
  fields dropped); agensio's own no-store (401/403/421) and Retry-After (503) stand.
- HTTP/1, HTTP/2 (CONTINUATION for large heads), HTTP/3 all carry them; names lower-cased on h2/h3.
- `path_check` lists every field's decision for a path with its source, previews proposed rules,
  and on a page lists `response_headers_offer` (fields not sent there, each with what it breaks).
- The older per-location `add_headers` (successful answers of that location only) is kept for
  presets; rules can override its fields.

## The security baseline (presets)
- On for a site with `app` (`response_headers_baseline = false` turns it off): Referrer-Policy:
  strict-origin-when-cross-origin as a default; X-Content-Type-Options: nosniff on agensio's own
  answers only (never an application's); X-Powered-By removed; on app = "static" Cache-Control:
  no-cache on .html/.htm files (success). Deliberately NOT in the baseline (offered by the agent,
  one at a time, after asking): X-Frame-Options/frame-ancestors (breaks embeds: WordPress post
  embeds, status pages, widgets), nosniff on app answers, CSP (report-only first), Permissions-Policy.
- Health `response_headers_suggested` (info): live HTTPS sites' home page fetched once; names missing
  frame field / CSP / Permissions-Policy / nosniff; `response_headers_offer_declined` records the
  owner's refusals.
- Managed: `site_update` fields `response_headers` (rules as objects), `response_headers_baseline`,
  `response_headers_offer_declined`; ctl `--response-header "PATH set|default NAME=VALUE"`,
  `--response-header-remove "PATH NAME"`, `--response-headers-file`, `--no-response-headers`,
  `--no-response-headers-baseline`, `--decline-response-header NAME`.
- An AI agent manages sites through MCP tools; the MCP texts tell it what to offer and what breaks.

## Not built (known), with reasons
- Decided out: regex/rewrite rules, variables in response fields, HSTS preload, CORS with several
  origins (a typed `cors` setting later "when a real case asks"), `merge`/`append` verbs, ETag removal.
- Open, listed in docs/redirects.md 12.4 / headers.md 11.3: error pages served with their status
  (`error_page = { 404 = "/404.html" }`; today a try_files fallback answers 200, a soft 404); clean
  addresses (`try_files` accepts only `$uri`, `$uri/`, `=403`, `=404` or a `/path`: no `$uri.html`);
  the single-page fallback on a managed static site (needs a root additions file); a MIME type table
  per site (.well-known files without extension, .svgz); upstreams by host name; internal rewrites
  that drop a segment (Magento static versions, PrestaShop images, WP multisite subdirectories); path
  patterns in header rule paths (`**/_app/immutable/`); conditions on the query (`immutable` only
  with ?v=) or on statuses beyond success (204); a second narrowing CSP.
- Health "later": a security field the application sends twice; a rule's X-Robots-Tag noindex on a
  site that looks live.
- Known rough edges (not yet decided): `remove = ["Server"]` is accepted but agensio's own Server
  line stays (and path_check says "removed"); `remove = ["Location"]` would strip agensio's own
  redirect targets; `remove = ["Alt-Svc"]` strips only an application's.
- No staging/maintenance mode feature (temporary "site under maintenance" 503 with Retry-After for
  all but the admin), no "redirect test" tool beyond path_check (which describes, not fetches),
  no bulk import from .htaccess / nginx files other than the agent translating them.
