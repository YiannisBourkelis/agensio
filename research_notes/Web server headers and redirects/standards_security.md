# Standards and security guidance for response headers and redirects (as of 2026-10-12)

Sources were read in full where possible. RFC 9110, 9111, 9112, 9113 and 9114 come from the copies in `docs/rfc/`, which match rfc-editor.org. The Fetch, URL, Service Worker and CSP specs were downloaded on 2026-10-12 and searched as text. Browser cache behaviour was read from the current Chromium, Firefox and WebKit sources. Anything marked "unverified" was not confirmed in this session.

## RFC 9110 rules: redirect status codes, Location, hop-by-hop fields, field syntax, repeated fields, Set-Cookie

### Takeaway
RFC 9110 defines 301 and 302 as "may become GET" redirects and 307 and 308 as method-preserving. Only 301 and 308 (and 300) are heuristically cacheable. Location is a single URI-reference: it may be relative, and it inherits the request's fragment unless it carries its own. A generated field value must be `field-content`: visible ASCII (obs-text tolerated) with inner SP/HTAB, no leading or trailing whitespace, and never CR, LF or NUL. A sender must not repeat a field name unless the field is list-based. Set-Cookie is the one exception everyone has to special-case.

### Cited Findings
**Redirect status codes**
- 3xx overview: 301, 302, 307 and 308 mean "this resource might be available at a different URI". 303 is "an indirect response". In HTTP/1.0, 301 and 302 were method-preserving, but "Prevailing practice eventually converged on changing the method to GET", so 307 and 308 were added "to unambiguously indicate method-preserving redirects" — [RFC 9110 §15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4)
- A user agent that follows a redirect SHOULD resend the request with these changes: resolve Location relative to the original target URI, and remove connection-specific, proxy, origin-specific (Host), cache-validator and resource-specific fields (Referer, Origin, Authorization, Cookie). It should consider dropping Authorization and Cookie. "A client SHOULD detect and intervene in cyclical redirections." A note says an earlier spec recommended at most five redirections and that "some clients might implement such a fixed limitation" — [RFC 9110 §15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4)
- 301: "assigned a new permanent URI". The server "SHOULD generate a Location header field". "For historical reasons, a user agent MAY change the request method from POST to GET… If this behavior is undesired, the 308 (Permanent Redirect) status code can be used instead." "A 301 response is heuristically cacheable" — [RFC 9110 §15.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.2)
- 302: "resides temporarily under a different URI… the client ought to continue to use the target URI for future requests". POST may become GET, and 307 is the fix — [RFC 9110 §15.4.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.3)
- 303: "applicable to any HTTP method. It is primarily used to allow the output of a POST action to redirect the user agent to a different resource". The follow-up is a GET or HEAD. Except for HEAD, the response "ought to contain a short hypertext note with a hyperlink" — [RFC 9110 §15.4.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.4)
- 307: "the user agent MUST NOT change the request method if it performs an automatic redirection" — [RFC 9110 §15.4.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.8)
- 308: permanent and method-preserving (by contrast with 301), "heuristically cacheable". It is "much younger (June 2014)… might not be recognized everywhere", see RFC 7538 §4 — [RFC 9110 §15.4.9](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.9)
- An unrecognized status code must be treated as the x00 of its class, so a client that does not know 308 treats it as 300 — [RFC 9110 §15](https://www.rfc-editor.org/rfc/rfc9110.html#section-15)
- The heuristically cacheable codes are "200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, and 501". "All other status codes are not heuristically cacheable", so 302, 303 and 307 are cached only with explicit freshness — [RFC 9110 §15.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.1)
- A cache "MUST NOT use heuristics… when an explicit expiration time is present". It may use heuristics only for heuristically cacheable codes, or when the response is marked explicitly cacheable (e.g. `public`). The suggested Last-Modified fraction is "10%" — [RFC 9111 §4.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.2)
- On any 3xx, `Retry-After` gives "the minimum time that the user agent is asked to wait before issuing the redirected request" — [RFC 9110 §10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3)

**Location**
- `Location = URI-reference`, a single value. "When it has the form of a relative reference… the final value is computed by resolving it against the target URI." — [RFC 9110 §10.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2)
- Fragments: "If the Location value provided in a 3xx… does not have a fragment component, a user agent MUST process the redirection as if the value inherits the fragment component" of the original reference — [RFC 9110 §10.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2)
- Location cannot be a list, because a comma is valid inside a URI. If multiple Location lines are sent, "Recovery… is difficult and not interoperable" — [RFC 9110 §10.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2)
- An inherited fragment can disclose one site's fragment to another. A site that puts personal data in fragments "ought to ensure that redirects to other sites include a (possibly empty) fragment component in order to block that inheritance" — [RFC 9110 §17.11](https://www.rfc-editor.org/rfc/rfc9110.html#section-17.11)
- URIs are not secret. Redirecting the result of a query to a server-generated URI "can remove potentially sensitive data from later links" — [RFC 9110 §17.9](https://www.rfc-editor.org/rfc/rfc9110.html#section-17.9)
- An origin server with a clock "MUST generate a Date header field in all 2xx…, 3xx…, and 4xx" responses — [RFC 9110 §6.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.1)

**Connection-specific (hop-by-hop) fields**
- A field carrying connection control information must be listed in `Connection`. Intermediaries remove the listed fields and SHOULD also remove "Proxy-Connection, Keep-Alive, TE, Transfer-Encoding, Upgrade" whether listed or not. "Cache-Control is never appropriate as a connection option" — [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1)
- HTTP/2: "An endpoint MUST NOT generate an HTTP/2 message containing connection-specific header fields". These are Connection, Proxy-Connection, Keep-Alive, Transfer-Encoding and Upgrade, and such a message is malformed. TE is allowed only in requests and only as "trailers" — [RFC 9113 §8.2.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2)
- HTTP/3 has the same rule, and uppercase field names make a message malformed — [RFC 9114 §4.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2)

**Field name and value syntax**
- `field-name = token` and names are case-insensitive. `tchar` is `!#$%&'*+-.^_`|~`, DIGIT and ALPHA. The delimiters `"(),/:;<=>?@[\]{}` are excluded — [RFC 9110 §5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1), [§5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2)
- `field-content = field-vchar [ 1*( SP / HTAB / field-vchar ) field-vchar ]`, with `field-vchar = VCHAR / obs-text` and `obs-text = %x80-FF`. New fields "SHOULD limit their values to visible US-ASCII octets (VCHAR), SP, and HTAB". "Field values containing CR, LF, or NUL characters are invalid and dangerous". Other CTLs "are also invalid" — [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5)
- HTTP/1.1: no whitespace between the name and the colon. Senders MUST NOT generate obs-fold (line folding) — [RFC 9112 §5.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-5.1), [§5.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-5.2)
- HTTP/2 minimal validation (a MUST): a name contains no 0x00-0x20, no 0x41-0x5A (uppercase) and no 0x7F-0xFF, and no colon except in pseudo-headers. A value contains no NUL, LF or CR, and does not "start or end with an ASCII whitespace character (ASCII SP or HTAB)" — [RFC 9113 §8.2.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.1)
- Underscores in names are discouraged because of the CGI `HTTP_` mapping ("Transfer_Encoding" smuggling example) — [RFC 9110 §17.10](https://www.rfc-editor.org/rfc/rfc9110.html#section-17.10)

**Repeated fields and Set-Cookie**
- "A sender MUST NOT generate multiple field lines with the same name in a message… unless that field's definition allows multiple field line values to be recombined as a comma-separated list". The note: "Set-Cookie… often appears… across multiple field lines and does not use the list syntax… recipients ought to handle 'Set-Cookie' as a special case" — [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3)
- A field repeated within a section is combined in order with commas. Order matters, and proxies must not reorder — [RFC 9110 §5.2–5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2)
- "Origin servers SHOULD NOT fold multiple Set-Cookie header fields into a single header field". "Servers SHOULD NOT include more than one Set-Cookie header field in the same response with the same cookie-name" — [RFC 6265 §3, §4.1.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.1)
- In Fetch, `Set-Cookie` and `Set-Cookie2` are "forbidden response-header names" that scripts never see — [Fetch §2.2.2](https://fetch.spec.whatwg.org/#forbidden-response-header-name)
- An origin server "MAY generate a Server header field". Product information in Server/Via/User-Agent "can make it easier for an attacker" — [RFC 9110 §10.2.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.4), [§17.12](https://www.rfc-editor.org/rfc/rfc9110.html#section-17.12)

### Inferences
- The proposed status set (301, 302, 307, 308) is consistent with RFC 9110. **Add 303** as an option: it is the only code defined for "after a POST, go GET this", and it is what applications behind a proxy emit. For a static redirect rule it is rarely needed, so it is a low-priority addition. In the docs, recommend 308/307 whenever the path can receive non-GET methods, because 301/302 turn a POST into a GET in every browser (see Fetch below).
- "Required status" is the right call: the RFC's distinctions between permanent and temporary, and between method-preserving and not, are exactly what an admin has to choose.
- For a same-site path target, emit a **path-absolute relative reference** (`/new/path?q`) in Location. This is legal (§10.2.2), and the response then never depends on the request's Host. That matters on a catch-all or default site, where Host is whatever the client sent. An absolute URL built from Host there would put an attacker-chosen host in Location (a cache-poisoning or open-redirect vector). Absolute URLs only for configured http(s) targets.
- Do not add a fragment by default. The UA carries the original fragment over (§10.2.2). For cross-site targets, an opt-in "drop fragment" that appends `#` follows §17.11.
- Keeping the query by default fits same-site moves. For a cross-site target, the query may carry tokens (§17.9). A config-time warning ("query forwarded to another host") is cheap.
- A header rule that "sets" a singleton field must replace, never add a second line (§5.3). Only list-based fields (e.g. `Vary`, `Cache-Control`, `Link`) may be appended. CSP is a special case: a second line is a second policy (see the multi-tenant section).

### Gaps
- A per-field "list-based or singleton" table was not compiled. The IANA HTTP Field Name Registry (https://www.iana.org/assignments/http-fields/) records "structured type" for some fields only. The implementer will need a hand-written list.

## How browsers cache 301/308 in practice, how to undo it, and whether Cache-Control bounds it

### Takeaway
Chromium still treats 300, 301, 308 and 410 without explicit freshness as fresh forever (`TimeDelta::Max()`). WebKit gives 301 (and 410) one year and gives 308 only the Last-Modified heuristic. Firefox has revalidated redirects that carry no max-age/Expires since April 2025. In all three engines, an explicit `Cache-Control: max-age` (or `Expires`) is checked before the implicit rule, so it bounds the lifetime, and `no-store`/`no-cache` stops reuse in Chromium. Once a client has cached an unbounded 301, the server cannot undo it, because the client never asks again.

### Cited Findings
- Chromium `HttpResponseHeaders::GetFreshnessLifetimes` checks in this order:
  1. `no-cache`/`no-store` (`HasCacheRestriction()`) returns "not fresh".
  2. `max-age` returns that value.
  3. `Expires`.
  4. The Last-Modified heuristic, `(date - last_modified) / 10`, only for 200, 203 and 206.
  5. "These responses are implicitly fresh (unless otherwise overruled)": for 300, 301, 308 and 410, `lifetimes.freshness = base::TimeDelta::Max(); lifetimes.staleness = base::TimeDelta(); // It should never be stale.`

  The default for everything else is 0 — [Chromium net/http/http_response_headers.cc (main, read 2026-10-12)](https://github.com/chromium/chromium/blob/main/net/http/http_response_headers.cc)
- Firefox `nsHttpResponseHead::ComputeFreshnessLifetime` checks in this order:
  1. max-age.
  2. Expires.
  3. 410 alone is "cached indefinitely" (`uint32_t(-1)`).
  4. Codes ≥ 400 get no heuristic.
  5. 302, 303, 304 and 307 get no heuristic unless `public` or `private`.
  6. Otherwise `min(one week, (date − Last-Modified)/10)`, else 0.

  301 and 308 are in `MustValidate`'s "Cacheable redirects" list — [Firefox nsHttpResponseHead.cpp (main)](https://github.com/mozilla-firefox/firefox/blob/main/netwerk/protocol/http/nsHttpResponseHead.cpp)
- The Firefox change: commit "Bug 1957619 - Revalidate cached redirects with no max-age or expires headers", 2025-04-02. It replaced `if ((mStatus == 300) || (mStatus == 410) || nsHttp::IsPermanentRedirect(mStatus))` with `if (mStatus == 410)` and added a web-platform test, "HTTP cache does not reuse a redirected response with no max-age and no Last-Modified header". Before this, Firefox also cached 300/301/308 indefinitely — [mozilla-firefox commit a8e07ec6f6](https://github.com/mozilla-firefox/firefox/commit/a8e07ec6f6), [Bugzilla 1957619](https://bugzilla.mozilla.org/show_bug.cgi?id=1957619)
- A later Firefox commit, "Bug 1958245 - Firefox not caching 303 redirects" (2025-11-24), also touched this file. Its diff was not read (unverified what it changed) — [Firefox commit history for the file](https://github.com/mozilla-firefox/firefox/commits/main/netwerk/protocol/http/nsHttpResponseHead.cpp)
- WebKit `computeFreshnessLifetimeForHTTPFamily` checks in this order: max-age, then Expires (an invalid Expires gives 0), then for 301 and 410 `24_h * 365`, because they are "semantically permanent and so get long implicit lifetime", then the Last-Modified heuristic `* 0.1`, else 0. There is no special case for 308 or 300 — [WebKit CacheValidation.cpp (main)](https://github.com/WebKit/WebKit/blob/main/Source/WebCore/platform/network/CacheValidation.cpp)
- RFC basis: 301 and 308 are heuristically cacheable, and an explicit expiration time excludes heuristics — [RFC 9110 §15.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.1), [RFC 9111 §4.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.2)
- In Fetch, 301 and 302 change POST to GET, and 303 changes any method other than GET/HEAD to GET. A cross-origin hop removes `Authorization`. More than 20 redirects is a network error. A Location whose scheme is not HTTP(S) is a network error — [Fetch §4.5 HTTP-redirect fetch](https://fetch.spec.whatwg.org/#http-redirect-fetch)

### Inferences
- **Give permanent redirects explicit freshness by default.** Every engine reads `Cache-Control: max-age` before its implicit rule, so a 301/308 sent with e.g. `Cache-Control: max-age=86400` (or an admin-chosen value) can be undone within that period. Without it, a mistaken 301 lives forever in Chromium-based browsers and a year in Safari. The only cures are on the client: clearing the cache or the profile.
- A field such as `cache = "1d"` on permanent rules (default bounded, `"forever"` to opt out) is the safe-by-construction choice. Bounding a 308 the same way keeps behaviour uniform.
- 302/307 need no Cache-Control, because no engine caches them without explicit freshness. Adding `Cache-Control: no-store` (or `no-cache`) is harmless and defends against shared caches that cache aggressively (optional).
- To retire a cached permanent redirect, the admin can only wait out the max-age that was sent. Document that changing or removing a 301 rule does not reach clients that cached it without max-age.

### Gaps
- Which Firefox release first shipped Bug 1957619 was not confirmed (landed in mozilla-central 2025-04-02; probably Firefox 139, unverified).
- Behaviour of HTTP/2 or HTTP/3 shared caches and CDNs on 301 without Cache-Control was not researched.
- Chromium's handling of `Cache-Control: no-cache` on 301 was read as "not fresh". Whether Chrome then revalidates or refetches a redirect without validators was not tested.

## OWASP guidance: Secure Headers Project values, headers to remove, Unvalidated Redirects cheat sheet, CWE-601

### Takeaway
The OWASP Secure Headers Project CI list (updated 2026-10-04) recommends:
- HSTS `max-age=63072000; includeSubDomains`
- a strict CSP
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: deny`
- `Referrer-Policy: no-referrer`
- COOP `same-origin`, COEP `require-corp`, CORP `same-origin`
- a long deny-all Permissions-Policy
- Clear-Site-Data and `Cache-Control: no-store` (logout or sensitive pages, not site-wide)

Its removal list includes Server and X-Powered-By. On redirects, OWASP and CWE-601 say: never take the destination from user input; use mappings or allow-lists; parse and compare components rather than string prefixes.

### Cited Findings
- OWASP Secure Headers `headers_add.json` (last_update_utc "2026-10-04 07:23:38"):
  - `Cache-Control: no-store, max-age=0`
  - `Clear-Site-Data: "cache","cookies","storage"`
  - `Content-Security-Policy: default-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests`
  - `Cross-Origin-Embedder-Policy: require-corp`
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cross-Origin-Resource-Policy: same-origin`
  - `Permissions-Policy: accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(self), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), hid=(), idle-detection=(), interest-cohort=(), serial=(), unload=()`
  - `Referrer-Policy: no-referrer`
  - `Strict-Transport-Security: max-age=63072000; includeSubDomains`
  - `X-Content-Type-Options: nosniff`
  - `X-DNS-Prefetch-Control: off`
  - `X-Frame-Options: deny`
  - `X-Permitted-Cross-Domain-Policies: none`

  — [OWASP Secure Headers headers_add.json](https://raw.githubusercontent.com/OWASP/www-project-secure-headers/master/ci/headers_add.json), project page [owasp.org/www-project-secure-headers](https://owasp.org/www-project-secure-headers/)
- OWASP `headers_remove.json` (same date): about 90 names. They include `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Php-Version`, `X-Generator`, `X-Redirect-By`, `SourceMap`/`X-SourceMap`, tracing ids (`X-B3-*`, `X-Datadog-*`), `X-Envoy-*`, `X-Kong-*`, `X-LiteSpeed-*`, `X-Varnish-*`, `X-Nextjs-*` and `X-Powered-By-Plesk` — [OWASP Secure Headers headers_remove.json](https://raw.githubusercontent.com/OWASP/www-project-secure-headers/master/ci/headers_remove.json)
- The OWASP HTTP Headers Cheat Sheet differs on some values:
  - `X-Frame-Options: DENY`, but "Content Security Policy (CSP) frame-ancestors directive obsoletes X-Frame-Options"
  - `X-XSS-Protection`: "Do not set this header or explicitly turn it off" (`0`); "in some cases, this header can create XSS vulnerabilities"
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Content-Type: text/html; charset=UTF-8`
  - HSTS `max-age=63072000; includeSubDomains; preload`, with a warning to "Read carefully how this header works before using it"
  - Expect-CT: "Do not use it"
  - Public-Key-Pins: "Do not use" (removed from Chromium in 2018)
  - ACAO: "set specific origins instead of `*`"
  - COOP `same-origin`, COEP `require-corp` (which "blocks misconfigured cross-origin resources"), CORP `same-site`
  - `Permissions-Policy: geolocation=(), camera=(), microphone=()`
  - `Server`: "Remove this header or set non-informative values"
  - "Remove all X-Powered-By headers"
  - `X-DNS-Prefetch-Control: off` is "not standard or fully supported"

  — [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- The two OWASP sources conflict on Referrer-Policy (`no-referrer` vs `strict-origin-when-cross-origin`), CORP (`same-origin` vs `same-site`) and HSTS `preload` (absent vs present) — [headers_add.json](https://raw.githubusercontent.com/OWASP/www-project-secure-headers/master/ci/headers_add.json) vs [HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- CSP `frame-ancestors` "MUST be ignored when contained in a policy declared via a meta element", so it works only as a header — [CSP Level 3 ED 2026-09-16 §6.4.2](https://w3c.github.io/webappsec-csp/#directive-frame-ancestors)
- OWASP Unvalidated Redirects and Forwards Cheat Sheet:
  - "Simply avoid using redirects and forwards"; the destination should not come from the user.
  - Map IDs or tokens to URLs server-side, with non-guessable IDs.
  - For local destinations, use a helper that rejects non-local URLs (ASP.NET `LocalRedirect`/`IsLocalUrl`). For external ones, use an allow-list checked "against parsed URL components" (scheme, canonical host, effective port, optionally path).
  - "Reject userinfo and ambiguous input" and redirect to the validated URL itself. "Avoid raw prefix or suffix string matching" (GitLab userinfo bypass cited).
  - An interstitial warning page.

  — [OWASP cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- CWE-601 "URL Redirection to Untrusted Site ('Open Redirect')" (CWE 4.20, page updated 2026-04-30). Mitigations:
  - "Use a list of approved URLs or domains to be used for redirection"
  - an intermediate disclaimer page
  - "Enforcement by Conversion": map fixed input values to URLs and reject the rest
  - a nonce
  - attack surface reduction
  - an application firewall (moderate)

  The example CVE-2020-11053 is HTML-encoded whitespace bypassing redirect validation — [CWE-601](https://cwe.mitre.org/data/definitions/601.html)

### Inferences
- The OWASP "add" list is a policy for an application's sensitive pages, not a server-wide default. `Clear-Site-Data` and `Cache-Control: no-store` on every response would log every visitor out and defeat caching on every load. COEP `require-corp` and COOP `same-origin` break cross-origin embeds and OAuth popups.
- A server should offer these headers as named presets or typed fields (HSTS, frame policy, nosniff, referrer policy) with safe defaults, rather than encouraging copy-paste of the full list.
- Removal: agensio already emits its own `Server`. OWASP's guidance ("remove or set non-informative values") supports offering a server-level option to reduce `Server` to `agensio` without a version, or to drop it. For proxied and PHP answers, a site-level `remove` of `X-Powered-By` (PHP's `expose_php`), `X-Redirect-By` (WordPress) and `X-Generator` (Drupal) matches the OWASP removal list and is the most common real use of a header rule.
- Open redirects (CWE-601) arise when the destination comes from the request. In the proposal, the destination is admin-configured and only the path remainder and query are copied from the request. The CWE-601 surface is therefore exactly the join, which must be proven unable to change the authority (next section and the redirect join notes below). The proposal should not accept `$arg_*`/`$query`-style variables in `to`.

### Gaps
- The OWASP project's own guidance text on which headers apply to every response and which only to logout or sensitive pages was not fetched (only the CI JSON lists). The "not site-wide" caveat above is an inference from the headers' semantics and the Clear-Site-Data spec.

## HSTS: RFC 6797 rules, preload list requirements, removal

### Takeaway
STS must only be sent over TLS. Browsers ignore it over HTTP, process only the first STS field, and drop the policy on `max-age=0`. Preload requires a valid certificate, an HTTP→HTTPS redirect on the same host, HTTPS on every subdomain, and `max-age` ≥ 31536000 with `includeSubDomains` and `preload` (also on HTTPS redirects). Leaving the preload list takes months.

### Cited Findings
- "An HSTS Host MUST NOT include the STS header field in HTTP responses conveyed over non-secure transport". For plain HTTP requests it should send a permanent redirect (301 in the example) to https — [RFC 6797 §7.2](https://www.rfc-editor.org/rfc/rfc6797.html#section-7.2)
- "If an HTTP response is received over insecure transport, the UA MUST ignore any present STS header field(s)". With more than one STS field over secure transport, the UA processes only the first — [RFC 6797 §8.1](https://www.rfc-editor.org/rfc/rfc6797.html#section-8.1)
- Syntax: "All directives MUST appear only once in an STS header field". Names are case-insensitive, unknown directives are ignored, and a non-conforming header is ignored entirely. `max-age=0` makes the host cease to be a Known HSTS Host, and includeSubDomains is then ignored — [RFC 6797 §6.1, §6.1.1, §6.2](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1)
- IP-literal hosts are never noted as HSTS hosts — [RFC 6797 §8.1.1](https://www.rfc-editor.org/rfc/rfc6797.html#section-8.1.1)
- "Only the given HSTS Host can update or can cause deletion of its issued HSTS Policy". A UA "MUST NOT modify the expiry time or the includeSubDomains directive of any superdomain matched Known HSTS Host" — [RFC 6797 §5.3, §8.1.1](https://www.rfc-editor.org/rfc/rfc6797.html#section-5.3)
- Denial of service: with includeSubDomains, subdomains lacking proper secure transport "will be rendered unreachable". An attacker able to inject headers (response splitting) can set policy — [RFC 6797 §14.5](https://www.rfc-editor.org/rfc/rfc6797.html#section-14.5)
- includeSubDomains exists because without it HSTS "is unable to protect such Secure-flagged domain cookies" — [RFC 6797 §14.4](https://www.rfc-editor.org/rfc/rfc6797.html#section-14.4)
- Preload requirements:
  - a valid certificate
  - "redirect HTTP to HTTPS on the same host" when listening on port 80
  - every subdomain over HTTPS ("including the www subdomain if a DNS record… exists")
  - on the base domain over HTTPS: `max-age` ≥ 31536000, `includeSubDomains`, `preload`
  - "Any redirect served from the HTTPS site must also carry the HSTS header"

  Removal: "Domains can be removed, but it takes months for a change to reach users with a Chrome update". The suggested ramp is `max-age=300` → `604800` → `2592000`, waiting the full max-age at each stage — [hstspreload.org](https://hstspreload.org/)

### Inferences
- An HSTS header rule must be suppressed on plain-HTTP listeners (sending it there is a MUST NOT), or HSTS should be a typed field that the server emits only on TLS. A typed field can also guarantee a single STS line, valid syntax, and directives appearing once.
- On a multi-site host, `includeSubDomains` on the site `example.com` also binds every other agensio site under `*.example.com`. That includes sites owned by other tenants and plain-HTTP-only sites, so it can cut them off (§14.5). This deserves a config-time warning naming the affected sibling sites served by the same server.
- `preload` deserves a stronger warning (months to undo). The server can refuse `preload` unless `max-age` ≥ 31536000 and `includeSubDomains` are both present, since hstspreload.org rejects that combination anyway.
- A redirect rule on an HTTPS site should carry the site's HSTS header too (a preload requirement). The HTTP→HTTPS redirect must go to the same host first (http://example.com → https://example.com, then to www), or preload submission fails.

### Gaps
- The exact error messages and current extra checks of the hstspreload.org submission API (e.g. the eTLD+1-only rule) were not fetched.

## CORS (Fetch standard): Access-Control-Allow-Origin, credentials, Vary: Origin, preflight

### Takeaway
`Access-Control-Allow-Origin` is one value: `*`, `null`, or a single serialized origin with no trailing slash, never a list. `*` (in ACAO and in the Allow-Methods/Allow-Headers/Expose-Headers wildcards) does not work with credentials, and credentials need `Access-Control-Allow-Credentials: true`. A static ACAO should be sent on every response with no `Vary`. A per-origin ACAO must come with `Vary: Origin`. A successful preflight is an ok status (200/204), and `Access-Control-Max-Age` defaults to 5 s.

### Cited Findings
- ABNF: `Access-Control-Allow-Origin = origin-or-null / wildcard`, `Access-Control-Allow-Credentials = %s"true" ; case-sensitive`, `Access-Control-Expose-Headers = #field-name`, `Access-Control-Max-Age = delta-seconds`, `Access-Control-Allow-Methods = #method`, `Access-Control-Allow-Headers = #field-name`. "For `Access-Control-Expose-Headers`, `Access-Control-Allow-Methods`, and `Access-Control-Allow-Headers` response headers, the value `*` counts as a wildcard for requests without credentials" — [Fetch §3.3.4 HTTP new-header syntax (Living Standard, updated 2026-10-06)](https://fetch.spec.whatwg.org/#http-new-header-syntax)
- ACAO indicates sharing "via returning the literal value of the `Origin` request header (which can be `null`) or `*`". "A successful HTTP response to a CORS-preflight request is similar, except it is restricted to an ok status, e.g., 200 or 204". Max-Age gives the seconds ("5 by default") for which Allow-Methods and Allow-Headers can be cached — [Fetch §3.3.3 HTTP responses](https://fetch.spec.whatwg.org/#http-responses)
- "If credentials mode is "include", then Access-Control-Allow-Origin cannot be `*`". "A serialized origin has no trailing slash" — [Fetch §3.3.5 CORS protocol and credentials](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials)
- "If CORS protocol requirements are more complicated than setting `Access-Control-Allow-Origin` to * or a static origin, `Vary` is to be used… `Vary: Origin`". Without it, a cached non-CORS response that lacks ACAO is reused for a later CORS request. But "if `Access-Control-Allow-Origin` is set to * or a static origin… always send `Access-Control-Allow-Origin`… for non-CORS requests as well as CORS requests — and do not use `Vary`" — [Fetch, Background reading: CORS protocol and HTTP caches](https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches)
- `X-Content-Type-Options` and `Cross-Origin-Resource-Policy` are also defined in Fetch (§3.6, §3.7) — [Fetch](https://fetch.spec.whatwg.org/#x-content-type-options-header)
- OWASP: "set specific origins instead of `*`" — [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)

### Inferences
- A raw header rule can produce only a static ACAO. That is fine per Fetch, as long as it is sent on every response for the path and with no `Vary`.
- Validate at config time:
  - ACAO is one value (`*`, `null`, or `scheme://host[:port]` with no path or trailing slash). Refuse comma or space lists, the most common misconfiguration.
  - Refuse `ACAO: *` together with `Access-Control-Allow-Credentials: true` on the same path (browsers reject it).
  - Warn on `null` (it is the origin of sandboxed iframes and `file:` pages, so allowing it is close to `*`).
  - Refuse `Access-Control-Allow-Credentials` with any value other than `true`.
- Multiple allowed origins need a typed CORS feature (match the request's `Origin` against a list, echo it, add `Vary: Origin`, answer the preflight with an ok status). That cannot be a plain header rule. If agensio builds it later, the preflight must answer 200/204 even where the location would otherwise give 405.

### Gaps
- Browser handling of a duplicated ACAO line (two identical values) was not verified. Combining per RFC 9110 §5.3 gives a comma list, which fails the ABNF, so presumably it fails (unverified).

## Response splitting / header injection (CWE-113), how servers prevent it, header size limits

### Takeaway
RFC 9112 and CWE-113 agree. The robust defence is that only the server's own protocol code ever writes CR or LF, and every value that reaches it (configured or derived from the request) is checked against `field-content`: no CR, LF or NUL, no other CTLs, no leading or trailing whitespace. HTTP gives no response header size limit. HTTP/2 and HTTP/3 peers can advertise one (name + value + 32 bytes per field).

### Cited Findings
- Response splitting "exploits the line-based nature of HTTP message framing". An example is a request parameter echoed in Location. Filtering `%0D`/`%0A` in requests is weak, because applications transform data in other ways. "A more effective mitigation is to prevent anything other than the server's core protocol libraries from sending a CR or LF within the header section, which means restricting the output of header fields to APIs that filter for bad octets" — [RFC 9112 §11.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-11.1)
- A recipient of CR, LF or NUL in a value "MUST either reject the message or replace each of those characters with SP" — [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5)
- In HTTP/2 an intermediary "MUST NOT forward fields that contain any of the values that are listed as prohibited" (NUL, CR, LF, leading or trailing SP/HTAB, uppercase or invalid name bytes) — [RFC 9113 §8.2.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.1)
- CWE-113 "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')" (CWE 4.20). Including unexpected data "allows an attacker to specify the entirety of the HTTP message". It notes HT and SP can also act as separators. Mitigations: construct headers "very carefully, avoiding the use of non-validated input data", "accept known good" validation, and canonicalize before validation without double decoding — [CWE-113](https://cwe.mitre.org/data/definitions/113.html)
- HSTS can be set by an attacker through response splitting — [RFC 6797 §14.5](https://www.rfc-editor.org/rfc/rfc6797.html#section-14.5)
- Limits: "HTTP does not place a predefined limit on the length of each field line, field value, or on the length of a header or trailer section as a whole" — [RFC 9110 §5.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.4)
- HTTP/2 `SETTINGS_MAX_HEADER_LIST_SIZE` is advisory and counts "the uncompressed size of field lines, including the length of the name and value… plus an overhead of 32 octets for each field line". Its initial value is unlimited — [RFC 9113 §6.5.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5.2)
- HTTP/3 `SETTINGS_MAX_FIELD_SECTION_SIZE`: a sender "SHOULD NOT send an HTTP message header that exceeds the indicated size". A client "can discard responses that it cannot process" — [RFC 9114 §4.2.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2.2)
- WHATWG URL parsing removes leading and trailing C0 control or space, and "Remove all ASCII tab or newline from input" — [URL Standard, basic URL parser (updated 2026-10-07)](https://url.spec.whatwg.org/#concept-basic-url-parser)

### Inferences
- The proposed "printable without CR/LF up to 1 KB" should be tightened to the exact `field-content` grammar (RFC 9110 §5.5 + RFC 9113 §8.2.1):
  - Refuse every CTL (0x00–0x1F except HTAB, and 0x7F).
  - Refuse a leading or trailing SP/HTAB.
  - Refuse obs-text (0x80–0xFF): RFC 9110 says new values SHOULD be VCHAR/SP/HTAB, and ASCII-only avoids charset ambiguity.
  - Validate names as `token`, then lowercase them for the HTTP/2 and HTTP/3 encoders (uppercase is malformed there).
  - Refuse names beginning with `:` and warn on `_`.
- Validate after any variable expansion, not only at load. Better, allow no request-derived variables in response header values at all. Then every value is checked once at load and the hot path cannot inject.
- **1 KB is too small for CSP and Permissions-Policy.** The OWASP Permissions-Policy value alone is about 600 bytes, and real CSPs with many sources commonly exceed 1 KB (unverified statistic). A per-value cap of 4–8 KB, plus a per-site cap on total added bytes (e.g. 16 KB, below common HTTP/2 client limits), fits better. The server's own HTTP/2 and HTTP/3 encoders should stay below the peer's advertised `SETTINGS_MAX_HEADER_LIST_SIZE` / `MAX_FIELD_SECTION_SIZE` where known.
- HTAB is legal inside field values but is removed by the URL parser. So Location (and Refresh or Link URLs) need stricter rules than general fields; see the redirect join notes below.

### Gaps
- Browser response-header size limits were not verified in this session. Chromium's 256 KB header buffer and Firefox's limit are from memory, so unverified and omitted.

## Multi-tenant risks when a less-privileged admin sets response headers, and an evaluation of agensio's header and redirect proposal

### Takeaway
On a host serving many sites, some header names reach beyond the site that sets them:
- **Set-Cookie** with a parent `Domain`, and **Clear-Site-Data** `"cookies"`, both act on the whole registrable domain.
- **Strict-Transport-Security; includeSubDomains** binds all subdomains.
- **Alt-Svc** redirects the origin's traffic to another host or port.
- **Service-Worker-Allowed** removes the path restriction a service worker relies on.

Others break the protocol or the server's own logic: framing fields, validators, `Content-Encoding`, `Vary`, `Date`, `Location`. CSP added as an extra header only tightens. Replacing an application's CSP can loosen it.

### Cited Findings
- Cookies: "the user agent will accept a cookie with a Domain attribute of "example.com" from foo.example.com". The UA rejects a Domain that does not domain-match the request host. Public suffixes are rejected: "This step is essential for preventing attacker.com from disrupting the integrity of example.com". "Cookies do not provide integrity guarantees for sibling domains (and their subdomains)… In the worst case, bar.example.com will be unable to distinguish this cookie from a cookie it set itself" — [RFC 6265 §4.1.2.3, §5.3, §8.6](https://www.rfc-editor.org/rfc/rfc6265.html#section-8.6)
- Clear-Site-Data `"cookies"` clears cookies for the whole registered domain (e.g. `www.example.com` and `more.subdomains.example.com`), because "cookies ignore the same-origin policy" (§3.1, §4.2.4). `"storage"` covers localStorage, sessionStorage, IndexedDB and service worker registrations. `"cache"` covers the network cache and prerendered pages. `"executionContexts"` reloads pages. `"*"` means all types including client hints. It is honored only for "a priori authenticated" (secure) URLs and network responses (§5.1, §5.2). "the web developer (and not the user) is in control of when the clearing event is triggered" (§6.1). The spec is an Editor's Draft dated 2023-11-10 — [W3C Clear Site Data ED](https://w3c.github.io/webappsec-clear-site-data/)
- Service workers: a script at `/~bob/sw.js` may control `/~bob/` but not `/` or `/~alice/`. "This provides some protection for sites that host multiple-user content in separated directories on the same origin… not considered a hard security boundary… Servers can remove the path restriction by setting a Service-Worker-Allowed header" — [Service Workers §6.5 Path restriction](https://w3c.github.io/ServiceWorker/#path-restriction)
- Alt-Svc:
  - "an attacker that can inject alternative services and listen at the advertised port is able to hijack an origin". Shared servers may let users run services on "less-privileged ports" (§9.1).
  - Changing hosts is "an opportunity for attackers to hijack communication" (§9.2).
  - Clients need a certificate valid for the origin (§2.1, §9.2). `clear` invalidates all alternatives, and the default freshness is 24 h (§3, §3.1).
  - Servers should consider not advertising for insecure schemes (§9.5).

  — [RFC 7838](https://www.rfc-editor.org/rfc/rfc7838.html#section-9)
- CSP: when multiple policies are present, "each must be enforced"; "adding additional policies to the list of policies to enforce can only further restrict the capabilities of the protected resource" — [CSP Level 3 ED §8.1](https://w3c.github.io/webappsec-csp/#multiple-policies)
- Deprecated headers: Expect-CT "Do not use it". HPKP "Do not use" (removed from Chromium 2018). X-XSS-Protection: set `0` or omit — [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- Date is mandatory on 2xx/3xx/4xx from an origin with a clock — [RFC 9110 §6.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.1)
- Hop-by-hop and framing fields are malformed in HTTP/2 and HTTP/3 — [RFC 9113 §8.2.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2), [RFC 9114 §4.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2)
- WHATWG URL parsing for special schemes (http, https): in the relative state, a `\` counts like `/` ("invalid-reverse-solidus"). In the relative slash state, `/` or `\` leads to the authority state. So `//x`, `/\x`, `\/x` and `\\x` all name host `x`. Tab, CR and LF anywhere are removed before parsing — [URL Standard, relative state / relative slash state](https://url.spec.whatwg.org/#relative-slash-state)
- Fetch follows a redirect only to HTTP(S) schemes, allows 20 redirects at most, and removes `Authorization` on a cross-origin hop — [Fetch §4.5](https://fetch.spec.whatwg.org/#http-redirect-fetch)

### Inferences
**Header names: refuse, warn or allow**

Hop-by-hop, framing and other server-owned fields (refuse):

| Header | Decision | Reason |
|---|---|---|
| Connection, Keep-Alive, Proxy-Connection, Transfer-Encoding, Upgrade, TE, Trailer, HTTP2-Settings | refuse | Malformed in HTTP/2 and HTTP/3 (RFC 9113 §8.2.2); framing |
| Content-Length, Content-Range | refuse | Framing and the Range engine are the server's |
| Content-Encoding | refuse | Agensio sets it for the precompressed twins. A wrong value makes the body undecodable or double-decoded |
| ETag, Last-Modified, Age | refuse | Validators drive the server's own 304 logic (RFC 9110 §15.4.5); Age belongs to caches |
| Date | refuse | MUST from the origin |
| Location | refuse | The redirect rules own it; a second Location is not recoverable (§10.2.2) |
| `:`-pseudo-headers | refuse | Pseudo-headers |
| Vary | allow append only; refuse set/remove | Removing `Accept-Encoding` from Vary on a precompressed answer lets a shared cache serve `br` bytes to a client that did not ask |

Cross-tenant fields (refuse):

| Header | Decision | Reason |
|---|---|---|
| Set-Cookie | refuse | The RFC 9110 §5.3 multi-line exception; parent-Domain cookie tossing onto sibling tenants (RFC 6265 §8.6) when tenants share a registrable domain not on the Public Suffix List; session fixation |
| Clear-Site-Data | refuse, or allow only on an exact path with a warning | `"cookies"` and `"*"` clear the registrable domain, so they hit sibling sites; on a prefix it logs users out on every page |
| Alt-Svc | refuse | Conflicts with agensio's own h3 advertisement; `clear` would withdraw it; RFC 7838 §9.1–9.2 hijack surface |

Authentication fields (refuse):

| Header | Decision | Reason |
|---|---|---|
| WWW-Authenticate, Proxy-Authenticate, Authentication-Info | refuse | Owned by `[[site.auth]]` |

Typed or validated fields (allow with checks):

| Header | Decision | Notes |
|---|---|---|
| Strict-Transport-Security | typed field | Sent only on TLS; one line; directives once; warn on `includeSubDomains` with the sibling sites it binds; refuse `preload` without max-age ≥ 1 year and includeSubDomains |
| Content-Security-Policy, Content-Security-Policy-Report-Only | allowed | Explain that `set` replaces an application's own CSP (which may loosen it), while a second header tightens only (CSP3 §8.1). The safe default for an upstream answer is "add as an extra policy" or "default" (only if absent) |
| Access-Control-* | validated | As in the CORS section |
| X-Frame-Options | validated | `DENY` or `SAMEORIGIN` only (ALLOW-FROM obsolete); suggest CSP `frame-ancestors` |

Warn:

| Header | Warning |
|---|---|
| Service-Worker-Allowed | It widens a service worker's scope (SW §6.5); only meaningful on the script's exact path |
| X-XSS-Protection | Any value other than `0` |
| COEP `require-corp`, COOP `same-origin` | May break embeds and popup sign-in |
| Refresh | A redirect outside the redirect rules; suggest a redirect rule |

Refuse or warn as obsolete:

| Header | Decision |
|---|---|
| Expect-CT, Public-Key-Pins, Public-Key-Pins-Report-Only | Refuse as obsolete. HPKP can lock users out |

Allow:

| Header | Notes |
|---|---|
| Link | Harmful only to the site's own pages; validate syntax |
| Cache-Control, Referrer-Policy, X-Content-Type-Options, Permissions-Policy, Cross-Origin-Resource-Policy | Validate syntax where cheap |
| `remove` of Server, X-Powered-By, X-Redirect-By, X-Generator | Any OWASP removal-list name |

**The proposal's refused list**

The proposed list (hop-by-hop, framing, Date, Location, Set-Cookie, WWW-Authenticate, Alt-Svc) is correct as far as it goes. The additions above that matter most are, by consequence:
- Content-Encoding, ETag and Last-Modified, which break correctness.
- Clear-Site-Data, which crosses tenants.
- HSTS on plain HTTP, which is a MUST NOT.
- `Vary` set/remove, which enables cache poisoning.
- Content-Range, Trailer and Proxy-Authenticate.

**Set, default and remove semantics**

- Match names case-insensitively.
- `set` on a singleton replaces every existing line (RFC 9110 §5.3).
- `default` (add if absent) is the safe verb for security headers when the application may already send one.
- `remove` should apply to upstream/PHP answers as well as to agensio's own fields where allowed (Server).
- Values are fixed at load time: no request-derived variables, so CWE-113 is closed by construction.

**Redirect rules**

The redirect join is the whole CWE-601 surface. "Cannot produce `//host`" must be widened:
- Neither the configured `to` nor the joined result may begin with `//`, `/\`, `\/` or `\\`.
- The remainder must be copied from the raw (still percent-encoded) request target, never the decoded path, and re-encoded so the result is a valid `URI-reference`. In particular `\` becomes `%5C`, SP becomes `%20`, and CTLs and `"<>^`{|}` are percent-encoded. CR, LF and NUL can then never appear, and a tab, which is legal in a field but stripped by the URL parser, can never turn `/\t/evil` into `//evil`.
- The robust check, as OWASP recommends, is to parse the final Location with the same rules as the WHATWG parser. Then assert that a path target stays a path-absolute reference with no authority, and that a URL target keeps the configured scheme, host and port.
- Refuse `to` URLs with userinfo (`https://user@host`), non-http(s) schemes (Fetch rejects them anyway) and fragments, unless an explicit "drop fragment" option is set.

**Further redirect additions**
- An optional 303.
- A bounded default `Cache-Control: max-age` on 301/308 (Chromium caches them forever otherwise).
- The site's HSTS header on redirects served over HTTPS.
- A config-time loop check (a `to` that falls under its own `from` prefix, or two rules pointing at each other; clients stop at 20 hops, or 5 in old clients).
- Date on every redirect.
- A short HTML body with the target HTML-escaped (and none for HEAD).
- A warning when the query is forwarded to a different host.

### Gaps
- Whether the hosting operators' domains (e.g. a shared `*.agensio-host.example`) would be on the Public Suffix List, which makes parent-Domain cookies impossible, depends on the deployment. PSL private-section rules were not fetched.
- The status of RFC 6265bis (draft-ietf-httpbis-rfc6265bis) as of 2026 was not verified. Its cookie-prefix (`__Host-`) rules would be the modern defence against cookie tossing.
- Clear-Site-Data browser support details (Safari's partial support, Chrome's handling of `"cache"`) were not verified. The spec itself is still an Editor's Draft (2023-11-10).
- No source was found that lists "headers a hosting panel should refuse". The refuse and warn table above is derived from the specifications cited, not taken from an existing panel's policy.
