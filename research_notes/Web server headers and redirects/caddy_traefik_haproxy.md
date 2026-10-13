# Response header manipulation and redirects in Caddy, Traefik and HAProxy

Versions current on 2026-10-12: Caddy v2.11.7 (released 2026-10-03, [release](https://github.com/caddyserver/caddy/releases/tag/v2.11.7)), Traefik v3.7.14 (2026-10-06, [release](https://github.com/traefik/traefik/releases/tag/v3.7.14)), HAProxy 3.4 LTS (3.4.0 on 2026-06-03, 3.4.6 on 2026-09-28), 3.3 stable and 3.2 LTS, with 3.5-dev in development ([haproxy.org](https://www.haproxy.org/)). Method: the Caddy and Traefik documentation was read from the Markdown sources that build the official pages (caddyserver/website and traefik/traefik `docs/`). The HAProxy manual was read from `doc/configuration.txt` on master, which is 3.5-dev. Behaviour was checked against each project's Go or C source on master as of 2026-10-12. The citations link the official pages, with source files where the behaviour comes from code.

## Caddy: the `header` directive (operators, defer, proxied responses, Server header, header_down)

### Takeaway
Caddy's `header` has set, `+`add, `-`delete (with wildcards), `?`default, `>`deferred set, and regex replace. The catch is timing. A plain set is written into the header map when the handler runs, before the response exists. The reverse proxy then appends the upstream's own fields, so a plain set produces duplicate fields. Only deferred operations (`-`, `?`, `>`, `defer`, `match`) run when the response is written. They are lost when a later handler returns an error, such as a `file_server` 404 or a `basic_auth` 401.

### Cited Findings
- Syntax: `header [<matcher>] [[+|-|?|>]<field> [<value>|<find>] [<replace>]] { ... [defer] match <inline_response_matcher> }`. No prefix sets (overwrites). `+` adds ("header fields can appear more than once"). `-` deletes, and "the field may use prefix or suffix `*` wildcards to delete all matching fields". `?` sets a default: "The field is only written if it doesn't yet exist". `>` sets and enables `defer`. Three arguments do an RE2 regex find/replace with `$1` captures, and an empty replacement removes the matched text. — [Caddy header docs](https://caddyserver.com/docs/caddyfile/directives/header)
- Timing: "By default, header operations are performed immediately unless any of the headers are being deleted (`-` prefix) or setting a default value (`?` prefix). In those cases, the header operations are automatically deferred until the time they are being written to the client." `defer` is switched on automatically for `-`, `?`, `>`, and when any `match` condition is present. — [Caddy header docs](https://caddyserver.com/docs/caddyfile/directives/header)
- `?` is split into its own handler. Under the hood it is a response matcher (`Require`) that applies the operations only if the field is not yet set. — [Caddy header docs](https://caddyserver.com/docs/caddyfile/directives/header)
- Proxied responses: to override the upstream's Cache-Control, "enabling `defer` is necessary to ensure the header is set _after_ the proxy writes its headers" (example `header /no-cache* >Cache-Control no-cache`). — [Caddy header docs](https://caddyserver.com/docs/caddyfile/directives/header)
- Source: a non-deferred operation runs `h.Response.ApplyTo(w.Header(), repl)` at once. A deferred one or one with `Require` wraps the ResponseWriter, and the wrapper applies the operations in `WriteHeader`. The module comment says: "Note that deferred changes do not take effect if an error occurs later in the middleware chain." — [caddy modules/caddyhttp/headers/headers.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/headers/headers.go)
- Within one operation set, `ApplyTo` runs in a fixed order: delete-all (`-*`) first, then add, then set, then the other deletes. A set with several values is joined with "," except `Set-Cookie`, which becomes several fields. — [headers.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/headers/headers.go)
- The deferred wrapper's `WriteHeader` applies its own operations and then calls the wrapped writer's `WriteHeader`. Deferred operations of nested `header` handlers therefore run innermost first, and the outermost (earliest in the chain) runs last and wins. — [headers.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/headers/headers.go)
- Reverse proxy copy: `copyHeader(rw.Header(), res.Header)` uses `dst.Add` for every upstream value. An already-present field therefore gains the upstream's values instead of being replaced. — [caddy reverseproxy.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/reverseproxy/reverseproxy.go)
- Two field-level reports of the resulting duplicates:
  - A user setting `Server` got it twice, Caddy's value and the upstream's. Matt Holt: "You can override headers from the upstream by using header_down inside the reverse_proxy directive", or "defer in the header directive to apply the changes after the reverse proxy sets the header". He also said: "header with defer overwrites pretty much any changes to the header while handling the request, whereas header_down in the reverse proxy affects only the proxied headers." — [caddy.community: Repeated Server Header (2024)](https://caddy.community/t/repeated-server-header/24830)
  - Duplicate `cache-control` fields when a `header` set met an upstream Cache-Control. — [caddy.community: Header directive is not mutually exclusive (2020)](https://caddy.community/t/header-directive-is-not-mutually-exclusive/8146)
- Server header: Caddy sets `Server: Caddy` on every request at the top of `ServeHTTP` (`h["Server"] = serverHeader`). — [caddy server.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/server.go)
- When proxying, `reverse_proxy` deletes Caddy's own Server and adds `Via: <proto> Caddy` ("delete our Server header and use Via instead (see #6275)"). The upstream's Server then passes through. — [reverseproxy.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/reverseproxy/reverseproxy.go); [issue #6275 "`reverse_proxy` leads to duplicate `Server` headers", closed 2024-04-26](https://github.com/caddyserver/caddy/issues/6275)
- `header_down` sets (no prefix), adds (`+`), deletes (`-`) or replaces (regex) "in a response header coming downstream from the backend". `header_up` does the same for request headers, with wildcard deletes such as `header_up -Some-*` and `-*`. — [Caddy reverse_proxy docs, Headers](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#headers)
- In code, `header_down` operations run on the upstream response's own header map before it is copied. They are optionally gated by a response matcher (`Require.Match(res.StatusCode, res.Header)`). — [reverseproxy.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/reverseproxy/reverseproxy.go)
- Response matchers in a `header` block filter on the outgoing response:
  - `match status 2xx`.
  - `match header Accept-CH "*Sec-CH-...*"`.
  - The documented example deletes Cache-Control and CDN-Cache-Control on `match status 500` "to prevent caching of error responses".

  — [Caddy header docs](https://caddyserver.com/docs/caddyfile/directives/header)
- Pitfall, inline path matchers: inline matchers must start with `/`. Writing `header *.html Content-Type text/html` silently parses `*.html` as the field name. A suffix match needs a named matcher (`@html path *.html`). — [caddy.community thread 13858](https://caddy.community/t/how-to-override-reverse-proxy-response-headers-with-path-matcher/13858)

### Inferences
- Caddy's `?` (deferred, applied only if absent at write time) corresponds to agensio's `default`. A deferred set (`>`) corresponds to agensio's `set` ("replace the application's field"). Caddy's *plain* set does not replace an upstream field, it duplicates it. Caddy users must learn `>` or `header_down` to get the replace semantics agensio proposes by default. This supports making agensio's `set` act on the final answer.
- Putting one delete in a block silently defers *all* operations of that block, which changes which rule wins (see the next section). A design whose operations all act on the final response avoids this mode switch entirely.

### Gaps
- Not verified: the Caddy release that introduced `>` and `match` in the Caddyfile `header` directive. The current docs carry no version note.

## Caddy: matchers, directive order, combining rules, error responses (handle_errors)

### Takeaway
Same-named directives are sorted most-specific-path first, and `header` is not terminal, so every matching `header` directive runs. With immediate sets the *least* specific one runs last and overwrites the specific one. With deferred operations the *most* specific (outermost) is applied last and wins. Caddy's own docs say to use `route` or `handle` blocks when this matters. Error responses (handler errors such as a file_server 404 or a basic_auth 401) go to a separate `handle_errors` route on the unwrapped writer. That route keeps the immediate header sets but loses every deferred operation.

### Cited Findings
- Built-in order (excerpt): `tracing, map, vars, fs, root, log_append, log_skip, log_name, header, copy_response_headers, request_body, timeouts, redir, method, rewrite, uri, try_files, basic_auth, forward_auth, request_header, encode, push, intercept, templates, invoke, handle, handle_path, route, abort, error, copy_response, respond, metrics, reverse_proxy, php_fastcgi, file_server, acme_server`. The order can be changed with the `order` global option or a `route` block. — [Caddy directives: Directive order](https://caddyserver.com/docs/caddyfile/directives#directive-order); [Caddy global options: order](https://caddyserver.com/docs/caddyfile/options#order)
- Sorting rules, all from [Caddy directives: Sorting algorithm](https://caddyserver.com/docs/caddyfile/directives#sorting-algorithm):
  - Same-named directives with a single path matcher are sorted "from most specific to least specific", by path length ignoring a trailing `*`. A path without `*` sorts higher than the same path with one.
  - Directives with named or multi-path matchers keep their file order, and single-path directives are not sorted past them.
  - A directive with no matcher is sorted last.
  - `vars` has its ordering "reversed, because it involves setting values which can overwrite each other, so the most specific matcher should be evaluated last". `header` gets no such reversal.
  - `route` preserves literal order.
- The header docs show "Multiple header directives that are intended to be mutually-exclusive" wrapped in `route { header Cache-Control max-age=3600 ; header /static/* Cache-Control max-age=31536000 }`. — [Caddy header docs](https://caddyserver.com/docs/caddyfile/directives/header)
- `handle` blocks are mutually exclusive, and their contents are reordered normally. `route` is not reordered. — [Caddy route docs](https://caddyserver.com/docs/caddyfile/directives/route)
- Field report (Caddy 2.0): inside `route`, a generic block `header { -server; Cache-Control "max-age=604800, public" }` followed by `header /libs/* { Cache-Control "public, max-age=31536000, immutable" }` returned the *generic* value for `/libs/foo.js`. The `-server` made the whole first block deferred. Without the `-server`, the result was duplicate Cache-Control fields from the upstream instead. — [caddy.community thread 8146](https://caddy.community/t/header-directive-is-not-mutually-exclusive/8146)
- Path matcher semantics, all from [Caddy request matchers: path](https://caddyserver.com/docs/caddyfile/matchers#path):
  - "Path matches are exact but case-insensitive."
  - `*` may appear only at the end (prefix), at the start (suffix), on both sides (substring), or in the middle (glob).
  - "`/foo*` will match `/foo`, `/foobar`, `/foo/`, and `/foo/bar`, but `/foo/*` will not match `/foo` or `/foobar`".
  - Paths are cleaned of dot segments, and duplicate slashes are merged unless the pattern has them.
  - The path is URL-decoded except at positions where the pattern itself has escapes.
- handle_errors: "When the normal HTTP request handlers return an error, normal processing stops and the error handlers are invoked". The directive can be repeated with status codes such as `404 410` or `5xx`. Its placeholders are `{err.status_code}`, `{err.status_text}`, `{err.message}`, `{err.trace}` and `{err.id}`. Also: "certain directives, for example `reverse_proxy` which may write a response with an HTTP status which is classified as an error, will _not_ trigger the error routes." — [Caddy handle_errors docs](https://caddyserver.com/docs/caddyfile/directives/handle_errors)
- Source: on an error, `ServeHTTP` calls `s.errorHandlerChain.ServeHTTP(w, r)` with the server's own `w`, not any handler's wrapper. Without error routes it writes only `w.WriteHeader(errStatus)`. — [caddy server.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/server.go)
- `basic_auth` fails with `caddyhttp.Error(http.StatusUnauthorized, ...)` ([caddyauth.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/caddyauth/caddyauth.go)). `file_server` returns `caddyhttp.Error(http.StatusNotFound, ...)` ([staticfiles.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/fileserver/staticfiles.go)). Both therefore take the error path.
- Issue #6689 (Caddy 2.8.4, closed 2024-11-13): `header { Foo "Test" }` plus `header { -Foo }`. A 200 has no `Foo`, but a file_server 404 still carries `Foo: Test`. Matt Holt: "Deleting a header is a deferred operation, i.e. performed when the response is written, but in an error case, the error bubbles back up to the HTTP server which executes a separate error handling chain... Use the handle_errors directive to manipulate the response in case of an error." Closed as working as intended. — [caddy issue #6689](https://github.com/caddyserver/caddy/issues/6689)

### Inferences
- Caddy's default combination is the opposite of agensio's "all matching rules, shortest path first". For immediate sets, the general rule overwrites the specific one. Which rule wins also flips between immediate and deferred operations. Caddy's maintainers fixed exactly this for `vars` ("most specific matcher should be evaluated last") but not for `header`, and recommend `route`/`handle`. That is strong support for agensio's deterministic rule: shortest prefix first, longer prefix (and exact) last, so the longest wins.
- Caddy only reaches "headers on every answer" with each policy written twice, once in the normal route with `>`/`-` and once in `handle_errors`. Even then the immediate sets leak into error answers while the deferred deletes do not. The 404 in issue #6689 shows `Foo` surviving where the user expected it removed. This supports agensio applying header rules uniformly to error answers. A side inference, not tested: `header -Server` will not remove `Server: Caddy` from error answers unless it is repeated in `handle_errors`.
- Caddy's documented "prevent caching of error responses" example shows the opposite risk: a site-wide `Cache-Control` or `CDN-Cache-Control` applied to 5xx answers. If agensio applies `set` to every answer, a long `Cache-Control` rule would also land on 404/500. Agensio may want either a status condition or documentation of that consequence.

### Gaps
- Not checked whether `handle_errors` responses produced with `respond` or `file_server` keep immediate header sets in every case. Issue #6689 shows it for the no-error-routes case only.

## Caddy: `redir`

### Takeaway
`redir [<matcher>] <to> [<code>]`. The default is 302. `permanent` gives 301. `html` gives a 200 HTML/JS page with no Location. Any 3xx or 401 is accepted. Neither the path remainder nor the query is kept unless the target contains `{uri}` (path plus query). `redir` sorts "very early", before rewrites and before `basic_auth`/`forward_auth`.

### Cited Findings
- Code values (all from [Caddy redir docs](https://caddyserver.com/docs/caddyfile/directives/redir)):
  - "A positive integer in the `3xx` range, or `401`".
  - `temporary` (302, "this is the default").
  - `permanent` (301).
  - `html` ("useful for redirecting browsers but not API clients").
  - A placeholder.

  The docs note that 301/302 "allow the user agent to change the method", recommend 307/308 when the method must be kept, and say "Caddy uses `308` as the status code in its automatic HTTP to HTTPS redirects".
- Examples: `redir https://example.com{uri}` preserves the URI. `redir /about-us /about` redirects one page. The docs say its order "is very early" because a redirect means the request is "rejected as-is". — [Caddy redir docs](https://caddyserver.com/docs/caddyfile/directives/redir)
- Parser (`parseRedir`), from [caddyconfig/httpcaddyfile/builtins.go](https://github.com/caddyserver/caddy/blob/master/caddyconfig/httpcaddyfile/builtins.go):
  - `permanent` → "301"; `temporary` or empty → "302".
  - `html` writes a body with `window.location.replace` plus `<meta http-equiv="refresh">`, the target HTML-escaped, `Content-Type: text/html; charset=utf-8`, and status 200 ("don't redirect non-browser clients").
  - Any other integer must be 300-399 or 401. A 401 with Location is for XHR clients that "eat" 3xx.
  - The Location value is exactly `<to>` after placeholder expansion.
- `{uri}` maps to `{http.request.uri}`, which in code is `req.URL.RequestURI()` (path plus query). `{path}` and `{query}` are separate. — [Caddy concepts: placeholders](https://caddyserver.com/docs/caddyfile/concepts#placeholders); [caddy replacer.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/replacer.go)
- Bulk mapping in Caddy is the `map` directive. It is evaluated lazily ("Mapped placeholders are not evaluated until they are used, so even for very large mappings, this directive is quite efficient"), with `~` for regex inputs. — [Caddy map docs](https://caddyserver.com/docs/caddyfile/directives/map). The handler scans its mappings linearly (`for _, m := range h.Mappings`). — [caddy map.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/map/map.go)
- Ordering pitfall: `redir` sorts before `file_server`. A catch-all `redir` with a specific `file_server /specific.html` needs a `route` block to make the file win. — [Caddy route docs](https://caddyserver.com/docs/caddyfile/directives/route)

### Inferences
- Caddy's defaults argue against agensio's choices in two places, and both are known sources of confusion:
  - The 302 default. Agensio requires a status.
  - Dropping both the remainder and the query unless `{uri}` is written. Agensio keeps the remainder and query by default.
- Caddy agrees with agensio on order: redirects run before `basic_auth`/`forward_auth`, so a moved path answers 3xx without asking for credentials. Header directives sort before `redir`, so immediate and deferred header operations both apply to redirect answers. A redirect is a normal response, not an error.
- Since `{uri}` contains the full original path, a Caddy prefix move such as `/old/* → /new/<rest>` needs `handle_path` plus `{uri}` or a regex matcher. Caddy has no built-in "remainder" concept.

### Gaps
- No published benchmark found for Caddy with thousands of `redir`/`map` entries.

## Traefik: the headers middleware (customResponseHeaders, removal, security options, CORS)

### Takeaway
Traefik's `headers` middleware applies `customResponseHeaders` *after* the backend answers. Each entry is a set (replace) or, with an empty value, a delete. There is no add and no "default only if absent". Security options (via unrolled/secure) and CORS are typed fields that also overwrite backend values. The modifier runs on whatever response passes through the middleware's position in the chain. An outer middleware therefore has the last word on the response path, so entry-point middlewares override router middlewares.

### Cited Findings
- "Custom headers will overwrite existing headers if they have identical names." An empty value removes: `X-Custom-Response-Header: "" # Removes`. — [Traefik headers middleware](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/headers/)
- Source, `PostRequestModifyResponseHeaders`: "This method is called AFTER the response is generated from the backend and can merge/override headers from the backend response". It loops `if value == "" { res.Header.Del(header) } else { res.Header.Set(header, value) }`. `CustomResponseHeaders` is a `map[string]string`, so one value per field. — [traefik pkg/middlewares/headers/header.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/headers/header.go); [pkg/config/dynamic/middlewares.go](https://github.com/traefik/traefik/blob/master/pkg/config/dynamic/middlewares.go)
- The response modifier runs in `WriteHeader` of a wrapping ResponseWriter (`NewResponseModifier`), once, for non-1xx statuses. — [traefik pkg/middlewares/response_modifier.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/response_modifier.go)
- Security options, all from [Traefik headers middleware](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/headers/):
  - HSTS: `stsSeconds`, `stsIncludeSubdomains`, `stsPreload`, and `forceSTSHeader` ("Adds STS header for HTTP connections").
  - Framing and sniffing: `frameDeny` (X-Frame-Options DENY), `customFrameOptionsValue` (overrides frameDeny), `contentTypeNosniff`.
  - XSS filter: `browserXssFilter`, `customBrowserXSSValue`.
  - Policies: `contentSecurityPolicy`, `contentSecurityPolicyReportOnly`, `referrerPolicy`, `permissionsPolicy`, `publicKey` (HPKP).
  - Host and SSL options: `allowedHosts`, `hostsProxyHeaders`, `sslProxyHeaders`, `isDevelopment`.

  Details are delegated to unrolled/secure.
- unrolled/secure, from [unrolled/secure secure.go](https://github.com/unrolled/secure/blob/v1/secure.go):
  - `ModifyResponseHeaders` applies the computed security headers with `res.Header.Set`, which overwrites backend values.
  - STS is emitted only when `STSSeconds != 0 && (ssl || ForceSTSHeader) && !IsDevelopment`.
- Traefik builds the middleware as "HeaderMiddleware -> SecureMiddleWare -> next", each with its own response modifier. — [traefik headers.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/headers/headers.go); [secure.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/headers/secure.go)
- CORS: `accessControlAllowCredentials`, `accessControlAllowHeaders`, `accessControlAllowMethods`, `accessControlAllowOriginList`, `accessControlAllowOriginListRegex`, `accessControlExposeHeaders`, `accessControlMaxAge`, `addVaryHeader`. "If CORS headers are set, then the middleware does not pass preflight requests to any service, instead the response will be generated and sent back to the client directly". For `accessControlAllowOriginList`: "If this value is set by a backend service, it will be overwritten by Traefik", and `null` is no longer supported. — [Traefik headers middleware](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/headers/)
- In code, a preflight is `OPTIONS` with both `Access-Control-Request-Method` and `Origin` and gets `200` with `Content-Length: 0`. A wildcard origin plus credentials echoes the request's Origin ("Can't use wildcard with credentials"). `addVaryHeader` appends `Origin` to an existing Vary. — [traefik header.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/headers/header.go)
- Combining levels, issue #12195 (closed 2025-10 as a question): an entry-point middleware set `Content-Security-Policy`, and a router middleware's different CSP never reached the client. Maintainer: "the entryPoint middleware is executed before the router's ones and when the response goes downstream, the entryPoint middleware is setting the header after the router middleware"; "it is not possible to override a response header set by the entry point middleware". — [traefik issue #12195](https://github.com/traefik/traefik/issues/12195)
- Entry-point `http.middlewares` "are prepended by default to the list of middlewares of each router associated to the named entry point". They "will take effect only if the rule matches", and they "are applied in the same order as their declaration". — [Traefik entrypoints](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/)
- "Router-level: Applied to all requests matching the router's rule, before forwarding to the service. Service-level: ... When both are configured, router middlewares execute first, followed by service middlewares." — [Traefik middleware overview](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/overview/)
- Open issue #11957 (2025): the `errors` (custom error page) middleware does not forward chosen headers from the error-page service to the client, for example `WWW-Authenticate` for basic auth. A PR (#12858) proposes configurable forwarding. — [traefik issue #11957](https://github.com/traefik/traefik/issues/11957); [PR #12858](https://github.com/traefik/traefik/pull/12858)

### Inferences
- Traefik's semantics match agensio's `set` (always replace the backend's field after the response) and `remove`. Traefik has no `default`, so an operator who wants "HSTS unless the app sets its own" cannot express it. Agensio's `default` fills a real gap.
- "Errors" coverage follows from the wrapper design (inferred from the source, not tested). The middleware applies to any response written *downstream* of it: the backend's answer, Traefik's own 502/504 from the proxy, a redirect or 401 from a middleware listed *after* it. It does not apply to a response written by a middleware listed *before* it, such as a redirectScheme placed first, nor to the 404 of a request no router matched.
- So in Traefik, "headers on every answer" depends on the operator's chain order. Agensio's fixed rule (header rules apply to every answer the site produces) removes that order dependence.
- Issue #12195 is a second example, after Caddy, where the general (outer, site-wide) rule silently beats the specific one. The user expected the reverse. This supports agensio's "longest match applied last".

### Gaps
- Not tested: whether Traefik's own 404 (no router matched) or a TLS/entry-point error can carry entry-point middleware headers. The docs say entry-point middlewares apply only when a router rule matches.
- I found no Traefik option or accepted proposal for "set only if absent" or "append a value". Absence was checked only in the current options table and the source.

## Traefik: redirectRegex, redirectScheme, chain order, router matching

### Takeaway
`redirectRegex` matches an RE2 regex against the full reconstructed URL (`scheme://host[:port]` plus the request URI, query included) and expands `${n}` into the target. Only a boolean `permanent` exists. The status then depends on the method: GET gets 302/301, and every other method (HEAD included) gets 307/308. `redirectScheme` is built on the same code. Order is the declared middleware chain, and routers are chosen by priority, which defaults to the length of the rule string.

### Cited Findings
- redirectRegex options: `regex` ("match and capture elements from the request URL"), `replacement`, and `permanent` (default false). Warning: "`$1x` is equivalent to `${1x}`, not `${1}x`... so use `${1}` syntax". In labels "all dollar signs need to be doubled for escaping". — [Traefik RedirectRegex](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/redirectregex/)
- Source, from [traefik pkg/middlewares/redirect/redirect.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/redirect/redirect.go) and [redirect_regex.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/redirect/redirect_regex.go):
  - `rawURL` joins scheme (https if TLS), Host, port and `req.RequestURI`, so the query string is part of the matched text.
  - If the regex does not match, the request passes to `next`.
  - If the rewritten URL equals the original, no redirect is sent; the request URL is replaced and passed on.
  - Status: `302` for GET, `307` otherwise. With `permanent`, `301` for GET, `308` otherwise. The body is `http.StatusText(status)`.
- The config struct comment reads "Permanent defines whether the redirection is permanent (308)", which does not match the code (301 for GET). An internal `StatusCode` field exists only "for supporting the NGINX annotations" and is not user-settable. — [traefik dynamic/middlewares.go](https://github.com/traefik/traefik/blob/master/pkg/config/dynamic/middlewares.go)
- redirectScheme options: `scheme` (required), `port` (a string), `permanent`. "For HTTP GET requests a 301 is returned, otherwise a 308". It relies on `X-Forwarded-Proto`, which is trusted only from a trusted last hop, and it drops `:80` and `:443` for the default ports. — [Traefik RedirectScheme](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/redirectscheme/); [redirect_scheme.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/redirect/redirect_scheme.go); [dynamic/middlewares.go](https://github.com/traefik/traefik/blob/master/pkg/config/dynamic/middlewares.go)
- Entry-point redirection: `http.redirections.entryPoint.to`, `.scheme` (default https), and `.permanent`, which **defaults to true**. Its priority is `MaxInt-1`. — [Traefik entrypoints](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/)
- Router rules (from [Traefik rules and priority](https://doc.traefik.io/traefik/reference/routing-configuration/http/routing/rules-and-priority/)):
  - Matchers: `Path` (exact), `PathPrefix`, `PathRegexp`. "`PathPrefix(`/products`)`" matches `/products/shoes` "but also `/products-for-sale`". Case-insensitive matching needs `PathRegexp(`(?i)^/products`)`.
  - Priority: "The priority is directly equal to the length of the rule, and so the longest length has the highest priority". `0` means the default. Negative priorities are allowed. Ties between providers are broken by `providers.precedence`.
- Issue #10690 ("RedirectRegex broken since update to v3.0", opened 2024-05): reported for Traefik 3.0.0 and reported working in v3.0.1. The issue is still open as an enhancement. — [traefik issue #10690](https://github.com/traefik/traefik/issues/10690)

### Inferences
- Traefik's method-dependent status is a deliberate safety choice: never turn a POST into a GET. Note, though, that `HEAD` gets 307/308 because the code tests only `GET`. Agensio's required status puts the choice on the operator. The note could state that 301/302 let clients change POST to GET (as Caddy's docs say).
- A `PathPrefix` that does not respect segment boundaries (`/products` matches `/products-for-sale`) is a classic pitfall. If agensio's prefix match covers whole segments, as its access rules already do, that is safer than Traefik's default.
- Because the regex sees the query string, a Traefik user who wants "keep the rest and the query" must capture it explicitly. Agensio's default of keeping remainder and query removes that work.
- A Traefik redirect only runs before auth if the operator lists it before `basicAuth` in the chain. Nothing enforces it.

### Gaps
- No public measurements found for Traefik with hundreds of redirectRegex middlewares. Per request, each middleware in the chain evaluates its own regex in sequence (inferred from code).

## HAProxy: http-response / http-after-response header actions

### Takeaway
HAProxy separates `http-response` rules, which run only on responses from servers, from `http-after-response` rules (since 2.2), which run on all responses including HAProxy's own redirects, denies, 401s, `return` and error pages. Early multiplexer-level errors are the exception. The actions are `set-header` (remove then add), `add-header`, `del-header` (exact, prefix, suffix, substring or regex on the name), `replace-header` (whole field line, regex) and `replace-value` (per comma element). Response rules run backend first, then frontend, each in declaration order, with conditions through ACLs.

### Cited Findings
- `http-after-response`: "Unlike http-response rules, these ones are applied on all responses, the server ones but also to all responses generated by HAProxy. These rules are evaluated at the end of the responses analysis, before the data forwarding phase." "Since these rules apply on responses, the backend rules are applied first, followed by the frontend's rules." "Note: Errors emitted in early stage of the request parsing are handled by the multiplexer at a lower level, before any http analysis. Thus no http-after-response ruleset is evaluated on these errors." Example: `http-after-response set-header Strict-Transport-Security "max-age=31536000"`. — [HAProxy configuration manual, http-after-response](https://docs.haproxy.org/3.4/configuration.html#4.2-http-after-response); [doc/configuration.txt (master)](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- `http-response`: rules "are evaluated in their declaration order when they are met in a frontend, listen or backend section. Since these rules apply on responses, the backend rules are applied first, followed by the frontend's rules." "The condition is evaluated just before the action is executed, and the action is performed exactly once." Rules from a named `defaults` section are evaluated before the proxy's own. — [HAProxy manual, http-response](https://docs.haproxy.org/3.4/configuration.html#4.2-http-response)
- Origin: the ruleset came from the commit "MEDIUM: http: Add a ruleset evaluated on all responses just before forwarding" (Feb 2020, 2.2 development cycle). The motivation given was adding headers to responses generated by the stats applet. — [haproxy commit 6d0c3df](https://github.com/haproxy/haproxy/commit/6d0c3dfac643d21478793759927dc7cfb8b1b3cd) (date and release taken from a search result summary; the commit page was not fetched)
- `set-header <name> <fmt>`: "does the same as the add-header action except that the header is first removed if it existed... or to force certain response headers such as 'Server' to hide external information. Note that the new value is computed before the removal so it is possible to concatenate a value to an existing header." — [HAProxy manual, set-header](https://docs.haproxy.org/3.4/configuration.html#4.4-set-header)
- `add-header <name> <fmt>` "appends an HTTP header field". "Note that header addition is performed immediately, so one rule might reuse the resulting header from a previous rule." — [HAProxy manual, add-header](https://docs.haproxy.org/3.4/configuration.html#4.4-add-header)
- `del-header <name> [-m <meth>]` "removes all HTTP header fields whose name is specified". Methods: `str`, `beg`, `end`, `sub`, `reg`, default exact. — [HAProxy manual, del-header](https://docs.haproxy.org/3.4/configuration.html#4.4-del-header)
- `replace-header <name> <match-regex> <replace-fmt>` matches each occurrence case-sensitively, replaces the whole value, accepts `\1` back-references, and is meant for values that contain commas (`Set-Cookie`, dates). Lists such as `Cache-Control` should use `replace-value`. — [HAProxy manual, replace-header](https://docs.haproxy.org/3.4/configuration.html#4.4-replace-header)
- All of set-header, add-header, del-header and replace-header are marked usable in HTTP Req, Res and Aft. — [HAProxy manual 4.3, Actions keywords matrix](https://docs.haproxy.org/3.4/configuration.html#4.3)

### Inferences
- HAProxy has no single "default if absent" action. The idiom is a condition on the response field, e.g. `http-response set-header X-Frame-Options DENY unless { res.hdr(X-Frame-Options) -m found }`. This is built from the documented condition semantics; no manual example shows it for this purpose.
- HAProxy keeps both flavours on purpose: server-only, which is safe for cache policy, and all-responses, which suits security headers. That users needed `http-after-response` at all, for example to get HSTS onto HAProxy's own redirects and error pages, supports agensio's choice that rules reach every answer by default.
- A design note: HAProxy's split also exists so that headers meant for application content do not land on generated errors. If agensio has a single scope, Cache-Control rules then hit 404/5xx answers too. This is the same caution as with Caddy's "prevent caching of error responses" example.
- Backend before frontend, with defaults before proxy within each, means the frontend (outer, broader) rule runs last and wins on the same field. This is the same "general wins" ordering as Traefik's entry points.

### Gaps
- Not verified exactly which HAProxy-internal responses are "early stage" mux errors. Presumably malformed requests rejected by the H1/H2 mux; the manual does not list them.

## HAProxy: redirects (location/prefix/scheme, codes, query, maps), ACL evaluation order, auth

### Takeaway
HAProxy redirects come in three forms:

- `prefix`: prepends to the full original URI, query included unless `drop-query`.
- `scheme`: scheme plus Host plus the URI with its query.
- `location`: an exact target; `keep-query` appends the original query, since 3.1.

The codes are 301, 302, 303, 307 and 308, with 302 the default. Bulk redirects use map files: exact keys sit in an ebtree, and prefix keys in a longest-prefix tree in current source. `http-request` rules (`redirect`, `auth`, `deny`, ...) run in declaration order. The legacy `redirect` keyword always runs after every `http-request` rule, then backend selection follows.

### Cited Findings
- From [HAProxy manual, redirect](https://docs.haproxy.org/3.4/configuration.html#4.2-redirect):
  - Syntax: `redirect location|prefix|scheme <x> [code <code>] <option> [{if|unless} <cond>]`.
  - `prefix`: "the 'Location' header is built from the concatenation of <pfx> and the complete URI path, including the query string, unless the 'drop-query' option is specified... if <pfx> equals exactly '/', then nothing is inserted before the original URI".
  - `scheme`: "<sch> with '://' then the first occurrence of the 'Host' header, and then the URI path, including the query string".
  - Codes: "Only codes 301, 302, 303, 307 and 308 are supported, with 302 used by default".
- Options, from [HAProxy manual, redirect](https://docs.haproxy.org/3.4/configuration.html#4.2-redirect):
  - `drop-query` affects prefix redirects only.
  - `append-slash` is used with drop-query, "a return code 301 is preferred".
  - `ignore-empty` skips the rule if the log-format result is empty, intended for "mass-redirects of known paths using a simple map".
  - `set-cookie NAME[=value]`, `set-cookie-fmt <fmt>`, and `clear-cookie NAME[=]` (Max-Age 0).
  - `keep-query`: in a location redirect, appends the original query with `&` if the location already has one.
  - Example: `http-request redirect code 301 location %[path,map_str(old-blog-articles.map)] ignore-empty`.
- `keep-query` was added in 3.1 (commit b2877db47, "Add option to keep query-string on a localtion-based redirect"). A crash when it was used on `http-response redirect` was fixed on 2026-08-06, to be backported to 3.1+. — [haproxy commit 1af2214](https://github.com/haproxy/haproxy/commit/1af221457bae61ea898e5c672a4fd65c1aefcca5)
- `http-request redirect` is "exactly the same as the 'redirect' statement except that it inserts a redirect rule which is processed in the middle of other 'http-request'... rules and that these rules use the Custom log format". "For responses, only the 'location' type of redirect is permitted", and the server transfer is interrupted. "This action is final". — [HAProxy manual, action redirect](https://docs.haproxy.org/3.4/configuration.html#4.4-redirect)
- Evaluation order: the config parser warns "a '...' rule placed after an 'http-request' rule will still be processed before" and the equivalents for `redirect`, `use_backend` and `use-server`. This encodes the fixed order tcp-request connection → session → content → monitor fail → http-request → redirect → use_backend → use-server. — [haproxy src/cfgparse-listen.c](https://github.com/haproxy/haproxy/blob/master/src/cfgparse-listen.c)
- `http-request` rules "are evaluated in their declaration order when they are met in a frontend, listen or backend section", and named-defaults rules come first. Manual example: `http-request allow if nagios`, `http-request allow if local_net auth_ok`, `http-request auth realm Gimme if local_net auth_ok`, `http-request deny`. — [HAProxy manual, http-request](https://docs.haproxy.org/3.4/configuration.html#4.2-http-request)
- `auth [realm <realm>]`: "stops the evaluation of the rules and immediately responds with an HTTP 401 or 407". It uses the proxy's error message (customisable with `errorfile`/`http-error`), and "all occurrences of the WWW-Authenticate header are removed and replaced". It is usable in HTTP Req only. — [HAProxy manual, action auth](https://docs.haproxy.org/3.4/configuration.html#4.4-auth)
- Maps: `map_<match>(<map_name>[,<default>])`, where `map` is an alias of `map_str`. Manual text: "IP addresses and strings are stored in trees, so the first of the finest match will be used. Other keys are stored in lists, so the first matching occurrence will be used." For ACL files: "HAProxy may load the lines into a binary tree, allowing very fast lookups. This is true for IPv4 and exact string matching." — [HAProxy manual, map converter](https://docs.haproxy.org/3.4/configuration.html#7.3.1-map); [7.1 ACL basics](https://docs.haproxy.org/3.4/configuration.html#7.1)
- Source on master disagrees in part with the manual: `PAT_MATCH_STR` is indexed with `pat_idx_tree_str`, and `PAT_MATCH_BEG` with `pat_idx_tree_pfx`. `pat_match_beg` uses `ebmb_lookup_longest`, so `map_beg` is a longest-prefix tree lookup. `sub`, `dir`, `dom`, `end` and `reg` stay lists. — [haproxy src/pattern.c](https://github.com/haproxy/haproxy/blob/master/src/pattern.c)
- Field data (2022): a redirect map with `http-request redirect location %[path,lower,map(/etc/haproxy/big-redir-map.txt)] code 301 if { path,lower,map(...) -m found }`. 0, 10k and 100k entries showed "negligible" difference, with "7k reqs/second even with 100k entries" on a small test system. Maintainer Lukas Tribus: "No issue, that is the use-case for map files". — [discourse.haproxy.org: Any issues with large map files?](https://discourse.haproxy.org/t/any-issues-with-large-map-files/7279)
- Maps can be changed at run time from rules (`http-request set-map(map.lst) ...`, `del-map`), as shown in the manual's examples. — [HAProxy manual, http-request](https://docs.haproxy.org/3.4/configuration.html#4.2-http-request)

### Inferences
- HAProxy's `redirect prefix` is the closest existing analogue to agensio's design: a fixed target prefix plus the original path and query kept by default, with opt-outs. HAProxy prepends the *whole* original URI, though. The "strip the matched prefix and keep the remainder" semantics agensio proposes needs `http-request redirect location` with a `regsub`/`replace-path` expression in HAProxy. No built-in does it.
- HAProxy's 302 default and `location` dropping the query by default (keep-query arrived only in 3.1) are the same defaults Caddy chose. Agensio's required status and default-kept query depart from both. The fact that HAProxy added `keep-query` late suggests the old default was a common nuisance; it is evidence of demand, not proof.
- On ordering, HAProxy's legacy `redirect` runs *after* all `http-request` rules, including `http-request auth`. Caddy's default order runs `redir` *before* `basic_auth`. Agensio's "redirects before access and password rules" matches Caddy, and HAProxy's `http-request redirect` placed first.
- One consequence for agensio to accept knowingly: redirect rules reveal to an unauthenticated client that a path moved, and where.
- For many redirects, HAProxy shows that exact and longest-prefix lookups in a tree scale to 100k entries at negligible cost. A sorted or trie structure keyed by path is the proven shape. Caddy's linear `map` scan and Traefik's one-regex-per-middleware chain are the anti-patterns at scale.

### Gaps
- Not verified: the HAProxy release in which `map_beg` moved from list to prefix tree, and whether `-i` (case-insensitive) prefix maps fall back to lists.
- Not verified: whether HAProxy's built-in error pages (errorfiles) carry a `Server` field.

## Cross-server summary against agensio's proposal (headers on errors, combining levels, performance)

### Takeaway
All three servers make "headers on error answers" an opt-in with a trap:

- Caddy: needs `handle_errors`, and deferred operations are lost on errors.
- Traefik: depends on chain position and needs a matched router.
- HAProxy: needs `http-after-response` instead of `http-response`.

All three also let the broader rule beat the more specific one in at least one common case: Caddy's sort of immediate sets, Traefik's entry-point middleware, and HAProxy's frontend after backend. Agensio's proposal (every answer, shortest path first so the longest wins, `set`/`default`/`remove` acting on the final answer, redirects with a required status that keep the remainder and query and run before access and passwords) avoids each of these documented pitfalls. The one point that argues for care is cache headers on error answers.

### Cited Findings
- Caddy: deferred deletes are not applied to file_server 404s ([caddy #6689](https://github.com/caddyserver/caddy/issues/6689)). The error chain runs on the unwrapped writer ([server.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/server.go)). Same-named directives sort most-specific first, with `vars` alone reversed ([sorting algorithm](https://caddyserver.com/docs/caddyfile/directives#sorting-algorithm)).
- Traefik: a router-level header cannot override an entry-point one ([traefik #12195](https://github.com/traefik/traefik/issues/12195)). Entry-point middlewares apply "only if the rule matches" ([entrypoints](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/)).
- HAProxy: `http-response` covers server responses only. `http-after-response` covers all, except early mux errors ([manual](https://docs.haproxy.org/3.4/configuration.html#4.2-http-after-response)). Response rules run backend first, then frontend ([manual](https://docs.haproxy.org/3.4/configuration.html#4.2-http-response)).
- Redirect defaults: Caddy 302 and the target as written ([redir](https://caddyserver.com/docs/caddyfile/directives/redir)). Traefik 302/307, or 301/308 with `permanent`, chosen by method ([redirect.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/redirect/redirect.go)). HAProxy 302, prefix keeping the URI and query, location keeping the query only with `keep-query` (3.1+) ([manual](https://docs.haproxy.org/3.4/configuration.html#4.2-redirect)).
- Operations available:

  | Server | Set | Add | Delete | Default if absent | Regex replace |
  |---|---|---|---|---|---|
  | Caddy | yes | `+` | `-`, wildcards | `?` | yes |
  | Traefik | yes | no | empty value | no | no |
  | HAProxy | set-header | add-header | del-header, `-m` | no built-in; condition idiom | replace-header, replace-value |

  Sources: [Caddy header](https://caddyserver.com/docs/caddyfile/directives/header), [Traefik headers](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/headers/), [HAProxy actions](https://docs.haproxy.org/3.4/configuration.html#4.4).

### Inferences
- **Support for agensio's `set` meaning "replace the application's field".** Traefik's and HAProxy's (`http-response set-header`) setters both act after the backend. Caddy's plain set duplicates the field and needs `>`.
- **Support for `default`.** Caddy alone offers it as a primitive, and it was important enough to get its own prefix. Traefik lacks it, and HAProxy needs a condition.
- **The missing `add`.** Agensio's proposal has no `add`. Caddy and HAProxy have one; Traefik does not and works around it for `Vary` with `addVaryHeader`. Multi-valued fields (`Link`, `Vary`, `Set-Cookie`) are the cases where operators have needed it.
- **Support for "every answer, including errors".** All three projects have issue threads where an operator expected exactly that and did not get it.
- **Argument for care with cache headers on errors.** Caddy's documented "prevent caching of error responses" example and HAProxy's deliberate `http-response` scope show a real need not to put long cache lifetimes on 404/5xx. A status condition, or excluding error answers from one specific field, would answer it.
- **Support for "shortest path first, so the longest wins".** It is the intuitive model users expected in Caddy thread 8146 and Traefik #12195, and the one Caddy itself adopted for `vars`.
- **Support for "remainder and query kept" and "required status".** HAProxy's `prefix` mode, and the later addition of `keep-query`, show the demand. A required status avoids the silent 302 default shared by all three. Traefik's method-dependent mapping shows that 301/302 versus 307/308 matters for non-GET clients.
- **Support for "redirects before access and passwords".** It matches Caddy's built-in order (`redir` before `basic_auth`/`forward_auth`) and is configurable in HAProxy and Traefik. The trade-off: it reveals moved-path targets without authentication.
- **Performance for many redirects.** Exact and prefix tree lookups (HAProxy maps) are the proven approach at 10k-100k entries. Linear scans (Caddy `map`) and chained regex middlewares (Traefik) are not built for that scale.

### Gaps
- No benchmark found comparing per-request cost of header rules across the three servers.
- No benchmark found for Caddy or Traefik with thousands of redirects.
- Not tested live: the behaviours inferred from source (Caddy's deferred-versus-immediate winner flip, Traefik headers missing on responses written by earlier middlewares). Both are derived from the cited code paths and from field reports.
