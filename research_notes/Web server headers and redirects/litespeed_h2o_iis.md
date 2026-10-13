# Response header manipulation and redirects in LiteSpeed / OpenLiteSpeed, h2o and Microsoft IIS

Researched 2026-10-12. Primary sources: the OpenLiteSpeed manual as shipped in its repository (`dist/docs`, "Users' Manual Version 1.9 Rev. 4"), OpenLiteSpeed and h2o source on GitHub `master` as of that date, h2o's configuration reference, and Microsoft Learn's IIS configuration reference. Where a statement comes from reading source code rather than documentation, it says "(source)". Source reading was not confirmed by running the servers. Items marked UNVERIFIED have only secondary or inferred support.

Design under comparison (agensio): site-level typed rules matched by path prefix or exact path. Header rules can `set` (replace the application's field), `default` (only when absent) and `remove`. They apply to every answer, including PHP, proxied and error answers, and all matching rules combine shortest path first. Redirect rules have `from`, `match`, `to` and a required status. The path remainder and query are kept by default, and redirects are checked before access and password rules.

## LiteSpeed / OpenLiteSpeed: response headers ("Header Operations", "Extra Headers", .htaccess and mod_headers)

### Takeaway
OpenLiteSpeed sets response headers per context, in the native config only, through "Header Operations": Apache `Header` syntax with set/append/merge/add/unset, stored under the old config key `extraHeaders`. A context's operations are inherited by its child contexts in the URI tree unless the child says `NONE`. OLS ignores `Header` lines in `.htaccess`, because it only reads mod_rewrite there. LiteSpeed Enterprise reads Apache's `httpd.conf` and `.htaccess`, including mod_headers, except `Header edit`.

### Cited Findings
- Every OLS context type (Static, LSAPI, Proxy, Redirect, CGI, and the others) has a "Header Operations" field: "Specifies additional response/request headers to be added. Multiple header directives can be added with one directive per line. "NONE" can be used to disable parent header inheritance. If no directive is provided 'Header' is assumed." — [OLS manual, Static Context](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/Static_Context.html); [Proxy Context](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/Proxy_Context.html); [LSAPI Context](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/LSAPI_Context.html); [Redirect Context](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/Redirect_Context.html)
- The syntax is `[Header]|RequestHeader [condition] set|append|merge|add|unset header [value] [early|env=[!]variable]`. Examples: `set Cache-control no-cache`, `append Cache-control no-store`, `Header set My-header cust_header_val`, `RequestHeader set My-req-header cust_req_header_val`. The manual says: "Syntax and usage are similar to Apache's mod_headers directives for supported operations." There is no `setifempty` (Apache's "only if absent") and no `edit`. — [OLS manual, Static Context](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/Static_Context.html)
- "Extra Headers" is the older name of the same feature. The context parser reads the config key `extraHeaders` and passes it to `setHeaderOps()`. The old `setExtraHeaders()`, which built a raw block of `Name: value` lines, is commented out. (source) — [httpcontext.cpp](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpcontext.cpp)
- Inheritance (source): a context that sets no operations shares its parent context's list. A context that sets its own list calls `inherit()` with the parent's list, so both apply. `applyHeaderOps()` first applies the virtual host root context's own (non-inherited) operations when the request is in the global vhost context, then the matched context's list, inherited entries included. — [httpcontext.cpp](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpcontext.cpp); [httpreq.cpp `applyHeaderOps`/`applyOps`](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpreq.cpp)
- Where they are applied (source): `HttpSession::prepareHeaders()` adds common headers, `WWW-Authenticate` and `Location`, then calls `m_request.applyHeaderOps(this, &headers)`. It is called from `sendRespHeaders()`, the common response-header path. For the proxy handler type, request-header operations (`RequestHeader`) are applied before forwarding. `unset` deletes the field by name; set, add, append and merge go through `HttpRespHeaders::add(..., operator)`. — [httpsession.cpp](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpsession.cpp); [httpreq.cpp `applyOp`](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpreq.cpp)
- `Expires` has its own typed settings: Enable Expires, Expires Default `A|Mseconds`, and Expires By Type, at server, vhost and context level, "Lower level settings will override higher level ones". — [OLS manual, Static Context](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/Static_Context.html); [Server General](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/ServGeneral_Help.html)
- The `Server` header is controlled by the server-level "Server Signature" setting: Hide Version, Show Version, or "Hide Full Header", where "the entire Server header will not be shown". — [OLS manual, Server General](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/ServGeneral_Help.html)
- OLS `.htaccess`: "OLS currently supports mod_rewrite rules from Apache" and "Unsupported directives will be ignored by OpenLiteSpeed". You "must restart OLS after making any changes to your rewrite rules". — [docs.openlitespeed.org, Rewrite Rules](https://docs.openlitespeed.org/config/rewriterules/). The manual's "Auto Load from .htaccess" setting (default No at server level) loads rewrite rules from a directory's `.htaccess` the first time that directory is accessed. "Once initially loaded, a graceful restart must be performed for any further changes to that .htaccess file to take effect." — [OLS manual, Rewrite](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/Rewrite_Help.html)
- Secondary sources say `<Files>`, `<IfModule>`, Order/Deny, Options and authentication directives in `.htaccess` are skipped on OLS, and a hosting forum quotes OLS docs saying only rewrite directives work there. — [linuxconfig.org](https://linuxconfig.org/openlitespeed-htaccess-setup) (secondary). CyberPanel's HSTS guide says that on OpenLiteSpeed the header must be set in the WebAdmin console or the vhost config, while LiteSpeed Enterprise accepts it in `.htaccess`. — [CyberPanel KB](https://cyberpanel.net/KnowledgeBase/home/how-to-set-hsts-header-strict-transport-security-using-cyberpanel-openlitespeed/) (secondary)
- LiteSpeed Enterprise is configured through Apache's config. Directives Apache does not know must be wrapped in `<IfModule litespeed>`. "LiteSpeed doesn't support Apache's header `edit` directive", for example `Header always edit Set-Cookie (.*) "$1;HTTPOnly;Secure;SameSite=none"`. The replacement is the LiteSpeed directive `ForceSecureCookie` (secure, httponly, same_site_*), which is allowed at server or vhost level or in the document root's `.htaccess`. LSWS "automatically adds a `secure` flag when serving traffic over HTTPS". Also unsupported: `AllowOverrideList` (`AllowOverride` is supported), `FallbackResource`, `DirectorySlash Off`, and `RewriteMap prg:`. — [LiteSpeed docs, Configuration](https://docs.litespeedtech.com/lsws/configuration/)

### Inferences
- OLS has no "default" (only-if-absent) operation. An administrator who wants "HSTS unless the app sets it" must use `set` and override the application's value, or `merge`/`append` and risk a duplicate token. This supports agensio offering `default` as a first-class verb.
- OLS combines operations along the context tree, parent first, with `NONE` as an opt-out. This is the closest of the three servers to agensio's "all matching rules combined shortest path first". The `NONE` escape hatch is something agensio does not have. A designer should decide whether a deeper rule may cancel inherited ones; agensio's `remove` on a deeper path covers removing a field, but not "drop the parent's set".
- Header operations run in the shared header-sending path, after `Location` and `WWW-Authenticate` are added. So they very likely reach PHP (LSAPI), proxied, redirect and server-generated error answers alike. Which context's list applies to an error page depends on whether the error was an internal redirect to a custom error URL (the vhost "Customized Error Pages" URL "will forward the request to this URL", [VH General](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/VHGeneral_Help.html)). If so, the context matching the error page URL decides, not the original URL. This is UNVERIFIED by running.
- Because PHP is normally run through a script handler inside a static context, a PHP answer gets the static context's operations for its URL.

### Gaps
- Whether OLS applies operations parent-first or child-first when both set the same field, and the exact semantics of the `[condition]` slot (Apache's `always`/`onsuccess`?), were not confirmed. `httpheaderops.cpp` was not located in the tree.
- No official LiteSpeed statement lists exactly which mod_headers forms Enterprise supports beyond "edit is not supported". `Header set` in `.htaccess` on Enterprise is widely reported to work: [StackHarbor](https://stackharbor.com/en/knowledge-base/litespeed-htaccess-compatibility/) (secondary). Whether Enterprise honours Apache's `always` vs `onsuccess` table split on error responses is UNVERIFIED.
- The LSWS Enterprise native (non-Apache) context reference was not fetched. These notes assume its "Header Operations" matches OLS.

## LiteSpeed / OpenLiteSpeed: redirects (Redirect context, rewrite rules, order against authentication, cPanel)

### Takeaway
OLS has a typed "Redirect" context: a URI (prefix, or `exp:` regex) plus an optional status and a destination. With a plain-prefix URI, the source appends the request's remaining path to the destination and appends the query string unless the destination already has a `?`. With no status set, an absolute destination gets 302. A destination starting with `/` and no status becomes an internal redirect, not a client redirect. The redirect is answered before the access and authentication check. Apache-style `RewriteRule [R=...]` lines at vhost or context level (or `.htaccess`) are the other mechanism, and on cPanel hosts they are the usual one.

### Cited Findings
- Redirect context: "can be used to forward one URI or a group of URIs to another location. The destination URI can be either on the same web site (an internal redirect) or an absolute URI pointing to another web site (an external redirect)." URI: plain (starting `/`) or a PCRE prefixed `exp:`. "If a plain URI ends with a "/", then this context will include all sub-URIs under this URI." External redirect: "Status Code may be specified and Destination URI can start either with "/" or "http(s)://". For internal redirection, Destination URI must start with "/"." Destination: "If this redirected URI maps to a URI in another redirect context, it will be redirected again." With a regex URI, "the destination can reference the matched variables, such as $1 or $2". The same page also lists Realm, Authentication Name, Require, Access Allowed/Denied and Authorizer settings. — [OLS manual, Redirect Context](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/Redirect_Context.html)
- Destination construction, `HttpReq::contextRedirect()` (source):
  - If the context's code is ≥ 400, or is set and < 300, that code is returned as is, so a Redirect context can also answer 403, 404 or 410.
  - For a plain URI, the destination is `Location` + the part of the request URI after the context URI.
  - If a code is set or the destination does not start with `/`, the redirect is external, and a missing code becomes 302 (`if (code == -1) code = SC_302`). The query string is appended (`?` + QS) only `if (memchr(pDestURI, '?', destLen) == NULL)`.
  - Otherwise the request is internally redirected.
  - Overlong results give 414.
  — [httpreq.cpp `contextRedirect`](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpreq.cpp)
- `Location` (source): a destination starting with `/` is made absolute with `http(s)://` + the request's Host header in `addLocationHeader()`. — [httpsession.cpp](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpsession.cpp)
- Processing order (source): the state machine runs `HSPS_VHOST_REWRITE` → `HSPS_CONTEXT_MAP` → `HSPS_CONTEXT_REWRITE` → `HSPS_HKPT_URI_MAP` → `HSPS_FILE_MAP` → `HSPS_CHECK_AUTH_ACCESS`. `processFileMap()` calls `processContextPath()`, which for a Redirect context returns `contextRedirect(...)`. A positive status other than 404 is returned at once, and only otherwise does the state move to `HSPS_CHECK_AUTH_ACCESS`. A source comment says "processContext() returns redirects and errors before it resets the [auth-checked] flag". — [httpsession.cpp `processFileMap`, state loop](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpsession.cpp)
- Contexts match by longest URI. A plain URI ending in `/` covers its sub-URIs. Access control "is determined by the smallest scope that a client's IP address falls into". — [OLS manual, Static Context](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/Static_Context.html)
- Rewrite rules: per vhost ("Do NOT add any document root level rewrite rules here … create a static context with uri "/" and add the rewrite rules there") or per context. Rewrite is inherited down the context tree until overridden, with "Rewrite Inherit" to opt in or out. They are Apache syntax ("Just copy and paste"), with these differences:
  - `%{LA-U:…}` and `%{LA-F:…}` are ignored.
  - There are new variables `%{CURRENT_URI}` and `%{SCRIPT_NAME}`.
  - "[L] … similar to that of the [END] flag in Apache".
  - Rewrite maps support `txt`, `rnd` and `int`, but not hash files or external programs.
  — [OLS manual, Rewrite](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/Rewrite_Help.html); [Static Context](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/Static_Context.html)
- OLS does not strip the directory prefix the way Apache does for `.htaccess`/per-directory rules. Its docs use `RewriteRule ^/?adminPages/(.*)$ …` to match with or without a leading slash, and show `RewriteRule (.*) https://www.your-domain.com/$1 [R=301,L]` and an `[R,L]` (302) HTTPS redirect. — [docs.openlitespeed.org, Rewrite Rules](https://docs.openlitespeed.org/config/rewriterules/)
- cPanel "Redirects" stores redirects in `.htaccess` ("places redirect rules at the bottom of the `.htaccess` file"). The user chooses Permanent (301) or Temporary (302). "Wild Card Redirect" sends "all files within a directory to the same filename in the new directory". www handling is one of "Redirect with or without www", "Only redirect with www" or "Do Not Redirect www". Warnings on the page: third-party applications such as WordPress may make the redirect fail; redirects cannot be edited, only deleted and recreated; browsers cache redirects. — [cPanel docs, Redirects](https://docs.cpanel.net/cpanel/domains/redirects/)
- On cPanel, LiteSpeed Enterprise replaces Apache and reads its configuration and `.htaccess`. — [LiteSpeed docs, cPanel switch from Apache](https://docs.litespeedtech.com/cp/cpanel/switch-apache); [LiteSpeed docs, Configuration](https://docs.litespeedtech.com/lsws/configuration/)

### Inferences
- The Redirect context does what agensio proposes:
  - a typed prefix redirect;
  - the remainder kept;
  - the query kept unless the target carries its own;
  - evaluated before access and authentication.
- Two OLS behaviours argue for agensio's choices:
  - A missing status silently gives either 302 (absolute target) or an internal rewrite (a `/path` target). That is a trap that a *required* status removes.
  - Realm and Access settings exist on a Redirect context, yet an external redirect is answered before `HSPS_CHECK_AUTH_ACCESS`, so they probably never take effect for an external redirect. This is a source reading, UNVERIFIED by test. agensio should document plainly that a redirect is answered before access and password rules, and that a protected path must not also be a redirect source.
- OLS keeps the query unless the target has a `?`. That is an implicit "target query replaces request query" rule. agensio should state explicitly what happens when `to` contains a query: append with `&`, replace, or refuse.
- On cPanel/LiteSpeed shared hosting, the practical mechanism for both headers and redirects is `.htaccess` (`Header set …`, `RewriteRule … [R=301]`) written by the panel or the user. Those rules are evaluated after Apache's per-directory phase ordering. For mod_rewrite in `.htaccess`, that is after authentication in Apache; whether LSWS keeps that order is UNVERIFIED.

### Gaps
- `getURI()` in `contextRedirect` is presumably the decoded, normalised URI. The source does not re-escape the appended remainder, unlike h2o. Whether a remainder with spaces or `%2F` is emitted raw was not confirmed.
- Whether a Redirect context with an `exp:` URI appends anything beyond the `$n` references was not checked. The code path differs (`destLen` comes from the match).
- No LiteSpeed documentation states a default status for the Redirect context. The 302 default is from source only.

## h2o: header directives (`header.*`, `when`, scoping, proxied and error responses)

### Takeaway
h2o has typed header commands: `header.add`, `append`, `merge`, `set`, `setifempty`, `unset`, `unsetunless`, and `cookie.unset`/`unsetunless`. They are usable at global, host, path and extension level, with `when: final|early|all` (default `final`, since v2.3). They are inherited lexically (global → host → path, outer commands first), but only the one longest-matching `paths:` entry applies; sibling path prefixes are not combined. They run as an output filter, so they reach proxied answers and h2o's own error answers, except errors for broken requests. `Server`, `Date`, `Content-Length`, `Connection` and `Transfer-Encoding` cannot be rewritten.

### Cited Findings
- Directives:
  - `header.add` "Adds a new header line even if one with the same name already exists".
  - `header.append` appends with a comma or adds.
  - `header.merge` adds or merges, and adds `must-revalidate` "only if it isn't already set".
  - `header.set` "Sets a header line and removes any existing headers with the same name".
  - `header.setifempty` sets "only if no header with that name exists".
  - `header.unset` "Removes all headers with the given name".
  - `header.unsetunless` "Removes all headers except those listed".
  
  Each accepts one field or a YAML sequence and can be used at "the global, host, path, and extension levels". `when` (v2.3+), default `final`: `final` applies to final (non-1xx) responses, `early` to 1xx, `all` to both. — [h2o docs, Headers directives](https://h2o.examp1e.net/configure/headers_directives.html)
- `cookie.unset` and `cookie.unsetunless` exist in the configurator source although the fetched page did not show them. (source) — [configurator/headers_util.c](https://github.com/h2o/h2o/blob/master/lib/handler/configurator/headers_util.c)
- Semantics (source, `h2o_rewrite_headers`):
  - SET = remove all of that name, then add.
  - SETIFEMPTY = return if the name exists, else add.
  - MERGE = add if absent; skip if the comma-separated token is already present; else append the token.
  - APPEND = add if absent, else append.
  - UNSET = remove all.
  
  — [headers_util.c](https://github.com/h2o/h2o/blob/master/lib/handler/headers_util.c)
- Refused names: the configurator errors with "the named header cannot be rewritten" for `Connection`, `Content-Length`, `Transfer-Encoding` ("connection-specific headers") and `Date`, `Server` ("headers added at protocol layer"). (source) — [headers.c `h2o_headers_is_prohibited_name`](https://github.com/h2o/h2o/blob/master/lib/handler/headers.c); [configurator/headers_util.c](https://github.com/h2o/h2o/blob/master/lib/handler/configurator/headers_util.c)
- Inheritance (source): on entering each configuration level the configurator copies the parent level's command list. Adding a command builds a new list (`memcpy` of the existing commands, then the new one appended). On leaving a level that has a pathconf (not extension level), the accumulated list is registered as one filter on that pathconf. Commands therefore run outer level first, inner level last, in file order. — [configurator/headers.c](https://github.com/h2o/h2o/blob/master/lib/handler/configurator/headers.c); [headers_util.c `h2o_headers_append_command`](https://github.com/h2o/h2o/blob/master/lib/handler/headers_util.c)
- Path selection (source): `h2o_config_register_path` keeps a host's paths "descending by the path length so that longer pathconfs overriding subdirectories of shorter ones would work, regardless of the registration order". `setup_pathconf` picks the first, that is longest, path that is a prefix of the normalised path *on a segment boundary*: the configured path ends in `/`, or the lengths are equal, or the next request character is `/`. Otherwise it picks the host's `fallback_path`. Only that one pathconf's filters are bound to the request (`h2o_req_bind_conf` copies `pathconf->_filters`). — [config.c](https://github.com/h2o/h2o/blob/master/lib/core/config.c); [request.c](https://github.com/h2o/h2o/blob/master/lib/core/request.c)
- Application point (source): the headers filter's `on_setup_ostream` rewrites `req->res.headers` for every non-`early` command when the response starts streaming. That covers whatever handler produced the response (file, proxy, FastCGI, mruby). 103 Early Hints go through `on_informational` with the non-`final` commands. When any non-unset command is `early`/`all`, a handler is inserted first in the path that sends a 103 on the next loop turn. — [headers.c](https://github.com/h2o/h2o/blob/master/lib/handler/headers.c)
- Errors (source): `h2o_send_error_generic` binds the host's `fallback_path` if no pathconf was chosen yet, then sends through the normal filter chain. Error responses therefore get that pathconf's filters, header commands included, but "If the request is broken or incomplete, do not apply filters, as it would be dangerous to do so" (`H2O_SEND_ERROR_BROKEN_REQUEST` sets `_next_filter_index = SIZE_MAX`). Unless `H2O_SEND_ERROR_KEEP_HEADERS` is passed, the error clears previously set response headers. — [request.c](https://github.com/h2o/h2o/blob/master/lib/core/request.c)

### Inferences
- h2o's verbs match agensio's almost one to one: `set` = set, `setifempty` = default, `unset` = remove. Its extra verbs (`add`, `append`, `merge`, `unsetunless`) are what people reach for with CSP/Cache-Control token lists. A designer might later want `merge` for `Cache-Control`/`Vary`, but agensio's typed three-verb set is a defensible subset with clean semantics.
- h2o refuses to let configuration touch `Server`, `Date`, `Content-Length`, `Connection` and `Transfer-Encoding`. agensio should likewise refuse framing fields at config load (`Content-Length`, `Transfer-Encoding`, `Connection`, and HTTP/2 pseudo-fields). Whether `Server` is removable is a policy choice: IIS and OLS make `Server` removal a separate server-level switch.
- Applying header rules as an output step on every response, including proxied, FastCGI and server-generated errors, is exactly h2o's model and supports agensio's choice. h2o's deliberate exception is that malformed-request errors skip the filters. agensio may want the same carve-out for 400s it sends before a site is known; there is no site to apply rules from anyway.
- h2o combines rules only along lexical nesting (global → host → path), not across sibling path prefixes. A host with paths `/` and `/admin/` gives `/admin/x` only the `/admin/` block (plus host and global). agensio's "all matching rules combined shortest path first" is a different, more additive model, closer to OLS's context-tree inheritance. Its advantage is that a site-wide security header on `/` cannot be lost by adding a `/admin` rule. Its cost is that there is no `NONE` to opt out of a parent rule.
- h2o's segment-boundary prefix match (`/abc` does not match `/abcdef`) matches what agensio's prefix rules do elsewhere (access rules cover whole segments).

### Gaps
- The h2o docs page did not say whether the host-level commands are registered on the host's `fallback_path`, which errors for unmatched paths use. That is likely from the enter/exit logic but UNVERIFIED.
- The extension-level behaviour (commands at extension level are not registered as a filter by `on_config_exit`) was not fully traced.

## h2o: redirect handler (status, internal redirect, path remainder, query, ordering)

### Takeaway
`redirect` is a path-level handler. A scalar URL means status 302. The mapping form *requires* `status` (300–399) and accepts `internal: YES` to re-process internally. The remaining part of the normalised path (re-escaped) and the raw query are always appended, with trailing-slash adjustment. There is no option to drop them.

### Cited Findings
- The docs say `redirect` "rewrites the URL by replacing the host and path part of the URL at which the directive is used with the given URL". The argument is a scalar URL or a mapping with `url`, `status`, `internal` (`YES`/`NO`, default `NO`; with `YES` "the server performs an internal redirect and returns the content at the redirected URL"). Level: `path`. The example redirects all of `example.com:80` `/` to `https://example.com/` with `status: 301` while `/rss` is served from files. — [h2o docs, Redirect directive](https://h2o.examp1e.net/configure/redirect_directives.html)
- Defaults and validation (source): `int status = 302; /* default is temporary redirect */`. The mapping is parsed with required keys `"url:s,status:*"` and optional `"internal:*"`, so in mapping form the status is mandatory. A status outside 300–399 is refused: "value of property `status` should be within 300 to 399". The command has `H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_DEFERRED`. — [configurator/redirect.c](https://github.com/h2o/h2o/blob/master/lib/handler/configurator/redirect.c)
- Destination (source): `h2o_build_destination(req, prefix, len, use_path_normalized=1)` produces the configured URL, then a `/` adjustment, then `h2o_uri_escape(path_normalized + pathconf->path.len, "/@:")`, then the raw query if present. The adjustment:
  - If the path config ends with `/` and the URL does not, a `/` is inserted.
  - If the URL ends with `/` and the path config does not, the URL's slash is dropped when there is a remainder.
  
  A `*` in the URL is replaced by the part of the Host that a wildcard host name matched. — [util.c `h2o_build_destination`](https://github.com/h2o/h2o/blob/master/lib/core/util.c); [redirect.c](https://github.com/h2o/h2o/blob/master/lib/handler/redirect.c)
- Internal redirect (source): for status 307/308 the method is kept; for any other status the method becomes GET and the request body is dropped. Then `h2o_reprocess_request_deferred(...)`. — [redirect.c](https://github.com/h2o/h2o/blob/master/lib/handler/redirect.c)
- Handlers in a pathconf are called in order until one handles the request (`call_handlers`); with none, the answer is 404. — [request.c](https://github.com/h2o/h2o/blob/master/lib/core/request.c)

### Inferences
- h2o mirrors two of agensio's choices: the remainder and query kept, and an explicit status in the structured form. The scalar-form default of 302 is the convenience agensio rejects. agensio's required status is stricter than h2o and consistent with its mapping form.
- Building the remainder from the *normalised, re-escaped* path rather than the raw target means `/old/a/../b` redirects to `.../b` and odd encodings are canonicalised. That is a defensible choice for agensio too, since it already normalises before routing. It differs from forwarding the raw target the way the proxy does.
- h2o has no exact-match paths and no "drop remainder" option. An exact redirect (`/old-page` → `/new-page` only) cannot be expressed with `redirect` alone without the remainder rule also catching `/old-page/x`. agensio's `match = "exact"` on redirect rules covers that gap.
- Ordering against authentication: h2o has no built-in Basic auth (it is done with mruby's `Htpasswd` handler). Order is therefore the order of handlers on the path. Because `redirect` is a DEFERRED command, it is probably registered after other handlers declared at the same path, so an auth handler on that path would run first. This is UNVERIFIED and opposite to agensio's "redirect before passwords".

### Gaps
- h2o's docs do not state the 302 default, the mandatory status in mapping form, or the query handling. All three come from source.
- The ordering between a DEFERRED `redirect` and an `mruby.handler` on the same path was not tested.

## IIS: response headers (customHeaders, removing Server and X-Powered-By, outbound rules)

### Takeaway
IIS's `<httpProtocol><customHeaders>` adds name/value pairs to "every response" and is a configuration collection (`add`/`remove`/`clear`) inherited down the applicationHost.config → site → app → folder web.config hierarchy. It has no set-vs-default distinction and cannot remove a header produced by the application. Removing `Server` needs `requestFiltering/@removeServerHeader` (IIS 10, Windows 1709+). Changing or blanking arbitrary response headers needs URL Rewrite *outbound* rules on `RESPONSE_*` server variables. `X-Powered-By: ASP.NET` is itself a default customHeaders entry and is removed with `<remove>`.

### Cited Findings
- customHeaders "specifies custom HTTP headers that Internet Information Services (IIS) 7 will return in HTTP responses from the Web server … Unlike redirect response headers, which are returned in responses only when redirection occurs, custom response headers are returned in every response." It has no attributes. Child elements are `add` (name, value), `remove`, and `clear` ("Removes all references to custom response headers from the `<customHeaders>` collection"). The default in ApplicationHost.config is `<customHeaders><clear /><add name="X-Powered-By" value="ASP.NET" /></customHeaders><redirectHeaders><clear /></redirectHeaders>`. It is configurable per "site, application, or directory" in IIS Manager. It was introduced in IIS 7.0, replacing IIS 6 `HttpCustomHeaders`, and is unchanged through IIS 10.0. — [Microsoft Learn, customHeaders](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpprotocol/customheaders/)
- `removeServerHeader`: "If set to **true**, request filtering will suppress the IIS server header … This attribute was added in IIS 10.0 and does not work in versions of Windows prior to Windows Server, version 1709 or Windows 10, version 1709." Default `false`. It is an attribute of `system.webServer/security/requestFiltering`. — [Microsoft Learn, requestFiltering](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/)
- On older IIS the usual workaround is a URL Rewrite outbound rule matching `RESPONSE_Server` with a Rewrite to an empty value. "The end result is an empty Server: response header line". It is "website-specific … If you want to create the rule for all of your applications, you have to create the rule at the server level", and some third-party applications depend on `Server`. — [saotn.org](https://www.saotn.org/windows-server/remove-iis-server-version-http-response-header/) (secondary). The same technique works for `X-Powered-By` via `RESPONSE_X_POWERED_BY`. — [Microsoft archive blog, URL Rewrite outbound rules](https://learn.microsoft.com/fr-fr/archive/blogs/chiranth/url-rewrite-part-3outbound-rules-rewrite-maps) (search summary; not fetched in full)

### Inferences
- IIS splits headers across three mechanisms with different powers:
  - customHeaders adds and cannot replace or remove the application's field;
  - requestFiltering removes `Server` only;
  - outbound rewrite edits anything but blanks rather than deletes on older versions.
  
  That fragmentation argues *for* agensio's single typed rule with `set`/`default`/`remove` acting on the final response, whatever produced it.
- customHeaders' `<remove name=…>` removes an *inherited configuration entry*, not a field the application sent. A designer should keep "remove a parent rule" separate from "remove a response field". agensio's `remove` is the latter only. If inheritance opt-out is ever needed, it should be a different word.
- Because customHeaders is "added", not "set", a header that both IIS config and the application emit is commonly reported as duplicated (for example `X-Frame-Options: SAMEORIGIN, SAMEORIGIN`). UNVERIFIED: no primary source was found in this session. agensio's distinction between `set` (replace) and `default` (only when absent) is aimed at exactly this failure mode.

### Gaps
- Microsoft's customHeaders page does not say whether entries are added to IIS-generated error responses (httpErrors) or whether they replace an existing field of the same name. Both are commonly believed (added on errors too, appended to the application's) but were not confirmed from a primary source here.
- Whether URL Rewrite outbound rules run on IIS-generated error pages and on kernel-cached responses was not confirmed.

## IIS: redirects (httpRedirect, URL Rewrite, rewrite maps, inheritance, pitfalls, order against authentication)

### Takeaway
IIS has two redirect mechanisms with *different defaults*:
- `<httpRedirect>` (the optional HTTP Redirection role service): default `Found`/302, values 301/302/307/308. By default the remainder of the URL is appended relative to the folder where it is configured. `exactDestination` turns that off, and `$S`/`$Q`/`$V`/`$P`/`$0-9` give explicit control. It is inherited by every child folder and application, the main source of loops, and runs at MapRequestHandler.
- URL Rewrite: regex or wildcard rules with Redirect actions 301/302/303/307 and no 308, defaulting to 301 (secondary source). `appendQueryString` defaults to true; the path enters the target only through back-references. Rewrite maps handle bulk static redirects. Rules run at PreBeginRequest (global) or BeginRequest (distributed), i.e. before authentication.

### Cited Findings
- httpRedirect attributes:
  - `enabled` (default false).
  - `destination` ("URL or virtual path").
  - `exactDestination` ("the destination value should be considered an absolute target location, not a relative location", default false).
  - `childOnly` (default false). Microsoft's description: "Specifies whether the destination value should be added to the beginning of the file name that contains the request to be redirected. For example, if **childOnly** were set to true and the destination value were configured to be `http://marketing.contoso.com/`, a request for `http://contoso.com/default.htm` would be redirected to `http://marketing.contoso.com/default.htm`."
  - `httpResponseStatus`, default `Found`: Found=302, Permanent=301, Temporary=307, PermRedirect=308 (308 added in IIS 10.0).
  
  "HTTP Redirection is not available on the default installation of IIS 7 and later." Wildcard rules (`<add wildcard destination>`) have "no user interface". — [Microsoft Learn, httpRedirect](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpredirect/)
- Wildcard rules: "If you add wildcard redirection rules, you must remove the default destination value in the `<httpRedirect>` section in order for the wildcard rules to work." Example: `<httpRedirect enabled="true" exactDestination="true" httpResponseStatus="Found"><add wildcard="*.php" destination="/default.htm" /></httpRedirect>`. — [Microsoft Learn, httpRedirect/add](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpredirect/add)
- From an IIS team member's write-up of HttpRedirectionModule:
  - "If set to false, original URL is appended to the redirected URL", and the "Added URL is relative to the deepest file path where the httpRedirect section configuration is set".
  - `childOnly` is "a safeguard to prevent looping": it applies the rule only to URLs under the folder when that folder is a subfolder of the target, and disabling the module in the subfolder (`enabled=false`) has the same effect.
  - Variables: `$S` is the remaining path with leading slash (its value depends on which folder's configuration is picked up); `$V` is the path without server name; `$P` is the query without `?`; `$Q` is the query with `?`, blank when there is none; `$0-$9` are wildcard captures.
  - The module "does its work in MapRequestHandler stage of request pipeline".
  - "Destination and wildcard rules are just like other configuration properties and can be inherited".
  - Pitfalls: a parent's destination, especially with `$S`, is inherited unexpectedly; leave the section destination blank when using wildcards; `<clear/>` inherited wildcard rules; put a single-file redirect under a `<location>` for that file; the `!` exclusion of IIS 6 "is removed in IIS7".
  
  — [IIS.NET blog (ksingla), Client side redirection using HttpRedirection module](https://blogs.iis.net/ksingla/client-side-redirection-using-httpredirection-module)
- In IIS 6, `$S` passed the suffix and `$Q` the query string, and the `CHILD_ONLY` flag prevented looping when the destination is a subdirectory of the original URL. — [IIS 6 SDK, Redirect reference](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525695(v=vs.90)) (search summary; not fetched in full)
- URL Rewrite scope and timing:
  - `<globalRules>` are server level only, "cannot be overridden or disabled on any lower configuration levels", operate on the absolute URL path, and "are evaluated early in the IIS request-processing pipeline (**PreBeginRequest** event)".
  - Distributed `<rules>` can be defined at any level, "operate on the URL path, relative to the location of the Web.config file", and "are evaluated on the BeginRequest event".
  - Evaluation order: all global rules, then distributed rules "in a parent-to-child order".
  - Rules run in order, a matched rule's output feeding the next, until `stopProcessing`.
  - "The URL string that is evaluated against the pattern does not include the query string." A site-level rule sees `content/default.aspx`, with no leading slash.
  
  — [Microsoft Learn, URL Rewrite Module Configuration Reference](https://learn.microsoft.com/en-us/iis/extensions/url-rewrite-module/url-rewrite-module-configuration-reference)
- Redirect action: `url`, `appendQueryString` ("By default … assumed to be TRUE … the query string from the original URL is appended"), and `redirectType` 301 Permanent, 302 Found, 303 See other or 307 Temporary. "HTTP status code 308 (Permanent Redirect) is not supported by the URL Rewrite module." A Redirect "implies that no subsequent rules evaluated". Rewrite maps are "particularly useful when you have a large set of rewrite rules and all of these rules use static strings". Example 2 redirects via `{StaticRedirects:{REQUEST_URI}}` with `redirectType="Found"`. Maps can be defined "on any configuration level, except the file level", and a missing key returns `defaultValue` (empty by default). — [Microsoft Learn, URL Rewrite Module Configuration Reference](https://learn.microsoft.com/en-us/iis/extensions/url-rewrite-module/url-rewrite-module-configuration-reference)
- The `redirectType` default when omitted is 301: a vendor KB says URL Rewrite "defaults to a 301 (Permanent) redirect", which browsers cache, and advises 307 instead. — [SecureAuth KB](https://support.secureauth.com/hc/en-us/articles/360035997852) (secondary; Microsoft's reference does not state the default). 308 support: a Microsoft Q&A answer says the 301/302/303/307 options are hard-coded in rewrite.dll and suggests the HTTP Redirect module for 308. — [Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/2243039/how-to-select-308-for-a-redirect-in-iis-10-url-rew)

### Inferences
- Within one product, two redirect modules default to different statuses (httpRedirect 302, URL Rewrite 301 per the secondary source), and only one supports 308. That is a strong argument for agensio's *required* status: nobody has to remember which default applies, and a cached 301 is never issued by accident.
- `exactDestination` is a negatively-named switch that controls whether the remainder is appended. Microsoft's own `childOnly` description contradicts the IIS team's "loop safeguard" explanation. Both are recurring confusion points. agensio keeping the remainder by default is the same default as httpRedirect. It should name the opt-out positively (for example `keep_path = false`) and document it with a worked example, rather than copy `exactDestination`.
- httpRedirect inherits into every child folder and application, so a site-wide redirect also fires inside the target folder and loops unless `childOnly` is set or the child disables the module. agensio's prefix redirect rules have the same structural risk when `to` lies under `from` (e.g. `/` → `/new/`). A config-time check refusing `to` paths inside the `from` prefix on the same site would remove the class of bug IIS documents.
- Order against authentication (inference from the documented events plus the standard IIS integrated pipeline order BeginRequest → AuthenticateRequest → AuthorizeRequest → … → MapRequestHandler, which was not fetched in this session): URL Rewrite redirects (PreBeginRequest/BeginRequest) happen before authentication, while httpRedirect (MapRequestHandler) happens after authentication and authorization. agensio's "redirect before access and password rules" matches URL Rewrite and OLS, not httpRedirect.
- IIS distributed rules see the path relative to the web.config folder without a leading slash, and never see the query in the pattern. agensio's absolute-path `from` with a separate query treatment avoids that portability trap.

### Gaps
- Whether httpRedirect appends the query string when `exactDestination=false` is not stated in Microsoft's reference or in the IIS team post. Likewise the exact difference between `$S` and the automatic remainder under nested configs.
- Microsoft's reference does not state the URL Rewrite `redirectType` default. 301 rests on a vendor KB and common knowledge.
- No primary documentation was found on whether customHeaders and outbound rules apply to `httpErrors` responses, or on how httpRedirect interacts with Windows/Basic authentication beyond the pipeline stage.

## Cross-server summary: default status, path remainder and query, order relative to authentication, and fit with agensio's design

### Takeaway
None of the three agrees on a default redirect status (OLS 302 or internal, h2o 302 scalar or required in mapping form, IIS httpRedirect 302, IIS URL Rewrite 301), which supports making the status required. All three keep the path remainder by default in their prefix-redirect mechanism, and most keep the query, which supports agensio's defaults. "Every response, including proxied and errors" is h2o's and OLS's actual model. On combining rules across paths, OLS's context-tree inheritance with `NONE` is the precedent closest to "all matching rules, shortest path first". h2o deliberately applies only the longest path entry, and IIS merges configuration collections parent to child.

### Cited Findings
- Default status:
  - OLS Redirect context: no code → 302 for an absolute target, internal redirect for a `/` target. — [httpreq.cpp](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpreq.cpp)
  - h2o: scalar 302; mapping requires `status` 300–399. — [configurator/redirect.c](https://github.com/h2o/h2o/blob/master/lib/handler/configurator/redirect.c)
  - IIS httpRedirect: `Found` 302. — [Microsoft Learn](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpredirect/)
  - URL Rewrite: 301 (secondary). — [SecureAuth KB](https://support.secureauth.com/hc/en-us/articles/360035997852)
  - cPanel asks the user to choose 301 or 302. — [cPanel docs](https://docs.cpanel.net/cpanel/domains/redirects/)
- Path remainder:
  - OLS appends the request URI after the context URI. — [httpreq.cpp](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpreq.cpp)
  - h2o appends the normalised, re-escaped remainder. — [util.c](https://github.com/h2o/h2o/blob/master/lib/core/util.c)
  - IIS httpRedirect appends unless `exactDestination`. — [IIS.NET blog](https://blogs.iis.net/ksingla/client-side-redirection-using-httpredirection-module)
  - URL Rewrite carries it only through back-references. — [Microsoft Learn](https://learn.microsoft.com/en-us/iis/extensions/url-rewrite-module/url-rewrite-module-configuration-reference)
- Query:
  - OLS appends unless the target contains `?`. — [httpreq.cpp](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpreq.cpp)
  - h2o always appends the raw query. — [util.c](https://github.com/h2o/h2o/blob/master/lib/core/util.c)
  - URL Rewrite `appendQueryString` defaults to true. — [Microsoft Learn](https://learn.microsoft.com/en-us/iis/extensions/url-rewrite-module/url-rewrite-module-configuration-reference)
- Order against authentication:
  - OLS answers a Redirect context before `HSPS_CHECK_AUTH_ACCESS`. — [httpsession.cpp](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpsession.cpp)
  - URL Rewrite runs at PreBeginRequest/BeginRequest. — [Microsoft Learn](https://learn.microsoft.com/en-us/iis/extensions/url-rewrite-module/url-rewrite-module-configuration-reference)
  - httpRedirect runs at MapRequestHandler. — [IIS.NET blog](https://blogs.iis.net/ksingla/client-side-redirection-using-httpredirection-module)
- Header verbs:
  - h2o set / setifempty / unset (+ add / append / merge / unsetunless). — [h2o docs](https://h2o.examp1e.net/configure/headers_directives.html)
  - OLS set / append / merge / add / unset, with no only-if-absent verb. — [OLS manual](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/Static_Context.html)
  - IIS customHeaders add only, plus config-level remove/clear. — [Microsoft Learn](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpprotocol/customheaders/)
- Scope of application: h2o filters every response of the pathconf, including proxied and h2o-generated errors, but not broken-request errors. — [headers.c](https://github.com/h2o/h2o/blob/master/lib/handler/headers.c); [request.c](https://github.com/h2o/h2o/blob/master/lib/core/request.c). OLS applies operations in the common `sendRespHeaders` → `prepareHeaders` path. — [httpsession.cpp](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpsession.cpp). IIS custom headers "are returned in every response". — [Microsoft Learn](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpprotocol/customheaders/)

### Inferences
- Supports agensio:
  - a required status (inconsistent defaults everywhere; IIS has two in one product);
  - remainder and query kept by default (h2o, OLS and IIS httpRedirect all do it);
  - a `default` verb (only h2o has it, and its absence in OLS and IIS forces override-or-duplicate);
  - header rules applied to every answer type (h2o and OLS do, structurally);
  - redirect before access and password rules (OLS, IIS URL Rewrite).
- Argues for care, or a feature agensio lacks:
  - (a) An opt-out of inherited header rules (OLS `NONE`, IIS `<remove>`/`<clear>`). With "all matching rules combined", a deeper path cannot cancel a parent's `set` except by its own `set`/`remove` of the same field. Decide whether that is enough.
  - (b) Refusing framing and protocol fields in header rules (h2o refuses `Content-Length`, `Transfer-Encoding`, `Connection`, `Date`, `Server`).
  - (c) A defined behaviour when `to` contains its own query (OLS: then the request query is dropped).
  - (d) Loop prevention when `to` lies under `from` (IIS `childOnly` history).
  - (e) Whether redirect rules apply to malformed or early-error requests (h2o skips filters for broken requests).
  - (f) Whether the remainder is built from the normalised path (h2o) or the raw target (OLS appears to use the decoded URI).
- A rule that runs before passwords (OLS, URL Rewrite) means a redirect can disclose that a protected path exists and where it moved. That is acceptable for agensio as long as it is documented. The IIS httpRedirect position (after authentication) is the counter-example if the owner wants a redirect inside a protected area to require login first.

### Gaps
- No server documents how its redirect and header features interact with HTTP/2 or HTTP/3 specifically; all treat them as protocol-independent.
- LiteSpeed Enterprise's native-config behaviour and its exact Apache phase emulation (is `.htaccess` mod_rewrite before or after auth?) were not verified.
