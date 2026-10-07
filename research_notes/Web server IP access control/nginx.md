# nginx address-based access control (state as of 2026-10-07)

Version context: current nginx mainline is 1.31.6 (15 Sep 2026) and stable is 1.30.5 (15 Sep 2026); the GitHub master read for these notes reports 1.31.7 (development) — [CHANGES](https://nginx.org/en/CHANGES), [CHANGES-1.30](https://nginx.org/en/CHANGES-1.30), [src/core/nginx.h](https://github.com/nginx/nginx/blob/master/src/core/nginx.h). Source citations below refer to function names in GitHub `nginx/nginx` master as fetched on 2026-10-07.

## 1. allow/deny: syntax, evaluation order, phase, response code, logging

### Takeaway
`allow`/`deny` take one argument each (an address, a CIDR, `unix:` or `all`). The rules are checked in order and the first match wins. The handler runs in `NGX_HTTP_ACCESS_PHASE` and returns 403 on a deny. A client that matches no rule is allowed, so a list without a final `deny all` grants access by default. A deny writes `access forbidden by rule` to the error log at `error` level.

### Cited Findings
- Syntax: `allow address | CIDR | unix: | all;` and `deny address | CIDR | unix: | all;`. No default. Contexts: `http, server, location, limit_except`. `unix:` (1.5.1) matches all UNIX-domain sockets. — [ngx_http_access_module docs](https://nginx.org/en/docs/http/ngx_http_access_module.html)
- The documentation says: "The rules are checked in sequence until the first match is found." Its example is `deny 192.168.1.1; allow 192.168.1.0/24; allow 10.1.1.0/16; allow 2001:0db8::/32; deny all;`. The docs also say: "In case of a lot of rules, the use of the ngx_http_geo_module module variables is preferable." — [ngx_http_access_module docs](https://nginx.org/en/docs/http/ngx_http_access_module.html)
- Each directive is declared `NGX_CONF_TAKE1` with the flags `NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF`. It takes exactly one address per directive, and it is not valid inside `if` (there is no `NGX_HTTP_LIF_CONF` flag). — [ngx_http_access_module.c, `ngx_http_access_commands`](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_access_module.c)
- How rules are parsed (`ngx_http_access_rule`):
  - The literal `all` is recognised.
  - `unix:` sets family `AF_UNIX`.
  - Anything else goes through `ngx_ptocidr`. An unparsable value is a config error `invalid parameter "%V"` (emerg).
  - A CIDR with host bits set is accepted with a warning `low address bits of %V are meaningless`, and the address is masked. The docs' own example `10.1.1.0/16` triggers that warning.
  - The rule is stored with `deny = (value[0].data[0] == 'd')`. — [ngx_http_access_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_access_module.c), [ngx_inet.c `ngx_ptocidr`](https://github.com/nginx/nginx/blob/master/src/core/ngx_inet.c)
- `ngx_ptocidr` accepts only literal IPv4/IPv6 addresses with an optional `/len` (`len` up to 32 or 128). It has no hostname resolution. (Contrast: `set_real_ip_from` accepts hostnames since 1.13.1.) — [ngx_inet.c](https://github.com/nginx/nginx/blob/master/src/core/ngx_inet.c), [realip docs](https://nginx.org/en/docs/http/ngx_http_realip_module.html#set_real_ip_from)
- Rules are stored in three separate per-family arrays in config order: `rules` (IPv4: mask, addr, deny), `rules6` (IPv6) and `rules_un` (unix). `all` is pushed into all three arrays. "First match wins" therefore applies within the client's address family. — [ngx_http_access_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_access_module.c)
- Matching:
  - IPv4 is `(addr & rule.mask) == rule.addr` in a `for` loop over the array.
  - IPv6 compares 16 bytes per rule.
  - Unix sockets: the first unix rule always matches (the source says `/* TODO: check path */ if (1)`).
  - If nothing matches, or the family has no rules, the handler returns `NGX_DECLINED` and the request proceeds. There is no implicit deny. — [ngx_http_access_module.c `ngx_http_access_inet`, `_inet6`, `_unix`, `_handler`](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_access_module.c)
- Phase: `ngx_http_access_init` pushes the handler onto `cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers`. — [ngx_http_access_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_access_module.c)
- Phase order: POST_READ, SERVER_REWRITE, FIND_CONFIG, REWRITE, POST_REWRITE, PREACCESS, ACCESS, POST_ACCESS, PRECONTENT, CONTENT, LOG. — [ngx_http_core_module.h](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.h), [development guide, HTTP phases](https://nginx.org/en/docs/dev/development_guide.html#http_phases)
- The development guide on the access phase: "Standard nginx modules such as ngx_http_access_module and ngx_http_auth_basic_module register their handlers at this phase. By default the client must pass the authorization check of all handlers registered at this phase." POST_ACCESS is "where the satisfy any directive is processed." — [development guide](https://nginx.org/en/docs/dev/development_guide.html#http_phases)
- Response and logging (`ngx_http_access_found`):
  - A deny returns `NGX_HTTP_FORBIDDEN` (403). Under `satisfy all` it first logs `ngx_log_error(NGX_LOG_ERR, ..., "access forbidden by rule")`.
  - An allow returns `NGX_OK`.
  - Under `satisfy any`, the same message is logged later, in `ngx_http_core_post_access_phase`, only if the final `access_code` is 403. — [ngx_http_access_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_access_module.c), [ngx_http_core_module.c](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.c)
- Under `satisfy all`, a non-OK/non-DECLINED code from the access checker reaches `ngx_http_finalize_request(r, rc)`. This is the normal special-response path, so `error_page 403` handling applies (see section 8). — [ngx_http_core_module.c `ngx_http_core_access_phase`](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.c)
- Subrequests skip the access phase entirely: `ngx_http_core_access_phase` begins with `if (r != r->main) { r->phase_handler = ph->next; return NGX_AGAIN; }`. — [ngx_http_core_module.c](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.c)

### Inferences
- `allow 10.0.0.0/8;` on its own (no `deny all`) restricts nothing: every client is either explicitly allowed or falls through as DECLINED. The idiom always needs a terminal `deny all`.
- Because the lists are per family, a v4-only list followed by `deny all` also denies every IPv6 client: `all` was added to `rules6` as the only IPv6 rule. That is usually intended, but administrators sometimes forget to list their IPv6 admin networks.
- Content pulled in by subrequests (SSI `include virtual`, `addition`, `mirror`, the `auth_request` subrequest itself) is not checked against the target location's allow/deny, because the checker short-circuits for `r != r->main`.
- One rule costs one AND and one compare on IPv4. There is no early exit except the first match, so a deny-list of N addresses costs O(N) per request in that location.

### Gaps
- The exact error-log line format (the `client:`, `server:`, `request:` and `host:` suffixes) was not re-verified in source for this note. It is the generic nginx request log context, not specific to this module.

## 2. Scoping and inheritance (http/server/location/limit_except, nested locations)

### Takeaway
Merging is all-or-nothing. A level that defines any `allow` or `deny` replaces every inherited rule of the three families. There is no appending. Nested locations, `limit_except` blocks and `server` blocks all follow this array-replacement rule.

### Cited Findings
- The documentation, for both directives: "These directives are inherited from the previous configuration level if and only if there are no allow and deny directives defined on the current level." — [ngx_http_access_module docs](https://nginx.org/en/docs/http/ngx_http_access_module.html)
- The source agrees. `ngx_http_access_merge_loc_conf` copies the parent's `rules`, `rules6` and `rules_un` pointers only when the child's `rules`, `rules6` and `rules_un` are all NULL. A child with only an IPv6 rule therefore also loses the parent's IPv4 rules. — [ngx_http_access_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_access_module.c)
- `limit_except method ... { ... }` is valid in `location` context. Inside it, "Access to other methods can be limited using the ngx_http_access_module, ngx_http_auth_basic_module, and ngx_http_auth_jwt_module (1.13.10) modules directives". Example: `limit_except GET { allow 192.168.1.0/32; deny all; }`, which "will limit access to all methods except GET and HEAD." — [ngx_http_core_module docs, limit_except](https://nginx.org/en/docs/http/ngx_http_core_module.html#limit_except)
- Nested-location constraints enforced at parse time:
  - A location cannot be inside an exact (`=`) location or a named location.
  - Named locations are "server level only". — [ngx_http_core_module.c `ngx_http_core_location`](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.c)
- The NGINX admin guide (stream) shows ordering matters: "if the first directive in the sequence is `deny all`, then all further `allow` directives have no effect." — [Restricting Access to Proxied TCP Resources](https://docs.nginx.com/nginx/admin-guide/security-controls/controlling-access-proxied-tcp/)

### Inferences
- A common mistake is to put `deny all; allow <office>;` at `server` level and then add `allow 1.2.3.4;` in one location "to add one more address". That location then has only `allow 1.2.3.4`, with no `deny all`, so it is open to everyone.
- Rule sets therefore have to be repeated in full at every level that customises them. In practice this is done with `include snippets/admin-ips.conf;`.
- Because `limit_except` inherits the location's rules unless it defines its own, a location-level `deny all` applies to all methods. A `limit_except GET { ... }` that defines rules replaces them for non-GET methods only.

### Gaps
- No primary documentation describes the interaction of `limit_except` with nested locations beyond the merge code. The behaviour above is derived from the generic merge rule.

## 3. Interaction with location matching (regex-vs-prefix pitfall, workarounds, internal redirects, `internal`, `return`, predicate locations)

### Takeaway
allow/deny apply only to the one location nginx finally selects. Regex locations beat any non-`^~` prefix location. As a result, `location /wp-admin/ { allow ...; deny all; }` does not protect `/wp-admin/admin.php` when a `location ~ \.php$` exists. The standard fixes are:
- a `^~` prefix with a nested PHP location;
- a nested regex inside the PHP location;
- repeating the rules (via `include`);
- a server-level `geo` plus `if` check that runs before location selection.

Internal redirects re-run the access phase in the new location. `return` and `rewrite` run in the rewrite phase, before access, so they bypass allow/deny in the same location.

### Cited Findings
- The location algorithm, from the docs:
  1. "nginx first checks locations defined using the prefix strings (prefix locations). Among them, the location with the longest matching prefix is selected and remembered."
  2. "Then regular expressions are checked, in the order of their appearance in the configuration file. The search of regular expressions terminates on the first match, and the corresponding configuration is used."
  3. Since 1.31.5: "If no match with a regular expression is found, predicate locations are checked in the order of their appearance". Otherwise "the configuration of the prefix location remembered earlier is used."
  4. "If the longest matching prefix location has the “^~” modifier, then regular expressions and predicate locations are not checked." An `=` exact match terminates the search.

  — [ngx_http_core_module docs, location](https://nginx.org/en/docs/http/ngx_http_core_module.html#location)
- Matching is against "a normalized URI, after decoding the text encoded in the “%XX” form, resolving references to relative path components “.” and “..”, and possible compression of two or more adjacent slashes". Prefix matching ignores case only on case-insensitive OSes (macOS, Cygwin). — [ngx_http_core_module docs, location](https://nginx.org/en/docs/http/ngx_http_core_module.html#location)
- Source: `ngx_http_core_find_location` searches the static (prefix) tree. If the prefix match is inclusive it recurses into nested locations. It then tries the `regex_locations` and then the `predicate_locations`, both only `if (noregex == 0 ...)`. A matching regex location replaces `r->loc_conf` and its nested locations are searched. — [ngx_http_core_module.c](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.c)
- The classic report: trac ticket #956, "Location problems". The reporter wrote `location /site { deny all; }` but `/site/index.php` was served via the `\.php$` regex location. Valentin Bartenev closed it as **invalid**, quoting the doc rule that the first regex match is used and the remembered prefix only applies when no regex matches. — [trac.nginx.org #956](https://trac.nginx.org/nginx/ticket/956)
- Workaround from the nginx mailing list (Francis Daly, 2020) for wp-admin: nest the restriction inside the PHP regex location, `location ~ \.php$ { location ~ ^/wp-admin/ { allow 192.168.1.0/24; deny all; fastcgi_pass ...; } fastcgi_pass ...; }`, plus `location = /wp-login.php { allow 192.168.1.0/24; deny all; fastcgi_pass ...; }`. — [mailman.nginx.org 2020-April/059310](https://mailman.nginx.org/pipermail/nginx/2020-April/059310.html)
- Another documented workaround: put the PHP handling inside the restricted area with a separate regex location carrying the same rules, and avoid duplicating the FastCGI block with `include`. — [mailman.nginx.org 2014-November/045783](https://mailman.nginx.org/pipermail/nginx/2014-November/045783.html), [trac #956](https://trac.nginx.org/nginx/ticket/956)
- Internal redirects re-run the access phase:
  - `ngx_http_internal_redirect` clears the module contexts, resets `r->loc_conf` to the server default, sets `r->internal = 1` and calls `ngx_http_handler`.
  - For internal requests, `ngx_http_handler` starts at `phase_engine.server_rewrite_index`. That goes through location lookup, PREACCESS and ACCESS again with the new location's config.
  - Named-location redirects (`@name`) start at `location_rewrite_index`.
  - Rewrites that change the URI loop back through FIND_CONFIG in `ngx_http_core_post_rewrite_phase`. — [ngx_http_core_module.c](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.c)
- The limit is 10 internal redirects or URI changes. After that comes 500 with "rewrite or internal redirection cycle" in the error log. — [ngx_http_core_module docs, internal](https://nginx.org/en/docs/http/ngx_http_core_module.html#internal), [ngx_http_rewrite_module docs, internals](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html)
- `internal;` (location context): "Specifies that a given location can only be used for internal requests. For external requests, the client error 404 (Not Found) is returned." Internal requests include redirects by `error_page`, `index`, `internal_redirect`, `random_index` and `try_files`, `X-Accel-Redirect`, SSI/addition/auth_request/mirror subrequests, and requests changed by `rewrite`. — [ngx_http_core_module docs, internal](https://nginx.org/en/docs/http/ngx_http_core_module.html#internal)
- The source applies the `internal` check in the FIND_CONFIG phase, before rewrite and access: `if (!r->internal && clcf->internal) { ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND); }`. — [ngx_http_core_module.c `ngx_http_core_find_config_phase`](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.c)
- `return` and `rewrite` bypass allow/deny:
  - The rewrite module's directives run at server level first, then "repeatedly: a location is searched ...; the directives of this module specified inside the found location are executed sequentially". That is the SERVER_REWRITE and REWRITE phases, both before ACCESS. — [ngx_http_rewrite_module docs](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html), [development guide](https://nginx.org/en/docs/dev/development_guide.html#http_phases)
  - Demonstration (2025-06-27): `location /a_folder/ { allow 127.0.0.1; deny all; return 200 "..."; }` returns the body to every client. The suggested fix is `try_files "" @secret_msg;` with the `return` in the named location. — [joshua.hu](https://joshua.hu/nginx-return-allow-deny)
  - The gixy-next linter has a dedicated check, "return bypasses allow deny". — [gixy.getpagespeed.com](https://gixy.getpagespeed.com/checks/return-bypasses-allow-deny/)
- Predicate locations (new in 1.31.5, 02 Sep 2026): `location $variable { ... }`, "matches if the variable value is not empty and is not equal to “0”". They are checked only after no regex matched, and never when the longest prefix is `^~`. — [ngx_http_core_module docs, location](https://nginx.org/en/docs/http/ngx_http_core_module.html#location), [CHANGES 1.31.5](https://nginx.org/en/CHANGES)
- 1.31.6 fixed two bugs: "an error while evaluating a predicate in a predicate location was ignored and the predicate was treated as false", and "an error during a nested location lookup might be ignored if locations given by regular expressions or predicates were configured". — [CHANGES 1.31.6](https://nginx.org/en/CHANGES)

### Inferences
- The robust patterns for "protect a path prefix regardless of handler" are:
  - (a) `location ^~ /wp-admin/ { allow ...; deny all; location ~ \.php$ { include fastcgi.conf; fastcgi_pass ...; } }`. The `^~` stops the regex search at server level and the nested regex inherits the parent's allow/deny.
  - (b) A `geo`/`map` variable tested by `if ($deny_admin) { return 403; }` at server level. The SERVER_REWRITE phase runs before any location is chosen, so the location layout cannot bypass it. A `map` keyed on `$uri` and a geo variable can be combined.
- Predicate locations (1.31.5+) do not replace pattern (b): a request that matches any regex location never reaches them.
- `try_files ... /index.php?$args` performs an internal redirect from PRECONTENT. The allowed request is then checked again by the rules of the location that matches `/index.php`. An allow-list on `/admin/` therefore does not need repeating on the PHP location for the fallback to work, but a stricter rule there would also apply.
- `error_page 403 /403.html` redirects into a location that is subject to its own (often inherited) `deny all`. A denied error page yields nginx's built-in 403 body, because `recursive_error_pages` is off by default.
- Matching is on the normalised and decoded URI, so `%2e%2e` or `//` tricks cannot step around a prefix. With `merge_slashes off`, `//wp-admin/` would no longer match `location /wp-admin/`.

### Gaps
- I did not find an official nginx.org "pitfalls" page that states the regex-vs-prefix access issue in the current docs. The evidence is the location doc, trac #956 and the mailing-list answers.

## 4. satisfy any/all with auth_basic, auth_request (and JWT/OIDC)

### Takeaway
With `satisfy all` (the default) every access-phase module must allow. With `satisfy any` one allowing module is enough. Under `satisfy any`, a 401 or 407 from an auth module takes precedence over a 403 from the IP check, so a client outside the allow-list gets a password prompt rather than 403.

### Cited Findings
- `satisfy all | any;` defaults to `satisfy all`, in contexts `http, server, location`. Access is allowed "if all (all) or at least one (any) of the ngx_http_access_module, ngx_http_auth_basic_module, ngx_http_auth_request_module, ngx_http_auth_jwt_module (1.13.10), or ngx_http_auth_oidc_module (1.27.4) modules allow access". Example: `satisfy any; allow 192.168.1.0/32; deny all; auth_basic "closed site"; auth_basic_user_file conf/htpasswd;`. — [ngx_http_core_module docs, satisfy](https://nginx.org/en/docs/http/ngx_http_core_module.html#satisfy)
- Source, `ngx_http_core_access_phase`:
  - Under ALL, `NGX_OK` moves to the next handler and any other code finalizes the request.
  - Under ANY, the first `NGX_OK` clears `r->access_code`, neutralises any `WWW-Authenticate`/`Proxy-Authenticate` headers already set (`h->hash = 0`) and jumps past the phase.
  - Under ANY, 403, 401 or 407 is recorded in `r->access_code` unless a 401 or 407 is already recorded. 401/407 win over 403.
  - `ngx_http_core_post_access_phase` then finalizes with the recorded code, logging "access forbidden by rule" only for 403. 401 and 407 go through `ngx_http_core_auth_delay`. — [ngx_http_core_module.c](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.c)
- `auth_delay time;` (default `0s`, since 1.17.10) "Delays processing of unauthorized requests with 401 response code to prevent timing attacks when access is limited by password, by the result of subrequest, or by JWT." — [ngx_http_core_module docs, auth_delay](https://nginx.org/en/docs/http/ngx_http_core_module.html#auth_delay)
- `auth_request` (1.5.4+): a 2xx subrequest allows, while 401 or 403 denies with that code. It "may be combined with other access modules, such as ngx_http_access_module, ngx_http_auth_basic_module, and ngx_http_auth_jwt_module, via the satisfy directive." — [ngx_http_auth_request_module docs](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
- 1.31.0 (13 May 2026) added the `ngx_http_tunnel_module` and "support for authenticating to proxies in the "auth_basic", "satisfy", and "auth_delay" directives". This is the source of the 407 / `Proxy-Authenticate` handling seen in the access-phase code. — [CHANGES 1.31.0](https://nginx.org/en/CHANGES)

### Inferences
- `satisfy any` is the usual "office IPs skip the password, everyone else must log in" pattern. Because 401 wins over 403, the outside client sees a 401 challenge, not a 403, and the error log gets no "access forbidden by rule" line for it.
- `auth_request` runs a subrequest. The subrequest itself skips the access phase (`r != r->main`), so the auth endpoint location's own allow/deny is not applied to it.

### Gaps
- None material.

## 5. realip module: set_real_ip_from, real_ip_header, real_ip_recursive; XFF spoofing; Cloudflare

### Takeaway
`ngx_http_realip_module` rewrites the connection's address (`c->sockaddr`, `$remote_addr`) for the current request when the TCP peer is in `set_real_ip_from`. Access, geo, logs and limits then all see the replaced address. The original stays in `$realip_remote_addr`. X-Forwarded-For is always read from the right. Without `real_ip_recursive on` only the single rightmost entry is taken; with it, nginx walks left past trusted addresses. Trusting too broadly (e.g. `0.0.0.0/0`) makes the client address spoofable by any client.

### Cited Findings
- Directives:
  - `set_real_ip_from address | CIDR | unix:;` "Defines trusted addresses that are known to send correct replacement addresses". Hostnames are allowed since 1.13.1.
  - `real_ip_header field | X-Real-IP | X-Forwarded-For | proxy_protocol;` defaults to `real_ip_header X-Real-IP;`. Since 1.11.0 the port is replaced too. `proxy_protocol` (1.5.12) uses the PROXY protocol header.
  - `real_ip_recursive on | off;` defaults to `off`.
  - All three are valid in `http, server, location`. The module is not built by default (`--with-http_realip_module`).
  
  — [ngx_http_realip_module docs](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
- The doc's statement of the recursive semantics: "If recursive search is disabled, the original client address that matches one of the trusted addresses is replaced by the last address sent in the request header field defined by the real_ip_header directive. If recursive search is enabled ... replaced by the last non-trusted address sent in the request header field." Variables: `$realip_remote_addr` (1.9.7), `$realip_remote_port` (1.11.0). — [ngx_http_realip_module docs](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
- Source, phases: `ngx_http_realip_init` registers the same handler in both `NGX_HTTP_POST_READ_PHASE` (server-level config, before rewrite) and `NGX_HTTP_PREACCESS_PHASE` (location-level config). Both run before ACCESS. The handler runs once per request: if the module ctx exists it declines, and the ctx is recovered from the pool cleanup after an internal redirect. — [ngx_http_realip_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_realip_module.c)
- Source, effect: `ngx_http_realip_set_addr` overwrites `c->sockaddr`, `c->socklen` and `c->addr_text`, and registers a pool cleanup that restores the originals when the request ends. The replacement is per request on a keep-alive connection. — [ngx_http_realip_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_realip_module.c)
- Source, header choice:
  - For a custom header name (e.g. `CF-Connecting-IP`) the first header with that name is used.
  - For `X-Forwarded-For` all XFF header lines are walked in reverse order.
  - Nothing happens unless the peer matches `set_real_ip_from` (`ngx_cidr_match`). — [ngx_http_realip_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_realip_module.c), [ngx_http_core_module.c `ngx_http_get_forwarded_addr`](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.c)
- Source, parsing (`ngx_http_get_forwarded_addr_internal`):
  - Starting from the end of the value, it skips trailing spaces and commas and takes the rightmost token as address[:port].
  - With `recursive` off it stops after one step.
  - With `recursive` on it repeats while the newly adopted address is itself trusted and tokens remain.
  - An unparsable token ends the walk, keeping the last good address. — [ngx_http_core_module.c](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.c)
- Maxim Dounin (nginx core developer) on the mailing list:
  - `set_real_ip_from 0.0.0.0/0` "makes client's address as seen by nginx easily spoofable by any client, and it is generally a bad idea to use it in production".
  - With recursion, "the last (rightmost) untrusted address from X-Forwarded-For is used as client's address."
  
  — [mailman.nginx.org 2017-February/052900](https://mailman.nginx.org/pipermail/nginx/2017-February/052900.html)
- Cloudflare's guidance for nginx: `set_real_ip_from <each Cloudflare range>;` and `real_ip_header CF-Connecting-IP;` (or `X-Forwarded-For`). The original visitor address "appears in an appended HTTP header called CF-Connecting-IP". "That list of prefixes needs to be updated regularly, and we publish the full list in Cloudflare IP addresses" — [Cloudflare docs](https://developers.cloudflare.com/support/troubleshooting/restoring-visitor-ips/restoring-original-visitor-ips/), [cloudflare.com/ips](https://www.cloudflare.com/ips)
- 1.27.3 (26 Nov 2024): "an IPv6 address in square brackets and no port can be specified ... as client address in ngx_http_realip_module." — [CHANGES 1.27.3](https://nginx.org/en/CHANGES)
- Stream equivalent: `ngx_stream_realip_module` (1.11.4) changes the client address only from the PROXY protocol header. Its only directive is `set_real_ip_from` (contexts `stream, server`), and the listener needs `listen ... proxy_protocol`. 1.31.4 added PROXY protocol v2 to the stream and mail `proxy_protocol` directive (sending side). — [ngx_stream_realip_module docs](https://nginx.org/en/docs/stream/ngx_stream_realip_module.html), [CHANGES 1.31.4](https://nginx.org/en/CHANGES)
- `geo` and `geoip` have their own, separate XFF handling. `geo { proxy CIDR; proxy_recursive; }` and `geoip_proxy` / `geoip_proxy_recursive` read only `X-Forwarded-For`, with the same rightmost and recursive algorithm (`ngx_http_geo_addr` calls `ngx_http_get_forwarded_addr` with `r->headers_in.x_forwarded_for`). — [ngx_http_geo_module docs](https://nginx.org/en/docs/http/ngx_http_geo_module.html), [ngx_http_geo_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_geo_module.c), [ngx_http_geoip_module docs](https://nginx.org/en/docs/http/ngx_http_geoip_module.html)

### Inferences
- Taking the leftmost XFF entry (what many applications do) trusts client-supplied data. nginx never does that unless every hop to its right is trusted. With `real_ip_recursive off` and two trusted hops (e.g. Cloudflare in front of a load balancer), `$remote_addr` becomes the inner proxy's address, not the client's.
- With `CF-Connecting-IP` there is a single value and no recursion question. The safety depends entirely on `set_real_ip_from` listing exactly Cloudflare's ranges, plus the origin not trusting anything else. A stale range list silently drops the replacement for new Cloudflare edges, which then appear as the client and may be denied or allow-listed by mistake.
- Realip configured only in a `location` takes effect in PREACCESS. Anything evaluated earlier still sees the TCP peer: a server-level `if ($geo_var)`, a `map` used in SERVER_REWRITE, and the location selection itself. Variables are cached per request unless volatile, so a geo variable computed before realip keeps the old value. The safe practice is to put realip at `http` or `server` level.
- Because realip replaces the connection address and access rules see only the result, `allow 10.0.0.0/8` placed behind a trusted proxy is evaluated against the forwarded client address. To restrict the proxy hop itself, test `$realip_remote_addr` with geo or map.

### Gaps
- Cloudflare's current published range list was not copied here. It changes; see [cloudflare.com/ips](https://www.cloudflare.com/ips).

## 6. geo, geoip, map, keyval and njs patterns (large and dynamic lists)

### Takeaway
For large lists nginx recommends `geo`. It compiles CIDRs into radix trees, or IPv4 ranges into a 65,536-bucket table, and yields a variable that is tested with `if`, `map` or (1.31.5+) a predicate location. `map` has no CIDR support, so it is for strings and regexes. GeoIP (legacy) still exists but its databases are discontinued. In open-source nginx every list change needs a reload. Dynamic lists need NGINX Plus `keyval` (`type=ip`) with the API, or njs shared dictionaries.

### Cited Findings
- `geo [$address] $variable { ... }` is valid in the `http` context only (the stream module has its own `geo`).
  - The address comes from `$remote_addr` by default, or from another variable (0.7.27).
  - An invalid address becomes `255.255.255.255`.
  - Entries are CIDRs or (with `ranges`, 0.7.23) ranges. IPv6 is supported since 1.3.10 / 1.2.7.
  - Parameters: `delete`, `default`, `include`, `proxy`, `proxy_recursive`, `ranges` ("should be the first"; ascending order speeds loading) and `volatile` (1.29.3).
  - "A value of the most specific match is used."
  - "Since variables are evaluated only when used, the mere existence of even a large number of declared “geo” variables does not cause any extra costs".
  
  — [ngx_http_geo_module docs](https://nginx.org/en/docs/http/ngx_http_geo_module.html)
- Data structures, from source:
  - CIDR mode builds `ngx_radix32tree` (IPv4) and `ngx_radix128tree` (IPv6). IPv4-mapped IPv6 clients are looked up in the IPv4 tree. Unix-socket clients get the default.
  - `ranges` mode is IPv4 only (source comment: "geo range is AF_INET only"). It uses `high.low[inaddr >> 16]`, a table of 0x10000 pointers to arrays of {start, end, value} over the low 16 bits, scanned linearly. Non-mapped IPv6 clients fall to the default.
  
  — [ngx_http_geo_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_geo_module.c)
- The radix lookup (`ngx_radix32tree_find`) walks one bit per level from the most significant bit and keeps the last node value seen: at most 32 steps for IPv4, 128 for IPv6. This gives longest-prefix-match semantics. — [ngx_radix_tree.c](https://github.com/nginx/nginx/blob/master/src/core/ngx_radix_tree.c)
- Binary geo base: in `ranges` mode, `include file` first tries `file.bin`. It is used if its header matches (`GEORNG`, version, pointer size, endianness) and it is not older than the text file; otherwise nginx warns "stale binary geo range base". nginx itself writes the `.bin` when a ranges geo has exactly one include, no entries outside it and more than 100,000 entries. — [ngx_http_geo_module.c `ngx_http_geo_include`, `ngx_http_geo_include_binary_base`, `ngx_http_geo_block`](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_geo_module.c)
- Duplicate entries warn ("duplicate network ... value ... old value"), and the later value wins. — [ngx_http_geo_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_geo_module.c)
- Recent geo changes:
  - `volatile` parameter, 1.29.3 (28 Oct 2025).
  - "the "include" directive inside the "geo" block supports wildcards", 1.29.8 (07 Apr 2026, in stable 1.30.x).
  - Bugfix in 1.31.6: a segfault while reading configuration with `ranges` and a corrupted binary base.
  
  — [CHANGES](https://nginx.org/en/CHANGES), [CHANGES-1.30](https://nginx.org/en/CHANGES-1.30)
- `map`:
  - "Source values are specified as strings or regular expressions (0.9.6). Strings are matched ignoring the case."
  - Parameters include `hostnames` and `volatile` (1.11.7).
  - Priority: exact string, longest prefix-mask hostname, longest suffix-mask hostname, first matching regex (in config order), then default.
  
  It has no CIDR matching. — [ngx_http_map_module docs](https://nginx.org/en/docs/http/ngx_http_map_module.html)
- `ngx_http_geoip_module` (0.8.6+, built with `--with-http_geoip_module`) uses the MaxMind GeoIP (legacy) C library and `.dat` databases. It provides `$geoip_country_code` and related variables, and `geoip_proxy` / `geoip_proxy_recursive`. With IPv6 databases "IPv4 addresses are looked up as IPv4-mapped IPv6 addresses". — [ngx_http_geoip_module docs](https://nginx.org/en/docs/http/ngx_http_geoip_module.html)
- F5's documentation: "MaxMind GeoLite Legacy databases are currently discontinued" (since 2 Jan 2019), and users should move to GeoIP2 / GeoLite2 and the GeoIP2 module (`nginx-module-geoip2`, the third-party ngx_http_geoip2_module packaged for Plus). — [docs.nginx.com GeoIP dynamic module](https://docs.nginx.com/nginx/admin-guide/dynamic-modules/geoip/)
- Configuration reload: lists live in the configuration. A HUP makes the master check the syntax, apply the new configuration and start new workers, while old workers drain. It rolls back if applying fails. — [Controlling nginx](https://nginx.org/en/docs/control.html)
- NGINX Plus `keyval` (commercial):
  - `keyval_zone zone=name:size [state=file] [timeout=time] [type=string|ip|prefix] [sync];`.
  - `type=ip` (1.17.1): "the search key is the textual representation of IPv4 or IPv6 address or CIDR range; to match a record key, the search key must belong to a subnet specified by a record key or exactly match an IP address". It needs extra zone memory for its index.
  - `keyval key $variable zone=name;` is valid in `http`.
  
  — [ngx_http_keyval_module docs](https://nginx.org/en/docs/http/ngx_http_keyval_module.html)
- F5's "Dynamic Denylisting of IP Addresses" guide:
  - Requires Plus R13 (R19 for network ranges).
  - Example: `keyval_zone zone=one:1m type=ip state=one.keyval; keyval $remote_addr $target zone=one;` plus `if ($target) { return 403; }` at server level.
  - Entries are managed with `POST`/`PATCH` on `/api/<ver>/http/keyvals/one` "without requiring a reload".
  
  — [docs.nginx.com denylisting](https://docs.nginx.com/nginx/admin-guide/security-controls/denylisting-ip-addresses/)
- njs alternatives:
  - `js_access module.function;` in `stream, server`: "called at the access phase" once per session.
  - `js_shared_dict_zone zone=name:size [timeout] [type=string|number] [evict] [state=file]` (njs 0.8.0) gives a dictionary shared between workers that can back a runtime blocklist.
  
  — [ngx_stream_js_module docs](https://nginx.org/en/docs/stream/ngx_stream_js_module.html#js_access), [ngx_http_js_module docs](https://nginx.org/en/docs/http/ngx_http_js_module.html#js_shared_dict_zone)
- A `stream` `keyval` module also exists (`ngx_stream_keyval_module`, listed in the docs index). — [nginx.org/en/docs](https://nginx.org/en/docs/)

### Inferences
- Typical open-source pattern for country blocks or big deny-lists:
  ```
  geo $blocked {
      default 0;
      include /etc/nginx/blocklist.conf;
  }
  ```
  then `if ($blocked) { return 403; }` (or `return 444;`) at server level. This runs in SERVER_REWRITE, before location choice, so regex locations cannot bypass it. With 1.31.5+ a `location $blocked { return 403; }` is possible but weaker (see section 3).
- `if (...) { return ...; }` is the one sanctioned use of `if` in location or server context (return), so it does not hit the "if is evil" class of bugs.
- The geo `ranges` form is IPv4 only. IPv6 country data must use CIDR mode.

### Gaps
- The new "control API" (1.31.5, "Feature: control API") is mentioned in CHANGES. I did not find its documentation page and cannot say whether it allows runtime changes to geo or access lists. Assume reload is still required for open-source lists.
- No published nginx benchmark of access-rule scan cost versus geo lookup was found. The cost statements are derived from the code.

## 7. Data structures and per-request cost (summary of the source)

### Takeaway
`allow`/`deny` is a linear array scan per request: one AND and one compare per IPv4 rule, up to 16 byte compares per IPv6 rule. It allocates nothing and stops at the first match. `geo` is O(prefix length) via a radix tree, or a bucketed range scan, and is computed lazily and cached per request. Every list is immutable until a reload, except NGINX Plus keyval and njs shared dictionaries.

### Cited Findings
- Access-module arrays are allocated at configuration time (`ngx_array_create(cf->pool, 4, ...)`). The per-request handler only reads `alcf->rules` / `rules6` / `rules_un`. — [ngx_http_access_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_access_module.c)
- The docs recommend geo for many rules (quoted in section 1). — [ngx_http_access_module docs](https://nginx.org/en/docs/http/ngx_http_access_module.html)
- Geo variables cost nothing unless used. `volatile` (1.29.3) turns off per-request caching of the value. — [ngx_http_geo_module docs](https://nginx.org/en/docs/http/ngx_http_geo_module.html)
- Radix lookup is bitwise descent (section 6). The range table has 65,536 high-half buckets, each with a linear list. — [ngx_radix_tree.c](https://github.com/nginx/nginx/blob/master/src/core/ngx_radix_tree.c), [ngx_http_geo_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_geo_module.c)
- 1.25.3 (24 Oct 2023): "startup speedup when using a large number of locations" (relevant when access rules are spread over many locations). — [CHANGES 1.25.3](https://nginx.org/en/CHANGES)

### Inferences
- A few dozen allow/deny rules cost nanoseconds. The access check is never the bottleneck at that size. With thousands of entries (e.g. fail2ban-generated deny files), the O(N) scan per request in every covered location is the argument for geo.

### Gaps
- No measured numbers (ns per lookup) from nginx sources were found.

## 8. IPv6, IPv4-mapped IPv6 addresses, unix sockets; returning 404 instead of 403

### Takeaway
An IPv4-mapped client (`::ffff:192.0.2.1`) is matched against the IPv4 rules whenever any IPv4 rule exists (`all` counts), so `allow 192.0.2.0/24` matches it. Mapped clients occur only on dual-stack listeners with `ipv6only=off` (the default is `on`). Unix-socket clients match the first `unix:`/`all` rule regardless of path. To hide a resource, map the 403 to 404 with `error_page 403 =404 ...`, or bypass allow/deny with `geo` + `return 404` (or `444`).

### Cited Findings
- `ngx_http_access_handler`, `AF_INET6` case: `if (alcf->rules && IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))` converts the last four bytes to an `in_addr_t` and calls `ngx_http_access_inet` (the IPv4 list). Only otherwise is `rules6` scanned. — [ngx_http_access_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_access_module.c)
- The same mapped-to-IPv4 conversion is in the stream access module, in geo (CIDR and ranges) and in `ngx_cidr_match` (used by realip's trusted list). — [ngx_stream_access_module.c](https://github.com/nginx/nginx/blob/master/src/stream/ngx_stream_access_module.c), [ngx_http_geo_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_geo_module.c), [ngx_inet.c](https://github.com/nginx/nginx/blob/master/src/core/ngx_inet.c)
- `listen ... ipv6only=on|off` "determines (via the IPV6_V6ONLY socket option) whether an IPv6 socket listening on a wildcard address [::] will accept only IPv6 connections or both ... This parameter is turned on by default." — [ngx_http_core_module docs, listen](https://nginx.org/en/docs/http/ngx_http_core_module.html#listen)
- `unix:` "allows [denies] access for all UNIX-domain sockets". The source has `/* TODO: check path */`, so there is no per-path matching. — [ngx_http_access_module docs](https://nginx.org/en/docs/http/ngx_http_access_module.html), [ngx_http_access_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_access_module.c)
- `$binary_remote_addr` is "always 4 bytes for IPv4 addresses or 16 bytes for IPv6 addresses". — [ngx_http_core_module docs, variables](https://nginx.org/en/docs/http/ngx_http_core_module.html#var_binary_remote_addr)
- `error_page code ... [=[response]] uri;`. "it is possible to change the response code to another using the “=response” syntax, for example: error_page 404 =200 /empty.gif;". It also causes an internal redirect (method changed to GET), and it is inherited only if the current level has no `error_page`. — [ngx_http_core_module docs, error_page](https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page)
- `return code` with "The non-standard code 444 closes a connection without sending a response header." — [ngx_http_rewrite_module docs, return](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#return)

### Inferences
- An IPv6 rule written in mapped form (`deny ::ffff:192.0.2.1;`) is dead whenever the location has any IPv4 rule or `all`. Mapped clients never reach `rules6` in that case. Write IPv4 rules in IPv4 form.
- 404 instead of 403, two options:
  - `error_page 403 =404 /404.html;` at server level. Note that any location defining its own `error_page` loses it, by the inheritance rule. The access module also still logs "access forbidden by rule".
  - `if ($not_admin_ip) { return 404; }` from a geo variable. That gives 404 with no access-module log line.
- `deny` itself cannot be told to emit a different code. The 403 is hard-coded (`NGX_HTTP_FORBIDDEN`).

### Gaps
- No documentation statement on IPv4-mapped handling in allow/deny was found. The behaviour above is from source only.

## 9. Stream (TCP/UDP) access module

### Takeaway
`ngx_stream_access_module` (1.9.2) has the same directives and the same first-match, per-family semantics in `stream` and `server` context. A denied session is closed with stream status 403. The check runs in the stream ACCESS phase, before TLS termination and preread.

### Cited Findings
- Syntax: `allow|deny address | CIDR | unix: | all;`, contexts `stream, server`. "The rules are checked in sequence until the first match is found." — [ngx_stream_access_module docs](https://nginx.org/en/docs/stream/ngx_stream_access_module.html)
- Source:
  - It registers on `NGX_STREAM_ACCESS_PHASE`.
  - A deny logs `access forbidden by rule` at `NGX_LOG_ERR` and returns `NGX_STREAM_FORBIDDEN` (403). `ngx_stream_core_generic_phase` then calls `ngx_stream_finalize_session(s, rc)`.
  - The same IPv4-mapped handling applies, and inheritance is per server via `ngx_stream_access_merge_srv_conf`.
  
  — [ngx_stream_access_module.c](https://github.com/nginx/nginx/blob/master/src/stream/ngx_stream_access_module.c), [ngx_stream_core_module.c](https://github.com/nginx/nginx/blob/master/src/stream/ngx_stream_core_module.c), [ngx_stream.h](https://github.com/nginx/nginx/blob/master/src/stream/ngx_stream.h)
- Stream phase order: POST_ACCEPT, PREACCESS, ACCESS, SSL, PREREAD, CONTENT, LOG. — [ngx_stream.h](https://github.com/nginx/nginx/blob/master/src/stream/ngx_stream.h)

### Inferences
- Because ACCESS precedes SSL in stream, a denied TLS client never gets a handshake. This is cheaper than HTTP, where the TLS handshake has already happened before any allow/deny check.
- In stream an `allow` match returns `NGX_OK`, which the generic phase checker treats as "skip the rest of this phase". In HTTP `satisfy all`, OK moves to the next handler.

### Gaps
- None material.

## 10. Changes in nginx 1.25–1.31 (2023–2026) relevant to address-based access control

### Takeaway
The core allow/deny module has not changed in this period. The relevant changes are:
- predicate locations (1.31.5), with a bugfix in 1.31.6;
- geo `volatile` (1.29.3) and wildcard `include` in geo (1.29.8);
- realip accepting bracketed IPv6 (1.27.3);
- proxy-authentication support in `satisfy` and `auth_delay` (1.31.0, for the tunnel / forward-proxy module);
- an HTTP/3 client-address spoofing vulnerability fixed in 1.31.0 / 1.30.1.

### Cited Findings
- 1.31.5 (02 Sep 2026): "Feature: control API." "Feature: predicate locations." — [CHANGES](https://nginx.org/en/CHANGES)
- 1.31.6 (15 Sep 2026): predicate evaluation errors were being treated as false, and a nested-location lookup error could be ignored with regex or predicate locations present (both fixed); a geo `ranges` corrupted binary base segfault (fixed). — [CHANGES](https://nginx.org/en/CHANGES)
- 1.31.0 (13 May 2026): "the ngx_http_tunnel_module; support for authenticating to proxies in the "auth_basic", "satisfy", and "auth_delay" directives." — [CHANGES](https://nginx.org/en/CHANGES)
- CVE-2026-40460, "HTTP/3 address spoofing", severity medium:
  - CHANGES text: "when using HTTP/3, processing of connection migration might cause new QUIC streams to receive a new client address before validation, allowing an attacker to cause address spoofing".
  - Vulnerable 1.25.0–1.30.0. Fixed in 1.31.0+ and 1.30.1+.
  
  — [nginx security advisories](https://nginx.org/en/security_advisories.html), [CHANGES 1.31.0](https://nginx.org/en/CHANGES), [CHANGES-1.30 (1.30.1)](https://nginx.org/en/CHANGES-1.30)
- 1.29.8 (07 Apr 2026): wildcards in `include` inside `geo`. 1.29.3 (28 Oct 2025): geo `volatile`. — [CHANGES](https://nginx.org/en/CHANGES)
- 1.27.4 added `ngx_http_auth_oidc_module` to the `satisfy` set (doc annotation "(1.27.4)"). — [ngx_http_core_module docs, satisfy](https://nginx.org/en/docs/http/ngx_http_core_module.html#satisfy)
- 1.27.3 (26 Nov 2024): bracketed IPv6 with no port accepted as the realip client address. — [CHANGES](https://nginx.org/en/CHANGES)
- 1.31.4 (19 Aug 2026): stream/mail `proxy_protocol` can send PROXY v2. — [CHANGES](https://nginx.org/en/CHANGES)

### Inferences
- The HTTP/3 CVE matters for allow/deny: on affected versions an HTTP/3 client could have new streams evaluated against an unvalidated migrated address. IP allow-lists on h3-enabled listeners should run 1.30.1+ or 1.31.0+.

### Gaps
- The scope of the 1.31.5 "control API" could not be confirmed from documentation.
