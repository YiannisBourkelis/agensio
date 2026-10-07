# Pre-routing allow-lists fix nginx's oldest trap

The section 22 proposal gets right the decision that most servers get wrong or leave to the administrator. It tests the normalised request path against a site-level rule **before** location routing, so an address rule follows the path whichever handler serves it. That removes the failure administrators report most often: nginx's `location /wp-admin/ { allow ...; deny all; }`, which a `\.php$` regex location bypasses. The same trap is still reported on hosting forums in 2025. The design also avoids Apache's merge-order and `ProxyPassMatch` bypasses and nginx's hole where `return` runs before the access check. Its address source is the peer, or the rightmost untrusted X-Forwarded-For hop behind `trusted_proxies`. That is the algorithm MDN, nginx's `real_ip_recursive` and Apache's mod_remoteip use, and it is safer than the defaults of Caddy, h2o, OpenLiteSpeed and Traefik.

The research, and a reading of agensio's source on 2026-10-07, show gaps that must close before the feature ships:

- `core/forwarded.hpp` reads only the first X-Forwarded-For field line. Behind HAProxy, which adds its own line, a client can pick its own address. This already affects logs, `REMOTE_ADDR` and fail2ban today.
- Rule paths compared with a plain string prefix would let `/cp` slip past a `/cp/` rule.
- A proxied Java application reads `..;/` differently from agensio's normaliser.
- IPv4-mapped peers are matched but never canonicalised.
- WordPress's public front end calls `/wp-admin/admin-ajax.php`. A plain `/wp-admin/` rule breaks those pages and sends ordinary visitors into the `agensio-auth` ban.

Administrators also ask for things the design lacks: a named address set ("office") reused across sites, a way to ask "would this address reach this path" before enforcing, and a refusal that says which address was tested and which rule refused it. None of the fixes adds cost to a site without rules. On a site with rules, a request to an unrestricted path pays one bit test.

On the four open questions, the evidence favours:

1. 403 with `Cache-Control: no-store`.
2. Allow lists only, plus an explicit `any` value for exceptions.
3. Keeping `allow`, `[[site.access]]` and `rules.restricted` with the same keys in both.
4. Allowing `path = "/"`, which is the use case administrators ask about most.

## Eight servers fail in the same two places: path scope and address source

Across the eight servers, the address matcher itself is almost never the weak point. This research found no CVE in nginx or Apache httpd core where `allow` or `Require ip` judged an address wrongly. Every recorded failure is about **which path the rule actually covered** or **which address it was handed**. The table summarises each server; the paragraphs below give the evidence.

| Server | Where the rule applies | How rules combine | Client address behind a proxy | Lookup | On refusal | Testing / live change |
|---|---|---|---|---|---|---|
| nginx 1.31 | The location finally selected (ACCESS phase) | First match in file order, per address family; no implicit deny; a level with any rule drops all inherited ones | `realip` (not built by default): rightmost XFF; `real_ip_recursive on` skips trusted hops | Linear arrays; `geo` radix tree for big lists | 403 hard-coded, one error-log line per denial | None; reload (Plus: keyval API) |
| Apache 2.4 | `Require ip` in Directory, Files, Location, `.htaccess` | Three-valued logic; implicit RequireAny; last merged section wins (`AuthMerging Off`) | mod_remoteip, right to left; trusts every host if no proxy list is set | Linear subnet array per line | 403, AH01630 at error level | None; reload; `.htaccess` read per request |
| LiteSpeed / OLS | Server, vhost and context lists, checked in sequence | Longest prefix within an Allowed/Denied pair | "Trusted IP only" by default, but OLS takes the **leftmost** valid XFF; Cloudflare ranges hard-coded as trusted | Exact-IP hash plus prefix tree; server verdict cached per client | Server level: TCP reset at accept; vhost/context: 403 | OLS ignores `.htaccess` access directives |
| h2o | mruby `acl {}` handler (optional build) | First match | `addr()` returns leftmost XFF, no trust check | IPv4-only Ruby hash trie | 403 | None; SIGHUP |
| Caddy 2.11 | Matcher plus `respond`/`error`/`abort`, subject to directive sort order | AND within a set, OR across repeats | `client_ip` with `trusted_proxies`; leftmost unless `trusted_proxies_strict` | Linear prefix slice (trie PR rejected) | As configured; `abort` closes the connection | Admin API, atomic; no dry run |
| HAProxy 3.x | `acl` plus `http-request deny/tarpit/silent-drop`, `tcp-request connection reject` | Boolean conditions | `src` = TCP peer or PROXY; XFF only by hand (`hdr_ip(...,-1)`) | ebtree longest prefix, v4 and v6 | 403 by default, any status; connection rejects not logged | Runtime `prepare`/`commit acl` (not persisted); `get acl` |
| Traefik 3.7 | `ipAllowList` middleware per router | Allow only; middlewares AND-chained | Peer, or `depth`/`excludedIPs` from the right after entrypoint `trustedIPs` | Linear | 403 or `rejectStatusCode` | Hot reload; no dry run |
| Envoy 1.39 | RBAC filter, per-route override | ALLOW, DENY or LOG policies | `use_remote_address`, `xff_num_trusted_hops`; default takes rightmost XFF | LC-trie per principal | 403 "RBAC: access denied" | Shadow rules; xDS |

### Classic servers attach the rule to whatever ends up serving the request

**nginx** is the reference most administrators know, and its design shows the problem.

- **Scope.** Rules belong to a location and are checked against the location nginx finally selects. Regex locations beat every prefix location that lacks `^~`, so `location /wp-admin/ { allow ...; deny all; }` does not protect `/wp-admin/admin.php` when a `location ~ \.php$` exists ([nginx location docs](https://nginx.org/en/docs/http/ngx_http_core_module.html#location)). The core team closed the classic report as invalid ([trac #956](https://trac.nginx.org/nginx/ticket/956)). The mailing-list fix is to nest the rule inside the PHP regex location ([nginx mailing list, 2020](https://mailman.nginx.org/pipermail/nginx/2020-April/059310.html)). The robust alternative is a `geo` variable tested by `if (...) { return 403; }` at server level, which runs before any location is chosen ([nginx geo docs](https://nginx.org/en/docs/http/ngx_http_geo_module.html)).
- **Three more traps nearby.** Rules run in order and an unmatched client is allowed, so `allow 10.0.0.0/8;` without `deny all` restricts nothing ([ngx_http_access_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_access_module.c)). A level that defines any rule drops every inherited one ([access module docs](https://nginx.org/en/docs/http/ngx_http_access_module.html)). And `return` runs in the rewrite phase, before the access check, so a location with `allow 127.0.0.1; deny all; return 200 "...";` answers everyone ([joshua.hu](https://joshua.hu/nginx-return-allow-deny)); the gixy-next linter now checks for this ([gixy-next](https://gixy.getpagespeed.com/checks/return-bypasses-allow-deny/)).
- **Address handling is good.** realip walks all X-Forwarded-For lines from the right. With `real_ip_recursive on` it skips trusted hops ([realip docs](https://nginx.org/en/docs/http/ngx_http_realip_module.html)). IPv4-mapped clients are matched against IPv4 rules.
- **Operational weak spots.** The 403 is hard-coded. Every denial writes an error-level line, which floods the log under deny lists ([Server Fault 782321](https://serverfault.com/questions/782321/nginx-deny-ip-access-forbidden-by-rule-in-error-log)). An HTTP/3 connection-migration bug let new streams carry an unvalidated client address until 1.30.1 and 1.31.0 (CVE-2026-40460, [nginx advisories](https://nginx.org/en/security_advisories.html)).

**Apache 2.4** replaced 2.2's `Order/Allow/Deny` with authorization providers under `Require`. These use three-valued logic: bare `Require` lines form an implicit `<RequireAny>`, and `Require not` can never grant ([mod_authz_core](https://httpd.apache.org/docs/2.4/mod/mod_authz_core.html)). The logic is expressive: "IP or password" takes two lines. Scope is where it bites.

- **Merge order.** Sections merge in a fixed order (Directory, Files, Location, If). With the default `AuthMerging Off`, the last section with any authorization replaces everything before it. The official docs show a "Whoops" example where a `<Directory>` deny has no effect because a `<Location>` grant merges later. They also warn never to use `<Location>` to protect filesystem objects ([Configuration Sections](https://httpd.apache.org/docs/2.4/sections.html#merging)).
- **PHP bypass.** `ProxyPassMatch` to php-fpm skips `<Directory>` and `.htaccess` processing entirely, so a directory restriction does not cover `/admin/x.php` ([Apache wiki: PHP-FPM](https://cwiki.apache.org/confluence/display/HTTPD/PHP-FPM)).
- **Behind proxies.** mod_remoteip walks right to left and stops at the first untrusted hop. But it "will trust all hosts presenting a RemoteIPHeader IP value" when no proxy list is configured ([mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html)).
- **Migration debris.** A decade after 2.4, the accepted answer on the 621,455-view "allow only one IP" question is still the deprecated 2.2 syntax ([Stack Overflow 4400154](https://stackoverflow.com/questions/4400154/deny-all-allow-only-one-ip-through-htaccess)). Mixing the two syntaxes produces 403s with no obvious cause (AH01797) ([Upgrading to 2.4](https://httpd.apache.org/docs/2.4/upgrading.html)).

**LiteSpeed** has the most efficient structure of the classic servers. It looks the address up in an exact-IP hash, then a longest-prefix subnet tree. It caches the server-level verdict per client, and answers a server-level denial with a TCP reset at accept, before any HTTP work ([OLS accesscontrol.cpp](https://github.com/litespeedtech/openlitespeed/blob/e37d9135c5ab74fae115d2f7220945f502773c1f/src/util/accesscontrol.cpp#L431-L477), [httplistener.cpp](https://github.com/litespeedtech/openlitespeed/blob/e37d9135c5ab74fae115d2f7220945f502773c1f/src/http/httplistener.cpp#L551-L712)). Its weaknesses are the address and compatibility:

- In the default "Trusted IP Only" mode, OpenLiteSpeed takes the **first valid** X-Forwarded-For entry from a trusted peer ([OLS httpsession.cpp](https://github.com/litespeedtech/openlitespeed/blob/e37d9135c5ab74fae115d2f7220945f502773c1f/src/http/httpsession.cpp#L1180-L1262)). A load balancer that appends to a header the client supplied therefore passes the client's choice through.
- The "Yes" and "Use Last IP" modes trust any peer, which LiteSpeed's own docs advise against ([LiteSpeed docs](https://docs.litespeedtech.com/lsws/visitorip/)).
- A hard-coded list of 22 Cloudflare prefixes is trusted by default ([OLS httpserver.cpp](https://github.com/litespeedtech/openlitespeed/blob/e37d9135c5ab74fae115d2f7220945f502773c1f/src/main/httpserver.cpp#L3172-L3193)).
- OpenLiteSpeed reads `.htaccess` for rewrite rules only ([OLS docs](https://docs.openlitespeed.org/security/access/)). Moving a site from Apache silently drops every `Require ip` and `Deny from`, including the `Require all denied` files that applications ship into `vendor/` and `storage/`.

**h2o** is the clearest cautionary example.

- It has no native allow/deny. Access control is an mruby `acl {}` DSL that exists only in builds with mruby ([h2o access control](https://h2o.examp1e.net/configure/access_control.html)).
- Its `addr()` helper returns the leftmost X-Forwarded-For entry by default, with no check of who sent it ([acl.rb](https://github.com/h2o/h2o/blob/master/share/h2o/mruby/acl.rb)). Yet h2o's lead developer wrote in 2016 that "an attacker can spoof the first entry of the header" ([h2o #746](https://github.com/h2o/h2o/issues/746)). The documented example `allow { addr == "127.0.0.1" }` therefore admits anyone who sends `X-Forwarded-For: 127.0.0.1`.
- The bundled CIDR helper handles IPv4 only and returns false for IPv6 ([access_control.mt](https://github.com/h2o/h2o/blob/master/srcdoc/configure/access_control.mt)), so a deny list fails open for every IPv6 client.
- Requests for a trusted-proxy mechanism have been open since 2016 and 2023 ([h2o #3223](https://github.com/h2o/h2o/issues/3223)).

### Proxies got the client address right only after public mistakes

**Caddy** shows how long it takes to get the client address right.

- Its `remote_ip` matcher read X-Forwarded-For by default until v2.3.0 called that "undocumented behavior, and an unsafe default" ([v2.3.0 notes](https://github.com/caddyserver/caddy/releases/tag/v2.3.0)).
- `client_ip` with `trusted_proxies` replaced it, but headers are still parsed **left to right by default**. The right-to-left `trusted_proxies_strict` mode arrived with "a failing test proving the potential security weakness" of the default ([PR #5805](https://github.com/caddyserver/caddy/pull/5805), [global options](https://caddyserver.com/docs/caddyfile/options)).
- Matching is a linear scan. A trie was proposed and closed unmerged in July 2026 ([PR #7906](https://github.com/caddyserver/caddy/pull/7906)).
- The directive sort order runs `respond` after `handle` and `route`, which produced a 403 for the allowed address in a 2025 forum thread ([Caddy community](https://caddy.community/t/cant-get-cf-connecting-ip-to-matcher-to-work/30730)).
- In 2026 the Caddy Defender plugin blocked on `r.RemoteAddr` instead of `client_ip`, so behind a CDN, blocked ranges got through (CVE-2026-46415, CVSS 8.2, [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-46415)).
- Caddy's IP matchers refuse to decide on 0-RTT early data and answer 425 ([v2.9.0 notes](https://github.com/caddyserver/caddy/releases/tag/v2.9.0)).

**HAProxy** has the richest toolkit:

- `acl src -f file` loads networks into longest-prefix trees for IPv4 and IPv6 ([pattern.c](https://github.com/haproxy/haproxy/blob/master/src/pattern.c)).
- Refusals range from `deny` with any status, through `tarpit`, to `silent-drop` and the unlogged `tcp-request connection reject`.
- The runtime API swaps a whole list atomically with `prepare acl`/`commit acl` and can test an address with `get acl` ([management guide](https://github.com/haproxy/haproxy/blob/master/doc/management.txt)).

Its traps:

- Runtime changes are never written to disk and vanish on reload ([HAProxy docs](https://www.haproxy.com/documentation/haproxy-runtime-api/reference/commit-acl/)).
- An ACL on `req.hdr_ip(X-Forwarded-For)` checks every occurrence, so it matches whatever the client sent unless written as `hdr_ip(X-Forwarded-For,-1)`.
- The manual tells back ends to "always use the last occurrence of this header only ... since it is really possible that the client has already brought one" ([configuration manual](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)).

**Traefik** ships the closest precedent to agensio's proposal: an allow-only middleware with no deny counterpart. `ipAllowList` was renamed from `IPWhiteList`; it answers 403 by default, with `rejectStatusCode` added in 3.0 ([Traefik docs](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/ipallowlist/), [PR #10130](https://github.com/traefik/traefik/pull/10130)). Its problems:

- `depth` must equal the exact number of proxies that append. A missing or short header gives an empty address and a 403, with no fallback; the issue has been open since 2021 ([#7884](https://github.com/traefik/traefik/issues/7884)).
- `DepthStrategy` reads only the first X-Forwarded-For line ([strategy.go](https://github.com/traefik/traefik/blob/master/pkg/ip/strategy.go)).
- Middlewares only chain with AND, so "IP or password" cannot be expressed. That is the most-reacted allowlist issue, with 93 thumbs-up ([#6007](https://github.com/traefik/traefik/issues/6007)).
- Lists cannot be shared across routers ([#12249](https://github.com/traefik/traefik/issues/12249)).
- A 2026 PR measured its linear scan at **514,240 ns per non-matching lookup at 100,000 addresses**, against 23.5 ns with a hash plus merged ranges ([PR #13077](https://github.com/traefik/traefik/pull/13077)). The scan is irrelevant at tens of entries and decisive at feed sizes.

**Envoy** has the only real dry run among the eight: `shadow_rules` with `shadow_allowed`/`shadow_denied` statistics, plus a `LOG` action ([RBAC filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/rbac_filter)). Since August 2025 it uses an LC-trie per IP principal ([commit a11b369](https://github.com/envoyproxy/envoy/commit/a11b3698fddb0bc9eadb4a506bf5203f835e51f4)). It explicitly separates `direct_remote_ip`, the socket peer, from `remote_ip`, the derived client ([rbac.proto](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/rbac/v3/rbac.proto)). Its trap is the default: with `use_remote_address: false`, the client address is the rightmost X-Forwarded-For entry, which the client controls at the edge. Envoy's own edge guidance says to set it to true ([XFF docs](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers), [edge best practices](https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge)). CVE-2024-45806 fixed a default that treated every RFC 1918 source as internal ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-45806)).

Read together, the eight show which traits hold up in real deployments. The robust servers:

- check the address before, or independently of, handler selection (nginx's server-level `geo` plus `if`; LiteSpeed's sequential gates);
- walk the merged forwarded list from the right past an explicit trust list (nginx recursive realip, mod_remoteip, Caddy strict, Envoy `xff_trusted_cidrs`);
- canonicalise address families;
- let operators test a rule before it bites (Envoy shadow rules, HAProxy `get acl`).

The fragile ones attach rules to a handler, default to the leftmost header value, or silently ignore what they do not support. agensio's proposal is already in the first group on scope and address source; the question is whether the details hold.

## Administrators want one address on one path, and keep losing to the plumbing

**Demand.** Stack Exchange view counts give a clear ranking of what administrators need:

1. **Restrict a whole site or one directory to one address.** "Deny all, allow only one IP" has 621,455 views ([SO 4400154](https://stackoverflow.com/questions/4400154/deny-all-allow-only-one-ip-through-htaccess)). Restricting a site to one IP before launch has 113,491 ([SO 8438867](https://stackoverflow.com/questions/8438867/how-can-i-allow-access-to-a-single-ip-address-via-nginx-conf)), and restricting a directory 161,388 ([SF 137907](https://serverfault.com/questions/137907/how-to-restrict-access-to-directory-and-subdirs)).
2. **Get the real client address behind a proxy**, the precondition for every rule: 143,036 views ([SF 314574](https://serverfault.com/questions/314574/nginx-real-ip-header-and-x-forwarded-for-seems-wrong)).
3. **IP or password**: 79,082 views ([SO 10419592](https://stackoverflow.com/questions/10419592/htaccess-htpasswd-bypass-if-at-a-certain-ip-address)), plus Traefik's 93-reaction issue.
4. **Block ranges and countries**: 66 votes for blocking 100,000 addresses ([SO 15579620](https://stackoverflow.com/questions/15579620/how-to-block-100-000-individual-ip-addresses)); a GeoIP request with 128 comments ([NPM #46](https://github.com/NginxProxyManager/nginx-proxy-manager/issues/46)).
5. **Only the CDN may reach the origin** ([SF 601339](https://serverfault.com/questions/601339/how-do-i-deny-all-requests-not-from-cloudflare); a one-click toggle in [CloudPanel](https://www.cloudpanel.io/docs/v2/frontend-area/security/)).
6. **Maintenance mode except the admin.**

Most of these are scoped to a path: an admin directory, a login script, a phpMyAdmin alias. That is exactly where location-matching pitfalls bite.

**Complaints** are structural, not syntactic, and they fall into four groups.

- **The rule sits on one location while another serves the request.** In 2025 a HestiaCP user added `location /wp-admin/ { allow MY-IP; deny all; }` and it "has no effect". The working version copies the whole FastCGI block into a regex location, in a vhost file the panel overwrites on rebuild ([HestiaCP forum](https://forum.hestiacp.com/t/restrict-wp-admin-by-ip/18456)).
- **The address tested is not the address the admin thinks.**
  - After `real_ip_header CF-Connecting-IP`, allowing Cloudflare's ranges refuses everyone, because the rules now see visitors ([SF 601339](https://serverfault.com/questions/601339/how-do-i-deny-all-requests-not-from-cloudflare)).
  - `Require ip 127.0.0.1` fails for a `::1` client ([SO 26699006](https://stackoverflow.com/questions/26699006/require-ip-127-0-0-1-works-sometimes-and-sometimes-it-wont)).
  - Rules break once IPv6 arrives ([SO 24422044](https://stackoverflow.com/questions/24422044/adding-an-ipv6-address-to-require-ip-in-phpmyadmin-conf-in-linux); [NPM #1671](https://github.com/NginxProxyManager/nginx-proxy-manager/issues/1671)).
  - IPv6 privacy addresses rotate about daily, so the answer is to allow the /64 ([SF 958682](https://serverfault.com/questions/958682/whitelist-an-individuals-ipv6-range-via-htaccess)).
  - A local proxy makes every client 127.0.0.1 ([SF 948073](https://serverfault.com/questions/948073/apache2-4-require-ip-not-working-because-127-0-0-1)).
- **Lists have to be repeated.** Twenty routers mean twenty copies of the management addresses ([Traefik #12249](https://github.com/traefik/traefik/issues/12249)), and the same question exists for nginx ([SF 916584](https://serverfault.com/questions/916584/nginx-common-ip-whitelist-for-all-subdomains)). A HestiaCP user asked to lock `/wp-admin` on 100+ sites from the panel ([HestiaCP forum](https://forum.hestiacp.com/t/restricting-access-to-directories-by-ip-from-the-panel/8180)).
- **Lockouts and opaque refusals.**
  - Many users "don't understand that their public IP address is dynamic and would accidentally lock themselves out" ([MainWP](https://community.mainwp.com/t/dashboard-lock-down-ip-address/3226)).
  - Apache's `AH01630` line shows the client address but not the rule that refused it ([SF 418101](https://serverfault.com/questions/418101/apache-client-denied-by-server-configuration-despite-allowing-access-to-direc), 194,216 views).
  - Traefik logs HTTP refusals only at debug level ([#13581](https://github.com/traefik/traefik/issues/13581)).
  - "Return 404 instead of 403" draws 50,562 views ([SO 1486304](https://stackoverflow.com/questions/1486304/is-there-a-way-to-force-apache-to-return-404-instead-of-403)).

**Praise** is thinner in the sources that could be reached; Reddit refused all requests. The designs that get recommended share three properties:

- a **named, reusable address set** (nginx `geo`, Caddy named matchers, Apache containers);
- an **explicit trust boundary** for forwarded addresses (`set_real_ip_from`, Caddy `trusted_proxies`);
- **readable composition**.

Panels mostly offer deny lists or restrict the panel login itself. Per-path allow-lists are left to raw directives pasted into "additional directives" boxes ([Plesk KB](https://support.plesk.com/hc/en-us/articles/12377517812759-How-to-allow-access-to-a-website-directory-from-specific-IP-address-in-Plesk)). Forge offers no way to set them through its interface ([Laravel Forge docs](https://laravel.com/forge/docs/sites/network)). Plesk users with "a large number of IP access rules" asked for a remark column to label them "Office Firewall" or "Corporate VPN" ([Plesk forum](https://talk.plesk.com/threads/feature-request-add-a-remark-column-to-ip-access-restriction-management.394740/)). That is the gap a control plane with typed rules can fill.

**Incidents** fall into four classes, and 2026 shows new software repeating the old mistakes.

- **Path-normalisation differences** between the rule and the handler:
  - Tomcat's `..;/` behind nginx ([Orange Tsai, Black Hat 2018](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf));
  - Apache's own CVE-2021-41773 ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-41773)).
- **Spoofable headers:**
  - a series of WordPress security plugins ([CVE-2022-4529](https://cveawg.mitre.org/api/cve/CVE-2022-4529) and siblings);
  - phpSysInfo in August 2026 ([NVD CVE-2026-55584](https://nvd.nist.gov/vuln/detail/CVE-2026-55584));
  - PrestaShop's maintenance allowlist ([advisory](https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-2cr4-vw9p-pjvf)).
- **An empty allowlist treated as "allow all":** nginx-ui's MCP endpoint (CVE-2026-33032, CVSS 9.8) ([GitLab advisory](https://advisories.gitlab.com/golang/github.com/0xjacky/nginx-ui/CVE-2026-33032/)).
- **Address-form mismatches:**
  - proxy-addr, where a `::/1`-shaped IPv6 trust entry matched every IPv4 client (CVE-2026-90711, [advisory](https://github.com/jshttp/proxy-addr/security/advisories/GHSA-jqcg-44mw-7w3h));
  - coturn, bypassed with `::ffff:127.0.0.1` ([advisory](https://github.com/coturn/coturn/security/advisories/GHSA-j8mm-mpf8-gvjg));
  - Grafana, where a bare IPv6 address meant its whole /32 ([CVE-2026-33376](https://grafana.com/security/security-advisories/cve-2026-33376)).

## The proposal removes the worst trap but inherits five gaps

### Most of the design is what the evidence asks for

| Design element | Evidence in favour | What it leaves open |
|---|---|---|
| Site rule checked on the normalised path before `Router::location` | The location bypass is the most-repeated complaint (nginx #956, SF 137907, HestiaCP 2025). nginx's own robust workaround is a server-level check before location choice. It also avoids Apache's `ProxyPassMatch` and `<Location>` merge traps and nginx's `return`-before-access hole. | How proxied and front-controller apps read the path; prefix semantics (gaps 2 and 3) |
| `try_files` fallback target re-checked | nginx re-runs the access phase on every internal redirect | Nothing material |
| Longest path decides, lists not merged | Avoids Apache's merge order and nginx's "allow without deny all". Fails closed, because every rule is an allow list | No "anyone" value to carve an exception; the same office list repeated per site |
| Allow lists only, empty list refused | nginx `allow` without `deny all` restricts nothing; Apache `Order Deny,Allow` admits unmatched clients; h2o deny lists fail open on IPv6; Traefik is allow-only; nginx-ui's empty list meant "allow all" | Blocking a visitor behind a CDN has no other home |
| Peer, or rightmost untrusted XFF hop behind `trusted_proxies` | MDN ([X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For)), Pritchard ([adam-p.ca](https://adam-p.ca/blog/2022/03/x-forwarded-for/)), nginx, mod_remoteip | Only the first XFF line is read (gap 1); other tenants of the same CDN can re-front the origin |
| 403 with a constant page | RFC 9110 15.5.4; nginx, Apache and IIS defaults | The refused user cannot see the address tested |
| Error line at most once a second per worker, plus access log and `agensio-auth` | nginx floods its error log; journald drops lines above 10,000 per 30 s ([journald.conf](https://man7.org/linux/man-pages/man5/journald.conf.5.html)); OWASP says logging must not deplete resources ([Logging cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)). The jail reads the access log, so suppressing error lines does not blind it | Collateral bans; bans are ineffective behind a CDN |
| At most 32 rules of 64 entries, scanned linearly | nginx reserves `geo` for "a lot of rules"; a linear scan hurts only at thousands of entries | A path scan on every request of a site with rules; the gate measures only sites without rules |
| `rules.restricted` through admin-only `site_update` | Panels lack per-path allow-lists or push raw directives | Preset knowledge (WordPress exceptions); named sets |
| `-t`/health warning when an allow entry overlaps `trusted_proxies` | Exactly the SF 601339 trap; a proxy on the list admits everything it forwards | Loopback and tunnels, IPv6, nested roots, CDN caches |

Two of the design's properties deserve credit beyond the table:

- **Every handler is covered.** Because the rule runs before routing, it applies to redirects, proxies and the static cache alike. Neither nginx's `return` hole nor LiteSpeed's reported problem of LSCache answering before new access rules ([StackHarbor KB](https://stackharbor.com/en/knowledge-base/litespeed-htaccess-compatibility/), a secondary source) can occur.
- **HTTP/3 is not exposed to nginx's spoofing bug.** In agensio's HTTP/3 path, `remote_from()` is called once, when the connection is created (`src/http3/connection.hpp`, read 2026-10-07). The address used for decisions therefore never follows a migration. nginx's CVE-2026-40460 was new streams receiving an unvalidated migrated address; that cannot happen here. The trade-off is that after a NAT rebinding, requests are judged on the address the handshake proved.

### Five gaps, four of them confirmed in agensio's source

#### Gap 1: only the first X-Forwarded-For line is read

`resolve_forwarded` (`src/core/forwarded.hpp`) calls `req.headers.get("x-forwarded-for")`. `Headers::get` returns the first matching field, and the HTTP/1 parser keeps repeated X-Forwarded-For lines as separate fields. `handlers/proxy.cpp` does the opposite and keeps the last.

MDN says the lines "must be treated as a single list" and that using one of them "is insufficient". Pritchard documents the same flaw in Go's `Header.Get`. Traefik's `DepthStrategy` has it too. HAProxy's manual tells back ends to use the last occurrence because the client may already have sent one.

So behind HAProxy, a client that sends `X-Forwarded-For: 10.1.2.3` becomes 10.1.2.3 in agensio's access log, in `REMOTE_ADDR`, in fail2ban's view, and, once this feature ships, in the allow-list decision. This is a **pre-existing bug**. The feature turns it into an access-control bypass.

#### Gap 2: prefix semantics

`Router::location` uses `path.starts_with(loc.path)`. If access rules reuse that comparison:

- a rule written `path = "/cp/"` misses the request `/cp`, where Statamic's control panel answers in agensio's own test bed;
- a rule written `/cp` also restricts `/cpanel-help`.

Front-controller frameworks route bare paths without a trailing slash, so the first case is a real bypass, not a cosmetic one.

#### Gap 3: how the origin reads the path

The rule matches agensio's normalised path, but a proxied origin receives the raw target, as nginx hands it on. agensio's normaliser (`src/path.cpp`) treats `..;` as an ordinary segment name. So `/public/..;/admin/` normalises to a path outside `/admin/`, while Tomcat reads `..;` as `..` and serves `/admin/`. That is Orange Tsai's bypass. Spring's StrictHttpFirewall rejects `;`, encoded `/` and `.`, and `//` by default for exactly this reason ([Spring Security](https://docs.spring.io/spring-security/reference/servlet/exploits/firewall.html)). agensio already handles the encoded-slash direction conservatively: `%2F` is decoded into a real separator before dot segments are resolved, so `/public%2F..%2Fadmin/` normalises to `/admin/` and is refused.

A related hypothesis needs a test before it is called a finding. Symfony-based front controllers (Laravel, Statamic, Drupal) are commonly reachable through `/index.php/<route>` as well as `/<route>`. If so, `/index.php/cp` reaches the control panel while a `/cp` rule never matches it. I did not verify this against agensio's FastCGI parameters; the Statamic bed can settle it in minutes.

#### Gap 4: address canonicalisation

Listeners on `[::]` are dual-stack (`v6_only(false)` in `src/server.cpp` and the QUIC socket), so IPv4 clients arrive as `::ffff:a.b.c.d`. `Cidr::contains` (`src/net/cidr.hpp`) maps them correctly for IPv4 entries, as nginx does. But an IPv6 entry is compared against the mapped bytes, so an entry with zero leading bits matches every IPv4 client. That is the shape of the 2026 proxy-addr CVE. The access log also prints the mapped text, where Apache records mapped clients "in their IPv4 representation" ([mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html)). One thing is already right: a bare address already means /32 or /128, which avoids the Grafana CVE.

#### Gap 5: WordPress exceptions and fail2ban collateral

Protecting `/wp-admin/` by address breaks `admin-ajax.php`, which the public front end calls ([SO 70737616](https://stackoverflow.com/questions/70737616/protect-wp-admin-while-whitelisting-admin-ajax-php)). The design has no value meaning "anyone" with which to carve that path out. With the shipped `agensio-auth` jail (ten 401/403 answers in ten minutes bans ports 80 and 443 for an hour, `packaging/fail2ban/jail.d/agensio.conf`), an ordinary visitor whose page fires AJAX calls would be banned from every site on the host.

#### Smaller findings

- **A stale trust verdict.** The cached trusted-peer verdict (`trusted_checked_` in all three connection types) is never reset on reload. A proxy removed from `trusted_proxies` keeps being believed on connections it already holds. This is the same class as the 2026-10-07 fix for connection limits.
- **fail2ban cannot protect a CDN-fronted site.** The access log carries the derived visitor address, so a ban drops packets that never come from that address; the visitor's traffic arrives from CDN edges. For such sites the 403 itself is the only enforcement.
- **Shared caches.** A shared cache in front can store an allowed client's heuristically cacheable 200 ([RFC 9110 15.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.1)) and serve it to anyone.
- **Other tenants of the same CDN.** Trusting Cloudflare's ranges proves only that a request came through *some* Cloudflare tenant ([Certitude](https://certitude.consulting/blog/en/using-cloudflare-to-bypass-cloudflare/); [Cloudflare docs](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/)). Pritchard describes the resulting re-fronting attack on forwarded addresses.

## Thirteen changes make it robust, helpful and nearly free

| # | Change | Evidence | Cost on the request path |
|---|---|---|---|
| 1 | Walk every X-Forwarded-For line, last line first, in `resolve_forwarded`; use the same merged list in `handlers/proxy.cpp` | MDN; HAProxy manual; Pritchard; Traefik `DepthStrategy` | None for direct clients; one header scan behind trusted proxies |
| 2 | Match rule paths on segment boundaries: `/cp` and `/cp/` both cover `/cp` and `/cp/…`, never `/cpanel` | `Router::location` uses `starts_with`; Statamic's `/cp` | One character test |
| 3 | For targets that miss the plain-path fast path, also test the raw path and the path with `;` parameters stripped from each segment; refuse if any reading falls under a rule the client fails. For PHP presets with a front controller, also test the path after `/index.php` once a test confirms the bypass | Orange Tsai `..;/`; Spring StrictHttpFirewall; CVE-2021-41773 | Zero on plain targets; the slow path already runs |
| 4 | Unmap `::ffff:a.b.c.d` once at accept (text and binary); convert mapped-form entries to IPv4 at parse; refuse zone ids, brackets and ports in entries | proxy-addr CVE-2026-90711; coturn CVE-2026-27624; [RFC 9844](https://www.rfc-editor.org/rfc/rfc9844.html); Apache's IPv4 logging | Once per connection |
| 5 | Reset the cached trusted-peer verdict when a connection picks up a new generation | `trusted_checked_` never reset in h1, h2, h3 | None; the generation compare exists |
| 6 | Add an explicit `any` entry for exception rules. A WordPress `/wp-admin/` rule keeps `/wp-admin/admin-ajax.php` open by default and suggests `/wp-login.php` too; MCP texts list each preset's admin paths | SO 70737616; hosting lock-down guides ([InMotion](https://www.inmotionhosting.com/support/edu/wordpress/lock-down-wordpress-admin-login-with-htaccess.md)); the `agensio-auth` jail | None |
| 7 | Named address sets with a label, `allow = ["@office"]`, defined by root and expanded at load | Traefik #12249; SF 916584; HestiaCP's 100+ sites; Plesk's remark request; nginx `geo` and Caddy named matchers | None |
| 8 | `access-check SITE PATH ADDRESS` (ctl and MCP) as a pure function over the configuration; optional `mode = "report"` that logs instead of refusing | Envoy shadow rules; HAProxy `get acl`; dynamic-IP lockouts | None, or one branch |
| 9 | A refusal record: the log line names site, deciding rule, derived and peer address, method, path and the count of suppressed lines; an eight-slot per-worker sample shown by `site_show` and health; the tested address printed on the 403 page | AH01630 names no rule; nginx's floods; Traefik's debug-only logging; the `::1` diagnosis in SO 26699006 | Refusal path only |
| 10 | More `-t`/health findings: loopback or private entries (a local proxy or tunnel makes everyone local); an IPv4-only list on an IPv6-reachable site; single IPv6 addresses (suggest the /64); a restricted root reachable through another site's root; a restricted path behind `trusted_proxies` (shared caches, CDN tenants) | SF 948073; SO 24422044; NPM #1671; SF 958682; Apache's warning against URL-scoped protection of files; Certitude | None |
| 11 | `Cache-Control: no-store` prebuilt into the 403 page | [RFC 9110 15.5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.5) and 15.1; CDNs set to "cache everything" | None |
| 12 | A first-byte bitmap over rule paths; per-family entry arrays compared as machine words; XFF entries parsed without a temporary `std::string`; an A/B row for a site with rules | nginx's per-family arrays; [iprbench](https://github.com/gaissmai/iprbench) | One bit test for unrestricted paths |
| 13 | Leave room in the rule for `users` (IP **or** password) and for answering 425 to 0-RTT on restricted paths when 0-RTT lands | Traefik #6007 (93 reactions); SO 10419592 (79,082 views); h2o and Caddy answer 425 | None now |

**Order of work.** Rows 1, 4 and 5 fix bugs that already exist. They harden the access log, `REMOTE_ADDR` and fail2ban today, so they belong in their own bug-fix commits ahead of the feature, each with a test that fails first. The highest-value one is row 1. Rows 2, 3 and 6 are part of the feature, and should be among its failing-first tests: a rule on `/cp/` refusing `/cp`; `/public/..;/admin/` refused through the proxy fixture; a front-end request to `admin-ajax.php` answered under a `/wp-admin/` rule.

**What makes it helpful for agents.** Rows 7 to 10 turn the feature from a correct filter into something an agent can operate.

- **Named sets** let "restrict the admin of all 40 WordPress sites to the office" be one set plus forty rules. When the office address changes, one edit updates every site.
- **The check command** answers "will this lock the user out?" before `site_update` applies a rule. Report-only mode lets an agent enable a rule, ask the user to browse, and confirm from the refusal sample that the user's address would have passed.
- **The refusal sample and the address on the 403 page** give the human the one number they need to tell the agent, after their dynamic address changes.
- **The operator cannot be locked out.** The control socket is a unix socket the rules never touch, so the agent can always repair a lockout, which no web panel on nginx can promise.

**Cost model.** A linear scan of fixed-size masked compares costs on the order of a nanosecond per entry. That is the notes' estimate, not a measurement. A modern trie answers longest-prefix lookups in about 17 to 24 ns even on large tables ([iprbench](https://github.com/gaissmai/iprbench)). Against agensio's roughly 2 µs per plain 1 KB request on Linux (CLAUDE.md performance notes), the address part is noise at 64 entries.

What is not noise in the current plan is scanning up to 32 rule paths on *every* request of a site that has rules, including its public pages. A 256-bit bitmap of the first byte after `/` across all rule paths makes that one bit test for unrestricted requests. A rule on `/` sets every bit, which is correct, because then everything is restricted.

The proposed gate (`bench/ab.sh <base> -2 -3`, all rows flat) measures only the emptiness test, because the benchmark sites have no rules. Add two rows:

- a site with a `/wp-admin/` rule while benchmarking `/`, the unrestricted path on a site with rules;
- a `path = "/"` rule of 64 entries whose matching entry is last, allowing 127.0.0.1, which is the worst allowed case.

## The four open questions have evidence-backed answers

### Question 1: answer 403, with `no-store`

RFC 9110 defines 403 as a server that "understood the request but refuses to fulfill it". It allows 404 only for a server that wishes to "hide" a resource's existence ([RFC 9110 15.5.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.4)). In this design the hiding benefit is small. The rule fires before routing, for existing and missing paths alike, so a 403 tells an outsider only that a prefix is restricted. For `/wp-admin/` that prefix is public knowledge, and for `path = "/"` the host name already reveals the site.

The costs of 404 are concrete:

- **Confusion.** GitHub, which answers 404 for private resources, has to tell users that a 404 on a resource they know exists means checking their authentication ([GitHub REST troubleshooting](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api)). An admin whose dynamic address changed would see their admin page "missing", not "refused".
- **Caching.** 404 is heuristically cacheable ([RFC 9110 15.5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.5)) and 403 is not. A shared cache could store an outsider's 404 and serve it to the allowed admin.
- **Detection is indifferent.** CrowdSec's probing scenarios count 403 and 404 alike ([CrowdSec hub](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/http-probing.yaml)). agensio's jails catch either: `agensio-auth` at ten 403s in ten minutes, `agensio-scan` at forty 404s in five.

The 404s agensio already uses (`rules.private`, `handler = "deny"`, hidden files) all mean "nobody may fetch this". A restricted path means "some may", which is what 403 says.

The steelman for 404 is OWASP's advice to answer 404 when existence itself is sensitive ([OWASP IDOR cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)), together with the steady demand for 404-instead-of-403 recipes. IIS is the precedent for making it a per-rule choice ([IIS ipSecurity](https://learn.microsoft.com/en-us/iis/configuration/system.webServer/security/ipSecurity/)).

Recommendation: ship 403 with the constant page plus `Cache-Control: no-store`. Leave a per-rule `status = 404` as a cheap later addition, for a case such as a secret staging host, only if the owner sees demand.

### Question 2: allow lists only, with an explicit exception value

Every ordering trap in the record comes from mixing allow and deny:

- nginx's `allow` without `deny all` restricts nothing;
- Apache's `Order Deny,Allow` admits unmatched clients by default;
- `Require not` cannot stand alone;
- h2o's deny lists fail open for IPv6.

Traefik shipped allow-only and kept it. Per-address blocking at scale belongs to structures built for size: nginx `geo`, HAProxy's tree files and runtime API, nftables sets. nginx's own docs push large lists there. That matches agensio's 2026-10-02 decision to leave per-address limits to the firewall and fail2ban.

Two refinements follow from the evidence:

- Rules need an explicit `any` value, so that a longer path can reopen a subtree (WordPress's `admin-ajax.php`). An empty list must stay an error, given the nginx-ui CVE.
- The one case the firewall cannot serve is blocking a visitor of a CDN-fronted site, because the host only sees the CDN's edges. If that need appears, it should be a separate site-wide blocklist keyed on the derived address and built as a trie loaded from a file, not deny entries mixed into path rules.

### Question 3: keep `allow` and `[[site.access]]`, and give both layers one shape

The evidence on names is thin, so this is a judgment.

- **`allow` and "access".** `allow` is the universal verb: nginx `allow`, LiteSpeed "Allowed List", Traefik `ipAllowList`, Envoy `ALLOW`. Traefik's forced rename away from `IPWhiteList` left a dashboard regression behind ([#10434](https://github.com/traefik/traefik/issues/10434)), so avoid "whitelist" entirely. "Access" is the term nginx (the access module), Apache ("Access Control") and LiteSpeed ("Access Control") all use for this feature, so `[[site.access]]` is what an administrator will search for.
- **`rules.restricted`.** It reads well beside `rules.private`: "nobody" next to "only these". Keep it. The rendered table and the rule should carry identical keys (`path`, `match`, `allow`), so an agent learns one shape. The MCP text should say once that `restricted` renders as `[[site.access]]`.
- **Set names.** The named sets of recommendation 7 should be referenced with a sigil such as `@office`, so a set name can never be confused with an address.

### Question 4: allow `path = "/"`

Restricting a whole site is the single largest use case in the record. It is the 621,455-view and 113,491-view questions, maintenance mode, and the per-domain allowlists requested on cPanel and HestiaCP. The design already exempts the ACME challenge, so certificates keep renewing on a locked staging site, and the control socket, so the operator cannot be locked out.

Two additions make it safe to leave on:

- `sites` and `site_show` mark a site restricted as a whole, and health reports it as an informational finding, so a staging rule is not forgotten after launch.
- The documentation says plainly that "only my CDN may reach this origin" is a different feature. It tests the peer rather than the client, and an allow list of Cloudflare ranges behind `trusted_proxies` refuses everyone, the SF 601339 trap. That need belongs in the nftables ruleset agensio already renders, with authenticated origin pulls when it must mean "through my zone".

## Conclusion

The record overturns the intuitive framing of this feature. The hard part of IP access control is not matching an address against a list; no major server's matcher has been the cause of a recorded bypass. The hard parts are agreeing on the path, so that the rule, the router and the application read the same request, and agreeing on the address, so that the rule sees the hop the operator trusts. agensio holds an unusual advantage here. The normaliser, the router, the forwarded-header parsing, the logs, the fail2ban renderer and the control plane are one codebase. It can therefore do what no panel layered on nginx can: make the rule follow the path, refuse readings it cannot disambiguate, explain a refusal to an agent, and warn before a mistake ships.

The most valuable work this research uncovered is not in the new feature. The single-line X-Forwarded-For read, the unmapped dual-stack addresses and the trust verdict that survives a reload already let a client behind HAProxy choose the address agensio logs, hands to PHP and feeds to fail2ban. Fixing them first, as their own commits, hardens today's server and makes the allow-list trustworthy on the day it lands.
