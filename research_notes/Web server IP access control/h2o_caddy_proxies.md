# Address-based access control in h2o, Caddy, HAProxy, Traefik and Envoy (state as of 2026-10-07)

Versions looked at: h2o master (h2o no longer tags releases), Caddy v2.11.7 (2026-10-03), HAProxy master
(manual header says 3.5, tags at v3.5-dev8), Traefik v3.7.14 (2026-10-06), Envoy v1.39.3 (2026-10-06).
Source files were read from each project's default branch on 2026-10-07; line-level claims about code
refer to that snapshot.

## h2o: is there a native allow/deny, how is it done, and how is the client address determined?

### Takeaway
h2o has no built-in allow/deny directive in its configuration. Address control is an mruby `acl { }` DSL
(since 2.1) that runs Ruby per request. Its `addr()` helper **by default returns the left-most
X-Forwarded-For entry with no trusted-proxy check**, so any client can spoof it. The bundled CIDR helper
(`TrieAddr`) supports IPv4 only. h2o has no `real_ip`/trusted-proxy mechanism at all; the issues asking
for one have been open since 2016 and 2023.

### Cited Findings
- **Release model**: h2o stopped tagging versions in 2019. Its release notice (republished 2026-01-19) says "Users are advised to use the up-to-date commit of the master branch". The last tags are v2.2.6 and v2.3.0-beta2 (2019-08-13). — [h2o release "We no longer tag versions!"](https://github.com/h2o/h2o/releases/tag/tag-no-more-releases)
- **ACL DSL**: "Starting from version 2.1, H2O comes with a DSL-like mruby library which makes it easy to write access control list (ACL)." It is configured as `mruby.handler: | acl { ... }` under a `paths:` entry, ahead of e.g. `file.dir`. — [h2o docs: Access Control](https://h2o.examp1e.net/configure/access_control.html)
- **ACL methods**: `allow { cond }` delegates the request to the next handler. `deny { cond }` returns `403 Forbidden`. `respond(status, header={}, body=[]) { cond }` returns any response. `redirect(location, status=302) { cond }` redirects. `use(handler) { cond }` applies another handler (e.g. `Htpasswd`) conditionally. Condition helpers are `addr(forwarded=true)`, `path`, `method`, `header(name)` and `user_agent`. — [h2o docs: Access Control](https://h2o.examp1e.net/configure/access_control.html)
- **Evaluation order**: first match wins. "The filter defined by the method that first matched the accompanying condition gets applied". If nothing matches, the handler returns 399, which means "delegate to next handler". A filter without a condition matches everything. `acl` may be called only once per handler, and the server refuses to start otherwise. — [h2o docs: Access Control](https://h2o.examp1e.net/configure/access_control.html)
- **Implementation**: `ACLHandler#call` walks the `@acl` array in order and calls the first entry whose condition `instance_eval`s true. Each condition is evaluated by creating a new `MatchingBlock.new(env)` per check. `deny` is `respond(403, {}, ["Forbidden"])` and `allow` is `respond(399, {}, [])`. — [h2o share/h2o/mruby/acl.rb](https://github.com/h2o/h2o/blob/master/share/h2o/mruby/acl.rb)
- **`addr()` spoofing pitfall (source)**: `def addr(forwarded=true)` takes `@env['REMOTE_ADDR']`, but `if forwarded && (xff = @env['HTTP_X_FORWARDED_FOR'])` it returns `xff.split(",")[0]`, the **left-most** entry, with no check of who sent it. — [h2o acl.rb](https://github.com/h2o/h2o/blob/master/share/h2o/mruby/acl.rb). The documentation states the same default: "If true, returns the value of X-Forwarded-For header if it exists. Default value: true" — [h2o srcdoc access_control.mt](https://github.com/h2o/h2o/blob/master/srcdoc/configure/access_control.mt)
- **The documented example uses that default**: `allow { addr == "127.0.0.1" }` and `deny { user_agent.match(/curl/i) && ! addr.start_with?("192.168.") }`. — [h2o docs: Access Control](https://h2o.examp1e.net/configure/access_control.html)
- **h2o's lead developer has called the first XFF entry spoofable**: in issue #746 (2016) kazuho wrote "if `x-forwarded-for` header already exists, a web server is expected append the peer addresses. That means that an attacker can spoof the first entry of the header by setting the header to an arbitrary value." In the same thread he said `%h` in the access log is the connected peer, as in Apache. — [h2o issue #746](https://github.com/h2o/h2o/issues/746)
- **0-RTT**: `addr()` raises `TooEarlyError` if `HTTP_EARLY_DATA` is set, and the ACL handler then answers **425** for the whole ACL. — [h2o acl.rb](https://github.com/h2o/h2o/blob/master/share/h2o/mruby/acl.rb)
- **CIDR matching**: `require "trie_addr.rb"; trie = TrieAddr.new.add(["192.168.0.0/16", "172.16.0.0/12"]); acl { allow { trie.match?(addr) }; deny }`. "This library currently supports only IPv4 addresses. `TrieAddr#match?` returns `false` when it receives an invalid IPv4 address (including an IPv6 address)". — [h2o srcdoc access_control.mt](https://github.com/h2o/h2o/blob/master/srcdoc/configure/access_control.mt)
- **TrieAddr data structure**: a 256-ary trie of Ruby `Hash`es keyed by octet *strings*, using shared `FULFILL`/`REJECT` sentinel leaves. `match?` does `ip.split(".", 4)` and then four hash lookups, `@root[s[0]][s[1]][s[2]][s[3]].equal?(FULFILL)`. Lookup cost is constant (4 lookups) whatever the list size. Each lookup allocates a String array per request. — [h2o trie_addr.rb](https://github.com/h2o/h2o/blob/master/share/h2o/mruby/trie_addr.rb)
- **Plain mruby alternative**: the mruby docs restrict to 192.168/16 with `if /\A192\.168\./.match(env["REMOTE_ADDR"]) return [399, {}, []]`. Status 399 delegates to the next handler. — [h2o docs: mruby](https://h2o.examp1e.net/configure/mruby.html)
- **mruby is optional at build time**: `WITH_MRUBY` "is turned on by default if the prerequisites (bison, ruby and the development files) are found", and `-DWITH_MRUBY=on|off` overrides it. A build without mruby has no ACL feature at all. — [h2o install docs](https://h2o.examp1e.net/install.html)
- **No trusted-proxy/real-IP directive**: the proxy directives cover only emitting headers. `proxy.emit-x-forwarded-headers` (default ON) appends or adds `x-forwarded-proto`/`x-forwarded-for`. `proxy.preserve-x-forwarded-proto` defaults OFF "as a precaution measure to prevent an attacker connecting through HTTP to lie that they are connected via HTTPS". `proxy.proxy-protocol` sends PROXY protocol *to* the upstream. — [h2o docs: proxy directives](https://h2o.examp1e.net/configure/proxy_directives.html)
- **Inbound PROXY protocol** is a listen option. When ON, h2o "tries to parse the first octets of the incoming connections as defined in version 1 of the specification" and passes those addresses to applications and logging. — [h2o docs: base directives](https://h2o.examp1e.net/configure/base_directives.html)
- **Open feature requests**: #746 "pass and get Real IP from upstream / proxy" (open since 2016-02-08; a 2017 comment asks for an equivalent of Apache's mod_remoteip). #3223 "Cloudflare Real IP" (open since 2023-04-16, asking for nginx `set_real_ip_from`/`real_ip_header`); the only reply suggests the mruby ACL plus logging `%{X-Forwarded-For}i`. #1617 "Add support for Forwarded header (RFC 7239)" (open since 2018). — [#746](https://github.com/h2o/h2o/issues/746), [#3223](https://github.com/h2o/h2o/issues/3223), [#1617](https://github.com/h2o/h2o/issues/1617)
- **The one native address ACL is for CONNECT destinations, not clients**: PR #3588 "Implement port range ACL" adds "support for port ranges in proxy.connect ACL list" (closed 2026-06-23). — [h2o PR #3588](https://github.com/h2o/h2o/pull/3588)
- **Reload**: in `master` mode (using `share/h2o/start_server`), "Users may send SIGHUP to the master process to reconfigure or upgrade the server". An ACL change therefore means a graceful restart. — [h2o srcdoc command_options.mt](https://github.com/h2o/h2o/blob/master/srcdoc/configure/command_options.mt)

### Inferences
- In the documented example, `allow { addr == "127.0.0.1" }` lets any remote client in if it sends `X-Forwarded-For: 127.0.0.1`. A safe h2o ACL must call `addr(false)`, or read `env["REMOTE_ADDR"]` directly. h2o's own maintainer called the first XFF entry spoofable, yet the default does the opposite. This is the clearest "insecure default" among the five servers.
- `TrieAddr` is IPv4-only and returns false for IPv6. An allow-list (`allow {match}; deny`) therefore fails closed for IPv6 clients, while a deny-list (`deny {match}`) **fails open** for every IPv6 client.
- Per-request cost: an mruby call, one `MatchingBlock` allocation per condition evaluated, and String splitting. That is much heavier than C-level matching, but no measured figure was found (see Gaps).
- h2o has no dry-run mode, no denial-specific logging (the 403 appears as an ordinary access-log line) and no runtime update API. Changes go through SIGHUP to the master.

### Gaps
- No published benchmark of mruby ACL overhead per request was found. The h2o mruby docs give no performance figures.
- I could not confirm whether any h2o fork or PR adds IPv6 to `TrieAddr`. None was found in issue search.

## Caddy v2: remote_ip / client_ip matchers, trusted_proxies, ordering, data structures, dynamic updates, pitfalls

### Takeaway
Caddy separates `remote_ip` (the TCP peer or the PROXY-protocol address) from `client_ip` (computed from
`client_ip_headers` only when the peer is in `trusted_proxies`). Denial is done by combining a named
matcher with `abort`, `error` or `respond 403`. The default (non-strict) header parsing takes the
**left-most** valid IP once the peer is trusted. That is spoofable behind proxies that append (Cloudflare,
ALB), which is why `trusted_proxies_strict` (right-to-left, v2.8.0) exists. Matching is a linear scan
over `[]netip.Prefix`. A proposed radix-trie PR was closed unmerged in July 2026.

### Cited Findings
- **Syntax**: `remote_ip <ranges...>` / `client_ip <ranges...>`, plus CEL forms `remote_ip('<ranges...>')` / `client_ip(...)`. Both accept exact IPs or CIDRs, IPv6 zones, and the shortcut `private_ranges` = `192.168.0.0/16 172.16.0.0/12 10.0.0.0/8 127.0.0.1/8 fd00::/8 ::1`. — [Caddy docs: request matchers](https://caddyserver.com/docs/caddyfile/matchers)
- **Semantics**: `remote_ip` "matches the IP address of the immediate network peer or the address set via PROXY protocol". `client_ip` "is best used when the `trusted_proxies` global option is configured, otherwise it acts identically to the `remote_ip` matcher". — [Caddy docs: request matchers](https://caddyserver.com/docs/caddyfile/matchers)
- **Combination logic**: matchers inside one named set are AND'ed. Several instances of the same matcher in a set are merged and OR'ed. `not <matcher>` or a `not { }` block negates. — [Caddy docs: request matchers](https://caddyserver.com/docs/caddyfile/matchers)
- **trusted_proxies** (server option): "By default, no proxies are trusted." When the peer is trusted, the real client IP is read from headers (default `X-Forwarded-For`) and used in access logs, the `{client_ip}` placeholder and the `client_ip` matcher. Syntax: `trusted_proxies static [private_ranges] <ranges...>`. "Headers are parsed left-to-right by default." — [Caddy docs: global options](https://caddyserver.com/docs/caddyfile/options)
- **trusted_proxies_strict**: "Enables right-to-left parsing of client IP headers". It is recommended "when downstream proxies (HAProxy, CloudFlare, AWS ALB, etc.) append connecting addresses to the right of X-Forwarded-For". **client_ip_headers**: the default is `X-Forwarded-For`, and with several headers "the first non-empty value is used". — [Caddy docs: global options](https://caddyserver.com/docs/caddyfile/options)
- **Algorithm (source)**: `determineTrustedProxy` runs per request. If the peer is not in `trustedProxies`, the client IP is the peer. If it is, non-strict mode calls `trustedRealClientIP`, which joins all configured header values and returns the "first valid left-most IP address". Strict mode calls `strictUntrustedClientIp`, which walks each header right-to-left (`slices.Backward`) and returns the first IP **not** in the trusted ranges. Trusted-proxy membership is `slices.ContainsFunc(trusted, prefix.Contains)`, a linear scan. — [caddy modules/caddyhttp/server.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/server.go)
- **Unix sockets**: v2.11.0/2.11.1 added `trusted_proxies_unix` "for trusting unix socket `X-Forwarded-*` headers" (PR #7265). — [Caddy v2.11.1 release](https://github.com/caddyserver/caddy/releases/tag/v2.11.1); the code branch is `if s.TrustedProxiesUnix && r.RemoteAddr == "@"` in [server.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/server.go)
- **IP sources are pluggable**: the `IPRangeSource` interface is `GetIPRanges(*http.Request) []netip.Prefix`, and `static` is the built-in implementation. — [caddy ip_range.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/ip_range.go). Third-party `trusted_proxies cloudflare { interval 12h timeout 15s }` fetches Cloudflare's published ipv4/ipv6 lists (default interval 1h, no timeout by default) and works from v2.6.3 on. — [WeidiDeng/caddy-cloudflare-ip README](https://github.com/WeidiDeng/caddy-cloudflare-ip)
- **Matcher data structure (source)**: `MatchRemoteIP` and `MatchClientIP` hold `Ranges []string`, `cidrs []*netip.Prefix` and `zones []string`. `matchIPByCidrZones` is a linear `for i, ipRange := range cidrs { if ipRange.Contains(clientIP) ...}` with a zone check. `client_ip` reads the precomputed `GetVar(r.Context(), ClientIPVarKey)`, while `remote_ip` parses `r.RemoteAddr`. — [caddy ip_matchers.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/ip_matchers.go)
- **Radix trie rejected**: PR #7906 (2026-07-24) proposed a PATRICIA trie for `remote_ip`/`client_ip` lists of 8 or more entries. It claimed linear scans cost "up to ~1,200ns+ per request" for 1,000+ CIDRs against "sub-50ns" with a trie. It was **closed unmerged** on 2026-07-26 by a maintainer over AI-generated code ("AI is a tool, not a substitute for thinking"). The performance figures are the PR author's and were not verified. — [caddy PR #7906](https://github.com/caddyserver/caddy/pull/7906)
- **Version history**:
  - v2.3.0 (2021-01-01): "The `remote_ip` matcher no longer reads the X-Forwarded-For header by default. This was undocumented behavior, and an unsafe default"; an opt-in `forwarded` option was added. — [v2.3.0](https://github.com/caddyserver/caddy/releases/tag/v2.3.0)
  - v2.5.0 (2022-04-25): reverse_proxy stops trusting incoming `X-Forwarded-*` without `trusted_proxies`, and the log field `remote_addr` is split into `remote_ip`/`remote_port`. — [v2.5.0](https://github.com/caddyserver/caddy/releases/tag/v2.5.0)
  - v2.5.1: `private_ranges` shortcut. — [v2.5.1](https://github.com/caddyserver/caddy/releases/tag/v2.5.1)
  - v2.6.3 (2023-02-08): server-level `trusted_proxies`. — [v2.6.3](https://github.com/caddyserver/caddy/releases/tag/v2.6.3)
  - v2.7 (notes published with v2.7.3, 2023-08-06): "The `remote_ip forwarded` matcher has been deprecated because it assumes trusting downstream proxies. Instead, the `client_ip` matcher should be used along with `trusted_proxies`" (#5103, #5104). — [v2.7.3](https://github.com/caddyserver/caddy/releases/tag/v2.7.3)
  - v2.8.0 (2024-05-29): `forwarded` removed from `remote_ip` (#6085), `trusted_proxies_strict` added via "Security enhancements for client IP parsing (#5805)", and XFF values with ports accepted. — [v2.8.0](https://github.com/caddyserver/caddy/releases/tag/v2.8.0)
- **Why strict mode exists**: PR #5805 introduced "a failing test proving the potential security weakness of existing `trusted_proxy` + `client_ip_headers` configuration" and added right-most-first-untrusted parsing as opt-in, keeping left-most as the default for backward compatibility. Merged 2024-01-13. — [caddy PR #5805](https://github.com/caddyserver/caddy/pull/5805)
- **0-RTT / early data**: v2.9.0 (2024-12-31) "Reject 0-RTT early data in IP matchers and set Early-Data header when proxying" (#6427), plus `MatchWithError` (#6596). The bug report was #6664: `client_ip` filtering broke on resumed HTTP/3 connections in the 2.9 beta. francislavoie said that after #6596 "the client_ip matcher will throw an error instead of returning false, meaning the request will fail with a specific error code (`425 Too Early`)". v2.11.1 added an "Option to disable 0-RTT" (#7485). — [v2.9.0](https://github.com/caddyserver/caddy/releases/tag/v2.9.0), [issue #6664](https://github.com/caddyserver/caddy/issues/6664), [v2.11.1](https://github.com/caddyserver/caddy/releases/tag/v2.11.1)
- **Ordering**: the Caddyfile sorts directives by a fixed order: … `basic_auth`, `forward_auth`, `request_header`, `encode`, … `handle`, `handle_path`, `route`, then `abort`, `error`, `copy_response`, `respond`, `metrics`, `reverse_proxy`, `php_fastcgi`, `file_server`. `handle` blocks are "mutually exclusive", and "The contents of the route directive ignores all the above rules, and preserves the order the directives appear within." — [Caddy docs: directives](https://caddyserver.com/docs/caddyfile/directives)
- **abort** (since v2.4.0): "Prevents any response to the client by immediately aborting the HTTP handler chain and closing the connection. Any concurrent, active HTTP streams on the same connection are interrupted." — [Caddy docs: abort](https://caddyserver.com/docs/caddyfile/directives/abort); [v2.4.0 release](https://github.com/caddyserver/caddy/releases/tag/v2.4.0)
- **Typical deny pattern** (from a 2024 user report): `@not-lan { not client_ip 10.0.10.0/24 }` then `respond @not-lan "Accesssss Denied" 403`. The access log line shows `"remote_ip"`, `"client_ip"` and the status. — [caddy issue #6664](https://github.com/caddyserver/caddy/issues/6664)
- **Open complaint**: #6783 (open since 2025-01-10), "Confusing trusted_proxies behaviour with x-forwarded-for". Even with `trusted_proxies_strict`, the `X-Forwarded-For` that `reverse_proxy` sends upstream "includes the full value, if at least one of them is trusted", untrusted left-hand entries included. — [caddy issue #6783](https://github.com/caddyserver/caddy/issues/6783)
- **Undocumented `!` negation**: the TLS-handshake `remote_ip` matcher (`modules/caddytls/matchers.go`, not the HTTP one) has supported `remote_ip 10.0.0.0/8 !10.1.2.3` since 2021. On 2026-10-04 francislavoie wrote "we never documented `!` as working for `remote_ip` ... I think we should remove it actually". — [caddy issue #8097](https://github.com/caddyserver/caddy/issues/8097)
- **Dynamic updates**: through the admin API (`POST /load`, `PATCH`/`PUT /config/[path]`), "Configuration changes are lightweight, efficient, and incur zero downtime". A failing config is rolled back. Changes are autosaved and restorable with `caddy run --resume`. `Etag`/`If-Match` give optimistic concurrency, with 412 on conflict. — [Caddy docs: API](https://caddyserver.com/docs/api)

### Inferences
- Default non-strict mode plus a CDN that appends to XFF lets the client pick its own `client_ip` by sending `X-Forwarded-For: <allowed IP>`, because the left-most entry is client-controlled. Behind Cloudflare/ALB, strict mode is required for `client_ip` to be safe. That is the main Caddy pitfall, and the default has stayed left-most for backward compatibility.
- Directive order puts `respond`, `abort` and `error` after `handle`/`route`. A top-level `respond @denied 403` written next to `handle` blocks will not run for requests that a `handle` block serves. The deny has to sit inside each `handle`, inside a `route` that comes first, or in a top-level `route`. (This follows from the documented sort order; I found no doc page that warns about it explicitly.)
- Per request: client-IP resolution scans the trusted ranges linearly and splits header strings (allocations). Each IP matcher is then another linear scan over prefixes. That is fine for tens of ranges; large blocklists are O(N) per request because the trie PR was rejected.
- Caddy has no dry-run/report-only mode for matchers. The nearest substitutes are logging the `client_ip` placeholder, or using a matcher to set a header or variable instead of denying. Denials appear in the access log only as the status code (403 for `respond`/`error`). `abort` closes the connection.

### Gaps
- I did not verify how an `abort`ed request appears in Caddy's access log (status value or whether it is logged at all).
- I found no official benchmark of matcher cost; the only figures are the unmerged PR author's.

## HAProxy: ACLs with src and -f files, deny/tarpit/silent-drop, tree lookup, runtime API, XFF and PROXY protocol, logging

### Takeaway
HAProxy has the richest native address ACL of the five. `acl <name> src -f file` loads networks into
ebtree prefix trees with longest-match lookup (IPv4 contiguous masks and IPv6). Non-contiguous IPv4 masks
fall back to a list. `http-request deny` (403 default, any status with `deny_status`), `tarpit`,
`silent-drop` and `tcp-request connection reject` give graded responses. The runtime API (`add/del/clear
acl`, plus `prepare`/`commit acl` since 2.4) updates lists atomically without reload, but nothing is
written back to disk. Behind proxies, `src` is the TCP peer unless `accept-proxy` is used. XFF must be read
with the last occurrence (`req.hdr_ip(X-Forwarded-For,-1)`), because an ACL on `req.hdr_ip` checks every
occurrence.

### Cited Findings
- **ACL flags**: `-f` loads patterns from a file (one per line, `#` comments, several `-f` allowed). `-M` loads a map, `-u` forces the unique id used by the CLI, `-n` forbids DNS resolution. "Depending on the data type and match method, HAProxy may load the lines into a binary tree, allowing very fast lookups. This is true for IPv4 and exact string matching. In this case, duplicates will automatically be removed." — [HAProxy configuration manual 7.1 "ACL basics"](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- **Address syntax**: IPv4 can be plain, with a netmask, or abbreviated (`10.12/8`). "Notice that this is different from RFC 4632 CIDR address notation in which 192.168.42/24 would be equivalent to 192.168.42.0/24." Hostnames are allowed for IPv4 but "generally discouraged", and never for IPv6. Cross-family matching: an IPv6 sample against an IPv4 pattern matches only for `2002:IPV4::`, `::IPV4` or `::ffff:IPV4`, and an IPv4 sample is converted to `::ffff:` for IPv6 patterns. — [HAProxy configuration manual 7.1.6](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- **Data structure (source)**: `pat_idx_tree_ip` inserts IPv4 patterns with a *contiguous* mask into `expr->pattern_tree` via `ebmb_insert_prefix(..., 4)`. Non-contiguous masks go to a list (`pat_idx_list_val`). "IPv6 also can be indexed": these go into `expr->pattern_tree_2` with `ebmb_insert_prefix(..., 16)`. Lookup is `ebmb_lookup_longest` (longest-prefix match). Entries whose `gen_id` is not the current generation are skipped with `ebmb_lookup_shorter`. `pat_match_ip` tries the IPv4 tree, then the v4-mapped IPv6 tree, then the linear list of non-contiguous masks. — [haproxy src/pattern.c](https://github.com/haproxy/haproxy/blob/master/src/pattern.c)
- **Map overlap rule**: "IP addresses and strings are stored in trees, so the first of the finest match will be used." — [HAProxy configuration manual, `map` converter](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- **Pattern cache does not apply to IP**: `tune.pattern.cache-size` (default 10000, LRU, per thread) is used "on slow pattern lookups, namely the ones using the "sub", "reg", "dir", "dom", "end", "bin" match methods as well as the case-insensitive strings". — [HAProxy configuration manual, tune.pattern.cache-size](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- **Conditions**: implicit AND, `or`/`||`, `!` negation, written after `if`/`unless`, e.g. `http-request deny if { var(txn.myip) -m ip 127.0.0.0/8 10.0.0.0/8 }`. — [HAProxy configuration manual 7.2](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- **deny**: `deny [ { status | deny_status } <code> ] [ content-type <type> ] [ errorfile ... | string ... | lf-string ... ] [ hdr <name> <fmt> ]*`. "By default an HTTP 403 error is returned for requests, and 502 for responses". It is final for the rule set. — [HAProxy configuration manual, actions](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- **tarpit**: holds the request "for a delay specified by "timeout tarpit"", then returns 500 by default. "Logs will report the flags "PT"." It is useful against "very dumb robots", but against good ones it "can make things worse by forcing HAProxy and the front firewall to support insane number of concurrent connections". — [HAProxy configuration manual, tarpit](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- **silent-drop**: closes without notifying the client, using TCP_REPAIR (or an RST with TTL 1 if privileges are missing). `rst-ttl <ttl>` sends an RST that dies before reaching the client. Stateful middleboxes "will also keep the established connection in their session tables". — [HAProxy configuration manual, silent-drop](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- **reject at connection level is not logged**: "In "tcp-request connection" rules, rejected connections do not even become a session, which is why they are accounted separately for in the stats, as "denied connections". They are not considered for the session rate-limit and are not logged either", by design for DDoS. "If logging is absolutely desired, then "tcp-request content" rules should be used instead". — [HAProxy configuration manual, reject](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- **Log flags for denials**: termination state `PR`: "The proxy blocked the client's HTTP request, either because of an invalid HTTP syntax ... or because a deny filter matched, in which case it returned an HTTP 403 error". `PT` marks tarpit. The stats counter `dreq` counts "requests denied because of security concerns". — [HAProxy configuration manual, termination states](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt); [HAProxy management guide, stats fields](https://github.com/haproxy/haproxy/blob/master/doc/management.txt)
- **src**: "Note that it is the TCP-level source address which is used, and not the address of a client behind a proxy. However if the "accept-proxy" or "accept-netscaler-cip" bind directive is used, it can be the address of a client behind another PROXY-protocol compatible component for all rule sets except "tcp-request connection" which sees the real address." — [HAProxy configuration manual, `src`](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- **accept-proxy** (bind): PROXY v1 and v2, with addresses used everywhere except `tcp-request connection` rules. It is called "an efficient and reliable alternative to the X-Forwarded-For mechanism". `tcp-request connection expect-proxy` decides which peers may use it. — [HAProxy configuration manual, accept-proxy](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- **req.hdr_ip pitfall**: it "extracts the last occurrence of header <name> ... When used with ACLs, all occurrences are checked". `<occ>` follows `req.hdr()`, where "Negative values indicate positions relative to the last one, with -1 being the last one". — [HAProxy configuration manual, req.hdr_ip / req.hdr](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- **option forwardfor**: "the server must be configured to always use the last occurrence of this header only ... since it is really possible that the client has already brought one". `if-none` "should only be used in perfectly trusted environment". — [HAProxy configuration manual, option forwardfor](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- **set-src**: `http-request set-src hdr(x-forwarded-for)` rewrites what every later `src` fetch returns. It is usable in tcp-request connection/session/content and http-request rules. — [HAProxy configuration manual, set-src](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- **Runtime API**:
  - `add acl [@<ver>] <acl> <pattern>` does not check for duplicates. `del acl <acl> [<key>|#<ref>]` removes entries. `clear acl [@<ver>] <acl>` empties an ACL.
  - `prepare acl <acl>` allocates a new version. Entries added to it "will not match until a "commit acl" operation is performed". `commit acl @<ver> <acl>` replacement "is atomic". Versions are u32 and wrap.
  - `show acl [@<ver>] <acl>` dumps the entries.
  - **`get acl <acl> <value>`** "Lookup the value ... This is useful for debugging maps and ACLs".

  — [HAProxy management guide](https://github.com/haproxy/haproxy/blob/master/doc/management.txt)
- **Not persisted**: "The ACLs aren't persisted to files on disk. Any changes you make via the Runtime API are lost when the proxy halts." `commit acl` became available in HAProxy 2.4 / HAProxy Enterprise 2.4r1. — [HAProxy docs: commit acl](https://www.haproxy.com/documentation/haproxy-runtime-api/reference/commit-acl/)

### Inferences
- The manual says only IPv4 and exact strings are tree-indexed, but current `pattern.c` indexes IPv6 in a second ebtree as well. The prose lags the code. For the report: IP lookups are longest-prefix tree lookups (O(prefix bits), independent of list size), except IPv4 non-contiguous masks, which are linear.
- The generation-id check in the lookup is what makes `prepare`/`commit` atomic without locks on the read side: old and new entries coexist in one tree, and the reader skips the ones not in the current generation.
- The safe XFF idiom is `req.hdr_ip(X-Forwarded-For,-1)` as a sample fetch (or `set-src` with an occurrence of -1), and only behind a proxy that is known to append. Writing `acl x req.hdr_ip(X-Forwarded-For) 10.0.0.0/8` matches if *any* entry matches, so it is spoofable.
- HAProxy has no built-in dry-run for ACLs. A "report-only" rule can be built by replacing `deny` with `http-request set-var(txn.would_deny) bool(true) if ...` (or `capture`, or `do-log`) and logging the variable. `get acl` tests a value offline against a live ACL. This is assembled from the documented actions, not a documented feature.
- Runtime changes must be mirrored into the `-f` file by the operator or tooling, or they vanish on the next reload.

### Gaps
- I did not find an official per-lookup timing for ebtree IP matching. Complexity is inferred from the longest-prefix ebtree code.

## Traefik: IPAllowList middleware, ipStrategy depth/excludedIPs, rejectStatusCode, client address selection, pitfalls, dynamic config

### Takeaway
Traefik's `ipAllowList` (allow-only; there is no deny-list middleware) checks `sourceRange` against the TCP
peer by default. With `ipStrategy.depth` it checks the Nth XFF entry from the right, and with
`excludedIPs` the first right-to-left entry not in a list. The XFF used is what arrived at Traefik,
**after** the entrypoint's `forwardedHeaders` sanitising and **before** Traefik appends its own hop.
Missing or short XFF yields an empty IP and a 403, with no fallback to the peer (open since 2021).
Matching is a linear scan of `net.IP`/`net.IPNet` slices. Middlewares hot-reload, but `trustedIPs` on
entrypoints are install configuration and need a restart.

### Cited Findings
- **Naming/versions**: `IPWhiteList` docs carry "This middleware is deprecated, please use the IPAllowList middleware instead." — [Traefik v2.11 docs: IPWhiteList](https://doc.traefik.io/traefik/v2.11/middlewares/http/ipwhitelist/). The current release is v3.7.14 (2026-10-06). — [Traefik releases](https://github.com/traefik/traefik/releases/tag/v3.7.14)
- **Options**:

  | Option | Meaning / default |
  |---|---|
  | `sourceRange` | required |
  | `ipStrategy.depth` | "Position in X-Forwarded-For to extract IP (counting right)", default 0 |
  | `ipStrategy.excludedIPs` | skip listed IPs when scanning XFF |
  | `ipStrategy.ipv6Subnet` | masks an IPv6 address to its subnet base |
  | `rejectStatusCode` | default 403 |

  "Without strategy: Traefik matches `sourceRange` against the remote address". "When `ipStrategy.depth` exceeds 0, the `excludedIPs` option is disregarded". For XFF `10.0.0.1,11.0.0.1,12.0.0.1,13.0.0.1`: depth 1 gives `13.0.0.1`, depth 3 gives `11.0.0.1`, and depth 5 gives an empty IP. — [Traefik docs: IPAllowList (current)](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/ipallowlist/)
- **When the hop is appended**: allowlisting happens "before the actual proxying to the backend takes place. In addition, the previous network hop only gets appended to `X-Forwarded-For` during the last stages of proxying, i.e. after it has already passed through whitelisting." — [Traefik v3.0 docs: IPAllowList](https://doc.traefik.io/traefik/v3.0/middlewares/http/ipallowlist/)
- **rejectStatusCode version**: PR #10130 "Add `rejectStatusCode` option to `IPAllowList` middleware" was merged 2024-01-09 under milestone 3.0. PR #13664 (2026-08-10, milestone 3.7) added it to the configuration example. — [PR #10130](https://github.com/traefik/traefik/pull/10130), [PR #13664](https://github.com/traefik/traefik/pull/13664). Conflict: my fetches of the v3.0, v3.1 and v3.3 doc pages did not list `rejectStatusCode`, and v3.3 lists `ipv6Subnet` ([v3.1 docs](https://doc.traefik.io/traefik/v3.1/middlewares/http/ipallowlist/), [v3.3 docs](https://doc.traefik.io/traefik/v3.3/middlewares/http/ipallowlist/)). The code shipped in 3.0, but it appears to have been documented late.
- **Handler (source)**: `ServeHTTP` gets `clientIP := al.strategy.GetIP(req)`, then `al.allowLister.IsAuthorized(clientIP)`. On failure it does `logger.Debug().Msgf("Rejecting IP %s: %v", ...)`, `observability.SetStatusErrorf(...)`, writes `rejectStatusCode` and `http.StatusText(code)` as the body. An invalid status code is refused at creation ("invalid HTTP status code"). An empty `sourceRange` is an error. — [traefik ip_allowlist.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/ipallowlist/ip_allowlist.go)
- **Checker data structure (source)**: `Checker{authorizedIPs []*net.IP; authorizedIPsNet []*net.IPNet}`. `ContainsIP` loops over exact IPs, then loops over networks with `authorizedNet.Contains(addr)`. Each check parses the string with `netip.ParseAddr` and converts it to a 16-byte `net.IP`. — [traefik pkg/ip/checker.go](https://github.com/traefik/traefik/blob/master/pkg/ip/checker.go)
- **Strategies (source)**:
  - `RemoteAddrStrategy` uses `req.RemoteAddr`.
  - `DepthStrategy` does `req.Header.Get("X-Forwarded-For")`, which returns only the **first** XFF header line. It splits on `,`, returns `""` if `len(xffs) < Depth`, else `xffs[len-Depth]`.
  - `PoolStrategy` (excludedIPs) walks right-to-left and returns the first entry not in the pool, or `""`.

  — [traefik pkg/ip/strategy.go](https://github.com/traefik/traefik/blob/master/pkg/ip/strategy.go)
- **Entrypoint sanitising (source)**: `if !x.insecure && !x.isTrustedIP(r.RemoteAddr) { DeleteXForwardedHeaders(r.Header) }`, then it sets `X-Real-Ip` to the peer if absent. — [traefik forwarded_header.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/forwardedheaders/forwarded_header.go). Entrypoint options: `forwardedHeaders.trustedIPs`, `forwardedHeaders.insecure` (default false, "only for tests purposes"), `forwardedHeaders.notAppendXForwardedFor`, and `proxyProtocol.trustedIPs`/`insecure` (PROXY v1 and v2). — [Traefik docs: EntryPoints](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/)
- **Dynamic configuration**: routing configuration (routers, middlewares) "can change and is seamlessly hot-reloaded, without any request interruption or connection loss". Install configuration (entrypoints, providers) needs a restart. — [Traefik docs: configuration overview](https://doc.traefik.io/traefik/getting-started/configuration-overview/)
- **Pitfalls and complaints**:
  - #7884 "No strategy fallback in case of X-Forwarded-For's absence" (open since 2021-02-10): with `excludedIPs`, requests without XFF get no fallback to the remote address. PR #12086 "Feat fallback if no X-Forwarded-For" has been open since 2025-09-20 in "needs design review". — [#7884](https://github.com/traefik/traefik/issues/7884), [PR #12086](https://github.com/traefik/traefik/pull/12086)
  - #10561 (2024): a single-IP XFF with depth 1 or excludedIPs returns an empty IP and Forbidden. It was closed after a maintainer said the implementation works as designed. — [#10561](https://github.com/traefik/traefik/issues/10561)
  - #11572 (2025): a request for left-most XFF selection was closed for lack of traction. — [#11572](https://github.com/traefik/traefik/issues/11572)
  - #6007 "OR-Chained middlewares" (open since 2019, 93 reactions): middlewares are AND-chained, so "allow if IP OR basic-auth" is not expressible. — [#6007](https://github.com/traefik/traefik/issues/6007)
  - #11605 (2025): an allowlist that "didn't work" was a second IngressRoute for the same service without the middleware. — [#11605](https://github.com/traefik/traefik/issues/11605)
- **Kubernetes ingress-nginx compatibility** (v3.7): PR #12932 "Add ipAllowListStrategy option for allowlist/whitelist annotations" and PR #12918 support for `nginx.ingress.kubernetes.io/limit-allowlist`. — [PR #12932](https://github.com/traefik/traefik/pull/12932), [PR #12918](https://github.com/traefik/traefik/pull/12918)

### Inferences
- With `depth: N`, the selected address is attacker-controlled whenever fewer than N real proxies append in front of Traefik. With more proxies than expected, a proxy's address is selected instead. Depth must equal the exact number of appending proxies, which is the classic depth pitfall.
- If the entrypoint does not trust the front proxy, Traefik deletes XFF before the middleware runs. Any `depth`/`excludedIPs` strategy then sees an empty header and **denies everything** (fail-closed). With `forwardedHeaders.insecure: true`, the client's own XFF reaches the strategy (spoofable).
- `DepthStrategy` reads only the first `X-Forwarded-For` header line (`Header.Get`). A request carrying several XFF lines (client-supplied first, proxy-appended as a separate line) would be evaluated on the client's line. Whether this is exploitable depends on how the front proxy appends. I found no issue documenting it.
- Changing trusted proxies (entrypoint) needs a restart, while changing `sourceRange` hot-reloads.
- Cost: a linear scan with parsing per request. There is no dry-run mode. Denials are a debug-level log line plus a tracing status, and in the access log they are just the status code.

### Gaps
- I did not confirm in which release `ipv6Subnet` first appeared (present in the v3.3 docs, absent in v3.1).
- No deny-list (block) middleware exists in Traefik core per the docs reviewed. Third-party plugins were not surveyed.

## Envoy: RBAC remote_ip / direct_remote_ip / source_ip, xff_num_trusted_hops and original IP detection, shadow mode, 403, stats, LC-trie

### Takeaway
Envoy's RBAC filter (HTTP and network) matches `direct_remote_ip` (the socket peer) or `remote_ip` (the
"trusted client address" that the HTTP connection manager derives from `use_remote_address`,
`xff_num_trusted_hops` or an original-IP-detection extension). `source_ip` is deprecated. It answers
`403 "RBAC: access denied"`. It has the only true dry-run among the five (`shadow_rules` with
`shadow_allowed`/`shadow_denied` stats and dynamic metadata), plus a `LOG` action. Since 2025-08 each IP
principal is an LC-trie, and the matcher-API `envoy.matching.matchers.ip` holds a whole list in one
LC-trie. The default `use_remote_address: false` makes `remote_ip` the right-most XFF entry, which a
client controls at the edge.

### Cited Findings
- **Principal fields**: `source_ip` (deprecated) "will honor proxy protocol, but will not honor XFF", and users should use `remote_ip` (same behaviour) or `direct_remote_ip`. `direct_remote_ip` is the physical peer. `remote_ip` "may differ from the physical peer when the remote IP is derived from x-forwarder-for headers, proxy protocol, or similar mechanisms". — [Envoy API: rbac.proto](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/rbac/v3/rbac.proto)
- **Actions and order**: `ALLOW` "Allows the request if and only if there is a policy that matches". `DENY` "Allows the request if and only if there are no policies that match". `LOG` "Allows all requests. If at least one policy matches, the dynamic metadata key `access_log_hint` is set". "The policies are evaluated in lexicographic order of the policy name." — [Envoy API: rbac.proto](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/rbac/v3/rbac.proto)
- **Trusted client address**:
  - With `use_remote_address` false (the default), it is the right-most XFF IP if XFF exists, else the peer.
  - With `use_remote_address` true, it is the peer.
  - With `xff_num_trusted_hops=N` and `use_remote_address` false, it is the (N+1)th IP from the right. With true, it is the Nth from the right, falling back to the peer if XFF is too short.
  - `original_ip_detection_extensions` "cannot be mixed with `use_remote_address` nor `xff_num_trusted_hops`".
  - The address also decides internal/external (`x-envoy-internal`, `x-envoy-external-address`).

  — [Envoy docs: HTTP header manipulation (x-forwarded-for)](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers)
- **XFF original-IP extension**: `xff_num_trusted_hops`, and `xff_trusted_cidrs`, where "each entry in the x-forwarded-for header is evaluated from right to left and the first non-trusted address is used". If all entries are trusted, the left-most is used. `skip_xff_append` stops Envoy appending the peer. — [Envoy API: xff original IP detection](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/http/original_ip_detection/xff/v3/xff.proto)
- **Edge guidance**: set `use_remote_address` to true "to avoid consuming HTTP headers from external clients". — [Envoy docs: edge proxy best practices](https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge)
- **Deny response (source)**: `callbacks_->sendLocalReply(Http::Code::Forbidden, "RBAC: access denied", ...)`, i.e. 403 with that body. The response-code details carry `rbac_access_denied_matched_policy[policy_name]`. — [envoy rbac_filter.cc](https://github.com/envoyproxy/envoy/blob/main/source/extensions/filters/http/rbac/rbac_filter.cc); [Envoy docs: RBAC filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/rbac_filter)
- **Shadow / dry-run**: shadow mode "won't affect real users, it is used to test that a new set of policies work before rolling out to production". Stats under `http.<stat_prefix>.rbac.`: `allowed`, `denied`, `shadow_allowed`, `shadow_denied`, `logged`, `not_logged`, with optional `rules_stat_prefix` / `shadow_rules_stat_prefix`. Dynamic metadata: `shadow_effective_policy_id`, `shadow_engine_result`, and `access_log_hint` (namespace `envoy.common`). `RBACPerRoute` overrides or disables the filter per virtual host, route or weighted cluster. — [Envoy docs: RBAC filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/rbac_filter)
- **Network (L4) RBAC**: the same stats and shadow mode. Denials are reported in connection termination details as `rbac_access_denied_matched_policy[...]`. — [Envoy docs: network RBAC filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/rbac_filter)
- **Data structure (source)**: `IPMatcher` holds `std::unique_ptr<Network::LcTrie::LcTrie<bool>> trie_` and a `Type` (`ConnectionRemote`, `DownstreamLocal`, `DownstreamDirectRemote`, `DownstreamRemote`). The commit "rbac: switch to using LC Trie for RBAC IP range matcher" (#40536, 2025-08-07) followed #40493. Principals are built one `IPMatcher::create(principal.remote_ip(), ...)` per CIDR. `or_ids` is an `OrMatcher` that loops over its matchers. A multi-range `create(RepeatedPtrField<CidrRange>)` exists in the class. — [envoy rbac matchers.cc](https://github.com/envoyproxy/envoy/blob/main/source/extensions/filters/common/rbac/matchers.cc), [matchers.h](https://github.com/envoyproxy/envoy/blob/main/source/extensions/filters/common/rbac/matchers.h), [commit a11b369](https://github.com/envoyproxy/envoy/commit/a11b3698fddb0bc9eadb4a506bf5203f835e51f4)
- **Unified matcher IP input**: `envoy.matching.matchers.ip` uses a "Level-Compressed trie, as described in the paper IP-address lookup using LC-tries". It is "more efficient than multiple single IP matcher, that would have a linear cost". Fields are `cidr_ranges` and `stat_prefix`, and the stat is `ip_parsing_failed`. — [Envoy API: IP input matcher](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/matching/input_matchers/ip/v3/ip.proto)
- **Dynamic updates**: ECDS supports listener filters, downstream network filters and HTTP filters. If an HTTP filter's config is missing, "a local HTTP response with '500' status code will be returned", and for network filters "the connection will be rejected until a valid config is updated". — [Envoy docs: extension configuration / ECDS](https://www.envoyproxy.io/docs/envoy/latest/configuration/overview/extension)
- **Related CVE**: CVE-2026-26308 / GHSA-ghc4-35x6-crw5 (published 2026-03-10, CVSS 7.5). In the RBAC header matcher, multi-value headers were concatenated ("true,true"), defeating exact-match deny rules. Affected: 1.34.12, 1.35.8, 1.36.4, 1.37.0. Fixed in 1.34.13, 1.35.9, 1.36.5, 1.37.1. The current release is v1.39.3 (2026-10-06). — [GHSA-ghc4-35x6-crw5](https://github.com/envoyproxy/envoy/security/advisories/GHSA-ghc4-35x6-crw5), [Envoy v1.39.3](https://github.com/envoyproxy/envoy/releases/tag/v1.39.3)

### Inferences
- An edge Envoy with the default `use_remote_address: false` derives `remote_ip` from the right-most XFF entry. A client sending `X-Forwarded-For: <allowed IP>` is then matched as that IP. `direct_remote_ip`, or `use_remote_address: true`, is required at the edge.
- In the classic RBAC API, a list of N CIDRs written as `or_ids` of N `remote_ip` principals still costs N single-entry trie lookups (a linear OR). Only the matcher API with `envoy.matching.matchers.ip` (or a future wiring of the multi-range constructor) gives one LC-trie lookup for the whole list. This is read from source, not stated in the docs.
- The LC-trie change landed on main 2025-08-07, so it applies to releases cut after that (likely 1.36 onward). The release mapping was not verified.
- Matching XFF through an RBAC *header* matcher is fragile (see the CVE). The documented path is to compute the client address in the HTTP connection manager and use `remote_ip`.

### Gaps
- I did not verify which Envoy release first shipped the RBAC LC-trie (#40536).
- I did not fetch the `custom_header` original-IP-detection extension docs.

## Cross-cutting: dry-run/report-only, testing a rule, and how denials are logged

### Takeaway
Only Envoy has a first-class dry-run (shadow rules plus a LOG action). HAProxy has the best offline test
(`get acl` against a live list) and the only atomic, versioned runtime list replacement. Caddy and Traefik
hot-reload their configuration, but neither has dry-run, and both log denials only as status codes (Traefik
also at debug level). h2o has none of these. Every server except HAProxy (with `accept-proxy`) and Envoy
(`use_remote_address: true`) has a spoofable or fragile client-address default or idiom somewhere: h2o's
`addr()` takes the left-most XFF, Caddy's non-strict mode the left-most, Traefik depth must be exact.

### Cited Findings
- Envoy shadow rules and the `LOG` action: see the Envoy section. — [Envoy RBAC filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/rbac_filter), [rbac.proto](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/rbac/v3/rbac.proto)
- HAProxy `get acl <acl> <value>` is "useful for debugging maps and ACLs". The `PR`/`PT` termination flags and `dreq` stats exist, and `tcp-request connection reject` is unlogged by design. — [HAProxy management guide](https://github.com/haproxy/haproxy/blob/master/doc/management.txt), [configuration manual](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- Traefik logs `Rejecting IP %s` at debug level and sets an observability status. — [traefik ip_allowlist.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/ipallowlist/ip_allowlist.go)
- Caddy access logs carry `remote_ip`, `client_ip` and status (example line in [issue #6664](https://github.com/caddyserver/caddy/issues/6664)). Config changes are atomic with rollback via the admin API. — [Caddy API](https://caddyserver.com/docs/api)
- h2o: the ACL is an mruby handler, and a 403 from `deny` is an ordinary response. kazuho noted that `%h` logs the connected peer. — [h2o acl.rb](https://github.com/h2o/h2o/blob/master/share/h2o/mruby/acl.rb), [issue #746](https://github.com/h2o/h2o/issues/746)
- 0-RTT is handled consistently: both h2o's ACL (`TooEarlyError` returns 425) and Caddy's IP matchers (since v2.9.0, 425) refuse to decide on early data. — [h2o acl.rb](https://github.com/h2o/h2o/blob/master/share/h2o/mruby/acl.rb), [Caddy v2.9.0](https://github.com/caddyserver/caddy/releases/tag/v2.9.0)

### Inferences
Comparison summary, synthesised from the findings above:

| | h2o | Caddy | HAProxy | Traefik | Envoy |
|---|---|---|---|---|---|
| Native allow/deny | mruby `acl` DSL only (optional build) | matchers + `abort`/`error`/`respond` | `acl` + `http-request deny/tarpit/silent-drop/reject` | allow-only middleware | RBAC ALLOW/DENY/LOG |
| Default deny code | 403 "Forbidden" | whatever you `respond`/`error`, or connection abort | 403 (`deny_status` any) | 403 (`rejectStatusCode`, since 3.0) | 403 "RBAC: access denied" |
| Client address behind proxy | `addr()` = left-most XFF by default (spoofable) | `client_ip` via `trusted_proxies`; left-most default, `trusted_proxies_strict` right-to-left | `src` = TCP or PROXY; XFF by hand (`req.hdr_ip(...,-1)`, `set-src`) | depth from the right / excludedIPs; entrypoint `trustedIPs` | HCM: `use_remote_address`, `xff_num_trusted_hops`, `xff_trusted_cidrs` |
| IPv6 | no (TrieAddr IPv4-only) | yes, with zones | yes (tree) | yes | yes |
| Lookup structure | 256-ary Ruby hash trie, 4 lookups | linear `[]netip.Prefix` | ebtree longest-prefix (v4 and v6); list for non-contiguous v4 masks | linear `[]net.IPNet` | LC-trie per principal; matcher API one LC-trie per list |
| Update without restart | SIGHUP graceful restart | admin API, atomic, rollback | runtime API, atomic prepare/commit, not persisted | provider hot-reload (entrypoint trust needs restart) | xDS/ECDS |
| Dry-run | no | no | no (emulate with set-var + log; `get acl` to test) | no | yes (shadow rules, LOG) |

### Gaps
- None of the five publishes per-request cost figures for IP matching. The only number found (Caddy PR #7906: "~1,200ns+" linear vs "sub-50ns" trie for 1,000+ CIDRs) is from an unmerged, AI-assisted PR and is unverified.
