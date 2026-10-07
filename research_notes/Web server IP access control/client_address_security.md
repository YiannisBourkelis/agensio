# Client address determination, allowlist bypasses, 403 vs 404, and denial logging (state as of 2026-10-07)

Scope: how a web server should decide "who is the client" for access-control decisions when it sits
behind proxies or CDNs; the documented ways IP allowlists have been bypassed; the 403-versus-404
question for refused requests; and how to log denials so they are debuggable and usable by fail2ban
or CrowdSec without flooding. All sources were read on 2026-10-07 unless a date is given. RFC texts
were read from the RFC Editor's plain-text copies (RFC 9110 from the copy in this repository,
`docs/rfc/rfc9110.txt`).

## Q1. What is the safe algorithm for the client address behind proxies and CDNs (X-Forwarded-For, Forwarded, PROXY protocol, CDN headers, trusted-proxy and CDN range lists), and who implements it which way?

### Takeaway
The only safe rule for access control is to start from the TCP peer address and walk the merged
X-Forwarded-For list from the right, skipping addresses that belong to configured trusted proxies,
and take the first untrusted one ("rightmost untrusted"). The alternative is to count a fixed number
of hops from the right. Leftmost values are attacker-controlled and are fit only for analytics.
nginx (`real_ip_recursive on`), Apache `mod_remoteip`, Express (with a list or count), Rails, Tomcat
`RemoteIpValve` and HAProxy's `hdr_ip(...,-1)` work from the right. Express `trust proxy = true`,
Caddy (unless `trusted_proxies_strict`), chi before v5.3.0 and many rate limiters take the leftmost
value. The PROXY protocol avoids header parsing, but it is only safe on a listener that requires it
from known sources. A CDN "trusted range" is a weaker boundary than it looks, because every tenant
of that CDN egresses from the same ranges.

### Cited Findings

**The algorithm (primary guidance)**
- MDN states that any security-related use of X-Forwarded-For "*must only* use IP addresses added by a trusted proxy", that using untrustworthy values "can result in rate-limiter avoidance, access-control bypass, memory exhaustion", and that "If the server can be directly connected to from the internet — even if it is also behind a trusted reverse proxy — **no part** of the `X-Forwarded-For` IP list can be considered trustworthy." — [MDN X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For)
- MDN gives two methods. Trusted proxy count: "The `X-Forwarded-For` IP list is searched from the rightmost by that count minus one". Trusted proxy list: "The `X-Forwarded-For` IP list is searched from the rightmost, skipping all addresses that are on the trusted proxy list. The first non-matching address is the target address." For non-security uses it says to take "the first IP from the leftmost that is *a valid address* and *not private/internal*". — [MDN X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For)
- On multiple headers, MDN says "There may be multiple `X-Forwarded-For` headers present in a request. The IP addresses in these headers must be treated as a single list ... It is insufficient to use only one of multiple `X-Forwarded-For` headers." — [MDN X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For)
- Adam Pritchard, "The perils of the 'real' client IP" (2022-03-04, updated through 2026-06-06), says "use the rightmost IP" for security uses, either by trusted proxy count or by trusted proxy CIDR list. He also says "you need to know either the IP addresses of those reverse proxies or the number of them that the request will pass through". — [adam-p.ca](https://adam-p.ca/blog/2022/03/x-forwarded-for/)
- Pritchard documents these pitfalls:
  - **Multiple headers.** Go's `http.Header.Get()` returns the first header while the proxy appends to the last one, so a client-sent first header wins.
  - **Separators differ.** AWS ALB joins with comma-space and Cloudflare with comma only.
  - **Private addresses** show up in the list.
  - **Unencrypted hops** make every hop untrustworthy.
  - **Fallback chains** ("True-Client-IP, then X-Real-IP, then XFF") are wrong: "There's *never* a time when you're okay with just falling back across a big list of header values."
  - **Rate limiters** that read the leftmost value can be escaped entirely, and their memory can be exhausted with spoofed values. IPv6 makes the memory attack worse.

  — [adam-p.ca](https://adam-p.ca/blog/2022/03/x-forwarded-for/)
- Pritchard describes a "re-fronting" attack. An attacker who sets up their own distribution on the same CDN can point it at your origin and set XFF freely while arriving from trusted CDN addresses. The mitigation is to prove the request came through *your* distribution, with a shared secret or a client certificate. — [adam-p.ca](https://adam-p.ca/blog/2022/03/x-forwarded-for/)

**RFC 7239 `Forwarded`**
- RFC 7239 section 8.1: "The 'Forwarded' HTTP header field cannot be relied upon to be correct, as it may be modified, whether mistakenly or for malicious reasons, by every node on the way to the server, including the client making the request." It also says whitelisting trusted proxies has two weaknesses: "the chain of IP addresses listed before the request came to the proxy cannot be trusted", and unless proxy-to-endpoint links are secured "the data can be modified by an attacker with access to the network." — [RFC 7239 §8.1](https://www.rfc-editor.org/rfc/rfc7239.html#section-8.1)
- In `Forwarded`, IPv6 addresses must be quoted and bracketed (`for="[2001:db8:cafe::17]:4711"`), because `:` and `[]` are not token characters. In XFF they "may not be quoted ... and may not be enclosed by square brackets". The `for` value may also be `unknown` or an obfuscated identifier (`_gazonk`). — [RFC 7239 §4, §6, §7.4](https://www.rfc-editor.org/rfc/rfc7239.html)
- RFC 7239 §8.3 says the default `for`/`by` values "SHOULD contain obfuscated identifiers" generated per request. This is a privacy default that leaves nothing to match an IP rule against. — [RFC 7239 §8.3](https://www.rfc-editor.org/rfc/rfc7239.html#section-8.3)
- Pritchard notes that `Forwarded` "suffers identical vulnerabilities" to XFF, has extra IPv6 parsing complexity, and that its "adoption remains negligible". — [adam-p.ca](https://adam-p.ca/blog/2022/03/x-forwarded-for/)

**PROXY protocol (HAProxy spec, versions 1 and 2, document dated 2020/03/05)**
- "The receiver MUST be configured to only receive the protocol described in this specification and MUST not try to guess whether the protocol header is present or not. This means that the protocol explicitly prevents port sharing between public and private access. Otherwise it would open a major security breach by allowing untrusted parties to spoof their connection addresses. The receiver SHOULD ensure proper access filtering so that only trusted proxies are allowed to use this protocol." — [PROXY protocol spec §2](https://www.haproxy.org/download/3.2/doc/proxy-protocol.txt)
- The security section says "if the opportunity is left to a normal client to use the protocol, it will be able to hide its activities or make them appear as coming from somewhere else. However, accepting the header only from a number of known sources should be safe." — [PROXY protocol spec §5](https://www.haproxy.org/download/3.2/doc/proxy-protocol.txt)
- The receiver "MUST NOT start processing the connection before it receives a complete and valid PROXY protocol header" and "may apply a short timeout ... (at least 3 seconds to cover a TCP retransmit)". Proxies "MUST NOT implement this protocol on multiplexed connections". — [PROXY protocol spec §2](https://www.haproxy.org/download/3.2/doc/proxy-protocol.txt)
- In v1 addresses are canonical: in IPv4, "Heading zeroes are not permitted in front of numbers in order to avoid any possible confusion with octal numbers", and IPv6 must decode to exactly 128 bits. — [PROXY protocol spec §2.1](https://www.haproxy.org/download/3.2/doc/proxy-protocol.txt)
- Apache `RemoteIPProxyProtocol` (2.4.31+) is per IP:port. If it is enabled for any name-based vhost on that address, it is enabled for all of them. A connection without the header is aborted unless the source is in `RemoteIPProxyProtocolExceptions`. — [Apache mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html)
- nginx accepts the PROXY protocol address with `real_ip_header proxy_protocol` (1.5.12). It must first be enabled on the `listen` directive. — [nginx realip module](https://nginx.org/en/docs/http/ngx_http_realip_module.html)

**Server and framework behaviour**
- **nginx `ngx_http_realip_module`** (not built by default). `set_real_ip_from` lists trusted addresses, CIDRs or `unix:`. `real_ip_header` defaults to `X-Real-IP`. `real_ip_recursive` defaults to `off`:
  - With `off`, the trusted peer's address "is replaced by the last address sent in the request header field".
  - With `on`, it is replaced "by the last non-trusted address sent in the request header field".
  - `$realip_remote_addr` keeps the original peer.

  — [nginx realip](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
- **nginx `geo` module** has its own `proxy` / `proxy_recursive` with the same last / last-non-trusted semantics. Its documentation adds: "In contrast to the regular addresses, trusted addresses are checked sequentially." — [nginx geo](https://nginx.org/en/docs/http/ngx_http_geo_module.html)
- **Apache `mod_remoteip`**:
  - The header list is "processed in Right-to-Left order. Processing halts when a given useragent IP address is not trusted to present the preceding IP address".
  - The overridden address feeds `Require ip`, `%a` and mod_status. The peer stays available as `%{c}a`.
  - Without `RemoteIPInternalProxy`/`RemoteIPTrustedProxy`, "mod_remoteip will trust all hosts presenting a RemoteIPHeader IP value". The docs warn "it is trivial for the remote useragent to impersonate another useragent."
  - Private ranges are only evaluated when internal proxies are registered.

  — [Apache mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html)
- **Express `trust proxy`**:
  - With `true`, the client is "the left-most entry in the `X-Forwarded-For` header". The docs warn that the last trusted proxy must then strip or overwrite XFF, X-Forwarded-Host and X-Forwarded-Proto.
  - With a list or number, XFF is checked "from right to left until the first non-trusted address is found".
  - With a number, the docs warn about "multiple, different-length paths" to the app.

  — [Express behind proxies](https://expressjs.com/en/guide/behind-proxies.html)
- **Caddy**: with `trusted_proxies`, client IP headers "are parsed from left-to-right by default. The first untrusted IP address found becomes the real client address." Right-to-left parsing is opt-in with `trusted_proxies_strict` (since v2.8) and is off "for backwards compatibility". Caddy recommends enabling it behind HAProxy, Cloudflare, ALB or CloudFront because "the left-most IP address may be spoofed". `client_ip_headers` may list several headers, in which case "the first non-empty header value is used". — [Caddy global options](https://raw.githubusercontent.com/caddyserver/website/master/src/docs/markdown/caddyfile/options.md)
- **Rails `ActionDispatch::RemoteIp`** reverses both Client-Ip and XFF, appends REMOTE_ADDR, and takes the first non-trusted address from the right. Its default `TRUSTED_PROXIES` are 127/8, ::1, fc00::/7, 10/8, 172.16/12, 192.168/16, 169.254/16 and fe80::/10. When both Client-Ip and XFF are set inconsistently it raises `IpSpoofAttackError` (on by default). — [rails remote_ip.rb](https://raw.githubusercontent.com/rails/rails/main/actionpack/lib/action_dispatch/middleware/remote_ip.rb)
- **Tomcat `RemoteIpValve`**: the default `internalProxies` regex trusts 10/8, 192.168/16, 169.254/16, 127/8, 100.64/10, 172.16/12, ::1, fe80::/10 and fc00::/7. — [Tomcat valve docs](https://tomcat.apache.org/tomcat-10.1-doc/config/valve.html)
- **Django** removed its `SetRemoteAddrFromForwardedFor` middleware in 1.1 because "this mechanism cannot be made reliable enough for general-purpose use" and it led developers "to assume that the value of REMOTE_ADDR is 'safe'". Django today ships no such middleware. Its docs show a sample that keeps only the last XFF element. — [Django 1.1 release notes](https://docs.djangoproject.com/en/dev/releases/1.1/), [Django request/response docs](https://docs.djangoproject.com/en/5.2/ref/request-response/)
- **HAProxy `req.hdr_ip(<name>[,<occ>])`** "extracts the last occurrence", and negative `<occ>` counts from the last (examples use `hdr_ip(x-forwarded-for,-1)`). Crucially, "When used with ACLs, all occurrences are checked". — [HAProxy configuration manual](https://raw.githubusercontent.com/haproxy/haproxy/master/doc/configuration.txt)
- **IIS `<ipSecurity enableProxyMode>`** (IIS 8.0+) blocks "requests from IP addresses that are received in the x-forwarded-for HTTP header" in addition to the peer. The default is `false`. — [IIS ipSecurity](https://learn.microsoft.com/en-us/iis/configuration/system.webServer/security/ipSecurity/)
- **go-chi `middleware.RealIP`** "splits the `X-Forwarded-For` header by `,` and uses the first IP". The advisory GHSA-9g5q-2w5x-hmxf (moderate, published 2026-05-22, no CVE) affects 0.9.0 and later and is fixed in 5.3.0 with a right-to-left, trusted-skipping API. Pritchard's 2026-06-06 update says the new `middleware.ClientIP*` API has "no default and no fallback header list". — [chi advisory](https://github.com/go-chi/chi/security/advisories/GHSA-9g5q-2w5x-hmxf), [adam-p.ca](https://adam-p.ca/blog/2022/03/x-forwarded-for/)

**CDN-specific headers**
- **Cloudflare**:
  - `CF-Connecting-IP` "provides the client IP address connecting to Cloudflare to the origin web server".
  - `True-Client-IP` is Enterprise-only and otherwise identical. In a stacked CDN, "its value can be spoofed to any value" unless you add it yourself.
  - For XFF, Cloudflare appends the address of the proxy connecting to it when the client already sent XFF.
  - Cloudflare "recommends that your logs or applications look at `CF-Connecting-IP` or `True-Client-IP` instead of `X-Forwarded-For`".
  - With Pseudo IPv4 "Overwrite Headers", CF-Connecting-IP and XFF carry a pseudo-IPv4 and the real address moves to `CF-Connecting-IPv6`.
  - In same-zone Worker subrequests, `CF-Connecting-IP` "reflects the value of `x-real-ip`", which "can be altered by the user in their Worker script". Cross-zone subrequests set it to `2a06:98c0:3600::103`.

  — [Cloudflare HTTP headers reference](https://developers.cloudflare.com/fundamentals/reference/http-headers/)
- **Fastly**: "The value is not protected from modification at the edge of the Fastly network, so if a client sets this header themselves, we will use it." Fastly's own fix is VCL that sets `Fastly-Client-IP = client.ip` when `fastly.ff.visits_this_service == 0 && req.restarts == 0`. — [Fastly-Client-IP](https://www.fastly.com/documentation/reference/http/http-headers/Fastly-Client-IP/)
- **Akamai**: per Pritchard, it is safe only with "Send True Client IP Header" = yes AND "Allow Clients To Set True Client IP Header" = no. — [adam-p.ca](https://adam-p.ca/blog/2022/03/x-forwarded-for/)
- **Azure Front Door**: per Pritchard, `X-Azure-ClientIP` is leftmost (spoofable) and `X-Azure-SocketIP` is the trustworthy one. **AWS ALB** passes client-set `X-Real-IP` / `True-Client-IP` through unchanged. — [adam-p.ca](https://adam-p.ca/blog/2022/03/x-forwarded-for/)

**CDN range lists and how often they change**
- Cloudflare's IP page ("Last updated: Sep 28, 2023") lists 15 IPv4 and 7 IPv6 prefixes, also served at `/ips-v4`, `/ips-v6` and through the API (`api.cloudflare.com/client/v4/ips`, with an `etag`). Its update history:
  - 2017-06-07: 199.27.128.0/21 removed.
  - 2020-10-01: "IPS were confirmed, no changes".
  - 2021-04-08: 104.16.0.0/12 replaced by 104.16.0.0/13 + 104.24.0.0/14.
  - 2022-05-09: 2405:b500::/32 removed.
  - 2023-09-28: 2405:b500::/32 re-added.

  That is five entries in about nine years and no change in the three years to 2026-10-07. — [cloudflare.com/ips](https://www.cloudflare.com/ips/), [API output](https://api.cloudflare.com/client/v4/ips)
- **Cloudflare tenant bypass.** Certitude (2023-09-28) showed that allowlisting Cloudflare IP ranges, or using Authenticated Origin Pulls with Cloudflare's shared certificate, admits "all connections originating from Cloudflare regardless of tenant". An attacker registers their own Cloudflare zone pointing at the victim origin with protections off. Cloudflare first closed the report as "Informative" and after disclosure rated it High (7.5). Recommended mitigations: custom origin-pull certificates, Host validation, keeping the origin IP confidential, Cloudflare Aegis dedicated egress IPs, and treating IP allowlisting as defense in depth. — [Certitude](https://certitude.consulting/blog/en/using-cloudflare-to-bypass-cloudflare/)
- **AWS** `ip-ranges.json`, retrieved 2026-10-07, had `createDate` 2026-10-07-13-17-06. It holds 10,568 IPv4 and 6,933 IPv6 prefixes across services: CLOUDFRONT has 211 IPv4 / 32 IPv6, CLOUDFRONT_ORIGIN_FACING has 46 IPv4 / 35 IPv6. AWS tells users to compare publication times between downloads and offers a notification subscription. — [ip-ranges.json](https://ip-ranges.amazonaws.com/ip-ranges.json), [AWS IP ranges docs](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html)
- **Fastly**'s public list (`api.fastly.com/public-ip-list`) had 19 IPv4 and 2 IPv6 prefixes on 2026-10-07. — [Fastly public IP list](https://api.fastly.com/public-ip-list)

### Inferences
- The textbook algorithm is: merge every XFF field line → split on commas → trim → parse each element strictly → start from the TCP peer → while the current address is trusted, step left → stop at the first untrusted or unparseable element. It has the same shape as nginx `real_ip_recursive on` and Apache `mod_remoteip`. The open choice is what to do on an unparseable element; failing closed means stopping there and using the last trusted hop's view.
- A server should not offer leftmost-first or header fallback chains as defaults for access control. Caddy's left-to-right default and Express's `true` are counter-examples that need per-deployment warnings.
- For Cloudflare, a static list of 22 prefixes is practical, since it changed 5 times in 9 years, but trusting Cloudflare ranges proves only "came through some Cloudflare tenant". An origin whose allowlist must mean "through *my* zone" also needs authenticated origin pulls with its own certificate, a secret header, or a tunnel.
- AWS-sized lists (thousands of prefixes, republished daily) need machine refresh, not hand-written config.
- PROXY protocol must be configured per listener, never auto-detected, and accepted only from a source list. Otherwise any client can name its own address.

### Gaps
- No primary source gives a change frequency for AWS's file. The `createDate` observed on the day of retrieval shows it is regenerated at least daily, but how often CloudFront prefixes in particular change was not measured.
- There is no official statement from Cloudflare on advance notice for range changes on the IPs page. A 2021 third-party blog ([riklewis.com](https://www.riklewis.com/2021/04/cloudflare-ip-address-changes/)) describes an email notice; not verified against a primary source.
- Envoy's `xff_num_trusted_hops` / original IP detection docs were not read directly; only its 2024 CVE is covered (Q2).

## Q2. Which documented vulnerabilities and bypasses defeated IP allowlists (header spoofing, CVEs in frameworks and servers, address-form mismatches, path normalisation against path-scoped rules)?

### Takeaway
Bypasses come in four recurring families:
1. Trusting a client-supplied header, either at all or from the wrong position. This is still producing CVEs every month in 2026.
2. Proxies whose header-trust boundary can be crossed, for example Traefik's hop-by-hop header removal and Envoy's default "RFC 1918 is internal".
3. Address-form mismatches: IPv4-mapped IPv6, leading-zero/octal octets, and an IPv6 entry silently widened to /32.
4. Path normalisation differences between the component that applies a path-scoped rule and the one that serves the path: `;` path parameters, encoded slashes and dots, `//`, `..;/`, `#`, and whitespace.

### Cited Findings

**Spoofed-header allowlist bypasses (applications, recent)**
- **phpSysInfo CVE-2026-55584** (published 2026-08-28): the `PSI_ALLOWED` check "trusts attacker-controlled X-Forwarded-For and Client-IP HTTP headers before REMOTE_ADDR". Fixed in 3.4.6. — [NVD CVE-2026-55584](https://nvd.nist.gov/vuln/detail/CVE-2026-55584)
- **Wekan GHSA-jggc-qvfc-jr6x**: the header-login IP allowlist reads client-supplied XFF and falls back to the socket only when the header is absent. One spoofed header gives a passwordless session for any user, including admin. — [Wekan advisory](https://github.com/wekan/wekan/security/advisories/GHSA-jggc-qvfc-jr6x)
- **rustfs GHSA-fc6g-2gcp-2qrq**: the `aws:SourceIp` policy condition trusted XFF / X-Real-Ip "without verifying a trusted proxy". — [rustfs advisory](https://github.com/rustfs/rustfs/security/advisories/GHSA-fc6g-2gcp-2qrq)
- **PrestaShop GHSA-2cr4-vw9p-pjvf**: any visitor could choose its own address, which bypassed the maintenance-mode IP allowlist and forged audit logs. — [PrestaShop advisory](https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-2cr4-vw9p-pjvf)
- **readarr CVE-2026-30975**: authentication bypass via spoofed XFF. — [issue #77](https://github.com/iuliandita/readarr/issues/77)
- **MyTube GHSA-59gr-529g-x45h**: express-rate-limit bypass via spoofed XFF. — [MyTube advisory](https://github.com/franklioxygen/MyTube/security/advisories/GHSA-59gr-529g-x45h)
- **go-chi RealIP GHSA-9g5q-2w5x-hmxf** (2026-05-22): leftmost XFF. See Q1. — [chi advisory](https://github.com/go-chi/chi/security/advisories/GHSA-9g5q-2w5x-hmxf)

**Proxy and framework trust-boundary bugs**
- **Traefik CVE-2024-45410** (2024-09-19, CVSS 9.8): over HTTP/1.1 a client could make Traefik-added headers hop-by-hop with `Connection: close, X-Forwarded-Host` and so remove them. Affected: X-Forwarded-Host/Port/Proto/Server, X-Real-Ip, X-Forwarded-Tls-Client-Cert(-Info). Fixed in 2.11.9 and 3.1.3. — [NVD CVE-2024-45410](https://nvd.nist.gov/vuln/detail/CVE-2024-45410), [GitLab advisory DB](https://advisories.gitlab.com/golang/github.com/traefik/traefik/v3/CVE-2024-45410/)
- **Envoy CVE-2024-45806** (2024-09-20): the default internal trust boundary "considers all RFC1918 private address ranges as internal". External clients arriving from such addresses could set `x-envoy-*` headers that are honoured without sanitisation. The default was changed. Fixed in 1.31.2, 1.30.6, 1.29.9 and 1.28.7. — [NVD CVE-2024-45806](https://nvd.nist.gov/vuln/detail/CVE-2024-45806)
- **Next.js CVE-2025-29927** (2025-03-21): authorisation done in middleware could be bypassed with the internal `x-middleware-subrequest` header. The advice is to block external requests that carry it. This is an internal-header-trusted-from-outside bug of the same family. — [NVD CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927)
- **HAProxy CVE-2023-25725** (2023-02-14): empty header names could truncate the header list, so headers disappeared after parsing and "a bypass of access control" followed. Fixed in 2.7.3, 2.6.9 and others. — [NVD CVE-2023-25725](https://nvd.nist.gov/vuln/detail/CVE-2023-25725)
- **ingress-nginx**: `use-forwarded-headers` is a global setting that makes the controller accept X-Forwarded-* from the public internet, so source-range rules keyed on them become spoofable when there is no proxy in front. This is from community and blog sources, not a CVE. — [Kubernetes discuss](https://discuss.kubernetes.io/t/enabling-ingress-nginx-use-forwarded-headers-option-on-subset-of-ingresses/5184), [dev.to write-up](https://dev.to/authagonal/every-per-ip-control-we-shipped-was-bypassable-with-one-header-371i)
- **GitLab** IP-restriction CVEs are endpoint coverage gaps, where some routes did not apply the group IP restriction, not header spoofing:
  - CVE-2022-2533: Package Registry with deploy token.
  - CVE-2022-3286: deploy token.
  - CVE-2025-2408: "under specific conditions", 13.12 to 17.10.
  - CVE-2025-1278.

  — [Wiz CVE-2022-2533](https://www.wiz.io/vulnerability-database/cve/cve-2022-2533), [Tenable CVE-2022-3286](https://jp.tenable.com/cve/CVE-2022-3286), [SentinelOne CVE-2025-2408](https://www.sentinelone.com/vulnerability-database/cve-2025-2408/), [Vulert CVE-2025-1278](https://vulert.com/vuln-db/CVE-2025-1278)

**Address-form mismatches**
- **proxy-addr (Express) CVE-2026-90711 / GHSA-jqcg-44mw-7w3h**, critical, published 2026-09-15:
  - A trust subnet written as `::ffff:10.0.0.0/8` (the correct form is `/104`), or any IPv6 subnet with zero leading bits such as `::/1`, "compiles with all-zero leading bits and matches every IPv4 address".
  - As a result, "Every unauthenticated client is then trusted as a proxy at hop 0", and `req.ip` returns whatever the client puts in XFF.
  - The advisory notes "The misconfiguration compiles without any error".
  - Fixed in proxy-addr 2.0.8, which canonicalises mapped candidates to IPv4 before matching.

  — [proxy-addr advisory](https://github.com/jshttp/proxy-addr/security/advisories/GHSA-jqcg-44mw-7w3h), [fix commit](https://github.com/jshttp/proxy-addr/commit/780911d84d)
- **Grafana CVE-2026-33376** (2026-05-13, CVSS 7.4): "When using an IPv6 allow-list for the Auth Proxy feature, it defaults to /32 addresses". A bare IPv6 address thus admitted its whole /32. The mitigation is to write the mask explicitly (`/128`). — [Grafana advisory](https://grafana.com/security/security-advisories/cve-2026-33376)
- **coturn CVE-2026-27624** (2026-02-23/25, CVSS 7.2): `::ffff:127.0.0.1` bypasses `denied-peer-ip` for any IPv4 range, because the range and loopback checks "do not check `IN6_IS_ADDR_V4MAPPED`". The earlier CVE-2020-26262 fix had covered `0.0.0.0`, `[::1]` and `[::]` but not mapped forms. — [coturn advisory](https://github.com/coturn/coturn/security/advisories/GHSA-j8mm-mpf8-gvjg), [NVD CVE-2026-27624](https://nvd.nist.gov/vuln/detail/CVE-2026-27624), [NVD CVE-2020-26262](https://nvd.nist.gov/vuln/detail/CVE-2020-26262)
- **Mattermost CVE-2026-2455** (2026-03-16): failure to "canonicalize IPv4-mapped IPv6 addresses before reserved IP validation". This is an SSRF filter, the mirror image of an allowlist. — [NVD CVE-2026-2455](https://nvd.nist.gov/vuln/detail/CVE-2026-2455)
- **Leading-zero / octal octets**:
  - Go before 1.17 "does not properly consider extraneous zero characters at the beginning of an IP address octet, which (in some situations) allows attackers to bypass access control" (`net.ParseIP`, `net.ParseCIDR`; CVE-2021-29923).
  - Python's `ipaddress` before 3.9.5 had the same problem (CVE-2021-29921).
  - npm `netmask` ≤1.0.6 had the same problem (CVE-2021-28918).

  — [NVD CVE-2021-29923](https://nvd.nist.gov/vuln/detail/CVE-2021-29923), [NVD CVE-2021-29921](https://nvd.nist.gov/vuln/detail/CVE-2021-29921), [NVD CVE-2021-28918](https://nvd.nist.gov/vuln/detail/CVE-2021-28918)
- **Python `ipaddress` CVE-2024-4032**: `is_private` / `is_global` gave wrong answers for some ranges. Fixed in 3.12.4 and 3.13.0a6. — [NVD CVE-2024-4032](https://nvd.nist.gov/vuln/detail/CVE-2024-4032)

**Path normalisation against path-scoped rules**
- **Spring CVE-2016-5007**: Spring Security and Spring MVC differed in matching strictness, "for example with regards to space trimming in path segments", so protected controllers were reachable. — [NVD CVE-2016-5007](https://nvd.nist.gov/vuln/detail/CVE-2016-5007)
- **Spring CVE-2023-20860**: a `**` pattern with `mvcRequestMatcher` mismatched between Security and MVC. — [NVD CVE-2023-20860](https://nvd.nist.gov/vuln/detail/CVE-2023-20860)
- **Spring CVE-2022-22978**: `RegexRequestMatcher` with `.` bypassable "on some servlet containers". — [NVD CVE-2022-22978](https://nvd.nist.gov/vuln/detail/CVE-2022-22978)
- **Spring Security `StrictHttpFirewall`** rejects by default:
  - path parameters (`;`);
  - encoded `/` (`%2F`) and `.` (`%2E`);
  - backslash;
  - `//`;
  - non-normalised paths;
  - control characters.

  The rationale it gives: "The servlet spec does not clearly state whether [path parameters] should be included in the `servletPath` and `pathInfo` ... an attacker could add them to the requested URL to cause a pattern match to succeed or fail unexpectedly." — [Spring Security HttpFirewall](https://docs.spring.io/spring-security/reference/servlet/exploits/firewall.html)
- **Apache Shiro CVE-2020-1957, CVE-2020-11989, CVE-2020-13933**: authentication bypasses from crafted request paths with Spring dynamic controllers. The NVD texts are terse. — [NVD CVE-2020-1957](https://nvd.nist.gov/vuln/detail/CVE-2020-1957), [NVD CVE-2020-11989](https://nvd.nist.gov/vuln/detail/CVE-2020-11989), [NVD CVE-2020-13933](https://nvd.nist.gov/vuln/detail/CVE-2020-13933)
- **Apache httpd CVE-2021-41773 / CVE-2021-42013** (2.4.49 / 2.4.50): a path-normalisation change let traversal reach files outside Alias directories that were not protected by "require all denied". It was exploited in the wild, and the first fix was incomplete. — [NVD CVE-2021-41773](https://nvd.nist.gov/vuln/detail/CVE-2021-41773), [NVD CVE-2021-42013](https://nvd.nist.gov/vuln/detail/CVE-2021-42013)
- **HAProxy CVE-2023-45539**: `#` was accepted in the URI, which could cause "misinterpretation of a path_end rule, such as routing index.html#.png to a static server". — [NVD CVE-2023-45539](https://nvd.nist.gov/vuln/detail/CVE-2023-45539)
- **Orange Tsai, "Breaking Parser Logic"** (Black Hat USA / DEF CON 26, 2018): path normalisation inconsistencies across layers, such as nginx or Apache in front of Tomcat with `..;/`, bypass reverse-proxy protections. 0-days were found in Spring, Rails, Next.js and aiohttp. — [Black Hat slides](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf), [PortSwigger summary](https://portswigger.net/daily-swig/multi-layered-systems-cracked-open-by-inconsistent-parsing)
- **nginx `merge_slashes on`** (the default): "compression is essential for the correct matching of prefix string and regular expression locations. Without it, the '//scripts/one.php' request would not match `location /scripts/`". — [nginx core module](https://nginx.org/en/docs/http/ngx_http_core_module.html#merge_slashes)
- **RFC 9110 §17.3**: local storage "prefer[s] user-friendliness over security when handling invalid or unexpected characters, recomposition of decomposed characters, and case-normalization of case-insensitive names". — [RFC 9110 §17.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-17.3)

### Inferences
- A path-scoped IP rule is only as strong as the agreement between the path the rule matched and the path the handler serves. The safe pattern is to match on the same normalised path that selects the location and file, and to refuse ambiguous forms outright as Spring's firewall does, rather than to match the raw target. This applies to encoded `/` or `.`, `;`, backslash, NUL, `#` in the target, and to case on case-insensitive filesystems.
- Rules applied in a proxy in front of the server (HAProxy ACLs, ingress source ranges) are especially exposed, because the backend normalises differently.
- Every address-form CVE above reduces to the same fix: parse strictly (no leading zeros, no octal, exact bit count, explicit mask required or defaulting to a host mask), and canonicalise before matching (unmap ::ffff:a.b.c.d to IPv4, drop or refuse zones). The Grafana case argues for making a bare IPv6 address mean /128 and rejecting masks that do not cover the ::ffff marker when an entry is written in mapped form.

### Gaps
- No Spring Framework, Django or Rails CVE was found where the framework's *built-in* client-IP logic was spoofable in recent years. Their documented risks are configuration-dependent (Rails and Tomcat trust private ranges by default; Django ships nothing).
- No primary write-up was found for an IPv6 zone-id (`fe80::1%eth0`) allowlist bypass in a web server.
- The NVD descriptions for the Shiro CVEs do not name the exact path forms. Community write-ups attribute them to `;` and encoded slashes; the vendor advisories were not read.

## Q3. How do dual-stack sockets present IPv4 clients (IPv4-mapped IPv6), how are zone ids handled, and which servers normalise before matching?

### Takeaway
On Linux an `AF_INET6` socket without `IPV6_V6ONLY` accepts IPv4 clients and reports them as `::ffff:a.b.c.d`. The kernel default `bindv6only = 0` makes that the norm unless the server sets the option. nginx and Apache map these back to IPv4 before matching IPv4 rules. Go's `netip` and Python's `ipaddress` deliberately do not match a mapped address against an IPv4 prefix, so code must unmap first. HAProxy goes further and treats 6to4 and IPv4-compatible forms as IPv4 too. Zone ids are local-only and must not appear in data from the wire.

### Cited Findings
- RFC 4291 §2.5.5.2 defines the IPv4-mapped IPv6 address as 80 zero bits, 16 one bits, then the IPv4 address, written e.g. `::FFFF:129.144.52.38`. — [RFC 4291 §2.5.5.2](https://www.rfc-editor.org/rfc/rfc4291.html#section-2.5.5.2)
- Linux `IPV6_V6ONLY(2const)`: if the flag is false, "the socket can be used to send and receive packets to and from an IPv6 address or an IPv4-mapped IPv6 address. The default value for this flag is defined by the contents of the file /proc/sys/net/ipv6/bindv6only. The default value for that file is 0 (false)." — [IPV6_V6ONLY man page](https://man7.org/linux/man-pages/man2/IPV6_V6ONLY.2const.html)
- Linux `ipv6(7)`: "When you get an IPv4 connection or packet to an IPv6 socket, its source address will be mapped to v6." — [ipv6(7)](https://man7.org/linux/man-pages/man7/ipv6.7.html)
- **nginx**: `ngx_http_access_module` checks `IN6_IS_ADDR_V4MAPPED` on an `AF_INET6` peer and, when IPv4 rules exist, rebuilds the IPv4 address from bytes 12 to 15 and evaluates the IPv4 rules. — [nginx source, ngx_http_access_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_access_module.c)
- **Apache**: "As with httpd in general, any IPv4-over-IPv6 mapped addresses are recorded in their IPv4 representation." — [Apache mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html)
- **HAProxy**: if the tested address is IPv6 and the pattern IPv4, "the match applies in IPv4 using the pattern's mask if the IPv6 address matches with 2002:IPV4::, ::IPV4 or ::ffff:IPV4, otherwise it fails". If the tested address is IPv4 and the pattern IPv6, the address is converted by "prefixing ::ffff:". — [HAProxy manual §7.1.6](https://raw.githubusercontent.com/haproxy/haproxy/master/doc/configuration.txt)
- **Go `net/netip`**:
  - `Prefix.Contains`: "An IPv4 address will not match an IPv6 prefix. An IPv4-mapped IPv6 address will not match an IPv4 prefix ... If ip has an IPv6 zone, Contains returns false, because Prefixes strip zones."
  - `Addr.Unmap` removes the mapped prefix.
  - Prefix parsing refuses zones.

  — [Go net/netip](https://pkg.go.dev/net/netip)
- **Express / proxy-addr 2.0.8** (2026-09-15) "Canonicalize[s] IPv4-mapped candidates to IPv4 so a mapped address cannot bypass the cross-family guard". An IPv6 trust subnet now spans IPv4 only when it "is a mapped subnet whose prefix covers the ::ffff: marker". — [proxy-addr index.js](https://github.com/jshttp/proxy-addr/blob/master/index.js), [advisory](https://github.com/jshttp/proxy-addr/security/advisories/GHSA-jqcg-44mw-7w3h)
- **Failures from not normalising**: coturn CVE-2026-27624 and Mattermost CVE-2026-2455 (see Q2); Sync-in Server CVE-2026-47684, where a private-IP regex did not match mapped forms. — [coturn advisory](https://github.com/coturn/coturn/security/advisories/GHSA-j8mm-mpf8-gvjg), [Mattermost CVE](https://nvd.nist.gov/vuln/detail/CVE-2026-2455), [GitLab advisory DB CVE-2026-47684](https://advisories.gitlab.com/npm/@sync-in/server/CVE-2026-47684/)
- **Zone ids**:
  - RFC 9844 (August 2025) obsoletes RFC 6874. It removes zone ids from URI syntax because browser implementers found them "impracticable to support".
  - It restates that "zone identifiers are of local significance only and must not be sent on the wire".
  - It says "software should not trust packets that contain textual non-global addresses as data".
  - It notes that RFC 4007 sets no length or character-set limit, so implementations must bound and check them, e.g. no NUL.

  — [RFC 9844 §3, §6](https://www.rfc-editor.org/rfc/rfc9844.html)
- **PROXY protocol v1** requires canonical textual addresses: no leading zeros, exactly 128 bits for IPv6. — [PROXY protocol spec §2.1](https://www.haproxy.org/download/3.2/doc/proxy-protocol.txt)

### Inferences
- A server that listens on `[::]` with `bindv6only = 0` and lets an operator write `allow 192.0.2.0/24` must unmap the peer before matching, as nginx does. Otherwise IPv4 clients never match IPv4 rules: allowlists fail closed and denylists fail open. Unmapping once at accept time also gives logs, fail2ban and CrowdSec the dotted-quad form they expect.
- HAProxy's treatment of 6to4 (`2002:IPV4::`) and IPv4-compatible (`::IPV4`) addresses as IPv4 is a design choice to be aware of. It lets a native IPv6 source in 2002::/16 match an IPv4 rule. A stricter server would unmap only ::ffff:0:0/96.
- For addresses taken from headers (XFF, `Forwarded`, PROXY v1), a zone id, brackets, a port, or a non-canonical IPv4 form should either be refused or be parsed strictly by one routine shared by configuration and request parsing. Go's `Contains` returning false for zoned addresses shows how a zone silently changes the result.

### Gaps
- Whether glibc's `getnameinfo` / `inet_ntop` append a scope id for link-local peers, and how each web server prints such a peer in its logs, was not verified from primary sources.
- No primary data was found on how often real deployments run dual-stack sockets with `bindv6only = 0`, as opposed to separate IPv4 and IPv6 listeners.

## Q4. 403 or 404 for refused requests: what do RFC 9110, OWASP and server defaults say, and what are the trade-offs?

### Takeaway
RFC 9110 makes 403 the meaning of a refusal and explicitly allows 404 to "hide" a forbidden resource's existence. 404 is defined as covering "not willing to disclose that one exists". OWASP endorses 404 when existence itself is sensitive. GitHub does it for private repositories, and documents the confusion it causes. nginx, Apache and IIS default to 403 for IP denials; IIS alone offers 404 (or abort) as a built-in choice. The operational cost of 404 is that legitimate users and admins cannot tell "blocked" from "missing" unless the log says so. Detection tools are mostly indifferent, because CrowdSec's probing scenarios count both codes.

### Cited Findings
- RFC 9110 §15.5.4 (403): "The 403 (Forbidden) status code indicates that the server understood the request but refuses to fulfill it. A server that wishes to make public why the request has been forbidden can describe that reason in the response content (if any). ... a request might be forbidden for reasons unrelated to the credentials. An origin server that wishes to 'hide' the current existence of a forbidden target resource MAY instead respond with a status code of 404 (Not Found)." — [RFC 9110 §15.5.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.4)
- RFC 9110 §15.5.5 (404): "The 404 (Not Found) status code indicates that the origin server did not find a current representation for the target resource or is not willing to disclose that one exists." It also says "A 404 response is heuristically cacheable". — [RFC 9110 §15.5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.5)
- RFC 9110 §11.4: "A server that receives valid credentials that are not adequate to gain access ought to respond with the 403 (Forbidden) status code". — [RFC 9110 §11.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.4)
- **OWASP IDOR Prevention Cheat Sheet** (Java examples added 2026-09-29): "If the resource's existence is sensitive, use the scoped lookup and map both cases to the same public response, such as a 404 (Not Found) response. For example, `GET /user/john@example.com` should not reveal whether an account exists to a caller who is not allowed to know." — [OWASP IDOR cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- **OWASP REST Security Cheat Sheet** status table: 403 "is used when the authentication succeeded but authenticated user doesn't have permission"; 404 "When a non-existent resource is requested". — [OWASP REST Security cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- **OWASP Authentication Cheat Sheet**: differing status codes (200 vs 403) "can leak information about whether the account is valid or not", even behind a generic error page. — [OWASP Authentication cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- **GitHub REST API**:
  - "If you make a request to access a private resource and your request isn't properly authenticated, you will receive a `404 Not Found` response. GitHub uses a `404 Not Found` response instead of a `403 Forbidden` response to avoid confirming the existence of private repositories."
  - The troubleshooting page then has to tell users "If you get a `404 Not Found` response when you know that the resource that you are requesting exists, you should check your authentication."
  - GitHub also answers 404 instead of 405 for unsupported methods.

  — [GitHub REST troubleshooting](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api)
- **nginx**: a matching `deny` returns `NGX_HTTP_FORBIDDEN` (403) and logs "access forbidden by rule" at `NGX_LOG_ERR`, only when `satisfy all`. — [nginx source](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_access_module.c), [nginx access module](https://nginx.org/en/docs/http/ngx_http_access_module.html)
- **Apache 2.4**: a denied authorisation without authentication logs `AH01630: client denied by server configuration: <file or uri>` at `APLOG_ERR` and returns `HTTP_FORBIDDEN`. — [httpd mod_authz_core.c](https://github.com/apache/httpd/blob/trunk/modules/aaa/mod_authz_core.c)
- **IIS `<ipSecurity denyAction>`**: `AbortRequest`, `Unauthorized` (401), `Forbidden` (403, the default) or `NotFound` (404). Microsoft warns that `Unauthorized` "may cause an authentication dialog to appear ... resulting in spurious authentication attempts". — [IIS ipSecurity](https://learn.microsoft.com/en-us/iis/configuration/system.webServer/security/ipSecurity/)
- **CrowdSec**: `crowdsecurity/http-probing` counts responses with status `404`, `403` or `400` on non-static paths, per source IP and FQDN, distinct paths, capacity 10, leak 10 s. `http-admin-interface-probing` counts 404 or 403 on admin paths, capacity 2. A 403-to-404 switch therefore does not change these detections. — [CrowdSec hub http-probing](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/http-probing.yaml), [http-admin-interface-probing](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/http-admin-interface-probing.yaml)
- **fail2ban 1.1.0**:
  - The stock jails that react to denials read the *error* log line, not the status code: `nginx-forbidden` matches "access forbidden by rule" (filter since 2018-09-14, jail present in 1.1.0's jail.conf), and `apache-auth` matches "client denied by server configuration".
  - `nginx-botsearch` matches *404* access-log lines for a list of probe paths.
  - The status a client sees therefore matters less than whether the server still writes the denial reason.

  — [fail2ban nginx-forbidden.conf](https://github.com/fail2ban/fail2ban/blob/master/config/filter.d/nginx-forbidden.conf), [fail2ban 1.1.0 filters and jail.conf](https://github.com/fail2ban/fail2ban/tree/1.1.0/config) (local copy: `docs/fail2ban-ref/config/`)

### Inferences
- **Arguments for 404**: it hides that a path exists (RFC 9110 and OWASP endorse this when existence is sensitive). It gives scanners one answer for "missing" and "blocked", so they cannot map which admin paths exist and are protected. It matches what the agensio codebase already does for hidden files, `handler = "deny"` and encoded separators (per CLAUDE.md).
- **Arguments for 403**:
  - It is the RFC's primary meaning and the default of nginx, Apache and IIS, so it is what admins expect when debugging.
  - Legitimate users blocked by a wrong rule get a distinguishable answer.
  - A 404 is heuristically cacheable (RFC 9110 §15.5.5), so a CDN could keep a refusal for an allowed client unless `Cache-Control` says otherwise. This also applies to a 403 with explicit freshness, but 404 is cached by default.
- **Middle ground**: answer 404 (or 403) to the client and always write the true reason ("denied by ip rule X") to the error or access log. This keeps the hiding benefit and the debuggability. The IIS-style per-rule choice (403, 404, abort) is the main precedent for making it configurable.

### Gaps
- No empirical study was found measuring user confusion or support load from 404-for-forbidden policies; GitHub's troubleshooting page is the only primary evidence of the cost.
- The OWASP Authorization and Error Handling cheat sheets contain no explicit 403-versus-404 guidance (checked 2026-10-07). The guidance found is in the IDOR, REST and Authentication cheat sheets.

## Q5. How should denials be logged so they are debuggable and usable by fail2ban or CrowdSec without flooding the logs?

### Takeaway
Both nginx and Apache log an IP denial as one error-level line per refused request that names the client and the request. fail2ban's stock jails key on exactly those strings. Neither server rate-limits these lines; journald drops lines above 10,000 per 30 s per service by default. The upstream advice from fail2ban and OWASP is to keep the failure stream small and separate (conditional or dedicated logs), to log authorisation failures always, and to make sure log volume cannot itself become a denial of service.

### Cited Findings
- **nginx**:
  - One line per denial at error level, `*N access forbidden by rule, client: <addr>, server: <name>, request: "<line>", host: "<host>"`. The example line is from the fail2ban filter header.
  - `log_not_found` (default on) controls error-log lines for missing files.
  - `limit_req_log_level` (default `error`; delays one level lower) sets the level for rate-limit refusals.
  - `access_log ... if=condition` (1.7.0) gives conditional access logging.

  — [fail2ban nginx-forbidden.conf](https://github.com/fail2ban/fail2ban/blob/master/config/filter.d/nginx-forbidden.conf), [nginx source](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_access_module.c), [nginx core log_not_found](https://nginx.org/en/docs/http/ngx_http_core_module.html#log_not_found), [nginx limit_req](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html#limit_req_log_level), [nginx log module](https://nginx.org/en/docs/http/ngx_http_log_module.html#access_log)
- **Apache**: `AH01630: client denied by server configuration: <path>` at error level per request. fail2ban's `apache-auth` failregex includes `^client (?:denied by server configuration|used wrong authentication scheme)\b`. — [httpd mod_authz_core.c](https://github.com/apache/httpd/blob/trunk/modules/aaa/mod_authz_core.c), [fail2ban apache-auth.conf](https://github.com/fail2ban/fail2ban/blob/1.1.0/config/filter.d/apache-auth.conf)
- **fail2ban wiki "Best practice"**:
  - "Try to reduce count of log-messages (especially unneeded or unrelated information ... 'parasitic')".
  - "observing of the access-log directly may be too heavy for your system (well visited web-server generating too many entries in access-log may produce high load by Fail2Ban)".
  - It shows an nginx `map $status $loggable` with `access_log /var/log/nginx/access_for_fail2ban.log combined if=$loggable`, which logs only non-2xx/3xx, and an `error_page` to an internal location with its own access log for 404/403/401/500.
  - It also says "Under DDOS-attack similar circumstances use other tools".

  — [fail2ban wiki Best practice](https://github.com/fail2ban/fail2ban/wiki/Best-practice) (local copy `docs/fail2ban-ref/wiki/Best-practice.md`)
- **journald**: `RateLimitIntervalSec=` / `RateLimitBurst=` "Defaults to 10000 messages in 30s", applied per service. Beyond the limit "all further messages within the interval are dropped". The effective burst is multiplied by a factor based on free disk space. — [journald.conf(5)](https://man7.org/linux/man-pages/man5/journald.conf.5.html)
- **OWASP Logging Cheat Sheet**:
  - "Authorization (access control) failures" are among the events to log.
  - Ensure "logging cannot be used to deplete system resources, for example by filling up disk space".
  - "If log data is utilized in any action against users (e.g. blocking access, account lock-out), ensure this cannot be used to cause denial of service (DoS) of other users".
  - It lists the threat "An attacker floods log files in order to exhaust disk space".

  — [OWASP Logging cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- **OWASP Authorization Cheat Sheet**: "Both too much and too little logging may be considered security weaknesses (see CWE-778 and CWE-779) ... Too much logging not only can strain resources and lead to excessive false positives". It asks for "consistent, well-defined formats that can be readily parsed". — [OWASP Authorization cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- **RFC 9110 §17.8**: log information "ought to be purged of personally identifiable information, including ... IP addresses ... as soon as that information is no longer necessary to support operational needs for security, auditing, or fraud control." — [RFC 9110 §17.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-17.8)
- **CrowdSec consumption**: the scenarios group by `evt.Meta.source_ip` and read status, path and FQDN from parsed access or error logs. Ban windows (`blackhole`) are 1 to 5 minutes per scenario. `http-sensitive-files` (capacity 4, leak 5 s) matches request endings such as `.git` / `.log` / `.db` whatever the status. — [CrowdSec hub scenarios](https://github.com/crowdsecurity/hub/tree/master/scenarios/crowdsecurity)
- **The address in the log matters.** With realip/remoteip, the logged `%a` / `$remote_addr` is the derived client, and the peer is kept separately (`%{c}a`, `$realip_remote_addr`). A ban acting on the peer address instead of the client would ban the CDN or proxy. — [Apache mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html), [nginx realip](https://nginx.org/en/docs/http/ngx_http_realip_module.html)

### Inferences
- A denial line that serves both humans and fail2ban carries:
  - the derived client address, and the peer when they differ;
  - the site;
  - the rule or location that refused, with its source file or line if available;
  - the method and normalised path;
  - the status sent.

  It should use a fixed, documented prefix so one `failregex` matches it and stays stable across versions.
- Writing the line at error level per request mirrors nginx and Apache, but under a scan it can produce thousands of lines a second. Two refinements fit OWASP's "logging cannot deplete resources": a per-worker, per-address suppression window ("N further denials from A suppressed") and the access-log status field, which carries every request anyway. A summarised line hides counts from a jail that counts lines, so if suppression is used the jail's `maxretry` must be reachable within the window, or the summary must carry the count.
- Behind a CDN, banning at the host firewall (fail2ban, nftables) bans the CDN's edge address. Denials of CDN-fronted clients have to be enforced in the server, or at the CDN through its API (CrowdSec has Cloudflare bouncers, not researched here).

### Gaps
- Neither nginx nor Apache rate-limits its own denial log lines; no primary source documents a server-side suppression mechanism for "access forbidden" lines. This is a design gap, not a research gap.
- CrowdSec's guidance on log volume and parser cost was not read.
- No public numbers were found on fail2ban CPU cost per log line.

## Q6. What data structures are used for fast CIDR matching, where is the break-even against a linear scan, and what does a lookup cost per request?

### Takeaway
Production servers use a linear, first-match scan for short hand-written rule lists: nginx `allow`/`deny`, nginx's trusted proxies, and Apache's lists. They switch to tries or trees for large lists: nginx `geo` uses a radix tree, and HAProxy loads IPv4 patterns from files into a binary tree. Modern software tries answer a longest-prefix match in roughly 15 to 40 ns, even with a full Internet table of about 1M prefixes. No published break-even figure against a linear scan was found.

### Cited Findings
- **nginx `ngx_http_access_module`**: "The rules are checked in sequence until the first match is found." The docs add "In case of a lot of rules, the use of the ngx_http_geo_module module variables is preferable." — [nginx access module](https://nginx.org/en/docs/http/ngx_http_access_module.html)
- **nginx `geo`**:
  - Uses `ngx_radix_tree_t` trees for IPv4 and IPv6.
  - Supports a `ranges` mode, loaded faster when addresses are in ascending order.
  - "the mere existence of even a large number of declared 'geo' variables does not cause any extra costs for request processing".
  - Its `proxy` list (trusted proxies) is "checked sequentially".

  — [nginx geo module](https://nginx.org/en/docs/http/ngx_http_geo_module.html), [ngx_http_geo_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_geo_module.c)
- **HAProxy**: for patterns loaded with `-f`, "Depending on the data type and match method, HAProxy may load the lines into a binary tree, allowing very fast lookups. This is true for IPv4 and exact string matching. In this case, duplicates will automatically be removed." — [HAProxy manual §7.1](https://raw.githubusercontent.com/haproxy/haproxy/master/doc/configuration.txt)
- **IIS `ipSecurity`**: "Rules are processed from top to bottom, in the order they appear in the list". Microsoft recommends listing deny rules first. — [IIS ipSecurity](https://learn.microsoft.com/en-us/iis/configuration/system.webServer/security/ipSecurity/)
- **iprbench** (Go, AMD Ryzen 7 PRO 4750U, repository updated 2026-09-21), longest-prefix-match geomean per lookup:

  | Implementation | Geomean per lookup |
  |---|---|
  | `bart.Table` | 23.8 ns |
  | `bart.Fast` | 20.0 ns |
  | `bart.Lite` | 23.9 ns |
  | `netipds` | 85 ns |
  | `kentik/patricia` | 185 ns |
  | `lpmtrie` | 197 ns |
  | `critbitgo` | 337 ns |

  - For `bart.Table`, 1,000 random prefixes take 17 to 20 ns, and a ~1M-prefix Tier-1 table takes 21 ns for IPv4 and 36 to 40 ns for IPv6.
  - BART is "a multibit trie with a fixed stride of 8 bits" based on Knuth's Allotment Routing Table, with popcount-compressed nodes.

  — [iprbench](https://github.com/gaissmai/iprbench), [bart](https://github.com/gaissmai/bart)
- **Cost of the list being searched**: Cloudflare's list is 22 prefixes, Fastly's 21, CloudFront's 243 (IPv4 + IPv6), and all of AWS 17,501 (counts on 2026-10-07). — [Cloudflare API](https://api.cloudflare.com/client/v4/ips), [Fastly list](https://api.fastly.com/public-ip-list), [AWS ip-ranges.json](https://ip-ranges.amazonaws.com/ip-ranges.json)

### Inferences
- **Lists of a few dozen entries.** A trusted-proxy list or a hand-written allowlist is a few dozen entries at most. A linear scan of fixed-size masked compares (IPv4 one 32-bit AND-compare, IPv6 two 64-bit ones) costs roughly a nanosecond or less per entry on current CPUs. That is comparable to or below a trie lookup up to some tens of entries, and it keeps first-match semantics, which a longest-prefix trie does not give for `allow` / `deny` ordering without extra work.
  - This is an estimate, not a measurement found in a source.
  - The parent project should measure it with its own A/B harness before choosing.
- **Lists in the hundreds or thousands.** CloudFront plus country or abuse feeds call for a trie (radix, Patricia, multibit ART/BART, or LC-trie), built once per configuration generation and read lock-free per worker.
- **Ordered allow/deny lists.** To keep nginx's first-match semantics in a trie, store each prefix with its rule index and take the minimum index among the matches. Otherwise the configuration language must be defined as longest-prefix (as nginx `geo` is: "A value of the most specific match is used").
- **Per-request cost is small next to the rest.** Even a 40 ns lookup is about 2 % of the ~2 µs per plain 1 KB request agensio measured on Linux (CLAUDE.md performance notes). XFF parsing (string splitting, address parsing per element) is likely to cost more than the CIDR match itself; this has not been measured.

### Gaps
- No published break-even list size between a linear scan and a trie for IP matching was found, and no per-request cost of nginx `allow`/`deny` or realip.
- No published measurement was found of the cost of parsing an X-Forwarded-For header of N elements.
- The Linux kernel's LC-trie (`fib_trie`) and nftables interval sets (rbtree / pipapo) were not researched from primary sources here, although they are the relevant structures if denial moves to the host firewall.
