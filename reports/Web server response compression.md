# Compress public responses by default, guard credentialed ones

Every server and CDN studied agrees on what to leave alone: a body that already has a `Content-Encoding`, a bodiless HEAD, 204 or 304, binary types and tiny bodies. They disagree on the four things the RFCs actually settle, which are the ETag of a coded variant, `Vary` on the uncompressed variant, `Cache-Control: no-transform` and streaming. Those disagreements produce most of the complaints administrators raise. Apache's `-gzip` ETag suffix blocked 304s from 2.4.0 until a directive arrived in 2.4.58. nginx's defaults are `text/html` only, no `Vary` and keyed on the `Via` header. Traefik had to fix server-sent events twice.

The cost question is settled by measurement. On the project's Linux box (Ryzen 9 9900X, one core), **zstd level 3 produces output 2 % larger than gzip 6 at eight times the speed (728 MB/s against zlib's 90)**, and brotli 4 matches gzip 6 at twice its speed. Brotli 10-11 and zstd 15+ are 15 to 500 times slower and belong to files compressed once. For concurrent streams, memory is the cost that bites, not CPU: brotli's default window costs 9-11 MB per stream, and a 256 KiB window cuts that to 1.4-2 MB for under 1 % of output.

Browsers in 2026 accept brotli at 97 % and zstd at 83 %. CDNs mostly ask origins for `br, gzip` and keep whatever coding the origin sends.

The security boundary is narrow but real. BREACH and its successors need three things together: a secret in the body, attacker-reflected input beside it, and requests the victim's browser sends with its own credentials. Static files and anonymous pages are therefore safe, and credentialed dynamic pages are not. Laravel, one of agensio's main presets, does not mask its CSRF token.

Applications make this harder. PHP's zlib layer compresses 304s and images, ignores `q=0`, compresses twice and stalls SSE. Next.js, Ghost, Grafana 13 and W3 Total Cache compress their own output.

For agensio, the evidence supports revising the roadmap's "on-the-fly off by default":

- **Static files:** compress once at cache fill (brotli 11 and gzip 9, on a background thread) and serve the results exactly as today's twins are served.
- **Dynamic responses:** compress in an `auto` mode with zstd 3, brotli 4 and gzip 5, capped windows, weak ETags and `Vary` always sent. `auto` skips any request the browser sent with an ambient credential.
- **Already compressed:** pass through whatever the application encoded.
- **Request bodies:** never decode them.
- **Agent interface:** show every decision to the agent through `path_check`, health and the access log.

## Nine servers share a skip list and split on validators, Vary and streaming

Every server whose behaviour is documented or readable in source skips a body that already carries a `Content-Encoding`, and none puts a coded body on a HEAD, 204 or 304. All but Envoy, and Traefik's brotli and zstd paths, keep 206 answers uncompressed. Beyond that shared list they split on almost everything the RFCs regulate.

**nginx's own code compresses only gzip.** It is off by default and runs at level 1. It compresses `text/html` unless more types are listed, and only statuses 200, 403 and 404 ([nginx gzip module](https://nginx.org/en/docs/http/ngx_http_gzip_module.html)). The defaults have several side effects:

- The 20-byte minimum is read only from `Content-Length`, so a chunked upstream answer of any size passes.
- nginx removes `Content-Length` and `Accept-Ranges`, so a Range request on a compressible response gets the whole compressed body as a 200.
- Strong ETags have been turned weak since 1.7.3.
- Requests that carry a `Via` header are not compressed (`gzip_proxied off`).
- No `Vary` is sent unless `gzip_vary` is on.
- `no-transform` appears nowhere in the filter's source.

Sources for this list: the [gzip filter source](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_gzip_filter_module.c) and the [nginx CHANGES](https://nginx.org/en/CHANGES). Brotli and zstd exist only as third-party modules. An nginx maintainer wrote on 2026-09-28 that "Native Brotli support is not planned at the moment" ([nginx #397](https://github.com/nginx/nginx/issues/397)).

**Apache's mod_deflate and mod_brotli are filters the administrator attaches per type, with no types by default.** mod_brotli exists since 2.4.26. gzip runs at zlib's default level 6, and brotli at quality 5 with an 18-bit (256 KB) window ([mod_deflate](https://httpd.apache.org/docs/2.4/mod/mod_deflate.html), [mod_brotli](https://httpd.apache.org/docs/2.4/mod/mod_brotli.html)). Both filters merge `Vary: Accept-Encoding` before they read the client's header, so the uncompressed variant is marked too. Both skip any response that carries `Content-Range`, which turns a Range request into an uncompressed 206 ([mod_deflate.c](https://github.com/apache/httpd/blob/trunk/modules/filters/mod_deflate.c)).

Apache's ETag handling is the clearest warning in the field. The default `AddSuffix` keeps validators distinct, but it "prevents serving 'HTTP Not Modified' (304) responses to conditional requests for compressed content". It has been the default since 2.4.0. A directive to change it, `DeflateAlterETag`, arrived only in 2.4.58 (2023-10-19), after bug reports PR 39727 and PR 45023 ([mod_deflate docs](https://httpd.apache.org/docs/2.4/mod/mod_deflate.html), [httpd 2.4 CHANGES](https://github.com/apache/httpd/blob/2.4.x/CHANGES)). Apache is also the reference for request-body inflation. Since 2.4.10, the inflated body counts against `LimitRequestBody`, and a request whose inflation ratio exceeds 200 more than three times is ended.

**LiteSpeed is the one family that compresses both static and dynamic responses by default** (IIS does so for static files only). LSWS and OpenLiteSpeed ship with "Enable Compression: Yes" and these defaults ([LSWS tuning](https://www.litespeedtech.com/docs/webserver/config/tuning), [OLS compression](https://docs.openlitespeed.org/config/advanced/compress/)):

- a broad built-in type list;
- gzip level 6 for both dynamic and static responses;
- brotli level 5 for static files, written once into a compressed-file cache, for files from 200 bytes to 10 MB;
- on LSWS only, dynamic brotli at level 2.

OpenLiteSpeed keeps one ETag base with a `;gz` or `;br` suffix. When it compares `If-None-Match`, it ignores the last three characters, so 304s survive. It decompresses an upstream's gzip for a client that does not accept gzip. Its `Accept-Encoding` test, though, is a substring search with no q-values ([staticfilecachedata.cpp](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/staticfilecachedata.cpp), [httpsession.cpp](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpsession.cpp), [httpreq.cpp](https://github.com/litespeedtech/openlitespeed/blob/master/src/http/httpreq.cpp)). Zstandard reached LSWS only in 6.4.0 RC1, on 2026-08-13 ([LSWS release log](https://www.litespeedtech.com/products/litespeed-web-server/release-log)).

**Caddy's `encode` is the design administrators point to.** One line enables zstd, then gzip, with these defaults:

- a 512-byte minimum;
- an allowlist of about 35 types;
- gzip level 5;
- a zstd window fixed at 128 KiB, because "the default of 8MB for the window is too large for many clients" ([zstd.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/zstd/zstd.go)).

Caddy and OpenLiteSpeed are the only servers that keep distinct strong validators and working 304s at the same time, and Caddy does it for proxied answers too. A strong ETag becomes `"abc-zstd"`, and the suffix is stripped from `If-None-Match` before the request reaches the handler that issued the tag. It also:

- adds `Vary` to 304s;
- never encodes a 206, and drops `Accept-Ranges`;
- honours `no-transform` on both the request and the response;
- since v2.11.6 and v2.11.7, sends the headers of `text/event-stream` and `Incremental: ?1` responses at once ([encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go), [Caddy encode docs](https://caddyserver.com/docs/caddyfile/directives/encode)).

Its precompressed sidecars carry their own ETag and serve byte ranges ([Caddy file_server docs](https://caddyserver.com/docs/caddyfile/directives/file_server), [staticfiles.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/fileserver/staticfiles.go)). Brotli on the fly is still a plugin. A maintainer argued in 2026 that brotli's "strongest fit" is compressing once at build time, and that putting it on the request path brings "runtime CPU cost, memory/allocation behaviour, streaming/reset semantics" ([caddy #7699](https://github.com/caddyserver/caddy/issues/7699)).

The remaining five servers fill out the range:

- **h2o** compresses only status 200, on HTTP/1.1 or later, and never HEAD. `compress: ON` gives gzip 1, brotli 1 and zstd 3, preferring br, then zstd, then gzip. It weakens ETags, sets `Accept-Ranges: none`, and obeys an `x-compress-hint` header from upstreams. It does not parse q-values, and on-the-fly zstd landed on master in June 2026 with no release since 2019 ([h2o compress directives](https://h2o.examp1e.net/configure/compress_directives.html), [compress.c](https://github.com/h2o/h2o/blob/master/lib/handler/compress.c)).
- **IIS** adapts its compression to load and popularity more than any other server (HAProxy has CPU and rate governors too):
  - static compression applies only to files hit twice in ten seconds and of at least 2,700 bytes;
  - dynamic compression switches off above 90 % CPU and back on below 50 %;
  - only gzip is built in; brotli needs the separate IIS Compression extension;
  - dynamic compression once overwrote the application's `Vary` ([IIS httpCompression](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpcompression/), [KB 2877816](https://support.microsoft.com/kb/2877816)).
- **HAProxy** compresses gzip and deflate through its embedded libslz, by default at level 1, and only statuses 200-203. When no types are listed, it compresses every type except multipart. It weakens ETags, honours `no-transform`, and has rate and CPU governors. Its own INSTALL file says zlib costs "about 3.5 times more" CPU and "~260 kB per compressed stream" ([HAProxy configuration](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt), [HAProxy INSTALL](https://github.com/haproxy/haproxy/blob/master/INSTALL)).
- **Traefik** compresses gzip, brotli and zstd, with gzip first since v3.3.5 reverted the zstd-first order. It has a 1,024-byte minimum and compresses every type except gRPC. It leaves ETags untouched, so one strong tag labels two different byte sequences, and it ignores `no-transform` ([Traefik compress](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/compress/), [migration notes](https://doc.traefik.io/traefik/migrate/v3/)).
- **Envoy** runs gzip, brotli and zstd as separate filters that compete on q-value. It has a 30-byte minimum and an 8-type list. It compresses 206 unless that status is listed as uncompressible, and by default deletes strong ETags; an option to weaken them instead arrived only in 1.38 ([Envoy compressor filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/compressor_filter), [Envoy 1.38 changelog](https://github.com/envoyproxy/envoy/blob/main/changelogs/1.38.0.yaml)).

| Server (Oct 2026) | On by default | On-the-fly codings | Default level | Minimum | Default types | Statuses |
|---|---|---|---|---|---|---|
| nginx 1.31.8 | no | gzip (br, zstd third-party) | gzip 1 | 20 B, from Content-Length only | text/html | 200, 403, 404 |
| Apache 2.4.69 | no, a filter per type | gzip, br | gzip 6, br 5 (window 18) | about 68 B, fixed | none until listed | all but 204 and Content-Range |
| LSWS 6.3.7 / OLS 1.9.4 | yes | gzip; dynamic br on LSWS only; zstd in 6.4 RC | gzip 6; br 5 static, 2 dynamic | 200 B | text, JS, JSON, XML, SVG, fonts | not documented |
| Caddy 2.11.7 | no, one-line `encode` | zstd, gzip (br plugin) | gzip 5, zstd ≈3, window 128 KiB | 512 B | ~35-type allowlist | all but 206 |
| h2o master | no | br, zstd, gzip | gzip 1, br 1, zstd 3 | 100 B | text/*, JS, JSON, +json, +xml | 200 only |
| IIS 10 | static yes, dynamic optional | gzip, deflate (br extension) | static 7, dynamic 0 | 2,700 B | text/*, message/*, JS | not documented |
| HAProxy 3.4 | no | gzip, deflate | 1 (`tune.comp.maxlevel`) | 0 | all but multipart | 200-203 |
| Traefik 3.7 | no | gzip, br, zstd | gzip 5, br 6, zstd window 8 MiB | 1,024 B | all but gRPC | any |
| Envoy 1.40 | yes once configured | gzip, brotli, zstd | gzip 6 (window 12), br 3, zstd 3 | 30 B | 8 types | any, 206 included |

| Server | ETag of a coded variant | Vary on identity | Range request | HEAD | no-transform | Streaming |
|---|---|---|---|---|---|---|
| nginx | strong → `W/` | only with `gzip_vary on` | full compressed 200 | no Content-Encoding | ignored | sync flush per upstream flush |
| Apache | `-gzip` suffix, 304 lost by default | always | identity 206 | stops compressing | ignored | FLUSH → sync flush |
| OLS | `;gz` suffix, ignored on compare | yes when encoding | identity 206 | not established | not established | partial flush |
| Caddy | `-zstd` suffix, stripped on the way in | yes, 304 included | not encoded, Accept-Ranges dropped | headers as for GET | honoured both ways | SSE headers at once, flush per write |
| h2o | `W/` | when the client offered a coding | `Accept-Ranges: none` | not compressed | not checked | flush per 8 KB |
| HAProxy | `W/`, an invalid ETag disables | appended | 206 excluded by status | not compressed | honoured | compresses as it flows |
| Traefik | unchanged | yes | gzip path skips; br and zstd paths do not | passed through bare | ignored | SSE excluded, fixed in 2019 and again in 2025 |
| Envoy | strong deleted, `W/` option | whenever compressible | 206 compressed unless listed | not compressed | honoured | chunked |

Three patterns stand out. On ETags, production uses four strategies:

- weaken the tag (nginx, h2o, HAProxy, CloudFront);
- add a suffix and translate it back on the way in (Caddy, OpenLiteSpeed);
- add a suffix without translating (Apache);
- delete the tag or leave it as it was (Envoy, Traefik).

Only the first two keep 304s working without breaking the strong-validator rule. On ranges there are three answers, a full 200, an identity 206 and a compressed 206; only the first two are safe for output compressed on the fly. On negotiation, quality is poor outside Caddy, HAProxy, Traefik and Envoy. OpenLiteSpeed and PHP use substring tests and h2o does not parse q, so none of them honours `gzip;q=0`.

## CDNs keep the origin's coding, and browsers take brotli almost everywhere

Behind a CDN, the origin's compression choice is usually what visitors receive. **Cloudflare asks every origin for `accept-encoding: br, gzip`, whatever the visitor sent.** It keeps an origin's br or gzip when the visitor accepts it, and stops compressing when the origin sends `no-transform`. It compresses only 200, 403 and 404, from 48-50 bytes up ([Cloudflare compression docs](https://developers.cloudflare.com/speed/optimization/content/compression/)). About 71 % of the HTML, JSON, CSS and JavaScript Cloudflare receives from origins arrives uncompressed ([Cloudflare cache transcoding, 2026-09-01](https://blog.cloudflare.com/cache-transcoding/)). Over a day of live traffic in 2024, Cloudflare measured average compression times of 0.848 ms for zstd, 1.544 ms for brotli and 0.872 ms for gzip, with ratios of 2.86, 3.08 and 2.56 ([Cloudflare, New standards](https://blog.cloudflare.com/new-standards/)).

**CloudFront compresses gzip and brotli at the edge only for bodies of 1,000 to 10,000,000 bytes that carry a `Content-Length`.** It never recompresses an origin's encoded body, weakens strong ETags, skips HTTP/1.0, and treats compression as best-effort, so under load it can cache and serve the uncompressed object ([CloudFront docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html)). The other CDNs differ:

- **Fastly** normalises `Accept-Encoding` to gzip or br and compresses only uncompressed origin content. It asks origins for `Vary: Accept-Encoding` "in all responses where compression was considered" ([Fastly Accept-Encoding](https://www.fastly.com/documentation/reference/http/http-headers/Accept-Encoding/)).
- **Akamai's** brotli support only caches the brotli an origin produces; compressing at the edge is a separate Ion feature ([Akamai Brotli Support](https://techdocs.akamai.com/property-mgr/docs/brotli-support)).
- **Bunny** compresses with gzip, br or zstd ([bunny.net](https://bunny.net/docs/cdn/frequently-asked-questions/mime-compression)).

Across CDNs in 2025, 46 % of compressed responses were brotli, 42 % gzip and 12 % zstd. Origins sent 61 % gzip and 39 % brotli ([Web Almanac 2025, CDN](https://almanac.httparchive.org/en/2025/cdn)).

Two consequences for an origin follow. First, zstd from an origin reaches only direct clients and Bunny, while br and gzip are what CDN pulls request. Second, an origin behind CloudFront that answers dynamic pages with chunked encoding gets no compression at the edge, so for those pages the origin's own compression is the only compression they get.

| Client | Support and default `Accept-Encoding` |
|---|---|
| Chrome, Edge 123+ (March 2024) | `gzip, deflate, br, zstd`; zstd window capped at 8 MB |
| Firefox 126+ | zstd; brotli over HTTPS only (as in Chrome) |
| Safari 26.3+ (Feb 2026) | zstd only on iOS/macOS 26.3 and later; brotli since 11 |
| Samsung Internet 28-30 | no zstd |
| Global (caniuse, 2026-10-22) | brotli 97.24 %; zstd 83.13 % full + 2.47 % partial |
| curl 8.14 | nothing by default; `--compressed` sends `deflate, gzip, br, zstd` |
| python-requests 2.32 | `gzip, deflate`, plus br or zstd only when those modules are installed |
| Node.js 20 `fetch` | `gzip, deflate` |
| GNU Wget 1.25, Python urllib | `identity` |

Sources: [caniuse zstd](https://caniuse.com/zstd), [caniuse brotli data](https://raw.githubusercontent.com/Fyrd/caniuse/main/features-json/brotli.json), [WebKit Safari 26.3](https://webkit.org/blog/17798/webkit-features-for-safari-26-3/), [Chromium intent to ship](https://groups.google.com/a/chromium.org/g/blink-dev/c/GFFOLCF12a4/m/crdNkVeaAQAJ), [MDN Accept-Encoding](https://raw.githubusercontent.com/mdn/content/main/files/en-us/web/http/reference/headers/accept-encoding/index.md), and the client headers captured locally on 2026-10-26 for the notes.

The table shows that a 2026 server can count on brotli for browsers and must keep gzip for programs. JSON APIs called from Node services or Python scripts are negotiated as gzip whatever the server prefers.

## The RFCs settle eight choices a compressor cannot improvise

The key rule is that **a content coding belongs to the representation, not to the message.** Once a server applies gzip, the gzip bytes are the representation: `Content-Length`, ETag and byte ranges all describe the coded form ([RFC 9110 8.4](https://www.rfc-editor.org/rfc/rfc9110#section-8.4)). Every obligation below follows from that.

| Obligation | Source | Who gets it wrong |
|---|---|---|
| The sender that applies a coding MUST list it in Content-Encoding, in the order applied; `identity` SHOULD NOT appear there | [RFC 9110 8.4](https://www.rfc-editor.org/rfc/rfc9110#section-8.4) | — |
| No Accept-Encoding means any coding is acceptable, `q=0` excludes a coding, the highest q wins, and ties are left to the server | [RFC 9110 12.5.3](https://www.rfc-editor.org/rfc/rfc9110#section-12.5.3) | PHP and OLS (substring match), h2o (no q); Traefik v3 beta sent br to curl |
| `Vary: Accept-Encoding` SHOULD be on cacheable negotiated responses, identity included; MUST be on 304 and 206 when the 200 has it | [RFC 9110 12.5.5](https://www.rfc-editor.org/rfc/rfc9110#section-12.5.5), [15.4.5](https://www.rfc-editor.org/rfc/rfc9110#section-15.4.5), [15.3.7](https://www.rfc-editor.org/rfc/rfc9110#section-15.3.7); [RFC 9111 4.1](https://www.rfc-editor.org/rfc/rfc9111#section-4.1) | nginx by default; PHP's identity variant |
| A strong ETag shared by the gzip and identity variants is weak by definition and MUST carry `W/`, or each variant gets its own tag | [RFC 9110 8.8.1](https://www.rfc-editor.org/rfc/rfc9110#section-8.8.1), [8.8.3](https://www.rfc-editor.org/rfc/rfc9110#section-8.8.3) | Traefik (one strong tag on both); Envoy deletes strong tags by default |
| If-Range needs strong comparison, so a weak tag never resumes a range | [RFC 9110 13.1.5](https://www.rfc-editor.org/rfc/rfc9110#section-13.1.5) | the price of weakening |
| Content-Length and byte ranges count the coded bytes | [RFC 9110 8.6](https://www.rfc-editor.org/rfc/rfc9110#section-8.6), [14.1.2](https://www.rfc-editor.org/rfc/rfc9110#section-14.1.2) | — |
| In HTTP/2 and HTTP/3, a content-length that differs from the sum of DATA frames makes the message malformed | [RFC 9113 8.1.1](https://www.rfc-editor.org/rfc/rfc9113#section-8.1.1), [RFC 9114 4.1.2](https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2) | any compressor copying the identity block |
| HEAD SHOULD send the GET's fields and MUST NOT send a wrong Content-Length | [RFC 9110 9.3.2](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.2), [8.6](https://www.rfc-editor.org/rfc/rfc9110#section-8.6) | Caddy ([#8148](https://github.com/caddyserver/caddy/issues/8148)); nginx sends no Content-Encoding on HEAD |
| A 304 carries ETag and Vary but should not carry Content-Encoding, because caches merge its fields | [RFC 9110 15.4.5](https://www.rfc-editor.org/rfc/rfc9110#section-15.4.5), [RFC 9111 3.2](https://www.rfc-editor.org/rfc/rfc9111#section-3.2) | PHP's zlib layer sends a gzip body on a 304 |
| `no-transform` binds every intermediary, and a reverse proxy is one | [RFC 9111 5.2.2.6](https://www.rfc-editor.org/rfc/rfc9111#section-5.2.2.6), [RFC 9110 3.7](https://www.rfc-editor.org/rfc/rfc9110#section-3.7) | nginx, Apache, h2o, Traefik |
| Transfer-Encoding is forbidden in HTTP/2 and HTTP/3; HTTP/1.0 has no chunked framing | [RFC 9113 8.2.2](https://www.rfc-editor.org/rfc/rfc9113#section-8.2.2), [RFC 9114 4.1](https://www.rfc-editor.org/rfc/rfc9114#section-4.1), [RFC 9112 6.1](https://www.rfc-editor.org/rfc/rfc9112#section-6.1) | — |
| zstd encoders MUST NOT need a window above 8 MB, and decoders MUST support up to 8 MB | [RFC 9659](https://www.rfc-editor.org/rfc/rfc9659) | library defaults at levels 17-19 sit at the limit |
| On a secure channel, a server MUST NOT compress confidential and attacker-controlled data together, and MUST NOT compress at all "if the source of data cannot be reliably determined" | [RFC 9113 10.6](https://www.rfc-editor.org/rfc/rfc9113#section-10.6), [RFC 9114 10.6](https://www.rfc-editor.org/rfc/rfc9114#section-10.6) | every server compresses dynamic output anyway |

Three of these rules need interpretation.

**`no-transform`.** RFC 9110 7.7 words the MUST for a "proxy", which section 3.7 defines as an agent the client chose. RFC 9111 5.2.2.6 says "an intermediary (regardless of whether it implements a cache) MUST NOT transform the content", and section 3.7 counts a gateway, that is a reverse proxy, as an intermediary. The strict reading, which Caddy, HAProxy, Envoy, Express and Rack follow, is that a server relaying FastCGI or proxied output must not add a coding to an answer marked `no-transform`. For its own files, the server is the origin and may decide for itself. No erratum settles the question.

**HEAD and 304.** RFC 9110 9.3.2 tolerates a HEAD that omits fields known only once the body is produced. But RFC 9111 4.3.5 lets caches update stored GET responses from a HEAD, so a HEAD whose `Content-Encoding` or ETag differs from the GET's costs cache entries. The safe form runs the same negotiation for HEAD as for GET and drops only `Content-Length`. For a 304, the ETag must be the tag of the variant this request would have received.

**RFC 9113 10.6.** Read literally, this section forbids compressing any dynamic TLS response whose provenance the server cannot see. No server implements it that way. Its value lies in the order it sets: compress what the server knows, and let operators opt in for the rest.

**Compression dictionary transport** ([RFC 9842](https://www.rfc-editor.org/rfc/rfc9842), September 2025) adds the `dcb` and `dcz` codings. It comes with HTTPS-only use, a MUST-level `Vary: accept-encoding, available-dictionary`, and a Sec-Fetch-based test that refuses dictionaries on risky cross-origin requests ([RFC 9842 9.3.3](https://www.rfc-editor.org/rfc/rfc9842#section-9.3.3)). It is a separate feature with its own storage and matching, and plain br and zstd do not depend on it.

## BREACH needs a secret, a reflection and the victim's credentials

Every compression side channel exploits the same fact: when attacker-chosen bytes share a compression context with a secret, the compressed length reveals whether a guess matched, and TLS does not hide lengths.

- **CRIME** (2012) broke compression at the TLS layer and in SPDY's header compression. TLS 1.3 removed TLS compression, and HPACK and QPACK were designed against CRIME ([RFC 7457 2.6](https://www.rfc-editor.org/rfc/rfc7457#section-2.6), [RFC 8446 4.1.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2), [RFC 7541 7.1.1](https://www.rfc-editor.org/rfc/rfc7541#section-7.1.1)).
- **BREACH** (Black Hat USA 2013) moved the attack to HTTP bodies ([breachattack.com](https://www.breachattack.com/)). It needs three things together:
  - the response is served "from a server that uses HTTP-level compression";
  - the response body "reflect[s] user-input";
  - the same body "reflect[s] a secret (such as a CSRF token)".
  
  The attack works against any TLS version and any cipher, with "a few thousand requests".
- **TIME** (2013) measured the same leak through timing.
- **HEIST** (2016) measured response sizes from JavaScript through TCP congestion-window effects, so no network position was needed, and noted that HTTP/2 makes this easier ([HEIST paper](https://www.blackhat.com/docs/us-16/materials/us-16-VanGoethem-HEIST-HTTP-Encrypted-Information-Can-Be-Stolen-Through-TCP-Windows-wp.pdf)).
- **Rupture** (2016) extended BREACH to block ciphers by statistics ([Rupture paper](https://raw.github.com/dionyziz/rupture/develop/etc/Black%20Hat%20Asia%202016/asia-16-Practical-New-Developments-In-The-BREACH-Attack-wp.pdf); read only in abstract).

**No protocol-level fix exists.** RFC 7457 says "application-level mitigations are needed".

The BREACH authors rank the mitigations by effectiveness, from most to least:

1. disabling compression;
2. separating secrets from user input;
3. randomising secrets per request;
4. masking secrets;
5. protecting vulnerable pages with CSRF checks;
6. length hiding;
7. rate limiting.

Disabling compression and separating secrets remove the side channel completely. Masking, which embeds a fresh one-time pad P as `P || (P ⊕ S)`, neutralises it for that one secret ([BREACH paper](https://www.breachattack.com/resources/BREACH%20-%20SSL,%20gone%20in%2030%20seconds.pdf)). On length hiding the literature disagrees:

- The BREACH paper shows random padding only multiplies the requests needed, since error falls as 1/√N.
- HEIST grades padding "inadequate".
- The 2022 "Heal the Breach" paper estimates that 1-10 bytes of random variation forces about 500 times more packets ([IEEE Access, HTB](https://ieeexplore.ieee.org/document/9754554)).

HEIST's authors call disabling third-party cookies "complete". Secondary sources report that SameSite cookies blunt the attack because cookies stop riding on cross-site subresource requests ([igvita](https://www.igvita.com/2016/08/26/stop-cross-site-timing-attacks-with-samesite-cookies/)). The current per-browser state of third-party cookie blocking was not researched, so a design cannot count on it.

Frameworks diverge sharply on whether their tokens are protected:

- **Django** masks its CSRF token per response. Since 4.2 its opt-in GZipMiddleware adds up to 100 random bytes per response ("Heal The Breach") and weakens ETags ([Django CSRF](https://docs.djangoproject.com/en/5.2/ref/csrf/), [Django middleware](https://docs.djangoproject.com/en/5.2/ref/middleware/)).
- **Rails** masks its authenticity token with a one-time pad per call ([Rails RequestForgeryProtection](https://api.rubyonrails.org/classes/ActionController/RequestForgeryProtection.html)).
- **Laravel's** `csrf_token()`, and the `@csrf` field built from it, is the raw 40-character session token, compared with `hash_equals` and not masked ([Laravel helpers.php](https://github.com/laravel/framework/blob/12.x/src/Illuminate/Foundation/helpers.php), [VerifyCsrfToken.php](https://github.com/laravel/framework/blob/12.x/src/Illuminate/Foundation/Http/Middleware/VerifyCsrfToken.php)). A compressed Laravel page that reflects a search term next to its form token meets all three BREACH conditions.
- **ASP.NET Core's** compression middleware is off over HTTPS by default, "because of the security risk" ([Microsoft Learn](https://learn.microsoft.com/en-us/aspnet/core/performance/response-compression)).
- **Thruster**, the proxy Rails 8 generates in its Dockerfile, gzips by default with 32 bytes of random jitter. It offers `GZIP_COMPRESSION_DISABLE_ON_AUTH`, off by default, which skips requests carrying `Cookie`, `Authorization` or `X-Csrf-Token` ([Thruster README](https://github.com/basecamp/thruster/blob/main/README.md)). That is the closest precedent for a server-side credential guard.

nginx and Apache document the risk in one sentence each and leave it to the operator.

**A server can remove one ingredient precisely: the victim's credentials.** BREACH works only because the victim's browser attaches something the attacker cannot replay. That something is a cookie, HTTP Basic or Digest credentials it has cached, or a network position that an allow-list trusts. A response to a request that carried none of these holds nothing the attacker could not fetch himself in plaintext, so compressing it leaks nothing.

The same model shows what is not a risk. A bearer token that application JavaScript puts in `Authorization` is never attached by the browser on a forged cross-site request, so JSON APIs authenticated that way can be compressed. The model also shows something easy to miss: a page admitted by an IP allow-list is credentialed by address. An attacker outside the office can make a browser inside the office fetch it, cookies or not. An intranet site trusted only because of the network it sits on is the same case.

On the header side, agensio's HPACK and QPACK encoders insert only values the server chooses itself (server, date, content-type). They therefore hold neither secrets nor attacker input, and sit outside the CRIME model ([RFC 7541 7.1](https://www.rfc-editor.org/rfc/rfc7541#section-7.1)).

**Request bodies are the other attack surface, and they are about denial of service rather than secrecy.** A server need not decode them. It may answer 415, listing the codings it accepts in `Accept-Encoding` ([RFC 9110 12.5.3](https://www.rfc-editor.org/rfc/rfc9110#section-12.5.3)). A decoder must bound its output, not its input:

- deflate reaches about 1032:1 ([zlib technical details](https://zlib.net/zlib_tech.html));
- gzip's ISIZE field is modulo 2³² and chosen by the attacker ([RFC 1952](https://www.rfc-editor.org/rfc/rfc1952));
- stacked codings multiply;
- RFC 7932 and RFC 8878 tell decoders to check output size per block and enforce memory limits ([RFC 7932 12](https://www.rfc-editor.org/rfc/rfc7932#section-12), [RFC 8878 8](https://www.rfc-editor.org/rfc/rfc8878#section-8)).

The problem is current. Envoy fixed CVE-2026-48044 in July 2026, where the zstd decompressor checked its inflate ratio "only after each input slice was fully processed" ([Envoy 1.39 changelog](https://github.com/envoyproxy/envoy/blob/main/changelogs/1.39.0.yaml)), and a related report is still open ([envoy #47970](https://github.com/envoyproxy/envoy/issues/47970)).

On the response side, the denial-of-service risk is the CPU an attacker can trigger by requesting large compressible resources. RFC 7932 names incompressible input as an attack on a web server's compressor and suggests falling back to simpler algorithms under load.

## zstd 3 buys gzip-6 bytes for an eighth of the CPU, and windows set the memory bill

The numbers below were measured for this research on 2026-10-26. The setup was one pinned core of the Ryzen 9 9900X under Debian 13, running zlib 1.3.1, zlib-ng 2.3.3, libdeflate 1.23, brotli 1.1.0 and zstd 1.5.7. The corpus was 14 real files totalling 1.9 MB: HTML pages, GitHub API JSON, Bootstrap and Font Awesome CSS, and the jQuery, lodash, React and Vue bundles. Source and raw data are in [`cdn_browsers_cost_bench/`](<../research_notes/Web server response compression/cdn_browsers_cost_bench/speed.csv>). The gzip-5 row was computed from the same CSV.

| Encoder and level | Ratio | Size vs zlib gzip 6 | MB/s, one core | µs per 100 KB |
|---|---|---|---|---|
| zlib gzip 1 | 3.96 | +20.1 % | 249 | 412 |
| zlib gzip 4 | 4.51 | +5.3 % | 164 | 623 |
| zlib gzip 5 | 4.68 | +1.4 % | 123 | ~830 |
| zlib gzip 6 | 4.75 | 0 | 90 | 1,135 |
| zlib-ng 6 / libdeflate 6 | 4.72 / 4.75 | +0.7 % / −0.1 % | 167 / 209 | 612 / 490 |
| brotli 1 | 4.21 | +13.0 % | 628 | 163 |
| brotli 4 | 4.82 | −1.3 % | 173 | 590 |
| brotli 5 | 5.19 | −8.5 % | 113 | 909 |
| brotli 9 | 5.31 | −10.5 % | 43 | 2,398 |
| brotli 11 | 5.88 | −19.2 % | 1.5 | 68,300 |
| zstd 1 | 4.41 | +7.7 % | 1,029 | 100 |
| **zstd 3** | **4.65** | **+2.3 %** | **728** | **141** |
| zstd 6 | 5.00 | −5.0 % | 211 | 485 |
| zstd 12 | 5.17 | −8.1 % | 50 | 2,070 |
| zstd 19 | 5.38 | −11.6 % | 6.4 | 16,000 |

Three readings matter for a server.

**First, zstd 3 is the cheapest way to get gzip-6 bytes.** On HTML and JSON, zstd 3 is 1.8 % smaller than gzip 6. On a 35 KB Hacker News page it costs 25 µs, against 127 µs for zlib 6, 104 µs for brotli 4 and 155 µs for brotli 5. Only on minified CSS and JS does zstd 3 lose (+9.8 % and +5.0 %), and those are static files that should be compressed once anyway.

**Second, high levels have a large fixed cost per response.** Brotli 9 takes 715 µs for a 6 KB JSON document where brotli 4 takes 27 µs, because the higher levels allocate and clear tables in the tens of megabytes. Small dynamic answers should never use brotli 7 or above, or zstd 10 or above.

**Third, flushing hurts the fastest modes.** Flushed every 16 KB, brotli 1 grows its output by 24 %. zlib grows by 0.2-0.4 %, brotli 4-6 by about 1.3 % and zstd 3 by 0.9 %.

The published numbers agree with this ordering:

- In the HTTP Archive top 10,000, brotli 5 averages 8.85 % smaller than gzip 6 and brotli 11 19.18 % smaller, while about 30 % of gzip responses are estimated to run at level 1 ([Paul Calvano](https://paulcalvano.com/2024-03-19-choosing-between-gzip-brotli-and-zstandard-compression)).
- The zstd README's lzbench table puts zstd -1 at 510 MB/s against zlib -1 at 105 MB/s on the Silesia corpus ([zstd README](https://raw.githubusercontent.com/facebook/zstd/dev/README.md)).

| Encoder | Peak memory per stream, unknown size, default window | With a capped window | Output cost of the cap on a 1 MB stream |
|---|---|---|---|
| zlib 1.3.1, any level | 268 KB | — | — |
| zlib-ng 2.3.3 | 350 KB | — | — |
| zstd 3 | 3.66 MB (windowLog 21) | 2.09 MB (windowLog 19) | +0.5 % |
| zstd 6 | 5.50 MB | 3.93 MB (windowLog 19) | +0.3 % |
| brotli 4 | 9.3 MB (lgwin 22) | 1.39 MB (lgwin 18) | +0.4 % |
| brotli 5 | 9.8 MB | 1.95 MB (lgwin 18) | +0.8 % |
| brotli 11 | 43.9 MB | — | — |

Memory, not CPU, decides how many compressed streams a worker can carry. At 1,000 concurrent streamed responses:

- zlib needs about 0.27 GB;
- zstd 3 needs 3.7 GB at default parameters, or 2.1 GB with windowLog 19;
- brotli 5 needs 9.8 GB at its default window, or 1.95 GB with lgwin 18.

A response smaller than the window loses nothing to the cap. When the whole body is known, a size hint shrinks the tables further: zstd 3 needs 803 KB for a 100 KB response.

Context reuse is cheap. A zlib stream reset with `deflateReset` and a reused zstd context save almost nothing against fresh ones at these sizes. Brotli has no reset at all, but its encoder takes caller-supplied allocation functions ([brotli encode.h](https://github.com/google/brotli/blob/master/c/include/brotli/encode.h)), so a server can recycle the large blocks instead of mapping fresh ones per response. Two library defaults must be overridden in a server: brotli's own defaults are quality 11 and window 22, and zstd at level 17 and above defaults to windowLog 23, the RFC 9659 ceiling. Every server examined sets brotli lower (nginx 6 with a 19-bit window, Apache 5 with 18, Envoy 3 with 18), and Caddy caps the zstd window at 128 KiB, while Traefik keeps klauspost's 8 MiB default at the ceiling.

Packaging is not an obstacle. The libraries have these licences:

| Library | Licence |
|---|---|
| brotli | MIT |
| zstd | BSD-3 or GPL-2, at the user's choice |
| libdeflate | MIT |
| zlib | zlib licence |

The packaged `-dev` versions on agensio's target distributions are:

| Distribution | libbrotli-dev | libzstd-dev |
|---|---|---|
| Debian 12 | 1.0.9 | 1.5.4 |
| Debian 13 | 1.1.0 | 1.5.7 |
| Ubuntu 22.04 | 1.0.9 | 1.4.8 |
| Ubuntu 24.04 | 1.1.0 | 1.5.5 |
| Ubuntu 26.04 | 1.2.0 | 1.5.7 |

Sources: [Debian madison](https://qa.debian.org/madison.php?package=libbrotli-dev&text=on) and [Ubuntu madison](https://people.canonical.com/~ubuntu-archive/madison.cgi?package=libbrotli-dev&text=on).

zlib-ng is not packaged in Debian. libdeflate is packaged but "There is currently no support for streaming" ([libdeflate README](https://github.com/ebiggers/libdeflate/blob/master/README.md)), so it fits only bodies that are fully buffered.

**For agensio, compression would be the largest single cost in its own share of the request path.** agensio spends 1.9-2.0 µs on a plain 1 KB static request, 4.98 µs on a proxied JSON request, and 26-86 µs of its own on a Laravel request around roughly 2.2 ms of PHP ([CLAUDE.md](../CLAUDE.md)). Compressing a 35 KB page with zstd 3 adds about 25 µs. That is about 1 % of a PHP request but five times a proxied one. Brotli 5 adds about 155 µs, 7 % of the PHP request.

## Applications compress in the wrong layer more often than servers do

**PHP compresses nothing on a stock Debian php-fpm.** `zlib.output_compression` is Off in php.ini-production, which Debian installs unchanged ([PHP zlib configuration](https://www.php.net/manual/en/zlib.configuration.php), [Debian php8.4-fpm](https://packages.debian.org/trixie/php8.4-fpm)). Once an administrator, a `.user.ini` or a plugin turns it on, PHP misbehaves in several ways, observed in a local FastCGI test against PHP 8.4.26:

- It compresses every type and status. A 304 gets a 20-byte gzip body, an empty response is gzipped, and a random PNG grows from 3,000 to 3,023 bytes.
- It chooses gzip by substring, so `gzip;q=0, br` still gets gzip.
- It sends `Vary: Accept-Encoding` only on the compressed variant.
- It never checks for a `Content-Encoding` the script set itself, so a `gzencode`d body came out gzip inside gzip under a single header.
- Combined with php.ini-production's `output_buffering = 4096`, it held back an SSE loop's flushed events until the script ended.

The mechanisms are in the PHP source ([zlib.c](https://github.com/php/php-src/blob/master/ext/zlib/zlib.c), [SAPI.c](https://github.com/php/php-src/blob/master/main/SAPI.c)). A script that sets `Content-Length` silently turns compression off.

**WordPress core compresses nothing**; it removed PHP compression of its concatenated scripts in 2018 ([Trac changeset 43580](https://core.trac.wordpress.org/changeset/43580)). The caching plugins split three ways:

- **WP Super Cache** has compression off by default and refuses to compress when PHP's zlib layer is on ([WP Super Cache readme](https://github.com/Automattic/wp-super-cache/blob/trunk/readme.txt)).
- **W3 Total Cache 2.11** gzips cached HTML, CSS/JS and other files by default. When rewrite rules do not apply, it sends `Content-Encoding: gzip` from PHP, and it refuses to cache a response that is already compressed ([W3TC ConfigKeys](https://github.com/BoldGrid/w3-total-cache/blob/master/ConfigKeys.php), [PgCache_ContentGrabber](https://github.com/BoldGrid/w3-total-cache/blob/master/PgCache_ContentGrabber.php)).
- **WP Rocket** writes no configuration on nginx. Its PHP fallback serves its gzip cache file through `readgzfile()`, which decompresses it, so visitors get plain HTML ([WP Rocket class-cache.php](https://github.com/wp-media/wp-rocket/blob/develop/inc/classes/Buffer/class-cache.php)).

Behind a server that ignores `.htaccess`, a front server therefore sees both shapes from WordPress sites. It must pass the first through untouched, and it may compress the second.

The PHP frameworks and the Ruby and Python stacks mostly leave compression to the server:

- **Drupal 8+** removed page compression but writes `.gz` (level 9) and, when the PHP brotli extension is loaded, `.br` (level 11) beside every CSS and JS aggregate. Its `.htaccess` serves them ([AssetDumper.php](https://git.drupalcode.org/project/drupal/-/raw/11.x/core/lib/Drupal/Core/Asset/AssetDumper.php)). agensio's twin support already picks those up.
- **Laravel and Symfony** have no compression of their own. Laravel's `stream()` and `eventStream()` responses send `X-Accel-Buffering: no`. Symfony's `EventStreamResponse` adds `Incremental: ?1` and a hop-by-hop `Connection: keep-alive` ([ResponseFactory.php](https://github.com/laravel/framework/blob/12.x/src/Illuminate/Routing/ResponseFactory.php), [EventStreamResponse.php](https://github.com/symfony/symfony/blob/7.4/src/Symfony/Component/HttpFoundation/EventStreamResponse.php)).
- **Rails** has no `Rack::Deflater` in its default stack, and Puma does not compress. Rails 8's generated Dockerfile puts Thruster in front, and Thruster gzips. `ActionDispatch::Static` serves `.br` and `.gz` twins ([Rails on Rack](https://guides.rubyonrails.org/rails_on_rack.html), [static.rb](https://github.com/rails/rails/blob/main/actionpack/lib/action_dispatch/middleware/static.rb)).
- **Django's** GZipMiddleware is opt-in. **WhiteNoise** precompresses static files at `collectstatic` ([WhiteNoise](https://whitenoise.readthedocs.io/en/stable/django.html)). **Gunicorn** has no compression.

The Node ecosystem is where applications most often compress themselves by default:

- **Express's** `compression` middleware does br, gzip and deflate above 1 KB, honours `no-transform`, and needs `res.flush()` after each write for SSE ([Express compression](https://expressjs.com/en/resources/middleware/compression.html)).
- **Next.js** gzips everything under `next start`. Its docs tell users to set `compress: false` when nginx compresses ([Next.js compress](https://nextjs.org/docs/app/api-reference/config/next-config-js/compress)).
- **Ghost** enables compression by default ([Ghost defaults.json](https://github.com/TryGhost/Ghost/blob/main/ghost/core/shared/config/defaults.json)).
- **Grafana** turned `enable_gzip` on by default in 13.0, merged on 2026-03-24 ([Grafana PR 106093](https://github.com/grafana/grafana/pull/106093)).
- **Home Assistant** compresses JSON above 1 KB ([home-assistant helpers/http.py](https://github.com/home-assistant/core/blob/dev/homeassistant/helpers/http.py)).
- **Gitea** leaves `ENABLE_GZIP` off ([Gitea config](https://docs.gitea.com/administration/config-cheat-sheet)).

On the JVM and .NET, Tomcat refuses to compress a response that carries a strong ETag ([CompressionConfig.java](https://github.com/apache/tomcat/blob/main/java/org/apache/coyote/CompressionConfig.java)). Microsoft tells ASP.NET Core users to prefer IIS, Apache or nginx compression.

**Three rules for a front server follow from this survey.** First, the only reliable signal that a body is compressed is `Content-Encoding`. Express, Django and .NET 11 add `Vary` to uncompressed answers, while PHP leaves it off the identity answers it would have compressed for another client. Second, every framework middleware and every major server except PHP's zlib layer skips an already-encoded response, so the double compression administrators report happens inside PHP and its plugins, not across the proxy boundary. Third, applications ask for streaming with `X-Accel-Buffering: no`, `Incremental: ?1` and `Content-Type: text/event-stream`. None of the frameworks examined sends `no-transform` on SSE, so a server that relies on `no-transform` alone misses them all.

## Administrators ask why nothing was compressed, not how to tune it

Ranked by Stack Exchange votes and views, the problems that recur most are, in order:

1. "Compression is on but this is not compressed." "NGINX gzip not compressing JavaScript files" has a top answer of 177 votes ([SO 23939722](https://stackoverflow.com/questions/23939722/nginx-gzip-not-compressing-javascript-files)).
2. Verifying that compression works. "How to properly handle a gzipped page when using curl?" has 160,317 views ([SO 8364640](https://stackoverflow.com/questions/8364640/how-to-properly-handle-a-gzipped-page-when-using-curl)).
3. Decoding errors from double or false compression. ERR_CONTENT_DECODING_FAILED has 211,333 views ([SO 14039804](https://stackoverflow.com/questions/14039804/error-330-neterr-content-decoding-failed)).
4. `Vary`. "How to Specify Vary: Accept-Encoding header in .htaccess" has 171,560 views ([SO 3641197](https://stackoverflow.com/questions/3641197/how-to-specify-vary-accept-encoding-header-in-htaccess)).
5. Packaging brotli for nginx.

Each nginx default produced its own family of questions:

- `gzip_types text/html` missed JavaScript, JSON, fonts and SVG, and failed on `application/json;charset=utf-8`.
- `gzip_proxied off`, keyed on `Via`, silently stopped compression behind CDNs ([SF 730883](https://serverfault.com/questions/730883/nginx-reverse-proxy-gzip-to-client)).
- `gzip_min_length` is read only from `Content-Length`, so it never applied to streamed answers ([SO 33269448](https://stackoverflow.com/questions/33269448/why-is-the-gzip-minimum-length-directive-not-being-respected)).
- On brotli, the most-reacted complaint is a dynamic module that refuses to load after every nginx minor upgrade ("version 1022000 instead of 1022001") ([ngx_brotli #140](https://github.com/google/ngx_brotli/issues/140)).
- On Apache, the top answer still shows the runtime workaround that rewrites `If-None-Match` to win back the 304s the ETag suffix cost ([SO 896974](https://stackoverflow.com/questions/896974/apache-is-not-sending-304-response-if-mod-deflate-and-addoutputfilterbytype-is)).

Streaming is the most active subject of 2023-2026, and every proxy has broken it:

- Traefik's "Problem with text/event-stream when compress=true" (2017) was fixed in 2019 and broken again in v3; the second fix landed in February 2025 ([traefik #2576](https://github.com/traefik/traefik/issues/2576), [PR #11511](https://github.com/traefik/traefik/pull/11511)).
- Caddy held SSE headers back until the first event, so clients waited to connect ([caddy #6293](https://github.com/caddyserver/caddy/issues/6293)).
- A Traefik library update silently added zstd to the gzip path in 2026, and was reverted as a regression ([traefik PR #13533](https://github.com/traefik/traefik/pull/13533)).

Negotiation order is a public battleground. Caddy took gzip over zstd for Chrome's header ([caddy #6179](https://github.com/caddyserver/caddy/issues/6179)), and Traefik went back to "least resource-intensive first" after memory growth ([traefik PR #11641](https://github.com/traefik/traefik/pull/11641)). Compressing for a client that sent no `Accept-Encoding` broke curl even though RFC 9110 permits it ([traefik #9734](https://github.com/traefik/traefik/issues/9734)).

Site owners act on scanners rather than on headers. Lighthouse's "Enable text compression" audit drove much of the demand, and Lighthouse itself did not recognise zstd when Chrome 123 shipped it ([Lighthouse #15882](https://github.com/GoogleChrome/lighthouse/issues/15882), [Chrome for Developers](https://developer.chrome.com/docs/lighthouse/performance/uses-text-compression)). Hosting panels expose compression as an on/off switch plus free-text directives ([cPanel](https://docs.cpanel.net/cpanel/software/optimize-website/), [Plesk KB](https://support.plesk.com/hc/en-us/articles/12377854166935-How-to-enable-disable-gzip-compression-in-nginx-on-a-Plesk-server)). BREACH questions are fewer and lower-voted than "it does not compress" questions. The consistent answer is that static assets are safe and that "Disabling gzip compression for everything does not make much sense" ([Sec.SE 65625](https://security.stackexchange.com/questions/65625/current-state-of-breach-gzip-ssl-attack)).

Taken together, the complaints give a design checklist:

1. compression on by default, for a broad type list matched without parameters;
2. gzip, brotli and zstd built in, with nothing to rebuild;
3. negotiation by q-value, with a documented tie order;
4. a minimum length that also works for streamed answers;
5. `Vary` on every response that could have been compressed, merged with the application's own and never duplicated;
6. no compression of anything already encoded;
7. 304s that keep working;
8. a correct HEAD;
9. streams that are never delayed;
10. per-site and per-path off switches;
11. a way to ask "why was this URL not compressed?".

## A design for agensio: compress once, cheaply, and only what no credential unlocked

### Where agensio starts

agensio already does the hardest static part right. The cached static file path:

- chooses `name.br` or `name.gz` twins with RFC 9110 q rules, `*` and the `x-gzip` alias, and gives br the tie ([`src/handlers/encoding.hpp`](../src/handlers/encoding.hpp));
- gives each twin its own strong ETag, built from the twin's own mtime and size;
- puts `Vary: Accept-Encoding` on both the file and its twins;
- serves byte ranges and 304s of the chosen twin, with `Vary` repeated ([`src/cache.hpp`](../src/cache.hpp), [`src/handlers/static.cpp`](../src/handlers/static.cpp)).

That is Caddy's correct model, applied to files. Two limits apply: twins exist only for memory entries, and only when a build has put them on disk.

zlib is an optional dependency today, used only by the site-install extractor ([`CMakeLists.txt`](../CMakeLists.txt)). FastCGI and proxy answers are buffered in memory up to 1 MB by default and spilled to a temp file beyond that, or streamed with `buffering = false` ([`src/upstream/options.hpp`](../src/upstream/options.hpp)). A search of `src/` finds no handling of `X-Accel-Buffering`, `text/event-stream` or `Incremental`. The roadmap's decision 5 says on-the-fly compression is "off by default", per site or location, with its cost measured ([`docs/ROADMAP.md`](../docs/ROADMAP.md)). The evidence above supports a different split: on by default for everything no credential unlocked, and the user's explicit choice for the rest.

### What to compress by default

| Decision | Recommendation | Evidence |
|---|---|---|
| Static files from the cache | On. Files without twins get variants made once at fill, on a background thread, and served exactly like twins. | No secret; CPU paid once; IIS and LiteSpeed compress static files once |
| Dynamic answers (FastCGI, proxy, CGI) | Site mode `auto`: compress unless the request carried an ambient credential (see the BREACH choices below) | BREACH needs the victim's credentials; LiteSpeed compresses dynamic output by default |
| Types | A `compressible` column in the built-in MIME table, matched on the media type without parameters (see the list after this table); a missing Content-Type is never compressed | Caddy's and Cloudflare's lists; the nginx `;charset` trap; HAProxy and ASP.NET skip untyped answers |
| Minimum size | 1,024 bytes of identity body: exact for buffered answers, judged after the first read for streamed ones | Traefik, Express, Fastify, Home Assistant, CloudFront (1,000) |
| Statuses | Any status that carries content except 206. HEAD gets the GET's headers without a body. 1xx, 204 and 304 never carry a coding. | RFC 9110 12.1 covers error content; Caddy |
| HTTP/1.0 | Only when the coded length is known before the head, else identity | No chunked framing in HTTP/1.0; nginx and IIS skip HTTP/1.0 |
| No `Accept-Encoding` | Identity | Every server checked; [traefik #9734](https://github.com/traefik/traefik/issues/9734) |
| Never | 101 tunnels, CONNECT, WebSocket handshakes, `Content-Range` answers, anything already encoded | All servers |

Compressible types:

- `text/*`, except `text/event-stream`;
- JavaScript;
- JSON and `+json`;
- XML and `+xml`;
- XHTML;
- SVG and ICO;
- wasm;
- TTF, OTF and EOT;
- web manifests.

Never compressible: images other than SVG and ICO, audio, video, archives, WOFF and WOFF2, and `application/octet-stream`.

### Encodings, levels, windows and libraries

| Setting | On-the-fly (dynamic) | Made once at cache fill (static) |
|---|---|---|
| Order at equal q | zstd > br > gzip | br > gzip (and a `.zst` twin if one is on disk) |
| zstd | level 3, windowLog 19 (never above 23), pledged size when known | none: every zstd browser also takes br |
| brotli | quality 4, lgwin 18, size hint when known, encoder memory from a per-worker allocator | quality 11 (lower for files of several MB), on a background thread |
| gzip | zlib level 5, window 15 | zlib level 9 |
| Size ceiling | none for buffered or streamed answers, processed in 64 KB steps | about 8 MiB per file; above that, identity or the on-disk twin |
| Budget | a per-worker cap on in-flight streaming contexts and their memory; over the cap, identity with `Vary` intact | a bounded fill queue; when it is full, the file is served without a variant until the next fill |

The two orders differ on purpose, because the right choice depends on when the CPU is spent. A static variant is paid for once, so the order maximises bytes saved: brotli 11 is 19 % smaller than gzip 6, and zstd 19 only 12 %. A dynamic answer is paid for on every request, so the order minimises CPU. Every browser that takes zstd also takes br over HTTPS, so zstd first is purely a cost choice: about 25 µs instead of about 104 µs for a 35 KB page, at a 1-8 % size penalty on HTML.

The levels can be adjusted for particular deployments:

- **Behind Cloudflare,** a site should raise brotli to 5. Cloudflare asks for `br, gzip` and passes the origin's brotli on to visitors.
- **For fewer bytes at moderate cost,** zstd 6 reaches brotli 4's size on HTML at slightly better speed.

Gzip at level 5 costs 1.4 % more bytes than level 6 for 27 % less CPU. Gzip mostly serves tools and API clients.

In a 64 KB step, the worst default costs about 0.5 ms (zlib 5) and zstd 3 under 0.1 ms. So compression can run on the worker between writes, under the yield budget that already governs memory bodies, without a thread pool. The step model has two cases:

- **A body of at most 64 KB** (most HTML and JSON) is compressed whole, in a context the worker reuses, and goes out with an exact `Content-Length`.
- **A larger buffered body, a spilled body or a stream** is compressed as the writer pulls from it. This keeps HTTP/2 and HTTP/3 backpressure intact: a slow client holds one compressed piece and one context, never a whole compressed body.

Libraries: link the system's **libbrotlienc and libzstd**, each optional at build time like zlib. The justification line for CLAUDE.md is that brotli and zstd are what 97 % and 83 % of browsers accept, are packaged on every target distribution, and carry MIT and BSD licences. A build without a library simply does not offer that coding, and status shows the codings the binary has. Do not add libdeflate or zlib-ng now: gzip is the fallback coding, and the access log will show whether its share justifies a faster encoder. Set every level and window explicitly, so that a library upgrade never changes what agensio sends, the lesson of the Traefik regression.

### Responses the application already compressed, and streaming

Pass through any answer that carries a `Content-Encoding` other than `identity`, unchanged, as every server and CDN does. Merge `Vary: Accept-Encoding` into it, because PHP's zlib layer leaves `Vary` off the identity variant. Treat `Content-Encoding: identity` as the application's opt-out, the nginx convention ([SO 41086260](https://stackoverflow.com/questions/41086260/how-can-i-disable-nginx-gzip-from-php)), and drop the field itself, since RFC 9110 says it SHOULD NOT be sent.

Never decode an upstream body. On an upstream 304 or 204, drop `Content-Encoding` along with the body PHP may have put there.

Keep forwarding the client's `Accept-Encoding` by default. Offer a per-site `offload` setting that removes it, as Envoy's `remove_accept_encoding_header` and HAProxy's `offload` do. With `offload`, the application never compresses, and agensio applies zstd or br and its own credential guard. HAProxy's documentation warns against offload in general, because it moves CPU to the proxy. For a Next.js, Ghost, Grafana 13 or Express application that sends gzip only, offload upgrades browsers to zstd or br. For a PHP site with `zlib.output_compression` on, it is the only way agensio's credential guard can protect logged-in pages, because PHP otherwise compresses them before agensio sees them. Health should recommend it, or the application's own switch, by name.

For streams, compress every eligible type except `text/event-stream` by default. Flush the compressor at the end of each upstream read that empties the socket (zstd `ZSTD_e_flush`, brotli `BROTLI_OPERATION_FLUSH`, zlib `Z_SYNC_FLUSH`). When an answer carries `X-Accel-Buffering: no`, `Incremental: ?1` or `text/event-stream`, send the head at once rather than waiting for the minimum-size decision.

Leave SSE uncompressed unless the site opts in. Two reasons support that default. A long-lived event stream would hold a 1-2 MB compression context for hours. And event streams of authenticated applications are exactly where secrets and reflected input meet. Traefik reached the same default after fixing SSE twice.

Separately, agensio should start honouring `X-Accel-Buffering: no` and `text/event-stream` by switching a buffered FastCGI or proxy exchange to streaming when the head arrives. Laravel, Symfony and Next.js send these headers, while agensio's cookbook today asks for `buffering = false` per location ([`docs/examples/php.md`](../docs/examples/php.md)).

### Validators, Vary, Range, HEAD, 304 and no-transform

The design applies these rules to each kind of response:

- **Variants made at cache fill** get a strong ETag of their own. It is formed from the file's tag, the coding and a 64-bit hash of the compressed bytes, computed once at fill. The variant then serves ranges, HEAD and 304 through the same code as an on-disk twin, and a library or level change shows up as a new tag. This is the strong-validator rule kept honestly.
- **Dynamic answers compressed on the fly** get a weak ETag: a strong upstream tag becomes `W/"…"`, as nginx, h2o, HAProxy, Django and CloudFront do. Streamed output depends on flush timing and cannot honestly carry a strong tag. Weakness costs nothing here, because agensio never serves ranges of upstream answers.
- **Revalidation with weak tags.** RFC 9110 13.1.2 requires weak comparison for `If-None-Match`, so a correct application matches the weak tag ([RFC 9110 13.1.2](https://www.rfc-editor.org/rfc/rfc9110#section-13.1.2)). Some applications compare strings exactly. For them, agensio can append the strong form `"x"` beside each `W/"x"` it forwards in `If-None-Match`. That changes no RFC-correct outcome, and it is the Apache community's workaround done systematically. On the application's 304, mirror the form the client sent. Treat this as agensio's own design, to be tested with the presets' applications.
- **Vary.** Add `Accept-Encoding` to every answer that passed the type, status and size tests, compressed or not, the 304s of a compressing location included. Merge it into the application's single `Vary` field. Leave `Vary: *` alone, and never add `Vary` to answers that could never be compressed.
- **Range.** Never compress a 206. When agensio compresses a 200, drop the application's `Accept-Ranges`. A Range request that the application answers with a 200 is compressed like any other 200.
- **HEAD.** Run the GET's negotiation. Send `Content-Encoding` and `Vary`, weaken the ETag, and drop `Content-Length`, never sending the length of an empty encoded stream. For static variants, send their exact length.
- **no-transform.** Honour it in the response for upstream answers, as RFC 9111 5.2.2.6 reads for gateways, and in the request too, as Caddy does at no cost.
- **Representation fields.** Drop any digest field that describes the identity bytes, as Apache and ASP.NET drop `Content-MD5`.
- **Content-Length.** Never copy the identity block's `Content-Length` into an HTTP/2 or HTTP/3 head.

### The BREACH choices

The `auto` mode is defined by the attack's own model: compress a dynamic answer only if the attacker could have fetched the same bytes himself. `auto` therefore skips a dynamic answer when any of these holds:

- the request carries a cookie the site counts as a session credential;
- the request carries `Authorization` with a scheme browsers replay on their own (Basic, Digest, Negotiate);
- the path is covered by agensio's own `[[site.auth]]`;
- the request was admitted by an address rule of `[[site.access]]` other than `any`.

Session cookies are recognised in three ways: a per-preset table of the applications' cookie names, a site-supplied list, and a conservative fallback for generic sites. The fallback counts any cookie whose name contains `sess`, `auth`, `token`, `login` or `logged`. The table is agensio's own construction, like its login paths for fail2ban, and needs checking against each application.

The guard deliberately does not count every cookie, because consent banners and analytics put a first-party cookie on almost every returning visitor, and those cookies unlock nothing. Bearer-token APIs are compressed, because no browser attaches a script's token to a forged request. Whether a site that listens only on private addresses should count as credentialed by network position is a choice for review: it would turn compression off for most intranet sites. The cost is concentrated where the risk is. Laravel's web pages carry `laravel_session` after the first visit and lose compression, which is the right outcome for an unmasked token. Logged-in WordPress and Drupal pages lose it too; WordPress's nonces were not examined, so those pages should be treated as unmasked.

The decision costs one scan of the request's `Cookie` and `Authorization` fields. It runs only when an answer is otherwise eligible, against tens to hundreds of microseconds of compression. The cache guards already read `Authorization` and the answer's cookies for a related purpose ([`src/core/private_cache.hpp`](../src/core/private_cache.hpp)). `Vary` stays `Accept-Encoding` alone, because the cookie decides only whether agensio compresses, never which content is sent.

Four modes cover what a site needs:

| Mode | Behaviour |
|---|---|
| `off` | No compression made by agensio; on-disk twins are still served |
| `static` | Files only |
| `auto` | The default for every site |
| `all` | Compresses credentialed answers too; set only on the user's explicit agreement after the agent explains BREACH |

`all` suits sites whose framework masks its tokens and whose pages reflect no input, such as Django and Rails. It adds up to 32 random bytes per answer, as Thruster does (Django adds up to 100). Padding is cheap, and the honest description is that it raises the attack's cost rather than removing the risk. A list of paths where compression is off, for example `/my-account/`, covers the remaining cases. The application can always opt out with the standard `Cache-Control: no-transform`, which Cloudflare honours too, so no new header is needed.

On request bodies, keep today's behaviour: agensio decodes nothing, passes `Content-Encoding` to the application, and applies `max_body_size` to the compressed bytes. The control socket consumes bodies itself, so check that it refuses a compressed body with 415 and `Accept-Encoding: identity`. If decoding is ever added, follow Apache's model:

- a limit on decoded bytes;
- a streaming ratio check (200, with a burst of 3) inside each input slice, the lesson of the Envoy CVE;
- one coding layer only;
- window limits of 8 MB for zstd and 16 MiB for brotli;
- a fuzz target.

### Configuration an agent can drive

Typed fields replace the free-text directives panels expose. Per the repository's rules, each key needs its reference row, its cookbook recipe and its MCP text. The levels are rare keys and stay restart-only, while the site mode applies on reload through the generation. A sketch for review:

```toml
[response_compression]              # root, restart: codings, levels, windows, budgets
prefer   = ["zstd", "br", "gzip"]   # equal-q order for on-the-fly answers
zstd     = 3                        # windowLog 19
br       = 4                        # lgwin 18
gzip     = 5
min_size = 1024
static   = { br = 11, gzip = 9, max_size = "8M" }
streams_per_worker = 64             # over it: identity, Vary kept

[[site]]
server_name = ["shop.example"]
app = "wordpress"
response_compression = { mode = "auto", off = ["/my-account/", "/checkout/"],
                         session_cookies = ["shop_sid"], upstream = "pass",
                         event_streams = false }
```

The agent needs more than the setting:

- **`path_check`** should answer, for a path, an `Accept-Encoding` and a choice of anonymous or credentialed visitor, which coding agensio would apply and why not otherwise. The possible reasons are: type, size, status, credential guard, already encoded, `no-transform` or budget. Envoy's `x-envoy-compression-status` values show such a list is practical ([Envoy compressor filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/compressor_filter)).
- **`health_check`** should probe each live site's home page, as the header probes already do, with `Accept-Encoding: zstd, br, gzip`. It should report:
  - the application compressing itself, naming the switch: `compress: false` in Next.js, `"compress": false` in Ghost, `enable_gzip = false` in Grafana, `zlib.output_compression` in a pool or `.user.ini`;
  - a PHP 304 or image that arrived with a coding;
  - a page served as identity, with the reason;
  - the streaming budget exhausted;
  - `all` set on a preset whose framework does not mask tokens.
- **`server_status`** and the JSON access log should carry the coding applied and the identity size. Counters per coding and per skip reason are per-worker integers with no locks.

The MCP texts must tell the agent that `all` is a security decision the user makes. They must also say that turning compression off inside an application is the application's switch, not agensio's.

### How to verify it works

The integration suite should decode every coding with the reference command-line tools and compare the result byte for byte with the identity body. It should then cover each rule:

- HEAD headers match the GET's;
- `Vary` appears on identity and on 304 answers;
- a weak ETag gets a 304 back from both a weak-comparing application and an exact-comparing one;
- Range on a compressible dynamic page is answered with an identity 206 or a full 200, never a compressed 206;
- `no-transform` is honoured both ways;
- an upstream gzip passes through untouched;
- PHP's zlib layer turned on is detected by health;
- the credential guard sees each cookie, `Authorization` and address case;
- an HTTP/1.0 request gets identity when the length is unknown;
- the first SSE event arrives at once and events keep their spacing;
- the static variants' ranges and tags behave like twins.

h2spec and the HTTP/3 attack suite must still pass. The `Accept-Encoding` parser, extended for zstd, and the media-type matcher each get a fuzz target. A sanitizer build should run under compressed HTTP/2 load, since every inline loop needs its yield budget. Browsers and clients cover what the suite cannot:

- Chrome, Firefox, Safari on 26.3 and an older Safari;
- curl with `--compressed`;
- python-requests and Node `fetch`;
- REDbot, which Caddy cites for `Vary` behaviour ([Caddy staticfiles.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/fileserver/staticfiles.go)).

### What to measure before and after

| Measurement | How | Pass condition |
|---|---|---|
| Static rows with compression built in | `bench/ab.sh <base>`; wrk sends no `Accept-Encoding` | within the 3 % noise band |
| Static rows as a browser asks | new rows with `Accept-Encoding: gzip, deflate, br, zstd` on 1 KB (below the minimum) and 100 KB CSS (fill variant) | 1 KB flat; 100 KB equal to the existing twin row |
| PHP pages | `bench/laravel/bench.sh` and the WordPress bed: off, zstd 3, br 4, gzip 5 | agensio µs per request, php-fpm µs, bytes per response, p50 and p99 recorded |
| Proxy rows | `bench/ab.sh <base> -P` with the header; JSON and 100 KB bodies | the extra µs matches the encoder table; no change in syscalls per request |
| HTTP/2 and HTTP/3 | `-2` and `-3 -r 3` with the header | single-stream and multi-stream rows recorded per coding |
| Memory | 1,000 slow clients reading compressed streamed answers (`bench/h2/memory.sh` style) | RSS per stream ≈ the window budget; the cap holds |
| Streams | time to first SSE event and spacing between events, compression on | no added delay |
| Cache fill | CPU and queue depth compressing a real site's assets at start | worker latency unchanged during fill |
| Decision cost | ineligible answers (images, small bodies) with the header | invisible in µs per request |

Every run's raw output goes under `bench/results/` with the machine, commit and command, as the project requires. The first measurements should then be checked against the test VPS's real access logs. The new coding field will show the share of zstd, br and gzip, and the bytes saved, for actual visitors.

## Conclusion

The research changes the question. Compression is no longer an algorithm choice: zstd, brotli and gzip each have a clear place once CPU per request and memory per stream are measured. The real variables are when the CPU is spent and who holds the secret. Spending it once at cache fill makes brotli 11 cost nothing per request and argues for br first on static files. Spending it per request makes zstd 3 the default for dynamic answers. Asking whether the browser attached a credential turns BREACH from an argument for keeping compression off into a rule that a server can evaluate in microseconds. agensio is placed to apply it better than most servers: its own `[[site.access]]` address rules and `[[site.auth]]` passwords are ambient credentials that no other server's compressor takes into account.

The second shift is about layers. The breakage administrators fear most comes from applications and their plugins compressing in the wrong place, PHP's zlib layer above all. A server cannot fix that by compressing better. It can only see the problem and say so, which is the job the MCP-driven control plane is built for. Three things remain open and should be tested before the defaults ship:

- the session-cookie table for each preset;
- the behaviour of WordPress nonces and Laravel pages under the guard;
- how the four modes read to an agent explaining them to a user who has never heard of BREACH.
