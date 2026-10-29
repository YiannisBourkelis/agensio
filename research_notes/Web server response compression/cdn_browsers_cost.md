# CDNs, browsers and the measured cost of gzip, brotli and zstd for on-the-fly compression

Researched 2026-10-26. Web pages fetched that day unless a date is given. "Measured locally" means the
benchmark run for these notes on 2026-10-26 (method in the "Measured costs" section). Its source, raw CSVs and
the corpus checksums are in
`/home/yiannis/projects/agensio/research_notes/Web server response compression/cdn_browsers_cost_bench/`
(`cbench.c`, `zng_part.c`, `speed.csv`, `mem.csv`, `memwin.csv`, `corpus_files.txt`, `corpus.sha256`).

## 1. Cloudflare: what it compresses to visitors, what it asks of the origin

### Takeaway
Cloudflare sends gzip, brotli or zstd to visitors, but always asks the origin for `accept-encoding: br, gzip`. It
passes an origin's br or gzip through when the visitor accepts it, and decompresses and recompresses when one of
its content-rewriting features is on. An origin's zstd is not accepted (the Sept 2024 plan for end-to-end zstd in
2025 is not in the April 2026 docs). `Cache-Control: no-transform` at the origin stops Cloudflare compressing.
About 71 % of the text responses Cloudflare gets from origins arrive uncompressed (2026).

### Cited Findings
- Visitor-side encodings are gzip, brotli and Zstandard. zstd is enabled through Compression Rules. The default
  by plan is Free: Zstandard, Pro and Business: Brotli, Enterprise: Gzip. Page last updated 2026-04-17. — [Cloudflare docs, Content compression](https://developers.cloudflare.com/speed/optimization/content/compression/)
- To the origin, on all plans, Cloudflare sends `accept-encoding: br, gzip`. The docs warn that this is not the
  visitor's header. — [Cloudflare docs](https://developers.cloudflare.com/speed/optimization/content/compression/)
- If the origin answers with brotli or gzip (`content-encoding` set) and the visitor supports it, Cloudflare keeps
  that encoding end to end. It can also convert between compressed and uncompressed "independently of caching". — [Cloudflare docs](https://developers.cloudflare.com/speed/optimization/content/compression/)
- These features force recompression: Automatic HTTPS Rewrites, Cloudflare Fonts, Email Address Obfuscation,
  Polish, Rocket Loader, JavaScript detections, RUM, and "Replace insecure JS libraries". The last cannot be
  turned off with Configuration Rules. — [Cloudflare docs](https://developers.cloudflare.com/speed/optimization/content/compression/)
- Compressed types: text (HTML, CSS, plain text, XML, RSS, SVG), JavaScript, JSON (including JSON-LD, GraphQL,
  GeoJSON), protobuf, WebAssembly, web app manifests, icons, multipart, fonts (TTF, OTF, WOFF, EOT…). — [Cloudflare docs](https://developers.cloudflare.com/speed/optimization/content/compression/)
- Status codes: success responses are compressed only for 200, errors only for 403 and 404. Minimum size: gzip
  48 bytes, brotli and zstd 50 bytes. — [Cloudflare docs](https://developers.cloudflare.com/speed/optimization/content/compression/)
- `Cache-Control: no-transform` set by the origin keeps the origin's `Content-Length` (Cloudflare may otherwise drop
  it when it compresses) and stops brotli or gzip being applied for visitors. Client requests cannot set it. — [Cloudflare docs](https://developers.cloudflare.com/speed/optimization/content/compression/)
- Blog of 2024-09-25: zstd was rolled out between Cloudflare and browsers at "Zstandard's default compression level of 3
  (out of 22)". Higher levels and multithreading were planned for Q4 2024. Origins could send only "GZIP and
  Brotli (since 2023)", and "full end-to-end support for Zstandard" was planned "in 2025". — [Cloudflare blog, New standards](https://blog.cloudflare.com/new-standards/)
- The same post measured over 24 hours in Q3 2024, switching Free-plan traffic from brotli to zstd ("billions of
  requests", HTML, CSS, JS and others). Average time to compress: zstd 0.848 ms, brotli 1.544 ms, gzip 0.872 ms.
  Average ratio: gzip 2.56, zstd 2.86, brotli 3.08. The headline claim is zstd "42 % faster than Brotli" and
  11.3 % better than gzip. The post does not give the brotli quality or gzip level used. — [Cloudflare blog](https://blog.cloudflare.com/new-standards/)
- The same post says zlib/gzip uses a 32 KB sliding window, and zstd "typically uses much less [than its maximum],
  around 1 MB at lower compression levels". Compression Rules limits: Free 10, Pro 25, Business 50,
  Enterprise 125. — [Cloudflare blog](https://blog.cloudflare.com/new-standards/)
- Blog of 2026-09-01 (Cache Transcoding prototype): "Cloudflare traditionally stores an asset using the content
  encoding supplied by its origin". Of the HTML/JSON/CSS/JavaScript slice (67.3 % of requests, 22.3 % of bytes),
  "approximately 71% arrived uncompressed with Content-Encoding unset". The prototype stores text in cache as zstd
  level 3: ratio 2.834x, encode 4.31 ns/byte (about 232 MB/s), decode 1.56 ns/byte (about 641 MB/s), assets
  about a third of their size on disk. Eligibility needs a 200, no Content-Encoding, and a known Content-Length of
  at least 4 KiB. — [Cloudflare blog, Cache transcoding](https://blog.cloudflare.com/cache-transcoding/)
- The Web Almanac 2025 CDN chapter puts zstd at 15 % of Cloudflare's compressed responses and 10 % of Google
  CDN's. Brotli is "prevalent on Cloudflare and Google". Published 2026-01-15. — [Web Almanac 2025, CDN](https://almanac.httparchive.org/en/2025/cdn)

### Inferences
- Behind Cloudflare, an origin's br or gzip is what the visitor gets (unless a rewriting feature is on), so the
  origin's choice of level is the visitor's. zstd from the origin is never used, because Cloudflare does not ask
  for it.
- Most origins behind Cloudflare send text uncompressed (71 %), and Cloudflare compresses it at the edge. An
  origin behind Cloudflare saves only origin-to-edge bandwidth by compressing, unless it sends br at a better
  level than Cloudflare's.
- A server meant to sit behind Cloudflare benefits most from br and gzip. zstd matters only for direct clients.

### Gaps
- The brotli quality and gzip level Cloudflare uses for on-the-fly compression to visitors are not stated in the
  docs or the 2024 post.
- I found no Cloudflare changelog entry saying origin zstd shipped in 2025. The 2026-04-17 docs still say
  `br, gzip` to the origin, so it most likely has not.
- Whether Cloudflare sends `Vary: Accept-Encoding` itself, and how it keys variants in cache, is not documented
  on the page read.

## 2. Fastly, Amazon CloudFront, Akamai, Bunny

### Takeaway
CloudFront and Fastly compress at the edge with gzip and brotli only (no zstd). Both normalise Accept-Encoding to
a few values for the cache key. Neither recompresses a response the origin already encoded. CloudFront compresses
only 1,000 to 10,000,000 bytes with a Content-Length. Fastly asks the origin for `Vary: Accept-Encoding`. Akamai's
Brotli Support only caches the origin's brotli. Edge compression there is a separate Ion feature. Bunny compresses
with gzip, br or zstd. Gzip is still the majority encoding on Akamai, CloudFront and Fastly (Web Almanac 2024 and
2025).

### Cited Findings
**Amazon CloudFront** (docs read 2026-10-26)
- Compresses with Gzip and Brotli when "Compress objects automatically" is on and the cache policy enables both.
  When the viewer supports both, "CloudFront uses Brotli". — [AWS CloudFront, Serve compressed files](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html)
- "CloudFront compresses objects that are between 1,000 bytes and 10,000,000 bytes in size." The origin "must
  include a Content-Length header". Without it, or outside the range, nothing is compressed. — [AWS docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html)
- Compresses only status 200, 403 and 404. HTTP/1.0 requests have Accept-Encoding removed and are not compressed. — [AWS docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html)
- Cache key and origin request: when compression is configured, CloudFront "includes the Accept-Encoding header in
  the cache key and in origin requests automatically". Values other than gzip and br, "such as deflate", are removed
  before forwarding to the origin. — [AWS docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html)
- If the origin's response has `Content-Encoding` (any value), CloudFront "doesn't compress the object, regardless of
  the header's value", serves it and caches it. — [AWS docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html)
- Compression is "best-effort": under high load CloudFront may skip it and then caches and serves the uncompressed
  object until it expires. Once a gzip copy is cached, later requests get that gzip version even from viewers that
  accept brotli. — [AWS docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html)
- A strong origin ETag becomes weak (`W/` prefixed) when CloudFront compresses. An invalid ETag is removed. — [AWS docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html)
- The docs say "Chrome and Firefox web browsers support Brotli compression only when the request is sent using
  HTTPS." — [AWS docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html)
- Content types: an explicit list, including text/html, text/css, text/javascript, application/javascript,
  application/json, application/xml, image/svg+xml, application/wasm, fonts, text/plain, text/csv. — [AWS docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html)
- The Web Almanac 2025 says Amazon CloudFront (and Automattic) "do not natively support Zstandard". — [Web Almanac 2025, CDN](https://almanac.httparchive.org/en/2025/cdn)

**Fastly**
- Static (edge) compression uses "either Brotli or gzip". Dynamic compression "compresses content just before
  responses are delivered" and is enabled through VCL or the `X-Compress-Hint` header. "Compression is only supported
  for content served uncompressed from your origin." Not compatible with Segmented Caching. No zstd is mentioned.
  No size limits or levels are stated. — [Fastly, Enabling automatic compression](https://www.fastly.com/documentation/guides/full-site-delivery/performance/enabling-automatic-compression)
- Accept-Encoding normalisation before `vcl_recv`: the original is copied to `Fastly-Orig-Accept-Encoding`. The
  header is removed for user agents with known problems. Otherwise it becomes `gzip` if gzip is present, else
  `deflate`, else it is removed. With brotli enabled, a header containing `br` becomes `br`. — [Fastly, Accept-Encoding reference](https://www.fastly.com/documentation/reference/http/http-headers/Accept-Encoding/)
- The origin "should include `Vary: Accept-Encoding` in all responses where compression was considered", whether or
  not it compressed. Cached responses are matched only to requests with the same (normalised) value. The origin sees
  the normalised value unless VCL restores `Fastly-Orig-Accept-Encoding`. — [Fastly reference](https://www.fastly.com/documentation/reference/http/http-headers/Accept-Encoding/)

**Akamai**
- Brotli Support "doesn't compress resources within the Akamai CDN in real-time". It caches and serves brotli that
  "you need to set up ... separately on your origin server". The page also says "Brotli supports only the
  compression level 6". If a gzip copy is cached, a brotli-capable client gets gzip until that copy's TTL expires.
  Edge compression needs Adaptive Acceleration (Ion), which "offers several forms of compression, including
  Brotli". Page updated 2026-05-21. No zstd mention. — [Akamai TechDocs, Brotli Support](https://techdocs.akamai.com/property-mgr/docs/brotli-support)

**Bunny**
- "automatically compresses content using gzip, Brotli (br), or Zstandard (zstd)" by the request's Accept-Encoding.
  Compression is guaranteed for a MIME list and for `.css`, `.js`, `.json`, `.xml`, `.svg`, `.html` even with a
  missing or wrong Content-Type. No size limits or origin behaviour are stated. — [bunny.net docs, MIME compression](https://bunny.net/docs/cdn/frequently-asked-questions/mime-compression)

**Shares by CDN and origin (HTTP Archive)**
- 2024 (mobile, Figure 17.9). CDN: brotli 55.89 %, gzip 41.38 %, zstd 2.72 %. Origin: brotli 41.83 %, gzip 57.40 %,
  zstd 0.70 %. CDN brotli rose from 47 % in 2022 and origin brotli from 25 %. Gzip is the majority on Akamai,
  CloudFront and Fastly. Facebook served zstd for over 60 %. Published 2024-11-11. — [Web Almanac 2024, CDN](https://almanac.httparchive.org/en/2024/cdn)
- 2025 (mobile, Figure 15.15). CDN: brotli 46 %, gzip 42 %, zstd 12 %. Origin: brotli 39 %, gzip 61 %. CDN zstd went
  from 3 % (2024) to 12 % (2025). Published 2026-01-15. — [Web Almanac 2025, CDN](https://almanac.httparchive.org/en/2025/cdn)
- 2024 Page Weight chapter (Lighthouse audit): 70-72 % of pages correctly compress text (desktop home 70 %, mobile
  home 71 %), down from 74 % (desktop) and 73 % (mobile) in 2022. — [Web Almanac 2024, Page Weight](https://almanac.httparchive.org/en/2024/page-weight)

### Inferences
- Every CDN here passes an origin's existing `Content-Encoding` through untouched (CloudFront and Fastly explicitly,
  Cloudflare for br and gzip, Akamai by design). An origin that compresses therefore decides the bytes visitors get,
  and an origin that compresses badly (gzip 1) makes the edge serve worse output than if it had sent identity.
- CloudFront needs `Content-Length` to compress. A dynamic origin answering with chunked encoding behind CloudFront
  gets no edge compression, so origin-side compression matters more there.
- `Vary: Accept-Encoding` on every compressible response (compressed or not) is what Fastly asks for. CloudFront
  adds the header to its key by itself. Sending it is the safe default for any origin.
- zstd from an origin is useful only toward direct clients and Bunny. None of Cloudflare's origin pull, CloudFront,
  Fastly or Akamai (per the pages read) request it.

### Gaps
- Fastly: no doc page read mentions zstd or a size limit. A Fastly zstd announcement, if any, was not found.
- Akamai: a search summary claimed that Adaptive Acceleration edge compression lists zstd as "experimental and
  disabled by default", but I did not find the Akamai page saying so. Unverified.
- Bunny: the levels, size limits and origin pass-through behaviour are not documented on the page read.
- Per-CDN exact percentages (Figure 17.10 / 15.x) are only in the charts.

## 3. Browser support in 2026 and the Accept-Encoding each client sends

### Takeaway
Brotli is accepted by about 97 % of browsers (over HTTPS only in Chrome and Firefox). zstd is in Chrome and Edge
since 123 (March 2024), Firefox since 126, Safari since 26.3 (February 2026), but in Safari only on OS 26.3 or
later. Samsung Internet does not support it. caniuse counts 83 % full plus 2.5 % partial zstd support (data of
2026-10-22). Chromium caps the zstd window at 8 MB, which RFC 9659 made a MUST for the `zstd` coding. Command-line
and library clients mostly send gzip/deflate or nothing.

### Cited Findings
- zstd content-encoding (caniuse data, last updated 2026-10-22): Chrome 123+, Edge 123+, Opera 109+, Firefox 126+.
  Chrome for Android and Firefox for Android are supported in their current versions. Safari 26.0-26.2 is partial
  (note 2: "supporting Zstandard, but not requesting it"). Safari on macOS 26.3+ is partial (note 3: "Requires macOS
  26.3 Tahoe or later"). iOS Safari 26.3+ is full. Samsung Internet 28-30: no. Global usage 83.13 % full + 2.47 %
  partial. — [caniuse zstd data](https://raw.githubusercontent.com/Fyrd/caniuse/main/features-json/zstd.json) (also [caniuse.com/zstd](https://caniuse.com/zstd)); commit dates from the [GitHub API](https://api.github.com/repos/Fyrd/caniuse/commits?path=features-json/zstd.json)
- Brotli (caniuse, same date): Chrome 50+, Edge 15+, Firefox 44+, Safari 11+ (macOS 10.13+), iOS 11+, Samsung 5+.
  Global usage 97.24 %. — [caniuse brotli data](https://raw.githubusercontent.com/Fyrd/caniuse/main/features-json/brotli.json)
- Chrome and Firefox support brotli only over HTTPS. — [AWS CloudFront docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html)
- Safari 26.3 (WebKit post of 2026-02-11) supports zstd for text assets. It needs iOS, iPadOS or visionOS 26.3, or
  macOS Tahoe 26.3, and is "not available in Safari 26.3 on earlier macOS versions" because support comes from the
  system networking stack. The post describes zstd as fast enough to compress on the fly, unlike brotli, which is
  "typically pre-compressed during your build process". — [WebKit, Features for Safari 26.3](https://webkit.org/blog/17798/webkit-features-for-safari-26-3/)
- MDN's example of a browser navigation: `Accept-Encoding: gzip, deflate, br, zstd`. MDN also lists the
  experimental `dcb` and `dcz` (dictionary-compressed brotli and zstd) tokens. — [MDN Accept-Encoding source](https://raw.githubusercontent.com/mdn/content/main/files/en-us/web/http/reference/headers/accept-encoding/index.md)
- Chromium's intent to ship (2024-02-12, Nidhi Jaju) targeted M123. It notes risks from broken servers and from
  middleboxes that intercept HTTPS but fail to strip zstd from Accept-Encoding. Chrome limits the zstd window to 8 MB,
  and "very few sites" exceed it. — [blink-dev, Intent to Ship: Zstd Content-Encoding](https://groups.google.com/a/chromium.org/g/blink-dev/c/GFFOLCF12a4/m/crdNkVeaAQAJ) (via search summary)
- RFC 9659 (September 2024, Jaju and Handte, Google and Meta): for the `zstd` coding, "decoders MUST support a
  Window_Size of up to and including 8 MB, and encoders MUST NOT generate frames requiring a Window_Size larger than
  8 MB". RFC 8878 had only recommended it. — [RFC 9659](https://www.rfc-editor.org/rfc/rfc9659.txt)
- Paul Calvano (2024-03-19) shows Facebook getting `gzip, deflate, br, zstd` and answering `content-encoding: zstd`.
  In January 2024 zstd was served mostly by Meta properties and Netflix. — [Paul Calvano, Choosing between gzip, Brotli and zStandard](https://paulcalvano.com/2024-03-19-choosing-between-gzip-brotli-and-zstandard-compression)
- Measured locally (2026-10-26, Debian 13, capturing the request on a loopback socket):
  curl 8.14.1 sends no Accept-Encoding by default. With `--compressed` it sends `deflate, gzip, br, zstd` (the build
  links zlib 1.3.1, brotli 1.1.0, zstd 1.5.7, so the list follows the build).
  python-requests 2.32.3 / urllib3 2.3.0 sends `gzip, deflate, br`. urllib3 appends `br` only when the
  `brotli`/`brotlicffi` module imports and `zstd` only when `zstandard` imports (source: `urllib3/util/request.py`).
  Python urllib sends `identity`. Node.js 20.19.2 `fetch` sends `gzip, deflate`. GNU Wget 1.25.0 sends
  `identity`. — measured locally; [curl --compressed docs](https://raw.githubusercontent.com/curl/curl/master/docs/cmdline-opts/compressed.md) ("using one of the algorithms curl supports")
- Web Almanac 2025: CDNs served 12 % of compressed responses as zstd. — [Web Almanac 2025, CDN](https://almanac.httparchive.org/en/2025/cdn)

### Inferences
- In 2026 a server can count on brotli (about 97 %) and gzip (all). zstd reaches about 83 % of browsers by caniuse's
  usage weighting. Older Safari on macOS before Tahoe 26.3, Samsung Internet and most non-browser clients still need
  br or gzip.
- caniuse marks iOS 26.3+ as full support while 26.0-26.2 is "supports but does not request". That suggests Safari
  26.3+ advertises zstd in Accept-Encoding, but WebKit's post does not say so directly.
- Any zstd encoder for HTTP must keep its window at or below 8 MB (windowLog ≤ 23). libzstd levels 17-19 default to
  windowLog 23 for unknown-size input (measured below), which is at the limit. A server should set
  `ZSTD_c_windowLog` explicitly.
- Non-browser clients (APIs, monitoring, scripts) often ask for gzip and deflate only (Node fetch, requests without
  brotli), so gzip stays necessary for JSON APIs.

### Gaps
- The exact Accept-Encoding sent by Safari 26.3+ was not confirmed from an Apple or WebKit source.
- Whether Chrome and Firefox advertise zstd over plain HTTP (as they do not for br) was not confirmed.
- The share of traffic accepting zstd by request volume (not caniuse's usage estimate) was not found. A search
  summary cited "State of Web Vitals Q1 2026" (corewebvitals.io: 25.5 % of text responses brotli, about 22 % gzip,
  about 2 % zstd, 49.6 % uncompressed), but I did not fetch it. Unverified.
- Go's net/http default (it transparently requests gzip) was not tested here, because Go is not installed.

## 4. Measured cost and ratio of gzip, brotli and zstd by level

### Takeaway
For on-the-fly compression of 6-600 KB text, zstd 1-3 is the cheapest encoder that matches gzip 6's size: zstd 3
is 2 % larger than zlib gzip 6 at 8x its speed (728 vs 90 MB/s). brotli 4 matches gzip 6 at about twice gzip's
speed. brotli 5-6 are 8-9 % smaller than gzip 6 at gzip-6 speed. brotli 10-11 and zstd 15+ are 15-500x slower and
only for precompressed static files. zlib-ng and libdeflate make gzip itself 2-2.5x cheaper at the same size.
Published results (Cloudflare, Paul Calvano, the zstd README) agree with this ordering.

### Cited Findings: published
- zstd README (lzbench, Core i7-9700K 4.9 GHz, Ubuntu 24.04, gcc 14.2, Silesia corpus). zstd 1.5.7 -1: ratio 2.896,
  510 MB/s compression, 1550 MB/s decompression. brotli 1.1.0 -1: 2.883, 290 MB/s, 425 MB/s. zlib 1.3.1 -1: 2.743,
  105 MB/s, 390 MB/s. zstd --fast=1: 2.439, 545 MB/s. — [facebook/zstd README](https://raw.githubusercontent.com/facebook/zstd/dev/README.md)
- Cloudflare's live traffic (Q3 2024): average compress time zstd (level 3) 0.848 ms, brotli 1.544 ms, gzip
  0.872 ms. Ratios: gzip 2.56, zstd 2.86, brotli 3.08. Levels for brotli and gzip not stated. — [Cloudflare blog](https://blog.cloudflare.com/new-standards/)
- Paul Calvano (2024-03-19). "Most servers and CDNs default to gzip level 6", "NGINX defaults to gzip level 1",
  Apache mod_brotli defaults to brotli 5, ngx_brotli to brotli 6. In the HTTP Archive top 10k, most gzip sits at an
  estimated level 4-6 and about 30 % at level 1. Most brotli is at level 4, about 25 % at level 1, and level 11 is
  mostly static content. — [Paul Calvano](https://paulcalvano.com/2024-03-19-choosing-between-gzip-brotli-and-zstandard-compression)
- Same post, size reduction versus gzip 6 over the top-10k first-party objects (average / p50 / p75 / p90):
  brotli 5 8.85 / 6.99 / 10.25 / 15.29 %; zstd 12 9.07 / 7.33 / 10.94 / 15.74 %; brotli 11 19.18 / 17.53 / 22.21 /
  27.21 %; zstd 19 14.11 / 12.40 / 17.10 / 22.40 %. zstd 19 compresses about 4x faster than brotli 11. gzip 6 is
  25-30 % smaller than gzip 1 on most payloads. — [Paul Calvano](https://paulcalvano.com/2024-03-19-choosing-between-gzip-brotli-and-zstandard-compression)
- Same post, ten large HTML pages (1.4-3.9 MB): gzip 6, brotli 5 and zstd 12 each took 0.04-0.10 s per page, with
  brotli 5 and zstd 12 producing near-identical sizes (for example Epicurious 271 / 145 / 145 KB). — [Paul Calvano](https://paulcalvano.com/2024-03-19-choosing-between-gzip-brotli-and-zstandard-compression)
- Web Almanac 2025: brotli is described as 20-26 % better than gzip (likely at high levels; the level is not
  stated). — [Web Almanac 2025, CDN](https://almanac.httparchive.org/en/2025/cdn)

### Cited Findings: measured locally (2026-10-26)
Method: AMD Ryzen 9 9900X, Debian 13, kernel 6.12.113, gcc 14.2 `-O2 -march=native`, one core pinned (`taskset -c 5`)
on a host running other services (load average about 2.3 of 24 threads). Libraries: zlib 1.3.1 (Debian), zlib-ng
2.3.3 (release of 2026-02-03, built from source, native API), libdeflate 1.23, brotli 1.1.0, zstd 1.5.7. The
corpus is 14 real files (1.9 MB): HTML (Debian home 16 KB, Hacker News 35 KB, MDN page 184 KB, Wikipedia "HTTP"
605 KB), JSON (GitHub API 6, 41, 239 KB), CSS (normalize 2 KB, Font Awesome 103 KB, Bootstrap 5.3.3 233 KB), JS
(lodash 73 KB, jQuery 3.7.1 88 KB, react-dom 18.3.1 132 KB, Vue 3.4 144 KB). "Oneshot" means the whole response in
memory with the size known: zlib and zlib-ng contexts reused with `deflateReset` (gzip wrapper, windowBits 15,
memLevel 8); brotli `BrotliEncoderCompress` (a new encoder per call, lgwin 22); zstd `ZSTD_compress2` on a reused
context; libdeflate on a reused compressor. "Stream16k" means 16 KB chunks, a flush after each, size unknown. Each
cell is at least 0.12 s and 3 runs. Source and raw CSV: `cdn_browsers_cost_bench/` beside these notes.

Whole corpus (1.9 MB). Ratio = input/output. "vs gzip 6" = output size relative to zlib level 6.

| encoder level | ratio | vs gzip 6 | MB/s | µs per 100 KB (derived) |
|---|---|---|---|---|
| zlib gzip 1 | 3.96 | +20.1 % | 249 | 412 |
| zlib gzip 4 | 4.51 | +5.3 % | 164 | 623 |
| zlib gzip 6 | 4.75 | 0 | 90 | 1,135 |
| zlib gzip 9 | 4.78 | −0.7 % | 61 | 1,690 |
| zlib-ng 1 | 3.31 | +43.8 % | 675 | 152 |
| zlib-ng 2 | 4.13 | +14.9 % | 349 | 293 |
| zlib-ng 4 | 4.59 | +3.5 % | 227 | 451 |
| zlib-ng 6 | 4.72 | +0.7 % | 167 | 612 |
| libdeflate 1 | 4.29 | +10.7 % | 492 | 208 |
| libdeflate 4 | 4.58 | +3.7 % | 314 | 326 |
| libdeflate 6 | 4.75 | −0.1 % | 209 | 490 |
| libdeflate 9 | 4.83 | −1.7 % | 89 | 1,151 |
| libdeflate 12 | 4.96 | −4.3 % | 8.6 | 11,900 |
| brotli 0 | 3.96 | +20.1 % | 1,051 | 97 |
| brotli 1 | 4.21 | +13.0 % | 628 | 163 |
| brotli 2 | 4.57 | +4.1 % | 309 | 331 |
| brotli 3 | 4.66 | +2.0 % | 265 | 386 |
| brotli 4 | 4.82 | −1.3 % | 173 | 590 |
| brotli 5 | 5.19 | −8.5 % | 113 | 909 |
| brotli 6 | 5.24 | −9.4 % | 102 | 1,004 |
| brotli 7 | 5.28 | −9.9 % | 87 | 1,182 |
| brotli 9 | 5.31 | −10.5 % | 43 | 2,398 |
| brotli 10 | 5.75 | −17.3 % | 4.2 | 24,400 |
| brotli 11 | 5.88 | −19.2 % | 1.5 | 68,300 |
| zstd −5 | 3.04 | +56.5 % | 1,323 | 77 |
| zstd −1 | 3.74 | +26.9 % | 1,074 | 95 |
| zstd 1 | 4.41 | +7.7 % | 1,029 | 100 |
| zstd 2 | 4.57 | +4.1 % | 858 | 119 |
| zstd 3 | 4.65 | +2.3 % | 728 | 141 |
| zstd 4 | 4.76 | −0.3 % | 413 | 248 |
| zstd 5 | 4.91 | −3.2 % | 276 | 371 |
| zstd 6 | 5.00 | −5.0 % | 211 | 485 |
| zstd 9 | 5.12 | −7.3 % | 133 | 770 |
| zstd 12 | 5.17 | −8.1 % | 50 | 2,070 |
| zstd 15 | 5.29 | −10.2 % | 22 | 4,760 |
| zstd 19 | 5.38 | −11.6 % | 6.4 | 16,000 |

By type. Each cell: ratio, size vs zlib gzip 6, MB/s. HTML = 3 pages (235 KB), JSON = 3 (286 KB), CSS = 3
(338 KB), JS = 4 (436 KB), large HTML = Wikipedia 605 KB.

| encoder level | HTML | JSON | CSS | JS (minified) | large HTML |
|---|---|---|---|---|---|
| zlib gzip 1 | 5.20, +20.0 %, 368 | 4.05, +18.1 %, 275 | 4.85, +27.7 %, 315 | 2.46, +15.5 %, 153 | 5.15, +24.4 %, 297 |
| zlib gzip 6 | 6.24, 0, 147 | 4.78, 0, 102 | 6.19, 0, 114 | 2.85, 0, 53 | 6.40, 0, 111 |
| zlib-ng 6 | 6.20, +0.5 %, 254 | 4.73, +1.1 %, 220 | 6.22, −0.4 %, 180 | 2.81, +1.2 %, 107 | 6.38, +0.3 %, 190 |
| libdeflate 6 | 6.21, +0.5 %, 308 | 4.79, −0.2 %, 243 | 6.22, −0.5 %, 227 | 2.84, +0.1 %, 132 | 6.42, −0.3 %, 258 |
| brotli 1 | 5.89, +5.9 %, 1138 | 4.54, +5.3 %, 713 | 4.98, +24.4 %, 740 | 2.49, +14.3 %, 408 | 5.73, +11.8 %, 679 |
| brotli 4 | 6.77, −7.9 %, 252 | 4.98, −4.1 %, 199 | 5.89, +5.2 %, 194 | 2.78, +2.3 %, 109 | 6.86, −6.7 %, 213 |
| brotli 5 | 7.35, −15.1 %, 172 | 5.26, −9.2 %, 129 | 6.62, −6.5 %, 133 | 2.94, −3.2 %, 69 | 7.54, −15.1 %, 138 |
| brotli 6 | 7.41, −15.8 %, 160 | 5.30, −9.9 %, 118 | 6.76, −8.3 %, 119 | 2.96, −3.8 %, 62 | 7.63, −16.0 %, 124 |
| brotli 11 | 8.38, −25.5 %, 2 | 6.01, −20.5 %, 2 | 7.99, −22.5 %, 2 | 3.21, −11.3 %, 1 | 8.76, −26.9 %, 1 |
| zstd 1 | 6.10, +2.3 %, 1767 | 4.67, +2.3 %, 1212 | 5.46, +13.5 %, 1187 | 2.56, +11.0 %, 739 | 6.12, +4.6 %, 1004 |
| zstd 3 | 6.35, −1.8 %, 1287 | 4.87, −1.8 %, 748 | 5.64, +9.8 %, 1017 | 2.71, +5.0 %, 450 | 6.56, −2.3 %, 817 |
| zstd 6 | 6.84, −8.8 %, 307 | 5.14, −7.0 %, 246 | 6.34, −2.4 %, 224 | 2.86, −0.6 %, 140 | 7.20, −11.1 %, 247 |
| zstd 9 | 7.00, −10.8 %, 176 | 5.22, −8.4 %, 148 | 6.62, −6.4 %, 129 | 2.93, −2.8 %, 84 | 7.35, −12.8 %, 185 |
| zstd 19 | 7.29, −14.4 %, 6 | 5.39, −11.4 %, 7 | 7.11, −12.9 %, 5 | 3.04, −6.4 %, 7 | 7.85, −18.4 %, 6 |

Per response, in µs on one core / output bytes, for typical sizes (from `speed.csv`):

| encoder level | JSON 6 KB | HTML 16 KB | HTML 35 KB | JSON 41 KB | jQuery 88 KB | MDN HTML 184 KB | JSON 239 KB |
|---|---|---|---|---|---|---|---|
| zlib gzip 1 | 11 / 1528 | 28 / 4814 | 37 / 6112 | 47 / 8318 | 544 / 35430 | 573 / 34204 | 984 / 60902 |
| zlib gzip 6 | 19 / 1387 | 60 / 4282 | 127 / 5655 | 127 / 7484 | 1575 / 30413 | 1406 / 27661 | 2672 / 51034 |
| zlib-ng 6 | 13 / 1380 | 40 / 4263 | 94 / 5654 | 63 / 7485 | 770 / 30683 | 791 / 27885 | 1227 / 51702 |
| libdeflate 6 | 13 / 1378 | 34 / 4264 | 66 / 5641 | 65 / 7484 | 652 / 30483 | 660 / 27881 | 1101 / 50940 |
| brotli 1 | 9 / 1528 | 25 / 4798 | 31 / 6029 | 33 / 7762 | 195 / 35042 | 150 / 28994 | 359 / 53807 |
| brotli 4 | 27 / 1357 | 71 / 4128 | 104 / 5522 | 112 / 7267 | 788 / 31402 | 756 / 24970 | 1300 / 48827 |
| brotli 5 | 30 / 1284 | 87 / 3846 | 155 / 4975 | 139 / 7079 | 1229 / 29763 | 1122 / 23086 | 2046 / 46009 |
| brotli 6 | 30 / 1281 | 90 / 3834 | 163 / 4961 | 142 / 7076 | 1318 / 29595 | 1211 / 22862 | 2257 / 45639 |
| brotli 9 | 715 / 1274 | 1264 / 3830 | 1236 / 4917 | 1421 / 7050 | 2998 / 29478 | 2943 / 22565 | 4414 / 45143 |
| brotli 11 | 3084 / 1181 | 9167 / 3325 | 21178 / 4328 | 17044 / 6146 | 58951 / 27445 | 87633 / 20343 | 160887 / 40287 |
| zstd 1 | 6 / 1460 | 16 / 4538 | 19 / 5718 | 20 / 7437 | 97 / 34450 | 98 / 28195 | 210 / 52397 |
| zstd 3 | 7 / 1432 | 19 / 4456 | 25 / 5573 | 28 / 7299 | 144 / 32250 | 138 / 26903 | 348 / 50090 |
| zstd 6 | 16 / 1389 | 52 / 4264 | 93 / 5374 | 90 / 7115 | 657 / 30417 | 619 / 24659 | 1056 / 47232 |
| zstd 12 | 104 / 1380 | 556 / 4213 | 576 / 5336 | 376 / 7077 | 2375 / 29659 | 5424 / 23617 | 5450 / 46041 |
| zstd 19 | 592 / 1358 | 2541 / 4173 | 8481 / 5153 | 4479 / 6982 | 11755 / 28896 | 31205 / 22847 | 35928 / 44753 |

Streaming (16 KB chunks, a flush after each, size unknown) against oneshot, summed over the corpus: zlib 1/4/6
output +0.3/+0.4/+0.2 %, time +14/+10/+6 %. brotli 4/5/6 output +1.4/+1.3/+1.3 %, time +16/+11/+9 %. **brotli 1
output +23.6 %**, time +45 %. zstd 1/3/6 output +2.3/+0.9/+1.4 %, time +36/+12/+4 %. — measured locally
(`speed.csv`, mode `stream16k`)

Per-response setup: a fresh zlib `deflateInit2` per response at level 6 cost 21,147 µs over the corpus against 21,076
with `deflateReset`. A fresh `ZSTD_CCtx` at level 3 cost 2,647 against 2,609 with reuse. Both are within noise for
responses of these sizes. — measured locally (`fresh-init`, `fresh-cctx` rows)

### Inferences
- The "matches gzip 6 in size" point per encoder: zlib-ng 6 or libdeflate 6 (same bytes, 1.9-2.3x faster than zlib
  6), brotli 4 (−1.3 %, 1.9x faster than zlib 6), zstd 3-4 (+2.3 % / −0.3 %, 8x / 4.6x faster). For a server already
  paying for gzip 6, zstd 3 frees about 88 % of the compression CPU at +2 % size, and brotli 5 buys 8.5 % fewer
  bytes at about the same CPU.
- Minified CSS and JS are where zstd's low levels lose. zstd 3 is 9.8 % (CSS) and 5.0 % (JS) larger than gzip 6,
  while it wins on HTML and JSON (−1.8 %). brotli also needs level 5+ to beat gzip 6 on CSS and JS. Static assets
  are better precompressed (brotli 11: −11 to −27 % vs gzip 6), which leaves dynamic HTML and JSON as the on-the-fly
  case, where zstd 3 and brotli 4-5 both do well.
- High levels have a large fixed cost per response: brotli 9 takes 715 µs for a 6 KB JSON and brotli 4 takes 27 µs.
  zstd 12 takes 104 µs for 6 KB. This is consistent with the large hash tables those levels allocate and clear per
  encoder (35 MB for brotli 9, see section 5), so small dynamic responses should never use brotli ≥ 7 or zstd ≥ 10.
- brotli 1 loses a lot when flushed every 16 KB (+24 % output; q0 was not measured streaming, but it uses the
  same fast one-pass mode, so the same loss is likely). A streaming proxy that flushes per chunk should use
  brotli ≥ 4 or zstd, or buffer before flushing.
- On a 100 KB dynamic response at one core, the order of cost is about 0.1 ms (zstd 1-3), 0.45-0.6 ms (zlib-ng or
  libdeflate 6, brotli 4), 0.9-1.0 ms (brotli 5-6), 1.1 ms (zlib 6). Against agensio's 2-20 µs per request
  (CLAUDE.md), compression of a dynamic response dominates the server's CPU at any level except zstd −5 to 3 and
  brotli 0-1.

### Gaps
- The Squash benchmark and a current lzbench results page were not read (lzbench's README URL given in the brief
  404s under `inikulin/`; the project is `inikep/lzbench`). The zstd README's lzbench table is used instead.
- Chrome's own zstd announcement data was not found beyond the intent-to-ship thread.
- My corpus is one sample per site with no Brotli `MODE_TEXT`/`MODE_FONT` hints. The zstd numbers use known-size
  parameters (smaller windows and tables for small inputs). zlib-ng was built with `-march=native` and the Debian
  libraries with their generic flags, which may favour zlib-ng.
- The Web Almanac has had no dedicated compression chapter since 2021 (the 2022 URL 404s). Server-side compression
  levels in the wild come only from Paul Calvano's 2024 top-10k estimate.

## 5. Memory per concurrent stream for each encoder

### Takeaway
zlib costs about 268 KB per stream whatever the level (zlib-ng 350 KB). zstd at level 3 costs 0.8 MB for a 100 KB response of known
size and 3.7 MB streamed with unknown size (2 MB window). brotli at its default 4 MB window costs 9-11 MB per stream
at qualities 2-6 and 17-44 MB at 7-11. Capping brotli's window at 2^18-2^19 cuts quality 4-6 to 1.4-3.5 MB, and
zstd at windowLog 19 to 2.1 MB, for 1 % or less of output on a 1 MB stream. Responses smaller than the window lose
nothing.

### Cited Findings
- zlib: deflate memory is `(1 << (windowBits+2)) + (1 << (memLevel+9))`, "128K for windowBits=15 + 128K for
  memLevel = 8 (default values)" plus a few KB. Inflate uses `1 << windowBits`. — [zlib zconf.h](https://github.com/madler/zlib/blob/develop/zconf.h) (read from Debian's `/usr/include/zconf.h`, zlib 1.3.1)
- Measured locally: zlib 1.3.1 peaks at 268,096 bytes at every level 1-9. zlib-ng 2.3.3 at 350,336 bytes. libdeflate
  1.23 (whole-buffer only) at 203 KB for level 1, 668 KB for 6-9, 9.0 MB for 12. — measured locally (`mem.csv`)
- Measured locally, brotli 1.1.0, default lgwin 22, peak heap of one encoder:
  - 1 MB streamed, size unknown: q0 146 KB, q1 162 KB, q2-3 8.9 MB, q4 9.3 MB, q5 9.8 MB, q6 10.9 MB, q7 17.2 MB,
    q8 25.6 MB, q9 42.5 MB, q10-11 43.6-43.9 MB.
  - 100 KB with `BROTLI_PARAM_SIZE_HINT`: q1 1.05 MB, q2-3 9.1 MB, q4 10.1 MB, q5 10.6 MB, q6 11.7 MB, q9 35.3 MB,
    q10 4.7 MB, q11 8.4 MB. — measured locally (`mem.csv`)
- Measured locally, brotli window cap on the same 1 MB stream (peak / output):
  - q4: lgwin 16 1.0 MB / 177,584 B; 18 1.39 MB / 173,927; 19 1.91 MB / 173,356; 20 2.96 MB / 173,163;
    22 9.25 MB / 173,163.
  - q5: lgwin 18 1.95 MB / 158,298; 19 2.47 MB / 157,431; 22 9.81 MB / 157,084.
  - q6: lgwin 18 3.0 MB / 156,350; 19 3.52 MB / 155,237; 22 10.86 MB / 154,834. — measured locally (`memwin.csv`)
- Measured locally, zstd 1.5.7, peak heap of one context:
  - 100 KB of known size: level 1 442 KB, 3 803 KB, 4 1.46 MB, 5-9 1.06 MB, 12 1.98 MB, 15-19 2.75 MB.
  - Streamed with unknown size: level 1 1.37 MB, 2 2.09 MB, 3 3.66 MB, 4 4.97 MB, 5-6 5.50 MB, 7 8.1 MB,
    9 15.5 MB, 12 46.9 MB, 15 72.1 MB, 19 93.8 MB. These match `ZSTD_estimateCStreamSize`. — measured locally (`mem.csv`)
- Measured locally, zstd default parameters for unknown size: windowLog 19 (level 1), 20 (2), 21 (3-8), 22 (9-16),
  23 (17-19). For a known 100 KB input, windowLog 17 at every level. — measured locally (`memwin.csv`, `zstdparams` rows from `ZSTD_getCParams`)
- Measured locally, zstd window cap on the 1 MB stream (peak / output):
  - level 3: windowLog 17 1.70 MB / 181,982 B; 19 2.09 MB / 179,465; 20 2.61 MB / 178,568; 21 3.66 MB / 178,572;
    23 9.95 MB.
  - level 1: wlog 19 1.37 MB / 190,776; 21 2.94 MB / 190,720.
  - level 6: wlog 19 3.93 MB / 163,044; 21 5.50 MB / 162,628. — measured locally (`memwin.csv`)
- The HTTP limit for zstd: encoders MUST NOT need a window above 8 MB (RFC 9659). Chrome enforces 8 MB. — [RFC 9659](https://www.rfc-editor.org/rfc/rfc9659.txt); [blink-dev intent](https://groups.google.com/a/chromium.org/g/blink-dev/c/GFFOLCF12a4/m/crdNkVeaAQAJ)
- Cloudflare: gzip uses a 32 KB window. zstd typically uses "around 1 MB at lower compression levels". — [Cloudflare blog](https://blog.cloudflare.com/new-standards/)

### Inferences
- For 1,000 concurrent streamed (unknown-size) responses: zlib about 0.27 GB. zstd 3 at default parameters 3.7 GB,
  2.1 GB at windowLog 19. brotli 5 at the default window 9.8 GB, 1.95 GB at lgwin 18. Brotli's default window is
  therefore not usable for many concurrent streams. A server should set lgwin 18-19 and zstd windowLog 19-20 for
  dynamic responses, which costs under 1 % of output on a 1 MB response and nothing on responses smaller than the
  window.
- When the whole response is in memory (buffered upstream answers), one context per worker can be reused for zlib,
  zlib-ng, libdeflate and zstd. brotli has no reset, so a new encoder is created per response; its allocation is
  inside the measured one-shot times. Memory is then per worker, not per stream.
- Decoder memory at the client: gzip 32 KB window, zstd up to 8 MB under RFC 9659, brotli up to 16 MB at lgwin 24
  (brotli's maximum by spec; not verified here). The client's cost is bounded by the window the server chooses.

### Gaps
- Brotli's documented maximum window and decoder memory were not read from a primary source in this pass.
- I did not measure zlib-ng or libdeflate streaming memory, because libdeflate has no streaming API and zlib-ng's
  is the same as one-shot.

## 6. Library facts: zlib, zlib-ng, libdeflate, brotli, zstd

### Takeaway
All five are permissively licensed (zlib licence, MIT, BSD-3/GPL-2 dual). libbrotli-dev, libzstd-dev,
libdeflate-dev and zlib1g-dev are packaged in Debian 12/13 and Ubuntu 22.04/24.04/26.04, so the new encoders need
no vendoring. zlib-ng is not packaged in Debian. libdeflate has no streaming API, so it suits buffered responses
only.

### Cited Findings
- Licences from Debian copyright files: brotli MIT, zstd "BSD-3-clause or GPL-2" (the patent clause was removed in
  1.3.1), libdeflate Expat (MIT), zlib Zlib. zlib-ng's LICENSE.md is the zlib licence. — Debian `/usr/share/doc/<pkg>/copyright` (trixie); [zlib-ng LICENSE.md](https://github.com/zlib-ng/zlib-ng/blob/develop/LICENSE.md)
- libdeflate: "There is currently no support for streaming ... if your application compresses large files as a
  single compressed stream, similarly to the gzip program, then libdeflate isn't for you." — [libdeflate README](https://github.com/ebiggers/libdeflate/blob/master/README.md)
- Versions of the `-dev` packages (madison, 2026-10-26):

  | package | Debian 12 bookworm | Debian 13 trixie | forky/sid | Ubuntu 22.04 jammy | Ubuntu 24.04 noble | Ubuntu 26.04 resolute |
  |---|---|---|---|---|---|---|
  | libbrotli-dev | 1.0.9 | 1.1.0 | 1.2.0 | 1.0.9 | 1.1.0 | 1.2.0 |
  | libzstd-dev | 1.5.4 | 1.5.7 | 1.5.7 | 1.4.8 | 1.5.5 | 1.5.7 |
  | libdeflate-dev | 1.14 | 1.23 | 1.25 | 1.10 | 1.19 | 1.23 |
  | zlib1g-dev | 1.2.13 | 1.3.1 | 1.3.2 | 1.2.11 | 1.3 | 1.3.1 |

  — [Debian madison](https://qa.debian.org/madison.php?package=libbrotli-dev&text=on) (same query for each package); [Ubuntu madison](https://people.canonical.com/~ubuntu-archive/madison.cgi?package=libbrotli-dev&text=on)
- zlib-ng: no `libz-ng-dev` or `zlib-ng` source in Debian (madison returned nothing, sources.debian.org returned
  404). The latest upstream release is 2.3.3 of 2026-02-03. — [Debian madison](https://qa.debian.org/madison.php?package=libz-ng-dev&text=on); [sources.debian.org API](https://sources.debian.org/api/src/zlib-ng/); [GitHub releases API](https://api.github.com/repos/zlib-ng/zlib-ng/releases/latest)
- Measured locally: zlib-ng 2.3.3 gives zlib's output size within 2 % at levels 4-9 and is 1.3-1.9x faster
  (1.85x at level 6). Its level 1 is a different, much faster algorithm (675 MB/s, ratio 3.31 against zlib 1's
  249 MB/s at 3.96). libdeflate 1.23 is 2.3x zlib's speed at level 6 with the same size, and its levels 10-12 are
  3.2-3.6 % smaller than zlib 9 at 8.6-19 MB/s. — measured locally (`speed.csv`)
- brotli has no reset call: the measured one-shot path creates an encoder per response. zstd contexts and zlib
  streams can be reused (`ZSTD_CCtx_reset`, `deflateReset`). — measured locally (benchmark code); [zlib zconf.h / API](https://github.com/madler/zlib/blob/develop/zconf.h)

### Inferences
- A build that links the system's libbrotli and libzstd works on every target distribution listed. Debian 12 and
  Ubuntu 22.04 carry older versions (brotli 1.0.9, zstd 1.4.8 on jammy), whose speed may differ from the 1.1.0 and
  1.5.7 measured here.
- libdeflate is a fit for buffered responses (whole body known, as in agensio's buffered upstream mode) but not for
  streamed ones. zlib-ng would have to be vendored or built on Debian.

### Gaps
- I did not check whether the brotli 1.0.9 and zstd 1.4.8 of the older LTS releases have the same level tables, or
  how fast they are.
- I did not check Fedora or RHEL, where zlib-ng-compat reportedly replaced zlib (Fedora 40).
