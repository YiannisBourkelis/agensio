# Design: response compression (phase E2, the on-the-fly part)

Status: proposed 2026-10-30; its seven decisions taken by the owner the same day (section 12). Built so far (section 11): step 1, the keys and the chooser (2026-10-30); step 2, the copies of cached files made once, with libzstd and libbrotli as optional dependencies (2026-10-30: a site without the key flat on every row, the 100 KB CSS served from its brotli copy at 0.42 of the identity row's CPU, `ab-20261030-011627.md`); step 3, buffered PHP, proxied and CGI answers up to 64 KB
compressed whole with gzip (2026-10-30, `ab-20261030-032443.md`: every row that compresses nothing
within noise, the upstream's 32 KB page 8.75 to 368 µs per request: gzip 5 on 33 KB of 3:1 prose costs
0.36 ms of the worker, which is why zstd 3 is the default once step 4 brings it). Built on the research of
2026-10-26, `reports/Web server response compression.md`, and its notes under
`research_notes/Web server response compression/` (nine servers, the CDNs, the RFCs, BREACH, the
cost of each encoder measured on this box, what applications do, what administrators ask).
Decided with the owner on 2026-10-30, ahead of the note: compression is **off by default** (no CPU
spent unless a site asks); signed-in visitors' pages are not compressed unless the user decides so;
libzstd and libbrotli join zlib as optional dependencies; agensio makes compressed copies of static
files itself, in memory only, counted in the cache's budget.

## 1. Goals

- Compress what a site serves, whatever produced it: cached static files, FastCGI (PHP), proxied
  and CGI answers, agensio's own error pages. One switch per site, `response_compression = "on"`,
  with defaults that are right for a WordPress, Laravel, Drupal, Rails or Node site without a
  second key.
- The three codings browsers accept in 2026, gzip, brotli and zstd, built into the binary; no
  module to rebuild (the most-reacted complaint about nginx).
- Correct where the other servers are not, by the RFCs: `Vary` on every answer that could have
  been compressed, a validator per representation that still gives 304s, nothing compressed
  twice, `no-transform` honoured for applications, a 206 never compressed, HEAD with the GET's
  fields, streams never held back.
- Safe by default against BREACH: a signed-in visitor's page is compressed only when the user
  decided it, knowing why.
- No cost when off: a site without the key pays nothing on the request path (the A/B gate). On,
  the cost is the encoder's and nothing else: no allocation per request beyond the encoder's
  context, no lock, no thread hop for buffered answers.
- The agent sees every decision: `path_check` says which coding a path gets and why not
  otherwise; health names an application that compresses itself; status counts bytes saved.

## 2. What the other servers do, and what administrators ask

The notes hold the detail. What decides this design:

- Every server skips a body that already has a `Content-Encoding`, HEAD, 204 and 304, binary
  types and tiny bodies. They split on the four things the RFCs settle: the ETag of a compressed
  answer (Apache's `-gzip` suffix blocked 304s from 2.4.0 to 2.4.58; nginx weakens; Caddy suffixes
  and translates `If-None-Match` back), `Vary` on the uncompressed answer (nginx sends none by
  default), `no-transform` (nginx, Apache, h2o and Traefik ignore it), and streaming (Traefik fixed
  server-sent events twice; Caddy once).
- The complaints, ranked by votes and views: "compression is on but this type is not
  compressed" (nginx's `text/html`-only default, the `application/json;charset=utf-8` trap,
  fonts and SVG), "how do I check it works" (201 votes), decoding errors from double compression
  (PHP's `zlib.output_compression` plus a plugin plus the server; 211k views), `Vary` (171k
  views), brotli needing a rebuild on nginx, the ETag and 304 trap, SSE broken by buffering, and
  BREACH scanners against Lighthouse's "enable text compression".
- Caddy's `encode` is what administrators point to: one line, zstd and gzip, a broad type list
  matched with parameters ignored, a 512-byte minimum, SSE streamed at once.
- The cost, measured on this box (one core, 14 real HTML/JSON/CSS/JS files of 2 to 605 KB):

  | encoder | size against gzip 6 | speed | memory per stream at its default window |
  |---|---|---|---|
  | zlib gzip 6 | baseline | 90 MB/s | 268 KB |
  | zlib gzip 5 | +1.4 % | 123 MB/s | 268 KB |
  | zstd 3 | +2.3 % | 728 MB/s | 3.7 MB streamed (2.1 MB at window 2^19) |
  | brotli 4 | −1.3 % | 173 MB/s | 9.3 MB (1.4 MB at window 2^18) |
  | brotli 11 | −19 % | 1.5 MB/s | 44 MB |

  So zstd 3 costs an eighth of gzip 6 for 2 % more bytes, brotli 4 matches gzip 6 at twice its
  speed, and brotli 11 belongs only to files compressed once. Memory, not CPU, is what bites with
  many concurrent streams: brotli's default window would cost 10 GB for a thousand streams, so
  the windows are capped (under 1 % of output lost).
- Browsers: brotli 97 %, zstd 83 % (Chrome 123+, Firefox 126+, Safari 26.3+ only; Samsung
  Internet none); both only over HTTPS in Chrome and Firefox. Cloudflare asks origins for `br,
  gzip` and passes the origin's brotli to visitors; CloudFront compresses only bodies with a
  `Content-Length`.
- BREACH needs three things together: a secret in the body, attacker-reflected input beside it,
  and requests the victim's browser sends with its own credentials. Static files and anonymous
  pages are safe. Laravel's `@csrf` token is not masked (Django's and Rails' are), so a
  compressed, signed-in Laravel page that reflects input meets all three conditions.
- Applications: PHP's `zlib.output_compression` (off by default) compresses every type and
  status, 304s and images included, ignores `q=0`, compresses twice and holds back SSE; Next.js,
  Ghost, Grafana 13 and W3 Total Cache compress their own output; WP Super Cache and W3TC send
  `Content-Encoding: gzip` from PHP on cached pages behind a server that ignores `.htaccess`.

## 3. Configuration

The site key is the whole interface for most sites; the root table is tuning.

```toml
[[site]]
server_name = ["shop.example"]
app = "wordpress"
response_compression = "on"            # "off" (default) or "on"
```

A site that needs more writes the table form; every field is optional:

```toml
response_compression = { mode = "on",
                         off = ["/my-account/", "/checkout/"],   # paths never compressed
                         signed_in = "off",                      # "off" (default): signed-in visitors' pages uncompressed
                         session_cookies = ["shop_sid"],         # the site's own login cookies, beside the preset's
                         upstream = "pass",                      # "offload": agensio compresses instead of the application
                         event_streams = false }                 # server-sent events uncompressed unless true
```

| field | values | meaning |
|---|---|---|
| `mode` | `off` (default), `on` | the site's switch; `on` covers static files, PHP, proxied and CGI answers and agensio's own pages |
| `off` | path prefixes, up to 32 | where the site never compresses, whoever asks: account and checkout pages, an odd client's API |
| `signed_in` | `off` (default), `on` | whether a signed-in visitor's answers are compressed (section 7); `on` is the user's decision, taken knowing BREACH |
| `session_cookies` | names, up to 16 | cookies that mark a visitor signed in, added to the preset's own list |
| `upstream` | `pass` (default), `offload` | `offload` stops the browser's `Accept-Encoding` reaching the application, so agensio compresses and the guard applies |
| `event_streams` | `false` (default), `true` | `text/event-stream` answers compressed, flushed per event |

Root's table, main file, restart-only (rare tuning read once at start; never re-read per request,
the rule of `no-request-cost-for-rare-keys`):

```toml
[response_compression]
codings   = ["zstd", "br", "gzip"]          # offered; the order decides when the browser accepts several equally
levels    = { zstd = 3, br = 4, gzip = 5 }  # for answers compressed per request (zstd 1-9, br 1-6, gzip 1-9)
min_size  = 1024                            # bytes; smaller answers go uncompressed
types_add = ["application/vnd.api+json"]    # media types beyond the built-in list
```

What is deliberately not a setting:

- **Windows.** zstd 2^19, brotli 2^18, gzip 2^15, fixed: the measured memory per stream against
  under 1 % of output. A setting here is a way to run out of memory.
- **Static levels.** brotli 11 and gzip 9 for the copies made once (section 5): paid once, the
  smallest output is right; no administrator asked for less.
- **The streaming budget.** 64 compressed streams in flight per worker; beyond it, uncompressed
  with `Vary` kept. Status reports when it was reached.
- **A coding the build lacks** is refused by `agensio -t`, naming the package
  (`libzstd1`, `libbrotli1`); `server_status` lists the codings the binary has.
- **Levels and windows are set explicitly in the code,** never left to a library's default, so a
  library upgrade never changes what agensio sends (Traefik's 2026 regression).

Every key gets its reference row, its cookbook recipe (`docs/examples/`, with the `curl` check of
section 10) and its MCP text, per the working agreement.

## 4. What is compressed

| decision | rule | why |
|---|---|---|
| types | a `compressible` column in the built-in MIME table, matched on the media type without parameters (so `application/json;charset=utf-8` matches `application/json`); `types_add` extends it; no `Content-Type` is never compressed | the top complaint; the nginx `;charset` trap; HAProxy and ASP.NET skip untyped answers |
| built-in list | `text/*` but `text/event-stream`; JavaScript (every spelling); JSON and `+json`; XML and `+xml`; XHTML; SVG; ICO; wasm; TTF, OTF, EOT; web manifests | Caddy's and Cloudflare's lists |
| never | images but SVG and ICO, audio, video, archives, WOFF and WOFF2 (already compressed), `application/octet-stream` | compressing them costs CPU for nothing or more bytes |
| minimum size | 1,024 bytes of uncompressed body; exact for a buffered answer, judged after the first read for a streamed one, so a streamed 100-byte JSON is not compressed (nginx's `gzip_min_length` reads only `Content-Length`) | Traefik, Express, Fastify; Lighthouse ignores answers under about 1.4 KB |
| statuses | every status that carries content, but 206 (a slice of the identity bytes); 1xx, 204 and 304 carry no coding; HEAD gets the GET's fields without a body | RFC 9110 12.1; Caddy |
| HTTP/1.0 | only when the coded length is known before the head (a buffered answer), since HTTP/1.0 has no chunked framing; else identity | nginx and IIS skip HTTP/1.0 |
| no `Accept-Encoding` | identity | every server; RFC 9110 allows more, curl users expect this |
| never | 101 tunnels, CONNECT, WebSocket handshakes, `Content-Range` answers, anything already encoded, the control socket | all servers |

Negotiation reuses `choose_encoding` (`handlers/encoding.hpp`), extended with zstd: q-values,
`identity;q=0`, `*`, the highest q wins, and at equal q the order of `codings`. `identity;q=0`
with nothing else acceptable sends identity (no server answers 406; RFC 9110 12.5.3 allows it).

## 5. Static files: copies made once, in memory

Today a cached file is served compressed only when its build left `name.br` or `name.gz` beside it
(Drupal, Rails and Vite do; WordPress and plain sites do not). With `mode = "on"`, a file that
has no twin on disk gets its copies made by agensio:

- **Where:** in memory only, hanging off the file's `CacheEntry` exactly as a disk twin does
  (`br` and `gzip` pointers, own prebuilt block, own ETag), served by the same code. Nothing is
  written to the site's directory, so Nextcloud's integrity check and WordPress's checksums never
  see them, and a site's `.htaccess` or build is never touched.
- **When:** at cache fill, on a background thread of the server (one, low priority, a bounded
  queue of entries), never on a worker: brotli 11 takes 60 ms per 100 KB. Until the copy is made
  the file is served as today; the worker finds the copy on its next hit through the entry's
  pointer, which the fill thread sets last (a release store the hit path already reads).
- **Which files:** memory entries only (files up to `cache.max_file_size`), of a compressible
  type, at least `min_size`, at most 8 MB; descriptor entries and larger files are served as
  today.
- **Levels:** brotli 11 and gzip 9, the smallest output, since the CPU is paid once. A zstd copy
  is not made: every browser that takes zstd also takes brotli over HTTPS, and brotli 11 is 12 %
  smaller than zstd 19.
- **Budget:** the copies count against `cache.max_size` with their file, as the disk twins do
  (`bytes_of` in `cache.hpp`), so the administrator's ceiling stays the ceiling; a file with both
  copies takes about 1.3 to 1.6 times its own space. Eviction evicts file and copies together; a
  copy never outlives its file. Revalidation drops the copies with the entry when the file
  changed. `server_status` reports the bytes the copies hold.
- **Validators:** each copy gets its own strong ETag, `"hex(mtime)-hex(size)-br"` from the file's
  tag and the coding, as a disk twin has one of its own; the bytes are fixed for the entry's
  lifetime, so a strong tag is honest, and ranges, HEAD and 304 work through the twin code
  unchanged. A level or library change shows up as a new entry at the next start.
- **A disk twin wins:** a file with a twin on disk keeps it and gets no copy (the build's bytes
  are the site's choice).
- **A file still being written** (`file_settled`) gets no copy until it settles.

## 6. Dynamic answers: compressed on the worker, in pieces

FastCGI, proxied and CGI answers, and agensio's own error pages, are compressed where the answer is
built, in `apply_upstream_result` and the error-page path, by a `Compressor` the worker owns:

- **The decision** runs once per answer, after the field loop has decided the head (it already
  reads every field): eligible type, size, status, no `Content-Encoding` in the answer, no
  `no-transform` in the request's or the answer's `Cache-Control`, the path not under `off`, the
  visitor not signed in (section 7), the budget not exhausted. The coding is the request's
  `choose_encoding` result, computed once at routing when the site has `mode = "on"` and kept on
  the `Stream` (a site without the key never computes it: the one test on the request path).
- **A buffered answer up to 64 KB** (most HTML and JSON) is compressed whole into the worker's
  reused output buffer, by a context the worker reuses (zlib and zstd reset; brotli allocates
  its encoder per answer, inside the measured times), and goes out with an exact
  `Content-Length`. Cost: 25 µs for a 35 KB page with zstd 3, 104 µs with brotli 4.
- **A larger buffered answer, a spilled body or a stream** is compressed as the writer pulls it:
  a `CompressedBody` wraps the source as a `StreamBody`, compressing each 64 KB piece as it is
  asked for, so HTTP/2 and HTTP/3 backpressure holds and a slow client holds one piece and one
  context, never a whole compressed body. Framing is the writer's as for any `StreamBody`:
  chunked on HTTP/1.1, DATA frames on HTTP/2 and HTTP/3. In a 64 KB step zstd 3 costs under
  0.1 ms and gzip 5 about 0.5 ms, under the yield budget that governs memory bodies, so no thread
  hop and no pool.
- **Flushes:** an upstream read that empties the socket, a FastCGI record boundary and the end of
  a chunk each end with the encoder flushed (`ZSTD_e_flush`, `BROTLI_OPERATION_FLUSH`,
  `Z_SYNC_FLUSH`), so what the application flushed reaches the client. brotli below quality 4
  loses up to 24 % when flushed per 16 KB (measured), which is why the dynamic default is 4.
- **Streams:** `text/event-stream` is not compressed unless `event_streams = true`; when it is,
  the head goes out at once and each event is flushed. An answer with `X-Accel-Buffering: no`
  or `Incremental: ?1` has its head sent before the minimum-size decision. Separately and
  regardless of compression, agensio should start honouring those two fields and
  `text/event-stream` by switching a buffered FastCGI or proxy exchange to streaming when the head
  arrives: Laravel's `eventStream`, Symfony's `EventStreamResponse` and Next.js send them, and the
  cookbook asks for `buffering = false` per location today. That is its own step (section 11).
- **Already compressed:** an answer with a `Content-Encoding` other than `identity` passes through
  untouched, with `Vary: Accept-Encoding` merged in (PHP's zlib layer leaves it off the identity
  variant). `Content-Encoding: identity` is the application's opt-out (nginx's convention): the
  field is dropped and the body left alone.
- **`upstream = "offload"`** removes `Accept-Encoding` from the forwarded request, so an
  application that compresses (Next.js, Ghost, Grafana 13, PHP's zlib layer) sends identity and
  agensio compresses with its guard. HAProxy warns that offload moves CPU to the proxy; here it is
  the one way the signed-in guard can protect a PHP site with `zlib.output_compression` on, and
  the way a gzip-only application's visitors get zstd or brotli. Health recommends it by name
  (section 9).
- **Budget:** at most 64 compressed streams in flight per worker (a `CompressedBody` counts from
  creation to end); past it, the answer goes out uncompressed with `Vary` kept, and the worker
  counts it. A context is 0.3 MB (zlib), 2.1 MB (zstd 3) or 1.4 MB (brotli 4) at the capped
  windows, so a worker holds at most about 130 MB of encoder memory.
- **Request bodies:** unchanged, nothing decoded; `Content-Encoding` on a request passes to the
  application, `max_body_size` applies to the bytes as sent. If decoding is ever wanted, Apache's
  limits (decoded size, a 200:1 ratio checked per slice, one layer) and a fuzz target come with
  it; the 2026 Envoy CVE on zstd slices is the reason.

## 7. The signed-in guard (BREACH)

The attack needs the victim's own credentials on the request. A visitor is **signed in** when the
request carries any of:

- a cookie the site counts as a session: the preset's own names (`wordpress_logged_in_*`,
  `laravel_session` and Laravel's `XSRF-TOKEN`, Drupal's `SESS*`/`SSESS*`, Rails' `_*_session`,
  Django's `sessionid`, Symfony's `PHPSESSID`, Kanboard's, Grav's; a table to verify per
  application, as the login paths of fail2ban were) plus `session_cookies`; for `app = "php"` and
  `"proxy"` without a known application, a conservative fallback: any cookie whose name contains
  `sess`, `auth`, `token`, `login` or `logged`;
- `Authorization` with a scheme browsers replay on their own (Basic, Digest, Negotiate); a
  Bearer token is not counted, since no browser attaches a script's token to a forged request;
- a path under agensio's own `[[site.auth]]` password;
- admission by an address rule of `[[site.access]]` other than `any`.

With `signed_in = "off"` such an answer is not compressed. The test costs one scan of the
request's `Cookie` and `Authorization` fields, run only when the answer is otherwise eligible,
against tens of microseconds of compression; the cache guards already read `Authorization` for a
related purpose (`core/private_cache.hpp`). `Vary` stays `Accept-Encoding` alone: the cookie
decides only whether agensio compresses, never which content is sent.

Why the guard counts only login cookies and not every cookie: consent banners and analytics put a
first-party cookie on almost every returning visitor, and those unlock nothing; counting them would
turn compression off for most of a public site.

`signed_in = "on"` compresses signed-in answers too. It suits sites whose framework masks its
tokens and whose pages reflect no input (Django, Rails). It adds up to 32 random bytes of padding
per compressed answer, as Rails' Thruster does (Django adds up to 100): cheap, and honestly a
raise of the attack's cost, not its removal. The `off` paths cover what is left (`/my-account/`).
The application can always opt out with the standard `Cache-Control: no-transform`, which
Cloudflare honours too, so no new header is invented.

The MCP bridge treats `signed_in = "on"` as `pip_install` treats a package: the user confirms in
person (`user_confirmed`), after the agent has explained BREACH in a sentence. Health warns when
`signed_in = "on"` is set on a preset whose framework does not mask its token (Laravel,
WordPress, plain PHP).

## 8. Validators, Vary, Range, HEAD, 304, no-transform

- **Copies made at fill** (section 5): a strong ETag of their own; ranges, HEAD and 304 as a disk
  twin.
- **Dynamic answers compressed on the fly** get a weak ETag: a strong upstream tag becomes
  `W/"…"`, as nginx, h2o, HAProxy, Django and CloudFront do. Streamed output depends on flush
  timing and cannot honestly carry a strong tag. Weakness costs nothing here: agensio never
  serves ranges of upstream answers. RFC 9110 13.1.2 requires weak comparison for
  `If-None-Match`, so a correct application still answers 304 to the `W/"x"` the browser sends
  back, and the header is forwarded as it came, nginx's way (decided 2026-10-30). An application
  that compares the strings exactly answers 200 instead of 304: a cache miss, nothing broken. A
  translation that forwards the strong form beside the weak one would buy those 304s for a header
  rewrite on every conditional request and a tag list no RFC describes; it is not built unless a
  preset's application shows the miss in the suite's exact-comparing test (section 10).
- **Vary.** `Accept-Encoding` is added to every answer that passed the type, status and size
  tests, compressed or not, 304s of such answers included (RFC 9110 15.4.5), merged into the
  application's single `Vary` field, never duplicated; `Vary: *` left alone; never added to an
  answer that could never be compressed (an image), which would split caches for nothing.
- **Range.** A 206 is never compressed; `Accept-Ranges` is dropped from a compressed 200; a Range
  request the application answered with a 200 is compressed like any 200.
- **HEAD.** The GET's negotiation; `Content-Encoding`, `Vary` and the weakened ETag sent; no
  `Content-Length`, never the length of an empty encoded stream (Caddy's 2026 bug). For a static
  copy, its exact length.
- **no-transform.** Honoured in the answer for application output (RFC 9111 5.2.2.6 binds an
  intermediary, and a gateway is one), and in the request too, as Caddy does, at no cost. For
  agensio's own files it is the origin and not bound, but the same rule applies for consistency.
- **Digests.** `Content-MD5` and any field describing the identity bytes is dropped on a
  compressed answer; `Content-Length` of the identity block is never copied into an HTTP/2 or
  HTTP/3 head (RFC 9113 8.1.1: a wrong length is a malformed message).

## 9. The agent interface

- **`site_create`, `site_update`:** the `response_compression` field of section 3 (`ctl
  --compression on|off`, `--compression-off PATH`, `--compression-signed-in on|off`,
  `--compression-cookie NAME`, `--compression-upstream pass|offload`, `--compression-events`);
  `signed_in: "on"` needs `user_confirmed`.
- **`site_show`:** the effective settings, with the preset's session-cookie names.
- **`path_check`:** two new arguments, `accept_encoding` (default: a current browser's `gzip,
  deflate, br, zstd`) and `visitor` (`anonymous` | `signed_in`); the answer names the coding
  agensio would apply, or the one reason it would not: `type`, `size`, `status`, `signed_in`,
  `already_encoded`, `no_transform`, `path_off`, `mode_off`, `budget`, `no_accept_encoding`,
  `build_lacks_coding`. This answers the second most-viewed question, "why isn't this URL
  compressed".
- **`health_check`:**
  - `compression_app_compresses` (info): the application sends `Content-Encoding` on the probed
    home page, so agensio's choice and guard do not apply; names the application's own switch
    (`compress: false` in Next.js, `"compress": false` in Ghost, `enable_gzip = false` in
    Grafana) or `upstream = "offload"`.
  - `compression_php_zlib` (warn): `zlib.output_compression` is on in the site's pool or
    `.user.ini`: it compresses 304s and images, can compress twice, and defeats the guard;
    the fix names the ini line, or `offload`.
  - `compression_signed_in_unmasked` (warn): `signed_in = "on"` on a preset whose framework does
    not mask its CSRF token.
  - `compression_budget_exhausted` (info): streams went out uncompressed because a worker's
    limit was reached, with the count.
  - `compression_unavailable` (info): the build lacks a coding a site asks for, with the package.
  - No `compression_suggested`: health is silent on a site with `mode = "off"` (decided
    2026-10-30; off is the owner's default). The user brings a PageSpeed or Lighthouse report
    instead, and the MCP text tells the agent that its "enable text compression" item is this
    key on that site.
- **`server_status`:** a `compression` block: the codings the build has, answers and bytes
  saved per coding, counts per skip reason, the copies' bytes in the cache, the budget's refusals.
- **The access log:** the JSON format gets `encoding` and `bytes_identity`; the combined format
  is unchanged, since fail2ban's filters read it.
- **The MCP texts** say that `signed_in = "on"` is a security decision the user makes, that
  turning compression off inside an application is the application's switch, that `path_check`
  is how to see why a URL is not compressed, and that a PageSpeed or Lighthouse "enable text
  compression" finding means `response_compression = "on"` on that site. Before turning it on,
  the agent asks whether the site is served directly or behind a proxy such as Cloudflare, and
  explains the fit (decided 2026-10-30): a site served directly keeps the default `zstd, br,
  gzip` (the cheapest coding for 83 % of browsers, brotli for the rest); a site behind Cloudflare
  gains from `codings = ["br", "zstd", "gzip"]` at root, because Cloudflare asks the origin for
  brotli and passes it to visitors and ignores an origin's zstd; a site behind CloudFront or
  Fastly the same, since neither takes zstd from an origin. `site_show` names the order in effect.

## 10. Verification

The integration suite decodes every coding with the reference tools (`zstd -d`, `brotli -d`,
`gzip -d`) and compares byte for byte with the identity body, then covers each rule: HEAD's fields
against the GET's; `Vary` on identity and on 304; a weak ETag answered 304 by a weak-comparing and
an exact-comparing application; Range on a compressible page answered with an identity 206 or a
full 200, never a compressed 206; `no-transform` both ways; an upstream gzip passed through
untouched with `Vary` merged; PHP's zlib layer on, detected by health and passed through; the
guard's cookie, `Authorization` and address cases; HTTP/1.0 identity when the length is unknown;
the first SSE event at once and events spaced as sent; a static copy's ranges and tags as a disk
twin's; a disk twin kept over a copy; the copies' bytes in `cache.max_size`; the budget. h2spec
and the HTTP/3 attack suite unchanged. The `Accept-Encoding` parser (now with zstd) and the type
matcher get fuzz targets; a sanitizer run under compressed HTTP/2 load, since every inline loop
needs its yield budget.

The cookbook recipe shows the check administrators ask for:

```sh
curl -sS -o /dev/null -D - -H 'Accept-Encoding: zstd, br, gzip' https://shop.example/ | grep -i '^content-encoding\|^vary'
agensio ctl path-check shop.example / --accept-encoding 'gzip, br' --visitor signed_in
```

Measured before and after, every run under `bench/results/`:

| measurement | how | pass |
|---|---|---|
| the request path with compression built in, no site using it | `bench/ab.sh <base>` (wrk sends no `Accept-Encoding`), `-2`, `-3 -r 3` | within noise |
| static rows as a browser asks | new rows with `Accept-Encoding: gzip, deflate, br, zstd`: 1 KB (under `min_size`, flat) and 100 KB CSS (the copy, equal to the disk-twin row) | 1 KB flat; 100 KB equals the twin row |
| PHP pages | `bench/laravel/bench.sh` and the WordPress bed: off, zstd 3, br 4, gzip 5 | agensio µs per request, php-fpm µs, bytes per response, p50 and p99 recorded |
| proxy rows | `bench/ab.sh <base> -P` with the header; JSON and 100 KB bodies | the extra µs matches the encoder table; syscalls per request unchanged |
| memory | 1,000 slow clients reading compressed streams (`bench/h2/memory.sh` style) | RSS per stream about the window; the budget holds |
| streams | time to first SSE event and spacing with compression on | no added delay |
| cache fill | CPU and queue depth while a real site's assets get their copies at start | worker latency unchanged |
| the decision's cost | ineligible answers (images, small bodies) with the header | invisible in µs per request |

Then the test VPS's access logs: the share of zstd, brotli and gzip, and the bytes saved, for
real visitors.

## 11. Staged plan

Each step: unit and integration suites green, the A/B flat on the rows it touches, the docs
(configuration.md, the cookbook, keys.md, the MCP texts, CHANGELOG) in the same commit.

1. **The keys and the chooser.** The reference rows, the parser, `choose_encoding` with zstd and
   the `codings` order, the `compressible` MIME column and `types_add`, the `Stream` field set at
   routing. No encoder yet: the A/B proves a site without the key pays nothing and one with it
   pays one test.
2. **Static copies in memory** (section 5): the fill thread, the entry's copies, the budget, the
   strong tags, status's bytes. Measured on the static rows with a browser's header.
3. **Buffered dynamic answers** (section 6, the up-to-64 KB case) with gzip through zlib: the
   decision, the weak ETag, `Vary`, HEAD, 304, `no-transform`, already-encoded passthrough. The
   Laravel and WordPress beds measured.
4. **zstd and brotli** as optional dependencies (CMake, the packages, `-t`'s refusal, status's
   list), the capped windows, the padding for `signed_in = "on"`.
5. **The signed-in guard** (section 7): the preset table, `session_cookies`, the `off` paths,
   `user_confirmed` in the bridge, health's `compression_signed_in_unmasked`.
6. **Streamed answers** (section 6): `CompressedBody`, flushes, the budget, SSE and
   `event_streams`, `offload`. The memory and streams rows measured.
7. **The agent interface** (section 9): `path_check`'s arguments and reasons, health's findings
   with the probes, status's block, the log fields, the cookbook's check.
8. **Honouring `X-Accel-Buffering: no`, `Incremental: ?1` and `text/event-stream`** for buffered
   exchanges, its own step and commit, independent of compression.

## 12. Decisions

All taken by the owner on 2026-10-30:

1. Off by default: no CPU spent unless a site asks.
2. `signed_in = "off"` once a site is on; `on` is the user's decision in person.
3. libzstd and libbrotli as optional dependencies beside zlib.
4. Static copies made by agensio in memory only, within `cache.max_size`, never on disk (an
   application's integrity check, Nextcloud's or WordPress's, must never see them).
5. `If-None-Match` forwarded as it came, with plain weakening of the tag (nginx's way); no
   translation unless a preset's application shows the miss.
6. No health finding nudging an `off` site; the user's PageSpeed or Lighthouse report is the
   trigger, and the MCP text maps its finding to the key.
7. The default order `zstd, br, gzip`; the agent asks whether the site is behind a proxy and
   advises brotli first behind Cloudflare, CloudFront or Fastly.

## 13. Sources

`reports/Web server response compression.md` and the six notes under `research_notes/Web server
response compression/`, each with its URLs: `nginx_apache_litespeed.md`,
`caddy_h2o_iis_haproxy_traefik_envoy.md`, `standards_security.md` (RFC 9110, 9111, 9112, 9113,
9114, 1952, 7932, 8878, 9659, 9842; CRIME, TIME, BREACH, HEIST, Rupture), `cdn_browsers_cost.md`
(with the benchmark under `cdn_browsers_cost_bench/`), `application_side.md`,
`administrator_needs.md`.
