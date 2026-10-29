# Response compression in Caddy, h2o, Microsoft IIS, HAProxy, Traefik and Envoy

Research date: 2026-10-26. Method: official documentation fetched directly, then the source on each project's default branch (raw GitHub files fetched on 2026-10-26), with release tags checked through the GitHub compare API. Versions current on that date: Caddy v2.11.7 (2026-10-03), h2o has no tagged release since v2.3.0-beta2 (2019-08-12) and is used from `master`, IIS 10.0 (IIS Compression extension v1.0.6502, 2022-03-10), HAProxy 3.4.0 stable (2026-06-03) with 3.5-dev9 on master, Traefik v3.7.16 (2026-10-20), Envoy v1.40 (2026-10-13). "Inference" means read from code by me, not stated by the project.

## Caddy: `encode` and `file_server precompressed`

### Takeaway
Core Caddy compresses on the fly with zstd and gzip only. Brotli is core only for serving precompressed `.br` sidecars; on-the-fly brotli needs a third-party plugin. A bare `encode` enables `zstd gzip`, `minimum_length` is 512, and a built-in Content-Type allowlist applies. Caddy keeps strong ETags strong by appending `-<encoding>` inside the quotes, and strips that suffix from `If-None-Match` before the request goes upstream. It always sets `Vary: Accept-Encoding`, drops `Accept-Ranges`, never encodes a 206, and skips responses that already carry `Content-Encoding` or `no-transform`. Since 2026 it streams SSE and RFC 10036 `Incremental: ?1` responses without buffering.

### Cited Findings
**Syntax and formats**
- Caddyfile syntax: `encode [<matcher>] [<formats...>] { gzip [<level>]; zstd [<level>]; minimum_length <length>; match <inline_response_matcher> }`. The docs say: "If multiple encodings are enabled, the encoding is chosen based the request's Accept-Encoding header; if the client has no strong preference (q-factor), then the first supported encoding is used. If omitted, `zstd` (preferred) and `gzip` are enabled by default." — [Caddy docs: encode](https://caddyserver.com/docs/caddyfile/directives/encode)
- The Caddyfile parser falls back to `remainingArgs = []string{"zstd", "gzip"}` when no format is given, and sets `enc.Prefer` to "the order in which the encoders were defined". So in a Caddyfile the order you write the formats is the server preference used for q-value ties. — [caddy encode/caddyfile.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/caddyfile.go)
- In JSON config with no `prefer`, `Provision` fills Prefer from `zstd`, `br`, `gzip`, in that order, keeping only the enabled ones. This comes from the commit "encode: prioritize zstd and br over gzip in content negotiation (#7772)" (2026-05-28), which shipped in v2.11.4 (2026-06-03) and was absent from v2.11.3. — [encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go); [PR #7772](https://github.com/caddyserver/caddy/pull/7772); [releases](https://github.com/caddyserver/caddy/releases)
- The default `zstd gzip` for a bare `encode` arrived with the commit "encode: good defaults (#6737)" (2024-12-10), included in v2.9.0 (2024-12-31). — [PR #6737](https://github.com/caddyserver/caddy/pull/6737)
- The core encoder modules are `http.encoders.gzip` and `http.encoders.zstd`, both from `github.com/klauspost/compress`. The `modules/caddyhttp/encode/brotli/` directory holds only `brotli_precompressed.go`, which registers `http.precompressed.br` with suffix `.br`. There is no core brotli encoder. — [caddy encode/gzip/gzip.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/gzip/gzip.go); [zstd.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/zstd/zstd.go); [brotli_precompressed.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/brotli/brotli_precompressed.go)
- On-the-fly brotli comes from third-party plugins:
  - `dunglas/caddy-cbrotli` (cgo, the C reference library) registers `http.encoders.br`. Quality runs 0-11, "defaults to 6"; the window runs 10-24, "defaults to auto". Usage is `encode zstd br gzip`. — [dunglas/caddy-cbrotli README](https://github.com/dunglas/caddy-cbrotli)
  - `ueffel/caddy-brotli` is pure Go (go-brrr), with level 0-11 and "default is 4". Its README advises that within Caddy "you probably shouldn't use brotli encoding as primary compression algorithm. Zstd and gzip are the better choice to maximize throughput." — [ueffel/caddy-brotli README](https://github.com/ueffel/caddy-brotli)

**Levels**
- gzip: `Level int`, with `defaultGzipLevel = 5` ("Informed from http://blog.klauspost.com/gzip-performance-for-go-webservers/"). The value must be at least klauspost's `gzip.StatelessCompression` and at most `gzip.BestCompression`. — [gzip.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/gzip/gzip.go)
- zstd:
  - The level is a string, one of `fastest`, `better`, `best` or `default`. The docs say: "The default compression level is roughly equivalent to the default Zstandard mode (level 3)." — [Caddy docs: encode](https://caddyserver.com/docs/caddyfile/directives/encode)
  - The encoder window is fixed at 128 KiB: "The default of 8MB for the window is too large for many clients, so we limit it to 128K". It also sets `WithEncoderConcurrency(1)` and `WithZeroFrames(true)`.
  - The `disable_checksum` subdirective sets `Checksum` (JSON `checksum`); if unset, the library default is kept. — [zstd.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/zstd/zstd.go)
  - The zstd level became configurable in "encode: Configurable compression level for zstd (#6140)" (2024-04-16), in v2.8.0. The checksum option came with "encode: make zstd checksum configurable (#7586)" (2026-03-28), in v2.11.3. — [PR #6140](https://github.com/caddyserver/caddy/pull/6140); [PR #7586](https://github.com/caddyserver/caddy/pull/7586)

**Minimum length**
- `minimum_length` defaults to 512 (`const defaultMinLength = 512`). A response is encoded only when a write exceeds MinLength or `Content-Length` > MinLength; the test is strictly greater. When Content-Type is missing, it is sniffed with `http.DetectContentType` on the first write. — [encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go)
- Docs: "Server-sent events responses (`Content-Type: text/event-stream`) and responses with the `Incremental: ?1` header field (RFC 10036) are not held back to reach this threshold: their headers are sent to the client immediately, and the body is streamed as it is written." — [Caddy docs: encode](https://caddyserver.com/docs/caddyfile/directives/encode)

**Default content types**
- When `match` is unset, the source matches Content-Type against `application/atom+xml*`, `application/eot*`, `application/font*`, `application/geo+json*`, `application/graphql+json*`, `application/graphql-response+json*`, `application/javascript*`, `application/json*`, `application/ld+json*`, `application/manifest+json*`, `application/opentype*`, `application/otf*`, `application/rss+xml*`, `application/truetype*`, `application/ttf*`, `application/vnd.api+json*`, `application/vnd.ms-fontobject*`, `application/wasm*`, `application/x-httpd-cgi*`, `application/x-javascript*`, `application/x-opentype*`, `application/x-otf*`, `application/x-perl*`, `application/x-protobuf*`, `application/x-ttf*`, `application/xhtml+xml*`, `application/xml*`, `font/ttf*`, `font/otf*`, `image/svg+xml*`, `image/vnd.microsoft.icon*`, `image/x-icon*`, `multipart/bag*`, `multipart/mixed*` and `text/*`. The code comment says the list is "based on https://developers.cloudflare.com/speed/optimization/content/brotli/content-compression/". — [encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go)
- The docs page lists `header Content-Type font/*` where the source has `font/ttf*` and `font/otf*`, so the docs are out of date. The source narrowed with "encode: Don't compress already-compressed fonts (#6432)" (2024-07-04), released in v2.9.0, which leaves woff/woff2 out. — [Caddy docs: encode](https://caddyserver.com/docs/caddyfile/directives/encode); [PR #6432](https://github.com/caddyserver/caddy/pull/6432)

**Negotiation (`AcceptedEncodings`)**
- Accept-Encoding is split on `,` and q parsed per token. Tokens with q < 0.00001 are dropped. The sort is by descending q, then by position in `Prefer`.
- If `Sec-WebSocket-Key` is present, every non-identity encoding is dropped ("don't encode WebSocket handshakes").
- An empty or missing Accept-Encoding gives no encoding. — [encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go)
- Inference: `*` and `identity` are never expanded or acted on. They are not in `writerPools`, so they are skipped, and `Accept-Encoding: *` alone gets an identity response. `identity;q=0` produces no 406.

**no-transform and existing Content-Encoding**
- `isEncodeAllowed` returns false when `Cache-Control` contains `no-transform`. It is checked on the request headers in `ServeHTTP` and on the response headers in `init()`.
- `init()` encodes only when `hdr.Get("Content-Encoding") == ""`, so upstream-compressed or precompressed responses pass through untouched. — [encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go)

**Headers changed when encoding**
- `init()` deletes `Content-Length`, sets `Content-Encoding`, adds `Vary: Accept-Encoding` if absent, and deletes `Accept-Ranges` ("we don't know ranges for dynamically-encoded content"). — [encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go)
- ETag: a strong ETag is rewritten to `"<orig>-<encoding>"`, for example `"abc"` becomes `"abc-zstd"`. The code comment reads "to comply with RFC 9110 section 8.8.3(.3), we modify the Etag when encoding by appending a hyphen and the encoder name". Weak (`W/`) ETags are left as they are.
- On the request side, `-<encName>"` is stripped from `If-None-Match` before calling the next handler, "so the upstream handlers can still honor client caches without knowing about our changes". This arrived in "encode: Improve Etag handling (fix #5849)" (2024-04-18), in v2.8.0. — [encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go); [issue #5849](https://github.com/caddyserver/caddy/issues/5849)
- A fix for "ETag list matching (#8128)" (2026-10-03) is on master but not in v2.11.7. — [caddy commits](https://github.com/caddyserver/caddy/commits/master/modules/caddyhttp/encode)

**Status codes, HEAD, 304, errors**
- `WriteHeader(206)` sets `disabled = true` ("partial representations must not be dynamically re-encoded").
- A 304 gets `Vary: Accept-Encoding` added (RFC 9110 15.4.5, #5849).
- 1xx is written immediately, and so is a 2xx answer to CONNECT.
- If the next handler returns an error, encoding is disabled, so `handle_errors` output is not corrupted. — [encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go)
- HEAD: `Close()` calls `init()` when nothing was written but `Content-Length` > MinLength. "Don't write an empty encoded stream for HEAD responses (#8150)" (2026-10-09) is on master but not in v2.11.7. — [encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go); [commit history](https://github.com/caddyserver/caddy/commits/master/modules/caddyhttp/encode)

**Streaming and flushing**
- `FlushError` delays the flush until the header has been decided, then flushes the encoder and the underlying writer.
- SSE (`text/event-stream`, parsed exactly) and `Incremental: ?1` responses get their headers written immediately and are flushed after every write. "encode: flush headers immediately for server-sent events responses (#7905)" (2026-07-31) shipped in v2.11.6. "feat: implement the Incremental header field (RFC 10036) (#8020)" (2026-10-03) shipped in v2.11.7. — [encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go); [PR #7905](https://github.com/caddyserver/caddy/pull/7905); [PR #8020](https://github.com/caddyserver/caddy/pull/8020)
- `ReadFrom` sniffs 512 bytes and then uses the wrapped writer's `ReadFrom` (sendfile) when the response is not being compressed: "encode: try to use sendfile when compression is not used (#6749)" (2024-12-20). — [encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go)
- `reverse_proxy` `flush_interval`: "By default, no periodic flushing is done. A negative value (typically -1) suggests 'low-latency mode'". The option is ignored, and responses flush immediately, for `Content-Type: text/event-stream`, `Incremental: ?1`, an unknown Content-Length, or "HTTP/2 on both sides of the proxy, `Content-Length` is unknown, and `Accept-Encoding` is either not set or is 'identity'". — [Caddy docs: reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)

**Reverse proxy and upstream compression**
- "when using the `http` transport, the `Accept-Encoding: gzip` header will be set, if it is missing in the request from the client. This allows the upstream to serve compressed content if it can. This behavior can be disabled with `compression off` on the transport." — [Caddy docs: reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
- The transport's `Compression *bool` ("Default: true") maps to `rt.DisableCompression = !*h.Compression`. — [httptransport.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/reverseproxy/httptransport.go)
- Go's `Transport.DisableCompression` docs: when the Transport itself requested gzip, "it's transparently decoded in the Response.Body". — [Go net/http Transport](https://pkg.go.dev/net/http#Transport)

**file_server precompressed**
- Syntax: `precompressed [<formats...>]`. "Supported formats are `gzip` (`.gz`), `zstd` (`.zst`) and `br` (`.br`). If formats are omitted, they default to `br zstd gzip` (in that order)." Also: "All file lookups will look for the existence of the uncompressed file first." — [Caddy docs: file_server](https://caddyserver.com/docs/caddyfile/directives/file_server)
- The JSON field is `precompressed_order`: "If no order specified here, the first encoding from the Accept-Encoding header that both client and server support is used". — [staticfiles.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/fileserver/staticfiles.go)
- file_server always adds `Vary: Accept-Encoding`: "the headers should contain 'Vary: Accept-Encoding' even when not compressed so caches can craft a reliable key (according to REDbot results) see #5849".
- A sidecar's ETag is computed from the sidecar's own mtime and size (`calculateEtag(compressedInfo)`), so each encoding has a distinct strong ETag. The format is `"<mtime-ns base36>-<size base36>"`.
- `Content-Length` is set from the sidecar's size when the request has no `Range`. A Range request gets a 206 slice of the compressed sidecar (issues #7040 and #7250 are referenced). `etag_file_extensions` reads ETags from sidecar files. — [staticfiles.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/fileserver/staticfiles.go); [fileserver/caddyfile.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/fileserver/caddyfile.go)

### Inferences
- Caddy's ETag suffix (`"x-gzip"`) is the one approach in this set that keeps a strong validator per representation. h2o, HAProxy and Envoy (with `weaken_etag_on_compress`) weaken it instead, and Envoy's default removes it.
- In a Caddyfile, `encode gzip zstd` makes gzip win ties: the written order is the prefer list. Only JSON configs without `prefer` get the zstd > br > gzip default from v2.11.4.
- Fonts: TTF and OTF are compressed while WOFF/WOFF2 are not, because the `font/*` wildcard was replaced by `font/ttf*` and `font/otf*`.

### Gaps
- The docs give no default `prefer`/`precompressed_order` beyond what is quoted. The exact change set of "good defaults" (#6737) was not read; only its title and inclusion in v2.9.0 were verified.
- The inclusion of #6749 (sendfile) in v2.9.0 is likely from the dates but was not verified; the GitHub API rate limit was exhausted.

## h2o: `compress`, `compress-minimum-size`, `file.send-compressed`

### Takeaway
h2o's compressor is off by default. `compress: ON` enables gzip at quality 1, brotli at quality 1 and zstd at level 3 when the build includes them, prefers br > zstd > gzip, and sets a minimum size of 100 bytes. It compresses only status 200, non-HEAD, HTTP/1.1+ responses whose MIME type is marked `is_compressible`, and an upstream can steer it with `x-compress-hint`. It weakens the ETag with `W/`, sets `Accept-Ranges: none`, adds `Vary: accept-encoding`, and flushes per chunk while streaming. On-the-fly zstd landed on master on 2026-06-09; no h2o release has shipped since 2019.

### Cited Findings
**Documentation**
- Docs: "If `x-compress-hint` response header does not exist or the value is `auto`, then whether if the response is considered compressible depends on the `is_compressible` attribute assigned to the content type (see `file.mime.addtypes`). If `x-compress-hint` response header exists and the value is `on`, the response is always considered to be compressible. If the value of the response header is set to `off`, then the response never gets compressed." — [h2o Compress Directives](https://h2o.examp1e.net/configure/compress_directives.html) (read from [srcdoc/configure/compress_directives.mt on master](https://github.com/h2o/h2o/blob/master/srcdoc/configure/compress_directives.mt))
- `compress` takes levels global/host/path/extension, defaults to `compress: OFF`, and dates from version 2.0: "If the argument is `ON`, gzip is enabled for compression. Brotli and zstd will also be enabled when the server was built with their support." It continues: "The default qualities specified for each compression method are: 1 for gzip, 1 for brotli, and 3 for zstd. To override the qualities, use a mapping ... (gzip: 1-9, br: 0-11, zstd: 1-22)." And: "When multiple algorithms are enabled and the client supports more than one, H2O prefers brotli, then zstd, then gzip." The examples are `compress: ON`, `compress: [ gzip, br, zstd ]` and `compress: { zstd: 7 }`. — [h2o Compress Directives](https://h2o.examp1e.net/configure/compress_directives.html)
- Doc defect: the docs link "Brotli" to RFC 8878 (which is zstd) rather than RFC 7932. — [srcdoc compress_directives.mt](https://github.com/h2o/h2o/blob/master/srcdoc/configure/compress_directives.mt)
- `compress-minimum-size` defaults to `compress-minimum-size: 100` (since 2.0): "Defines the minimum size a files needs to have in order for H2O to compress the request." `gzip: ON|OFF` is "Equivalent to `compress: [ gzip ]`" (since 1.5). — [h2o Compress Directives](https://h2o.examp1e.net/configure/compress_directives.html)

**Configurator source**
- `DEFAULT_GZIP_QUALITY 1`, `DEFAULT_BROTLI_QUALITY 1`, `DEFAULT_ZSTD_QUALITY 3`. Two presets exist: `all_on = {100, ...}` (min_size 100) and `all_off = {0, {-1},{-1},{-1}}`.
- A sequence or mapping argument starts from `*self->vars = all_off` and then enables the listed algorithms, and so does `gzip: ON`. — [lib/handler/configurator/compress.c](https://github.com/h2o/h2o/blob/master/lib/handler/configurator/compress.c)
- Inference from that code: only `compress: ON` sets min_size to 100. The sequence, mapping and `gzip:` forms leave min_size at 0 unless `compress-minimum-size` is set. I did not check whether directive order within a YAML level matters.

**When it compresses (`on_setup_ostream`)**
- The handler skips when `req->version < 0x101` (HTTP/1.0), when `req->res.status != 200`, and for `HEAD`. `x-compress-hint` is DISABLE, ENABLE, ENABLE_BR, ENABLE_GZIP, ENABLE_ZSTD or AUTO. Under AUTO it requires `mime_attr->is_compressible` and `req->res.content_length >= min_size`.
- It skips when the response already has `Content-Encoding`. Brotli is tried first, then zstd, then gzip.
- When it compresses, it sets `content_length = SIZE_MAX`, adds `Content-Encoding`, and sets `Vary: accept-encoding`. It prefixes a non-weak ETag with `W/` ("Do not happend W/ to an already weak etag", 2023-03-02) and sets `Accept-Ranges: none`.
- When the client offers an encoding of the response type's set but none of them is enabled, it still sets `Vary: accept-encoding` ("let proxies know that we looked at accept-encoding"). — [lib/handler/compress.c](https://github.com/h2o/h2o/blob/master/lib/handler/compress.c)
- Inference: `compress.c` has no `Cache-Control: no-transform` check. A response of unknown length (content_length SIZE_MAX) always passes the minimum-size test.
- `x-compress-hint` is read from proxied responses: `on`, `off`, `gzip`, `br` and `zstd` map to hints, anything else is AUTO. The field is removed before forwarding (`goto Skip`). — [lib/core/proxy.c](https://github.com/h2o/h2o/blob/master/lib/core/proxy.c)

**Accept-Encoding parsing**
- `h2o_get_compressible_types` tokenises Accept-Encoding on `,` and matches tokens case-insensitively against exactly `gzip`, `br` and `zstd`. — [lib/core/util.c](https://github.com/h2o/h2o/blob/master/lib/core/util.c); [lib/common/string.c h2o_next_token](https://github.com/h2o/h2o/blob/master/lib/common/string.c)
- Inference: h2o does not parse q-values. The whole token, such as `gzip;q=0.5`, is compared, so a token with any parameter (`q=0` or `q=0.8`) is not recognised, and `*` is ignored.

**Default compressible types**
- `h2o_mimemap_get_default_attributes` marks these compressible: `text/css`, `application/ecmascript`, `application/javascript`, `text/ecmascript` and `text/javascript` (with priority HIGHEST); `application/json`, `application/xml`, any `text/*`, and any type ending in `+json` or `+xml` (so `image/svg+xml`). Everything else is not compressible unless `file.mime.addtypes` sets `is_compressible`. — [lib/handler/mimemap.c](https://github.com/h2o/h2o/blob/master/lib/handler/mimemap.c)

**Streaming**
- The handler caps `preferred_chunk_size` at `BUF_SIZE 8192` ("compress by 8192 bytes"). — [compress.c](https://github.com/h2o/h2o/blob/master/lib/handler/compress.c)
- gzip uses `deflateInit2(..., quality, Z_DEFLATED, WINDOW_BITS, 8, ...)` and ends each send batch with `Z_SYNC_FLUSH` while the response is in progress, `Z_FINISH` at the end. — [lib/handler/compress/gzip.c](https://github.com/h2o/h2o/blob/master/lib/handler/compress/gzip.c)
- brotli uses `BROTLI_OPERATION_FLUSH`/`FINISH` and shrinks `LGWIN` for small known lengths. zstd uses `ZSTD_e_flush`/`ZSTD_e_end` and shrinks `windowLog` for small responses. — [brotli.c](https://github.com/h2o/h2o/blob/master/lib/handler/compress/brotli.c); [zstd.c](https://github.com/h2o/h2o/blob/master/lib/handler/compress/zstd.c)

**History**
- "add on-the-fly zstd compression" is commit 6627dd53 (2026-06-09). A follow-up made cmake use the system zstd (2026-06-25). ".zstd file in send-compressed" was supported from 2024-03-23. The newest tag is v2.3.0-beta2 (2019-08-12). — [h2o commits for compress.c](https://github.com/h2o/h2o/commits/master/lib/handler/compress.c); [h2o tags](https://github.com/h2o/h2o/tags)

**file.send-compressed**
- Default `file.send-compressed: OFF`, levels global/host/path. "If set to `ON`, the handler looks for a file with `.br`, `.zst`, or `.gz` appended and sends the file, if the client is capable of transparently decoding a brotli, zstd, or gzip-encoded response ... When both the client and the server support multiple content encodings, the encoding chosen is the first one listed in the following order: brotli, zstd, gzip."
- "Starting from version 2.2, `gunzip` is also supported ... the handler will send an uncompressed response by dynamically decompressing the `.gz` file if the client and the server failed to agree on using a pre-compressed file as the response and if a non-compressed file was not found."
- `file.send-gzip` was "Obsoleted in 2.0. Synonym of `file.send-compressed`." — [h2o File Directives](https://h2o.examp1e.net/configure/file_directives.html#file.send-compressed)
- Source: `TRY_VARIANT` order is br (`.br`), zstd (`.zst`), gzip (`.gz`), then the deprecated zstd `.zstd`. Variants are tried only for HTTP/1.1+. With send-compressed on, `send_vary` sets `Vary: accept-encoding` on every response, including 304s through `add_headers_unconditional`. — [lib/handler/file.c](https://github.com/h2o/h2o/blob/master/lib/handler/file.c)
- Inference: the ETag comes from the opened variant's file cache entry, so it differs per encoding.

### Inferences
- h2o's rules are the strictest on status (200 only) and the loosest on negotiation (no q-values, no `*`, no no-transform check).
- Because compressing sets `Accept-Ranges: none` while `file.send-compressed` serves real files, Range requests work against precompressed variants but not against dynamically compressed responses.

### Gaps
- I did not verify whether h2o.examp1e.net already shows the master text with zstd; it may lag.
- 206 is excluded implicitly by the status-200 rule. I found no explicit Range handling in the compressor.
- The behaviour of `file.mime.addtypes` `is_compressible` overrides was taken from the docs reference only, not read in detail.

## Microsoft IIS: `<urlCompression>`, `<httpCompression>`, IIS Compression (brotli)

### Takeaway
IIS has a static module, installed by default, and a dynamic module, which is optional. Static compression is cached on disk and applies only to frequently hit files: by default at least 2 hits in 10 seconds and at least 2,700 bytes. CPU thresholds switch it off and on: dynamic off at 90 % and back on below 50 %, static off at 100 %. Out of the box it supports only gzip and deflate (`gzip.dll`), at static level 7 and dynamic level 0. Brotli comes from Microsoft's separately installed IIS Compression (`iisbrotli.dll`, `iiszlib.dll`), and from IIS 10.0 version 1803 the server's scheme order breaks q-value ties. I found no zstd in any IIS documentation.

### Cited Findings
**Modules and setup**
- "IIS 7 caches compressed static content in the path that is specified by the directory attribute ... IIS 7 performs dynamic compression each time a client requests the content, but the compressed version is not cached to disk." — [IIS httpCompression](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpcompression/)
- "HTTP compression is usually available on the default installation of IIS 7 and later. However, only static compression is installed by default." — [IIS httpCompression](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpcompression/)

**`<urlCompression>`** (site, application or folder level)
- `doStaticCompression` defaults to true. `doDynamicCompression` defaults to true; "In IIS 7.5, the default value of the doDynamicCompression attribute changed from false to true".
- `dynamicCompressionBeforeCache` defaults to false: "When dynamicCompressionBeforeCache is false, IIS returns the uncompressed response until the compressed response has been added to the cache directory." — [IIS urlCompression](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/urlcompression)

**`<httpCompression>` attributes** ("These attributes can only be configured at server level")
- `cacheControlHeader` defaults to `max-age=86400`, used only with `sendCacheHeaders`.
- `directory` defaults to `%SystemDrive%\inetpub\temp\IIS Temporary Compressed Files`.
- `doDiskSpaceLimiting` defaults to `true`.
- `dynamicCompressionBufferLimit` defaults to `65536` ("maximum amount of dynamically compressed data that IIS will buffer before flushing the buffer to a client"; IIS 7.5+).
- `dynamicCompressionDisableCpuUsage` defaults to `90`.
- `dynamicCompressionEnableCpuUsage` defaults to `50`.
- `expiresHeader` defaults to `Wed, 01 Jan 1997 12:00:00 GMT`.
- `maxDiskSpaceUsage` defaults to `100` (MB; per application pool in IIS 7).
- `minFileSizeForComp` defaults to `2700` in IIS 7.5 ("for IIS 7.0 the default value was 256").
- `noCompressionForHttp10` defaults to `true`.
- `noCompressionForProxies` defaults to `true`.
- `noCompressionForRange` defaults to `true` ("whether compression is disabled for HTTP requests that include the Range header").
- `sendCacheHeaders` defaults to `false`.
- `staticCompressionDisableCpuUsage` defaults to `100`.
- `staticCompressionEnableCpuUsage` defaults to `50`.
- `staticCompressionIgnoreHitFrequency` defaults to `False` (IIS 8.5+): "If the behavior is not disabled, a hit rate of greater than or equal to two hits in 10 seconds will result in compression of the static content."
- "Average CPU utilization is calculated every 30 seconds." — [IIS httpCompression](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpcompression/)

**Default MIME types and schemes**
- The default `applicationHost.config` (IIS 7) has `<scheme name="gzip" dll="%Windir%\system32\inetsrv\gzip.dll" />`. Both dynamicTypes and staticTypes list `text/*`, `message/*` and `application/javascript` as enabled and `*/*` as `enabled="false"`. — [IIS httpCompression](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpcompression/)
- `dynamicTypes` can be set at site level from IIS 10.0. — [IIS httpCompression](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpcompression/)
- `<scheme>` attributes:
  - `dll`.
  - `doDynamicCompression`, default true.
  - `doStaticCompression`, default true; a non-NTFS store disables static compression.
  - `dynamicCompressionLevel`, "levels range from 0 ... to 10", default `0`.
  - `staticCompressionLevel`, range 0-10, "0 means that compression is disabled", default `7`.
  - "By default, only the Gzip compression scheme is available in IIS 7"; Deflate is enabled programmatically. Both are in `gzip.dll`. — [IIS scheme](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpcompression/scheme)
- Static flow: "If a fresh, compressed version of the static file is found in the directory, it is sent to the client browser. If a fresh, compressed version of the file is not found ... IIS sends the requested file in uncompressed form, and adds that file to the background compression queue." — [IIS scheme](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpcompression/scheme)

**IIS Compression extension**
- "IIS Compression is a bundle of two IIS compression scheme providers, iisbrotli.dll and iiszlib.dll ... iisbrotli.dll supports Brotli compression, while iiszlib.dll supports both Gzip and Deflate compression."
- The installer "registers iisbrotli.dll as the br (Brotli) compression scheme provider ... It also replaces the default gzip compression scheme provider gzip.dll with iiszlib.dll".
- Its sample staticTypes add `application/atom+xml`, `application/xaml+xml` and `image/svg+xml`, and its sample dynamicTypes add `application/x-javascript`. — [IIS Compression Overview](https://learn.microsoft.com/en-us/iis/extensions/iis-compression/iis-compression-overview) (last updated 2022-06-14)
- Level ranges: `gzip.dll` 0 (best speed) to 10; `iiszlib.dll` 0 (no compression), 1 (best speed) to 9; `iisbrotli.dll` 0 to 11. "Level 0 of iiszlib.dll specifies no compression rather than best-speed compression. The default IIS dynamicCompressionLevel attribute value ... is 0 as well. Therefore, dynamicCompressionLevel needs to be explicitly set above 0 to allow iiszlib.dll to compress dynamically generated contents." — [Using IIS Compression](https://learn.microsoft.com/en-us/iis/extensions/iis-compression/using-iis-compression)
- Negotiation, IIS 10.0 version 1803 and later: "A compression scheme appearing on the top of the <scheme> collection is prioritized over the one appearing after, if their quality values specified in the Accept-Encoding request header value are the same. A compression scheme with higher quality value ... is prioritized ... regardless of their order".
- Before 1803 the client's header order decided ties: "IIS always prioritizes gzip over br for the typical scenario that the browser sets Accept-Encoding: gzip, deflate, br". The workaround was a URL Rewrite rule that sets `HTTP_ACCEPT_ENCODING` to `br`. — [Using IIS Compression](https://learn.microsoft.com/en-us/iis/extensions/iis-compression/using-iis-compression)
- The latest IIS.Compression release is v.1.0.6502 (2022-03-10). — [microsoft/IIS.Compression releases](https://github.com/microsoft/IIS.Compression/releases)

**Vary**
- With dynamic compression enabled, "a Vary header is overwritten as 'Accept-Encoding'": an app's `Vary: User-Agent` became `Vary: Accept-Encoding`. The hotfix covers Windows 7 SP1 and 2008 R2 SP1 through 8.1 and 2012 R2. — [Microsoft KB 2877816](https://support.microsoft.com/kb/2877816)
- An IIS blog post (affecting IIS 5.0, 6.0 and 7.0) called this "by design" and noted the 2013 patch. — [IIS compression overwrites the VARY header](https://learn.microsoft.com/en-us/archive/blogs/chaun/iis-compression-overwrites-the-vary-header)

### Inferences
- IIS is the only server here with load-adaptive compression (the CPU thresholds) and a hit-frequency gate. A cold or rarely requested static file is served uncompressed, which matters behind CDNs; Microsoft's own example for `staticCompressionIgnoreHitFrequency` is an edge cache.
- With the in-box `gzip.dll`, the dynamic default (level 0) is "best speed". After installing iiszlib, the same default means "no compression".

### Gaps
- None of the fetched official pages says how IIS treats a response that already carries `Content-Encoding` from an application or handler.
- No official page fetched says how IIS changes, or keeps, the ETag of a compressed response.
- No IIS zstd support was found in official sources; one search and the docs reviewed.
- The current default MIME lists on Windows Server 2022/2025 were not verified; the quoted defaults are the IIS 7 sample and the IIS Compression installer sample.

## HAProxy: `compression algo/type/offload/minsize`, filters, decompression

### Takeaway
HAProxy compresses only with gzip, deflate or raw-deflate (built-in libslz by default, zlib optional), plus `identity` for debugging; it has no brotli or zstd. Compression is off unless configured, and with no `compression type` every non-multipart Content-Type is compressed. It applies only to status 200-203 on HTTP/1.1+ that is not HEAD, and skips Content-Encoding, no-transform, invalid or multiple ETags and old Mozilla/4 agents. It weakens strong ETags, appends `Vary: Accept-Encoding`, and switches to chunked. The global level defaults to 1 (`tune.comp.maxlevel`), with rate and CPU governors. `minsize-res` (default 0) arrived in 3.2. The `comp-req`/`comp-res` filters arrived in 3.4. A decompression feature exists only on 3.5-dev.

### Cited Findings
**Keywords and algorithms**
- Keywords: `compression algo <algorithm> ...`, `algo-req <algorithm>`, `algo-res <algorithm> ...`, `type <mime type> ...`, `type-req`, `type-res`. Sections: defaults, frontend, listen, backend. — [HAProxy configuration.txt (master, 3.5)](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt); [docs.haproxy.org 3.4](https://docs.haproxy.org/3.4/configuration.html)
- Supported algorithms:
  - `identity` ("mostly for debugging").
  - `gzip` ("only available when support for zlib or libslz was built in").
  - `deflate` ("ambiguous support on many browsers and no support at all from recent ones. It is strongly recommended not to use it").
  - `raw-deflate` ("same as 'deflate' without the zlib wrapper ... Do not use it in conjunction with 'deflate'").
  - The source table `comp_algos[]` lists only identity, deflate, raw-deflate and gzip, under `USE_SLZ` or `USE_ZLIB`. — [configuration.txt](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt); [src/compression.c](https://github.com/haproxy/haproxy/blob/master/src/compression.c)
- libslz "is embedded in haproxy. It is enabled by default as it is very fast and does not keep a copy of the contents in memory". `USE_ZLIB=1` disables SLZ. "Zlib compresses a bit better than libslz but at the expense of more CPU usage (about 3.5 times more minimum), and a huge memory usage (~260 kB per compressed stream)." — [HAProxy INSTALL](https://github.com/haproxy/haproxy/blob/master/INSTALL)

**Behaviour**
- "If backend servers support HTTP compression, these directives will be no-op: HAProxy will see the compressed response and will not compress again."
- Compression is disabled when:
  - the request does not advertise a supported algorithm;
  - "the response message is not HTTP/1.1 or above";
  - "HTTP status code is not one of 200, 201, 202, or 203";
  - the response has neither Content-Length nor chunked Transfer-Encoding;
  - the Content-Type starts with "multipart";
  - `Cache-control` contains `no-transform`;
  - the User-Agent matches "Mozilla/4" (unless MSIE 6 with XP SP2, or MSIE 7 and later);
  - the response has a `Content-Encoding`;
  - "The response contains an invalid 'ETag' header or multiple ETag headers";
  - "The payload size is smaller than the minimum size (see compression minsize-res)".
- "Note: The compression does not emit the Warning header." — [configuration.txt](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)

**Source (`flt_http_comp.c`)**
- The response path also fails for `HEAD` (`txn->meth == HTTP_METH_HEAD`) and for bodyless messages. Both the request and the response must be HTTP/1.1.
- The size check uses the known content length (`kip`) when Content-Length is present or the message has ended.
- It honours `global.comp_rate_lim` (`maxcomprate`) and `compress_min_idle` (`maxcompcpuusage`). — [src/flt_http_comp.c](https://github.com/haproxy/haproxy/blob/master/src/flt_http_comp.c)
- `type` matching is a case-insensitive prefix compare (`strncasecmp(ctx.value.ptr, comp_type->name, comp_type->name_len)`).
- With no `type` configured, any non-multipart response is compressed, including one without a Content-Type. With `type` configured, a response lacking a Content-Type is not compressed ("a content-type was required"). — [src/flt_http_comp.c](https://github.com/haproxy/haproxy/blob/master/src/flt_http_comp.c)
- Inference: the default is "all types". HAProxy ships no default MIME allowlist, and a `type text/html` entry also matches `text/html; charset=...`.
- Headers rewritten when compressing:
  - adds `Transfer-Encoding: chunked` when the message was not chunked, and removes every `Content-Length`;
  - converts a strong ETag to weak ("This a strong ETag. Convert it to a weak one", prefixing `W/`);
  - adds `Vary: Accept-Encoding`, or appends it to the last existing Vary;
  - adds `Content-Encoding` unless the algorithm is identity. — [src/flt_http_comp.c](https://github.com/haproxy/haproxy/blob/master/src/flt_http_comp.c)
- Inference: HAProxy does not touch `Accept-Ranges` (the filter never references it) and has no Range-specific logic beyond the 200-203 rule, which excludes 206.

**Negotiation**
- Each Accept-Encoding token is parsed with its `q=`. A token is taken only when q > best_q (best_q starts at 0, so q=0 is never chosen), and ties keep the first token in the client's order.
- For a token, the first configured algorithm that matches it is used. `*` matches the first configured algorithm.
- If nothing matches but `identity` is configured, identity is selected. — [src/flt_http_comp.c](https://github.com/haproxy/haproxy/blob/master/src/flt_http_comp.c)

**Other keywords and globals**
- `compression minsize-req <size>` / `compression minsize-res <size>`: "Payloads smaller than this size will not be compressed ... The default value is 0." These first appear in the 3.2.0 manual (3.2.0 tagged 2025-05-28) and are absent from 3.1.0. — [configuration.txt v3.2.0](https://github.com/haproxy/haproxy/blob/v3.2.0/doc/configuration.txt); [configuration.txt v3.1.0](https://github.com/haproxy/haproxy/blob/v3.1.0/doc/configuration.txt)
- `compression offload`: "Makes HAProxy work as a compression offloader only ... remove the Accept-Encoding header to prevent backend servers from compressing responses. It is strongly recommended not to do this". It is ignored with a warning in `defaults`. — [configuration.txt](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- `compression direction <direction>`: values `request`, `response` and `both`; the default value is "response". It is marked "(deprecated)" in the 3.4.0 manual: "only relevant when legacy 'filter compression' was enabled". `algo-req`/`algo-res`, request compression, are already in 2.8.0. — [configuration.txt v3.4.0](https://github.com/haproxy/haproxy/blob/v3.4.0/doc/configuration.txt); [v2.8.0](https://github.com/haproxy/haproxy/blob/v2.8.0/doc/configuration.txt)
- Filters (9.2):
  - `filter comp-req` ("Implicitly sets 'compression direction request'");
  - `filter comp-res`;
  - `filter compression (deprecated)`, an alias for both;
  - `filter-config http-comp-req` / `http-comp-res` (new mode, ordered by `filter-sequence`).
  - `filter comp-res` first appears in the 3.4.0 manual. — [configuration.txt](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt); [v3.4.0](https://github.com/haproxy/haproxy/blob/v3.4.0/doc/configuration.txt)
- Global tuning:
  - `tune.comp.maxlevel <number>`: "Sets the maximum compression level ... The default value is 1."
  - `maxcomprate <number>` (KB/s per process; "the compression level will be decreased during the stream"; default 0, no limit).
  - `maxcompcpuusage <number>` (percent; default 100, no limit; stops compression for new requests or lowers the level).
  - `maxzlibmem <number>` (MB, default 0). — [configuration.txt](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)
- Decompression is new on 3.5-dev (master) and absent from 3.4.0:
  - `decompression algo-req|algo-res <algorithms>` takes `uslz-auto`, `gzip`, `deflate` or `raw-deflate`, "only available when support for libslz was built in".
  - `decompression mode-req|mode-res { none | auto | always }`, default none.
  - "In HTTP, enabling decompression on the stream will enforce chunked mode". It is usable in http and tcp contexts. — [configuration.txt (master)](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt)

### Inferences
- HAProxy's default level of 1 is the lowest of the compressors here; libslz has no levels beyond its fast mode, and the level only matters with zlib. Together with the CPU and rate governors this makes HAProxy's compression a cheap, best-effort transform.
- HAProxy's status allowlist (200-203) is the most explicit; Envoy's default compresses any status.

### Gaps
- No HAProxy version has brotli or zstd (none in source or docs); I found no roadmap statement on adding them.
- Whether HTTP/2 and HTTP/3 messages carry the `HTTP_MSGF_VER_11` flag, which the "HTTP/1.1 or above" rule needs, was not traced in source.

## Traefik: the `compress` middleware

### Takeaway
Traefik v3 compresses with gzip (klauspost `gzhttp`), brotli (andybalholm) and zstd (klauspost). `encodings` defaults to `gzip, br, zstd`; it was `zstd, br, gzip` in v3.2.0-v3.3.4, and v3.3.5 reverted it to the v2 behaviour. `minResponseBodyBytes` defaults to 1024 and `defaultEncoding` is unset. Only `application/grpc` is excluded by default; there is no allowlist. Traefik skips HEAD and responses that already have Content-Encoding. It does not touch ETags, ignores `no-transform`, and has no Range/206 handling on the brotli and zstd paths.

### Cited Findings
**Documentation**
- "The `compress` middleware compresses response. It supports Gzip, Brotli and Zstandard compression". — [Traefik docs: Compress](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/compress/)
- Options:
  - `excludedContentTypes` (default ""; "Content types are compared in a case-insensitive, whitespace-ignored manner"; mutually exclusive with includedContentTypes);
  - `defaultEncoding` ("specifies the default encoding if the `Accept-Encoding` header is not in the request or contains a wildcard (`*`)", default "");
  - `encodings` ("valid entries are `zstd` (Zstandard), `br` (Brotli), and `gzip` (Gzip). The order of the list also sets the priority, the top entry has the highest priority", default `gzip, br, zstd`);
  - `includedContentTypes` (default "");
  - `minResponseBodyBytes` (default 1024). — [Traefik docs: Compress](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/compress/)
- Activation rules in the docs:
  - "The `Accept-Encoding` request header contains `gzip`, `*`, and/or `br`, and/or `zstd` with or without quality values. If the `Accept-Encoding` request header is absent, the response won't be encoded. When `defaultEncoding` is configured, the response is encoded even when `Accept-Encoding` is absent. If it is present, but its value is the empty string, then compression is turned off."
  - The response must not already be compressed, the Content-Type must pass the include/exclude lists, and the body must be larger than `minResponseBodyBytes`.
  - "If the `Content-Type` header is not defined, or empty, the compress middleware will automatically detect a content type."
  - "Note that `application/grpc` is never compressed." — [Traefik docs: Compress](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/compress/)

**Defaults and version history**
- `func (c *Compress) SetDefaults() { c.Encodings = []string{"gzip", "br", "zstd"} }`. The field comment reads: "`application/grpc` is always excluded." — [pkg/config/dynamic/middlewares.go](https://github.com/traefik/traefik/blob/master/pkg/config/dynamic/middlewares.go)
- Migration note: "In `v3.3.5`, the compress middleware `encodings` option default value is now `gzip, br, zstd`. This change helps the algorithm selection to favor the `gzip` algorithm over the other algorithms." The commit "Revert compress middleware algorithms priority to v2 behavior" changed the default from `zstd, br, gzip`. — [Traefik migration v3](https://doc.traefik.io/traefik/migrate/v3/); [commit 496f00c7](https://github.com/traefik/traefik/commit/496f00c7)
- Versions:
  - zstd support ("Add support for Zstandard to the Compression middleware", 2024-06-12): first in v3.1.0.
  - The `encodings` option ("Add encodings option", 2024-08-07): first in v3.2.0.
  - Accept-Encoding weights ("Support Accept-Encoding header weights", 2024-06-06): in v3.0.2.
  - "Disable br compression when no Accept-Encoding header is present" (2024-01-16) and `includedContentTypes` (2024-01-17), both from the v2.11 line.
  - "Disable Zstd support in the gzhttp wrapper" (2026-07-20): in v3.7.16, not in v3.6.0. — [Traefik commits](https://github.com/traefik/traefik/commits/master/pkg/middlewares/compress)

**Source (`compress.go`)**
- `defaultMinSize = 1024`, "See klauspost gzhttp".
- `excludes := []string{"application/grpc"}` plus the user list.
- A `HEAD` request passes through unmodified.
- If the *request* Content-Type is in excludes, the request passes through ("Notably for text/event-stream requests the response should not be compressed", issue #2576).
- Without Accept-Encoding, `defaultEncoding` is used if set ("RFC says: 'If no Accept-Encoding header field is in the request, any content coding is considered acceptable'"); otherwise there is no encoding ("for compatibility", issue #9734). — [pkg/middlewares/compress/compress.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/compress/compress.go)
- Negotiation (`acceptencoding.go`):
  - An empty header value gives identity.
  - Tokens are kept only if supported (configured encodings plus `*` and `identity`); `q=0` is skipped and the default weight is 1.0.
  - Sorting is by weight, then by priority: `*` = -1 (most preferred at equal weight), each encoding by its list index, `identity` = len(encodings).
  - A winning `*` selects `defaultEncoding` or `encodings[0]`. Nothing acceptable gives `not_acceptable`, meaning no compression ("TODO: return 415"). — [acceptencoding.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/compress/acceptencoding.go)
- Libraries and levels:
  - gzip: `gzhttp.NewWrapper(gzhttp.EnableZstd(false), gzhttp.ExceptContentTypes(excludes) or ContentTypes(includes), gzhttp.MinSize(minSize))`.
  - brotli: `brotli.NewWriter(rw)`.
  - zstd: `zstd.NewWriter(rw)`. — [compress.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/compress/compress.go)
  - andybalholm `NewWriter` uses `DefaultCompression = 6`. — [andybalholm/brotli writer.go](https://github.com/andybalholm/brotli/blob/master/writer.go)
  - gzhttp's default level is `gzip.DefaultCompression`, which klauspost's flate maps to level 5. — [klauspost gzhttp/compress.go](https://github.com/klauspost/compress/blob/master/gzhttp/compress.go); [klauspost flate/deflate.go](https://github.com/klauspost/compress/blob/master/flate/deflate.go)
  - The zstd encoder's defaults: `windowSize: 8 << 20`, `level: SpeedDefault`, `crc: true`, `concurrent: runtime.GOMAXPROCS(0)`. — [klauspost zstd/encoder_options.go](https://github.com/klauspost/compress/blob/master/zstd/encoder_options.go)
- The brotli/zstd writer (`compression_handler.go`):
  - It always adds `Vary: Accept-Encoding` at entry, and passes 1xx through.
  - Compression is disabled if Content-Encoding is set or the Content-Type cannot be parsed or is excluded or not included.
  - It buffers until `minSize`, then deletes Content-Length and sets Content-Encoding.
  - On flush before minSize it forces compression and flushes ("to be aligned with klauspost's gzip behavior").
  - Source comments: "TODO: check whether we want to implement content-type sniffing (as gzip does)" and "TODO: check whether we should support Accept-Ranges (as gzip does ...)". — [compression_handler.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/compress/compression_handler.go)
- The gzip path (klauspost gzhttp):
  - It does not compress when the response has `Content-Encoding`, `Content-Range` or the `No-Gzip-Compression` header, or when the body is under minSize.
  - It deletes `Accept-Ranges` unless `KeepAcceptRanges`.
  - It changes the ETag only if `SuffixETag`/`DropETag` are configured; Traefik configures neither.
  - Bodies are not allowed for 1xx, 204 or 304.
  - It sniffs the Content-Type with `http.DetectContentType`.
  - Its own `DefaultContentTypeFilter` (excludes `video/`, `audio/`, `image/jp` and types containing compress, zip, snappy, lzma, xz, zstd, brotli or stuffit) is replaced when `ExceptContentTypes` is passed. — [klauspost gzhttp/compress.go](https://github.com/klauspost/compress/blob/master/gzhttp/compress.go)
- Traefik's master `go.mod` pins `github.com/klauspost/compress v1.20.4-0.20261021124103-35c6f98a5cb9` ("TODO: pin a released version once https://github.com/klauspost/compress/pull/1272 is part of a release"). — [traefik go.mod](https://github.com/traefik/traefik/blob/master/go.mod)

### Inferences
- Because Traefik passes `ExceptContentTypes`, its gzip path does not get gzhttp's default exclusion of video, audio, JPEG and archives. Apart from gRPC, all types are compressed unless the user lists exclusions. The brotli and zstd paths behave the same.
- Neither Traefik nor gzhttp checks `Cache-Control: no-transform` (a grep of the middleware and gzhttp found none).
- The brotli and zstd paths do not check for `Content-Range` and do not delete `Accept-Ranges`. A 206 of at least 1024 bytes from a backend could therefore be compressed on those paths but not on gzip.
- No path weakens or rewrites a strong ETag, so the same strong ETag can label the identity and compressed bodies.
- HEAD is passed through untouched, so a HEAD answer lacks the `Content-Encoding`/`Vary` that the matching GET gets.
- Before v3.7.x's `EnableZstd(false)`, the gzhttp wrapper (zstd enabled and preferred by default) could itself answer `zstd` on the "gzip" path.
- The zstd window of 8 MiB is the largest allowed for HTTP zstd; Caddy deliberately uses 128 KiB.

### Gaps
- `docs.traefik.io` gives no explicit statement on Range, ETag or no-transform; the behaviour above is from code.
- The exact v3.7.x patch release that first carried `EnableZstd(false)` was not pinned because the API rate limit was reached.

## Envoy: compressor filter (gzip, brotli, zstd) and decompressor

### Takeaway
Envoy's `envoy.filters.http.compressor` uses one compressor library per filter instance, with gzip, brotli and zstd as extensions; several filters in a chain compete through q-values. The response direction is on by default and the request direction is off. Defaults: `min_content_length` 30, an 8-type content_type list, and `uncompressible_response_codes` empty (so 206 is compressed unless listed). Envoy skips Content-Encoding, `no-transform`, upgrades and compression-coded Transfer-Encoding. Strong ETags are removed by default; `weaken_etag_on_compress` (1.38) weakens them instead and `disable_on_etag_header` skips compression. `Vary: accept-encoding` is added whenever the response is compressible. Library defaults: gzip level 6, window 12, memory 5; brotli quality 3, window 18; zstd level 3. A separate decompressor filter exists.

### Cited Findings
**Filter behaviour (docs)**
- "Currently the filter supports gzip, brotli and zstd compression only. Other compression libraries can be supported as extensions." — [Envoy docs: Compressor filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/compressor_filter)
- "By *default* request compression is disabled, but when enabled it will be *skipped* if": the request lacks a matching content-type, lacks `content-length`, has `content-encoding`, or has a compression Transfer-Encoding. — [Envoy docs: Compressor filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/compressor_filter)
- "By *default* response compression is enabled, but it will be *skipped* when":
  - the request has no `accept-encoding`;
  - accept-encoding lacks `gzip` or `*`;
  - `gzip` or `*` has `q=0` ("the `gzip` will have a higher weight than `\*`. For example, if `accept-encoding` is `gzip;q=0,\*;q=1`, the filter will not compress. But if the header is set to `\*;q=0,gzip;q=1`, the filter will compress");
  - another encoding in the chain has a higher weight;
  - the response has `content-encoding`;
  - `cache-control` contains `no-transform`;
  - Transfer-Encoding names a compression;
  - the content-type does not match the list, whose defaults are `application/javascript`, `application/json`, `application/xhtml+xml`, `image/svg+xml`, `text/css`, `text/html`, `text/plain` and `text/xml`;
  - there is no `content-length` or `transfer-encoding`;
  - "Response size is smaller than 30 bytes (only applicable when `transfer-encoding` is not chunked)";
  - "A response code is on the list of uncompressible response codes, which is empty by default";
  - the response has an `ETag` and `disable_on_etag_header` is on. — [Envoy docs: Compressor filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/compressor_filter)
- When response compression is applied: "The `content-length` is removed ... Response headers contain `transfer-encoding: chunked`, and `content-encoding` ... The `vary: accept-encoding` header is inserted on every response." Also: "the `vary: accept-encoding` header may be inserted even if compression is **not** applied due to incompatible `accept-encoding` header in a request". — [Envoy docs: Compressor filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/compressor_filter)

**ETag handling (docs)**
- With `disable_on_etag_header: false` (the default) and `weaken_etag_on_compress: false` (the default): "Weak `ETag` values (RFC 7232: `W/` prefix, case-insensitive `W`) are preserved. Any other value is treated as strong and is *removed* from the response when compressing".
- `weaken_etag_on_compress: true`: strong values "are *weakened* by prepending `W/` ... This behavior matches common practice in other proxies (e.g. Varnish)".
- When both are true, "`weaken_etag_on_compress` takes precedence". — [Envoy docs: Compressor filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/compressor_filter)
- `weaken_etag_on_compress` was added in 1.38.0 (April 23, 2026). The same release made strong-ETag removal use the same `W/` test: "Previously removal applied only when `ETag` length was greater than 2". — [Envoy changelog 1.38.0](https://github.com/envoyproxy/envoy/blob/main/changelogs/1.38.0.yaml)

**API fields (`compressor.proto`, v3)**
- `CommonDirectionConfig`:
  - `enabled` (RuntimeFeatureFlag; enabled if unset);
  - `min_content_length` ("Defaults to 30");
  - `content_type` (deprecated);
  - `content_type_matcher` (StringMatcher list; "When this field is specified, the default content type list is not used").
- `ResponseDirectionConfig`:
  - `disable_on_etag_header`;
  - `weaken_etag_on_compress`;
  - `remove_accept_encoding_header` ("removes `Accept-Encoding` from the request headers before dispatching the request to the upstream so that responses do not get compressed before reaching the filter");
  - `uncompressible_response_codes` (unique, 200-599; "e.g., 206 Partial Content should not be compressed");
  - `status_header_enabled`.
- Top level:
  - `compressor_library` (required);
  - `request_direction_config` ("If this field is not specified, request compression is disabled");
  - `response_direction_config` ("If this field is not specified, response compression is enabled");
  - `choose_first` ("this compressor is preferred when q-values in `Accept-Encoding` are equal. If multiple compressor filters set `choose_first` to `true`, the last one in the filter chain is chosen").
- The deprecated top-level `content_length`, `content_type`, `disable_on_etag_header`, `remove_accept_encoding_header` and `runtime_enabled` date from 3.0.
- `CompressorPerRoute`: `disabled`, or overrides of `remove_accept_encoding_header` and `compressor_library`. — [compressor.proto](https://github.com/envoyproxy/envoy/blob/main/api/envoy/extensions/filters/http/compressor/v3/compressor.proto); [API reference](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/compressor/v3/compressor.proto)
- Changelog dates: `uncompressible_response_codes` in 1.34.0 (April 15, 2025). The per-route `compressor_library` override and `status_header_enabled` (`x-envoy-compression-status: <encoder>;<status>[;params]`, statuses Compressed, ContentLengthTooSmall, ContentTypeNotAllowed, EtagNotAllowed, StatusCodeNotAllowed) in 1.36.0 (October 14, 2025). — [changelog 1.34.0](https://github.com/envoyproxy/envoy/blob/main/changelogs/1.34.0.yaml); [changelog 1.36.0](https://github.com/envoyproxy/envoy/blob/main/changelogs/1.36.0.yaml); [Compressor filter docs](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/compressor_filter)

**Source (`compressor_filter.cc`)**
- Response compression requires `!end_stream` on headers, response compression enabled, `isMinimumContentLength` (checked only when a Content-Length header exists), `!isUpgrade`, an allowed content type, no `no-transform`, the ETag check, no existing Content-Encoding, a compressible response code, Accept-Encoding allowing this filter's encoding, and an allowed Transfer-Encoding.
- Vary is inserted if `isCompressible`, independent of Accept-Encoding; it is appended to an existing Vary if absent.
- A comment reads: "Envoy does NOT re-write entity tags" (sanitize removes strong ETags). — [compressor_filter.cc](https://github.com/envoyproxy/envoy/blob/main/source/extensions/filters/http/compressor/compressor_filter.cc)
- `chooseEncoding`:
  - Gathers the compressors registered in the chain whose content types allow the response, ignoring later duplicates of an encoding.
  - Parses Accept-Encoding tokens and their `q`; an unparseable q-value skips the token. A `q=0` token removes that compressor.
  - Picks the highest q among allowed compressors, `identity` and `*`. Ties keep the earlier token unless the candidate has `choose_first`.
  - A winning `identity` means no compression. A winning `*` takes the first-registered compressor. A q of zero overall counts as invalid, giving identity. — [compressor_filter.cc](https://github.com/envoyproxy/envoy/blob/main/source/extensions/filters/http/compressor/compressor_filter.cc)
- Inference: `!end_stream` means HEAD, 204 and 304 answers (headers with end_stream) are never compressed. Range and 206 are not special-cased unless 206 is listed in `uncompressible_response_codes`. `Accept-Ranges` is not touched.

**Library defaults**
- gzip:
  - `memory_level` 1-9, "Defaults to `5`";
  - `compression_level` "Defaults to `DEFAULT_COMPRESSION`", the same as level 6;
  - `compression_strategy` defaults to `DEFAULT_STRATEGY` (FILTERED, HUFFMAN_ONLY, RLE and FIXED also available);
  - `window_bits` 9-15, "Defaults to `12`, which will produce a 4096 bytes window";
  - `chunk_size` 4096-65536, default 4096. — [gzip compressor proto](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/compression/gzip/compressor/v3/gzip.proto)
- brotli:
  - `quality` 0-11, "The default value is 3";
  - `encoder_mode` DEFAULT, GENERIC, TEXT or FONT;
  - `window_bits` 10-24, "The default is 18";
  - `input_block_bits` 16-24, "The default is 24";
  - `chunk_size` default 4096;
  - `disable_literal_context_modeling`. — [brotli compressor proto](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/compression/brotli/compressor/v3/brotli.proto)
- zstd:
  - `compression_level` ("Value 0 means default, and default level is 3");
  - `enable_checksum` ("If not set, defaults to false");
  - `strategy` (DEFAULT, FAST through BTULTRA2);
  - `dictionary` (DataSource);
  - `chunk_size` default 4096. — [zstd compressor proto](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/compression/zstd/compressor/v3/zstd.proto)

**Decompression**
- `envoy.filters.http.decompressor` handles gzip, brotli and zstd in both directions. It is skipped when there is no `content-encoding`, when the content-encoding does not match, or for `no-transform` "unless `ignore_no_transform_header` is set to `true`". When applied, it removes `content-length`, strips the applied coding from `content-encoding`, and adds `x-envoy-decompressor-<name>-<compressed/uncompressed>-bytes` trailers. — [Envoy docs: Decompressor filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/decompressor_filter)
- 1.39.0 (July 14, 2026) fixed CVE-2026-48044 in the zstd decompressor: "the `MaxInflateRatio` limit was only checked after each input slice was fully processed". — [changelog 1.39.0](https://github.com/envoyproxy/envoy/blob/main/changelogs/1.39.0.yaml)

### Inferences
- Envoy's defaults are the most proxy-oriented in this set. The 30-byte minimum is very low, the 8-type allowlist leaves out `application/xml`, `text/javascript`, `application/wasm` and `+json` types unless they count as "synonyms", 206 is compressed by default, and the default ETag policy is to delete strong ETags.
- Several algorithms need several filter instances. The docs' skip list is written in terms of "gzip" but applies to whatever encoding each library registers.

### Gaps
- The "synonyms" of the default content-type list were not enumerated; the source of the default list was not read.
- Exactly when Envoy adds `transfer-encoding: chunked` on HTTP/2 and HTTP/3 (the docs state it generally) was not checked.

## Cross-server comparison (defaults unless noted)

### Takeaway
Defaults differ widely:
- Minimum size: 30 B (Envoy), 100 B (h2o with `compress: ON`), 512 B (Caddy), 1024 B (Traefik), 2700 B (IIS static), 0 (HAProxy).
- Type selection: an allowlist (Caddy, h2o, IIS, Envoy) or all but an exclusion (HAProxy: every type when unset; Traefik: all but gRPC).
- ETag: suffixed and kept strong (Caddy), weakened (h2o, HAProxy, Envoy opt-in), removed (Envoy default), untouched (Traefik); for IIS not found.
- Status: only h2o (200) and HAProxy (200-203) restrict it.
- Brotli and zstd: on the fly in Traefik and Envoy; Caddy core does zstd only (br needs a plugin); h2o has both on master (zstd since 2026-06); IIS does br through its extension; HAProxy has neither.

### Cited Findings
| Aspect | Caddy (v2.11.7) | h2o (master) | IIS 10 | HAProxy 3.4 | Traefik v3.7 | Envoy 1.40 |
|---|---|---|---|---|---|---|
| On by default | no (`encode` directive) | no (`compress: OFF`) | static yes, dynamic module optional; `doDynamicCompression` true | no | no (middleware) | response yes once the filter is configured; request no |
| On-the-fly algorithms | zstd, gzip (br via plugin) | br, zstd, gzip (build-dependent) | gzip, deflate (br via IIS Compression) | gzip, deflate, raw-deflate, identity | gzip, br, zstd | gzip, brotli, zstd (one per filter) |
| Server preference | Caddyfile order; JSON default zstd > br > gzip | br > zstd > gzip, fixed | scheme order (IIS 10 1803+) | client token order, first matching configured algo | `gzip, br, zstd` | first token / `choose_first` |
| q-values | yes | not parsed (inference) | yes | yes | yes | yes |
| Default level | gzip 5, zstd "default" (~3), window 128 KiB | gzip 1, br 1, zstd 3 | static 7, dynamic 0 | `tune.comp.maxlevel` 1 | gzip 5 (klauspost default), br 6, zstd SpeedDefault, window 8 MiB (library defaults) | gzip 6 (window 12, mem 5), br 3, zstd 3 |
| Minimum size | 512 | 100 (`compress: ON`) | 2700 (`minFileSizeForComp`) | 0 (`minsize-res`, 3.2+) | 1024 | 30 |
| Default types | ~35-entry allowlist incl. `text/*` | `is_compressible`: text/*, JS, JSON, XML, +json, +xml | text/*, message/*, application/javascript | all (no `type`) except multipart | all except application/grpc | 8-type list |
| Status codes | all but 206 | 200 only | not documented | 200-203 | any (gzhttp: no body for 204/304) | any unless listed |
| HEAD | headers as for GET | not compressed | not documented | not compressed | passed through | not compressed (end_stream) |
| no-transform | honoured (request and response) | not checked | not documented | honoured | not checked | honoured |
| Existing Content-Encoding | skipped | skipped | not documented | skipped | skipped | skipped |
| ETag | strong → `"…-<enc>"`, stripped on If-None-Match | `W/` prefix | not documented | `W/` prefix; invalid or multiple ETags disable | unchanged | strong removed (default) / `W/` (1.38+) / skip |
| Vary | added when encoding; file_server always; on 304 | added when encoding, or when the client offered other codings | overwrites app Vary (pre-hotfix) | appended | always added (br/zstd path) | added whenever compressible |
| Range | 206 not encoded; Accept-Ranges removed | `Accept-Ranges: none` | `noCompressionForRange` true | 206 not in 200-203 | gzip skips Content-Range; br/zstd no check | not special (206 compressed unless listed) |
| Precompressed files | `precompressed` br, zstd, gzip | `file.send-compressed` br, zstd, gz (+`gunzip`) | static disk cache (own) | n/a | n/a | n/a |

Sources for each cell are in the server sections above: [Caddy encode docs](https://caddyserver.com/docs/caddyfile/directives/encode), [Caddy encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go), [h2o compress docs](https://h2o.examp1e.net/configure/compress_directives.html), [h2o compress.c](https://github.com/h2o/h2o/blob/master/lib/handler/compress.c), [IIS httpCompression](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpcompression/), [HAProxy configuration.txt](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt), [HAProxy flt_http_comp.c](https://github.com/haproxy/haproxy/blob/master/src/flt_http_comp.c), [Traefik compress docs](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/compress/), [Traefik compress.go](https://github.com/traefik/traefik/blob/master/pkg/middlewares/compress/compress.go), [Envoy compressor docs](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/compressor_filter), [Envoy compressor_filter.cc](https://github.com/envoyproxy/envoy/blob/main/source/extensions/filters/http/compressor/compressor_filter.cc).

### Inferences
- The `Accept-Encoding: *` handling splits the servers. HAProxy, Traefik and Envoy map `*` to their first configured algorithm. Caddy and h2o ignore it, and so answer identity.
- `identity;q=0` with nothing else acceptable: none of the six answers 406. All of them send identity; Traefik's code carries a "TODO: return 415".
- Streaming and SSE: Caddy, h2o and Traefik flush the encoder on every flush or chunk, and Caddy since v2.11.6 sends SSE headers at once without the minimum-length wait. HAProxy and Envoy compress chunked bodies as they flow; no special SSE rule was found for either.

### Gaps
- Several IIS cells (status codes, HEAD, no-transform, existing Content-Encoding, ETag) are not documented in the official pages I fetched. They need testing on a live IIS or Microsoft sources not found here.
- Any cell marked as inference was read from code and not confirmed by a live request against each server.
