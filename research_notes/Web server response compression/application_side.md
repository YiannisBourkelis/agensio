# Application-side response compression and its interaction with a front server

Scope: what PHP, the PHP applications and their caching plugins, the Ruby, Python, Node.js, Go, Java
and .NET frameworks, and common self-hosted applications do about compressing their own responses
(defaults, configuration, headers sent), what goes wrong when a front server also compresses, and
what streaming / server-sent-event responses send to keep proxies from buffering or compressing.
Researched 2026-10-26. Versions are given where the source states them. Where a fact comes from
reading source code on a project's default branch, the link is to that file; where it comes from a
local experiment, that is said explicitly and the method is given.

Local experiment used below ("local FastCGI test"): the Debian 13 package php8.4-fpm
8.4.26-1~deb13u1 (agensio-devbox:php image), php-fpm on 127.0.0.1:9000, started with
`-d zlib.output_compression=On` (and variants), driven by a 60-line Python FastCGI client that sends
`HTTP_ACCEPT_ENCODING` and prints the CGI header block, body bytes and the time of each FCGI_STDOUT
record. Test scripts: plain echo of 6,000 bytes; the same with `header('Content-Length: ...')`; a
script that gzencodes its body and sets `Content-Encoding: gzip`; an SSE loop with `ob_flush(); flush();`
every 300 ms; `http_response_code(304)` with no output; an empty `text/plain` response; 3,000 random
bytes as `image/png`.

## PHP: zlib.output_compression, ob_gzhandler, PHP-FPM through FastCGI, Debian defaults

### Takeaway
PHP compresses nothing unless `zlib.output_compression` (default Off, also Off in php.ini-production
and therefore in Debian's php-fpm php.ini) or `ob_gzhandler` is turned on. When on, it compresses
every response whatever its type or status (images, empty bodies, even a 304), adds
`Content-Encoding: gzip` and `Vary: Accept-Encoding` (choosing gzip by substring, so even `gzip;q=0`),
drops nothing the script set except that a
script-set `Content-Length` silently turns compression off, never checks whether the script already
set its own `Content-Encoding` (so it double-compresses), and with php.ini-production's
`output_buffering = 4096` it holds back flushed SSE output.

### Cited Findings
- Defaults: `zlib.output_compression` "0", `zlib.output_compression_level` "-1" ("lets the server decide which level to use"), `zlib.output_handler` "", all `INI_ALL`. When On, "pages are compressed if the browser sends an 'Accept-Encoding: gzip' or 'deflate' header. 'Content-Encoding: gzip' (respectively 'deflate') and 'Vary: Accept-Encoding' headers are added to the output. In runtime, it can be set only before sending any output." An integer value sets the output buffer size (default 4 KB). `output_handler` must be empty when it is On — [PHP manual, zlib runtime configuration](https://www.php.net/manual/en/zlib.configuration.php)
- php.ini-production ships `zlib.output_compression = Off`, `;zlib.output_compression_level = -1`, `output_buffering = 4096` (Default Value: Off; Development and Production Value: 4096), `implicit_flush = Off`; its comment says compression makes PHP output "chunks that are few hundreds bytes each" and recommends enabling output_buffering in addition for larger chunks; "you cannot use both 'ob_gzhandler' and 'zlib.output_compression'" — [php-src php.ini-production](https://github.com/php/php-src/blob/master/php.ini-production)
- Debian 13: php8.4-fpm 8.4.26-1~deb13u1 installs `/usr/lib/php/8.4/php.ini-production` as `/etc/php/8.4/fpm/php.ini` through ucf in its postinst; the installed file is byte-identical to php.ini-production and has `zlib.output_compression = Off`, `output_buffering = 4096` — local inspection of the package in the devbox image; package page [packages.debian.org php8.4-fpm (trixie)](https://packages.debian.org/trixie/php8.4-fpm)
- Encoding choice: `php_zlib_output_encoding()` reads `HTTP_ACCEPT_ENCODING` from `$_SERVER` and picks gzip if the string contains "gzip", else deflate if it contains "deflate" (a substring test, no q-values; `gzip;q=0` would still select gzip); result cached per request — [php-src ext/zlib/zlib.c](https://github.com/php/php-src/blob/master/ext/zlib/zlib.c)
- Headers: the zlib output handler adds `Content-Encoding: gzip|deflate` and `Vary: Accept-Encoding` at the start of output; the handler code also has a branch that adds `Vary: Accept-Encoding` on START when no encoding was negotiated (but see the local test below: under php-fpm with no gzip/deflate in Accept-Encoding the handler was not installed at all and no Vary was sent); `ob_gzhandler` adds the same headers. Compression is abandoned if `SG(headers_sent)`; there is no check for a `Content-Encoding` the script set itself; the file never touches Content-Length — [php-src ext/zlib/zlib.c](https://github.com/php/php-src/blob/master/ext/zlib/zlib.c)
- A script that sets `Content-Length` turns compression off for that request: `sapi_header_op` sets `zlib.output_compression` to "0" because "The script cannot reasonably know the size of the message body after compression ... See req #44164" — [php-src main/SAPI.c](https://github.com/php/php-src/blob/master/main/SAPI.c)
- Flush semantics in the handler: default deflate flag `Z_SYNC_FLUSH`, an explicit output-layer flush (`PHP_OUTPUT_HANDLER_FLUSH`, i.e. `ob_flush()` reaching the zlib handler) uses `Z_FULL_FLUSH`, the final call `Z_FINISH`. Conflict check refuses zlib compression when `ob_gzhandler`, `mb_output_handler` or URL-Rewriter is active — [php-src ext/zlib/zlib.c](https://github.com/php/php-src/blob/master/ext/zlib/zlib.c)
- `ob_gzhandler`: "You cannot use both ob_gzhandler() and zlib.output_compression. Also note that using zlib.output_compression is preferred over ob_gzhandler()"; returns false when the browser does not accept compression; user notes report a gzip stream header emitted on 304 responses and `Content-Encoding: gzip` left set after `ob_end_clean()` (blank pages) — [PHP manual, ob_gzhandler](https://www.php.net/manual/en/function.ob-gzhandler.php)
- Local FastCGI test, what php-fpm sends through FastCGI with zlib.output_compression On and `Accept-Encoding: gzip, deflate, br`: CGI head `Content-Encoding: gzip`, `Vary: Accept-Encoding`, `Content-type: text/html; charset=UTF-8`, no Content-Length, gzip body (6,000 bytes became 62). With no Accept-Encoding, with `br` only, or with `identity`: uncompressed, and no `Vary` at all (the output-buffer stack then held only the default handler, i.e. the zlib handler was never installed). With `gzip;q=0, br` PHP still answered gzip (the substring match ignores q=0, contrary to RFC 9110 12.5.3) — observed on [php8.4-fpm 8.4.26 (Debian 13)](https://packages.debian.org/trixie/php8.4-fpm); mechanism in [zlib.c](https://github.com/php/php-src/blob/master/ext/zlib/zlib.c)
- Local FastCGI test: with a script-set `Content-Length: 6000`, PHP sent the body uncompressed with that Content-Length and no Content-Encoding (the req #44164 rule) — [php-src main/SAPI.c](https://github.com/php/php-src/blob/master/main/SAPI.c)
- Local FastCGI test, double compression inside PHP: a script that `gzencode()`s its body and sets `Content-Encoding: gzip` while zlib.output_compression is On produced a body that, gunzipped once, still began with the gzip magic `1f8b` (gzip inside gzip) under a single `Content-Encoding: gzip` — the browser would show garbage. This is the mechanism behind the WordPress caching-plugin "garbled page" reports below — observed on [php8.4-fpm 8.4.26](https://packages.debian.org/trixie/php8.4-fpm); no Content-Encoding check in [zlib.c](https://github.com/php/php-src/blob/master/ext/zlib/zlib.c)
- Local FastCGI test, everything is compressed: `http_response_code(304)` with no output gave `Status: 304 Not Modified`, `Content-Encoding: gzip`, `Vary: Accept-Encoding` and a 20-byte gzip body (a 304 must have no body); an empty `text/plain` response got a 20-byte gzip body; 3,000 random bytes sent as `image/png` were compressed to 3,023 bytes (larger) — observed on [php8.4-fpm 8.4.26](https://packages.debian.org/trixie/php8.4-fpm)
- Local FastCGI test, flushing: with zlib On and php.ini-production's `output_buffering = 4096`, the output-buffer stack was `default output handler, zlib output compression` (zlib on top); an SSE loop doing `ob_flush(); flush();` every 300 ms delivered nothing until the script ended (all events arrived together at 0.9 s), because `ob_flush()` flushes only the top (zlib) buffer into the 4 KB default buffer below it and `flush()` does not empty user-level buffers. With `output_buffering=0` and zlib On, each event arrived at 0.3 s intervals as a ~20-byte compressed chunk; with zlib Off (the Debian default) and output_buffering 4096 the events also arrived on time, uncompressed — observed on [php8.4-fpm 8.4.26](https://packages.debian.org/trixie/php8.4-fpm); buffer semantics in [php.ini-production](https://github.com/php/php-src/blob/master/php.ini-production)
- `readgzfile()` "Reads a file, decompresses it and writes it to standard output" (relevant to WP Rocket below) — [PHP manual, readgzfile](https://www.php.net/manual/en/function.readgzfile.php)

### Inferences
- On a default Debian/Ubuntu php-fpm install, PHP sends uncompressed output; compressed output from php-fpm means an administrator or an application turned it on (php.ini, a pool's `php_admin_value`, `.user.ini`, `ini_set()` before output, or an application calling `ob_start('ob_gzhandler')` / `gzencode()` itself).
- A front server talking FastCGI must expect, when PHP compresses: no Content-Length, `Content-Encoding: gzip` on any content type and any status including 304 and 204-like empty answers (it must discard the body of a 304/204/HEAD regardless of the encoding header). The uncompressed variants PHP sends to clients without gzip carry no `Vary: Accept-Encoding`, so only the compressed variant is marked as varying; a front server that caches PHP answers should add `Accept-Encoding` to Vary itself whenever PHP compression is in play.
- Because PHP's choice is a substring match on Accept-Encoding, a server that rewrites or strips Accept-Encoding before passing it as `HTTP_ACCEPT_ENCODING` controls whether PHP compresses at all.
- The "compress at one layer" rule applies inside PHP too: PHP's zlib layer is the one place in the stack that blindly re-compresses an already-encoded body, which is why WordPress plugins test `ini_get('zlib.output_compression')` before compressing themselves.

### Gaps
- Did not test HEAD requests over FastCGI with zlib on, or deflate-only Accept-Encoding.
- Did not find Ubuntu's own packaging file; Ubuntu derives from Debian's php packaging (Ondřej Surý), so the same php.ini-production default is likely but was not verified for Ubuntu specifically.
- Did not find official PHP documentation saying whether `zlib.output_compression` honours `Cache-Control: no-transform` (the source shows no such check).

## WordPress core and its caching plugins

### Takeaway
WordPress core does not compress responses: it removed its PHP compression of concatenated admin
scripts in 2018 and in trunk the concatenation endpoint is now a 410 stub. Caching plugins either
write web-server rules (Apache `.htaccess`, nginx snippets) that serve precompressed cache files, or
send gzip from PHP: WP Super Cache (compression off by default) and W3 Total Cache (gzip of cached
HTML on by default) emit `Content-Encoding: gzip` from PHP when the web server's rewrite rules do not
apply; WP Rocket's PHP fallback decompresses its gzip file and sends plain HTML. Double-compression
garbage comes from PHP-level double compression or from `.gz` files served without
`Content-Encoding`, and every vendor's fix is "enable compression in one place".

### Cited Findings
- Core: Trac changeset 43580 (August 2018), "Script loader: remove (PHP based) compression from load-styles.php and load-scripts.php", fixes #44815, references #43308; reasons given: the scripts and styles grew, compression "has become pretty slow and consumes a lot of server resources", and "most servers already compress PHP output"; merged to the 4.9 (r43618) and 5.0 (r43697) branches — [WordPress Trac changeset 43580](https://core.trac.wordpress.org/changeset/43580) (page returned 403 to the fetcher; details from the search-result summary of that page and of [r43618](https://core.trac.wordpress.org/changeset/43618/branches/4.9/src/wp-admin/load-scripts.php))
- Trunk `wp-admin/load-scripts.php` now only answers `410` with `Content-Type: text/plain`, "Scripts are no longer concatenated", `@deprecated 7.2.0`, and does not load WordPress — [wordpress-develop trunk load-scripts.php](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-admin/load-scripts.php)
- WP Super Cache 3.1.4 (tested up to WordPress 7.1): "Compress pages" option; readme: if pages download instead of display, "you must disable Super Cache compression"; garbled output after enabling it means "compression may already be enabled in your web server" (mod_deflate or PHP zlib output compression), fix by disabling one of them — [WP Super Cache readme.txt](https://github.com/Automattic/wp-super-cache/blob/trunk/readme.txt)
- WP Super Cache default: `$cache_compression = 0; // Super cache compression` — [wp-cache-config-sample.php](https://github.com/Automattic/wp-super-cache/blob/trunk/wp-cache-config-sample.php); the settings page says "Compression is disabled by default because some hosts have problems with compressed files. Switching it on and off clears the cache." — [partials/advanced.php](https://github.com/Automattic/wp-super-cache/blob/trunk/partials/advanced.php)
- WP Super Cache guard: `gzip_accepted()` returns false when `zlib.output_compression` is on ("don't compress WP-Cache data files when PHP is already doing it") or Accept-Encoding lacks "gzip"; when serving a supercache file from PHP it reads `file.gz` (or gzencodes level 6), sends `Content-Encoding: gzip`, `Content-Length`, `Vary: Accept-Encoding, Cookie` (overridable by `WPSC_VARY_HEADER`) and `Cache-Control: max-age=3, must-revalidate` (overridable by `WPSC_CACHE_CONTROL_HEADER`) — [wp-cache-phase2.php](https://github.com/Automattic/wp-super-cache/blob/trunk/wp-cache-phase2.php)
- WP Super Cache Apache rules: rewrite to `cache/supercache/<host>/<path>/index-https.html.gz` (or `index.html.gz`) when `%{HTTP:Accept-Encoding}` contains gzip and the file exists; the cache directory's `.htaccess` sets `AddEncoding gzip .gz`, `AddType text/html .gz`, `FileETag None` on `.html.gz`, and `SetEnvIfNoCase Request_URI \.gz$ no-gzip` under mod_deflate (to stop Apache compressing again), plus `Vary: Accept-Encoding, Cookie` — [inc/htaccess.php](https://github.com/Automattic/wp-super-cache/blob/trunk/inc/htaccess.php)
- Forum reports for WP Super Cache compression: garbled characters on LiteSpeed after enabling "Compress pages", with the support reply that LiteSpeed already gzips at the server level; browsers downloading a `.gz` file on every page until the option was turned off — [WordPress.org support thread](https://wordpress.org/support/?p=15781920) (third-party forum report)
- W3 Total Cache 2.11.0 defaults: `browsercache.enabled` true, `browsercache.html.compression`, `browsercache.cssjs.compression`, `browsercache.other.compression` true (gzip), the matching `.brotli` keys false — [W3TC ConfigKeys.php](https://github.com/BoldGrid/w3-total-cache/blob/master/ConfigKeys.php)
- W3TC page cache: refuses to cache a page whose response already has `Content-Encoding` ("Response is compressed"); stores gzip (`gzencode`) and brotli (`brotli_compress`) variants; `_get_compression()` returns nothing when `Util_Environment::is_zlib_enabled()` (PHP zlib on) or in debug mode, else the first stored encoding found in Accept-Encoding by substring; serving from PHP sets `Content-Encoding` and `Vary: Accept-Encoding` (plus `User-Agent,Cookie` in some modes, and `Cookie` for logged-out users) — [PgCache_ContentGrabber.php](https://github.com/BoldGrid/w3-total-cache/blob/master/PgCache_ContentGrabber.php)
- W3TC disk-enhanced rules: Apache sets `W3TC_ENC` to `_gzip` / `_br` and serves `_index*.html_gzip` / `.html_br` with `AddEncoding gzip .html_gzip`, `AddEncoding br .html_br` and `no-gzip` / `no-brotli` env; the nginx snippet adds `location ~ <cache_dir>.*gzip$ { gzip off; types {} default_type text/html; add_header Content-Encoding gzip; }` (same for br with `brotli off`) and a browser-cache section with `gzip on; gzip_types ...` and optionally `brotli on;` — [PgCache_Environment.php](https://github.com/BoldGrid/w3-total-cache/blob/master/PgCache_Environment.php), [BrowserCache_Environment_Nginx.php](https://github.com/BoldGrid/w3-total-cache/blob/master/BrowserCache_Environment_Nginx.php)
- W3TC ERR_CONTENT_DECODING_FAILED / white page reports fixed by turning off gzip under Performance > Browser Cache because the server, PHP zlib or another plugin already compressed; a cache key shown as `_default_.html.gzip` with `Content-Encoding: gzip` — [WordPress.org support thread](https://wordpress.org/support/?p=1515285), [BoldGrid support](https://boldgrid.com/support/question/content-encoding-error) (third-party support forums)
- WP Rocket (3.24-beta on develop): on Apache/LiteSpeed it writes mod_deflate rules into `.htaccess` (`SetOutputFilter DEFLATE`, an Accept-Encoding repair, `no-gzip dont-vary` for media, `AddOutputFilterByType DEFLATE ...`, `Header append Vary: Accept-Encoding`), `Header unset ETag` + `FileETag None`, and for its cache `AddType text/html .html_gzip`, `AddEncoding gzip .html_gzip`, `SetEnvIfNoCase Request_URI \.html_gzip$ no-gzip`, with a rewrite that sets `WPR_ENC=_gzip` when Accept-Encoding contains gzip and serves `index{-https}{-webp}.html_gzip` — [WP Rocket: rules in the .htaccess file](https://docs.wp-rocket.me/article/1788-wp-rocket-rules-in-the-htaccess-file), [WP Rocket: Enable GZIP compression](https://docs.wp-rocket.me/article/63-enable-gzip-compression)
- WP Rocket on nginx: writes no configuration ("Nginx doesn't use an .htaccess"); for uncompressed HTML it suggests `zlib.output_compression = On` in a user.ini/php.ini — [WP Rocket: Enable GZIP compression](https://docs.wp-rocket.me/article/63-enable-gzip-compression)
- WP Rocket's PHP fallback: writes `<cache>_gzip` with `gzencode($content, 6)` (filter `rocket_gzencode_level_compression`); when serving from PHP and the client accepts gzip, `serve_gzip_cache_file()` sends `Last-Modified` (or a 304) and then `readgzfile()` — which decompresses — so the PHP path sends plain HTML with no Content-Encoding — [wp-rocket inc/classes/Buffer/class-cache.php](https://github.com/wp-media/wp-rocket/blob/develop/inc/classes/Buffer/class-cache.php); [readgzfile](https://www.php.net/manual/en/function.readgzfile.php)
- LiteSpeed: compression (gzip and Brotli, separate levels for static and dynamic content) is a server setting in LiteSpeed Web Server — [LiteSpeed docs: compression](https://docs.litespeedtech.com/cp/cpanel/compression/); OpenLiteSpeed's "Enable Compression" is on by default — [OpenLiteSpeed docs: compression](https://docs.openlitespeed.org/config/advanced/compress/); the LiteSpeed Cache plugin has no compression feature of its own (community answer, not official) — [DigitalOcean community answer](https://www.digitalocean.com/community/questions/how-to-enable-gzip-compression-on-a-droplet-with-openlitespeed-wordpress-installation)

### Inferences
- Behind a server that ignores `.htaccess` (nginx, agensio), WP Super Cache with compression on and W3TC with its defaults will answer cached pages from PHP with `Content-Encoding: gzip` (and their own Vary/Cache-Control); WP Rocket will answer with plain HTML. A front server therefore sees both shapes from WordPress sites and must pass the first through untouched and may compress the second.
- The plugins' precompressed files (`index.html.gz`, `*.html_gzip`, `*.html_br`) are only reached directly when the server implements the plugin's rewrite logic; a server could serve them itself (like nginx `gzip_static` / W3TC's nginx snippet) but that means emulating each plugin's file naming and cookie bypass rules.
- Every plugin protects against double compression in its own way (PHP zlib check, `no-gzip` env for mod_deflate, `gzip off` in its nginx location) — evidence that the ecosystem expects the front server to skip anything that already carries `Content-Encoding`.

### Gaps
- Could not read Trac ticket #44815 itself (403); the version that first shipped without load-scripts compression is inferred from the 4.9 and 5.0 branch merges.
- LiteSpeed Cache plugin source was not read; whether it ever emits `Content-Encoding` from PHP is not confirmed.
- WP Super Cache's exact behaviour when compression is on but `$wp_cache_gzip_encoding` comes from a CDN-forwarded Accept-Encoding was not tested.

## Laravel, Symfony and Drupal

### Takeaway
Laravel and Symfony have no response compression of their own; third-party middleware packages
exist. Drupal 8+ removed "Compress cached pages" (its `response.gzip` key became dead config and was
deleted by an update) and leaves HTML compression to the web server, but it still writes `.gz`
(and `.br` when the PHP brotli extension is loaded) beside every aggregated CSS/JS file, with
`.htaccess` rules to serve them and to stop Apache compressing them again.

### Cited Findings
- Laravel: community middleware packages such as chr15k/laravel-response-compression (gzip or Brotli by client support, needs the Brotli PHP extension for br, global or per-route), erlandmuchasaj/laravel-gzip (`GZIP_MIN_LENGTH` default 256), open-southeners/laravel-response-compression (Laravel 11/12) — [chr15k/laravel-response-compression](https://github.com/chr15k/laravel-response-compression), [erlandmuchasaj/laravel-gzip on Packalyst](https://packalyst.com/packages/package/erlandmuchasaj/laravel-gzip), [open-southeners on Packagist](https://root.packagist.org/packages/open-southeners/laravel-response-compression)
- Laravel streaming: `response()->stream()` with a generator adds `X-Accel-Buffering: no` and calls `ob_flush()` (when `ob_get_level() > 0`) and `flush()` per chunk; `response()->eventStream()` sends `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`, writes `event:` / `data:` lines and ends with a `</stream>` event by default — [laravel/framework 12.x ResponseFactory.php](https://github.com/laravel/framework/blob/12.x/src/Illuminate/Routing/ResponseFactory.php)
- Symfony: `EventStreamResponse` (HttpFoundation, 7.4 branch) defaults `Connection: keep-alive`, `Content-Type: text/event-stream`, `Cache-Control: private, no-cache, no-store, must-revalidate, max-age=0`, `X-Accel-Buffering: no`, `Incremental: ?1`, `Pragma: no-cache`, `Expires: 0`; its doc comment points high-traffic use to Mercure — [symfony 7.4 EventStreamResponse.php](https://github.com/symfony/symfony/blob/7.4/src/Symfony/Component/HttpFoundation/EventStreamResponse.php); the plain `StreamedResponse` sets none of these — [symfony 7.4 StreamedResponse.php](https://github.com/symfony/symfony/blob/7.4/src/Symfony/Component/HttpFoundation/StreamedResponse.php)
- Drupal page compression: after the page cache moved to its own module, `response.gzip` "doesn't actually do anything any more"; the "Compress cached pages" option was removed but the key lingered — [drupal.org issue 2775381](https://www.drupal.org/node/2775381), [drupal.org issue 2892179](https://www.drupal.org/node/2892179); `system_update_8401` deletes the `response.gzip` and `response` keys from system.performance — [api.drupal.org system_update_8401](https://api.drupal.org/api/drupal/core%21modules%21system%21system.install/function/system_update_8401/8.9.x)
- Drupal 11.x defaults in system.performance: `cache.page.max_age: 0`, `css.preprocess: true`, `css.compress: true`, `js.preprocess: true`, `js.compress: true` — [core/modules/system/config/install/system.performance.yml (11.x)](https://git.drupalcode.org/project/drupal/-/raw/11.x/core/modules/system/config/install/system.performance.yml)
- Drupal AssetDumper: when `css.compress`/`js.compress` (or the old `.gzip`) is set it writes `<aggregate>.gz` (`gzencode(..., 9)`) and, if the PHP `brotli` extension is loaded, `<aggregate>.br` (`brotli_compress(..., 11, BROTLI_TEXT)`); the comment says the file is "served conditionally to browsers that accept gzip using .htaccess rules" and sites where rewrites do not work can turn compress off — [core/lib/Drupal/Core/Asset/AssetDumper.php (11.x)](https://git.drupalcode.org/project/drupal/-/raw/11.x/core/lib/Drupal/Core/Asset/AssetDumper.php)
- Drupal `.htaccess`: rewrites `css_*.css` / `js_*.js` to `.br` when `Accept-encoding` contains br and the file exists, else to `.gz`; then `[T=text/css,E=no-gzip:1,E=no-brotli:1]` "to prevent double compression", and for `.css.gz`/`.js.gz` `Header set Content-Encoding gzip` + `Header append Vary Accept-Encoding` (same with `br`) — [core/assets/scaffold/files/htaccess (11.x)](https://git.drupalcode.org/project/drupal/-/raw/11.x/core/assets/scaffold/files/htaccess)
- Drupal's on-demand aggregate controller sends `Cache-control` from a class constant and `public, max-age=3600, must-revalidate` in one branch; no `Content-Encoding` there — [AssetControllerBase.php (11.x)](https://git.drupalcode.org/project/drupal/-/raw/11.x/core/modules/system/src/Controller/AssetControllerBase.php)

### Inferences
- A Drupal site behind a server without `.htaccess` gets uncompressed aggregates unless the server itself serves the `.gz`/`.br` twins (a static-file feature) or compresses on the fly; the twins exist on disk either way.
- Symfony's SSE response hands a FastCGI server two fields that matter to the front server: `Connection: keep-alive` (hop-by-hop; must not be forwarded on HTTP/2 or HTTP/3) and `Incremental: ?1` (a request to deliver the response incrementally, i.e. not to buffer).
- Laravel's `ob_flush()` flushes only one output-buffer level, so with PHP's zlib compression on and output_buffering 4096 (see PHP section) its event streams are held back.

### Gaps
- No official Laravel or Symfony statement found that compression is left to the web server; "no built-in compression" is from the absence of a feature, not a quoted policy.
- The Drupal version that added the `.br` aggregates and renamed `.gzip` to `.compress` was not pinned down.
- Drupal 7 (end of life) `page_compression` behaviour not researched in detail.

## Ruby on Rails, Rack, Puma, Thruster

### Takeaway
Rails does not compress responses in its default middleware stack (no `Rack::Deflater`; it does
include `Rack::ETag` and `Rack::ConditionalGet`); Puma has no compression. Since Rails 8 the generated
Dockerfile starts the app behind Thruster, which gzips by default with random padding against
BREACH. Propshaft (the default asset pipeline) produces no `.gz`/`.br` files; Sprockets did (`.gz`
beside each compiled text asset), and `ActionDispatch::Static` serves `.br`/`.gz` twins if present.

### Cited Findings
- Default middleware stack of a fresh Rails app (guide for v8.1.4): `ActionDispatch::HostAuthorization`, `Rack::Sendfile`, `ActionDispatch::Static`, `Propshaft::Server`, ..., `Rack::Head`, `Rack::ConditionalGet`, `Rack::ETag`, `Rack::TempfileReaper`; no `Rack::Deflater` — [Rails guides: Rails on Rack](https://guides.rubyonrails.org/rails_on_rack.html)
- Rails asset pipeline guide (8.1.4): the pipeline "no longer includes transpilation, bundling, or compression by default"; "with CDNs automatically compressing assets, the need for manual compression has decreased" — [Rails guides: Asset Pipeline](https://guides.rubyonrails.org/asset_pipeline.html)
- `Rack::Deflater`: skips empty bodies, responses with `Cache-Control` containing `no-transform`, responses whose `content-encoding` is anything but identity, `Content-Length: 0`, types outside `:include` (default: all types), and a false `:if`; adds `Accept-Encoding` to Vary (unless Vary is `*` or already lists it); deletes Content-Length; `:sync` (default true) flushes the gzip stream after every body chunk — [rack lib/rack/deflater.rb](https://github.com/rack/rack/blob/main/lib/rack/deflater.rb)
- `Rack::ETag` buffers the body to compute a digest and sets a weak ETag `W/"<digest>"`; it is skipped when the response already has `ETag` or `Last-Modified` — [rack lib/rack/etag.rb](https://github.com/rack/rack/blob/main/lib/rack/etag.rb)
- Thruster: gzip enabled by default (`GZIP_COMPRESSION_ENABLED`), `GZIP_COMPRESSION_JITTER` default 32 bytes of random padding on compressed responses, `GZIP_COMPRESSION_DISABLE_ON_AUTH` default false (when true, no compression for requests carrying `Cookie`, `Authorization` or `X-Csrf-Token`); X-Sendfile on by default; a 64 MB cache of public assets (items up to 1 MB); runs as `thrust bin/rails server` in front of Puma (`TARGET_PORT` 3000) — [basecamp/thruster README](https://github.com/basecamp/thruster/blob/main/README.md)
- The Rails app generator's Dockerfile: `EXPOSE 80` and `CMD ["./bin/thrust", "./bin/rails", "server"]` unless `--skip-thruster` (then `EXPOSE 3000`, `CMD ["./bin/rails", "server"]`) — [railties Dockerfile.tt](https://github.com/rails/rails/blob/main/railties/lib/rails/generators/rails/app/templates/Dockerfile.tt)
- Sprockets: "By default when Sprockets generates a compiled asset file it will also produce a gzipped copy of that file" (CSS, JS, SVG only; `application-12345.css.gz`); assets meant to be served by nginx or `config.public_file_server` — [rails/sprockets README](https://github.com/rails/sprockets/blob/main/README.md); Propshaft's README lists what it does (digesting, load path, basic compilers) and nothing about compression — [rails/propshaft README](https://github.com/rails/propshaft/blob/main/README.md)
- `ActionDispatch::Static` / FileHandler: `precompressed: %i[ br gzip ]` by default for compressible types (`text/*`, `application/javascript`, `image/svg+xml`); if `path.br` exists it is returned "with a content-encoding: br header", `.gz` likewise, and `vary: accept-encoding` is set when other encodings exist — [actionpack static.rb](https://github.com/rails/rails/blob/main/actionpack/lib/action_dispatch/middleware/static.rb)
- Puma's README has no mention of gzip, compression or deflate (search of the file) — [puma README](https://github.com/puma/puma/blob/master/README.md)
- `ActionController::Live`: on first write sets `Cache-Control: no-cache` if unset and deletes Content-Length; the docs warn that `Rack::ETag` (in the default stack) buffers the response so streaming "may not work properly with Rack 2.2.x" and suggest setting `ETag` or `Last-Modified` or removing `Rack::ETag` — [actionpack metal/live.rb](https://github.com/rails/rails/blob/main/actionpack/lib/action_controller/metal/live.rb)

### Inferences
- A Rails app proxied directly to Puma sends uncompressed responses; a Rails 8 container proxied as generated (port 80, Thruster) sends gzip with jitter padding, so the front server sees `Content-Encoding: gzip` already and can only pass it through (no brotli/zstd unless Thruster's gzip is turned off with `GZIP_COMPRESSION_ENABLED=0`).
- Rails apps emit weak ETags from `Rack::ETag`, which survive front-server compression unchanged (nginx keeps weak ETags; Apache's AddSuffix still appends).

### Gaps
- Thruster's README states no version; whether Thruster honours `Cache-Control: no-transform` or skips `text/event-stream` was not checked in its source.
- Rails' own guidance specifically telling users to let nginx compress was not found in current guides (only the CDN remark).

## Python: Django, WhiteNoise, Flask-Compress, Gunicorn

### Takeaway
Django's `GZipMiddleware` is opt-in (not in the default MIDDLEWARE), compresses any content type
including streaming responses (flushed per chunk), adds up to 100 random bytes to every gzip stream
since Django 4.2 as a BREACH mitigation, weakens strong ETags and skips responses that already carry
`Content-Encoding`. WhiteNoise precompresses static files (gzip and Brotli) at collectstatic and serves
them with `Content-Encoding` and `Vary`. Flask-Compress (1.25) compresses by MIME list and size with
zstd/br/gzip/deflate. Gunicorn has no compression.

### Cited Findings
- Django docs (5.2): `GZipMiddleware.max_random_bytes` defaults to 100; Django "implements a technique called Heal The Breach (HTB). It adds up to 100 bytes ... of random bytes to each response"; it will NOT compress if the body is under 200 bytes, the response already has `Content-Encoding`, or the request lacks `gzip` in Accept-Encoding; a strong ETag is made weak (RFC 9110 8.8.1); `gzip_page()` per view; place it before middleware that read or write the body; `ConditionalGetMiddleware` should come after it — [Django docs: middleware](https://docs.djangoproject.com/en/5.2/ref/middleware/)
- Django 4.2 release notes: "GZipMiddleware now includes a mitigation for the BREACH attack. It will add up to 100 random bytes to gzip responses" — [Django 4.2 release notes](https://docs.djangoproject.com/en/dev/releases/4.2/)
- Django source: no Content-Type filter; `patch_vary_headers(response, ("Accept-Encoding",))` happens before the Accept-Encoding test (so Vary is added even when not compressing, once past the size and Content-Encoding checks); streaming (sync and async) responses are compressed and Content-Length deleted; non-streaming compressed content is used only if shorter; ETag `"x"` becomes `W/"x"` — [django/middleware/gzip.py](https://github.com/django/django/blob/main/django/middleware/gzip.py)
- Django's `compress_sequence` writes each streamed item and calls `zfile.flush()` before yielding, and puts the random bytes in the gzip header's filename field; level 6 — [django/utils/text.py](https://github.com/django/django/blob/main/django/utils/text.py)
- Current releases: Django 6.1.2, whitenoise 6.12.0, Flask-Compress 1.25, gunicorn 26.2.0 — [PyPI Django](https://pypi.org/project/Django/), [PyPI whitenoise](https://pypi.org/project/whitenoise/), [PyPI Flask-Compress](https://pypi.org/project/Flask-Compress/), [PyPI gunicorn](https://pypi.org/project/gunicorn/)
- WhiteNoise 6.12.0: `CompressedManifestStaticFilesStorage` / `CompressedStaticFilesStorage` create gzip and Brotli copies (Brotli needs `whitenoise[brotli]`), only when smaller; `WHITENOISE_SKIP_COMPRESS_EXTENSIONS` default jpg, jpeg, png, gif, webp, zip, gz, tgz, bz2, tbz, xz, br, swf, flv, woff, woff2; Brotli served only to browsers that ask (over HTTPS in practice); notes CloudFront drops Accept-Encoding except gzip unless configured to cache on it — [WhiteNoise Django guide](https://whitenoise.readthedocs.io/en/stable/django.html); responders set `Vary: Accept-Encoding` and `Content-Encoding: <encoding>` for a precompressed variant — [whitenoise responders.py](https://github.com/evansd/whitenoise/blob/main/src/whitenoise/responders.py)
- Flask-Compress: `COMPRESS_LEVEL` 6 (gzip), `COMPRESS_BR_LEVEL` 4, `COMPRESS_ZSTD_LEVEL` 3, `COMPRESS_MIN_SIZE` 500, `COMPRESS_ALGORITHM` from `['zstd', 'br', 'gzip', 'deflate']` (order breaks q-value ties), `COMPRESS_ALGORITHM_STREAMING` `['zstd', 'br', 'deflate']`, `COMPRESS_STREAMS` True, `COMPRESS_REGISTER` True (global) — [flask-compress README](https://github.com/colour-science/flask-compress); source: skips status outside 200-299, MIME types not listed, `Content-Encoding` already present, streams when disabled, small Content-Length; adds `Accept-Encoding` to Vary; a strong ETag becomes `"<etag>:<algorithm>"` — [flask_compress.py](https://github.com/colour-science/flask-compress/blob/master/flask_compress/flask_compress.py)
- Gunicorn's settings reference contains no gzip or compression setting (zero matches in the page) — [Gunicorn settings](https://docs.gunicorn.org/en/stable/settings.html)

### Inferences
- Django and Wagtail sites (as agensio's presets run them, Gunicorn behind the server) send uncompressed HTML unless the project added GZipMiddleware; their `/static/` files may have `.gz`/`.br` twins on disk if WhiteNoise's compressed storage ran at collectstatic, even when the front server, not WhiteNoise, serves `/static/`.
- Django's GZipMiddleware compresses `text/event-stream` and binary types alike and does not honour `no-transform`; with it on, an SSE view still streams (per-chunk flush) but its framing is gzip.

### Gaps
- Django docs do not state the default MIDDLEWARE list on the middleware page; the `startproject` template was not read (it is widely known not to include GZipMiddleware, but not verified here).
- FastAPI/Starlette `GZipMiddleware` (minimum_size, excluded `text/event-stream`) was not researched.

## Node.js: Express compression, Next.js, Fastify, Nuxt/Nitro, Ghost-style apps

### Takeaway
Node frameworks compress only through middleware, but some popular apps and frameworks turn it on
by default: Next.js `compress: true` (gzip only, through a vendored compression 1.7.4) and Ghost
`compress: true` (Express compression). Express compression 1.8.2 does br/gzip/deflate above 1 KB,
honours `Cache-Control: no-transform`, skips already-encoded responses and HEAD, always adds Vary, and
needs `res.flush()` for SSE. Fastify's plugin is global by default with zstd first. Nitro (Nuxt)
precompresses public assets only when asked and recommends letting the edge compress.

### Cited Findings
- Express compression (v1.8.2 on the page; npm latest 1.8.2): codings deflate, gzip, br (Brotli on Node 18+); `threshold` default `1kb`, "advisory" (if size is unknown when headers are written, it is assumed over the threshold); default filter uses the `compressible` module on Content-Type; "will never compress responses that include a Cache-Control header with the no-transform directive"; adds `res.flush()`; "does not work out of the box with server-sent events" — call `res.flush()` after each write (example sets `Content-Type: text/event-stream`, `Cache-Control: no-cache`) — [Express: compression middleware](https://expressjs.com/en/resources/middleware/compression.html), [npm registry compression/latest](https://registry.npmjs.org/compression/latest)
- Express compression source: `vary(res, 'Accept-Encoding')` after the filter and no-transform checks but before the threshold check (so small uncompressed answers still get Vary); skips when Content-Encoding is not `identity` ("already encoded") and for HEAD; preference `['br', 'gzip']` when Brotli is available (deflate supported, never preferred); removes Content-Length; no ETag handling — [expressjs/compression index.js](https://github.com/expressjs/compression/blob/master/index.js)
- Next.js `compress`: "By default, Next.js uses gzip to compress rendered content and static files when using `next start` or a custom server"; set `compress: false` to disable; "We do not recommend disabling compression unless you have compression configured on your server ... For example, you're using nginx and want to switch to brotli, set the compress option to false to allow nginx to handle compression" (page last updated 2025-06-16) — [Next.js docs: compress](https://nextjs.org/docs/app/api-reference/config/next-config-js/compress)
- Next.js implementation: `router-server.ts` calls `setupCompression()` from `next/dist/compiled/compression` unless `config.compress === false`; Next's package.json pins `"compression": "1.7.4"` (canary 16.5.0-canary.27; npm latest `next` 16.4.3) — [next.js router-server.ts](https://github.com/vercel/next.js/blob/canary/packages/next/src/server/lib/router-server.ts), [next package.json](https://github.com/vercel/next.js/blob/canary/packages/next/package.json), [npm next/latest](https://registry.npmjs.org/next/latest)
- Next.js self-hosting: "If you are using nginx or a similar proxy, you will need to configure it to disable buffering to enable streaming", e.g. a `headers()` rule adding `X-Accel-Buffering: no` to every path; load balancers and proxies in between must pass chunked responses without buffering; Partial Prerendering needs streaming — [Next.js self-hosting guide](https://nextjs.org/docs/app/guides/self-hosting)
- @fastify/compress (npm latest 9.2.2): encodings zstd (Node 22.15+/23.8+), br, gzip, deflate in that order; `*` maps to gzip; threshold 1024 bytes for buffered payloads (streams not subject); global by default (`global: false` to opt out); `x-no-compression` request header disables; removes Content-Length by default (`removeContentLengthHeader`); compressible types from mime-db plus `customTypes` — [fastify-compress README](https://github.com/fastify/fastify-compress), [npm @fastify/compress/latest](https://registry.npmjs.org/@fastify/compress/latest)
- Nitro (Nuxt's server): `compressPublicAssets` default false; true or `{ gzip, brotli, zstd }` precompresses "supported types of public assets and prerendered routes" larger than 1024 bytes into the public directory; recommends an edge (nginx, Apache, cloud) serve `.output/public/` and handle compression — [Nitro config](https://nitro.build/config)
- Ghost: `"compress": true` in the shared config defaults; the parent Express app does `if (config.get('compress') !== false) parentApp.use(compress())` ("enabled gzip compression by default") using the `compression` package — [Ghost defaults.json](https://github.com/TryGhost/Ghost/blob/main/ghost/core/shared/config/defaults.json), [Ghost server/web/parent/app.js](https://github.com/TryGhost/Ghost/blob/main/ghost/core/server/web/parent/app.js)
- Uptime Kuma (3.0.0-beta.0 on master): serves its built front end with `express-static-gzip("dist", { enableBrotli: true })` (precompressed `.br`/`.gz` files), dependency `express-static-gzip ~2.1.8` — [uptime-kuma server/server.js](https://github.com/louislam/uptime-kuma/blob/master/server/server.js), [uptime-kuma package.json](https://github.com/louislam/uptime-kuma/blob/master/package.json)
- Immich (server 3.3.0-rc.0) depends on `compression ^1.8.0` — [immich server/package.json](https://github.com/immich-app/immich/blob/main/server/package.json)

### Inferences
- Any Next.js app started with `next start` (the usual `app = "node"` style deployment) and every Ghost blog arrive at the front server already gzip-compressed for HTML and JSON; the front server cannot offer brotli/zstd for them unless the app is configured off (`compress: false` in next.config.js; `"compress": false` in Ghost's config).
- Express-based apps that use compression honour `Cache-Control: no-transform`, so a front server that does the same behaves consistently with them.
- Because Express compression adds `Vary: Accept-Encoding` even to answers it decided not to compress (below threshold), a front server cannot use "Vary: Accept-Encoding present" as a signal that the body is compressed; only `Content-Encoding` says that.

### Gaps
- Immich's actual use of the compression middleware (where it is mounted, options) was not located in source.
- Nuxt/Nitro runtime (h3) compression of dynamic responses: the Nitro page does not say; not researched further.
- Whether Next.js's compression is applied to its own streamed RSC responses with flushes (and how) was not examined.

## Go net/http, Java Spring Boot (Tomcat), ASP.NET Core

### Takeaway
Go's standard library server never compresses (only the client transport transparently gunzips);
compression comes from packages such as klauspost's gzhttp. Spring Boot leaves
`server.compression.enabled` false; when on, Tomcat compresses only text types above 2 KB and refuses
to compress a response with a strong ETag or an existing Content-Encoding. ASP.NET Core's middleware
is opt-in, off over HTTPS by default for BREACH/CRIME reasons, Brotli first (zstd in .NET 11), and
Microsoft's own advice is to prefer server-based compression (IIS, Apache, nginx).

### Cited Findings
- Go (net/http docs, go1.27.3): the only gzip behaviour documented is the client Transport, which adds `Accept-Encoding: gzip` itself unless `DisableCompression`, and transparently decodes the response then; nothing on the server side — [pkg.go.dev net/http](https://pkg.go.dev/net/http)
- `github.com/klauspost/compress/gzhttp` wraps handlers to compress with gzip or zstd (both on by default, zstd preferred), forked from the dead nytimes/gziphandler — [pkg.go.dev gzhttp](https://pkg.go.dev/github.com/klauspost/compress/gzhttp); `CAFxX/httpcompression` supports zstd, brotli, gzip, deflate, pre-1.0 — [pkg.go.dev httpcompression](https://pkg.go.dev/github.com/CAFxX/httpcompression)
- Spring Boot 4.1.2: compression supported by Jetty, Tomcat and Reactor Netty; enable with `server.compression.enabled=true`; responses must be at least 2048 bytes (`server.compression.min-response-size`); default types `text/html`, `text/xml`, `text/plain`, `text/css`, `text/javascript`, `application/javascript`, `application/json`, `application/xml`; `additional-mime-types` to extend — [Spring Boot how-to: web server](https://docs.spring.io/spring-boot/how-to/webserver.html); the properties appendix gives `server.compression.enabled` default `false`, `min-response-size` `2KB`, and `excluded-user-agents` — [Spring Boot application properties](https://docs.spring.io/spring-boot/appendix/application-properties/index.html)
- Tomcat `CompressionConfig.useCompression`: off when compressionLevel is 0; if `Content-Encoding` contains `identity` it does no content-encoding modification; if it contains any of `br, compress, dcb, dcz, deflate, gzip, pack200-gzip, zstd` it does not compress again; length below `compressionMinSize` (2048) or a type outside the compressible list skips it; honours `TE: gzip` (transfer-coding); "Check if the resource has a strong ETag": a non-`W/` ETag means no content-encoding compression — [apache/tomcat CompressionConfig.java](https://github.com/apache/tomcat/blob/main/java/org/apache/coyote/CompressionConfig.java)
- ASP.NET Core (docs for 10.0, monikers to 12.0, updated 2026-10-13): "Use server-based response compression technologies in IIS, Apache, or Nginx. The performance of the response compression middleware probably can't match that of the server modules"; Kestrel and HTTP.sys have no built-in compression; `EnableForHttps` "disabled by default because of the security risk" (CRIME, BREACH); IIS/Azure App Service may gzip even when the app does not; providers Brotli (default) and Gzip, zstd added in 11.0+; providers default to `CompressionLevel.Fastest`; removes Content-Length and Content-MD5 when compressing; compresses only when Content-Type matches the configured MIME list, no `Content-Range`, and HTTP unless HTTPS is enabled; `Vary: Accept-Encoding` added only when compressed up to .NET 10, always from .NET 11 — [Microsoft Learn: Response compression in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/performance/response-compression)
- ASP.NET Core source: `ShouldCompressResponse` returns false over HTTPS unless opted in, when the response has `Content-Range`, when it already has `Content-Encoding`, and when there is no Content-Type — [aspnetcore ResponseCompressionProvider.cs](https://github.com/dotnet/aspnetcore/blob/main/src/Middleware/ResponseCompression/src/ResponseCompressionProvider.cs)
- Microsoft's docs state "When Nginx proxies the request, the Accept-Encoding header is removed", tracked as aspnetcore issue #5989 — [Microsoft Learn: Response compression](https://learn.microsoft.com/en-us/aspnet/core/performance/response-compression); contradicted by nginx's proxy module docs, which say only `Host` and `Connection` are redefined by default (and, with caching enabled, the conditional and Range fields are not passed); stripping Accept-Encoding takes an explicit `proxy_set_header Accept-Encoding "";` — [nginx ngx_http_proxy_module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)

### Inferences
- ASP.NET Core behind a TLS-terminating front server sees `Request.IsHttps` false unless forwarded-headers handling sets the scheme, so an app with the middleware but without `EnableForHttps` may compress responses that the front server then delivers over HTTPS — defeating the BREACH opt-in the framework intended.
- Tomcat's strong-ETag rule and Caddy/Apache's ETag suffixing show the two accepted answers to "compressing a representation with a strong ETag": refuse to compress, or change the ETag.

### Gaps
- Go: no statement from the Go team on built-in server compression was found (no proposal located).
- Jetty and Reactor Netty compression conditions (Content-Encoding, ETag) were not read.

## Self-hosted applications (Ghost, Nextcloud, Grafana, Gitea and others) and their proxy docs

### Takeaway
Defaults differ: Ghost (compress on), Grafana 13 (enable_gzip on since 13.0, off in 12.x) and Home
Assistant (JSON above 1 KB) compress themselves; Gitea (ENABLE_GZIP off) and Nextcloud (compression
left to nginx/Apache in its docs, output_buffering forced to 0) do not. Official proxy docs mostly
put gzip in the proxy (Nextcloud, Mastodon) or say nothing (Gitea); Grafana warns that its compression
can "cause issues with poorly-configured reverse proxies".

### Cited Findings
- Ghost: `compress` default true, Express compression on the parent app unless `compress` is false — [Ghost defaults.json](https://github.com/TryGhost/Ghost/blob/main/ghost/core/shared/config/defaults.json), [Ghost parent/app.js](https://github.com/TryGhost/Ghost/blob/main/ghost/core/server/web/parent/app.js)
- Nextcloud (admin manual for 36, sample configs "Version 2026-06-09"): nginx config with `gzip on; gzip_vary on; gzip_comp_level 4; gzip_min_length 256; gzip_proxied expired no-cache no-store private no_last_modified no_etag auth; gzip_types application/atom+xml text/javascript application/javascript application/json application/ld+json ...` under the comment "Enable gzip but do not remove ETag headers"; troubleshooting notes that custom gzip caching of JS/CSS can cause problems — [Nextcloud admin manual: nginx](https://docs.nextcloud.com/server/latest/admin_manual/installation/nginx.html)
- Nextcloud forces `output_buffering=0` in `.user.ini` and `php_value output_buffering 0` in `.htaccess` (which also has `AddEncoding gzip svgz`); no mod_deflate rules there — [nextcloud/server .user.ini](https://github.com/nextcloud/server/blob/master/.user.ini), [nextcloud/server .htaccess](https://github.com/nextcloud/server/blob/master/.htaccess)
- Grafana: `[server] enable_gzip` default `true`, "recommended that most users leave it set at the default of true", may "increase CPU usage on constrained environments or cause issues with poorly-configured reverse proxies" — [Grafana docs: configure Grafana](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/); `conf/defaults.ini` has `enable_gzip = false` in v12.0.0 through v12.4.0 and `true` in v13.0.0 — [grafana conf/defaults.ini](https://github.com/grafana/grafana/blob/main/conf/defaults.ini); changed by PR #106093 "Config: Change default value for server.enable_gzip to true", merged 2026-03-24, milestone 13.0.x — [grafana PR 106093](https://github.com/grafana/grafana/pull/106093); a follow-up PR #118424 adding `enable_compression`/`content_encoding` was closed unmerged — [grafana PR 118424](https://github.com/grafana/grafana/pull/118424)
- Gitea: `[server] ENABLE_GZIP` default false, "Enable gzip compression for runtime-generated content, static resources excluded" — [Gitea config cheat sheet](https://docs.gitea.com/administration/config-cheat-sheet), [gitea app.example.ini](https://github.com/go-gitea/gitea/blob/main/custom/conf/app.example.ini); its reverse-proxy page has no gzip or buffering guidance for nginx/Apache; its IIS example blanks `HTTP_ACCEPT_ENCODING` before proxying and uses `urlCompression doDynamicCompression="true"` — [Gitea reverse proxies](https://docs.gitea.com/administration/reverse-proxies)
- Mastodon's shipped nginx config: `gzip on; gzip_disable "msie6"; gzip_vary on; gzip_proxied any; gzip_comp_level 6; gzip_buffers 16 8k; gzip_http_version 1.1; gzip_types ...; gzip_static on;` and `proxy_buffering off` for the streaming API location — [mastodon dist/nginx.conf](https://github.com/mastodon/mastodon/blob/main/dist/nginx.conf)
- Home Assistant compresses its own JSON responses above `MIN_COMPRESSED_RESPONSE_SIZE = 1024` bytes with aiohttp's `enable_compression()` ("Responses smaller than this fit within a single network packet") and swaps in `aiohttp_fast_zlib` — [home-assistant helpers/http.py](https://github.com/home-assistant/core/blob/dev/homeassistant/helpers/http.py), [home-assistant components/http/__init__.py](https://github.com/home-assistant/core/blob/dev/homeassistant/components/http/__init__.py)
- Vaultwarden's Cargo.toml lists brotli, deflate, gzip, zstd only as features of its reqwest HTTP client (favicons, version checks), not of its server — [vaultwarden Cargo.toml](https://github.com/dani-garcia/vaultwarden/blob/main/Cargo.toml)

### Inferences
- An administrator upgrading Grafana from 12 to 13 behind a compressing proxy silently moves compression from the proxy to Grafana; the proxy then passes Grafana's gzip through.
- For apps that compress by default (Ghost, Grafana 13, Next.js, Home Assistant, Thruster-fronted Rails), a front server's per-site compression setting has no effect unless the app's own switch is turned off; a hosting tool that wants brotli/zstd at the edge has to tell the administrator which app switch to flip.

### Gaps
- Ghost's official nginx/Ghost-CLI proxy configuration was not checked for gzip directives.
- Vaultwarden's server-side compression (Rocket) was not confirmed either way.

## Front server behaviour when the upstream already compresses, Vary and ETag, and the common advice

### Takeaway
The major front servers and frameworks all skip a response that already carries a non-identity
`Content-Encoding` (nginx skips on any non-empty value), so true double compression across the
proxy boundary is rare; the observed failures are double compression inside PHP, `.gz` cache files
served without `Content-Encoding`, and a decode mismatch after a layer changes encodings. They differ on
`no-transform` (Express, Rack::Deflater and Caddy honour it; nginx and Apache mod_deflate do not) and
on ETags (nginx weakens strong ETags, Apache and Caddy append the coding, Django weakens, Flask-Compress
appends, Tomcat refuses to compress). Vendor advice is consistent: compress in one place, preferably the
server/edge.

### Cited Findings
- nginx gzip header filter skips when the response status is not 200/403/404, when `Content-Encoding` is present with any non-empty value, when `Content-Length` is known and below `gzip_min_length`, when the type is not in `gzip_types`, or for header-only responses; then sets `gzip_vary` and calls `ngx_http_weak_etag(r)`; the file contains no `no-transform` handling — [nginx ngx_http_gzip_filter_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_gzip_filter_module.c)
- nginx 1.7.3 (2014): "weak entity tags are now preserved on response modifications, and strong ones are changed to weak" — [nginx CHANGES](https://nginx.org/en/CHANGES)
- nginx `gzip_proxied` (default off) concerns requests that arrived through a proxy, "determined by the presence of the 'Via' request header field", not responses from upstreams; `gzip_vary` default off; `gzip_min_length` default 20 and judged "only from the Content-Length response header field"; `gzip_types` default text/html — [nginx ngx_http_gzip_module](https://nginx.org/en/docs/http/ngx_http_gzip_module.html)
- Apache mod_deflate: "If it's already encoded, don't compress again" (any Content-Encoding token other than identity, 7bit, 8bit or binary stops it); `DeflateAlterETag AddSuffix|NoChange|Remove`, default AddSuffix ("default since 2.4.0, but prevents serving 'HTTP Not Modified' (304) responses to conditional requests for compressed content"), directive available from 2.4.58 — [Apache mod_deflate docs](https://httpd.apache.org/docs/2.4/mod/mod_deflate.html), [httpd mod_deflate.c](https://github.com/apache/httpd/blob/trunk/modules/filters/mod_deflate.c); the trunk source has no `no-transform` check — [httpd mod_deflate.c](https://github.com/apache/httpd/blob/trunk/modules/filters/mod_deflate.c)
- Caddy `encode`: only when the response has no `Content-Encoding`; returns false for `Cache-Control` containing `no-transform`; adds `Vary: Accept-Encoding` (also on 304); appends `-<encoding>` to a strong ETag and strips that suffix from `If-None-Match` before the upstream sees it (RFC 9110 8.8.3); sends headers at once for `text/event-stream` and for incremental responses — [caddy modules/caddyhttp/encode/encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go)
- Framework middlewares skip already-encoded responses: Django (`response.has_header("Content-Encoding")`) — [django gzip.py](https://github.com/django/django/blob/main/django/middleware/gzip.py); Express compression ("already encoded" unless identity) — [compression index.js](https://github.com/expressjs/compression/blob/master/index.js); Rack::Deflater (non-identity content-encoding) — [rack deflater.rb](https://github.com/rack/rack/blob/main/lib/rack/deflater.rb); Flask-Compress — [flask_compress.py](https://github.com/colour-science/flask-compress/blob/master/flask_compress/flask_compress.py); ASP.NET Core — [ResponseCompressionProvider.cs](https://github.com/dotnet/aspnetcore/blob/main/src/Middleware/ResponseCompression/src/ResponseCompressionProvider.cs); Tomcat — [CompressionConfig.java](https://github.com/apache/tomcat/blob/main/java/org/apache/coyote/CompressionConfig.java); PHP's zlib layer does not — [php-src zlib.c](https://github.com/php/php-src/blob/master/ext/zlib/zlib.c)
- `ERR_CONTENT_DECODING_FAILED` means the headers claim gzip but the body is not valid gzip, typically a caching/optimisation plugin compressing at the application level while the server also compresses — [cloudingenium explainer](https://kx.cloudingenium.com/en/error-330-neterr_content_decoding_failed-google-chrome-means/) (third-party)
- Advice to compress in one place: ASP.NET Core prefers server modules — [Microsoft Learn](https://learn.microsoft.com/en-us/aspnet/core/performance/response-compression); Next.js says turn `compress` off when nginx compresses — [Next.js compress](https://nextjs.org/docs/app/api-reference/config/next-config-js/compress); Nitro recommends the edge — [Nitro config](https://nitro.build/config); WP Super Cache says disable mod_deflate or zlib or the plugin's option — [readme.txt](https://github.com/Automattic/wp-super-cache/blob/trunk/readme.txt); W3TC support says keep its gzip off when the server already compresses — [WordPress.org support](https://wordpress.org/support/?p=1515285); Gitea's IIS example blanks Accept-Encoding to the app and compresses in IIS — [Gitea reverse proxies](https://docs.gitea.com/administration/reverse-proxies)

### Inferences
- For a front server, "upstream sent `Content-Encoding`" is the one reliable signal to pass the body through untouched; `Vary: Accept-Encoding` and a weak/strong ETag say nothing about whether the body is compressed (Express, Django and .NET 11 add Vary to uncompressed answers; PHP's zlib layer, conversely, sends no Vary on its uncompressed ones).
- When the front server compresses an uncompressed upstream answer that has a strong ETag, it must change it (weaken or suffix) and, if suffixing, strip the suffix from `If-None-Match` on the way back so the application's conditional logic still matches (Caddy's approach); weakening (nginx) keeps 304s working with no request rewrite but loses byte-range validators.
- An application's own `Vary` must be merged, not duplicated, when the front server adds `Accept-Encoding`.
- A front server that also honours `no-transform` matches the Express/Rack/Caddy behaviour applications built on those stacks expect.

### Gaps
- No measurement found of how often double compression actually reaches clients across a proxy boundary; the reports found are all PHP-plugin or misconfigured-.gz cases.
- Behaviour of CDNs (Cloudflare etc.) on already-encoded origins belongs to another researcher's scope and was not covered here.

## Server-sent events and streamed responses: headers that stop buffering or compression

### Takeaway
Frameworks signal "do not buffer" with `X-Accel-Buffering: no` (an nginx convention: Laravel's
`stream()` and `eventStream()`, Symfony's `EventStreamResponse`, Next.js's self-hosting advice) plus
`Content-Type: text/event-stream` and `Cache-Control: no-cache`; Symfony also sends
`Incremental: ?1`. None of the frameworks examined sends `Cache-Control: no-transform` on SSE.
In-app compression breaks SSE unless flushed (Express needs `res.flush()`, PHP's zlib layer stalls
behind output_buffering), and Rails' default `Rack::ETag` can buffer streams.

### Cited Findings
- nginx: buffering "can also be enabled or disabled by passing 'yes' or 'no' in the 'X-Accel-Buffering' response header field" (fastcgi_buffering; the same field is listed among the special headers `fastcgi_ignore_headers` can disable) — [nginx ngx_http_fastcgi_module](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html)
- Laravel 12: `eventStream()` → `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`; generator `stream()` → `X-Accel-Buffering: no`, `ob_flush()` + `flush()` per chunk — [ResponseFactory.php](https://github.com/laravel/framework/blob/12.x/src/Illuminate/Routing/ResponseFactory.php)
- Symfony 7.4: `EventStreamResponse` → `Connection: keep-alive`, `Content-Type: text/event-stream`, `Cache-Control: private, no-cache, no-store, must-revalidate, max-age=0`, `X-Accel-Buffering: no`, `Incremental: ?1`, `Pragma: no-cache`, `Expires: 0` — [EventStreamResponse.php](https://github.com/symfony/symfony/blob/7.4/src/Symfony/Component/HttpFoundation/EventStreamResponse.php)
- Rails: `ActionController::Live` sets `Cache-Control: no-cache` (if unset) and removes Content-Length on first write; `Rack::ETag` in the default stack buffers bodies, so set `ETag`/`Last-Modified` or remove it — [live.rb](https://github.com/rails/rails/blob/main/actionpack/lib/action_controller/metal/live.rb), [rack etag.rb](https://github.com/rack/rack/blob/main/lib/rack/etag.rb); `Rack::Deflater` flushes per chunk by default (`sync: true`) and skips `no-transform` — [deflater.rb](https://github.com/rack/rack/blob/main/lib/rack/deflater.rb)
- Express: compression "does not work out of the box with server-sent events"; call `res.flush()` after each write; responses with `Cache-Control: no-transform` are never compressed — [Express compression](https://expressjs.com/en/resources/middleware/compression.html)
- Next.js: add `X-Accel-Buffering: no` through `headers()` for streaming behind nginx — [Next.js self-hosting](https://nextjs.org/docs/app/guides/self-hosting)
- Django: GZipMiddleware compresses streaming responses and flushes the gzip stream after each chunk — [django text.py](https://github.com/django/django/blob/main/django/utils/text.py)
- Mastodon's nginx config turns `proxy_buffering off` for its streaming endpoint — [mastodon dist/nginx.conf](https://github.com/mastodon/mastodon/blob/main/dist/nginx.conf)
- Caddy's encoder writes the header section immediately for `text/event-stream` (exact media type, parameters allowed) and for incremental responses, and honours `no-transform` — [caddy encode.go](https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/encode/encode.go)
- PHP: with `zlib.output_compression` On and `output_buffering = 4096`, a PHP SSE loop's `ob_flush(); flush();` events were held until the script ended; with zlib Off they arrived on time — local FastCGI test on [php8.4-fpm 8.4.26](https://packages.debian.org/trixie/php8.4-fpm); Nextcloud forces `output_buffering=0` for its own streaming — [nextcloud .user.ini](https://github.com/nextcloud/server/blob/master/.user.ini)

### Inferences
- A FastCGI/proxy front server that wants to stream SSE correctly can key on `Content-Type: text/event-stream`, `X-Accel-Buffering: no` and `Incremental: ?1`; relying on `Cache-Control: no-transform` alone would miss every framework examined. On-the-fly compression of `text/event-stream` should either be skipped or flushed per upstream chunk.
- When PHP itself compresses an SSE stream (zlib on), the front server receives gzip fragments whose timing PHP's buffers control; it cannot fix a stall that happens inside PHP and should pass the encoded stream through.
- `Connection: keep-alive` from Symfony through FastCGI is a hop-by-hop field the server must drop, especially on HTTP/2 and HTTP/3 connections.

### Gaps
- Not checked: whether Laravel's `streamJson()` and Inertia/Livewire streaming set the same headers; FastAPI/Starlette `StreamingResponse` and `sse-starlette` headers; Spring `SseEmitter` and ASP.NET Core SSE (.NET 10 `TypedResults.ServerSentEvents`) headers.
- No framework documentation was found that recommends `Cache-Control: no-transform` for SSE specifically.
