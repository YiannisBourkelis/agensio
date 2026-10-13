# Official proxy configurations against the redirect and header design (as of 2026-10-13)

What 25 applications publish for running behind a reverse proxy, read directive by directive against
the two proposals: `docs/redirects.md` (sections 1-8: `http`, `canonical`, `hsts`, `[[site.redirect]]`)
and `docs/headers.md` (sections 1-4: `[[site.response_headers]]`, the refused names, the per-preset
baseline). Both documents were read as they stand in the working tree on 2026-10-13 (commit
`7937a6a` plus uncommitted edits to both files). The existing site features named as "another
feature" are those of `docs/configuration.md` at the same commit (0.1.0-alpha.72).

The applications, in the order of the sections below: Mastodon, Discourse, Ghost, Plausible CE,
Umami, Gitea, Forgejo, GitLab, Mattermost, Rocket.Chat, Matrix Synapse, Element Web, Keycloak,
Vaultwarden, n8n, Jellyfin, Home Assistant, Immich, Nextcloud All-in-One, Paperless-ngx, Grafana,
Uptime Kuma, BookStack, Outline, Metabase. The end of the file has the cross-cutting findings
(section 26), the summary table (27) and the design changes the evidence supports (28).

## Method

- **Sources.** Each project's own configuration at its latest release on 2026-10-12/13: the file in
  the project's repository at a pinned tag or commit, or the repository the docs site is built from.
  Where a docs site has no public source (Rocket.Chat, Outline), the page was read through the
  site's own export and is cited by URL, heading and fetch date. Every link in sections 1-25 is
  pinned; line numbers are those of the pinned file. Downloads were read as text, never executed,
  and were kept only in the session's scratch directory.
- **Who read what.** Five readers worked in parallel, five applications each, with the design
  summarised for them; this file joins their notes (sections 1-25, lightly renumbered) and adds the
  synthesis. The readers' per-group conclusions are folded into sections 26-28.
- **Re-checked against the pinned sources** (all matched): Synapse `docs/reverse_proxy.md` (the
  whole file, by hash), Mastodon `dist/nginx.conf` L29-30, L70, L76-79, L118-123, L149, L162 and
  `config.md` L28-38, Ghost-CLI `ssl-params.conf` L7-8 and `nginx-ssl.conf` L1-4 and L20-23,
  Discourse `nginx.sample.conf` L120-124 and L195-202, GitLab omnibus `recipes/nginx.rb` L63-75,
  Jellyfin `nginx.md` L44-55 and L88-90, Nextcloud `nginx-root.conf.sample` L11-15, L119-124,
  L136-148 and L226-251, Paperless wiki L20-40 and L58-62, Element `default.conf.template` L9-27,
  BookStack `public/.htaccess` L12-15, Vaultwarden `.env.template` L328-344, Rocket.Chat
  `getClientAddress.ts` and `remoteAddressMiddleware.ts`, Grafana `pkg/web/context.go` L71-92.
- **Community material the projects host.** The Vaultwarden, Uptime Kuma, Paperless-ngx and
  Plausible CE pages are GitHub wikis the projects publish but users write (Plausible's says its
  nginx and Apache examples "have not been tested by the maintainers"; Paperless's docs call its
  wiki "user-maintained"). They are included and marked so. Home Assistant's docs no longer
  publish any nginx, Apache or Caddy example (the old pages redirect to forum threads, not read);
  its one project-maintained proxy configuration is the NGINX SSL proxy add-on.
- **Projects with little or nothing to classify.** Keycloak, Immich and Gitea publish proxy
  configurations with no redirect and no response-header directive at all; Umami publishes two
  nginx snippets; Metabase one bare nginx block plus an old Elastic Beanstalk bundle its docs still
  link; Outline one nginx page.
- **Marks.** "unverified" means not confirmed from a primary source in this session; "inferred"
  means the reader's interpretation of code or config, not a statement in the source.

### Classes

| class | meaning | abbreviations used in sections 1-25 |
|---|---|---|
| EXPRESSIBLE | an agensio setting of the design says it; the TOML is given | EXPR |
| NEEDS A CHANGE | the design lacks it; the smallest change is named | CHANGE |
| NOT OFFERED ON PURPOSE | the design leaves it out and says why; whether the app still works is stated | NOT-OFFERED |
| NOT A REDIRECT/HEADER RULE | another existing agensio feature covers it, named | OTHER, NOT A RULE |

### How the nginx directives were read

- `add_header` without `always` reaches only 200, 201, 204, 206, 301, 302, 303, 304, 307 and 308;
  with `always`, every status. A location inherits the `add_header` lines of an outer level only
  when it has none of its own, which is why several configurations repeat HSTS in every location.
- `expires N` sets `Expires` (now + N, a moving date) and `Cache-Control: max-age=N`; a following
  `add_header Cache-Control ...` adds a second `Cache-Control` line. A moving `Expires` cannot be
  written as fixed text; `Cache-Control: max-age=N` alone carries the same meaning (RFC 9111 5.3).
- agensio's `when = "success"` is 2xx and 304, so it leaves out the 3xx that nginx's `add_header`
  reaches; for a cache lifetime that is the safer reading.
- A `location /x/` with `proxy_pass` makes nginx answer the bare `/x` with a 301 to `/x/` without
  any directive saying so (Grafana and BookStack sub-paths rely on it).

### agensio facts checked in the source (0.1.0-alpha.72, commit `7937a6a`)

These decide several rows, so they were read in the code, and one was run:

- **MIME type by extension only.** `mime_for_path` (`src/mime.cpp` L118-134) answers
  `application/octet-stream` for a name without an extension; there is no configuration key to
  override it, and `Content-Type` is a refused name in `[[site.response_headers]]`.
- **A JSON answer for an extensionless `.well-known` path works today.** Run on alpha.72
  (2026-10-13): a site with `<root>/.well-known/matrix/server.json` and
  `[[site.location]] path = "/.well-known/matrix/server"`, `match = "exact"`,
  `try_files = ["/.well-known/matrix/server.json"]` answers `GET /.well-known/matrix/server` with
  200 and `Content-Type: application/json; charset=utf-8`. This is the lighttpd form of Synapse's
  docs (section 11) and turns the Matrix rows from "needs a change" into "expressible".
- **No fixed-body handler**: the location handlers are `static`, `fastcgi`, `proxy`, `cgi`, `deny`.
- **A filename condition exists once, inside a preset**: `LocationConfig::hashed_headers`
  (`src/handlers/static.cpp` L625-626, set only for Django's `/static/` in `src/config.cpp`
  L978-979) is a precedent for a header that depends on the file name.
- **Request fields to an origin** (`src/handlers/proxy.cpp` L91-119): every client field goes
  through except the hop-by-hop ones, `Expect`, those listed in `Connection` and those the
  configuration sets; `X-Forwarded-For`, `-Host`, `-Proto`, `-Port` and `Forwarded` from an
  untrusted client are dropped and rebuilt. So a client's own `X-Real-IP`, `CF-Connecting-IP`,
  `True-Client-IP` or `X-Plausible-IP` reaches the application unchanged (section 26.3).
- **Host for HTTP/2 and HTTP/3 requests**: a proxied request without a `Host` field gets one from
  `:authority` (`proxy.cpp` L123-126), which Home Assistant's aiohttp requires.
- **An origin's `Upgrade` on a non-101 answer** is dropped by the HTTP/2 and HTTP/3 writers
  (`fields::connection_specific`, `src/http2/writer.hpp` L566, `src/http3/connection.hpp` L678) and
  passed on over HTTP/1, where it is legal. That covers Nextcloud's `proxy_hide_header Upgrade`.
- **Upstreams are IP literals** (`src/upstream/client.cpp` L94-99: "names are resolved in a later
  phase").
- **No duration grammar yet**: `trash_keep` is an integer of days; the design's `max_age = "2y"`
  introduces one without saying which units it takes (section 28.1).
- **One name on two addresses is allowed** (`docs/configuration.md` L1530 names only "a name both
  claim on one address" as a conflict), so a plain-HTTP site and a TLS site may share a name on
  different listeners.

## 1. Mastodon

**Version read:** `v4.7.3`, the latest release (published 2026-10-01, branch `stable-4.7`). For
context, `dist/nginx.conf` at `v4.5.0` was also read.

**Sources:**
- https://github.com/mastodon/mastodon/blob/v4.7.3/dist/nginx.conf: the official template.
  `docs/admin/install.md` lines 186-217 say to copy it to `/etc/nginx/sites-available/mastodon`.
- docs.joinmastodon.org, source `mastodon/documentation` at commit
  `58425765225abf378b08ddf0b1d48403674e7afa` (2026-10-09):
  - https://github.com/mastodon/documentation/blob/58425765225abf378b08ddf0b1d48403674e7afa/content/en/admin/config.md (served as https://docs.joinmastodon.org/admin/config/)
  - https://github.com/mastodon/documentation/blob/58425765225abf378b08ddf0b1d48403674e7afa/content/en/admin/optional/object-storage-proxy.md (https://docs.joinmastodon.org/admin/optional/object-storage-proxy/)
- Application source at v4.7.3, for what the app sends itself:
  - `config/environments/production.rb`
  - `config/initializers/content_security_policy.rb`
  - `config/initializers/cors.rb`
  - `app/controllers/statuses_controller.rb`
  - Rails `v8.1.3.1` (from `Gemfile.lock` line 653) `actionpack/lib/action_dispatch/middleware/ssl.rb`

### Directives: `dist/nginx.conf` (v4.7.3)

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| [L29](https://github.com/mastodon/mastodon/blob/v4.7.3/dist/nginx.conf#L29)-[L30](https://github.com/mastodon/mastodon/blob/v4.7.3/dist/nginx.conf#L30), port-80 server | `location /.well-known/acme-challenge/ { allow all; }` / `location / { return 301 https://$host$request_uri; }` | plain HTTP to HTTPS, ACME exempt (inferred from structure) | EXPRESSIBLE | `http = "redirect"` (the default for a TLS site on 443). The status is 308 instead of 301, and ACME is exempt by design. |
| [L70](https://github.com/mastodon/mastodon/blob/v4.7.3/dist/nginx.conf#L70), `location /` | `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains";` | HSTS on static files from `public/` (`try_files $uri @mastodon`). It does not reach `@mastodon`, a separate named location, whose answers get HSTS from Rails `force_ssl` (see App guidance). | EXPRESSIBLE | `hsts = { max_age = "2y", subdomains = true }`. Sent on every HTTPS answer and replaces Rails' own copy, which has the same value. |
| [L77](https://github.com/mastodon/mastodon/blob/v4.7.3/dist/nginx.conf#L77)-78, `location ^~ /assets/` | `add_header Cache-Control "public, max-age=2419200, must-revalidate";` `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains";` | 28-day cache for compiled assets served from disk (path prefix, not extension). HSTS is repeated because the block's own `add_header` would otherwise drop the inherited one (inferred). | EXPRESSIBLE | `[[site.response_headers]]` `path = "/assets/"`, `when = "success"`, `set = { "Cache-Control" = "public, max-age=2419200, must-revalidate" }`. HSTS comes from `hsts`. |
| [L83](https://github.com/mastodon/mastodon/blob/v4.7.3/dist/nginx.conf#L83)-84 `^~ /avatars/`; [L89](https://github.com/mastodon/mastodon/blob/v4.7.3/dist/nginx.conf#L89)-90 `^~ /emoji/`; [L95](https://github.com/mastodon/mastodon/blob/v4.7.3/dist/nginx.conf#L95)-96 `^~ /headers/`; [L101](https://github.com/mastodon/mastodon/blob/v4.7.3/dist/nginx.conf#L101)-102 `^~ /ocr/`; [L107](https://github.com/mastodon/mastodon/blob/v4.7.3/dist/nginx.conf#L107)-108 `^~ /packs/`; [L113](https://github.com/mastodon/mastodon/blob/v4.7.3/dist/nginx.conf#L113)-114 `^~ /sounds/` | each block: `add_header Cache-Control "public, max-age=2419200, must-revalidate";` `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains";` | same as `/assets/`: static files by path prefix | EXPRESSIBLE | One rule per prefix (6 rules), e.g. `path = "/packs/"`, `when = "success"`, `set = { "Cache-Control" = "public, max-age=2419200, must-revalidate" }`. HSTS comes from `hsts`. |
| [L119](https://github.com/mastodon/mastodon/blob/v4.7.3/dist/nginx.conf#L119)-122, `location ^~ /system/` | `add_header Cache-Control "public, max-age=2419200, immutable";` `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains";` `add_header X-Content-Type-Options nosniff;` `add_header Content-Security-Policy "default-src 'none'; form-action 'none'";` | user-uploaded media from disk: long cache, plus nosniff and a locked-down CSP so an uploaded file cannot run as a document (inferred) | EXPRESSIBLE | Rule 1: `path = "/system/"`, `when = "success"`, `set = { "Cache-Control" = "public, max-age=2419200, immutable" }`. Rule 2: `path = "/system/"`, `set = { "X-Content-Type-Options" = "nosniff", "Content-Security-Policy" = "default-src 'none'; form-action 'none'" }`. `set` on the CSP is safe because these are disk files with no app CSP. |
| [L149](https://github.com/mastodon/mastodon/blob/v4.7.3/dist/nginx.conf#L149), `location @mastodon` | `proxy_pass_header Server;` | pass Rails' `Server: Mastodon` (production.rb L101) instead of nginx's | NOT OFFERED ON PURPOSE | `Server` is refused in rules (server-wide `[server] server_header`), and agensio drops the origin's `Server`. Cosmetic; the app works. |
| [L162](https://github.com/mastodon/mastodon/blob/v4.7.3/dist/nginx.conf#L162), `location @mastodon` | `add_header X-Cached $upstream_cache_status;` | debug field for nginx's `proxy_cache` | NOT OFFERED ON PURPOSE | Variables are refused, and agensio has no proxy cache to report on. The app works. |

**Removed between v4.5.0 and v4.7.3 (context only):**
- `location = /sw.js { add_header Cache-Control "public, max-age=604800, must-revalidate"; ... }` is gone.
- The prefixes were regexes `location ~ ^/assets/` in v4.5.0. They are `^~` prefixes in v4.7.3.
- `/shortcuts/` was dropped and `/ocr/` added.

### Directives: docs.joinmastodon.org

| source / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| [config.md L31-L34](https://github.com/mastodon/documentation/blob/58425765225abf378b08ddf0b1d48403674e7afa/content/en/admin/config.md#L28-L38), section `WEB_DOMAIN`, on the **apex** server (`example.com`, which hosts another site) | `location /.well-known/webfinger {` `add_header Access-Control-Allow-Origin '*';` `return 301 https://mastodon.example.com$request_uri;` `}` | handles `@alice@example.com` when Mastodon runs on `mastodon.example.com`. L38: "You must serve the redirect with CORS headers; otherwise, some functions of Mastodon's web UI will not work. For example: `Access-Control-Allow-Origin: *`" | EXPRESSIBLE | On the **apex site**: `[[site.redirect]]` with `from = "/.well-known/webfinger"`, `match = "exact"`, `to = "https://mastodon.example.com/.well-known/webfinger"`, `status = 301` (query kept by default), and `[[site.response_headers]]` with `path = "/.well-known/webfinger"`, `match = "exact"`, `set = { "Access-Control-Allow-Origin" = "*" }`. The rules apply to redirects, so CORS goes on the 301. A permanent redirect also gets agensio's `Cache-Control: max-age=86400`, which nginx does not send. |
| config.md, same section | (nothing about `host-meta` or `nodeinfo`) | grep of `content/en/admin` for `host-meta` and `nodeinfo`: no hits | none | Only WebFinger delegation is documented. |
| [config.md L793-L800](https://github.com/mastodon/documentation/blob/58425765225abf378b08ddf0b1d48403674e7afa/content/en/admin/config.md#L793-L800), section `CDN_HOST` | prose: "You must serve the files with CORS headers ... For example, `Access-Control-Allow-Origin: *`" | assets served from a separate host or CDN | EXPRESSIBLE | On the assets site: `path = "/"`, `set = { "Access-Control-Allow-Origin" = "*" }`. |
| [object-storage-proxy.md L50-L59](https://github.com/mastodon/documentation/blob/58425765225abf378b08ddf0b1d48403674e7afa/content/en/admin/optional/object-storage-proxy.md#L50-L59), `location @s3` on `files.example.com` | `proxy_hide_header Set-Cookie;` `proxy_hide_header 'Access-Control-Allow-Origin';` `proxy_hide_header 'Access-Control-Allow-Methods';` `proxy_hide_header 'Access-Control-Allow-Headers';` `proxy_hide_header x-amz-id-2;` `proxy_hide_header x-amz-request-id;` `proxy_hide_header x-amz-meta-server-side-encryption;` `proxy_hide_header x-amz-server-side-encryption;` `proxy_hide_header x-amz-bucket-region;` `proxy_hide_header x-amzn-requestid;` | doc L89-90: "Prevents the object storage provider from setting cookies" and "Removes unnecessary headers returned by the object storage provider" | NOT A REDIRECT/HEADER RULE | `proxy = { hide = ["Set-Cookie", "Access-Control-Allow-Origin", ...] }` on that location. For every name except `Set-Cookie`, `[[site.response_headers]] remove = [...]` would also work. |
| [L69-L74](https://github.com/mastodon/documentation/blob/58425765225abf378b08ddf0b1d48403674e7afa/content/en/admin/optional/object-storage-proxy.md#L69-L74), `location @s3` | `expires 1y;` `add_header Cache-Control public;` `add_header 'Access-Control-Allow-Origin' '*';` `add_header X-Cache-Status $upstream_cache_status;` `add_header X-Content-Type-Options nosniff;` `add_header Content-Security-Policy "default-src 'none'; form-action 'none'";` | doc L94-96: "cacheable by browsers for up to a year", "Adds CORS headers necessary for Mastodon's web UI", cache hit/miss field | EXPRESSIBLE, except `X-Cache-Status`, which is NOT OFFERED ON PURPOSE | `path = "/"`, `when = "success"`, `set = { "Cache-Control" = "max-age=31536000, public" }`, plus a rule with `path = "/"`, `set = { "Access-Control-Allow-Origin" = "*", "X-Content-Type-Options" = "nosniff", "Content-Security-Policy" = "default-src 'none'; form-action 'none'" }`. **The proxy itself NEEDS A CHANGE (not a header rule):** `proxy_pass $s3_backend$uri` to `https://BUCKET.S3HOST` needs a DNS-named upstream, which agensio refuses. `limit_except GET { deny all; }` maps to location `methods = ["GET"]` (405 instead of 403). |
| [object-storage-proxy.md L143](https://github.com/mastodon/documentation/blob/58425765225abf378b08ddf0b1d48403674e7afa/content/en/admin/optional/object-storage-proxy.md#L143), section "Migration" | prose: "You may want to add a `rewrite` or `redirect` rule to the `location ^~ /system/` section in `nginx.conf` which appropriately sends this traffic to the new location." | old local media URLs to the new files host | EXPRESSIBLE | `[[site.redirect]]` with `from = "/system/"`, `to = "https://files.example.com/"`, `status = 301`, remainder kept. This assumes the S3 key equals the path after `/system/`, which is inferred and matches the alias host layout. |

### Other directives (existing features)
- **WebSocket** `/api/v1/streaming` (L126-141, upstream `streaming` on :4000, `least_conn`, `proxy_buffering off`): `[[site.location]]` with `path = "/api/v1/streaming"` and `upstream = "http://127.0.0.1:4000"`. WebSocket is automatic. Streaming without buffering via `proxy = { buffering = false }`. Several streaming processes would be an upstream group (round-robin, not least-conn).
- `client_max_body_size 99m` (L54) maps to the site's `max_body_size = "99MB"`. `proxy_read_timeout 120` (L55) maps to `proxy = { read_timeout = 120 }`.
- `proxy_set_header Host $host`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`, `Proxy ""` (L127-131, L144-148): agensio does these by default. It passes Host and replaces X-Forwarded-For/Proto. `X-Real-IP` is not needed by Rails, but `proxy = { headers = { "X-Real-IP" = "$remote_addr" } }` adds it. `Proxy ""` (httpoxy): agensio forwards other client fields; `headers = { "Proxy" = "" }` removes it.
- **Static files from disk:**
  - `root /home/mastodon/live/public` with `try_files $uri @mastodon` (L57, L71) has no agensio equivalent: there is no try_files fallback to a proxy.
  - `app = "rails"` proxies everything (`configuration.md` around line 595).
  - Use per-prefix `[[site.location]]` blocks with `alias = "/home/mastodon/live/public/<dir>"` and `final = true` for `/assets/`, `/packs/`, `/system/`, `/emoji/`, `/avatars/`, `/headers/`, `/sounds/`, `/ocr/`.
  - Leave the rest (`/500.html`, `/robots.txt`, `/favicon.ico`) to Rails with `RAILS_SERVE_STATIC_FILES=true` (config.md L161-163).
- gzip (L59-66) has no on-the-fly equivalent. `gzip_static on` maps to agensio serving `.gz` and `.br` twins.
- `proxy_cache` (L22, L158-161) has no equivalent in agensio.
- `error_page 404 500 501 502 503 504 /500.html;` (L167) has no custom error pages in agensio; its own error pages are used. The app still works.

### App guidance (Mastodon)
- **HSTS** has two sources:
  - **nginx:** `max-age=63072000; includeSubDomains`, with no preload (dist/nginx.conf L70).
  - **Rails:** `config.force_ssl = true` ([production.rb L38](https://github.com/mastodon/mastodon/blob/v4.7.3/config/environments/production.rb#L38)) sends `max-age=63072000; includeSubDomains` on app answers ([Rails ssl.rb L67-73](https://github.com/rails/rails/blob/v8.1.3.1/actionpack/lib/action_dispatch/middleware/ssl.rb#L67-L73): `{ expires: HSTS_EXPIRES_IN, subdomains: true, preload: false }`).
  - `force_ssl` also redirects non-HTTPS requests, except `/health`, `.onion` and `.i2p` (production.rb L41-45). The proxy must send `X-Forwarded-Proto: https`, which agensio does.
- **CSP:**
  - The app sends its own CSP on its answers (`config/initializers/content_security_policy.rb` L15-35: `default-src 'none'`, `frame-ancestors 'none'`, nonce for style-src). The proxy must not set one on app paths. A `set` would replace a policy with per-request nonces (inferred).
  - The nginx CSP is only on `/system/` static uploads.
- **X-Frame-Options:**
  - Rails default headers send `X-Frame-Options: DENY`, `nosniff`, `X-XSS-Protection: 0`, `Referrer-Policy: same-origin` ([production.rb L100-106](https://github.com/mastodon/mastodon/blob/v4.7.3/config/environments/production.rb#L100-L106)).
  - The embed page `/@user/:id/embed` deletes `X-Frame-Options` and drops `frame-ancestors` ([statuses_controller.rb L20-22, L47](https://github.com/mastodon/mastodon/blob/v4.7.3/app/controllers/statuses_controller.rb#L20-L47)).
  - A proxy frame field, even `default` (only if absent), would break post embeds. The embed address is a suffix (`/embed`), which a path rule cannot exempt.
- **CORS:** the app handles it itself with rack-cors, `origins '*'`, on `/.well-known/*`, `/nodeinfo/*`, `/api/*` and the OAuth endpoints ([cors.rb L10-28](https://github.com/mastodon/mastodon/blob/v4.7.3/config/initializers/cors.rb#L10-L28)). The proxy adds CORS only on the apex WebFinger redirect, the CDN host and the S3 proxy, all with a fixed `*`. There is no origin echo anywhere.
- **`.well-known`:**
  - **Apex domain:** only WebFinger delegation, as a 301 plus `Access-Control-Allow-Origin: *` (config.md L28-38).
  - **On the Mastodon host:** host-meta and nodeinfo are answered by the app. Nothing at the proxy.
- **Trusting the proxy:** `TRUSTED_PROXY_IP` defaults to loopback and private ranges (config.md L173-185). It is used by `config.action_dispatch.trusted_proxies` (production.rb L32). agensio on the same host is trusted by default.
- **Redirect of `/` to a sub-path:** none. Mastodon does not support a sub-path.

---

## 2. Discourse

**Version read:**
- **discourse/discourse** `v2026.10.0-latest` (commit `a51251632c2dae3e0be8e0ba9119dc295b838128`, 2026-09-22). `config/nginx.sample.conf` is byte-identical at `v2026.9.0`. There is no `stable` branch in the new scheme. The tags `v2026.9.0` and `v2026.10.0-latest` exist.
- **discourse/discourse_docker** `main` at `ac99052ff83bb79df1ad99684aa40e879aff2b27` (2026-10-06). It has no tags or releases.
- **meta.discourse.org** topic 17247, first post, version 53, updated 2026-06-29.

**Context that decides most rows:**
- [docs/INSTALL.md L7](https://github.com/discourse/discourse/blob/v2026.10.0-latest/docs/INSTALL.md#L7): "The only officially supported installs of Discourse are Docker based."
- In that install, `nginx.sample.conf` is copied into the container (`web.template.yml` L141) and stays there. agensio would replace only the **outer** proxy of the meta guide.
- The rows for `nginx.sample.conf` below therefore describe a hypothetical agensio *in place of* the inner nginx. That is not the supported setup.

**Sources:**
- https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf
- https://github.com/discourse/discourse_docker/blob/ac99052ff83bb79df1ad99684aa40e879aff2b27/templates/web.ssl.template.yml
- `templates/web.template.yml`, `web.socketed.template.yml`, `web.letsencrypt.ssl.template.yml`, `offline-page.template.yml` and `cloudflare.template.yml` at the same commit. Grep of all templates and samples for `add_header`, `return 30x`, `rewrite ... permanent` and `expires` finds only the four lines in `web.ssl.template.yml`.
- https://meta.discourse.org/t/run-other-websites-on-the-same-machine-as-discourse/17247: post #1, raw from `/raw/17247` lines 1-112, section "Create an NGINX 'site' for the outer nginx".
- App source at the tag, for what the app sends itself:
  - `lib/middleware/default_headers.rb`
  - `app/controllers/embed_controller.rb`
  - `app/controllers/application_controller.rb`
  - `lib/content_security_policy/default.rb`
  - `config/site_settings.yml`

### Directives: outer proxy (meta guide, the supported way to put another server in front)

| source / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| meta 17247 post #1, raw L74-82, section "Create an NGINX 'site' for the outer nginx" | `proxy_pass http://unix:/var/discourse/shared/standalone/nginx.http.sock:;` `proxy_set_header Host $http_host;` `proxy_http_version 1.1;` `proxy_set_header X-Forwarded-For $remote_addr;` `proxy_set_header X-Forwarded-Proto $scheme;` `proxy_set_header X-Real-IP $remote_addr;` | outer TLS proxy to the container's unix socket; HTTPS through `certbot --nginx` | NOT A REDIRECT/HEADER RULE | `app = "proxy"`, `upstream = "unix:/var/discourse/shared/standalone/nginx.http.sock"`, `proxy = { headers = { "X-Real-IP" = "$remote_addr" } }`. X-Real-IP is required; see App guidance. |
| same | (no `add_header`, no `return`) | certbot may add its own HTTP to HTTPS redirect (**unverified**, not in the post) | EXPRESSIBLE | `http = "redirect"`, `hsts = true` if wanted. |

### Directives: discourse_docker `templates/web.ssl.template.yml` (the container's own TLS, when no outer proxy)

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| [L32-L37](https://github.com/discourse/discourse_docker/blob/ac99052ff83bb79df1ad99684aa40e879aff2b27/templates/web.ssl.template.yml#L32-L37), port-80 server | `location ~ /.well-known { root /var/www/discourse/public; allow all; }` `return 301 https://${DISCOURSE_HOSTNAME}\$request_uri;` | HTTP to HTTPS on the one canonical host | EXPRESSIBLE | `http = "redirect"` plus `canonical = "forum.example.com"`: one hop, 308. **Note (inferred from nginx's phase order):** a server-level `return` runs before location matching, so this `.well-known` location is never reached. Let's Encrypt issuance uses a separate temporary nginx (`web.letsencrypt.ssl.template.yml` L41-49). |
| [L59](https://github.com/discourse/discourse_docker/blob/ac99052ff83bb79df1ad99684aa40e879aff2b27/templates/web.ssl.template.yml#L59), server outlet `20-https.conf`, and [L67](https://github.com/discourse/discourse_docker/blob/ac99052ff83bb79df1ad99684aa40e879aff2b27/templates/web.ssl.template.yml#L67), `@discourse` outlet | `add_header Strict-Transport-Security 'max-age=31536000';` | HSTS for 1 year, no subdomains, no preload. Repeated in `@discourse` because that location is separate. **Inferred:** `location /` in nginx.sample.conf has its own `add_header ETag ""` (L94), so static assets and the nested locations do not inherit the server-level HSTS. It reaches Rails answers (`@discourse`), `/favicon.ico` and the server-level redirects. | EXPRESSIBLE | `hsts = true`, which also reaches every static answer. |
| [L61-L63](https://github.com/discourse/discourse_docker/blob/ac99052ff83bb79df1ad99684aa40e879aff2b27/templates/web.ssl.template.yml#L61-L63), HTTPS server | `if (\$http_host != ${DISCOURSE_HOSTNAME}) {` `rewrite (.*) https://${DISCOURSE_HOSTNAME}\$1 permanent;` `}` | every other Host, including an IP or an unknown name, goes 301 to the canonical host | EXPRESSIBLE for listed names; NOT OFFERED ON PURPOSE for unlisted names | `canonical = "forum.example.com"` with the other names in `server_name` gives 308. Hosts the site does not list (an IP, a random Host) are not redirected, by design (redirects.md 3.3). The app works. |
| [offline-page.template.yml L13-17](https://github.com/discourse/discourse_docker/blob/ac99052ff83bb79df1ad99684aa40e879aff2b27/templates/offline-page.template.yml#L13-L17) | `error_page 502 /error_page.html;` | static offline page while the app restarts | NOT A REDIRECT/HEADER RULE | agensio has no custom error page and serves its own 502. |

### Directives: `config/nginx.sample.conf` (inner nginx, v2026.10.0-latest)

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| [L78](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf#L78), server | `etag off;` | comment L75-77: "without weak etags we get zero benefit from etags on dynamically compressed content ... use dates" | NOT OFFERED ON PURPOSE | Not a header rule. agensio has no dynamic compression: twins carry their own ETag. |
| [L86-L90](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf#L86-L90), `location /favicon.ico` | `return 204;` | comment L85: "bypass rails stack with a cheap 204 for favicon.ico requests" | NOT A REDIRECT/HEADER RULE | No fixed-status answer except 404 (`handler = "deny"`) or 410 (a redirect rule). Leaving it to Discourse works (cost only). What Discourse answers there is **unverified**. |
| [L94](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf#L94), `location /` | `add_header ETag "";` | strip ETag (same reason as L75-77). In nginx an empty value on `ETag` deletes it (headers filter, inferred from nginx source). Nested locations with no `add_header` of their own inherit it. | NOT OFFERED ON PURPOSE | `ETag` is refused even in `remove` (a representation field, headers.md 2.5). agensio has no dynamic gzip, so the stated reason does not apply. The app works. |
| [L120-L124](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf#L120-L124), `location ~* (fonts\|assets\|plugins\|uploads)/.*\.(eot\|ttf\|woff\|woff2\|ico\|otf)$` | `expires 1y;` `add_header Cache-Control public,immutable;` `add_header Access-Control-Allow-Origin *;` | fonts usable cross-origin (CDN or theme) and cached a year (inferred). **Extension regex**, unanchored, case-insensitive. | NEEDS A CHANGE for exactness; EXPRESSIBLE by approximation | Prefix rules give the same fields for `/assets/` and `/plugins/` (rows below), plus one for `/fonts/` (`when = "success"`, `set = { "Cache-Control" = "max-age=31536000, public, immutable" }` and a rule setting ACAO `*`). For `/uploads/` the approximation is ACAO `*` on the whole prefix (row below). Exactness needs a **suffix/extension condition** on rules. Smallest change: `match = "suffix"` (as locations have) or a `suffixes = [".woff2", ...]` filter. |
| [L136-L138](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf#L136-L138), `location ~ ^/javascripts/` | `expires 1d;` `add_header Cache-Control public,immutable;` `add_header Access-Control-Allow-Origin *;` | comment L133-134: "some minimal caching here so we don't keep asking" | EXPRESSIBLE | `path = "/javascripts/"`, `when = "success"`, `set = { "Cache-Control" = "max-age=86400, public, immutable" }`, plus a rule with `path = "/javascripts/"`, `set = { "Access-Control-Allow-Origin" = "*" }`. |
| [L142-L146](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf#L142-L146), `location ~ ^/assets/(?<asset_path>.+)$` | `expires 1y;` `brotli_static on;` `add_header Cache-Control public,immutable;` `add_header Access-Control-Allow-Origin *;` | fingerprinted assets (comment L143: "asset pipeline enables this"). Anchored path regex, so in effect a prefix. | EXPRESSIBLE | `path = "/assets/"`, `when = "success"`, `set = { "Cache-Control" = "max-age=31536000, public, immutable" }`, and `path = "/assets/"`, `set = { "Access-Control-Allow-Origin" = "*" }`. `brotli_static` is the `.br` twins (existing). |
| [L153-L155](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf#L153-L155), `location ~ ^/plugins/` | `expires 1y;` `add_header Cache-Control public,immutable;` `add_header Access-Control-Allow-Origin *;` | plugin assets | EXPRESSIBLE | same as `/assets/`, with `path = "/plugins/"`. |
| [L160-L162](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf#L160-L162), `location ~ /images/emoji/` (unanchored) | `expires 1y;` `add_header Cache-Control public,immutable;` `add_header Access-Control-Allow-Origin *;` | comment L158: "cache emojis" | EXPRESSIBLE as a prefix | `path = "/images/emoji/"`, same two rules. The unanchored regex would also match the segment deeper in a path; no such Discourse path is known (**unverified**). |
| [L177-L178](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf#L177-L178), `location ~ ^/uploads/` | `expires 1y;` `add_header Cache-Control public,immutable;` | uploads cached a year. In nginx this also reaches **proxied 3xx answers** (redirects to S3 or a CDN) and Rails-sent uploads (inferred from the status list). | EXPRESSIBLE (success only) | `path = "/uploads/"`, `when = "success"`, `set = { "Cache-Control" = "max-age=31536000, public, immutable" }`. It does not reach 3xx, which is safer than nginx. `/uploads/short-url/` is proxied to Rails before this regex (L110-113) and answers with redirects, so a success-only rule leaves it alone. |
| [L186](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf#L186) `location ~ /stylesheet-cache/`; [L192](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf#L192) `location ~* \.(gif\|png\|jpg\|jpeg\|bmp\|tif\|tiff\|ico\|webp\|avif)$`; [L205](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf#L205) `location ~ /_?optimized/` (all nested in `/uploads/`) | `add_header Access-Control-Allow-Origin *;` in each, served from disk with `try_files $uri =404` | CORS on images, thumbnails and custom CSS under `/uploads/`, not on other uploads (attachments go through Rails) | NEEDS A CHANGE for exactness; EXPRESSIBLE by approximation | The `stylesheet-cache` and `optimized` parts are path-like. A prefix rule needs the full path (`/uploads/<db>/optimized/`, `<db>` per site, usually `default`, **unverified**). The images part is an **extension condition**. Approximation: `path = "/uploads/"`, `set = { "Access-Control-Allow-Origin" = "*" }` on all uploads, a fixed `*` without credentials on public files (secure uploads use `/secure-uploads/`). Exact: suffix condition as above. |
| [L197-L201](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf#L197-L201), `location ~* \.(svg)$` (nested in `/uploads/`) | `add_header Access-Control-Allow-Origin *;` `add_header Content-Disposition attachment;` | comment L196: "force attachment so SVGs can't render as a document on direct navigation (does not affect <img>/CSS rendering)" | NEEDS A CHANGE | An **extension condition** is needed. `Content-Disposition: attachment` on the whole `/uploads/` prefix would also force downloads of PDFs and other inline files and replace Rails' own value. Smallest change: suffix match on response rules. A prefix-wide `default = { "Content-Security-Policy" = "default-src 'none'; sandbox" }` on `/uploads/` is an alternative mitigation, but its effect on every upload is **unverified**. |
| [L237-L240](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/nginx.sample.conf#L237-L240), `location ~ ^/(svg-sprite/\|letter_avatar/\|letter_avatar_proxy/\|user_avatar\|highlight-js\|stylesheets\|theme-javascripts\|favicon/proxied\|service-worker\|extra-locales/)` | `proxy_ignore_headers "Set-Cookie";` `proxy_hide_header "Set-Cookie";` `proxy_hide_header "X-Discourse-Username";` `proxy_hide_header "X-Runtime";` | comment L235-236: "if Set-Cookie is in the response nothing gets cached". Strips fields so nginx's `proxy_cache` can store these. | NOT A REDIRECT/HEADER RULE | `proxy = { hide = ["Set-Cookie", "X-Discourse-Username", "X-Runtime"] }` on one location per prefix. With no proxy cache in agensio the hiding is optional. Prefixes without a slash (`/user_avatar`, `/service-worker`) need care: agensio prefixes match whole segments, so `/service-worker.js` needs an exact location (**unverified** exact path). |

### Other directives (existing features)
- **Buffers and limits:** `proxy_buffer_size 32k; proxy_buffers 4 32k; large_client_header_buffers 4 32k;` (L19-24) is the request-head cap `max_header_size` (default 16 KB). Raising it is a server-wide key.
- **Scheme:** `map $http_x_forwarded_proto $thescheme` (L27-30) preserves `https` from an outer proxy. agensio always sends X-Forwarded-Proto.
- **Compression:** gzip and brotli on the fly (L50-60) have no equivalent. `brotli_static` maps to twins.
- **Body size:** `client_max_body_size 10m` (L70, replaced by `$upload_size` in `web.template.yml` L172-175) maps to the site's `max_body_size`.
- **Backups:** `location ^~ /backups/ { internal; }` (L81-83) maps to `refuse = ["/backups/"]` (404).
- **Request fields:** the `proxy_set_header` set (L102-108 and repeats) covers Host, `X-Request-Start "t=${msec}"`, X-Forwarded-For/Proto, `X-Sendfile-Type`, `X-Accel-Mapping` and `Client-Ip ""`.
  - `X-Request-Start` needs a `$msec` variable that agensio's `proxy.headers` lacks. It feeds queue-time metrics only (inferred).
  - `Client-Ip ""` maps to `proxy = { headers = { "Client-Ip" = "" } }`.
- **X-Accel-Redirect:** `/uploads/` and `/admin/backups/` (L173-174, L221-222) use it with the internal `/downloads/` alias (L263-266). agensio has no X-Accel-Redirect. Leaving `X-Sendfile-Type` empty (as the default locations do) makes Rails send the file itself.
- **Message bus:** `/message-bus/` with `proxy_buffering off` (L252-257) maps to `proxy = { buffering = false }` on that location.
- **Not offered:** `proxy_cache` (L15, L243-246).
- **Static files:** `try_files $uri @discourse` (L260) has no try_files-to-proxy equivalent.
- **Real IP:** `web.socketed.template.yml` L14-31 sets `listen unix:/shared/nginx.http.sock; set_real_ip_from unix:;`, so the inner nginx takes the client address from **X-Real-IP** (nginx `real_ip_header` default). `cloudflare.template.yml` L6 sets `real_ip_header cf-connecting-ip;`.

### App guidance (Discourse)
- **HSTS:** only the container's TLS template sends it: `max-age=31536000`, with no includeSubDomains and no preload (web.ssl.template.yml L59, L67). grep of `lib/`, `app/` and `config/` finds no HSTS in the app. The `force_https` site setting (default `false`, [site_settings.yml L3111](https://github.com/discourse/discourse/blob/v2026.10.0-latest/config/site_settings.yml#L3111)) drives https URLs and secure cookies, not HSTS.
- **CSP:** the app sends its own CSP (site setting `content_security_policy`, default `true`, site_settings.yml L3239-3250) with `frame-ancestors 'self'` plus embeddable hosts ([default.rb L19, L52-57](https://github.com/discourse/discourse/blob/v2026.10.0-latest/lib/content_security_policy/default.rb#L19-L57)). The proxy should not set one (inferred: a `set` would replace the app's).
- **X-Frame-Options:**
  - The app's DefaultHeaders middleware excludes `X-Frame-Options` ([default_headers.rb L5-6](https://github.com/discourse/discourse/blob/v2026.10.0-latest/lib/middleware/default_headers.rb#L5-L6)).
  - The embed controller deletes it ([embed_controller.rb L172](https://github.com/discourse/discourse/blob/v2026.10.0-latest/app/controllers/embed_controller.rb#L172)), and so does the application controller when `allow_embedding_site_in_an_iframe` is set ([application_controller.rb L116](https://github.com/discourse/discourse/blob/v2026.10.0-latest/app/controllers/application_controller.rb#L116)).
  - A proxy frame field, `set` or `default`, would break comment embedding on `/embed/` (inferred).
- **CORS:** fixed `*` only, on assets, plugins, javascripts, emoji, fonts and image uploads. There is no origin echo.
- **`.well-known`:** none, except ACME in the TLS templates.
- **Trusting the proxy:**
  - The inner nginx in the socketed setup trusts `unix:` and reads `X-Real-IP`. It then sets `X-Forwarded-For $remote_addr` itself (L104).
  - `X-Forwarded-Proto: https` must arrive so `$thescheme` is https.
  - agensio needs `proxy = { headers = { "X-Real-IP" = "$remote_addr" } }`. Without it every client appears as the socket peer (inferred from realip semantics).
- **Sub-path redirect:** none.

---

## 3. Ghost

**Version read:**
- **Ghost** `v6.69.0` (published 2026-10-07).
- **Ghost-CLI** `v1.33.4` (commit `630700fa3443b0f522dbbe7f1fe1fdc80d38fc48`, 2026-10-09).
- **TryGhost/ghost-docker** `main` at `c51d5601a2c738db55aba6ea15d0d0421d7affb7` (2026-10-12). The only tags are `v0.1.0-beta.1` and `v0.1.0-beta.2`; `docs.ghost.org/install/docker` points at `main`.
- **docs.ghost.org** source `TryGhost/docs` at `db110909ac590bfd3c2fd6939920838ed359e3b3` (2026-10-12).

**Sources:**
- https://github.com/TryGhost/Ghost-CLI/tree/v1.33.4/extensions/nginx/templates: `nginx.conf`, `nginx-ssl.conf`, `ssl-params.conf`. Generated by `extensions/nginx/index.js` L131-147 (location `/`, or `^~ <subdir>`).
- https://github.com/TryGhost/ghost-docker/tree/c51d5601a2c738db55aba6ea15d0d0421d7affb7/caddy: `Caddyfile.example` and `snippets/SecurityHeaders`, `ActivityPub`, `TrafficAnalytics`, `Logging`.
- https://github.com/TryGhost/docs/blob/db110909ac590bfd3c2fd6939920838ed359e3b3/faq/proxying-https-infinite-loops.mdx (https://docs.ghost.org/faq/proxying-https-infinite-loops, title "Reverse Proxying To Ghost").
- https://github.com/TryGhost/docs/blob/db110909ac590bfd3c2fd6939920838ed359e3b3/install/docker.mdx (https://docs.ghost.org/install/docker) and `config.mdx`.
- Ghost core v6.69.0:
  - `ghost/core/core/shared/express.js`
  - `ghost/core/core/server/web/shared/middleware/url-redirects.js`
  - `ghost/core/core/server/web/admin/app.js`
  - `ghost/core/core/shared/config/defaults.json`
- Ghost-CLI git history: commit `f3755e570fb0aa1518161a589664cb54d09c556a` (#1858).

### Directives: Ghost-CLI nginx templates (v1.33.4)

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| [nginx-ssl.conf L1-L4](https://github.com/TryGhost/Ghost-CLI/blob/v1.33.4/extensions/nginx/templates/nginx-ssl.conf#L1-L4) with L22, L36, L52 (same in [nginx.conf L1-4, L18, L32, L48](https://github.com/TryGhost/Ghost-CLI/blob/v1.33.4/extensions/nginx/templates/nginx.conf#L1-L4)), every location | `map $status $header_content_type_options { 204 ""; default "nosniff"; }` and `add_header X-Content-Type-Options $header_content_type_options;` | nosniff on every answer **except 204**. Commit f3755e5 (#1858, 2024-08-01): Ghost returns an empty 204 for `/ghost/auth-frame/` when no staff session exists (admin/app.js L38-58), and "when returning an empty 204 response ... iOS safari interpret this header as a file to download from the url". No `always`, so not on 4xx/5xx. | NEEDS A CHANGE (status condition) | `set = { "X-Content-Type-Options" = "nosniff" }` with `when = "always"` or `"success"` would include 204 and bring back the iOS download prompt. Smallest change: never add `nosniff` to an answer without a body or Content-Type (204, 304), or a `when` that excludes 204. Today's baseline puts nosniff only on agensio's own answers, so a default Ghost site is not affected; it matters when the agent offers nosniff on app answers. |
| [ssl-params.conf L7](https://github.com/TryGhost/Ghost-CLI/blob/v1.33.4/extensions/nginx/templates/ssl-params.conf#L7), included at **server** level of nginx-ssl.conf (L15) | `add_header Strict-Transport-Security 'max-age=63072000; includeSubDomains; preload';` | HSTS for 2 years with subdomains and preload (purpose inferred). **Inferred:** since #1858 every location in nginx-ssl.conf has its own `add_header` (L22, L36, L52), so this server-level line is not inherited by any location. In practice it is not sent. | EXPRESSIBLE without preload; NOT OFFERED ON PURPOSE for `preload` | `hsts = { max_age = "2y", subdomains = true }`. Preload is not offered (redirects.md 4.6); the app works. |
| [ssl-params.conf L8](https://github.com/TryGhost/Ghost-CLI/blob/v1.33.4/extensions/nginx/templates/ssl-params.conf#L8), server level | `add_header X-Frame-Options SAMEORIGIN;` | anti-framing (inferred). Shadowed for the same reason as L7 (inferred). | EXPRESSIBLE (with a caution) | `path = "/"`, `default = { "X-Frame-Options" = "SAMEORIGIN" }`. Caution: with a separate admin domain, Ghost Admin frames the site for previews (ghost-docker uses CSP `frame-ancestors 'self' <admin domain>` for that, below), and SAMEORIGIN would block it (inferred). |
| [nginx-ssl.conf L51](https://github.com/TryGhost/Ghost-CLI/blob/v1.33.4/extensions/nginx/templates/nginx-ssl.conf#L51) and [nginx.conf L47](https://github.com/TryGhost/Ghost-CLI/blob/v1.33.4/extensions/nginx/templates/nginx.conf#L47), main location, sub-directory installs only | `<% if (location !== '/') { %>proxy_redirect off;<% } %>` | Ghost's own redirects already carry the configured URL (inferred) | NOT A REDIRECT/HEADER RULE | `proxy = { redirects = "pass" }` on the sub-path location. Ghost's absolute URLs never point at the origin address, so `rewrite` is a no-op anyway. |
| [nginx.conf L6-L56](https://github.com/TryGhost/Ghost-CLI/blob/v1.33.4/extensions/nginx/templates/nginx.conf#L6-L56), port-80 server | (no redirect: it proxies to Ghost) | Ghost redirects HTTP to HTTPS itself: [url-redirects.js L82-90, L102-104](https://github.com/TryGhost/Ghost/blob/v6.69.0/ghost/core/core/server/web/shared/middleware/url-redirects.js#L82-L104) send a 301 to `https://<requested host>` when `url` is https and `req.secure` is false | EXPRESSIBLE | `http = "redirect"` at agensio (308); Ghost's own redirect stays as a fallback. |

### Directives: ghost-docker Caddy (main @ c51d560)

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| [snippets/SecurityHeaders L1-L12](https://github.com/TryGhost/ghost-docker/blob/c51d5601a2c738db55aba6ea15d0d0421d7affb7/caddy/snippets/SecurityHeaders#L1-L12), imported in the site block (Caddyfile.example L19, "Optional: Add security headers") | `header {` `Strict-Transport-Security max-age=31536000;` | comment "Enable HSTS": 1 year, no subdomains or preload | EXPRESSIBLE | `hsts = true`. |
| same, L5 | `X-XSS-Protection "1; mode=block"` | comment "Enable XSS protection" | EXPRESSIBLE (with load warning) | `set = { "X-XSS-Protection" = "1; mode=block" }`. headers.md 2.6 warns for any value other than `0`, and `0` is the right value today. |
| same, L7 | `X-Content-Type-Options nosniff` | comment "Prevent MIME sniffing" | EXPRESSIBLE, but conflicts with Ghost-CLI #1858 | `set = { "X-Content-Type-Options" = "nosniff" }`. **Observation:** Caddy's `header` puts it on every answer, including the 204 from `/ghost/auth-frame/` that Ghost-CLI exempts on purpose, so the iOS issue of #1858 likely returns here (inferred, not tested). This is the same case as the Ghost-CLI row. |
| same, L9 | `Referrer-Policy strict-origin-when-cross-origin` | comment "Referrer policy" | EXPRESSIBLE | The agensio baseline already does this as `default`. |
| same, L11 | `Content-Security-Policy "frame-ancestors 'self' {$ADMIN_DOMAIN:}"` | comment "Prevent embedding in external iframes", while letting a separate admin domain frame the site (previews) | EXPRESSIBLE | `default = { "Content-Security-Policy" = "frame-ancestors 'self' admin.example.com" }`. The env placeholder is resolved at load, so it is fixed text. Use `default` so a CSP Ghost sends wins. Ghost core sends none in the files read (**unverified** for the whole codebase). Whether this snippet in the ADMIN_DOMAIN block blocks the cross-domain `/ghost/auth-frame/` used by comments is **unverified**. |
| [Caddyfile.example L48-L51](https://github.com/TryGhost/ghost-docker/blob/c51d5601a2c738db55aba6ea15d0d0421d7affb7/caddy/Caddyfile.example#L48-L51) (commented; "Redirect www -> root domain") | `www.{$DOMAIN} {` `import snippets/Logging` `redir https://{$DOMAIN}{uri}` `}` | www to apex. Caddy's `redir` default is **302** (caddyserver.com/docs/caddyfile/directives/redir: "`temporary` ... `302 Found`, this is the default"). `{uri}` is path plus query (Caddy placeholder, **unverified** on the docs page). | EXPRESSIBLE | `server_name = ["example.com", "www.example.com"]`, `canonical = "example.com"` (308 instead of 302). |
| [Caddyfile.example L57-L60](https://github.com/TryGhost/ghost-docker/blob/c51d5601a2c738db55aba6ea15d0d0421d7affb7/caddy/Caddyfile.example#L57-L60) (commented; "Redirect root -> www domain") | `CHANGE_ME {` `import snippets/Logging` `redir https://{$DOMAIN}{uri}` `}` | apex to www. Comment L56 and [docker.mdx L64, L74](https://github.com/TryGhost/docs/blob/db110909ac590bfd3c2fd6939920838ed359e3b3/install/docker.mdx#L64-L74): "This is required for ActivityPub to work correctly with www domains", meaning WebFinger on the apex | EXPRESSIBLE | `canonical = "www.example.com"` with both names. WebFinger clients follow the 308 (inferred). |
| [snippets/ActivityPub L3-L13](https://github.com/TryGhost/ghost-docker/blob/c51d5601a2c738db55aba6ea15d0d0421d7affb7/caddy/snippets/ActivityPub#L3-L13) | `handle /.ghost/activitypub/* { reverse_proxy {$ACTIVITYPUB_TARGET} }` `handle /.well-known/webfinger { reverse_proxy {$ACTIVITYPUB_TARGET} }` `handle /.well-known/nodeinfo { reverse_proxy {$ACTIVITYPUB_TARGET} }` | .well-known delegation **by proxy** (not redirect) to the ActivityPub service. `compose.yml` L13 defaults to `https://ap.ghost.org`; `.env.example` L27 gives `activitypub:8080` for a local service. | NOT A REDIRECT/HEADER RULE; the proxy NEEDS A CHANGE for the default | With a local service: `[[site.location]]` with `path = "/.ghost/activitypub/"` and `upstream = "http://127.0.0.1:8080"`, plus exact locations `/.well-known/webfinger` and `/.well-known/nodeinfo` to the same upstream. With the default `https://ap.ghost.org` (Ghost's hosted service, which identifies the blog by the Host passed through), agensio cannot: upstreams must be IP literals. A redirect would not work because the service needs the blog's Host (inferred). |
| [snippets/TrafficAnalytics L2-L6](https://github.com/TryGhost/ghost-docker/blob/c51d5601a2c738db55aba6ea15d0d0421d7affb7/caddy/snippets/TrafficAnalytics#L2-L6) | `@analytics_paths path_regexp analytics_match ^(.*)/\.ghost/analytics(.*)$` `handle @analytics_paths { rewrite * {re.analytics_match.2} reverse_proxy traffic-analytics:3000 }` | proxy `/.ghost/analytics/...` under any prefix, prefix stripped | NOT A REDIRECT/HEADER RULE | `[[site.location]]` with `path = "/.ghost/analytics/"` and `upstream = "http://127.0.0.1:3000/"` (the URI part replaces the prefix). A sub-path blog needs a second location (`/blog/.ghost/analytics/`), because there is no regex. |

### Other directives (existing features)
- **Proxy fields:** `proxy_set_header X-Forwarded-For $remote_addr` (main location; `$proxy_add_x_forwarded_for` on the ActivityPub locations), `X-Forwarded-Proto $scheme`, `X-Real-IP $remote_addr` and `Host $http_host` (nginx-ssl.conf L46-49; doc faq L12-15). agensio sends Host and X-Forwarded-For/Proto by default; X-Real-IP via `proxy.headers` if wanted, though Ghost does not need it (Express trust proxy reads X-Forwarded-For).
- **ActivityPub proxy:** the locations `~ /.ghost/activitypub/*` and `~ /.well-known/(webfinger|nodeinfo)` (nginx-ssl.conf L17-43) proxy to `https://ap.ghost.org` with `resolver`, `proxy_ssl_server_name on` and the blog's Host. This is the same as the Caddy ActivityPub row: a DNS-named upstream is missing. Both regexes are unanchored.
- **Body size:** `client_max_body_size 50m` (HTTP, nginx.conf L55; doc faq L19) and `1g` (HTTPS, nginx-ssl.conf L55) map to the site's `max_body_size`.
- **ACME:** `location ~ ^/.well-known/acme-challenge { allow all; }` with `root <webroot>` (nginx.conf L51-53) is replaced by agensio's built-in ACME.
- **Sub-directory:** `location ^~ /<subdir>` (index.js L142) maps to `[[site.location]] path = "/blog/"` with `final = true`. There is no redirect of `/` to the sub-path.
- **Compression:** `encode gzip` (Caddyfile.example L16) has no on-the-fly equivalent.

### App guidance (Ghost)
- **HTTPS and proxy trust:**
  - [faq/proxying-https-infinite-loops.mdx L22](https://github.com/TryGhost/docs/blob/db110909ac590bfd3c2fd6939920838ed359e3b3/faq/proxying-https-infinite-loops.mdx#L22): "set the `x-forwarded-proto` header to `https`. Without this, Ghost will think the requests are insecure, attempt to redirect to the https version of a URL and cause an infinite redirect loop."
  - Ghost trusts any proxy by default: `app.enable('trust proxy')`, or only loopback with config `usingLoopbackReverseProxy: true` ([express.js L19-25](https://github.com/TryGhost/Ghost/blob/v6.69.0/ghost/core/core/shared/express.js#L19-L25); default `false` in defaults.json L378, not in the docs).
- **HSTS:** Ghost-CLI's template value is `max-age=63072000; includeSubDomains; preload`, shadowed in practice (inferred). ghost-docker sends `max-age=31536000`. Ghost itself sends none in the files read (**unverified** repo-wide).
- **Admin domain:**
  - [config.mdx L365-374](https://github.com/TryGhost/docs/blob/db110909ac590bfd3c2fd6939920838ed359e3b3/config.mdx#L365-L374) covers the `admin.url` key.
  - Ghost redirects `/ghost/` to the admin host itself (url-redirects.js L41-53).
  - `/ghost/auth-frame/` is framed by the comments UI and returns 204 without a staff cookie, with `Cache-Control: public, max-age=0` ([admin/app.js L38-58](https://github.com/TryGhost/Ghost/blob/v6.69.0/ghost/core/core/server/web/admin/app.js#L38-L58)).
- **CSP / XFO:** ghost-docker uses `frame-ancestors 'self' <admin domain>` rather than XFO. Ghost-CLI's XFO SAMEORIGIN is shadowed (inferred). A proxy XFO would block admin previews across domains (inferred).
- **CORS:** none at the proxy.
- **Caching:** Ghost sets its own Cache-Control. `caching.*.maxAge` in config covers frontend, contentAPI, robotstxt, sitemap, wellKnown, cors, publicAssets 1y and 301 1y ([config.mdx L858-881](https://github.com/TryGhost/docs/blob/db110909ac590bfd3c2fd6939920838ed359e3b3/config.mdx#L858-L881)). No hashed-asset rule at the proxy.
- **`.well-known`:** WebFinger and NodeInfo go **by proxy** to the ActivityPub service (Ghost-CLI and ghost-docker), not by redirect.

---

## 4. Plausible Community Edition

**Version read:**
- **plausible/community-edition** branch `v3.2.1`, the default branch (`ec6c4da776547516d8f48159ce1a704df4f475ad`, 2026-05-15). The repository has no tags or releases; versions are branches. The app tag `plausible/analytics` `v3.2.1` is the newest v3 tag.
- **The `reverse-proxy/` directory does not exist** on `v3.2.1`, `v3.0.0` or `v2.1.5` (`git ls-tree`). The guidance is the wiki page **Reverse-Proxy**, last revision `e31a04e927ff4e5cce0cd27bd537fae1c041f9ad` (2025-03-06). The wiki HEAD is `86f2c793` (2025-10-29).

**Sources:**
- https://github.com/plausible/community-edition/wiki/Reverse-Proxy (README L72 links it). Its own L3 says: "Starting from version 2.1.2 a reverse proxy is no longer necessary since Plausible CE can handle HTTPS and automatic Let's Encrypt certificates ... The Nginx and Apache configurations provided here have been contributed by the community and have not been tested by the maintainers."
- Wiki `Configuration.md` (BASE_URL, HTTP_PORT and HTTPS_PORT).
- App source `plausible/analytics` v3.2.1:
  - `lib/plausible_web/remote_ip.ex`
  - `lib/plausible_web/endpoint.ex`
  - `lib/plausible_web/router.ex`
  - `lib/plausible_web/plugs/secure_embed_headers.ex`
  - Phoenix `v1.8.2` (`mix.lock`) `lib/phoenix/controller.ex`
- The tracking-script proxy guides (for the *tracked* website, not the CE server): https://github.com/plausible/docs/blob/8de932bdb28470ca4709e8ed494be8dd0e6dc0d1/docs/proxy/guides/nginx.md (https://plausible.io/docs/proxy/guides/nginx) and `caddy.md`, `apache.md` at the same commit (2026-10-12).

### Directives

| source / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| wiki Reverse-Proxy L41-45, section "Caddy" | `plausible.example.com {` `reverse_proxy localhost:8000` `}` | whole site to CE. Caddy's automatic HTTPS adds an implicit HTTP to HTTPS redirect (its 308 status is **unverified**: not stated on caddyserver.com/docs/automatic-https). | EXPRESSIBLE (the implicit redirect) | `http = "redirect"` (the default). |
| wiki L59-78, section "Nginx" | (no `add_header` or `return`; plain `listen 80`, no TLS) | community-contributed | none | Nothing to classify. |
| wiki L102-121, section "Apache" | (no `Header`, `Redirect` or `RedirectMatch`). `ProxyPassReverse / http://localhost:8000/` rewrites Location from the origin. | community-contributed | NOT A REDIRECT/HEADER RULE | `ProxyPassReverse` maps to `proxy = { redirects = "rewrite" }` (the default). |
| [plausible/docs nginx.md L61](https://github.com/plausible/docs/blob/8de932bdb28470ca4709e8ed494be8dd0e6dc0d1/docs/proxy/guides/nginx.md#L61), `location = /js/script.js` (on the **tracked site**) | `add_header X-Cache $upstream_cache_status;` | comment L60: "Optional. Adds a header to tell if you got a cache hit or miss" | NOT OFFERED ON PURPOSE | Variables, and no proxy cache. The script works without it. |

### Other directives (existing features)
- **Proxy:** `proxy_pass http://127.0.0.1:8000;` with `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` (wiki L66-69) maps to `app = "proxy"` and `upstream = "http://127.0.0.1:8000"`. agensio replaces X-Forwarded-For from untrusted clients; nginx's `$proxy_add_x_forwarded_for` appends, which lets a client choose its own leftmost entry (see App guidance).
- **WebSocket** `location /live/websocket` with Upgrade/Connection (wiki L71-76) and Apache `ProxyPassMatch ^/(live/websocket)$ ws://localhost:8000/$1` (L109): automatic in agensio.
- **Apache logging and fields:** `ProxyPreserveHost On` and `ProxyAddHeaders On` are agensio defaults (Host through, X-Forwarded-*). The `SetEnvIf X-Forwarded-For` / `LogFormat` lines (L113-119) are logging only.
- **Tracking-script proxy** (tracked site; nginx.md L47-73, caddy.md L33-41): `proxy_pass` to `https://plausible.io/js/pa-XXXXX.js` and `/api/event` with `proxy_set_header Host plausible.io`, `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host $host`; Caddy `rewrite` plus `reverse_proxy https://plausible.io { header_up Host {http.reverse_proxy.upstream.hostport} }`. In agensio these are exact locations with an upstream URI part and `proxy = { host = "plausible.io" }`, but they **need a DNS-named upstream**: a NEEDS A CHANGE in the proxy, not a header rule. A self-hosted CE on an IP-reachable address works today.
- **Not offered:** `proxy_cache` and `proxy_buffering` for the script.

### App guidance (Plausible)
- **Built-in TLS:** with `HTTP_PORT=80` and `HTTPS_PORT=443`, CE issues Let's Encrypt certificates itself (README L60-72; wiki Configuration L103-108) and forces HTTPS through `Plug.SSL` ([endpoint.ex L7-8, L149-155](https://github.com/plausible/analytics/blob/v3.2.1/lib/plausible_web/endpoint.ex#L7-L8)). The HSTS details of that path are **unverified**. Behind agensio only `HTTP_PORT` is set.
- **Client address (no trusted-proxy setting):** [remote_ip.ex L6-35](https://github.com/plausible/analytics/blob/v3.2.1/lib/plausible_web/remote_ip.ex#L6-L35) takes, in order, `x-plausible-ip`, `cf-connecting-ip`, `b-forwarded-for` (leftmost), `x-forwarded-for` (**leftmost**), then `forwarded`, then the peer.
  - agensio's replaced X-Forwarded-For gives the right leftmost entry.
  - The fields ranked *above* it pass through from the client unchanged (configuration.md: "Every other field except the hop-by-hop ones"), so a visitor can forge their address (inferred).
  - Recommended: `proxy = { headers = { "X-Plausible-IP" = "", "CF-Connecting-IP" = "", "B-Forwarded-For" = "", "Forwarded" = "" } }`.
- **BASE_URL** must be the public `https://` address. It is used for links and the LiveView WebSocket `check_origin` (wiki Configuration L7-14; endpoint.ex L22-24).
- **CSP / XFO:**
  - The browser pipeline uses Phoenix 1.8.2 `put_secure_browser_headers`: `referrer-policy`, `content-security-policy: base-uri 'self'; frame-ancestors 'self';`, nosniff, `x-permitted-cross-domain-policies` ([phoenix controller.ex L1415-1421](https://github.com/phoenixframework/phoenix/blob/v1.8.2/lib/phoenix/controller.ex#L1415-L1421); [router.ex L10](https://github.com/plausible/analytics/blob/v3.2.1/lib/plausible_web/router.ex#L10)). It sends no XFO.
  - The `shared_link` pipeline (embeddable shared dashboards) uses `SecureEmbedHeaders`, with no CSP and no XFO ([secure_embed_headers.ex L12-21](https://github.com/plausible/analytics/blob/v3.2.1/lib/plausible_web/plugs/secure_embed_headers.ex#L12-L21); router.ex L35-40).
  - A proxy frame field, even `default`, would break embedded dashboards (inferred). The proxy must not set a CSP over the app's (inferred).
- **HSTS, CORS, `.well-known`, sub-path redirect:** none in any official proxy config.

---

## 5. Umami

**Version read:**
- **umami-software/umami** `v3.4.0` (published 2026-09-17, commit `ec0ff50388c264ed8ce46f00967e92f7e71476ae`).
- **Docs** (umami.is/docs) source `umami-software/docs` at `69c0ec9367eca5f9df93e2821444ed4aeaaa0c75` (2026-10-06). The repository `umami-software/website` is not public (git asks for credentials).

**Sources (what was checked):**
- grep of all of `content/` in the docs repo for nginx, caddy, traefik, apache, proxy, `add_header`, `expires`, `return 30x`, `redir`, `Header`, `X-Frame`, `Content-Security` and HSTS.
- **Two pages publish nginx snippets:**
  - https://github.com/umami-software/docs/blob/69c0ec9367eca5f9df93e2821444ed4aeaaa0c75/content/docs/guides/running-on-digitalocean.mdx (https://umami.is/docs/guides/running-on-digitalocean, section "Proxying with Nginx")
  - https://github.com/umami-software/docs/blob/69c0ec9367eca5f9df93e2821444ed4aeaaa0c75/content/docs/enable-cloudflare-headers.mdx (https://umami.is/docs/enable-cloudflare-headers)
- **No Caddy, Traefik or Apache config is published.**
  - `install.mdx` L77 only links to nginx's own reverse-proxy guide.
  - `guides/hosting.mdx` L12 mentions nginx and Apache.
  - `bypass-ad-blockers.mdx` L32-33 links to the nginx and Apache docs and shows no config.
- Related header guidance: `heatmaps.mdx` L52-65 and `environment-variables.mdx` (CLIENT_IP_HEADER, ALLOWED_FRAME_URLS, FORCE_SSL).
- App source v3.4.0: `next.config.ts`, `src/lib/ip.ts`, `src/lib/csp.ts`.

### Directives

| source / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| [running-on-digitalocean.mdx L77-L81](https://github.com/umami-software/docs/blob/69c0ec9367eca5f9df93e2821444ed4aeaaa0c75/content/docs/guides/running-on-digitalocean.mdx#L77-L81), `location /stats/_next/static/` (sub-path install, `BASE_PATH=/stats`) | `alias /your_install_location/umami/.next/static/;` `access_log off;` `expires max;` | serve Next.js build output (content-hashed) from disk with a maximal cache (inferred). nginx `expires max` sends `Expires: Thu, 31 Dec 2037 23:55:55 GMT` and `Cache-Control: max-age=315360000`. Path prefix, not extension. | EXPRESSIBLE | `[[site.location]]` with `path = "/stats/_next/static/"`, `alias = "/your_install_location/umami/.next/static"`, `final = true`, plus `[[site.response_headers]]` with `path = "/stats/_next/static/"`, `when = "success"`, `set = { "Cache-Control" = "max-age=315360000" }`. The fixed `Expires` date could be added as text but is redundant. A year with `immutable` is the usual modern choice. |
| [heatmaps.mdx L52-L65](https://github.com/umami-software/docs/blob/69c0ec9367eca5f9df93e2821444ed4aeaaa0c75/content/docs/heatmaps.mdx#L52-L65), section "Allowing the page preview" (headers on the **tracked site**, not on Umami) | `Content-Security-Policy: frame-ancestors 'self' https://your-umami-instance.com;` and "If your site also sends `X-Frame-Options: DENY` or `SAMEORIGIN`, remove it — it overrides `frame-ancestors` in some browsers." | let the Umami dashboard frame the tracked page for the heatmap preview | EXPRESSIBLE | On the tracked site: `path = "/"`, `default = { "Content-Security-Policy" = "frame-ancestors 'self' https://umami.example.com" }`, `remove = ["X-Frame-Options"]` (`remove` also strips the app's). Use `default` for the CSP so an app policy is not replaced. An app CSP without that `frame-ancestors` would still block the preview, and appending to a CSP is not offered. |

### Other directives (existing features)
- **Proxy:**
  - `location / { proxy_pass http://localhost:3000; proxy_set_header X-Real-IP $remote_addr; proxy_set_header Host $host; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; }` (running-on-digitalocean.mdx L58-69) maps to `app = "proxy"`, `upstream = "http://127.0.0.1:3000"`, `proxy = { headers = { "X-Real-IP" = "$remote_addr" } }`.
  - The same under `location /stats` (L82-87) maps to `[[site.location]]` with `path = "/stats"` and that upstream, with no URI part because `BASE_PATH` keeps the prefix. There is no redirect of `/` to `/stats`.
- **Cloudflare fields:** `proxy_set_header CF-Connecting-IP $http_cf_connecting_ip; CF-IPCountry ...; CF-Region-Code ...; CF-IPCity ...;` plus X-Forwarded-* and X-Real-IP (enable-cloudflare-headers.mdx L29-40). agensio forwards client fields as they are, so nothing is needed when Cloudflare is really in front.
- SSL is only a link to a DigitalOcean Let's Encrypt tutorial (L92-94). agensio uses `tls = "auto"` with `http = "redirect"`.

### App guidance (Umami)
- **Headers the app sends itself** ([next.config.ts L36-108](https://github.com/umami-software/umami/blob/v3.4.0/next.config.ts#L36-L108)):
  - on every path: `X-DNS-Prefetch-Control: on` and a **CSP of its own** ([csp.ts L12-28](https://github.com/umami-software/umami/blob/v3.4.0/src/lib/csp.ts#L12-L28)). The CSP has `frame-ancestors 'self' $ALLOWED_FRAME_URLS`.
  - **HSTS** `max-age=63072000; includeSubDomains; preload`, only when `FORCE_SSL` is set (L47-52; env docs L355-363).
  - **CORS** `*` on `/api/*`: `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Headers: *`, `Access-Control-Allow-Methods`, `Access-Control-Max-Age`, `Cache-Control: no-cache`.
  - on `/script.js` and `/recorder.js` in production: ACAO `*` and `Cache-Control: public, max-age=86400, must-revalidate`.
  - The proxy needs to add none of these and should not set a CSP (inferred: a `set` would replace the app's frame-ancestors list).
  - **Observation for the design:** with `FORCE_SSL`, the app's HSTS carries `preload`. If agensio `hsts` is set it replaces this value without preload. If `hsts` is unset the app's preload value passes through; whether that is intended is a design question.
- **Framing:** embedding of shared dashboards is governed by `ALLOWED_FRAME_URLS`, a build-time variable (env docs L294-302; `guides/create-a-public-dashboard.mdx` L70-76). A proxy XFO would conflict in older browsers. Modern browsers ignore XFO when `frame-ancestors` is present, which Umami always sends (inferred, from CSP Level 2).
- **Client address (no trusted-proxy setting):** [ip.ts L3-17, L75-88](https://github.com/umami-software/umami/blob/v3.4.0/src/lib/ip.ts#L3-L88) uses `CLIENT_IP_HEADER` if set (env docs L28-37). Otherwise it takes the first present of `true-client-ip`, `cf-connecting-ip`, `fastly-client-ip`, `x-nf-client-connection-ip`, `do-connecting-ip`, `x-real-ip`, `x-appengine-user-ip`, `x-forwarded-for` (leftmost), `forwarded`, and three more.
  - Without a CDN in front, a client can forge the higher-ranked fields (inferred).
  - Recommended with agensio: Umami `CLIENT_IP_HEADER=x-forwarded-for`, since agensio replaces it from untrusted clients. Alternatively `x-real-ip` together with `proxy = { headers = { "X-Real-IP" = "$remote_addr" } }`, which overwrites the client's.
- **`.well-known`, redirects:** none at the proxy. Next.js redirects (next.config.ts L147-) are the app's own.

---

## 6. Gitea

**Version read:**
- Gitea v28.1.0, released 2026-10-06. Tag `v28.1.0` → commit `4ebd5e319b6a9e629bfd7a04292a6fe85b08dee9`.
- Docs repo `gitea.com/gitea/docs` at `main` = `2275bef3bddeea7141a2b0a3f1e7d8baf41083ee` (2026-10-12). `versioned_docs/version-28/...` is byte-identical to `docs/...` for this page.

**Sources:**
- Reverse proxies page (docs.gitea.com/administration/reverse-proxies): https://gitea.com/gitea/docs/src/commit/2275bef3bddeea7141a2b0a3f1e7d8baf41083ee/versioned_docs/version-28/administration/reverse-proxies.md
- HTTPS setup: `versioned_docs/version-28/administration/https-support.md` (same commit).
- Config cheat sheet: `versioned_docs/version-28/administration/config-cheat-sheet.md` (same commit).
- Source: https://github.com/go-gitea/gitea/blob/4ebd5e319b6a9e629bfd7a04292a6fe85b08dee9/routers/web/web.go , `routers/common/middleware.go`, `services/context/context_template.go`, `modules/setting/security.go`.

**Redirect and response-header directives in the official proxy configs: none.**

The page has nginx, nginx sub-path, nginx static split, Nginx Proxy Manager, Apache, Apache sub-path, Apache static, Caddy, Caddy sub-path, IIS, HAProxy, HAProxy sub-path, Traefik and Traefik sub-path. The only directives near the categories asked for:

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| [L142-155](https://gitea.com/gitea/docs/src/commit/2275bef3bddeea7141a2b0a3f1e7d8baf41083ee/versioned_docs/version-28/administration/reverse-proxies.md#L142-L155) "Two nodes and two domains", CDN `server`, `location /` | `return 404;` | everything on the CDN host that is not `/gitea/` is 404 (inferred) | NOT A REDIRECT/HEADER RULE (status answer, not a redirect) | a `[[site.location]] path = "/" handler = "deny"` next to the `/gitea/` alias location |
| [L176-185](https://gitea.com/gitea/docs/src/commit/2275bef3bddeea7141a2b0a3f1e7d8baf41083ee/versioned_docs/version-28/administration/reverse-proxies.md#L176-L185) Apache `<VirtualHost *:80>` (also L210, L260) | `RequestHeader set "X-Forwarded-Proto" expr=%{REQUEST_SCHEME}` | tell Gitea the scheme (L16: "Make sure `Host` and `X-Forwarded-Proto` headers are correctly passed") | NOT A REDIRECT/HEADER RULE (request field) | built in: agensio always sends X-Forwarded-Proto from the real scheme |
| [L193](https://gitea.com/gitea/docs/src/commit/2275bef3bddeea7141a2b0a3f1e7d8baf41083ee/versioned_docs/version-28/administration/reverse-proxies.md#L193) Apache prose | "add the line `ProxyPass /.well-known !` before `ProxyPass`" | Let's Encrypt webroot: keep `/.well-known/` off the proxy | NOT A REDIRECT/HEADER RULE | built in: agensio answers `/.well-known/acme-challenge/` before routing (redirects.md step 1). Gitea's own `/.well-known/*` must stay proxied (see App guidance). |
| [L307-308](https://gitea.com/gitea/docs/src/commit/2275bef3bddeea7141a2b0a3f1e7d8baf41083ee/versioned_docs/version-28/administration/reverse-proxies.md#L307-L308) IIS prose | ensure "Rewrite the domain names of the links in HTTP response" is set; turn "Reverse rewrite host in response headers" off | outbound HTML link rewriting; stop ARR rewriting `Location` back to `127.0.0.1:3000` | link rewriting: NOT OFFERED (agensio has no body rewriting; not needed when `ROOT_URL` is right). `Location`: NOT A REDIRECT/HEADER RULE | `proxy = { redirects = "rewrite" }` (default) rewrites origin-pointing `Location` *to* the site, the direction Gitea needs |
| [L342-361](https://gitea.com/gitea/docs/src/commit/2275bef3bddeea7141a2b0a3f1e7d8baf41083ee/versioned_docs/version-28/administration/reverse-proxies.md#L342-L361) IIS `<outboundRules>` | `<match filterByTags="A, Form, Img" pattern="^http(s)?://127.0.0.1:3000/(.*)" />` `<action type="Rewrite" value="http{R:1}://git.example.com/{R:2}" />` (precondition `{RESPONSE_CONTENT_TYPE}` `^text/html`) | rewrite internal URLs inside HTML | NOT OFFERED (no sub_filter/body rewrite); the app works when `ROOT_URL` is set | none |

**Other directives** (existing agensio features):
- WebSocket: `proxy_http_version 1.1; proxy_set_header Connection $http_connection; proxy_set_header Upgrade $http_upgrade;` (L45-47) for `/-/ws` (web.go L608). Upgrade is automatic in agensio (`proxy.upgrade = true`).
- `client_max_body_size 512M;` (L43, L66, L167) → site `max_body_size = "512MB"`. No per-location body size exists in agensio (keys.md has no location row for it).
- Request fields: `proxy_set_header Host $host` (passed through by default); `X-Real-IP $remote_addr` → `proxy = { headers = { "X-Real-IP" = "$remote_addr" } }` (agensio does not send it by default); `X-Forwarded-For $proxy_add_x_forwarded_for`, `X-Forwarded-Proto $scheme` (built in; behind `trusted_proxies` the chain is appended).
- Sub-path, nginx (L65-71): `location ~ ^/(gitea|v2)($|/)`, `rewrite ^ $request_uri;` `rewrite ^/(gitea($|/))?(.*) /$3 break;` `proxy_pass http://127.0.0.1:3000$uri;`. These are internal rewrites that strip `/gitea`, pass `/v2` as is and keep `%2F` raw, with no client redirect. agensio: `[[site.location]] path = "/gitea" upstream = "http://127.0.0.1:3000/"` (URI part replaces the prefix) and `[[site.location]] path = "/v2" upstream = "http://127.0.0.1:3000"`. **Unverified**: whether the prefix-replaced target keeps `%2F` undecoded (L15 requires it; agensio passes the raw target to a proxied app per CLAUDE.md).
- Sub-path via Apache `ProxyPass /git http://localhost:3000 nocanon`, Caddy `uri strip_prefix /git`, HAProxy `http-request replace-path /gitea\/?(.*) \/\1`, Traefik `stripprefix`: same internal stripping.
- Static files from disk (L107-122): `location /_/static/assets/ { alias /path/to/gitea/public/; }` with `STATIC_URL_PREFIX = /_/static`.
  - agensio: `[[site.location]] path = "/_/static/assets" alias = "/path/to/gitea/public"`.
  - The doc adds no Cache-Control. When Gitea serves them itself it sends `Cache-Control: public, max-age=<STATIC_CACHE_TIME>` (6h) (`modules/public/public.go` L106, cheat sheet L436). To match, add `add_headers = { "Cache-Control" = "public, max-age=21600" }` on that location, or a `[[site.response_headers]]` rule with `when = "success"`.
  - **Unverified**: whether `alias .../public/` versus the `assets/` path segment is right (`make frontend` output layout not checked).
- `AllowEncodedSlashes NoDecode` / `nocanon` (Apache): keep `%2F` raw. agensio passes the raw target to proxy locations; `encoded_slashes` affects only disk-backed locations.
- Container registry `/v2` at the root must be proxied even with a sub-path (L29-31).
- No gzip, timeouts or buffering directives in Gitea's examples.

**App guidance:**
- **Trust the proxy**:
  - `[server] ROOT_URL = https://git.example.com/` (L13).
  - `PUBLIC_URL_DETECTION = auto` (default; cheat sheet L354-358): use `Host`, plus `X-Forwarded-Proto` if present.
  - Client IP: `[security] REVERSE_PROXY_LIMIT = 1`, `REVERSE_PROXY_TRUSTED_PROXIES = 127.0.0.0/8,::1/128` (defaults; cheat sheet L598-600; `ForwardedHeadersHandler`, middleware.go L33-34, L112-121, chi-middleware/proxy). Which of X-Forwarded-For / X-Real-IP that library prefers is **unverified**.
  - Reverse-proxy authentication (`X-WEBAUTH-USER`) is off by default.
  - Do not let the proxy decode the URI (L15).
- **HSTS**: not recommended or set anywhere in Gitea's docs or code (no `Strict-Transport-Security` in `modules/`, `routers/`, `services/`). Gitea's own HTTPS mode only offers a port-80 redirector (`REDIRECT_OTHER_PORT`, https-support.md L34-42; 302/301 not checked).
- **CSP**: Gitea sets its own nonce-based policy on every page, both as a header and as a `<meta http-equiv>` (`context_template.go` L116-152; `base.go` L205-209). The default is `default-src * data: blob:; script-src * 'nonce-…'; style-src * 'unsafe-inline';`; `CONTENT_SECURITY_POLICY_GENERAL` is either empty (default policy) or `unset` (cheat sheet L603). The code comment (L128-131) suggests "Let end users configure their reverse proxy to add CSP header; browsers merge and use the stricter rules".
  - agensio cannot add a second CSP line: NEEDS A CHANGE if this is wanted.
  - `set` replaces the header but leaves the `<meta>` policy in place.
- **X-Frame-Options / nosniff**: set by Gitea on every response (`SecurityHeadersHandler`, middleware.go L49-62). `[security] X_FRAME_OPTIONS = SAMEORIGIN` and `X_CONTENT_TYPE_OPTIONS = nosniff` are the defaults; `unset` drops them (cheat sheet L601-602). Embedding is the app's setting, so a proxy XFO should be `default`, not `set`.
- **CORS**: app-side `[cors]`. `ENABLED = false`, `ALLOW_DOMAIN = *` (a list with wildcards, echoed by the app), `ALLOW_CREDENTIALS = false` (cheat sheet L247-254). `[repository] ACCESS_CONTROL_ALLOW_ORIGIN` is a fixed value, empty by default (L135). Nothing at the proxy.
- **.well-known**: Gitea answers it itself (web.go [L524-534](https://github.com/go-gitea/gitea/blob/4ebd5e319b6a9e629bfd7a04292a6fe85b08dee9/routers/web/web.go#L524-L534)):
  - `/openid-configuration`;
  - `/nodeinfo` and `/webfinger` when federation is enabled;
  - `/change-password`, an app redirect to `/user/settings/account`;
  - `/passkey-endpoints`;
  - any file under `$GITEA_CUSTOM/public/.well-known/` (`security.txt` goes there; customizing-gitea.md L44-52).

  The proxy must not shadow `/.well-known/` beyond ACME. With a sub-path deployment, root-level `/.well-known/` delegation is not covered by the docs (inferred).
- **Cache-Control on hashed assets**: the app's own (6h). The docs' disk-served variant adds none.
- **Redirect of `/` to a sub-path**: none; the docs discourage sub-paths (L22).

---

## 7. Forgejo

**Version read:**
- Forgejo v16.0.6, released 2026-10-12. Tag → commit `1aa13944143b3bc4312607239a68da23512d5ce3`.
- Docs `codeberg.org/forgejo/docs`, branch `v16.0` at `ee287bcd948f2dedc74cda8f7ff3d8a9b0aa3f37` (2026-10-01).
- `v17.0` and `next` branches exist for unreleased versions.

**Sources:**
- Reverse proxy page (forgejo.org/docs/v16.0/admin/setup/reverse-proxy/): https://codeberg.org/forgejo/docs/src/commit/ee287bcd948f2dedc74cda8f7ff3d8a9b0aa3f37/docs/admin/setup/reverse-proxy.md
- Cheat sheet: `docs/admin/config-cheat-sheet.md`.
- Source: https://codeberg.org/forgejo/forgejo/src/commit/1aa13944143b3bc4312607239a68da23512d5ce3/routers/web/web.go

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| [L138-147](https://codeberg.org/forgejo/docs/src/commit/ee287bcd948f2dedc74cda8f7ff3d8a9b0aa3f37/docs/admin/setup/reverse-proxy.md#L138-L147) nginx "Add a redirect from HTTP", `server { listen 80 default_server; ... location / {` | `return 301 https://$host$request_uri;` | "redirect anyone visiting the HTTP site to the HTTPS site" (L149) | EXPRESSIBLE | `http = "redirect"` (default for a TLS site on 443): 308, path and query kept, ACME exempt. Differences: 308 not 301; nginx's `default_server` + `$host` redirects *any* Host, while agensio redirects only the site's names |
| [L216-222](https://codeberg.org/forgejo/docs/src/commit/ee287bcd948f2dedc74cda8f7ff3d8a9b0aa3f37/docs/admin/setup/reverse-proxy.md#L216-L222) Apache `<VirtualHost *:80>` | `RewriteEngine on` / `RewriteCond %{SERVER_NAME} =git.example.com` / `RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]` | same (L225) | EXPRESSIBLE | `http = "redirect"` (`canonical` if the site has several names) |
| [L249-257](https://codeberg.org/forgejo/docs/src/commit/ee287bcd948f2dedc74cda8f7ff3d8a9b0aa3f37/docs/admin/setup/reverse-proxy.md#L249-L257) HAProxy `listen forgejo_80` | `redirect scheme https code 301` | "Redirection to SSL" | EXPRESSIBLE | `http = "redirect"` |
| [L380-389](https://codeberg.org/forgejo/docs/src/commit/ee287bcd948f2dedc74cda8f7ff3d8a9b0aa3f37/docs/admin/setup/reverse-proxy.md#L380-L389) Puppet `haproxy::listen { 'forgejo_80':` | `{ 'redirect' => 'scheme https code 301' },` | same, through Puppet | EXPRESSIBLE | `http = "redirect"` |
| [L105](https://codeberg.org/forgejo/docs/src/commit/ee287bcd948f2dedc74cda8f7ff3d8a9b0aa3f37/docs/admin/setup/reverse-proxy.md#L105), L195 prose (certbot) | "This should automatically set up HTTPS on port 443 and a redirect on the old port 80." | certbot-generated redirect, not shown verbatim | EXPRESSIBLE | `http = "redirect"` |

No response-header directives in any Forgejo example. L20-21 lists "advanced security settings … apply Content Security policies" as a reason for a proxy, with no example.

**Other directives:**
- `merge_slashes off; # Required to handle URL-encoded slashes` (L49, L78). This is Forgejo's equivalent of Gitea's `rewrite ^ $request_uri`. agensio: the proxy gets the raw target (CLAUDE.md, "Request target").
- Request fields: `proxy_set_header Connection $http_connection; Upgrade $http_upgrade; Host $host; X-Real-IP $remote_addr; X-Forwarded-For $proxy_add_x_forwarded_for; X-Forwarded-Proto $scheme;` (L54-59). Unlike Gitea's example there is no `proxy_http_version 1.1`. Forgejo v16 has no `/-/ws` route (grep of `routers/web/web.go` finds no websocket), so it does not matter. agensio: built in, plus `proxy.headers` for X-Real-IP.
- `client_max_body_size 512M;` (L61, L90) → `max_body_size = "512MB"`.
- Sub-path: nginx `location /code/ { proxy_pass http://127.0.0.1:3000/; }` (L80-81), Apache `ProxyPass /code http://127.0.0.1:3000/ nocanon` (L181), Caddy `route /code/* { uri strip_prefix /code ... }` (L433-436). These strip the prefix internally; agensio: `[[site.location]] path = "/code" upstream = "http://127.0.0.1:3000/"`. Container registry `/v2` must still be routed at the root (L462-466).
- HAProxy timeouts (`timeout connect 10s`, `client 30s`/`1m`, `server 30s`/`1m`) → `proxy = { connect_timeout, read_timeout }`.
- HAProxy `option forwardfor` → built-in X-Forwarded-For.
- Unix-socket upstream (L292-330) → `upstream = "unix:/path/forgejo.sock"`.
- **Differences from Gitea**:
  - adds HTTP→HTTPS redirect examples (nginx, Apache, HAProxy);
  - uses `merge_slashes off` instead of `rewrite ^ $request_uri`;
  - has no static-files-from-disk recipe, Traefik, IIS or Nginx Proxy Manager sections, but has HAProxy over a unix socket and a Puppet example;
  - adds a sub-path security warning (L28-33: same-origin assumption, CSRF);
  - mentions CSP at the proxy as a reason to use one (L20-21).

**App guidance:**
- **Trust the proxy**:
  - `ROOT_URL` (L95, L107; cheat sheet L305).
  - `[security] REVERSE_PROXY_LIMIT = 1`, `REVERSE_PROXY_TRUSTED_PROXIES = 127.0.0.0/8,::1/128` (cheat sheet L578-580).
  - Forgejo's cheat sheet has no `PUBLIC_URL_DETECTION`; that is a Gitea-only setting (not found in Forgejo's cheat sheet).
- **HSTS**: none in the docs or the code (no `Strict-Transport-Security` in `modules/`, `routers/`, `services/`).
- **CSP**: no general CSP from the app, only per-route policies: `default-src 'none'; style-src 'unsafe-inline'; sandbox` on served raw files (`modules/httplib/serve.go` L134-139), and `frame-src 'self'` / sandbox for rendered markup (`routers/web/repo/render.go` L48, `view.go` L565). The docs suggest a proxy CSP (L21).
  - agensio: `[[site.response_headers]] path = "/"` with `default = { "Content-Security-Policy" = "..." }` is EXPRESSIBLE.
  - Use `default`, not `set`: `set` would replace the sandbox policy on raw files, a security regression.
- **X-Frame-Options**: `[cors] X_FRAME_OPTIONS = SAMEORIGIN` (cheat sheet L217; still under `[cors]` in Forgejo, moved to `[security]` in Gitea). Sent by `services/context/context.go` L183, `api.go` L442, `errpage.go` L36.
- **nosniff**: set by the app (`base.go` L245, `serve.go` L61).
- **CORS**: app-side `[cors]` (cheat sheet L208-216), the same as Gitea's.
- **.well-known**: app routes [web.go L639-649](https://codeberg.org/forgejo/forgejo/src/commit/1aa13944143b3bc4312607239a68da23512d5ce3/routers/web/web.go#L639-L649): `/openid-configuration`, `/nodeinfo` and `/webfinger` (federation), `/change-password` (app redirect to `/user/settings/account`), and files from the custom `public/.well-known/` (`m.Methods("GET, HEAD", "/*", public.FileHandlerFunc())`). There is no `passkey-endpoints`, which Gitea has.
- **`/` to a sub-path redirect**: none.

---

## 8. GitLab

**Version read:**
- GitLab 19.4.2, the latest stable patch of the newest minor, released 2026-10-07. Patch releases 19.3.5 and 19.2.8 of older lines exist.
- `omnibus-gitlab` tag `19.4.2+ce.0` → commit `62bd053ca25858c01f5d0d3446e611d1ce14a49a`.
- `gitlab-org/gitlab` tag `v19.4.2-ee` → commit `9c053f678a4924425869b1b9e4bca3a44e45edf7`.

**Sources:**
- (a) Omnibus template: https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/62bd053ca25858c01f5d0d3446e611d1ce14a49a/files/gitlab-cookbooks/gitlab/templates/default/nginx-gitlab-rails.conf.erb . In 19.x the hint's `nginx-gitlab-http.conf.erb` is `nginx-gitlab-rails.conf.erb`, and `nginx[...]` keys moved to `gitlab_rails['nginx'][...]` in 19.2 (gitlab.rb.template L1994-1996).
- (b) Defaults: `files/gitlab-cookbooks/nginx/libraries/helpers/nginx_helper.rb` (not `gitlab/attributes/default.rb`, which holds no nginx defaults), `nginx/libraries/nginx.rb`, `letsencrypt/libraries/helper.rb`, `gitlab/recipes/nginx.rb`, `gitlab/templates/default/nginx-gitlab-health.conf.erb`, `nginx/templates/default/nginx.conf.erb`.
- (c) `files/gitlab-config-template/gitlab.rb.template`.
- (d) Docs source of docs.gitlab.com/omnibus/settings/nginx/ and /omnibus/settings/ssl/: `doc/settings/nginx.md`, `doc/settings/ssl/_index.md`, `doc/settings/configuration.md` (same commit).
- (e) Source install: https://gitlab.com/gitlab-org/gitlab/-/blob/v19.4.2-ee/lib/support/nginx/gitlab-ssl and `.../gitlab`.
- (f) App: `app/controllers/application_controller.rb`, `config/routes.rb`, `config/routes/well_known.rb`, `config/initializers/content_security_policy.rb`, `lib/gitlab/content_security_policy/config_loader.rb` (tag `v19.4.2-ee`).

### 8a. Omnibus `nginx-gitlab-rails.conf.erb` (ERB-conditional directives)

Base URL: `https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/62bd053ca25858c01f5d0d3446e611d1ce14a49a/files/gitlab-cookbooks/gitlab/templates/default/nginx-gitlab-rails.conf.erb`

| location / line | directive (verbatim) | condition and default | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|---|
| [#L33-66](https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/62bd053ca25858c01f5d0d3446e611d1ce14a49a/files/gitlab-cookbooks/gitlab/templates/default/nginx-gitlab-rails.conf.erb#L33-66) "HTTPS redirect server", `location /` (L49-51) | `return 301 https://<%= @fqdn %>:<%= @port %>$request_uri;` | `<% if @https && @redirect_http_to_https %>`. `redirect_http_to_https` defaults to `false` (nginx_helper.rb L92), but is set `true` automatically with Let's Encrypt unless the user set it (letsencrypt/libraries/helper.rb L53). Listens on `redirect_http_to_https_port` = 80 (L93). `server_name <fqdn>` only | "Redirects all HTTP traffic to the HTTPS host" (L34) | EXPRESSIBLE | `http = "redirect"` (with `canonical = "<fqdn>"` if the site has other names; for a non-443 TLS port, `http = { listen = ["0.0.0.0:80"] }`). Differences: 308 not 301; GitLab always writes the port (`https://host:443/...`) |
| L43-47 (same server) | `location /.well-known/acme-challenge/ { root <%= @dir %>/www/; }` | `<% if @letsencrypt_enable %>` (`letsencrypt['enable'] = nil` → auto) | ACME webroot, exempt from the redirect | NOT A REDIRECT/HEADER RULE | built in: ACME is answered first (redirects.md step 1) |
| L53-61 (same server) | `proxy_set_header ...` + `include <%= @gitlab_health_conf %>;`, which renders `location = /-/health { proxy_cache off; proxy_http_version 1.0; proxy_pass http://gitlab-workhorse; error_page 404 500 502 /error.txt; }` and the same for `/health_check`, `/health_check/database`, `/health_check/migrations`, `/health_check/cache`, `/health_check/geo` (txt) and `/-/readiness`, `/-/liveness` (json) | always, inside the redirect server | "These addresses will be allowed through plain http, even if `redirect_http_to_https` is enabled" (`gitlab/recipes/nginx.rb` L65-74) | NEEDS A CHANGE (or a workaround) | `http = "redirect"` exempts only ACME. Workaround with existing features (inferred): a second site on an internal plain listener (`listen = ["127.0.0.1:8080"]`, `http = "serve"`, `upstream` = workhorse, `[[site.access]]` for the probe addresses); **unverified** that two sites may share the name on different listeners. Smallest change: a list of exact paths exempt from the scheme redirect |
| [#L137-142](https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/62bd053ca25858c01f5d0d3446e611d1ce14a49a/files/gitlab-cookbooks/gitlab/templates/default/nginx-gitlab-rails.conf.erb#L137-142) main `server`, server level | `add_header Strict-Transport-Security "max-age=<%= @hsts_max_age -%><% if @hsts_include_subdomains %>; includeSubdomains<% end %>" always;` | `<% unless @hsts_max_age.nil? \|\| @hsts_max_age <= 0 %>`. Defaults `hsts_max_age = 63072000` (2 years), `hsts_include_subdomains = false` (nginx_helper.rb L72-73; gitlab.rb.template L2036-2039). **Not inside `<% if @https %>`**, so it is also emitted when `listen_https = false` behind another proxy (inferred from the template) | "Defaults to forcing web browsers to always communicate using only HTTPS" (template L2036). The docs say "enabled by default … two years … Setting `max_age` to `0` disables HSTS" (ssl/_index.md L582-614) | EXPRESSIBLE | `hsts = { max_age = "2y" }`; with `hsts_include_subdomains = true`: `hsts = { max_age = "2y", subdomains = true }`; `hsts_max_age = 0` → `hsts = { max_age = 0 }` (to clear) or no `hsts`. `always` matches agensio (every HTTPS answer). No preload in GitLab either. Behind agensio, set agensio's `hsts` (replaces GitLab nginx's copy) or `hsts_max_age = 0` in gitlab.rb |
| [#L144-149](https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/62bd053ca25858c01f5d0d3446e611d1ce14a49a/files/gitlab-cookbooks/gitlab/templates/default/nginx-gitlab-rails.conf.erb#L144-149) main `server` | `proxy_hide_header Referrer-Policy;` then `add_header Referrer-Policy <%= @referrer_policy %>;` | `<% if @referrer_policy %>`; default `'strict-origin-when-cross-origin'` (nginx_helper.rb L94); `false` disables (nginx.md L331-335). No `always` | "Rails sets a default policy of strict-origin-when-cross-origin, so hide that and just send the one we've configured for nginx" (L145-146) | EXPRESSIBLE | default value: nothing to write (the agensio baseline's `default` gives the same and Rails sends it anyway); another value: `[[site.response_headers]] path = "/"` with `set = { "Referrer-Policy" = "same-origin" }` (`set` = hide + add). Doc warning: `origin` or `no-referrer` breaks GitLab features (nginx.md L340-341) |
| L181-183 | `proxy_intercept_errors on;` | `<% if @custom_error_pages %>`, default nil | let nginx replace upstream error bodies with its own pages | NOT A REDIRECT/HEADER RULE (custom error pages) | no agensio equivalent (no error-page key in keys.md); the app works, only error pages differ |
| L197-205 `location ~ ^/api/v\d` | `proxy_intercept_errors off;` | always | API errors keep their JSON bodies | NOT A REDIRECT/HEADER RULE | agensio never replaces upstream bodies |
| [#L243-246](https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/62bd053ca25858c01f5d0d3446e611d1ce14a49a/files/gitlab-cookbooks/gitlab/templates/default/nginx-gitlab-rails.conf.erb#L243-246) `location <path>/assets` | `proxy_cache <%= @proxy_cache %>;` `proxy_pass http://gitlab-workhorse;` | `proxy_cache = 'gitlab'` (nginx_helper.rb L62; `proxy_cache_path` in nginx.conf.erb L40) | cache the precompiled assets at the proxy (Workhorse/Rails send the cache headers) | NOT A REDIRECT/HEADER RULE (proxy cache) | agensio has no response cache for proxied answers (inferred: the cache is for static files); the app works, performance only. Alternative: serve `/assets` from disk (see 8c) |
| [#L248-255](https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/62bd053ca25858c01f5d0d3446e611d1ce14a49a/files/gitlab-cookbooks/gitlab/templates/default/nginx-gitlab-rails.conf.erb#L248-255) | `error_page <%= err %> /<%= location %>;` (404, 500, 502 → `404.html` etc., or `NNN-custom.html`) + `location ~ ^/(404\|500\|502)(-custom)?\.html$ { root <%= GitlabRails.public_path %>; internal; }` | always (nginx.rb L84-95) | GitLab's own static error pages for nginx-generated errors (Workhorse down) | NOT A REDIRECT/HEADER RULE | no equivalent; agensio's own 502/504 pages apply |
| L257 | `<%= @custom_gitlab_server_config %>` | default nil | free text at the end of the server block | — | see the CORP row below |

Health conf (`nginx-gitlab-health.conf.erb` L5-13): `location /error.txt { return 500 'nginx returned $status when communicating with gitlab-workhorse\n'; }` and the same for `/error.json`. These are fixed error bodies for the monitoring locations. NOT A REDIRECT/HEADER RULE; there is no agensio equivalent and none is needed.

### 8b. Omnibus docs (docs.gitlab.com, source `doc/settings/*.md` at the same commit)

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| [nginx.md L345-365](https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/62bd053ca25858c01f5d0d3446e611d1ce14a49a/doc/settings/nginx.md#L345-365) "Cross-Origin-Resource-Policy header and Mermaid diagrams" | `gitlab_rails['nginx']['custom_gitlab_server_config'] = "add_header Cross-Origin-Resource-Policy same-site;"` (the breaking example) and `... "add_header Cross-Origin-Resource-Policy cross-origin;"` (the working one) | CORP `same-site`/`same-origin` breaks Mermaid's null-origin sandboxed iframe; use `cross-origin` | EXPRESSIBLE | `[[site.response_headers]] path = "/"` with `set = { "Cross-Origin-Resource-Policy" = "cross-origin" }` |
| [nginx.md L315-343](https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/62bd053ca25858c01f5d0d3446e611d1ce14a49a/doc/settings/nginx.md#L315-343) "Set the Referrer-Policy header" | `gitlab_rails['nginx']['referrer_policy'] = 'same-origin'` / `= false` | see 8a | EXPRESSIBLE | as 8a |
| [ssl/_index.md L332-351](https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/62bd053ca25858c01f5d0d3446e611d1ce14a49a/doc/settings/ssl/_index.md#L332-351) "Redirect HTTP requests to HTTPS" | `gitlab_rails['nginx']['redirect_http_to_https'] = true` | "By default, when you specify an `external_url` starting with `https`, NGINX no longer listens for unencrypted HTTP traffic on port 80" (L334-335); on by default with Let's Encrypt (L350-351) | EXPRESSIBLE | `http = "redirect"` (agensio's default is to redirect, GitLab's is off without LE) |
| [ssl/_index.md L582-614](https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/62bd053ca25858c01f5d0d3446e611d1ce14a49a/doc/settings/ssl/_index.md#L582-614) "Configure the HTTP Strict Transport Security (HSTS)" | `gitlab_rails['nginx']['hsts_max_age'] = 63072000` / `gitlab_rails['nginx']['hsts_include_subdomains'] = false` | HSTS on by default, two years; "only work for the main GitLab application and not for … Pages and Container Registry" | EXPRESSIBLE | `hsts = { max_age = "2y" }` (+ `subdomains = true` if wanted) |
| [nginx.md L707-712](https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/62bd053ca25858c01f5d0d3446e611d1ce14a49a/doc/settings/nginx.md#L707-712) "Use an existing Passenger and NGINX installation", `location ~ ^/(assets)/` | `root /opt/gitlab/embedded/service/gitlab-rails/public;` `gzip_static on;` `expires max;` `add_header Cache-Control public;` | "Enable gzip compression as per rails guide" (L702-706); long cache for fingerprinted Rails assets (inferred) | EXPRESSIBLE (matched by path prefix, not by extension) | `[[site.location]]` with `path = "/assets"` and `root = "/opt/gitlab/embedded/service/gitlab-rails/public"` (`.gz` twins are served automatically), plus `[[site.response_headers]]` with `path = "/assets"`, `when = "success"`, `set = { "Cache-Control" = "public, max-age=315360000", "Expires" = "Thu, 31 Dec 2037 23:55:55 GMT" }`. nginx sends two `Cache-Control` lines (`max-age=315360000` and `public`); agensio sends one. A location's `add_headers` would also do |
| nginx.md L714 | `error_page 502 /502.html;` | the app's 502 page from `public/` | NOT A REDIRECT/HEADER RULE | no equivalent |
| nginx.md L623-663 | `error_page 418 = @gitlab-workhorse;` `return 418;` (git HTTP, archives, artifacts) | internal routing hack ("'Error' 418 is a hack to re-use the @gitlab-workhorse block") | NOT A REDIRECT/HEADER RULE | a `[[site.location]]` per path with `upstream` = workhorse; regex paths are not available (prefix/exact/suffix only) |
| nginx.md L89-121 "Change the default proxy headers" | `gitlab_rails['nginx']['proxy_set_headers'] = { "X-Forwarded-Proto" => "http", "CUSTOM_HEADER" => "VALUE" }` | request fields | NOT A REDIRECT/HEADER RULE | `proxy = { headers = { ... } }` |

### 8c. Source install `lib/support/nginx/gitlab-ssl` and `gitlab` (v19.4.2-ee)

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| [gitlab-ssl L69-82](https://gitlab.com/gitlab-org/gitlab/-/blob/v19.4.2-ee/lib/support/nginx/gitlab-ssl#L69-82) port-80 `server` | `return 301 https://$http_host$request_uri;` (L79) | "Redirects all HTTP traffic to the HTTPS host" | EXPRESSIBLE | `http = "redirect"` (308; `$http_host` means any name; agensio redirects the site's names) |
| [gitlab-ssl L119-120](https://gitlab.com/gitlab-org/gitlab/-/blob/v19.4.2-ee/lib/support/nginx/gitlab-ssl#L119-120) HTTPS server, **commented out** | `# add_header Strict-Transport-Security "max-age=63072000; includeSubDomains";` | "[Optional] Enable HTTP Strict Transport Security" | EXPRESSIBLE | `hsts = { max_age = "2y", subdomains = true }` |
| gitlab-ssl L156-166; gitlab L117-127 | `error_page 404 /404.html; error_page 422 /422.html; error_page 500 /500.html; error_page 502 /502.html; error_page 503 /503.html;` + `location ~ ^/(404\|422\|500\|502\|503)\.html$ { root /home/git/gitlab/public; internal; }` | GitLab's static pages for nginx-generated errors (without `proxy_intercept_errors` they cover nginx's own errors only) | NOT A REDIRECT/HEADER RULE | no equivalent |
| gitlab-ssl L106, gitlab L82 (comment) | `## See app/controllers/application_controller.rb for headers set` | security headers are the app's | — | see App guidance |

**Other directives (GitLab):**
- Upstream Workhorse over a unix socket → `upstream = "unix:/var/opt/gitlab/gitlab-workhorse/sockets/socket"` (or `.../tmp/sockets/gitlab-workhorse.socket` for a source install).
- WebSocket: `map $http_upgrade $connection_upgrade`; `proxy_set_header Upgrade/Connection`. Automatic in agensio.
- `client_max_body_size` is 0 (unlimited) in Omnibus (nginx_helper.rb L69) and the source install, and 250m in the Passenger recipe. agensio has only a site `max_body_size`; whether "unlimited" can be written is **unverified**, so use a large value. LFS and git push need it.
- Timeouts: `proxy_read_timeout 3600` and `proxy_connect_timeout 300` in Omnibus; 300/300 in the source install → `proxy = { read_timeout = 3600, connect_timeout = 300 }`.
- `proxy_request_buffering off` for `request_buffering_off_path_regex` (`/api/v\d/jobs/\d+/artifacts$|/import/gitlab_project$|\.git/git-receive-pack$|...`, nginx_helper.rb L95) → `proxy = { request_buffering = false }`, site-wide or per prefix/suffix location; agensio has no regex locations.
- `proxy_buffering off` (Passenger) → `proxy = { buffering = false }`.
- `proxy_redirect off` (no `Location` rewriting) → agensio's `redirects = "rewrite"` only touches `Location` values pointing at the origin's own address, so it is harmless; `"pass"` is the exact equivalent.
- `proxy_cache off` / `gitlab` → there is no proxy cache.
- Request fields:
  - Omnibus: `Host $http_host_with_default`, `X-Real-IP $remote_addr`, `X-Forwarded-For $remote_addr` (replace, nginx_helper.rb L82-88; the gitlab.rb.template comment shows `$proxy_add_x_forwarded_for`), `Upgrade`, `Connection`, plus `X-Forwarded-Proto https` and `X-Forwarded-Ssl on` when the external URL is https (nginx.rb L54-58).
  - Source install: `X-Forwarded-Ssl on` (gitlab-ssl L147).
  - agensio: Host and X-Forwarded-For/Proto are built in; add `proxy = { headers = { "X-Real-IP" = "$remote_addr", "X-Forwarded-Ssl" = "on" } }`. A fixed `"on"` is correct only on a TLS-only site, since agensio has no conditional value.
- `gzip` / `gzip_static` (Omnibus gzip on for text types, `gzip_proxied no-cache no-store private expired auth`; source install `gzip off` in `/`). agensio does no on-the-fly gzip, only precompressed twins from disk.
- `real_ip_header` / `set_real_ip_from` → `[server] trusted_proxies`.
- `server_tokens off` (L41, L78) → agensio's `Server` is its own and refused in rules (version disclosure not checked).
- Access-log filtering of `private_token`, `authenticity_token`, `rss_token`, `feed_token` and `token` from logged URIs (`nginx.conf.erb` L48-84; gitlab-ssl L38-66). agensio has no equivalent (**unverified**); tokens in query strings would reach agensio's access log. This is logging, not a header rule, but security-relevant.
- Relative URL (`@path`) handling: GitLab serves the sub-path itself; the proxy passes it unchanged.

**App guidance (GitLab):**
- **HSTS**: on by default in the bundled nginx, `max-age=63072000`, `always`; `includeSubdomains` is opt-in, spelled `includeSubdomains` in the template; no preload. The source install has it commented, with `includeSubDomains`. The other bundled vhosts (registry, Pages, KAS) have their own HSTS without `always` (their templates L105-108, L111-114, L98-101).
- **Headers the app sets**: `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection: 1; mode=block`, `X-UA-Compatible: IE=edge`, `X-Content-Type-Options: nosniff` (`application_controller.rb` L324-329). Rails sets `Referrer-Policy: strict-origin-when-cross-origin` (template comment L145).
- **CSP**: Rails, nonce-based (`content_security_policy.rb` L17-18). Off by default on self-managed (`config_loader.rb` L15-16: enabled only in development and test; configuration.md L791-792: "not configured by default on GitLab Self-Managed"); turned on in gitlab.rb (`gitlab_rails['content_security_policy']`). The proxy must not `set` a CSP: it would break the nonce.
- **CORS**: app-side. OAuth/OIDC OPTIONS preflight routes are in `config/routes.rb` L77-88. Nothing at the proxy.
- **.well-known**: served by the app.
  - `/change-password` is an app 302 to `-/user_settings/password/edit` (`config/routes/well_known.rb` L3).
  - `/security.txt` is generated from an admin setting (L4).
  - `/openid-configuration`, `/webfinger` and `/oauth-protected-resource` (routes.rb L48, L80-82).
  - MCP discovery: `/.well-known/oauth-authorization-server/api/v4/mcp` etc. (L66-71).
  - Terraform `/.well-known/terraform.json` (L116).

  The proxy must pass `/.well-known/` through, except ACME.
- **Trust the proxy**:
  - Non-bundled web server: `gitlab_rails['trusted_proxies'] = [...]` (nginx.md L220-231); bundled: `real_ip_trusted_addresses` (L123-149).
  - TLS terminated outside: `gitlab_rails['nginx']['listen_port'] = 80` and `['listen_https'] = false` (ssl/_index.md L418-438). Forward `Host`, `X-Forwarded-Ssl`, `X-Forwarded-For` and `X-Forwarded-Port`, or see "422 / Can't verify CSRF token authenticity" (L468-472).
  - `external_url` decides scheme and host.
- **XFO and embedding**: the app's SAMEORIGIN; CSP `frame_ancestors` is configurable in gitlab.rb.
- **Cache-Control on assets**: proxied assets get the app's headers. The Passenger recipe adds `expires max` + `Cache-Control public` for the `/assets/` prefix (fingerprinted Rails assets; a path prefix, not an extension regex).
- **`/` to a sub-path redirect**: none.

---

## 9. Mattermost

**Version read:**
- Mattermost server v11.11.1, released 2026-09-24. Lightweight tag → commit `3acb3a7f684d11ccfcec4e5bd11c79f64e3eabf9`.
- Docs repo `mattermost/docs`, `master` = `bd09d959514c34e72a33c24663b5946682b656ec` (2026-09-17). The docs are not versioned per release.
- Official Docker deployment repo `mattermost/docker`, `HEAD` = `497414659ee7127677d2b91b44bb4f3ea9d14695` (linked from docs `install-docker.rst` L36 as the official deployment).

**Sources:**
- docs.mattermost.com "(Recommended) Set up an NGINX proxy": https://github.com/mattermost/docs/blob/bd09d959514c34e72a33c24663b5946682b656ec/source/deployment-guide/server/setup-nginx-proxy.rst
- HA guide: `source/administration-guide/scale/high-availability-cluster-based-deployment.rst`.
- Containers: `source/deployment-guide/server/deploy-containers.rst`.
- Docker repo: https://github.com/mattermost/docker/blob/497414659ee7127677d2b91b44bb4f3ea9d14695/nginx/conf.d/default.conf
- Server source: https://github.com/mattermost/mattermost/blob/3acb3a7f684d11ccfcec4e5bd11c79f64e3eabf9/server/channels/web/handlers.go
- No official Caddy, Traefik or Apache example exists in the docs repo (grep for `Caddyfile`, `traefik.http` and `haproxy.cfg` found none; HAProxy is only named in the maintenance page, without a config).

### 9a. setup-nginx-proxy.rst

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| [L120-124](https://github.com/mattermost/docs/blob/bd09d959514c34e72a33c24663b5946682b656ec/source/deployment-guide/server/setup-nginx-proxy.rst#L120-L124) `server { listen 80 default_server; server_name mattermost.example.com;` | `return 301 https://$server_name$request_uri;` | HTTP to HTTPS (L23: "HTTP to HTTPS redirect") | EXPRESSIBLE | `http = "redirect"` (`$server_name` is the canonical name: `canonical` if there are several) |
| [L147-148](https://github.com/mattermost/docs/blob/bd09d959514c34e72a33c24663b5946682b656ec/source/deployment-guide/server/setup-nginx-proxy.rst#L147-L148) HTTPS `server`, server level (repeated at L384-385 in the post-certbot config) | `add_header Strict-Transport-Security max-age=15768000;` | "HSTS (ngx_http_headers_module is required) (15768000 seconds = six months)" | EXPRESSIBLE (syntax caveat) | `hsts = { max_age = "15768000s" }`. **Unverified**: whether a seconds unit is accepted; the design shows `"2y"` and `"1d"`. Differences: no `always` in nginx (2xx/3xx only), while agensio sends it on every HTTPS answer; no `includeSubDomains`, no preload |
| [L154](https://github.com/mattermost/docs/blob/bd09d959514c34e72a33c24663b5946682b656ec/source/deployment-guide/server/setup-nginx-proxy.rst#L154) HTTPS `server` | `add_header X-Early-Data $tls1_3_early_data;` (with `map $ssl_early_data $tls1_3_early_data { "~." $ssl_early_data; default ""; }`, L196-199, and `ssl_early_data on;` L142) | comment L138-140: "Enable TLSv1.3's 0-RTT. Use $ssl_early_data when reverse proxying to prevent replay attacks"; L193-195: "useful for debugging TLS v1.3". It is a *response* field to the client, so it gives the app no replay protection (inferred; the Docker repo uses `proxy_set_header Early-Data` instead) | NOT OFFERED ON PURPOSE (no variables in values) | moot: agensio has no TLS early-data support (no `early_data` in `src/`), so the value would always be empty. The app works without it |
| L164, L184, L260, L279, L336, L356 (every `location`), and HA guide L312, L332, L354 | `proxy_set_header X-Frame-Options SAMEORIGIN;` | intended as anti-clickjacking (inferred), but it is a **request** field sent to Mattermost, which never reads it (no read found in `server/channels/web`) | NOT A REDIRECT/HEADER RULE (a request field with no effect) | omit. A literal copy would be `proxy = { headers = { "X-Frame-Options" = "SAMEORIGIN" } }`. The response XFO is set by the app itself (handlers.go L255-257) |
| [L393-403](https://github.com/mattermost/docs/blob/bd09d959514c34e72a33c24663b5946682b656ec/source/deployment-guide/server/setup-nginx-proxy.rst#L393-L403) port-80 `server` written by certbot | `if ($host = mattermost.example.com) { return 301 https://$host$request_uri; } # managed by Certbot` … `return 404; # managed by Certbot` | redirect the site's name, 404 for other Host values | EXPRESSIBLE | `http = "redirect"`; other names never match the site (agensio answers 421 or the catch-all) |
| [L497-498](https://github.com/mattermost/docs/blob/bd09d959514c34e72a33c24663b5946682b656ec/source/deployment-guide/server/setup-nginx-proxy.rst#L497-L498) `location ~ /api/v[0-9]+/users/[a-z0-9]+/image$` (also HA guide L343-344) | `proxy_ignore_headers Cache-Control Expires;` `proxy_cache_valid 200 24h;` | "User images cached for 24 hours" (L557) at the proxy, ignoring the app's cache headers | NOT A REDIRECT/HEADER RULE (proxy cache) | no proxy cache in agensio; the app works (performance at scale only) |
| [L604-611](https://github.com/mattermost/docs/blob/bd09d959514c34e72a33c24663b5946682b656ec/source/deployment-guide/server/setup-nginx-proxy.rst#L604-L611) FAQ "Too many redirects", `location ~* ^/sub-path` | `if ($request_method = HEAD) { return 200; }` | a workaround for a redirect loop with a sub-path | NOT A REDIRECT/HEADER RULE (fixed status by method) | no equivalent (no method conditions); likely unnecessary when SiteURL includes the sub-path (inferred) |

### 9b. Official Docker deployment `mattermost/docker` `nginx/conf.d/default.conf`

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| [L17-24](https://github.com/mattermost/docker/blob/497414659ee7127677d2b91b44bb4f3ea9d14695/nginx/conf.d/default.conf#L17-L24) `server { server_name _; listen 80 default_server;` | `return 301 https://$host$request_uri;` | "redirect all HTTP requests to HTTPS with a 301 Moved Permanently response" | EXPRESSIBLE | `http = "redirect"` |
| [L73](https://github.com/mattermost/docker/blob/497414659ee7127677d2b91b44bb4f3ea9d14695/nginx/conf.d/default.conf#L73) server level ("security headers", L70-72, citing securityheaders.com) | `add_header X-Frame-Options "SAMEORIGIN" always;` | anti-clickjacking | EXPRESSIBLE | `[[site.response_headers]] path = "/" default = { "X-Frame-Options" = "SAMEORIGIN" }`. Use `default`: the app sends SAMEORIGIN plus CSP `frame-ancestors 'self' <FrameAncestors>` on HTML. nginx adds a second copy; agensio never duplicates |
| L74 | `add_header X-XSS-Protection "1; mode=block" always;` | legacy XSS filter | EXPRESSIBLE | `set = { "X-XSS-Protection" = "1; mode=block" }` (not a refused name) |
| L75 | `add_header X-Content-Type-Options "nosniff" always;` | no MIME sniffing | EXPRESSIBLE | the baseline covers agensio's own answers; for app answers `set = { "X-Content-Type-Options" = "nosniff" }`. The app already sends it (handlers.go L252, static.go L143) |
| L76 | `add_header Referrer-Policy no-referrer;` (no `always`) | referrer policy | EXPRESSIBLE | `set = { "Referrer-Policy" = "no-referrer" }`. Without it, the baseline `default` puts `strict-origin-when-cross-origin` only on answers that have none (agensio's own error pages); the app itself sends `no-referrer` (handlers.go L253) |
| L77 | `add_header Strict-Transport-Security "max-age=63072000" always;` | HSTS, 2 years | EXPRESSIBLE | `hsts = { max_age = "2y" }` |
| L78 | `add_header Permissions-Policy "interest-cohort=()";` (no `always`) | opt out of Google FLoC (inferred; FLoC is obsolete) | EXPRESSIBLE | `set = { "Permissions-Policy" = "interest-cohort=()" }`. The app sends an empty `Permissions-Policy: ` (handlers.go L251), so nginx yields two lines; agensio `set` yields one |
| [L82-86](https://github.com/mattermost/docker/blob/497414659ee7127677d2b91b44bb4f3ea9d14695/nginx/conf.d/default.conf#L82-L86) `location ^~ /.well-known` | `default_type "text/plain";` `root /usr/share/nginx/html;` `allow all;` | "ACME-challenge" webroot | NOT A REDIRECT/HEADER RULE (static from disk) | ACME is answered by agensio itself. For other extensionless files there, agensio sends `application/octet-stream` (`src/mime.cpp` L119-123) and `Content-Type` is refused in rules: a per-location default type NEEDS A CHANGE only if something besides ACME is served there |
| [L88-89](https://github.com/mattermost/docker/blob/497414659ee7127677d2b91b44bb4f3ea9d14695/nginx/conf.d/default.conf#L88-L89) server level, written after a location | `add_header X-Robots-Tag "noindex";` | "disable Google bots from indexing this site" | EXPRESSIBLE | `set = { "X-Robots-Tag" = "noindex" }` |
| L99, L120 (both locations) | `proxy_set_header X-Frame-Options SAMEORIGIN;` | as 9a (request field, no effect) | NOT A REDIRECT/HEADER RULE | omit |
| L100, L121 | `proxy_set_header Early-Data $ssl_early_data;` | RFC 8470 replay signal to the app | NOT A REDIRECT/HEADER RULE (request field) | moot: agensio never accepts 0-RTT, so there is nothing to signal |

nginx inheritance note: in 9b, all `add_header` lines are at server level and no location has its own, so every location inherits them. In agensio the same is one rule at `path = "/"`.

**Other directives (Mattermost):**
- WebSocket: `location ~ /api/v[0-9]+/(users/)?websocket$` with `proxy_set_header Upgrade $http_upgrade; Connection "upgrade";` → automatic in agensio; no separate location needed.
- `client_max_body_size` 50M (websocket location, HA, snippets) and 100M (`/`, docs L178, Docker L114) → site `max_body_size = "100MB"` (one value per site).
- Timeouts:
  - `client_body_timeout 60s` → `[server] body_timeout` (60 s default);
  - `send_timeout 300s` → no direct equivalent (agensio's idle clock is refreshed per 64 KB piece);
  - `lingering_timeout 5s` → no equivalent;
  - `proxy_connect_timeout 90s`/`30s`, `proxy_send_timeout 300s`/`90s`, `proxy_read_timeout 90s`/`600s` → `proxy = { connect_timeout, send_timeout, read_timeout }`. A WebSocket tunnel has no idle limit by default (`tunnel_timeout`).
- Buffers: `proxy_buffers 256 16k; proxy_buffer_size 16k` → `proxy.buffer_max`, `head_max`.
- `proxy_http_version 1.1; proxy_set_header Connection "";` + `upstream { keepalive 32/64/256; }` → agensio keeps upstream connections (`max_idle`).
- Request fields: `Host $host`/`$http_host` (passed through by default), `X-Real-IP $remote_addr` (add with `proxy.headers`), `X-Forwarded-For`, `X-Forwarded-Proto $scheme` (built in; the containers page hard-codes `https`, L52).
- `proxy_cache mattermost_cache; proxy_cache_revalidate on; proxy_cache_min_uses 2; proxy_cache_use_stale timeout; proxy_cache_lock on;` → no proxy cache in agensio.
- Load balancing `upstream backend { server ... max_fails=0; ... }` → `upstream = [...]` groups (`max_fails`).
- `gzip on` (Docker L37-41, high-performance http block) → none on the fly.
- `map $status $loggable` conditional access log → not in agensio (**unverified**).
- TLS: `ssl_early_data on`, `ssl_stapling on` → agensio has no 0-RTT and no OCSP stapling (CLAUDE.md "Not yet").
- `proxy_pass https://backend` (transport-encryption.rst L48) → `upstream = "https://..."` with `proxy.tls`.

**App guidance (Mattermost):**
- **HSTS**:
  - docs nginx: `max-age=15768000` (six months), not `always`, no subdomains, no preload;
  - Docker repo: `max-age=63072000` `always`;
  - app setting `ServiceSettings.TLSStrictTransport` (default `false`) with `TLSStrictTransportMaxAge` (default `63072000`) sends `Strict-Transport-Security: max-age=N` from the app (handlers.go L246-248; config.go L670-675).
- **Headers the app sets itself** (handlers.go [L250-268](https://github.com/mattermost/mattermost/blob/3acb3a7f684d11ccfcec4e5bd11c79f64e3eabf9/server/channels/web/handlers.go#L250-L268), comment "Hardcoded sensible default values for these security headers. Feel free to override in proxy or ingress"):
  - `Permissions-Policy: ""`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` on all handler answers;
  - on static/HTML answers, `X-Frame-Options: SAMEORIGIN` and `Content-Security-Policy: frame-ancestors 'self' <FrameAncestors>; script-src 'self'<sha hashes>`;
  - API answers get `Expires: 0` on GET;
  - static files get `Cache-Control: max-age=31556926, public` (`no-cache, max-age=31556926, public` for `remote_entry.js`) plus the same three security headers (static.go L130-145).

  The proxy must not `set` a CSP: it would drop the script hashes and `FrameAncestors`. Use `default` only.
- **Embedding**: `ServiceSettings.FrameAncestors` (Integrations settings, integrations-configuration-settings.rst L469-475) extends `frame-ancestors`. A proxy-level `X-Frame-Options: SAMEORIGIN` on HTML is superseded by `frame-ancestors` in CSP2 browsers (inferred from the CSP spec). It still conflicts in principle, so prefer `default`.
- **CORS**: app-side `ServiceSettings.AllowCorsFrom` (default empty; config.go L136, L441). The WebSocket Origin check compares against Host, so keep Host passed through (FAQ L613-635).
- **Trust the proxy**: `ServiceSettings.TrustedProxyIPHeader`, default `[]`: no header trusted, so every client appears as the proxy's address (environment-configuration-settings.rst L472-494). Set it to `["X-Forwarded-For"]` behind agensio, which replaces the client's own X-Forwarded-For, or to `["X-Real-IP"]` together with `proxy.headers` X-Real-IP. Also set `SiteURL`.
- **.well-known**: the app serves none (no route found in `server/channels/web` / `app/platform`; sparse check). The Docker config serves `/.well-known` from disk only for ACME.
- **Hashed assets**: the app sets Cache-Control itself; no proxy rule for it.
- **`/` to a sub-path**: none (sub-path is SiteURL-driven; the FAQ HEAD workaround only).

---

## 10. Rocket.Chat

> **Note added with the synthesis (2026-10-13).** The Matrix federation file below is expressible today: a `.json` file and an exact location with `try_files` answer it as `application/json` (run on 0.1.0-alpha.72; see the method section).

**Version read:**
- Rocket.Chat 8.9.0, released 2026-10-05. Tag → commit `057a927d903c83b5d61cf236d650c4500ebb4b66`.
- Docs: docs.rocket.chat (Document360). The GitHub `RocketChat/docs` repo is stale (last push 2024-06-27), so the pages were read through their `.md` exports listed in https://docs.rocket.chat/llms.txt, fetched 2026-10-13.
- The old "Configuring SSL Reverse Proxy" URLs (`/docs/configuring-ssl-reverse-proxy`, `/setup-and-configure/environment-configuration/configuring-ssl-reverse-proxy`) now redirect to `/docs/additional-configurations`, which is 404. **There is no dedicated reverse-proxy page any more**; the proxy configs live inside the deployment guides.
- Official compose repo `RocketChat/rocketchat-compose` `HEAD` = `967a4d3a8a7dd8be1836067f447a60cb10f86b00` (2026-07-30), which the Docker guide names as "official".

**Sources (page `updated:` stamp in brackets; line numbers are of the `.md` export):**
- Deploy with Docker and Docker Compose: https://docs.rocket.chat/docs/deploy-with-docker-docker-compose [2026-09-08]
- Deploy with Ubuntu: https://docs.rocket.chat/docs/deploy-with-ubuntu [2026-10-05]. CentOS and Debian are the same config; Podman has the same nginx as Docker.
- Configure with Post-Quantum Resistant TLS: https://docs.rocket.chat/docs/configure-rocket-chat-with-post-quantum-resistant-tls [2026-09-04]
- Deploy with Snaps (Caddy): https://docs.rocket.chat/docs/deploy-with-snaps [2026-04-23]
- Running Multiple Instances (Traefik): https://docs.rocket.chat/docs/running-multiple-instances [2026-09-08]
- Federation Configuration: https://docs.rocket.chat/docs/federation-configuration [2026-07-28]
- Deployment Environment Variables: https://docs.rocket.chat/docs/deployment-environment-variables
- Compose: https://github.com/RocketChat/rocketchat-compose/blob/967a4d3a8a7dd8be1836067f447a60cb10f86b00/compose.traefik.yml and `compose.manual-cert.traefik.yml`
- Source: https://github.com/RocketChat/Rocket.Chat/blob/057a927d903c83b5d61cf236d650c4500ebb4b66/apps/meteor/server/lib/cors/cors.ts

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what is missing |
|---|---|---|---|---|
| Docker guide `.md` L337-341 and L388-392 (section "Step 3: Install and configure Nginx"), `server { listen 80; server_name <ABC.DOMAIN.COM>;` | `return 301 https://$host$request_uri;` | HTTP to HTTPS | EXPRESSIBLE | `http = "redirect"` |
| Post-quantum TLS `.md` L169-173 | `return 301 https://$host$request_uri;` | same | EXPRESSIBLE | `http = "redirect"` |
| Post-quantum TLS `.md` L190-191, HTTPS `server`, "# Security headers" | `add_header Strict-Transport-Security "max-age=63072000" always;` | HSTS 2 years, every answer | EXPRESSIBLE | `hsts = { max_age = "2y" }` |
| Post-quantum TLS `.md` L192 | `add_header X-Frame-Options SAMEORIGIN;` | anti-clickjacking | EXPRESSIBLE | `[[site.response_headers]] path = "/" default = { "X-Frame-Options" = "SAMEORIGIN" }`. Use `default`, never `set`: the app sends `X-Frame-Options` itself when `Iframe_Restrict_Access` is true (default), and an admin who turns it off for iframe embedding or iframe SSO would be overridden by a proxy `set` (nginx's `add_header` duplicates it) |
| Post-quantum TLS `.md` L193 | `add_header X-Content-Type-Options nosniff;` | no sniffing | EXPRESSIBLE | `set = { "X-Content-Type-Options" = "nosniff" }`. The app already sends it (cors.ts L32) |
| Ubuntu/CentOS/Debian `.md` (Ubuntu L302) prose: "Follow the prompts to … enable HTTPS redirection. Certbot will automatically configure SSL" | certbot-generated redirect (not shown) | HTTP to HTTPS | EXPRESSIBLE | `http = "redirect"` |
| Ubuntu `.md` Traefik `traefik.toml` (`[entryPoints.web] address = ":80"`, `[entryPoints.websecure] address = ":443"`) and `rocketchat.toml` router on `websecure` only | no redirect configured: plain-HTTP requests on :80 match no router (404 from Traefik; inferred) | — | — (no directive) | agensio's default `http = "redirect"` is better |
| [compose.traefik.yml L57-64](https://github.com/RocketChat/rocketchat-compose/blob/967a4d3a8a7dd8be1836067f447a60cb10f86b00/compose.traefik.yml#L57-L64), written into the *dynamic* file `/traefik_config/https/dynamic.yml` (also running-multiple-instances `.md` L218-225) | `https:` / `address: ":443"` / `http:` / `redirections:` / `entryPoint:` / `to: "http"` / `scheme: "https"` | HTTP to HTTPS (intended) | EXPRESSIBLE (as intent) | `http = "redirect"`. As written it is an entryPoint (static) setting inside a dynamic config and names `to: "http"`; most likely ignored by Traefik (inferred, **unverified**) |
| [compose.manual-cert.traefik.yml L116-120](https://github.com/RocketChat/rocketchat-compose/blob/967a4d3a8a7dd8be1836067f447a60cb10f86b00/compose.manual-cert.traefik.yml#L116-L120) command line | `--entrypoints.http.http.redirections.entryPoint.to=https` `--entrypoints.http.http.redirections.entryPoint.scheme=https` `--entrypoints.http.http.redirections.entryPoint.permanent=true` | "Redirect all HTTP traffic to HTTPS at the entrypoint level" | EXPRESSIBLE | `http = "redirect"`. Traefik's permanent redirect status (301 for GET, 308 otherwise) is from memory of Traefik's middleware, **unverified** here |
| Snaps `.md` L299-326 (Caddyfile) | `example-domain.com` / `reverse_proxy localhost:3000` | Caddy's automatic HTTPS, which implies an HTTP→HTTPS redirect (Caddy behaviour, not written in the file) | EXPRESSIBLE | `tls = "auto"` + default `http = "redirect"` |

There are no other response-header directives in any Rocket.Chat page.

**Other directives (Rocket.Chat):**
- WebSocket: `proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade";` → automatic (agensio recipe `docs/examples/proxy.md` L227-273).
- Request fields:
  - `Host $http_host` → passed through.
  - `X-Real-IP $remote_addr` → **must be added**: `proxy = { headers = { "X-Real-IP" = "$remote_addr" } }`. See App guidance; agensio forwards a client's own X-Real-IP otherwise.
  - `X-Forwarded-For $proxy_add_x_forwarded_for` → built in.
  - `X-Forwarded-Proto http` (hard-coded `http` even in the TLS server block of the Docker guide L319 and the Ubuntu config) / `https` (Grafana location; post-quantum page L208) → built in from the real scheme. That is correct and avoids `Force_SSL` loops.
  - `X-Nginx-Proxy true` → not read by the server code checked (no match in `apps/meteor/server`, `app/api/server`, `app/lib/server`, `app/cors`; sparse check). Omit, or add via `proxy.headers`.
  - `X-Forwarded-Host $http_host` (post-quantum page L209) → agensio sends it only when Host is rewritten.
- `proxy_redirect off;` → agensio `redirects = "rewrite"` only touches origin-pointing `Location` values; harmless.
- Grafana under `/grafana` (`proxy_pass http://localhost:5050/grafana;`) → `[[site.location]] path = "/grafana" upstream = "http://127.0.0.1:5050/grafana"`. Grafana on a subdomain → a second site.
- `root /usr/share/nginx/html; index index.html index.htm;` in the Docker guide's TLS server: dead with `location /` proxied (inferred).
- Body size: the Ubuntu/Docker guides set none (nginx default 1m); agensio's recipe sets `max_body_size = "100MB"`.
- Matrix federation (federation-configuration `.md` L39-55): a JSON file at `https://<federation domain>/.well-known/matrix/server`, e.g. `{ "m.server": "chat.acme.com:443" }`, "requires a web server (nginx, Apache, or a CDN) running on acme.com:443". Under agensio this is a static file: `<root>/.well-known/matrix/server`, served on the federation domain's site (dot-segment `/.well-known/` is allowed since alpha.70). It goes out as `application/octet-stream`, because the name has no extension and `Content-Type` is refused in `[[site.response_headers]]`. Whether Matrix peers accept that is **unverified**. If they need `application/json`: NEEDS A CHANGE (a per-file or per-location type, or a static JSON answer).

**App guidance (Rocket.Chat):**
- **HSTS**: only the post-quantum TLS page sets it (`max-age=63072000` `always`, no subdomains, no preload). The app never sends HSTS (no `Strict-Transport-Security` in `apps/meteor/server`).
- **Headers the app sets** (cors.ts [L28-81](https://github.com/RocketChat/Rocket.Chat/blob/057a927d903c83b5d61cf236d650c4500ebb4b66/apps/meteor/server/lib/cors/cors.ts#L28-L81)):
  - `X-XSS-Protection: 1`;
  - `X-Content-Type-Options: nosniff`;
  - `X-Frame-Options: <Iframe_X_Frame_Options>` (default `sameorigin`) when `Iframe_Restrict_Access` (default true; settings/general.ts L111-120);
  - `Content-Security-Policy` built from settings when `Enable_CSP` (default **true**, general.ts L95), including CDN prefixes and `Extra_CSP_Domains`;
  - the Livechat route sets its own `frame-ancestors` from `Livechat_AllowedDomainsList` or removes the CSP (`server/lib/omnichannel/livechat.ts` L43-70);
  - static files get `Access-Control-Allow-Origin: *` (cors.ts L100).

  So: no proxy CSP, and XFO only as `default`. Whether the app's own XFO blocks third-party Livechat embedding is **unverified**.
- **CORS**: app-side `API_Enable_CORS` (default false) / `API_CORS_Origin` (default `*`) (general.ts L24-28).
- **Trust the proxy**:
  - `ROOT_URL=https://your_domain.com` (Ubuntu `.md` L403-412; Docker guide `.md` L206).
  - `HTTP_FORWARDED_COUNT`, "the number of proxies in front of Rocket.Chat. If not configured, it defaults to 1" (environment variables `.md` L59). The 8.9.0 REST middleware uses `parseInt(process.env.HTTP_FORWARDED_COUNT) || 0` and, at 0, returns `x-real-ip || socket address` (`server/api/v1/middlewares/remoteAddressMiddleware.ts` L14-22). Docs and code disagree on the default; Meteor's DDP path was not checked (**unverified**).
  - `x-real-ip` takes precedence (`server/lib/getClientAddress.ts` L10).
  - **agensio implication**: add `proxy = { headers = { "X-Real-IP" = "$remote_addr" } }`, which also drops a client's own copy. The current agensio recipe lacks it.
- **Force_SSL** (setting, default false): an app-side `302` to `https://<Host><url>` when the request is not local and `X-Forwarded-Proto` lacks `https` (cors.ts L136-163). agensio's correct X-Forwarded-Proto avoids a loop; with agensio's `http = "redirect"` the setting is unnecessary.
- **.well-known**: Matrix `/.well-known/matrix/server` on the federation domain (above). No other `.well-known` delegation is documented.
- **Hashed assets**: the app sets its own headers (e.g. `Cache-Control: public, max-age=3600` for `meteor_runtime_config.js`, cors.ts L119); no proxy rule.
- **`/` to a sub-path**: none (Grafana's sub-path is proxied, not redirected).

---

## 11. Matrix Synapse (plus the Matrix specification)

> **Note added with the synthesis (2026-10-13).** The rows below that call the fixed JSON answers "NEEDS A CHANGE" were written before a run on 0.1.0-alpha.72 showed that a `.json` file under the site's root plus `[[site.location]] path = "/.well-known/matrix/server"`, `match = "exact"`, `try_files = ["/.well-known/matrix/server.json"]` answers with `Content-Type: application/json; charset=utf-8` (the lighttpd form at L387-395 below). They are expressible today; see the method section and 28 "No change".

### Version read
- Synapse **v1.162.0** (GitHub "latest release", published 2026-09-29). The annotated tag object is
  `03005bc9436b774bdd9b1e173c1e161e11b283b3`; it points to commit **`63dc0cbfe514f60743212566374ffeb5e9e295c2`**.
- Matrix spec **v1.19**, at commit `b9c3d5ed3b0b46b2b025b4a427119036bc9ed71a` (the newest tag on matrix-org/matrix-spec).

### Sources
- `docs/reverse_proxy.md`: https://github.com/element-hq/synapse/blob/v1.162.0/docs/reverse_proxy.md (examples for nginx, NPM, Caddy, Apache, HAProxy, relayd and lighttpd).
- `docs/delegate.md`: https://github.com/element-hq/synapse/blob/v1.162.0/docs/delegate.md
- `docs/setup/installation.md`, "Client Well-Known URI": https://github.com/element-hq/synapse/blob/v1.162.0/docs/setup/installation.md#L514-L568
- `docs/usage/configuration/config_documentation.md` (`web_client_location` L208-L210, `public_baseurl` L217-L227, `serve_server_wellknown` L230-L244, `extra_well_known_client_content` L247-L256, `x_forwarded` L536).
- Synapse's code, read to see what Synapse answers by itself: `synapse/rest/well_known.py`, `synapse/http/server.py`, `synapse/config/server.py`, `synapse/app/homeserver.py`, `synapse/media/_base.py` and `synapse/rest/media/download_resource.py`, all at v1.162.0.
- Matrix spec, client-server API: https://github.com/matrix-org/matrix-spec/blob/v1.19/content/client-server-api/_index.md ("Web Browser Clients" L355-L383, "Well-known URIs" L418-L472); `data/api/client-server/support.yaml` L18-L36; server-server API `content/server-server-api.md` L118-L130.

### Directives that redirect, set a header or answer with a fixed body

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML or what is missing |
|---|---|---|---|---|
| [reverse_proxy.md L117-L120](https://github.com/element-hq/synapse/blob/v1.162.0/docs/reverse_proxy.md#L117-L120), NPM "Tab Advanced", `location /.well-known/matrix/server` | `return 200 '{"m.server": "matrix.example.com:443"}';` | Server delegation: federation reaches port 443 instead of 8448 (comment at L114-L115) | **NEEDS A CHANGE** | agensio cannot answer with a fixed body. **Smallest change:** a fixed answer for one exact path (status 200, a content type, a short body), for example a hypothetical `[[site.respond]] path = "/.well-known/matrix/server", match = "exact", content_type = "application/json", body = '{"m.server":"matrix.example.com:443"}'`. A narrower alternative is a per-exact-path MIME type, so that an extensionless file on disk is served as JSON. **Today:** (a) proxy `/.well-known/matrix/` to Synapse with `serve_server_wellknown: true` (see App guidance; only fits when `https://<server_name>/_matrix` also reaches Synapse); (b) a file on disk at `<root>/.well-known/matrix/server`. `/.well-known/` is exempt from `hidden_files` (alpha.70), but an extensionless file is served as `application/octet-stream` (`src/mime.hpp:9`). Whether homeservers accept that content type is **unverified**. |
| same block, L119 | `add_header Content-Type application/json;` | Mark the body as JSON | **NOT OFFERED ON PURPOSE** in `[[site.response_headers]]` (Content-Type is a refused name) | Belongs to the fixed-answer change above, or to the MIME of a `.json` file. Inferred: in nginx this adds a second `Content-Type` line beside the default `text/plain` (installation.md uses `default_type` instead). |
| L122-L126, NPM, `location /.well-known/matrix/client` | `return 200 '{"m.homeserver": {"base_url": "https://matrix.example.com"}}';` | Client discovery | **NEEDS A CHANGE** | Same as the server row. Today Synapse can serve this file itself when `public_baseurl` is set (with CORS). Proxy it with `[[site.location]] path = "/.well-known/matrix/"` and `upstream = "http://127.0.0.1:8008"`. |
| L124 | `add_header Content-Type application/json;` | as above | **NOT OFFERED ON PURPOSE** (refused name) | as above |
| L125 | `add_header "Access-Control-Allow-Origin" *;` | CORS so that browser clients can read the file (spec L430-L431) | **EXPRESSIBLE** | `[[site.response_headers]]` `path = "/.well-known/matrix"` `set = { "Access-Control-Allow-Origin" = "*" }` |
| [L147](https://github.com/element-hq/synapse/blob/v1.162.0/docs/reverse_proxy.md#L145-L151), Caddy delegation, site `example.com` | `header /.well-known/matrix/* Content-Type application/json` | JSON type for the `respond` bodies | **NOT OFFERED ON PURPOSE** (refused name) | Goes with the fixed-answer change |
| L148 | `header /.well-known/matrix/* Access-Control-Allow-Origin *` | CORS on both files | **EXPRESSIBLE** | as in the L125 row (the `/.well-known/matrix` prefix covers `server`, `client` and `support`) |
| L149 | ``respond /.well-known/matrix/server `{"m.server": "matrix.example.com:443"}` `` | server delegation | **NEEDS A CHANGE** | fixed answer, as in the first row |
| L150 | ``respond /.well-known/matrix/client `{"m.homeserver":{"base_url":"https://matrix.example.com"},"m.identity_server":{"base_url":"https://identity.example.com"}}` `` | client discovery with an identity server | **NEEDS A CHANGE** | fixed answer. Proxying to Synapse also covers it: Synapse adds `m.identity_server` from `default_identity_server` (well_known.py L51-L54). |
| [L259-L261](https://github.com/element-hq/synapse/blob/v1.162.0/docs/reverse_proxy.md#L250-L269), HAProxy `backend matrix-well-known-client` | `http-after-response set-header Access-Control-Allow-Origin "*"` / `http-after-response set-header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"` / `http-after-response set-header Access-Control-Allow-Headers "Origin, X-Requested-With, Content-Type, Accept, Authorization"` | CORS on the generated answer (`after-response` also reaches answers HAProxy generates itself) | **EXPRESSIBLE** | `[[site.response_headers]]` `path = "/.well-known/matrix"` `set = { "Access-Control-Allow-Origin" = "*", "Access-Control-Allow-Methods" = "GET, POST, PUT, DELETE, OPTIONS", "Access-Control-Allow-Headers" = "Origin, X-Requested-With, Content-Type, Accept, Authorization" }`. The design applies response headers to every answer of the site, including agensio's own. |
| L262 | `http-request return status 200 content-type application/json string '{"m.homeserver":{"base_url":"https://matrix.example.com"},"m.identity_server":{"base_url":"https://identity.example.com"}}'` | client discovery | **NEEDS A CHANGE** | fixed answer |
| L265-L267, `backend matrix-well-known-server` | the same three `http-after-response set-header` lines | CORS on server delegation (the spec does not require it for federation) | **EXPRESSIBLE** | covered by the same prefix rule |
| L268 | `http-request return status 200 content-type application/json string '{"m.server":"matrix.example.com:443"}'` | server delegation | **NEEDS A CHANGE** | fixed answer |
| [L283-L286](https://github.com/element-hq/synapse/blob/v1.162.0/docs/reverse_proxy.md#L283-L286), relayd | `match request path "/.well-known/matrix/*" tag "matrix-cors"` / `match response tagged "matrix-cors" header set "Access-Control-Allow-Origin" value "*"` | CORS; the comment says "httpd does not support setting headers, so do it here" (the files themselves come from httpd on disk) | **EXPRESSIBLE** | the prefix rule above. The files on disk carry the extensionless MIME caveat from the first row. |
| [L342-L347 and L350-L354](https://github.com/element-hq/synapse/blob/v1.162.0/docs/reverse_proxy.md#L342-L354), lighttpd on `0.0.0.0:80` and `[::]:80` | `url.redirect = ( "" => "https://${url.authority.noport}${url.path}${qsa}" )` | "redirect HTTP traffic to HTTPS" (L342) | **EXPRESSIBLE** | `http = "redirect"` (the default for a TLS site on 443; 308 rather than lighttpd's default status, which is **unverified**, path and query kept) |
| [L387-L390](https://github.com/element-hq/synapse/blob/v1.162.0/docs/reverse_proxy.md#L385-L397), lighttpd delegation | `url.rewrite-once = ( "^/\.well-known/matrix/client$" => "/.well-known/matrix/client.json", "^/\.well-known/matrix/server$" => "/.well-known/matrix/server.json" )` | internal rewrite, so static `.json` files get a JSON type | **NOT A RULE** (internal rewrite, not a redirect) | Nearest today: an exact `[[site.location]] path = "/.well-known/matrix/client"` with `try_files = ["/.well-known/matrix/client.json"]`. That is an internal redirect, routed again, so the `.json` file gets `application/json; charset=utf-8` from `mime.cpp:30`. **Unverified:** (1) whether a `try_files` with a single `/path` element behaves this way on an exact location; (2) on a proxy-preset site the `.json` path needs its own static location; (3) which path `[[site.response_headers]]` matches after the hop. The cleaner fix is the same fixed-answer or per-path MIME change. |
| L394 | `mimetype.assign = ( ".json" => "application/json" )` | JSON type | **NOT A RULE** | built-in MIME table (`json`) |
| L395 | `setenv.set-response-header = ( "Access-Control-Allow-Origin" => "*" )` | CORS | **EXPRESSIBLE** | the prefix rule above |
| [installation.md L554-L558](https://github.com/element-hq/synapse/blob/v1.162.0/docs/setup/installation.md#L551-L559), `location /.well-known/matrix/client` | `return 200 '{"m.homeserver": {"base_url": "https://<matrix.example.com>"}}';` | client discovery | **NEEDS A CHANGE** | fixed answer (or proxy to Synapse with `public_baseurl` set) |
| same, L556 | `default_type application/json;` | JSON type of the `return` body | **NEEDS A CHANGE** (it is part of the fixed answer) | content type of the fixed answer |
| same, L557 | `add_header Access-Control-Allow-Origin *;` | CORS: "To work in browser based clients, the file must be served with the appropriate CORS headers. A recommended value would be `Access-Control-Allow-Origin: *`" (L546-L549) | **EXPRESSIBLE** | the prefix rule above |

The plain nginx example in the reverse-proxy section (L61-L88) has no redirect, header or fixed-body directive.
Synapse's docs publish no nginx `return 301` for HTTPS and no HSTS.

### Other directives (existing agensio features)
- `proxy_pass http://localhost:8008;` with no URI part, and the note "do not add a path ... otherwise nginx will canonicalise the URI and cause signature verification errors" (L72-L76, also L28-L31 "must not canonicalise or normalise the requested URI", Apache `nocanon` and `AllowEncodedSlashes NoDecode` at L167-L172 and L186). In agensio this is `upstream = "http://127.0.0.1:8008"` with no URI part. agensio hands the raw target to a proxied application, and the `%2F` refusal applies only to filesystem-backed locations (CLAUDE.md, "Request target"). Worth a live test with Synapse's signed federation requests (**unverified**).
- `location ~ ^(/_matrix|/_synapse/client)` is a regex location. In agensio it becomes two prefix `[[site.location]]` blocks (`/_matrix`, `/_synapse/client`) with `upstream`, or `app = "proxy"` for the whole host.
- `proxy_set_header X-Forwarded-For $remote_addr;` and `X-Forwarded-Proto $scheme;` (L77-L78), Apache `RequestHeader set "X-Forwarded-Proto"` (L166, L179), and HAProxy `http-request set-header X-Forwarded-Proto/For` (L203-L205, L216-L218, L234-L236): agensio sends X-Forwarded-For and X-Forwarded-Proto by default.
- `proxy_set_header Host $host:$server_port;` (L79): `proxy = { host = "pass" }` (the default) passes the client's Host. If the explicit port really matters, `proxy = { headers = { "Host" = "$host:$server_port" } }` (headers may replace agensio's own Host line, configuration.md L1429).
- `client_max_body_size 50M;` (L83): a site's `max_body_size = "50MB"`.
- `proxy_http_version 1.1;` (L86): agensio talks HTTP/1.1 to origins.
- `listen 8448 ssl default_server;` (L67-L68), Caddy `example.com:8448` (L138-L140), HAProxy `frontend matrix-federation` (L214-L220): the site's `listen` gains `"0.0.0.0:8448"` with TLS.
- Apache `ProxyPreserveHost on` and `ProxyPassReverse` (L168-L172, NOTE 3 at L196): `proxy.host = "pass"` and `proxy.redirects = "rewrite"`.
- HAProxy routing by Host plus path and by SNI (L208-L212, L238-L244): routing by Host and location.
- lighttpd `proxy.forwarded = ("for"=>1,"proto"=>1,"host"=>1)` (L371-L375): `proxy.forwarded` (`"both"` for RFC 7239 plus X-Forwarded-*).
- lighttpd `$HTTP["remoteip"] !="fd00::/8" { $HTTP["url"] =~ "^/_synapse/admin/" { url.access-deny = ( "" ) } }` (L377-L382): `[[site.access]] path = "/_synapse/admin"` with `allow = ["fd00::/8"]` (403). Synapse also recommends not exposing `/_synapse/admin` publicly (L406-L411).
- Apache `SecRuleEngine off` (L188-L194): there is no ModSecurity in agensio.
- `docs/workers.md` L371-L400 shows an nginx `map` that picks a worker upstream by `$arg_since` and by the access-token localpart (hash routing). That is upstream selection, not a redirect or header rule; agensio groups are round-robin only.
- `/health` exists on every listener (L400-L404).

### App guidance (Synapse and the Matrix spec)
- **.well-known served by Synapse itself.** The client listener mounts `/.well-known` (`homeserver.py` L191-L198, `"/.well-known": well_known_resource(self)`).
  - `/.well-known/matrix/client` is served only when `public_baseurl` is set explicitly (`config/server.py` L454-L461; config doc L249). It is JSON with **CORS from Synapse**: `DirectServeJsonResource._send_response` uses `send_cors=True` (`http/server.py` L433-L447), and `set_cors_headers` sends `Access-Control-Allow-Origin: *`, `-Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS`, `-Allow-Headers: X-Requested-With, Content-Type, Authorization, Date` and `-Expose-Headers` (L1021-L1052).
  - `/.well-known/matrix/server` is served only with `serve_server_wellknown: true`, with `Content-Type: application/json` and **no CORS** (`well_known.py` L93-L120). Its value is always `<server_name host>:443` (or the explicit port), so it fits only when `https://<server_name>` itself routes to Synapse (delegate.md L54-L68, "generally not suitable if Synapse is hosted at a subdomain").
  - Synapse does **not** serve `/.well-known/matrix/support`: `well_known.py` L123-L132 mounts only `server` and `client`.
  - So in agensio the delegation files are either proxied (`[[site.location]] path = "/.well-known/matrix/"` with `upstream = "http://127.0.0.1:8008"`, adequate for client and, in the same-host case, server) or need the fixed-answer change. For a typical setup (server_name `example.com` on a website and Synapse on `matrix.example.com`), `server` and `support` need the change.
- **Spec on CORS.** "Servers hosting the `.well-known` JSON file SHOULD offer CORS headers, as per the CORS section" (client-server `_index.md` L430-L431). The recommended values are `Access-Control-Allow-Origin: *`, `-Methods: GET, POST, PUT, DELETE, OPTIONS` and `-Headers: X-Requested-With, Content-Type, Authorization` (L368-L374). This is a fixed `*`, which the design allows; no Origin echo is needed.
- **Spec on `/.well-known/matrix/support`** (added in v1.10, `support.yaml` L19-L36): "Like the well-known discovery URI, this endpoint should be accessed with the hostname of the homeserver's server name ... Note that this endpoint is not necessarily handled by the homeserver. It may be served by another webserver." I read the CORS note at L430-L431 as applying to it too, since it sits in the same "Well-known URIs" section (my inference).
- **Spec on server well-known caching and redirects** (`server-server-api.md` L118-L130): "30x redirects should be followed, however redirection loops should be avoided." Responses "should be cached by the requesting server ... respect the cache control headers ... sensible default is 24 hours ... maximum ... 48 hours". An optional `[[site.response_headers]] path = "/.well-known/matrix/server", match = "exact", set = { "Cache-Control" = "max-age=86400" }, when = "success"` is EXPRESSIBLE, but no official config sets it.
- **Root redirect is Synapse's own.** `/` redirects to `web_client_location` or to the static "Synapse is running" page (`homeserver.py` L144-L156; config doc L208-L210). The proxy configs forward only `/_matrix` and `/_synapse/client`, so it never shows. No agensio redirect is needed.
- **Headers Synapse sets itself.** HTML: `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none';` (`http/server.py` L1106-L1118). Media downloads: `Content-Security-Policy: sandbox; default-src 'none'; script-src 'none'; plugin-types application/pdf; style-src 'unsafe-inline'; media-src 'self'; object-src 'self';`, `X-Content-Security-Policy: sandbox;` and `Referrer-Policy: no-referrer` (`download_resource.py` L65-L79), plus `Cache-Control: public,max-age=86400,s-maxage=0,proxy-revalidate` and `X-Robots-Tag` (`media/_base.py` L235, L248-L250).
  - A site-wide `set` of CSP or `Referrer-Policy` on a Synapse site would replace these media policies. agensio's baseline `Referrer-Policy` is a `default`, so Synapse's `no-referrer` is kept.
  - Media sends `public, s-maxage=0, proxy-revalidate` deliberately. CLAUDE.md says `core/private_cache.hpp` drops `public`, `s-maxage` and `proxy-revalidate` only on `[[site.auth]]`-protected answers, so this is not an issue unless `[[site.auth]]` covers `/_matrix`.
- **HSTS**: none of Synapse's docs recommends one (grep of reverse_proxy.md, delegate.md and installation.md). No CSP or X-Frame-Options is recommended for the proxy.
- **Trusting the proxy**: `x_forwarded: true` on the listener (reverse_proxy.md L44-L48; config doc L536). It defaults to true on Unix sockets (L554), and docs recommend `bind_addresses: ['127.0.0.1']`. Synapse has no trusted-proxy list; it trusts whoever can reach the listener.
- **WebFinger, openid-configuration, change-password**: none appear in Synapse's proxy docs. OIDC discovery is configured toward an upstream IdP; it is not served by the proxy.

---

## 12. Element Web

### Version read
- **v1.12.30** (published 2026-09-29). Tag object `126f0463ccc5411bc23cdd49ed2e3d35a8843a6d`, commit **`f19cfd9030429240a4209bf5175b372175cf0464`**. The repository is now a monorepo (`apps/web`, `apps/desktop`).

### Sources
- `apps/web/README.md`, "Important Security Notes" and "Caching requirements": https://github.com/element-hq/element-web/blob/v1.12.30/apps/web/README.md (`docs/install.md` L3 and L14 point there).
- `apps/web/docker/nginx-templates/default.conf.template` (the official Docker image's nginx config; `apps/web/Dockerfile` L43-L45 copies it).
- `docs/kubernetes.md` L151-L176 (ingress annotation), `docs/custom-home.md` L59-L63, `docs/install.md`, `docs/config.md` L11-L12, `docs/usercontent.md`.
- `apps/web/src/vector/index.html` L20-L33 (meta CSP) and `apps/web/webpack.config.ts` (`sw.js` at L122-L124; hashed bundles at L574 and L720).

### Directives that redirect, set a header or answer with a fixed body

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML or what is missing |
|---|---|---|---|---|
| [README.md L38](https://github.com/element-hq/element-web/blob/v1.12.30/apps/web/README.md#L35-L55), nginx snippet (server-level) | `add_header X-Frame-Options SAMEORIGIN;` | "to prevent Element Web from being framed and protect from clickjacking" (L20-L21) | **EXPRESSIBLE** | `[[site.response_headers]]` `path = "/"` `set = { "X-Frame-Options" = "SAMEORIGIN" }`. Use SAMEORIGIN, not DENY: Element iframes its own `usercontent/` (usercontent.md L27) and `jitsi.html` (webpack L598) from the same origin. Inferred: DENY would break those. |
| L39 | `add_header X-Content-Type-Options nosniff;` | "to disable MIME sniffing" (L26-L27) | **EXPRESSIBLE** | With `app = "static"` the baseline already sends nosniff on every file agensio serves. Otherwise add `"X-Content-Type-Options" = "nosniff"` to the same `set`. |
| L40 | `add_header X-XSS-Protection "1; mode=block";` | "basic XSS protection in legacy browsers" (L28-L29) | **EXPRESSIBLE** | `"X-XSS-Protection" = "1; mode=block"` in the same `set` |
| L41 | `add_header Content-Security-Policy "frame-ancestors 'self'";` | "the modern replacement for X-Frame-Options (though both should be included)" (L22-L25). Note at L53-L55: "In case you are already setting a `Content-Security-Policy` header elsewhere, you should modify it to include the `frame-ancestors` directive instead of adding that last line." | **EXPRESSIBLE** | `"Content-Security-Policy" = "frame-ancestors 'self'"` in the same `set`. Element's real CSP is a `<meta http-equiv>` in `index.html` L20-L33, and `frame-ancestors` cannot be delivered by meta (inferred from the CSP spec), hence the header. The design has no "append to a list field", but none is needed: Element sends no CSP header. |
| L47-L50, Apache | `Header set X-Frame-Options SAMEORIGIN` / `Header set X-Content-Type-Options nosniff` / `Header set X-XSS-Protection "1; mode=block"` / `Header set Content-Security-Policy "frame-ancestors 'self'"` | same | **EXPRESSIBLE** | same `set` (Apache `Header set` matches agensio `set`) |
| [kubernetes.md L160-L164](https://github.com/element-hq/element-web/blob/v1.12.30/docs/kubernetes.md#L151-L176), ingress `nginx.ingress.kubernetes.io/configuration-snippet` | the same four `add_header` lines | same | **EXPRESSIBLE** | same |
| [default.conf.template L13-L15](https://github.com/element-hq/element-web/blob/v1.12.30/apps/web/docker/nginx-templates/default.conf.template#L9-L27), `location = /index.html` | `add_header Cache-Control "no-cache";` | "Set no-cache for the version, config, i18n, and index.html so that browsers always check for a new copy of Element Web. NB http://your-domain/ and http://your-domain/? are also covered by this" (L9-L11). README L99-L111 requires `/config.*.json`, `/i18n`, `/version` and `/index.html` not to be cached, and recommends `Cache-Control: no-cache` for `/`. | **EXPRESSIBLE** | `[[site.response_headers]] path = "/index.html", match = "exact", set = { "Cache-Control" = "no-cache" }` **plus** `[[site.response_headers]] path = "/", match = "exact", set = { "Cache-Control" = "no-cache" }`. In nginx, `/` reaches this location through the internal `index` redirect; agensio rules match the request path, so `/` needs its own exact rule. `no-cache` grants no freshness, so `when = "always"` (the default) is allowed. |
| L16-L18, `location = /version` | `add_header Cache-Control "no-cache";` | same | **EXPRESSIBLE** | `path = "/version", match = "exact", set = { "Cache-Control" = "no-cache" }` |
| L19-L21, `location /i18n/` | `add_header Cache-Control "no-cache";` | same | **EXPRESSIBLE** | `path = "/i18n", set = { "Cache-Control" = "no-cache" }` (prefix, whole segments) |
| L23-L27, `location /config` | `root /tmp/element-web-config;` and `add_header Cache-Control "no-cache";` | "covers config.json and config.hostname.json requests as it is prefix" (L23) | **EXPRESSIBLE, one exact rule per file** | nginx's `/config` is a character prefix; agensio prefixes cover whole segments only, so `/config` would not match `/config.json`. Element loads `config.$domain.json`, then `config.json` (config.md L11-L12), so write `path = "/config.json", match = "exact"` and one `path = "/config.<server name>.json", match = "exact"` per name of the site, each with `set = { "Cache-Control" = "no-cache" }`. Expressible because the domains are the site's own names. A site with many names needs one rule each; a character-prefix or glob path would remove that, a possible small NEEDS A CHANGE. The `root` override is the same story: exact `[[site.location]]`s with `root = "/tmp/element-web-config"`. |
| [custom-home.md L59-L63](https://github.com/element-hq/element-web/blob/v1.12.30/docs/custom-home.md#L59-L63) | `add_header Access-Control-Allow-Origin *;` | "may be needed to set CORS headers for the `home.html` to enable element-desktop to fetch it" | **EXPRESSIBLE** | `[[site.response_headers]] path = "/home.html", match = "exact", set = { "Access-Control-Allow-Origin" = "*" }` (on whichever site serves home.html) |

### Other directives (existing agensio features)
- `root /usr/share/nginx/html; index index.html;` (template L6-L7): a static site (`app = "static"`, `root`, `index`).
- `location /modules { alias /modules; }` (L28-L30): `[[site.location]] path = "/modules/"`, `alias = "/modules/"` (alias needs a prefix ending in `/`).
- `error_page 500 502 503 504 /50x.html;` (L33): agensio's own error pages; not a header or redirect rule.
- `docs/install.md` L36: "point your chosen web server ... at the `/usr/share/element-web` webroot", which is `root`.
- No redirect appears anywhere in Element's official configs, and nothing serves `.well-known` (that belongs to the homeserver's domain).

### App guidance (Element Web)
- **Separate domain**: "We do not recommend running Element from the same domain name as your Matrix homeserver" (README L3-L13). So `X-Frame-Options`/CSP rules for Element must not land on a Synapse site's `/_matrix` (Synapse sets `DENY` on its own HTML).
- **CSP the app expects from the proxy**: only `frame-ancestors 'self'`. The rest of the CSP is in the page's meta tag (`index.html` L20-L33: `default-src 'none'; style-src 'self' 'unsafe-inline' ...; script-src 'self' 'wasm-unsafe-eval' https://www.recaptcha.net/recaptcha/ https://www.gstatic.com/recaptcha/ ...; img-src * blob: data:; connect-src * blob:; ... frame-src * blob: data:; ...`). A stricter header CSP would intersect with the meta CSP and could break Element (inferred).
- **X-Frame-Options**: SAMEORIGIN (not DENY), for its same-origin iframes (inferred, see above).
- **Caching**: no-cache on `/`, `/index.html`, `/version`, `/i18n/`, `/config*.json` (README L97-L111, template L9-L27).
  - Long caching of the hashed `bundles/<fullhash>/...` (webpack L574, L720) is **not** in the official guidance, and neither is anything for the unhashed `/sw.js` service worker at the web root (webpack L122-L124).
  - If someone wants the long cache it is EXPRESSIBLE: `[[site.response_headers]] path = "/bundles", set = { "Cache-Control" = "public, max-age=31536000, immutable" }, when = "success"`.
- **HSTS**: not mentioned. Only "serve Element over HTTPS" (install.md L5-L7).
- **CORS**: only for `home.html` (fixed `*`).
- **Trusting a proxy**: not applicable (static files).

---

## 13. Keycloak

### Version read
- **26.8.0** (published 2026-10-01). Lightweight tag at commit **`4246609cf2024c85016d3fb1254c3d2533367c31`**.

### Sources
- `docs/guides/server/reverseproxy.adoc` (the source of keycloak.org/server/reverseproxy): https://github.com/keycloak/keycloak/blob/26.8.0/docs/guides/server/reverseproxy.adoc
- Blueprints: `docs/guides/server/haproxy-reencrypt.adoc`, `traefik-reencrypt.adoc`, `haproxy-passthrough.adoc` and `traefik-passthrough.adoc` at 26.8.0. The Compose quickstarts they link to (keycloak/keycloak-quickstarts, `proxy/haproxy/reencrypt` and `proxy/traefik/reencrypt`) were **not read**.
- `docs/guides/server/hostname.adoc`, `docs/documentation/server_admin/topics/threat/clickjacking.adoc`, `server-spi-private/.../BrowserSecurityHeaders.java`, `ContentSecurityPolicyBuilder.java` and `services/.../resources/WelcomeResource.java` (to see what Keycloak sends itself).

### Directives that redirect, set a header or answer with a fixed body

**None.** No official Keycloak proxy configuration at 26.8.0 contains a redirect, a response-header directive or a fixed-body answer. The HAProxy and Traefik blueprints contain only request-header removal, path and address filtering, health checks and TLS. The passthrough blueprints are TCP/SNI only. The one redirect involved is Keycloak's own: `/` redirects to `/admin/` with 302 when the welcome theme has `redirectToAdmin` and an admin exists (`WelcomeResource.java` L211-L216). The blueprints mention it: "With these settings, the redirect to the welcome screen or Admin UI will not work from external IP addresses, and this is expected." (haproxy-reencrypt.adoc L72, traefik-reencrypt.adoc L183).

### Other directives (existing agensio features)
- **Exposed path table** (reverseproxy.adoc L280-L343): `/realms/`, `/resources/`, `/.well-known/` and `/lb-check` are exposed. `/`, `/admin/`, `/metrics` and `/health` are not, and `/realms/master/` is "Only internally" (L304-L307, L345-L353).
  - Blueprints: HAProxy `acl is_public_path path_beg /realms/` ... `http-request deny unless is_public_path or is_allowed_src` (haproxy-reencrypt.adoc L73-L83); Traefik routers `PathPrefix(`/realms/`) || PathPrefix(`/resources/`) || PathPrefix(`/.well-known/`)` plus an `ipAllowList` on everything else (traefik-reencrypt.adoc L118-L150); master realm `acl is_master_realm path /realms/master` / `path_beg /realms/master/` / `http-request deny if is_master_realm !is_allowed_src` (haproxy-reencrypt.adoc L241-L247).
  - **NOT A RULE** in agensio terms; it is `[[site.access]]` (403):

    ```toml
    [[site.access]]
    path = "/"
    allow = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
    [[site.access]]
    path = "/realms"
    allow = ["any"]
    [[site.access]]
    path = "/resources"
    allow = ["any"]
    [[site.access]]
    path = "/.well-known"
    allow = ["any"]
    [[site.access]]
    path = "/realms/master"
    allow = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
    ```

    The longest rule decides, so `/realms/master` beats `/realms`. That gives the same result as HAProxy's ordered rules.
- **Request-header filtering** (reverseproxy.adoc L208-L278): overwrite `Forwarded` and `X-Forwarded-*`; strip `X-Original-Forwarded-For`, `X-Real-IP`, `X-Original-URL`, `X-Original-Method`, `X-Forwarded-Access-Token`, `traceparent`, `tracestate`, `baggage`, `b3`, `x-b3-*`, `uber-trace-id` and `x-ot-span-context`. Blueprints: HAProxy `http-request del-header ...` (haproxy-reencrypt.adoc L44-L65) and Traefik `customRequestHeaders: { Forwarded: "" ... }` (traefik-reencrypt.adoc L78-L111).
  - **NOT A RULE**: `proxy = { headers = { "X-Original-Forwarded-For" = "", "X-Real-IP" = "", "X-Original-URL" = "", "X-Original-Method" = "", "X-Forwarded-Access-Token" = "", "traceparent" = "", "tracestate" = "", "baggage" = "", "b3" = "", "X-B3-TraceId" = "", "X-B3-SpanId" = "", "X-B3-ParentSpanId" = "", "X-B3-Sampled" = "", "X-B3-Flags" = "", "uber-trace-id" = "", "x-ot-span-context" = "" } }`.
  - agensio replaces X-Forwarded-* from untrusted peers (the "overwrite" the guide asks for). Whether it removes a client-sent `Forwarded` when `forwarded = "x-forwarded"` is **unverified**; `headers = { "Forwarded" = "" }` covers it.
  - There is no regex removal (`x-b3-.*`); each name must be listed, as the Traefik blueprint notes (L175).
- **Client certificate forwarding** (L381-L562; HAProxy `http-request set-header Client-Cert %[ssl_c_der,base64] if ...`, L68-L69): agensio has no client-certificate forwarding; out of scope.
- **Sub-path**: "Configure a reverse proxy to map the `/.well-known/` path without the prefix to the path with the prefix on the server" when `http-relative-path` is set (L339). In agensio this is `[[site.location]] path = "/.well-known/"`, `upstream = "http://127.0.0.1:8080/auth/.well-known/"` (a location upstream with a URI part). It is a path mapping, not a redirect. Other sub-path options: `X-Forwarded-Prefix` or a full `--hostname` URL (L355-L364).
- Health checks against the management port 9000, `balance roundrobin`, `slowstart`, timeouts `connect 5s / client 50s / server 50s` (haproxy-reencrypt.adoc L35-L37): agensio groups, `proxy` timeouts. Port 9000 should not be proxied (reverseproxy.adoc L130-L133).
- TLS re-encrypt with mTLS to the backend (`ssl verify required crt ... ca-file ...`): `proxy = { tls = { verify, server_name, ca } }`. A client certificate toward the origin is **unverified** (not in the summary).
- PROXY protocol for passthrough: agensio does not offer it (TCP passthrough is out of scope).

### App guidance (Keycloak)
- **Trusting the proxy**: `--proxy-headers xforwarded` (or `forwarded`) and `--proxy-trusted-addresses=127.0.0.1` (L175-L206). "If you ... do not set the `proxy-headers` option, then by default you will see 403 Forbidden responses to requests via the proxy that perform origin checking" (L182). `--hostname=https://kc.example.com` (a full URL) removes any reliance on `X-Forwarded-Host`, `X-Forwarded-Port` or `X-Forwarded-Prefix` (L360-L361; hostname.adoc). agensio sends X-Forwarded-Host only when it rewrote Host; whether it sends `X-Forwarded-Port` is **unverified**.
- **Security headers Keycloak sets itself**, per realm under "Security Defenses" (`BrowserSecurityHeaders.java` L27-L33; clickjacking.adoc L6-L19):
  - `X-Frame-Options: SAMEORIGIN`
  - `Content-Security-Policy: frame-src 'self'; frame-ancestors 'self'; object-src 'none';` (`ContentSecurityPolicyBuilder.java` L37-L39)
  - `X-Content-Type-Options: nosniff`
  - `X-Robots-Tag: none`
  - **`Strict-Transport-Security: max-age=31536000; includeSubDomains`**
  - `Referrer-Policy: no-referrer`

  The docs ask the proxy for none of these.
- **Consequence for the design.** agensio's `hsts` *replaces* an application's HSTS.
  - `hsts = true` on a Keycloak site would *drop* Keycloak's `includeSubDomains`. To keep parity, either leave `hsts` unset (Keycloak sends its own on its answers, but not on agensio's own errors or redirects) or write `hsts = { max_age = "1y", subdomains = true }`.
  - Any site-wide `set` of CSP or X-Frame-Options would override the realm's per-realm settings (for example a realm that allows embedding via `frame-ancestors`). Do not set them.
  - The baseline `Referrer-Policy` default leaves Keycloak's `no-referrer` alone.
- **.well-known**: `/realms/{realm}/.well-known/openid-configuration` (hostname.adoc L110) is under `/realms/` and served by Keycloak. The root `/.well-known/` is for RFC 8414 discovery (L314-L317, L339). Both are proxied, with no fixed answers. No WebFinger and no change-password.
- **CORS**: none at the proxy (Keycloak manages Web Origins per client; that is my inference, not read in docs).

---

## 14. Vaultwarden

### Version read
- Application **1.37.4** (published 2026-10-05). Tag object `54a40806c990da2def7acd5a3152edc530c59b79`, commit **`7c188967e7a467b19b2757bc3326f9cf3ccae327`**.
- Wiki repository `dani-garcia/vaultwarden.wiki.git` at commit **`8216c0f929b83dbf8fff3621ace691252a7da78a`** (2026-10-07 13:48 +0200).
- **The wiki is community-maintained but published by the project** under its own GitHub wiki. Proxy-examples.md L1 itself says "Below is a user-curated list of example configurations", and several examples carry contributors' names. None of it is versioned with the release.

### Sources
- Wiki "Proxy examples": https://github.com/dani-garcia/vaultwarden/wiki/Proxy-examples (raw: https://raw.githubusercontent.com/wiki/dani-garcia/vaultwarden/Proxy-examples.md). Line numbers are from the wiki clone at 8216c0f; the revision URL is https://github.com/dani-garcia/vaultwarden/wiki/Proxy-examples/8216c0f929b83dbf8fff3621ace691252a7da78a. The same pattern applies to "Hardening-Guide", "Using-an-alternate-base-dir" and "Enabling-HTTPS" (no redirect or header directives in the last).
- Code at 1.37.4: `src/util.rs` (AppHeaders and the Cors fairing), `src/api/web.rs`, `.env.template`.

### Directives that redirect, set a header or answer with a fixed body

| location / line (Proxy-examples.md @8216c0f unless noted) | directive (verbatim) | purpose | proposed class | agensio TOML or what is missing |
|---|---|---|---|---|
| L36-L42, Caddy 2.x, snippet `(admin_redir)` (commented out; enabled by `# import admin_redir` at L86-L87) | `@admin { path /admin* ; not remote_ip private_ranges }` then `redir @admin /` | "allow access to the admin interface only from local networks" (L26, L86) | **NOT OFFERED ON PURPOSE** (a redirect conditioned on the client address) | The design has no client-address condition on redirects. The *purpose* is met by `[[site.access]] path = "/admin"`, `allow = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "127.0.0.0/8", "::1"]`, which answers 403 instead of redirecting to `/`. Vaultwarden works. Caddy's `/admin*` is a character prefix (it also matches `/administrator`); agensio's prefix is whole segments. |
| L67-L84, Caddy `header / { ... }` (commented: "Uncomment to improve security (WARNING: only use if you understand the implications!)") | `Strict-Transport-Security "max-age=31536000;"` | "Enable HTTP Strict Transport Security (HSTS)" | **EXPRESSIBLE** | `hsts = true` (max-age=31536000, no subdomains, no preload) |
| same block | `X-XSS-Protection "0"` | "Disable cross-site filter (XSS)" | **EXPRESSIBLE** (redundant) | `[[site.response_headers]] path = "/", set = { "X-XSS-Protection" = "0" }`. Vaultwarden already sends it (`util.rs` L67). |
| same block | `X-Frame-Options "DENY"` | "Disallow the site to be rendered within a frame (clickjacking protection)". The block's own comment (L66): "If you want to use FIDO2 WebAuthn, set X-Frame-Options to "SAMEORIGIN" or the Browser will block those requests" | **EXPRESSIBLE, but harmful here** | Vaultwarden sets `X-Frame-Options: SAMEORIGIN` itself and **removes** it on `*connector.html` for WebAuthn and Duo (`util.rs` L79-L85, L140). Both `set` and `default` on `/` would put a frame field back on the connector pages (`default` because they carry none), which would break MFA. Recommendation: no frame rule on Vaultwarden. If one is wanted anyway, add exact rules with `remove = ["X-Frame-Options"]` for each connector page; the exact connector file names are **unverified**. |
| same block | `X-Robots-Tag "noindex, nofollow"` | "Prevent search engines from indexing (optional)" | **EXPRESSIBLE** (redundant) | `set = { "X-Robots-Tag" = "noindex, nofollow" }`. Vaultwarden sends it (`util.rs` L64). |
| same block | `X-Content-Type-Options "nosniff"` | "Disallow sniffing" | **EXPRESSIBLE** (redundant) | `set = { "X-Content-Type-Options" = "nosniff" }`. Vaultwarden sends it (`util.rs` L63). |
| same block | `-Server` | "Server name removing" | **NOT OFFERED ON PURPOSE** (`Server` is a refused name; it is agensio's own) | `proxy = { hide = ["Server"] }` may drop the origin's copy, but agensio's own `Server` stays (**unverified** what agensio does with an origin's `Server`). The app works. |
| same block | `-X-Powered-By` | "better opsec to remove" | **EXPRESSIBLE** | The preset baseline removes `X-Powered-By` from application answers (`app` set), or `remove = ["X-Powered-By"]`. Vaultwarden does not appear to send it (inferred). |
| same block | `-Last-Modified` | "Remove Last-Modified because etag is the same and is as effective" | **NOT OFFERED ON PURPOSE** (`Last-Modified` is refused: validators belong to the file layer) | The app works. |
| (scope note on the block above) | `header / {` | | | Per Caddy's own docs, "Path matching is an exact match by default, not a prefix match. You must append a `*` for a fast prefix match" (https://caddyserver.com/docs/caddyfile/matchers, "Path matchers", fetched 2026-10-12). As written, the block therefore applies only to the exact path `/`, although the comments read as site-wide. agensio `hsts` is site-wide by design. |
| L90-L97, Caddy (commented) | `@not_allowed_admin { path /admin* ; not client_ip xx.xx.xx.xx/32 xx.xx.xx.xx/32 }` and `respond @not_allowed_admin "401 - {http.request.header.Cf-Connecting-Ip} is not an allowed IP." 401` | allow `/admin` only from given forwarded IPs (Cloudflare) | **NOT A RULE** | `[[site.access]] path = "/admin"`, `allow = [...]` with `[server] trusted_proxies` set to Cloudflare's ranges (403 naming the tested address). A fixed body with a request-header placeholder is not offered (no variables). |
| L135-L141, lighttpd sub-path, port 80, `$HTTP["host"] =~ "vaultwarden.example.tld"` | `url.redirect = ( "^/(.*)" => "https://shared.example.tld/$1" )` | redirect plain HTTP on the old name to HTTPS on the shared host, keeping the path | **EXPRESSIBLE** | A plain-HTTP site for the old name: `[[site]] server_name = ["vaultwarden.example.tld"]`, `listen = ["0.0.0.0:80"]`, with `[[site.redirect]] from = "/"`, `to = "https://shared.example.tld/"`, `remainder = "keep"`, `query = "keep"`, `status = 301`. The `(.*)` capture is the whole path, which `remainder = "keep"` covers. **Unverified:** whether a site that only redirects needs a `root`. |
| L149-L153, lighttpd `proxy.header` | `"https-remap" => "enable"` | lighttpd remaps `http://` URLs in response fields to `https://` when the client used https (**unverified** semantics; lighttpd docs not read) | **EXPRESSIBLE (Location part)** | agensio upgrades an application's `Location: http://<site name>/...` on a site that redirects plain HTTP (design 2.5), and `proxy = { redirects = "rewrite" }` covers the origin's own address. Set-Cookie rewriting is not offered (cookie editing is out of the design); Vaultwarden needs neither if `DOMAIN` is https. |
| L184-L191, nginx (BlackDex), `server { listen 80; ... }` | `return 301 https://$host$request_uri;` | "Redirect HTTP to HTTPS" | **EXPRESSIBLE** | `http = "redirect"` (default for a TLS site on 443; 308 instead of 301, path and query kept) |
| L204, nginx 443 server (commented) | `#add_header Strict-Transport-Security "max-age=31536000;";` | HSTS (no `always`, so not on errors) | **EXPRESSIBLE** | `hsts = true` (sent on every HTTPS answer, errors included) |
| L281-L289, nginx sub-path, port 80, `location /vault/` | `return 301 https://$host$request_uri;` | HTTPS only for the Vaultwarden sub-path; the rest of the domain stays plain | **EXPRESSIBLE** (via a separate plain-HTTP `[[site]]`) | A port-80 `[[site]]` for `shared.example.tld` that serves the rest of the domain over plain HTTP (its root or upstream) and adds `[[site.redirect]] from = "/vault"`, `to = "https://shared.example.tld/vault"`, `remainder = "keep"`, `query = "keep"`, `status = 301`. This must live on a plain-only site (a rule on the TLS site would loop); the design allows separate sites per listener (redirects.md §10.1 shows the port-80 and port-443 sites). `to` must be a fixed host, unlike nginx's `$host`. |
| L291-L294, same server | `return 301 https://$host$request_uri;` | "If you want to enforce HTTPS for the entire domain anyway" | **EXPRESSIBLE** | `http = "redirect"` |
| L308, nginx sub-path (commented) | `#add_header Strict-Transport-Security "max-age=31536000;";` | HSTS | **EXPRESSIBLE** | `hsts = true` (site-wide; HSTS is per host and cannot be per path) |
| L440-L447, nginx with proxy_protocol | `return 301 https://$host$request_uri;` | HTTPS redirect | **EXPRESSIBLE** | `http = "redirect"`. Accepting the PROXY protocol on the listener is a different matter; agensio support is **unverified**/absent. |
| L561-L578, Traefik v2 labels | `traefik.http.middlewares.redirect-https.redirectScheme.scheme=https` / `traefik.http.middlewares.redirect-https.redirectScheme.permanent=true` (attached to the `web` router at L577) | HTTP to HTTPS, permanent | **EXPRESSIBLE** | `http = "redirect"` (Traefik's exact status for permanent is **unverified**) |
| L380, NixOS | `forceSSL = true;` | redirect HTTP to HTTPS (the NixOS module renders a 301 server; inferred) | **EXPRESSIBLE** | `http = "redirect"` |
| L666-L667, Istio Gateway | `tls: httpsRedirect: true` | HTTP to HTTPS | **EXPRESSIBLE** | `http = "redirect"` |
| L776-L784, Pound `ListenHTTP` | `Redirect 301 "https://vaultwarden.example.tld"` | HTTP to HTTPS (whether Pound appends the request path is **unverified**) | **EXPRESSIBLE** | `http = "redirect"` |
| L756-L758, Cloudflare tunnel `ingress` | `- hostname: vaultwarden.example.tld` / `service: http_status:404` / `path: admin` | answer 404 for the admin page at the edge | **NOT A RULE** | `refuse = ["/admin"]` or `[[site.location]] path = "/admin"`, `handler = "deny"` (404). cloudflared's `path` is a regular expression, so `admin` matches anywhere in the path (**unverified**); agensio anchors. |
| Hardening-Guide.md L98-L109, Caddy | `handle /* { abort }` (after `reverse_proxy /my-custom-path/* ...`) | drop every connection except the secret sub-path | **NOT A RULE** | `handler = "deny"` on `/` (404, not an abort) with a proxy location for the sub-path. agensio has no connection abort. |

### Other directives (existing agensio features)
- `client_max_body_size 525M;` (L206, L310, L460): a site's `max_body_size = "525MB"`.
- WebSocket: `map $http_upgrade $connection_upgrade {...}`, `proxy_set_header Upgrade/Connection` (L175-L182, L208-L210), Apache `ProxyPass / http://127.0.0.1:8000/ upgrade=websocket` (L503, L540), lighttpd `"upgrade" => "enable"`, NixOS `proxyWebsockets = true`. agensio upgrades automatically (`/notifications/hub`).
- `proxy_set_header Host $host; X-Real-IP $remote_addr; X-Forwarded-For $proxy_add_x_forwarded_for; X-Forwarded-Proto $scheme;` (L212-L218), Caddy `header_up X-Real-IP {remote_host}` (L105), Apache `RequestHeader set X-Real-IP %{REMOTE_ADDR}s` (L507, L542) and `# RequestHeader add X-Forwarded-Proto https` (L509), HAProxy `option forwardfor` + `http-request set-header X-Real-IP %[src]` (L600-L602).
  - agensio passes Host and sends X-Forwarded-For and X-Forwarded-Proto.
  - `X-Real-IP` is not sent by default: add `proxy = { headers = { "X-Real-IP" = "$remote_addr" } }`, or set Vaultwarden `IP_HEADER=X-Forwarded-For` (L157 says the same for lighttpd).
- `upstream vaultwarden-default { keepalive 2; }` and `proxy_http_version 1.1` (L169-L173): agensio keeps upstream connections when the origin allows.
- Timeouts `proxy_connect_timeout 777; proxy_send_timeout 777; proxy_read_timeout 777; send_timeout 777;` (L237-L244): `proxy = { connect_timeout = 777, send_timeout = 777, read_timeout = 777 }`. nginx `send_timeout` (to the client) has no exact agensio equivalent (`idle_timeout` is server-wide).
- `location /vault/ { proxy_pass http://vaultwarden-default; }` (sub-path, the path passed through unchanged, L316-L326): `[[site.location]] path = "/vault/"`, `upstream = "http://127.0.0.1:8000"` (no URI part, so the path stays). Vaultwarden requires `DOMAIN=https://shared.example.tld/vault/` (L254-L259; Using-an-alternate-base-dir.md L9-L40, "the request must go to `http://localhost:8080/base-dir/api/sync`").
- `#location /admin { auth_basic "Private"; auth_basic_user_file ...; }` (L224-L233): `[[site.auth]] path = "/admin"`.
- Pound `HeadRemove "X-Forwarded-For"`, `AddHeader "Front-End-Https: on"` (a request field toward the backend), `RewriteLocation 0`, `HeadRemove/AddHeader "X-Forwarded-Proto"` (L779-L793): `proxy.headers` (`"Front-End-Https" = "on"`), automatic X-Forwarded-*, `proxy.redirects = "pass"`.
- Caddy `encode zstd gzip` (L60-L63, with a warning about Firefox attachment downloads): no on-the-fly compression in agensio. This is a gap but not a header rule, and Vaultwarden works without it.
- Caddy `log { ... }`, global `trusted_proxies static private_ranges` / `client_ip_headers` (L26-L35): agensio access log and `[server] trusted_proxies`.
- HAProxy commented `compression ...` and Kubernetes ingress annotations: out of scope.

### App guidance (Vaultwarden)
- **Headers Vaultwarden sets itself** on every non-WebSocket answer (`util.rs` L39-L147):
  - `Permissions-Policy` (a long deny list, L61), `Referrer-Policy: same-origin` (L62), `X-Content-Type-Options: nosniff` (L63), `X-Robots-Tag: noindex, nofollow` (L64), `X-XSS-Protection: 0` (L67).
  - `Cross-Origin-Resource-Policy: same-origin`, except on images and the `icon_external` route (L69-L77).
  - `Content-Security-Policy` (a full policy with `frame-ancestors 'self' chrome-extension://... moz-extension://* {ALLOWED_IFRAME_ANCESTORS}`) and `X-Frame-Options: SAMEORIGIN`, **both omitted on `*connector.html`** (L79-L141).
  - `Cache-Control: no-cache, no-store, max-age=0` unless the route set one (L143-L146).
  - On WebSocket upgrades to `notifications/hub` it removes X-Frame-Options, X-Content-Type-Options and Permissions-Policy, "this could cause issues with reverse proxies or CloudFlare" (L43-L58).

  So the proxy should add **no** CSP, X-Frame-Options or Permissions-Policy. agensio's `set` would replace the application's per-path decisions, and `default` would fill the deliberate gaps on the connector pages. The design excludes 1xx answers and WebSocket bytes from `[[site.response_headers]]`, so the 101 upgrade answer stays bare, as Vaultwarden wants.
- **HSTS**: the wiki recommends `max-age=31536000;` (commented, nginx L204 and L308, Caddy L69). No `includeSubDomains`, no `preload`. Vaultwarden itself sends no HSTS (not in `util.rs`; inferred from the code read).
- **CORS**: Vaultwarden **echoes the request Origin** when it is the configured `DOMAIN` origin, `file://`, `bw-desktop-file://bundle` or the SSO authority. It answers preflights by echoing `Access-Control-Request-Method/-Headers` with `Allow-Credentials: true` (`util.rs` L160-L207). This is application-side, so the proxy must not add CORS. agensio's "no echo" design is not an obstacle.
- **Redirects Vaultwarden makes itself**: `/index.html` redirects to `<domain_path>/` (`web.rs` L160-L162). Vaultwarden serves `/.well-known/apple-app-site-association` (L208) and `/app-id.json` (L176) itself, so the proxy needs no `.well-known` answers. There is no change-password well-known.
- **Trusting the proxy**: `IP_HEADER` (default `X-Real-IP`, `.env.template` L330-L333) and `IP_HEADER_TRUSTED_PROXIES` (default `local`, any non-global address, L335-L343). `DOMAIN` must be the public https URL, including any sub-path (L205-L211; Proxy-examples L121, L254-L259; Apache note L488 about `X-Forwarded-Proto`).
- **Logs**: the WebSocket `access_token` query parameter appears in proxy access logs; Hardening-Guide L32-L46 recommends redacting it. That concerns the agensio access log, not a header or redirect. agensio's access log presumably records the full target (**unverified**).

---

## 15. n8n

### Version read
- Application **n8n@2.42.7** (GitHub "latest release", published 2026-10-12). Tag at commit **`92e4ff858a6ec0dc3ce3995d8696861575698bd0`** (no peeled `^{}` line, so a lightweight tag).
- Docs: `n8n-io/n8n-docs` (the source of docs.n8n.io; the site is now built with GitBook under `docs/deploy/...`) at commit **`aa9e7bd61b20cdbe5878a743c2e27822397a1e47`** (2026-10-12 16:19 +0200). There are no docs tags.
- Official companion repositories linked from the docs: `n8n-io/n8n-docker-caddy` at **`2f93c081f0249edb42ce821aed451704d8095cf8`**, and `n8n-io/n8n-hosting` at **`280f88762c3c5ca88508fa96c99ff9d25ec8f31b`**.

### Sources
- "Docker-Compose" (Traefik): `docs/deploy/host-n8n/install-options/use-a-cloud-provider/use-docker-compose.md`, published at https://docs.n8n.io/deploy/host-n8n/install-options/use-a-cloud-provider/use-docker-compose (front-matter L8; formerly `/hosting/installation/server-setups/docker-compose`).
- Hetzner and DigitalOcean (Caddy): `deploy-to-hetzner.md` L149-L157 and `deploy-to-digital-ocean.md` L155-L173. Both use `n8n-docker-caddy/caddy_config/Caddyfile` L1-L5.
- "Configure webhook URLs with reverse proxy": `docs/deploy/host-n8n/configure-n8n/basic-configuration/configuration-examples/configure-webhook-urls-with-reverse-proxy.md` L15-L34.
- Environment variables: `.../use-environment-variables/deployment.md` (`N8N_PATH` L77, `N8N_HOST` L78, `N8N_PROTOCOL` L81, `N8N_PROXY_HOPS` L101), `endpoints.md` L57-L58 (`N8N_WEBHOOK_URL`, `WEBHOOK_URL`), `security.md` L33-L39.
- `n8n-hosting/docker-compose/subfolderWithSSL/docker-compose.yml`.
- Code at n8n@2.42.7: `packages/cli/src/server.ts` and `packages/cli/src/abstract-server.ts`.
- **No nginx example** was found in the official n8n docs at this commit. I checked the deploy and configure trees by file name, and the MCP, queue-mode and SSL pages by grep.

### Directives that redirect, set a header or answer with a fixed body

Lines refer to [use-docker-compose.md @aa9e7bd](https://github.com/n8n-io/n8n-docs/blob/aa9e7bd61b20cdbe5878a743c2e27822397a1e47/docs/deploy/host-n8n/install-options/use-a-cloud-provider/use-docker-compose.md#L121-L181) unless noted.

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML or what is missing |
|---|---|---|---|---|
| L131-L132, Traefik `command` | `--entrypoints.web.http.redirections.entryPoint.to=websecure` / `--entrypoints.web.http.redirections.entrypoint.scheme=https` | every plain-HTTP request goes to HTTPS ("n8n is only accessible using secure HTTPS, not over plain HTTP", L213) | **EXPRESSIBLE** | `http = "redirect"` (default for a TLS site on 443). The Traefik entrypoint redirect's exact status code is **unverified**. |
| L155, labels on n8n, middleware `n8n` | `traefik.http.middlewares.n8n.headers.SSLRedirect=true` | redirect to HTTPS (headers-middleware style) | **EXPRESSIBLE** (`http = "redirect"`), and redundant | Traefik v3 removed `sslRedirect`, `sslTemporaryRedirect`, `sslHost`, `sslForceHost` and `featurePolicy` from the Headers middleware (https://doc.traefik.io/traefik/migrate/v2-to-v3-details/, "Deprecated Options Removal", fetched 2026-10-12). The compose file uses the unpinned `traefik` image, so on v3 this label does nothing (or is rejected; **unverified**). The entrypoint redirect above does the job anyway. |
| L160 | `traefik.http.middlewares.n8n.headers.SSLHost=${DOMAIN_NAME}` | host for the SSL redirect | **NOT A RULE to reproduce** | Removed in Traefik v3 (same source). On v2 it would point the redirect at the bare `DOMAIN_NAME` (`example.com`), not at n8n's `SUBDOMAIN.DOMAIN_NAME` (inferred from the label values at L92-L95, L151). The nearest agensio setting, `canonical`, must be one of the site's own names. |
| L156 | `traefik.http.middlewares.n8n.headers.STSSeconds=315360000` | HSTS max-age, 10 years | **EXPRESSIBLE** | `hsts = { max_age = "3650d", subdomains = true }` (with the next row). That the design's duration syntax accepts 3650 days / 10 years is **unverified**; redirects.md shows only `"2y"` and `0`. |
| L161 | `traefik.http.middlewares.n8n.headers.STSIncludeSubdomains=true` | HSTS `includeSubDomains` | **EXPRESSIBLE** | `subdomains = true` (with health listing the bound sites) |
| L162 | `traefik.http.middlewares.n8n.headers.STSPreload=true` | HSTS `preload` token | **NOT OFFERED ON PURPOSE** (redirects.md 4.6: Chromium's list, binds every subdomain, months to leave) | The app works. The token alone does not enrol a domain; submission to hstspreload.org does. |
| L159 | `traefik.http.middlewares.n8n.headers.forceSTSHeader=true` | send STS even over plain HTTP | **NOT OFFERED ON PURPOSE** ("never over plain HTTP"; RFC 6797 7.2/8.1, browsers ignore it there, redirects.md L257-L258) | The app works. Plain requests are redirected anyway. |
| L157 | `traefik.http.middlewares.n8n.headers.browserXSSFilter=true` | `X-XSS-Protection: 1; mode=block` (Traefik's meaning; inferred from Traefik semantics, not re-read) | **EXPRESSIBLE** | `[[site.response_headers]] path = "/", set = { "X-XSS-Protection" = "1; mode=block" }` |
| L158 | `traefik.http.middlewares.n8n.headers.contentTypeNosniff=true` | `X-Content-Type-Options: nosniff` | **EXPRESSIBLE** | The baseline sends it only on agensio's own answers; for n8n's answers: `set = { "X-Content-Type-Options" = "nosniff" }` (or `default`) |
| L163 | `traefik.http.routers.n8n.middlewares=n8n@docker` | attaches the headers middleware to the router | (wiring) | n/a |
| [n8n-hosting subfolderWithSSL/docker-compose.yml L39-L46](https://github.com/n8n-io/n8n-hosting/blob/280f88762c3c5ca88508fa96c99ff9d25ec8f31b/docker-compose/subfolderWithSSL/docker-compose.yml#L31-L46) | the same eight `traefik.http.middlewares.n8n.headers.*` labels | same | same classes as above | In this file the router's middlewares are only `n8n-stripprefix` (L37), so the `n8n` headers middleware is defined but **not attached** (inferred from the labels). There is no `web` (:80) entrypoint (L10), so plain HTTP is not answered at all: agensio `http = "off"`. |

### Other directives (existing agensio features)
- Caddy `reverse_proxy n8n:5678 { flush_interval -1 }` (n8n-docker-caddy `caddy_config/Caddyfile` L1-L5; Hetzner L151-L157; DigitalOcean L157-L173): no buffering of streamed answers (SSE and streaming responses, inferred). agensio: `app = "proxy"`, `upstream = "http://127.0.0.1:5678"`, `proxy = { buffering = false }`.
- Traefik `--certificatesresolvers.mytlschallenge.acme.tlschallenge=true` (TLS-ALPN-01): agensio `tls = "auto"` (HTTP-01; TLS-ALPN-01 is listed under "Not yet" in CLAUDE.md).
- `ports: "127.0.0.1:5678:5678"` (L147-L148): the upstream address.
- `traefik.http.middlewares.n8n-stripprefix.stripprefix.prefixes=/${SUBFOLDER}` (subfolderWithSSL L36-L37): sub-path with the prefix stripped, which is `[[site.location]] path = "/n8n/"`, `upstream = "http://127.0.0.1:5678/"` (URI part replaces the prefix). n8n's own docs warn: "Combining `N8N_PATH` with reverse proxies can cause folder navigation issues. Use a subdomain" (deployment.md L77).
- Queue mode (enable-queue-mode.md L220-L227): route `/webhook/*` and `/webhook-waiting/*` to webhook processes, everything else (including `/webhook-test/*`) to main. In agensio these are locations with different `upstream`s. Multi-main needs sticky sessions (L331), which agensio does not offer (round-robin only).
- MCP: "make sure it doesn't strip the MCP request headers" (connect-to-n8n-mcp-server.md L355, L366-L380). agensio forwards request fields; nothing to do.

### App guidance (n8n)
- **Trusting the proxy**: set `N8N_PROXY_HOPS=1` (webhook page L22; deployment.md L101). In code: `if (proxyHops > 0) this.app.set('trust proxy', proxyHops)` (`abstract-server.ts` L88-L89).
  - Set `N8N_WEBHOOK_URL=https://n8n.example.com/` (`WEBHOOK_URL` is deprecated from 2.35.0; webhook page L21, L29-L30; endpoints.md L57-L58), plus `N8N_PROTOCOL=https` and `N8N_HOST` (compose L166-L170).
  - The docs ask the last proxy to set `X-Forwarded-For`, `X-Forwarded-Host` and `X-Forwarded-Proto` (webhook page L23-L26). agensio sends X-Forwarded-Host only when Host was rewritten. To follow the doc literally: `proxy = { headers = { "X-Forwarded-Host" = "$host" } }`. With Host passed through, Express falls back to Host, so leaving it out probably works (inferred from Express behaviour, **unverified**).
- **HSTS**: n8n leaves HSTS to the proxy. Code comment: "Enable HSTS headers only when n8n handles TLS. if n8n is behind a reverse-proxy, then these headers needs to be configured there" (`server.ts` L428-L436; when n8n terminates TLS itself: `maxAge: 180 days, includeSubDomains: false, preload: false`). The official Traefik example asks for 315360000 s with includeSubdomains and preload (above).
- **CSP**: n8n serves its **own** CSP with a per-request nonce, default `script-src <nonce> 'strict-dynamic' 'unsafe-eval'; object-src 'none'; base-uri 'none'` (security.md L33; `server.ts` L417-L420: "helmet cannot inject a per-request nonce"). The proxy must **not** set a CSP: a `set` would replace the nonce policy and either break the editor or weaken it (inferred). Use `N8N_CONTENT_SECURITY_POLICY` instead.
- **X-Frame-Options**: n8n sends `SAMEORIGIN` itself except in preview mode, e2e tests and development (`server.ts` L421-L422). For embedding: `N8N_PREVIEW_MODE` and `N8N_POSTMESSAGE_ALLOWED_ORIGINS` (security.md L39). A proxy-level frame field would conflict with preview/embed setups.
- **Other headers n8n sets**: `Cross-Origin-Opener-Policy` (`server.ts` L437-L439). X-Powered-By is disabled (`abstract-server.ts` L82). Cache-Control: the editor page `no-cache, no-store, must-revalidate, proxy-revalidate` (L484), `/types/*.json` `no-cache, must-revalidate` (L527), static assets 1 day (`maxAge = Time.days`, L349-L350), private files `private, max-age=...` (L364-L368). The proxy needs no cache rules.
- **CORS**: application-side ("n8n allows these routing headers in its CORS policy from n8n 2.36.0", MCP page L371). No proxy CORS in the official configs.
- **.well-known**: n8n excludes `\.well-known` from its SPA fallback (`server.ts` L448). No official proxy answer for any `.well-known` path, and no WebFinger or change-password.

---

## 16. Jellyfin

**Version read**
- Server: tag `v12.2`, commit `ca0f16eb7c195f720a1493ed469a27c4657db0c6`, released 2026-10-05.
- Docs: the `jellyfin/jellyfin.org` repository, branch `master`, commit `1e5f982651d2164f56a252ecd5c8fe57509aeaf9`, dated 2026-10-11. The docs repository has no releases; this is the version live on jellyfin.org.

**Sources**
- Reverse-proxy docs, `docs/general/post-install/networking/8_reverse-proxy/`:
  - `index.md`
  - `nginx.md`
  - `caddy.md`
  - `apache.md`
  - `haproxy.md`
  - `traefik.md`
- `docs/general/post-install/networking/index.md` (Base URL section).
- `.../9_advanced/letsencrypt.md`.
- Server code in the `jellyfin/jellyfin` repository at v12.2:
  - `Jellyfin.Api/Middleware/BaseUrlRedirectionMiddleware.cs`
  - `Jellyfin.Api/Middleware/RobotsRedirectionMiddleware.cs`
  - `Emby.Server.Implementations/ConfigurationOptions.cs`
  - `Jellyfin.Server/Startup.cs`

**History check on the hint.** The `/` → `/web/` redirect is no longer in the docs.
- `location = / { return 302 http://$host/web/; }` was removed in jellyfin.org commit `6712644` (2024-09-11, "Correcting and adjusting Nginx docs (#1098)").
- `location = /web/ { proxy_pass .../web/index.html; }` was removed in `450c824` (2024-05-13, "Remove nginx location block invalid with 10.9").
- Commit `47c7b1d` (2025-01-27, "Nginx Documentation Re-work (#1277)") removed three things:
  - `add_header X-Frame-Options "SAMEORIGIN"`. Its comment said: "X-Frame-Options may cause issues with the webOS app".
  - `X-XSS-Protection "0"`.
  - The nginx subpath examples.
- Commit `451982f` (2025-09-25) removed `frame-ancestors 'self'` from the CSP. Commit `9b9d209` had given the reason: the webOS (LG TV) app needs it removed.

Base URLs for the links below:
- `D` = `https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy`
- `S` = `https://github.com/jellyfin/jellyfin/blob/ca0f16eb7c195f720a1493ed469a27c4657db0c6`

### Directives that redirect or set headers

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML, or what is missing |
|---|---|---|---|---|
| [D/nginx.md#L45](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/nginx.md#L45), `server` 443 | `add_header X-Content-Type-Options "nosniff";` | Under the comment "Security / XSS Mitigation Headers". Jellyfin itself sends no security headers: in `S/Jellyfin.Api/Middleware/` the only header set is `X-Response-Time-ms`. | EXPR | `[[site.response_headers]] path = "/"` with `set = { "X-Content-Type-Options" = "nosniff" }`. The baseline only covers agensio's own answers, so this rule is needed for Jellyfin's answers. nginx without `always` covers only 2xx/3xx; `when = "always"` is a superset of that, which is harmless here. |
| [D/nginx.md#L48](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/nginx.md#L48), `server` 443 | `add_header Permissions-Policy "accelerometer=(), ambient-light-sensor=(), battery=(), bluetooth=(), camera=(), clipboard-read=(), display-capture=(), document-domain=(), encrypted-media=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(), keyboard-map=(), local-fonts=(), magnetometer=(), microphone=(), payment=(), publickey-credentials-get=(), serial=(), sync-xhr=(), usb=(), xr-spatial-tracking=()" always;` | The docs' comment: "Permissions policy. May cause issues with some clients". | EXPR (fixed text, about 440 bytes) | The same rule, with `set = { "Permissions-Policy" = "accelerometer=(), ... xr-spatial-tracking=()" }`. The docs flag this as a risk, so it should be offered after asking, not applied by default. |
| [D/nginx.md#L54](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/nginx.md#L54), `server` 443 | `add_header Content-Security-Policy "default-src https: data: blob: ; img-src 'self' https://* ; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://www.gstatic.com https://www.youtube.com blob:; worker-src 'self' blob:; connect-src 'self'; object-src 'none'; font-src 'self'";` | The docs' comment: "Enforces https content and restricts JS/CSS to origin. External Javascript (such as cast_sender.js for Chromecast) must be whitelisted." It is **active, not commented out**, and has had no `frame-ancestors` since 2025-09-25. | EXPR | `default = { "Content-Security-Policy" = "default-src https: data: blob: ; img-src 'self' https://* ; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://www.gstatic.com https://www.youtube.com blob:; worker-src 'self' blob:; connect-src 'self'; object-src 'none'; font-src 'self'" }`. The design asks for `default` on app sites; Jellyfin sends no CSP, so it behaves like `set`. |
| [D/nginx.md#L89](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/nginx.md#L89), `server` 80 | `return 301 https://$host$request_uri;` | HTTP → HTTPS, with Host, path and query kept. | EXPR | `http = "redirect"`, the default for a TLS site on 443. agensio answers 308 instead of 301, and redirects on the site's own names rather than any `$host`. |
| [D/caddy.md#L86](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/caddy.md#L86), subpath site | `redir /jellyfin /jellyfin/` | Adds the trailing slash for a Base URL `/jellyfin`. Caddy's default status is 302 (inferred from Caddy's defaults). | EXPR, but not needed | One option is `[[site.redirect]]` with `from = "/jellyfin"`, `match = "exact"`, `to = "/jellyfin/"`, `status = 302`. **Unverified**: whether an exact `/jellyfin` and `/jellyfin/` normalise to the same path, which would loop. It is not needed anyway: with a prefix location `/jellyfin` that forwards the bare `/jellyfin`, Jellyfin redirects itself ([S/.../BaseUrlRedirectionMiddleware.cs#L48-L73](https://github.com/jellyfin/jellyfin/blob/ca0f16eb7c195f720a1493ed469a27c4657db0c6/Jellyfin.Api/Middleware/BaseUrlRedirectionMiddleware.cs#L48-L73): a path equal to the base URL, or outside it, is redirected to `baseUrl + "/web/"`). |
| [D/apache.md#L13](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/apache.md#L13), `<VirtualHost *:80>` | `Redirect permanent / https://DOMAIN_NAME/` | HTTP → HTTPS. The docs' comment: "Comment to prevent HTTP to HTTPS redirect". | EXPR | `http = "redirect"` |
| [D/apache.md#L47](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/apache.md#L44-L47), `<VirtualHost *:443>`, **commented out** | `# Header set Cache-Control "no-store, no-cache, must-revalidate, max-age=0"` | The docs' comment: "Sometimes, Jellyfin requires clients to empty their cache... might also fix some syncplay issues (#5485 and #8140)". | EXPR (a no-freshness value is allowed with any `when`) | `[[site.response_headers]] path = "/"` with `set = { "Cache-Control" = "no-store, no-cache, must-revalidate, max-age=0" }`. Only when asked for. Note that it overrides Jellyfin's own `no-cache` on `index.html` ([S/Jellyfin.Server/Startup.cs#L223](https://github.com/jellyfin/jellyfin/blob/ca0f16eb7c195f720a1493ed469a27c4657db0c6/Jellyfin.Server/Startup.cs#L223)). |
| [D/haproxy.md#L22](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/haproxy.md#L22), `frontend`, commented out | `#    redirect scheme https if !{ ssl_fc }` | HTTP → HTTPS. | EXPR | `http = "redirect"` |
| [D/traefik.md#L87](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/traefik.md#L87), middleware `jellyfin-mw` | `'traefik.http.middlewares.jellyfin-mw.headers.customResponseHeaders.X-Robots-Tag=noindex,nofollow,nosnippet,noarchive,notranslate,noimageindex'` | Keep search engines out (inferred). | EXPR | `set = { "X-Robots-Tag" = "noindex,nofollow,nosnippet,noarchive,notranslate,noimageindex" }` |
| [D/traefik.md#L89](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/traefik.md#L88-L89) | `'traefik.http.middlewares.jellyfin-mw.headers.SSLRedirect=true'` | The docs' comment: "then only allow https requests". | EXPR | `http = "redirect"` |
| [D/traefik.md#L92](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/traefik.md#L90-L92) and [#L95](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/traefik.md#L93-L95) | `'...headers.SSLHost=HOST_NAME.DOMAIN_NAME:9999'` and `'...headers.SSLForceHost=true'` | Redirect to one host and port, "even the ones that are already using SSL". | EXPR for the host part; CHANGE for the port | The host part is `canonical = "HOST_NAME.DOMAIN_NAME"`. The `:9999` port is the problem: the redirect target is plain and TLS on the same non-default port. **Unverified** whether `http = "redirect"` can target the site's TLS port when it is not 443. No change is recommended: use 443. |
| [D/traefik.md#L97](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/traefik.md#L96-L97) and [#L100](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/traefik.md#L98-L100) | `'...headers.STSSeconds=315360000'` and `'...headers.STSIncludeSubdomains=true'` | HSTS for 10 years, including subdomains. | EXPR | `hsts = { max_age = "10y", subdomains = true }`. **Unverified**: the duration syntax and any upper bound; `"3650d"` is the alternative. |
| [D/traefik.md#L102](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/traefik.md#L101-L102) | `'...headers.STSPreload=true'` | Adds `preload`. | NOT-OFFERED | Preload is left out on purpose (redirects.md 4.6). The app works the same without it. |
| [D/traefik.md#L104](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/traefik.md#L103-L104) | `'...headers.forceSTSHeader=true'` | Send STS over HTTP too. | NOT-OFFERED | agensio never sends HSTS over plain HTTP, and RFC 6797 tells browsers to ignore it there. Nothing is lost. |
| [D/traefik.md#L106](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/traefik.md#L105-L106) | `'...headers.frameDeny=true'` | `X-Frame-Options: DENY`. | EXPR, but discouraged | `set = { "X-Frame-Options" = "DENY" }`. The nginx page removed its frame field because of the webOS app (see the history above). The Traefik page is older (it uses the `traefik:chevrotin` image, v2.2) and was not updated. |
| [D/traefik.md#L108](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/traefik.md#L107-L108) | `'...headers.contentTypeNosniff=true'` | `nosniff` | EXPR | as for nginx L45 |
| [D/traefik.md#L110](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/traefik.md#L109-L110) | `'...headers.customresponseheaders.X-XSS-PROTECTION=1'` | The comment says the value is "1; mode=block", but the label sets `1`. | EXPR, with the design's warning | `set = { "X-XSS-Protection" = "1" }`. headers.md 2.6 warns on any value other than `0`. The nginx page used to say `"0"; # Do NOT enable. This is obsolete/dangerous`, removed in 2025-01. |
| [D/traefik.md#L113](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/traefik.md#L111-L113) | `"traefik.http.middlewares.jellyfin-mw.headers.customFrameOptionsValue='allow-from https://DOMAIN_NAME'"` | Allow framing from the parent domain. It overrides `frameDeny`. | NOT-OFFERED | `ALLOW-FROM` is refused because browsers ignore it. The working equivalent is `default = { "Content-Security-Policy" = "... frame-ancestors 'self' https://DOMAIN_NAME" }`. The app works without either. |
| [D/traefik.md#L120-L126](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/traefik.md#L119-L126), router `jellyfin-insecure` | `'...jellyfin-insecure-mw.redirectscheme.scheme=https'`, `'...redirectscheme.port=9999'`, `'...redirectscheme.permanent=false'` | Redirect HTTP on :9999 to HTTPS on :9999 ("consistent protocol"). | CHANGE, and not recommended | Plain and TLS on the same port is not offered. **Unverified**: whether one agensio listener can sniff both. Use 80 and 443 with `http = "redirect"`. |
| [D/traefik.md#L183-L189](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/traefik.md#L182-L189), `traefik.toml` | `[entryPoints.http.http.redirections.entrypoint] to = "https" scheme = "https"` | "Standard HTTP redirects to HTTPS". | EXPR | `http = "redirect"` |
| [S/.../BaseUrlRedirectionMiddleware.cs#L48-L73](https://github.com/jellyfin/jellyfin/blob/ca0f16eb7c195f720a1493ed469a27c4657db0c6/Jellyfin.Api/Middleware/BaseUrlRedirectionMiddleware.cs#L48-L73) (app code, for context) | `httpContext.Response.Redirect(target);`, a relative redirect to `baseUrl + "/" + "web/"` ([ConfigurationOptions.cs#L17](https://github.com/jellyfin/jellyfin/blob/ca0f16eb7c195f720a1493ed469a27c4657db0c6/Emby.Server.Implementations/ConfigurationOptions.cs#L17): `{ DefaultRedirectKey, "web/" }`) | Jellyfin redirects `/`, and any path outside its base URL, to `web/` itself. `/health` is handled separately. | OTHER | Nothing to configure. The proxy must just forward `/`. This is why the old `location = / { return 302 .../web/ }` was dropped. |
| [S/.../RobotsRedirectionMiddleware.cs#L36-L40](https://github.com/jellyfin/jellyfin/blob/ca0f16eb7c195f720a1493ed469a27c4657db0c6/Jellyfin.Api/Middleware/RobotsRedirectionMiddleware.cs#L36-L40) (app code) | `httpContext.Response.Redirect("web/robots.txt");` | Jellyfin redirects `/robots.txt` itself. | OTHER | Nothing to configure. |

### Other directives (existing features)

- **WebSocket.**
  - nginx `location /socket` with `proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade";` (nginx.md L70-82).
  - Apache `RewriteCond %{HTTP:Upgrade} =websocket` / `RewriteRule /(.*) ws://SERVER_IP_ADDRESS:8096/socket/$1 [P,L]` (apache.md L38-42). This is an internal proxy rewrite, not a redirect. It prepends `/socket/` to the path; inferred to be a docs quirk.
  - Subpath `<Location /jellyfin/socket>` (apache.md L89-93).
  - agensio needs none of this: the upgrade is automatic and the path is forwarded unchanged.
- **Body size.** `client_max_body_size 20M;` (nginx.md L30; comment: "this might not be enough for some posters") → `max_body_size = "20MB"` on the site.
- **Buffering.** `proxy_buffering off;` (nginx.md L67; "when the nginx proxy gets very resource heavy upon streaming") → `proxy = { buffering = false }`.
- **Request fields to the origin.** `proxy_set_header Host $host; X-Real-IP $remote_addr; X-Forwarded-For $proxy_add_x_forwarded_for; X-Forwarded-Proto $scheme; X-Forwarded-Protocol $scheme; X-Forwarded-Host $http_host;` (nginx.md L59-64 and L76-81).
  - agensio passes Host through and always sets X-Forwarded-For and X-Forwarded-Proto.
  - The extras would be `proxy = { headers = { "X-Real-IP" = "$remote_addr", "X-Forwarded-Protocol" = "$scheme" } }`.
  - X-Forwarded-Host is redundant when Host is passed through.
  - Apache uses `RequestHeader set X-Forwarded-Proto "https"` and `X-Forwarded-Port "443"` (apache.md L34-35). `ProxyPreserveHost On` is the same as agensio's Host pass-through.
- **ACME webroot carve-outs.** Apache `ProxyPass "/.well-known/" "!"` (apache.md L31, letsencrypt.md L40-41) and HAProxy `acl letsencrypt_auth path_beg /.well-known/acme-challenge/` (haproxy.md L25-26). agensio's built-in ACME answers first. No other `/.well-known/` path is used by Jellyfin.
- **Subpath.** Base URL `/jellyfin`; Apache `<Location /jellyfin> ProxyPass "http://127.0.0.1:8096/jellyfin"` (apache.md L94-97); Caddy `reverse_proxy /jellyfin/* 127.0.0.1:8096` (caddy.md L87). In agensio: `[[site.location]] path = "/jellyfin"`, `upstream = "http://127.0.0.1:8096"`, with no URI part so the path is passed unchanged.
- **Health check.** HAProxy `option forwardfor` and `http-check send meth GET uri /health` (haproxy.md L32-35). agensio has no active health checks; it has passive health on groups.
- **Log redaction.** nginx `map $request $secretfilter` / `log_format stripsecrets` (nginx.md L99-115) hides `api_key=` in logs. It is neither a redirect nor a header; agensio has no log-field redaction (**unverified**).
- **certbot.** letsencrypt.md L110 runs `certbot --nginx --agree-tos --redirect --hsts ...`, which makes certbot write its own redirect and HSTS lines. Those are certbot's defaults, not in the docs text.

### App guidance

- **HSTS.** nginx.md and apache.md set none. traefik.md sets `STSSeconds=315360000`, `STSIncludeSubdomains=true`, `STSPreload=true` and `forceSTSHeader=true` (L96-104).
- **CSP.** The nginx page recommends a proxy-set CSP (L54, active). Jellyfin itself sends no CSP. Chromecast needs `https://www.gstatic.com`.
- **Frame fields.**
  - The current nginx docs set **no** X-Frame-Options and no `frame-ancestors`. Both were removed for the LG webOS app (commits `47c7b1d` and `451982f`).
  - The Traefik page still sets `frameDeny` and `ALLOW-FROM`.
  - agensio's baseline adds no frame field, which suits Jellyfin.
  - Jellyfin itself sends none.
- **CORS.** None in the docs.
- **.well-known.** Only the ACME carve-out. Jellyfin uses no other `/.well-known/` path.
- **Caching.** Jellyfin sets `Cache-Control: no-cache` on `web/index.html` itself ([Startup.cs#L214-L224](https://github.com/jellyfin/jellyfin/blob/ca0f16eb7c195f720a1493ed469a27c4657db0c6/Jellyfin.Server/Startup.cs#L214-L224)). There is no proxy-side asset caching guidance.
- **Trusting the proxy** ([D/index.md#L24-L34](https://github.com/jellyfin/jellyfin.org/blob/1e5f982651d2164f56a252ecd5c8fe57509aeaf9/docs/general/post-install/networking/8_reverse-proxy/index.md#L24-L34)): "the IP address(es) of your reverse proxy must be configured under 'Known Proxies'". Jellyfin then honours `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` through `UseForwardedHeaders` ([Startup.cs#L184](https://github.com/jellyfin/jellyfin/blob/ca0f16eb7c195f720a1493ed469a27c4657db0c6/Jellyfin.Server/Startup.cs#L184)). Otherwise "all limitations for external access will not work".
- **WebSockets.** Required (index.md L36-38).
- **Logs.** `api_key` appears in URLs. index.md L18-22 recommends redacting or protecting the logs.

---

## 17. Home Assistant

**Version read**
- Core: tag `2026.10.1`, commit `abe1fdd7cd6b4de1715c87b6fd87d92699514ef9`, released 2026-10-10.
- Docs: the `home-assistant/home-assistant.io` repository, branch `current`, commit `7c990c88474854ab2ae656b55ca1cd4ccaaa92df`, dated 2026-10-12.
- Add-ons: the `home-assistant/addons` repository, branch `master`, commit `f9fa97ab7569ce5456e46684248187a411a75abc`, dated 2026-10-09. The "NGINX Home Assistant SSL proxy" add-on is at **version 4.5.1** (`config.yaml` L2).

**Sources**
- Docs: `source/_integrations/http.markdown`, `source/_docs/configuration/remote.markdown`, `source/_redirects`.
- Add-on:
  - `nginx_proxy/rootfs/etc/nginx/nginx.conf.gtpl`
  - `nginx_proxy/config.yaml`
  - `nginx_proxy/DOCS.md`
- Core: `homeassistant/components/http/headers.py`, `static.py`, `forwarded.py`, and `homeassistant/components/auth/login_flow.py`.

**The official docs no longer publish an nginx, Apache or Caddy example.** `source/_redirects` sends each old page to a community-forum thread:
- `/docs/ecosystem/apache` (L449)
- `/docs/ecosystem/caddy` (L453)
- `/docs/ecosystem/haproxy` (L458)
- `/docs/ecosystem/nginx` (L459)
- `/docs/ecosystem/nginx_subdomain` (L460)

Those community guides, including their special `/api/websocket` location, are not project-maintained, and I did not read them (**unverified**). The only project-maintained proxy configuration is the NGINX add-on.

Base URLs for the links below:
- `A` = `https://github.com/home-assistant/addons/blob/f9fa97ab7569ce5456e46684248187a411a75abc/nginx_proxy`
- `H` = `https://github.com/home-assistant/home-assistant.io/blob/7c990c88474854ab2ae656b55ca1cd4ccaaa92df/source`
- `C` = `https://github.com/home-assistant/core/blob/abe1fdd7cd6b4de1715c87b6fd87d92699514ef9/homeassistant/components`

### Directives that redirect or set headers

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML, or what is missing |
|---|---|---|---|---|
| [A/rootfs/etc/nginx/nginx.conf.gtpl#L62-L69](https://github.com/home-assistant/addons/blob/f9fa97ab7569ce5456e46684248187a411a75abc/nginx_proxy/rootfs/etc/nginx/nginx.conf.gtpl#L62-L69), `server` 80 for `{{ .options.domain }}` | `return 301 https://$host$request_uri;` | HTTP → HTTPS. Port 80 is **disabled by default** in the add-on ([A/DOCS.md#L96](https://github.com/home-assistant/addons/blob/f9fa97ab7569ce5456e46684248187a411a75abc/nginx_proxy/DOCS.md#L96), `config.yaml` L32 `80/tcp: null`) because `emulated_hue` may need port 80. | EXPR | `http = "redirect"`. Or `http = "off"` to match the add-on's default of not listening on 80. |
| [A/.../nginx.conf.gtpl#L46-L60](https://github.com/home-assistant/addons/blob/f9fa97ab7569ce5456e46684248187a411a75abc/nginx_proxy/rootfs/etc/nginx/nginx.conf.gtpl#L46-L60), `default_server` | `ssl_reject_handshake on;` and `return 444;` | Drop requests for unknown names: TLS refused, plain connection closed. | OTHER | agensio's listener catch-all: 421 for a name no site lists, and a TLS handshake refused for an unknown SNI (the `tls_handshakes_refused` counter). It is a different code from 444, but not a redirect or header rule. |
| [A/.../nginx.conf.gtpl#L107-L109](https://github.com/home-assistant/addons/blob/f9fa97ab7569ce5456e46684248187a411a75abc/nginx_proxy/rootfs/etc/nginx/nginx.conf.gtpl#L107-L109), `server` 443 | `add_header Alt-Svc 'h3=":{{ .variables.quic_port }}"; ma=86400';` | Advertise HTTP/3 when the QUIC port is set. | OTHER (the name is refused) | `[server] protocols = [..., "h3"]` (with `http3.alt_svc` on by default) |
| [A/.../nginx.conf.gtpl#L111-L113](https://github.com/home-assistant/addons/blob/f9fa97ab7569ce5456e46684248187a411a75abc/nginx_proxy/rootfs/etc/nginx/nginx.conf.gtpl#L111-L113), `server` 443 | `{{- if .options.hsts }}` / `add_header Strict-Transport-Security "{{ .options.hsts }}" always;` | HSTS. The default option value is **`max-age=31536000; includeSubDomains`** ([A/config.yaml#L18](https://github.com/home-assistant/addons/blob/f9fa97ab7569ce5456e46684248187a411a75abc/nginx_proxy/config.yaml#L18); DOCS.md L61-63: "If empty, the header is not sent."). | EXPR (`max-age` and `includeSubDomains`). A free-text value with `preload` is NOT-OFFERED. | `hsts = { max_age = "1y", subdomains = true }`. Duration syntax as in the design's `"2y"`; **unverified** for `"1y"`, else `"365d"`. agensio sends HSTS on every HTTPS answer, which is the same as nginx's `always`. |
| [A/.../nginx.conf.gtpl#L134](https://github.com/home-assistant/addons/blob/f9fa97ab7569ce5456e46684248187a411a75abc/nginx_proxy/rootfs/etc/nginx/nginx.conf.gtpl#L134), `location /` | `proxy_redirect http:// https://;` | Rewrite any `Location: http://...` that HA sends to `https://` (HA sees plain HTTP from the proxy). | EXPR for the site's own names | Built in (redirects.md 2.5): on a site that redirects plain HTTP, agensio upgrades `Location: http://<site name>/...`. nginx would also rewrite `http://` URLs for other hosts; agensio passes those unchanged. That is harmless (inferred: HA's redirects are relative or to its own host). |
| [C/http/headers.py#L22-L31](https://github.com/home-assistant/core/blob/abe1fdd7cd6b4de1715c87b6fd87d92699514ef9/homeassistant/components/http/headers.py#L22-L31) (app code, for context) | `REFERRER_POLICY: "no-referrer"`, `X_CONTENT_TYPE_OPTIONS: "nosniff"`, `hdrs.SERVER: ""`, and `if use_x_frame_options: added_headers[X_FRAME_OPTIONS] = "SAMEORIGIN"` | HA's own security headers on every answer, errors included (L38-42). | OTHER | Nothing to configure. The baseline's `Referrer-Policy` is `default`, so HA's `no-referrer` stays. HA already sends `nosniff`. |
| [C/http/static.py#L13-L15](https://github.com/home-assistant/core/blob/abe1fdd7cd6b4de1715c87b6fd87d92699514ef9/homeassistant/components/http/static.py#L13-L15) and [#L46](https://github.com/home-assistant/core/blob/abe1fdd7cd6b4de1715c87b6fd87d92699514ef9/homeassistant/components/http/static.py#L46) (app code) | `CACHE_TIME: Final = 31 * 86400` / `CACHE_HEADER = f"public, max-age={CACHE_TIME}"` | HA's own caching of static frontend files. | OTHER | Nothing to configure. |

### Other directives (existing features)

- **WebSocket.** `map $http_upgrade $connection_upgrade { default upgrade; '' close; }` (L16-19) and `proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection $connection_upgrade;` in the one `location /` (L135-137). There is **no special `/api/websocket` location** in the official add-on. agensio upgrades automatically.
- **Buffering.** `proxy_buffering off;` (L115) → `proxy = { buffering = false }`.
- **Body size.** `client_max_body_size {{ .options.client_max_body_size_megabytes }}m;` (L117-119), default `1` (config.yaml L23) → `max_body_size`.
- **Request fields.**
  - `proxy_set_header Origin $http_origin;` (L131) is passed through by agensio anyway.
  - `X-Forwarded-Proto $scheme` (L132) is automatic.
  - `Host $forward_host` (L133) with `map $http_host $forward_host { default $http_host; '' $host; }` (L21-29). The map exists because HTTP/3 clients send `:authority` and no `Host`, and since 2026.7.0 aiohttp rejects a missing Host with a 400. agensio must send a `Host` derived from `:authority` on h2 and h3 requests it proxies; **unverified** here.
  - `X-Forwarded-Host $forward_host` (L138): agensio sends X-Forwarded-Host only when Host is rewritten. If wanted: `proxy = { headers = { "X-Forwarded-Host" = "$host" } }`.
  - `X-Forwarded-For` (L140) is automatic.
- **PROXY protocol.** `real_ip_from` → `listen ... proxy_protocol; set_real_ip_from; real_ip_header proxy_protocol;` (L92-105). I found no PROXY-protocol support in agensio's `docs/keys.md` or `configuration.md` (**unverified**). `[server] trusted_proxies` covers the X-Forwarded-For case.
- **Cloudflare.** `include /data/cloudflare.conf` (L42-44) is a `set_real_ip_from` list → `[server] trusted_proxies`.
- **Upstream TLS.** `use_ssl_backend` → `proxy_pass https://...` (L126-130) → `upstream = "https://..."` with `proxy.tls`.
- **Customisation.** `customize.active` includes user files from `/share` (L121-123, L148-150). These are user content, not shipped.

### App guidance

- **Trusting the proxy.**
  - [H/_integrations/http.markdown#L95-L109](https://github.com/home-assistant/home-assistant.io/blob/7c990c88474854ab2ae656b55ca1cd4ccaaa92df/source/_integrations/http.markdown#L95-L109): "When using a reverse proxy, turn on **Trust X-Forwarded-For** and add the proxy to **Trusted proxies**. Requests from reverse proxies are blocked if these options are not set."
  - Since 2026.8 these are UI settings, imported from the old YAML `use_x_forwarded_for` / `trusted_proxies` (L82-93).
  - Add-on DOCS.md L16-23 shows the YAML form with `172.30.33.0/24`, and L101 says: "`400 Bad Request` ... missing the `trusted_proxies`".
  - Core [C/http/forwarded.py#L57-L70](https://github.com/home-assistant/core/blob/abe1fdd7cd6b4de1715c87b6fd87d92699514ef9/homeassistant/components/http/forwarded.py#L57-L70) answers 400 in four cases:
    - X-Forwarded-For arrives from an untrusted peer;
    - X-Forwarded-For is malformed;
    - **the number of `X-Forwarded-Proto` elements is neither 1 nor equal to the number of X-Forwarded-For elements**;
    - X-Forwarded-Host or X-Forwarded-Proto is empty.
  - The count rule matters when agensio itself sits behind a CDN and appends to these fields.
- **Frame fields.** HA itself sends `X-Frame-Options: SAMEORIGIN` unless "Send X-Frame-Options" (`use_x_frame_options`, default true) is off ([H/http.markdown#L75-L77](https://github.com/home-assistant/home-assistant.io/blob/7c990c88474854ab2ae656b55ca1cd4ccaaa92df/source/_integrations/http.markdown#L75-L77); core `__init__.py` L99 `default=True`).
  - To embed HA in another site (iframes), the user turns that option off, and **the proxy must not add a frame field**. agensio's baseline adds none.
  - HA's own iframe/webpage dashboards depend on the *embedded* site's frame policy, not HA's.
- **CORS.** HA's own setting, "CORS allowed origins" (http.markdown L72-74). There is no proxy CORS.
- **HSTS.** The add-on's default `max-age=31536000; includeSubDomains`. HA itself sends none.
- **CSP.** None recommended. HA sends none.
- **Caching** ([H/http.markdown#L111-L120](https://github.com/home-assistant/home-assistant.io/blob/7c990c88474854ab2ae656b55ca1cd4ccaaa92df/source/_integrations/http.markdown#L111-L120)):
  - A caching proxy or CDN must not cache 404s, HTML (`index.html`) or service workers (`/sw-modern.js`, `/sw-legacy.js`), or anything under `/api/` or `/auth/`.
  - `/frontend_latest/`, `/frontend_es5/` and `/static/` may be cached ("Home Assistant already tells browsers to cache these for up to a month").
  - This is guidance for caching proxies; agensio does not cache proxied answers, so there is nothing to set.
- **.well-known.** HA serves `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource` itself ([C/auth/login_flow.py#L125](https://github.com/home-assistant/core/blob/abe1fdd7cd6b4de1715c87b6fd87d92699514ef9/homeassistant/components/auth/login_flow.py#L125), L170), used by MCP clients (DOCS.md L97).
  - agensio's proxy site forwards them, since only `/.well-known/acme-challenge/` is intercepted.
  - The add-on notes that over HTTP/3 the Host loses its port, which breaks this OAuth discovery on non-443 ports (DOCS.md L97).

---

## 18. Immich

**Version read**
- Tag `v3.3.1`, commit `db6e11ecc851228aec9c525abb0ee026d1f5055e`, released 2026-10-08.

**Sources**
- `docs/docs/administration/reverse-proxy.md` (docs.immich.app "Reverse Proxy").
- `docs/docs/install/environment-variables.md`.
- `docs/docs/FAQ.mdx`.
- Server code:
  - `server/src/controllers/app.controller.ts`
  - `server/src/constants.ts`
  - `server/src/app.common.ts`
  - `server/src/repositories/config.repository.ts`
  - `server/helmet.json`
- `web/static/.well-known/security.txt`.

Base URL for the links below: `I` = `https://github.com/immich-app/immich/blob/db6e11ecc851228aec9c525abb0ee026d1f5055e`

### Directives that redirect or set headers

**There are none.** None of the four official examples (nginx, Caddy, Apache, Traefik) sends a redirect or adds, sets or hides a response header. The only Location-related directive:

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML, or what is missing |
|---|---|---|---|---|
| [I/docs/docs/administration/reverse-proxy.md#L38](https://github.com/immich-app/immich/blob/db6e11ecc851228aec9c525abb0ee026d1f5055e/docs/docs/administration/reverse-proxy.md#L38), `server` | `proxy_redirect     off;` | Pass the app's `Location` unchanged. | OTHER | `proxy = { redirects = "pass" }`. The default, `"rewrite"`, only touches a Location that points at the origin's own address, so it is also fine. |
| [I/.../reverse-proxy.md#L78](https://github.com/immich-app/immich/blob/db6e11ecc851228aec9c525abb0ee026d1f5055e/docs/docs/administration/reverse-proxy.md#L78), Apache | `ProxyPassReverse / http://127.0.0.1:2283/` | Rewrite an origin-address Location. | OTHER | `proxy = { redirects = "rewrite" }`, the default |
| [I/.../reverse-proxy.md#L52-L54](https://github.com/immich-app/immich/blob/db6e11ecc851228aec9c525abb0ee026d1f5055e/docs/docs/administration/reverse-proxy.md#L51-L54), **commented out** | `# location = /.well-known/immich {` / `#     proxy_pass http://<backend_url>:2283;` / `# }` | "useful when using Let's Encrypt http-01 challenge": a webroot `/.well-known` location would otherwise swallow it. | OTHER | Nothing to configure. agensio intercepts only `/.well-known/acme-challenge/`, so `/.well-known/immich` reaches the upstream. |

### Other directives (existing features)

- **Body size.** `client_max_body_size 50000M;` (L22, "allow large file uploads") → `max_body_size = "50GB"`. Note that `[control] site_limits.max_body_size` defaults to 512MB for managed sites. **Unverified**: whether `0` or "unlimited" is accepted.
- **Request buffering.** `proxy_request_buffering off;` (L25: "disable buffering uploads to prevent OOM ... and make uploads twice as fast") → `proxy = { request_buffering = false }`.
- **Body buffer.** `client_body_buffer_size 1024k;` (L28). agensio has no matching knob; it is not needed.
- **Request fields.** `proxy_set_header Host $host; X-Real-IP $remote_addr; X-Forwarded-For ...; X-Forwarded-Proto $scheme;` (L31-34). L3 says these four are required. agensio's automatic fields cover three of them; add `proxy = { headers = { "X-Real-IP" = "$remote_addr" } }`.
- **WebSocket.** `proxy_http_version 1.1;` (L37), `proxy_set_header Upgrade $http_upgrade; Connection "upgrade";` (L47-48), and Apache `upgrade=websocket` (L77) → automatic. The FAQ (L392-394): "Server Status Offline | Version Unknown" means WebSockets are missing.
- **Timeouts.** `proxy_read_timeout 600s; proxy_send_timeout 600s; send_timeout 600s;` (L41-43), Apache `timeout=600` (L77), Traefik `respondingTimeouts: readTimeout: 600s, idleTimeout: 600s` (L97-100: "videos stop uploading after 1 minute") → `proxy = { read_timeout = 600, send_timeout = 600 }` and `body_timeout`.
- **No subpath.** L6: "Immich does not support being served on a sub-path... It has to be served on the root path of a (sub)domain."

### App guidance

- **.well-known.**
  - `GET /.well-known/immich` is served by the app ([I/server/src/controllers/app.controller.ts#L10-L19](https://github.com/immich-app/immich/blob/db6e11ecc851228aec9c525abb0ee026d1f5055e/server/src/controllers/app.controller.ts#L10-L19)) and returns `{"api":{"endpoint":"/api"}}`. It is excluded from the `/api` prefix (`constants.ts` L63). The mobile app uses it for discovery.
  - Docs L10: "verify that the Immich well-known endpoint (`/.well-known/immich`) gets correctly routed to Immich, otherwise ... the mobile app may run into connection issues."
  - Immich also ships `web/static/.well-known/security.txt`, served by the app.
  - It must be **proxied, not redirected**. agensio does this by default.
- **Trusting the proxy.**
  - `app.set('trust proxy', ['loopback', ...network.trustedProxies]);` ([I/server/src/app.common.ts#L49](https://github.com/immich-app/immich/blob/db6e11ecc851228aec9c525abb0ee026d1f5055e/server/src/app.common.ts#L49)).
  - The default is `['linklocal', 'uniquelocal']` (`config.repository.ts` L324). Together that is loopback plus private ranges.
  - Override with `IMMICH_TRUSTED_PROXIES` (environment-variables.md L46).
  - agensio on the same host, or reaching the Docker bridge, is trusted with no setting.
- **CSP and other security headers.**
  - The docs recommend none at the proxy.
  - The app has an opt-in Helmet configuration, `IMMICH_HELMET_FILE` (default `false`; `true` uses `server/helmet.json`; environment-variables.md L40).
  - Its CSP: `default-src 'self'`; `script-src 'self' 'wasm-unsafe-eval' 'unsafe-inline' https://www.gstatic.com`; `connect-src 'self' blob: https://pay.futo.org https://static.immich.cloud https://tiles.immich.cloud`; `frame-src 'none'`; `object-src 'none'`; and so on.
  - A proxy CSP that misses `https://tiles.immich.cloud` or `static.immich.cloud` would break maps (inferred). If an agent offers a CSP, `default` with the app's `helmet.json` values is the safe source.
- **Caching.** The app sets `cache-control: public,max-age=31536000,immutable` itself on `/_app/immutable/*` ([I/server/src/app.common.ts#L79-L82](https://github.com/immich-app/immich/blob/db6e11ecc851228aec9c525abb0ee026d1f5055e/server/src/app.common.ts#L79-L82)). Nothing is needed at the proxy.
- **CORS.** Enabled only in development (app.common.ts L61-63). There is no proxy CORS.
- **HSTS, frame fields.** Nothing in the docs. The FAQ (L90-98) discourages Basic Auth, custom headers and mTLS in front of the mobile app.

---

## 19. Nextcloud All-in-One, behind a reverse proxy (with Nextcloud server and admin-manual context)

**Version read**
- AIO: tag `v14.2.0`, commit `2599cb62878a59a5186655353afc0f379d51854f`, released 2026-09-21.
- Nextcloud server: tag `v35.0.1`, commit `3c012e618ab46ac73c61a96f5bb7168a693ca1fb`, released 2026-09-24.
- Admin manual: the `nextcloud/documentation` repository, branch **`stable35`**, commit `c02abf851cf492c0914d49ce0469b1f8b681a646`. The sample header reads "Version 2026-06-09".

**Sources**
- AIO `reverse-proxy.md`.
- AIO `Containers/apache/Caddyfile`, `nextcloud.conf` and `start.sh`. This is the "apache" container AIO puts behind the user's proxy. It runs Caddy in front of Apache.
- Server `.htaccess`, `lib/public/AppFramework/Http/Response.php`, and `apps/settings/lib/SetupChecks/SecurityHeaders.php` / `WellKnownUrls.php`.
- Docs `admin_manual/installation/nginx-root.conf.sample` and `admin_manual/configuration_server/reverse_proxy_configuration.rst`.

Base URLs for the links below:
- `R` = `https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/reverse-proxy.md`
- `K` = `https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/Containers/apache`
- `N` = `https://github.com/nextcloud/documentation/blob/c02abf851cf492c0914d49ce0469b1f8b681a646/admin_manual`
- `V` = `https://github.com/nextcloud/server/blob/3c012e618ab46ac73c61a96f5bb7168a693ca1fb`

### 19a. AIO's outer reverse-proxy examples (what the user's proxy must do)

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML, or what is missing |
|---|---|---|---|---|
| [R#L204-L212](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/reverse-proxy.md#L204-L212), Apache `<VirtualHost *:80>` | `RewriteEngine On` / `RewriteCond %{HTTPS} off` / `RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}` / `RewriteCond %{SERVER_NAME} =<your-nc-domain>` / `RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]` | HTTP → HTTPS. The second pair is certbot's usual output (inferred). | EXPR | `http = "redirect"` |
| [R#L534-L536](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/reverse-proxy.md#L534-L536), nginx `server` | `if ($scheme = "http") {` / `return 301 https://$host$request_uri;` / `}` | HTTP → HTTPS on the same server block. | EXPR | `http = "redirect"` |
| [R#L537-L539](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/reverse-proxy.md#L537-L539), nginx `server` | `if ($http_x_forwarded_proto = "http") {` / `return 301 https://$host$request_uri;` / `}` | HTTP → HTTPS when **another** proxy or CDN in front says the visitor used HTTP. | EXPR | `http = "redirect"` with `[server] trusted_proxies = [...]` (redirects.md 2.4: X-Forwarded-Proto is believed only from trusted proxies). The nginx example trusts it from anyone. |
| [R#L552](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/reverse-proxy.md#L552), nginx `server`, **commented out** | `#add_header Alt-Svc 'h3=":443"; ma=86400'; # uncomment to enable HTTP/3 / QUIC - supported on nginx v1.25.0+` | Advertise HTTP/3. | OTHER (the name is refused) | `[server] protocols` with `"h3"`; agensio sends `alt-svc` itself |
| [R#L922-L929](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/reverse-proxy.md#L922-L929) (Traefik 2) and [R#L1019-L1026](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/reverse-proxy.md#L1019-L1026) (Traefik 3), middleware `nextcloud-secure-headers` | `headers: hostsProxyHeaders: - "X-Forwarded-Host"` / `referrerPolicy: "same-origin"` / `customRequestHeaders: X-Forwarded-Proto: "https"` | `referrerPolicy` sets a response header. `hostsProxyHeaders` tells Traefik's allowed-hosts check to read X-Forwarded-Host (a request-side setting). `customRequestHeaders` is a request field. | `referrerPolicy`: EXPR. The other two: OTHER. | `[[site.response_headers]] path = "/"` with `default = { "Referrer-Policy" = "same-origin" }`. Use **`default`**, not `set`, so Nextcloud's own policy stays (`.htaccess`: `no-referrer`, and `same-origin` on `/login`). `same-origin` passes Nextcloud's setup check. In practice nothing is needed. X-Forwarded-Proto is automatic. `hostsProxyHeaders` has no equivalent and none is needed. |
| [R#L931-L940](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/reverse-proxy.md#L931-L940) (Traefik 2) and [R#L1028-L1037](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/reverse-proxy.md#L1028-L1037) (Traefik 3) | `https-redirect:` / `redirectscheme:` / `scheme: https` | HTTP → HTTPS. Traefik's default without `permanent` is 302 (inferred from Traefik's defaults). | EXPR | `http = "redirect"` (308) |
| [R#L1084-L1090](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/reverse-proxy.md#L1083-L1090), IIS `web.config` | `<rule name="Https" stopProcessing="true">` / `<match url="(.*)" />` / `<add input="{HTTPS}" pattern="^OFF$" />` / `<action type="Redirect" url="https://{HTTP_HOST}/{REQUEST_URI}" appendQueryString="false" />` | "Force https". | EXPR | `http = "redirect"` |
| [R#L705-L711](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/reverse-proxy.md#L705-L711), Node `http-proxy` | `autoRewrite: true,` / `// Do not enable followRedirects.` / `followRedirects: false,` | Rewrite the host and port of Location on redirects. | OTHER | `proxy = { redirects = "rewrite" }`, the default |
| [R#L617](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/reverse-proxy.md#L617) and [#L620-L621](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/reverse-proxy.md#L620-L621), NPMplus prose | "Disable URI Sanitisation ... may need to be enabled if you use Collabora"; "Send noindex header ..."; "change the X-Frame-Options header if you want to embed Nextcloud" | Advice. Nextcloud already sends `X-Robots-Tag: noindex, nofollow`. | Embedding: EXPR in part | Embedding Nextcloud elsewhere would need `[[site.response_headers]] path = "/"` with `remove = ["X-Frame-Options"]`. **Inferred**: Nextcloud's own per-response CSP (see 19c) probably also carries `frame-ancestors 'self'`, so embedding needs a change in the app as well. Not verified. |

AIO's inner layer, for context. It explains why the outer proxy needs no `.well-known` redirects and no headers.

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML, or what is missing |
|---|---|---|---|---|
| [K/Caddyfile#L35-L41](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/Containers/apache/Caddyfile#L35-L41), site block `{$PROTOCOL}://{$NC_DOMAIN}:{$APACHE_PORT}`, which is also the block behind an external proxy | `header {` / `Strict-Transport-Security max-age=31536000;` / `-Server` / `-X-Powered-By` / `-Via` / `}` | AIO always sends HSTS of one year without includeSubDomains, and strips the version-revealing fields. | OTHER (sent by the app container) | Nothing is needed. If the site sets `hsts`, agensio replaces AIO's value. If not, AIO's passes through on HTTPS answers. The equivalent in agensio would be `hsts = true`, `[server] server_header`, `remove = ["X-Powered-By", "Via"]`, and the baseline already strips X-Powered-By. |
| [K/Caddyfile#L101-L102](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/Containers/apache/Caddyfile#L101-L102) | `redir /.well-known/carddav /remote.php/dav/ 301` / `redir /.well-known/caldav /remote.php/dav/ 301` | CalDAV/CardDAV service discovery (RFC 6764), done **inside AIO**. | OTHER for the outer proxy; EXPR if needed | Nothing on agensio in front of AIO. On its own it would be two `[[site.redirect]]` rules: `from = "/.well-known/carddav"`, `match = "exact"`, `to = "/remote.php/dav/"`, `status = 301`, and the same for `caldav`. |
| [K/nextcloud.conf#L20-L29](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/Containers/apache/nextcloud.conf#L20-L29) | `AllowOverride All` | Nextcloud's `.htaccess` applies inside AIO, so its security headers, its well-known rewrites and its DavClnt redirect are all active (19c). | OTHER | Nothing to configure. |

### 19b. Other directives in the AIO outer examples (existing features)

- **Encoded slashes.** Apache `AllowEncodedSlashes NoDecode` (L222) with `ProxyPass / http://localhost:11000/ nocanon upgrade=websocket` (L225); Traefik 3 `encodedCharacters: allowEncodedSlash / allowEncodedQuestionMark / allowEncodedPercent: true` (L976-980: "Required for Nextcloud to correctly handle encoded URL characters (%2F, %3F and %25)"); IIS `useOriginalURLEncoding="false"`, `{UNENCODED_URL}` (L1082, L1098); NPMplus "Disable URI Sanitisation" (L617). agensio already does this: a proxied application gets the raw target (CLAUDE.md, alpha.45). `encoded_slashes` only matters for filesystem locations.
- **WebSocket.** `upgrade=websocket` (L225), the legacy `RewriteRule .? "ws://localhost:11000/%1" [P,L,NE,UnsafeAllow3F]` (L273-276), nginx `map $http_upgrade $connection_upgrade` (L518-521) and `Upgrade`/`Connection` (L582-584) → automatic.
- **Body size and buffering.** `LimitRequestBody 0` (L254), `client_max_body_size 0;` (L565, NPM L657, "0 means unlimited"), `proxy_buffering off; proxy_request_buffering off;` (L562-563), IIS `maxAllowedContentLength="2147483648"` (L1105) → `max_body_size` (**unverified**: whether unlimited is accepted) and `proxy = { buffering = false, request_buffering = false }`.
- **Timeouts.** `Timeout 3610` / `ProxyTimeout 3610` (L259-260), `proxy_read_timeout 3610s;` (L570, NPM L655), Traefik `readTimeout: 3610s` (L879, L974), Node `timeout`/`proxyTimeout: 1000 * 3610` (L705-706). The comment: "default NEXTCLOUD_MAX_TIME value is 3600 seconds ... so that always Nextcloud times out". → `proxy = { read_timeout = 3610 }` and `body_timeout`.
- **Request fields.** `ProxyPreserveHost On` (L218), `RequestHeader set X-Real-IP %{REMOTE_ADDR}s` (L219), `RequestHeader set X-Forwarded-Proto "https"` (L221, "Added to support Euro-office"), and nginx `Host $host; X-Forwarded-Host $host; X-Forwarded-Proto $scheme; X-Real-IP $remote_addr; X-Forwarded-For ...` (L575-579). agensio passes Host and sets X-Forwarded-For and X-Forwarded-Proto. Add `proxy = { headers = { "X-Real-IP" = "$remote_addr" } }` if wanted.
- **HTTP/2.** `Protocols h2 h2c http/1.1` (L229) and `H2WindowSize 5242880` (L232, "Solves slow upload speeds caused by http2"). agensio has server-wide `protocols`; its receive windows are derived from `max_body_size` (configuration.md 16).
- **Methods and files.** `TraceEnable off` (L248): agensio answers 405 to TRACE on static sites; **unverified** for proxy locations. `<Files ".ht*"> Require all denied </Files>` (L249-251) → `refuse` or hidden files.
- **ACME.** HAProxy `acl ... path_beg -i /.well-known/acme-challenge/` with `use_backend acme_challenge_backend` (L411-L435) → agensio's built-in ACME.
- **AIO interface.** Caddy `https://<your-nc-domain>:8443 { reverse_proxy https://localhost:8080 { header_up Host {host} transport http { tls_insecure_skip_verify } } }` (L1240-1248) → a second site with `upstream = "https://localhost:8080"` and `proxy = { tls = { verify = false } }`. L1215 warns: "do always use an ip-address if you access this port and not a domain as HSTS might block access to it later".

### 19c. Nextcloud server's own nginx sample (admin manual `stable35`): what Nextcloud expects from any server in front of PHP

This is context: on AIO, Nextcloud's `.htaccess` does all of it inside the container. It shows what agensio would need to run Nextcloud directly on a PHP preset (`app = "php"`).

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML, or what is missing |
|---|---|---|---|---|
| [N/installation/nginx-root.conf.sample#L25-L26](https://github.com/nextcloud/documentation/blob/c02abf851cf492c0914d49ce0469b1f8b681a646/admin_manual/installation/nginx-root.conf.sample#L25-L26), `server` 80 | `return 301 https://$server_name$request_uri;` | "Enforce HTTPS". `$server_name` is the first `server_name`, so it also canonicalises. | EXPR | `http = "redirect"`, plus `canonical = "cloud.example.com"` if there are several names. |
| [N/.../nginx-root.conf.sample#L49-L55](https://github.com/nextcloud/documentation/blob/c02abf851cf492c0914d49ce0469b1f8b681a646/admin_manual/installation/nginx-root.conf.sample#L49-L55) (server) and [#L229-L235](https://github.com/nextcloud/documentation/blob/c02abf851cf492c0914d49ce0469b1f8b681a646/admin_manual/installation/nginx-root.conf.sample#L229-L235) (static location), **commented out** | `#add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;` | HSTS. The comment: "WARNING: Only add the preload option once you read about the consequences in https://hstspreload.org/ ... getting removed from this list could take several months." | EXPR without preload; preload is NOT-OFFERED | `hsts = { max_age = "1y", subdomains = true }`. Nextcloud's setup check wants at least **15552000** seconds ([V/apps/settings/lib/SetupChecks/SecurityHeaders.php#L99-L110](https://github.com/nextcloud/server/blob/3c012e618ab46ac73c61a96f5bb7168a693ca1fb/apps/settings/lib/SetupChecks/SecurityHeaders.php#L99-L110)), so `hsts = true` (31536000) passes. |
| [N/.../nginx-root.conf.sample#L87-L92](https://github.com/nextcloud/documentation/blob/c02abf851cf492c0914d49ce0469b1f8b681a646/admin_manual/installation/nginx-root.conf.sample#L87-L92), `server` 443 | `add_header Referrer-Policy "no-referrer" always;` / `add_header X-Content-Type-Options "nosniff" always;` / `add_header X-Frame-Options "SAMEORIGIN" always;` / `add_header X-Permitted-Cross-Domain-Policies "none" always;` / `add_header X-Robots-Tag "noindex, nofollow" always;` | "HTTP response headers borrowed from Nextcloud `.htaccess`". | EXPR | `[[site.response_headers]] path = "/"` with `set = { "Referrer-Policy" = "no-referrer", "X-Content-Type-Options" = "nosniff", "X-Frame-Options" = "SAMEORIGIN", "X-Permitted-Cross-Domain-Policies" = "none", "X-Robots-Tag" = "noindex, nofollow" }`. The setup check expects each of these exact values (SecurityHeaders.php L49-54; `deny` is accepted for X-Frame-Options with a warning, and Referrer-Policy may be any of `no-referrer`, `no-referrer-when-downgrade`, `strict-origin`, `strict-origin-when-cross-origin` or `same-origin`, L78-79). The `.htaccess` gives `/login` the value `same-origin` ([V/.htaccess#L21-L29](https://github.com/nextcloud/server/blob/3c012e618ab46ac73c61a96f5bb7168a693ca1fb/.htaccess#L21-L29), the regex `m#/login$#`). Expressible as exact rules for `/login` and `/index.php/login` with `set = { "Referrer-Policy" = "same-origin" }`. A suffix match ("any path ending in /login") is not offered; **inferred** that those two paths are the real login URLs. Note `fastcgi_param modHeadersAvailable true` at L202 ("Avoid duplicate security headers"); see "Other directives". |
| [N/.../nginx-root.conf.sample#L94-L95](https://github.com/nextcloud/documentation/blob/c02abf851cf492c0914d49ce0469b1f8b681a646/admin_manual/installation/nginx-root.conf.sample#L94-L95) | `fastcgi_hide_header X-Powered-By;` | "Remove X-Powered-By, which is an information leak". | EXPR (baseline) | The preset baseline removes `X-Powered-By` from app answers. Explicitly: `remove = ["X-Powered-By"]`. |
| [N/.../nginx-root.conf.sample#L120-L124](https://github.com/nextcloud/documentation/blob/c02abf851cf492c0914d49ce0469b1f8b681a646/admin_manual/installation/nginx-root.conf.sample#L119-L124), `location = /` | `if ( $http_user_agent ~ ^DavClnt ) {` / `return 302 /remote.php/webdav/$is_args$args;` / `}` | "Rule borrowed from `.htaccess` to handle Microsoft DAV clients". `.htaccess` L108-114: DavClnt sends OPTIONS to `/`, so redirect it to the DAV endpoint. | CHANGE, or NOT-OFFERED | There is no condition on a request header (User-Agent). The smallest change would be a `user_agent_prefix` condition on an exact rule, which the design rules out by intent. Without it, a Windows WebDAV mini-redirector pointed at the bare site URL gets the login page. Giving it the full `/remote.php/dav/files/USER/` URL works (inferred). AIO is unaffected, because its inner `.htaccess` does this. |
| [N/.../nginx-root.conf.sample#L136-L141](https://github.com/nextcloud/documentation/blob/c02abf851cf492c0914d49ce0469b1f8b681a646/admin_manual/installation/nginx-root.conf.sample#L136-L141), `location ^~ /.well-known` | `location = /.well-known/carddav { return 301 /remote.php/dav/; }` / `location = /.well-known/caldav  { return 301 /remote.php/dav/; }` | CalDAV/CardDAV discovery. The setup check sends PROPFIND to both and expects a redirect that ends at `/remote.php/dav` ([V/apps/settings/lib/SetupChecks/WellKnownUrls.php#L50-L72](https://github.com/nextcloud/server/blob/3c012e618ab46ac73c61a96f5bb7168a693ca1fb/apps/settings/lib/SetupChecks/WellKnownUrls.php#L50-L72)). | EXPR | `[[site.redirect]]` with `from = "/.well-known/carddav"`, `match = "exact"`, `to = "/remote.php/dav/"`, `status = 301`, `query = "drop"` (nginx's `return` drops the query); the same for `caldav`. Redirect rules have no method condition, so PROPFIND is redirected too, which is what the check needs. |
| [N/.../nginx-root.conf.sample#L143-L148](https://github.com/nextcloud/documentation/blob/c02abf851cf492c0914d49ce0469b1f8b681a646/admin_manual/installation/nginx-root.conf.sample#L143-L148), `location ^~ /.well-known` | `location /.well-known/acme-challenge    { try_files $uri $uri/ =404; }` / `location /.well-known/pki-validation    { try_files $uri $uri/ =404; }` / `return 301 /index.php$request_uri;` | "Let Nextcloud's API for `/.well-known` URIs handle all other requests by passing them to the front-end controller": webfinger, nodeinfo and others (the setup check, L51-52, expects the `X-NEXTCLOUD-WELL-KNOWN` header). | EXPR as a redirect, with a gap. OTHER is better. | As a redirect: `[[site.redirect]]` with `from = "/.well-known"`, `to = "/index.php/.well-known"`, `status = 301`, keeping the remainder and the query by default (`/.well-known/webfinger?resource=x` becomes `/index.php/.well-known/webfinger?resource=x`). ACME is answered first anyway. **Gap**: there is no way to exempt `/.well-known/pki-validation` from a prefix redirect (no "pass" rule). The smallest change would be a rule with no target that ends redirect processing. **Better**: Nextcloud's own `.htaccess` does this as an **internal rewrite**, not a redirect ([V/.htaccess#L153](https://github.com/nextcloud/server/blob/3c012e618ab46ac73c61a96f5bb7168a693ca1fb/.htaccess#L144-L153): `RewriteRule ^\.well-known/(?!acme-challenge|pki-validation) /index.php [L]`). In agensio that is the front controller (`try_files = ["$uri", "$uri/", "/index.php$request_uri"]`, or `rules.front_controller = "/index.php"`): a real file under pki-validation is served, and anything else reaches index.php. No redirect is needed. |
| [N/.../nginx-root.conf.sample#L226-L245](https://github.com/nextcloud/documentation/blob/c02abf851cf492c0914d49ce0469b1f8b681a646/admin_manual/installation/nginx-root.conf.sample#L225-L245), `location ~ \.(?:css\|js\|mjs\|svg\|gif\|ico\|jpg\|png\|webp\|wasm\|tflite\|map\|ogg\|flac\|mp4\|webm)$` | `add_header Cache-Control "public, max-age=15778463$asset_immutable";`, with [L11-L15](https://github.com/nextcloud/documentation/blob/c02abf851cf492c0914d49ce0469b1f8b681a646/admin_manual/installation/nginx-root.conf.sample#L11-L15) `map $arg_v $asset_immutable { "" ""; default ", immutable"; }` | Six-month caching of static assets, and `immutable` only for cache-busted URLs carrying `?v=`. The `.htaccess` equivalent is [V/.htaccess#L46-L54](https://github.com/nextcloud/server/blob/3c012e618ab46ac73c61a96f5bb7168a693ca1fb/.htaccess#L46-L54): `<FilesMatch "\.(css\|js\|mjs\|svg\|gif\|png\|jpg\|webp\|ico\|wasm\|tflite)$">`, then `<If "%{QUERY_STRING} =~ /(^\|&)v=/">` `Header set Cache-Control "max-age=15778463, immutable"`, else `"max-age=15778463"`. | CHANGE | Two things are missing from `[[site.response_headers]]`: **(a)** a condition on file extension (the rules are path-only); **(b)** a condition on a query parameter (`v`), with no variables. Today's workaround is an existing feature: one `[[site.location]]` per extension with `path = ".css"`, `match = "suffix"`, `try_files = ["$uri", "/index.php$request_uri"]` and `add_headers = { "Cache-Control" = "public, max-age=15778463" }`. A hand-written site may use suffix locations (`config.cpp` L470-483 only requires a leading dot). **Unverified**: the router's precedence between these and `/` and other prefix locations. Without `immutable` the assets still revalidate rarely. The **smallest change** for (a) is a `suffixes = [".css", ...]` filter on a response_headers rule (with `when = "success"`). (b) could be dropped (keep `immutable` out) at a small cost. |
| [N/.../nginx-root.conf.sample#L247-L251](https://github.com/nextcloud/documentation/blob/c02abf851cf492c0914d49ce0469b1f8b681a646/admin_manual/installation/nginx-root.conf.sample#L247-L251), `location ~ \.(otf\|woff2?)$` | `expires 7d;         # Cache-Control policy borrowed from \`.htaccess\`` | One-week font caching (sets Expires and `Cache-Control: max-age=604800`; `.htaccess` L56-59 sets `Header set Cache-Control "max-age=604800"`). | CHANGE (extension condition), as above | Same workaround: suffix locations `.otf`, `.woff`, `.woff2` with `add_headers = { "Cache-Control" = "max-age=604800" }`. In nginx this location defines no `add_header`, so it inherits the five security headers from the server level; in agensio site-wide response headers apply anyway. |
| [N/.../nginx-root.conf.sample#L253-L256](https://github.com/nextcloud/documentation/blob/c02abf851cf492c0914d49ce0469b1f8b681a646/admin_manual/installation/nginx-root.conf.sample#L253-L256), `location /remote` | `return 301 /remote.php$request_uri;` | "Rule borrowed from `.htaccess`" (L129-135, where it is an internal rewrite, "XXX: Is this even used anymore? Seems a relic from <NC12"). `$request_uri` keeps `/remote/...`, so `/remote/x` becomes `/remote.php/remote/x`. | EXPR | `[[site.redirect]]` with `from = "/remote"`, `to = "/remote.php/remote"`, `status = 301`, keeping remainder and query. agensio's segment matching does not catch `/remoteXYZ` as nginx's string prefix does; that is harmless. `/remote.php/...` is not caught (different segment). |
| [N/configuration_server/reverse_proxy_configuration.rst#L56-L163](https://github.com/nextcloud/documentation/blob/c02abf851cf492c0914d49ce0469b1f8b681a646/admin_manual/configuration_server/reverse_proxy_configuration.rst#L56-L163), "Service Discovery" | Apache: `RewriteRule ^/\.well-known/carddav https://%{SERVER_NAME}/remote.php/dav/ [R=301,L]` (and caldav, L67-68). Traefik 1 and 2: `redirectregex.regex=https://(.*)/.well-known/(?:card\|cal)dav` / `replacement=https://$${1}/remote.php/dav` (L78-80, L98-101, L106-110). HAProxy: `acl url_discovery path /.well-known/caldav /.well-known/carddav` / `http-request redirect location /remote.php/dav/ code 301 if url_discovery` (L116-117). nginx: `location /.well-known/carddav { return 301 $scheme://$host/remote.php/dav; }`, the same for caldav, and `location ^~ /.well-known { return 301 $scheme://$host/index.php$uri; }` (L124-134). Caddy: `redir /.well-known/carddav /remote.php/dav/ 301` (L144-145). Pomerium: `path_redirect: /remote.php/dav/` (L155-161). | "The redirects for CalDAV or CardDAV does not work if Nextcloud is running behind a reverse proxy. The recommended solution is that your reverse proxy does the redirects." (L59-60). This is for setups whose inner server does not redirect; AIO's does. | EXPR | `[[site.redirect]]` with `from = "/.well-known/carddav"`, `to = "/remote.php/dav/"`, `status = 301`, `remainder = "drop"` (the Apache and nginx forms are prefix matches that drop the rest); the same for caldav. The regex captures only the host, which a relative `to` keeps. The nginx catch-all `return 301 $scheme://$host/index.php$uri` uses `$uri`, which drops the query (inferred: that breaks `webfinger?resource=`). agensio's prefix rule `from = "/.well-known"`, `to = "/index.php/.well-known"` keeps the query by default, but has the pki-validation gap described above. |

### 19d. Other directives in Nextcloud's nginx sample (existing features)

- **Body and timeouts.** `client_max_body_size 512M; client_body_timeout 300s; fastcgi_buffers 64 4K; client_body_buffer_size 512k;` (L58-60, L85) → `max_body_size`, `body_timeout`, and the FastCGI buffering keys.
- **gzip.** `gzip on; gzip_vary on; ... gzip_types ...` (L71-76). **Not offered**: agensio does no compression on the fly, only pre-compressed twins.
- **MIME types.** `include mime.types; types { text/javascript mjs; application/wasm wasm; }` (L101-105) → OTHER: agensio's built-in MIME table already has `mjs` → `text/javascript; charset=utf-8` and `wasm` → `application/wasm` (`src/mime.cpp` L29, L36). Content-Type is refused in header rules.
- **Index and fallback.** `index index.php index.html /index.php$request_uri;` (L117) and `location / { try_files $uri $uri/ /index.php$request_uri; }` (L258-260) → `index` and `try_files`, or the front controller.
- **Hidden paths.** `return 404;` for `^/(?:build|tests|config|lib|3rdparty|templates|data)(?:$|/)`, `^/(?:\.|autotest|occ|issue|indie|db_|console)` and metadata files (L152-157) → `refuse = ["/build/", "/tests/", "/config/", "/lib/", "/3rdparty/", "/templates/", "/data/", "/autotest*", "/occ*", "/issue*", "/indie*", "/db_*", "/console*", "/composer.json", "/composer.lock", "/package.json", "/package-lock.json", "/core/shipped.json"]`, plus hidden files for the dot paths.
- **Front controller.** `rewrite ^/(?!index|remote|public|cron|status|ocs\/v[12]|ocs-provider\/.+|core\/ajax\/update|updater\/.+|.+\/richdocumentscode(_arm64)?\/proxy) /index.php$request_uri;` (L181) is an internal rewrite, not a redirect → `rules.entry_points` and `front_controller`. The `.+/richdocumentscode(_arm64)?/proxy` pattern lies under any app directory; **unverified** whether entry_points can express it.
- **FastCGI.** `fastcgi_split_path_info`, `try_files $fastcgi_script_name =404`, PATH_INFO (L189-194): agensio's suffix handling with PATH_INFO. `fastcgi_param HTTPS on; modHeadersAvailable true; front_controller_active true;` (L201-203): the last two are Nextcloud-specific FastCGI parameters. I found **no key for extra FastCGI parameters** in `docs/keys.md` or `configuration.md`. That is outside the redirect and header scope, but `front_controller_active` is what makes Nextcloud generate pretty URLs. `fastcgi_intercept_errors on;` (L207). `fastcgi_request_buffering on; fastcgi_max_temp_file_size 0;` (L211, L222) → `request_buffering` and `buffering`.
- **robots.txt.** `location = /robots.txt { allow all; log_not_found off; access_log off; }` (L126-130) is static.

### App guidance (Nextcloud and AIO)

- **.well-known.**
  - Behind AIO, the outer proxy needs **no** `.well-known` handling. AIO's inner Caddy redirects caldav and carddav (Caddyfile L101-102), and the inner Apache `.htaccess` sends every other `/.well-known/*` to `index.php` (L153).
  - agensio forwards everything except `/.well-known/acme-challenge/`, which it answers itself.
  - **Unverified**: whether agensio's hidden-files policy applies to proxy locations. It allows a leading `/.well-known/` anyway since alpha.70.
  - Nextcloud handles webfinger and nodeinfo itself (`lib/private/Http/WellKnown/RequestManager.php`) and marks them with `X-NEXTCLOUD-WELL-KNOWN`.
  - change-password and security.txt are not mentioned in any of these files.
- **HSTS.**
  - AIO sends `max-age=31536000;` itself (Caddyfile L36).
  - The manual's nginx sample has `max-age=31536000; includeSubDomains; preload`, commented out with a warning about preload.
  - The setup check wants a max-age of at least 15552000.
  - None of the outer AIO examples sets HSTS.
- **CSP.** Nextcloud sends its **own** `Content-Security-Policy` (and `Feature-Policy`, `X-Robots-Tag`, `Cache-Control: no-cache, no-store, must-revalidate`) on every AppFramework response ([V/lib/public/AppFramework/Http/Response.php#L228-L234](https://github.com/nextcloud/server/blob/3c012e618ab46ac73c61a96f5bb7168a693ca1fb/lib/public/AppFramework/Http/Response.php#L228-L234)). It is per page, with nonces. **A proxy must not `set` a CSP.** `default` would only reach answers without one.
- **Frame fields.**
  - Nextcloud sends `X-Frame-Options: SAMEORIGIN` (`.htaccess` L34-35, `always`).
  - The setup check expects `sameorigin`; `deny` is accepted with a warning.
  - To embed Nextcloud in another site, the proxy would have to remove the field (NPMplus note, L621), and the app's CSP would also have to allow it (inferred).
- **Referrer-Policy.** `no-referrer`, and `same-origin` on `/login`. The check accepts `strict-origin-when-cross-origin`. agensio's baseline `default` never overrides Nextcloud's.
- **CORS.** None at the proxy.
- **Trusting the proxy.**
  - AIO's inner Caddy trusts `private_ranges 100.64.0.0/10` when `APACHE_PORT != 443` ([K/start.sh#L59-L66](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/Containers/apache/start.sh#L59-L66)).
  - When the proxy connects "not using localhost nor 127.0.0.1", add its IP to Nextcloud's `trusted_proxies` with `occ config:system:set trusted_proxies 2 --value=ip.address.of.proxy` ([R#L1218-L1225](https://github.com/nextcloud/all-in-one/blob/2599cb62878a59a5186655353afc0f379d51854f/reverse-proxy.md#L1218-L1225)), and to Collabora's WOPI allow list (L1227-1230).
  - The plain-Nextcloud manual: `trusted_proxies`, `forwarded_for_headers`, `overwriteprotocol`, `overwritehost`, `overwritewebroot`, `overwritecondaddr` (reverse_proxy_configuration.rst L11-54).
- **Subpath.** AIO only works on its own hostname ("You cannot run it in a subfolder like `example.com/nextcloud/`", reverse-proxy.md L69-70).
- **The `Upgrade` field.** The manual (rst L136-137) says that with NGINX Proxy Manager, `proxy_hide_header Upgrade;` is needed, "otherwise mobile devices (iPad, iPhone etc.) will simply receive the Error Message 'Connection Closed'". Inferred cause: Apache's `Upgrade: h2,h2c` response field reaching an HTTP/2 client. In agensio `Upgrade` is a framing field that header rules refuse. `proxy = { hide = ["Upgrade"] }` could carry it. **Unverified**: whether agensio already drops an origin's `Upgrade` on a non-101 answer (RFC 9113 8.2.2 forbids it over h2).

---

## 20. Paperless-ngx

**Version read**
- Tag `v3.3.1`, commit `c4d1b0c7325ea8782d87c64b6738ac39d313df2e`, released 2026-10-12.
- GitHub wiki page "Using a Reverse Proxy with Paperless ngx" at revision `77c2b65c84d5baf4472a5309d3a2c25dfd0ade03` (last edited 2026-09-29), read from a clone of the wiki whose head is `5e8970189c0460cfa961f8b894cf10a7044d81d1` (2026-10-09).

**Status of the wiki.** The official docs link to the wiki and call it "user-maintained documentation" (`docs/setup.md` L665-667; also L406-409). The docs themselves publish **no** proxy configuration. Everything in the table comes from the wiki: the project hosts it, but it is community-maintained, not code-reviewed (for example the Caddy CORS block says "Gemini fixed some logic mistakes").

**Sources**
- The wiki page.
- `docs/configuration.md`, `docs/setup.md`.
- `src/paperless/settings/__init__.py`, `src/paperless/urls.py`.

Base URLs for the links below:
- `W` = `https://github.com/paperless-ngx/paperless-ngx/wiki/Using-a-Reverse-Proxy-with-Paperless-ngx/77c2b65c84d5baf4472a5309d3a2c25dfd0ade03`. Revision link; line numbers refer to the raw `.md` at that revision.
- `P` = `https://github.com/paperless-ngx/paperless-ngx/blob/c4d1b0c7325ea8782d87c64b6738ac39d313df2e`

### Directives that redirect or set headers

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML, or what is missing |
|---|---|---|---|---|
| W L23-L40, nginx `location ~ ^/accounts/(signup\|login\|2fa)/` | `proxy_hide_header Referrer-Policy;` / `add_header Referrer-Policy "same-origin" always;` | The wiki's comment: "Referrer-Policy: no-referrer everywhere except the login page, which needs same-origin so Django's CSRF check gets a real Origin header instead of 'null' on the login POST". `2fa` was added 2026-09-29 (commit 77c2b65: "CSRF Verification Failed" after TOTP). | EXPR | Three rules: `[[site.response_headers]]` with `path = "/accounts/login"` and `set = { "Referrer-Policy" = "same-origin" }`; the same for `path = "/accounts/signup"` and `path = "/accounts/2fa"`. `set` replaces the app's copy, which is the same as nginx's hide plus add. agensio's prefix also matches the bare segment without the trailing `/`; that is harmless. |
| W L60-L61, nginx `location /` | `proxy_hide_header Referrer-Policy;` / `add_header Referrer-Policy "no-referrer" always;` | A stricter privacy default than Django's own `same-origin`. | EXPR | `[[site.response_headers]] path = "/"` with `set = { "Referrer-Policy" = "no-referrer" }`. The three longer rules above win for their paths, since the longest path decides per field. **Without any rule, agensio needs nothing**: Django sends `same-origin`, and the baseline is only a default. |
| W L85, prose | "Some have found adding the P3P header (`add_header P3P 'CP=""';` ...) works; only IE and Edge support it." | A legacy IE/old-Edge cookie policy (issue #817). | EXPR, but obsolete | `set = { "P3P" = "CP=\"\"" }`. Not worth offering. |
| W L158-L160, Apache `<VirtualHost *:80>` | `RewriteEngine On` / `RewriteCond %{REQUEST_URI} !^/\.well\-known/acme\-challenge/` / `RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]` | HTTP → HTTPS, except ACME. | EXPR | `http = "redirect"`. ACME is exempt by design. |
| W L187, Apache `<VirtualHost *:443>` | `Header always set Strict-Transport-Security "max-age=15552000; preload"` | HSTS, 180 days, with preload. | EXPR for max-age; preload is NOT-OFFERED | `hsts = { max_age = "180d" }`. Preload is not offered, and without `includeSubDomains` and a max-age of at least a year this value would not even qualify for the preload list (hstspreload.org's rules; inferred, not checked today). |
| W L188 | `Header always set X-Content-Type-Options nosniff` | nosniff | EXPR | `set = { "X-Content-Type-Options" = "nosniff" }`. Django already sends it by default (`SecurityMiddleware` is enabled at [P/src/paperless/settings/__init__.py#L191](https://github.com/paperless-ngx/paperless-ngx/blob/c4d1b0c7325ea8782d87c64b6738ac39d313df2e/src/paperless/settings/__init__.py#L191); `SECURE_CONTENT_TYPE_NOSNIFF` is a Django default and is not overridden here). |
| W L189 | `Header always set X-Robots-Tag none` | Keep crawlers out (inferred). | EXPR | `set = { "X-Robots-Tag" = "none" }` |
| W L190 | `Header always set X-XSS-Protection "1; mode=block"` | Legacy XSS filter. | EXPR, with the design's warning | `set = { "X-XSS-Protection" = "1; mode=block" }`. The design warns on anything but `0`. |
| W L191 | `Header always set X-Frame-Options "SAMEORIGIN"` | Clickjacking. | EXPR | `set = { "X-Frame-Options" = "SAMEORIGIN" }`. Paperless already sends it: `X_FRAME_OPTIONS = "SAMEORIGIN"`, commented "X-Frame options for embedded PDF display" ([P/.../settings/__init__.py#L424-L425](https://github.com/paperless-ngx/paperless-ngx/blob/c4d1b0c7325ea8782d87c64b6738ac39d313df2e/src/paperless/settings/__init__.py#L424-L425)). |
| W L197-L204 | `<If "%{REQUEST_URI} =~ m#^/accounts/login/#">` / `Header onsuccess unset Referrer-Policy` / `Header always set Referrer-Policy "same-origin"` / `</If>` / `<Else>` / `Header onsuccess unset Referrer-Policy` / `Header always set Referrer-Policy "no-referrer"` / `</Else>` | The same split as nginx, but only `/accounts/login/` (no signup or 2fa). The "onsuccess unset + always set" form is explained at L192-196 and L401-406 (Apache's two header tables). | EXPR | The rules above. agensio has a single resolved field, so the table-split trap does not exist (headers.md 2.2-2.3). |
| W L207 | `Header always set Content-Security-Policy "default-src 'none'; base-uri 'self'; font-src 'self' data: ${public_url}; media-src 'self' blob: data: https: ${public_url}; script-src 'self' 'unsafe-inline' ${public_url}; style-src 'self' 'unsafe-inline' ${public_url}; img-src 'self' data: blob: https: ${public_url}; worker-src * blob:; frame-src 'self' https://${public_url}; connect-src 'self' wss: https: ${public_url}; form-action 'self'; frame-ancestors 'self' https://${public_url} https://my.domain https://*.my.domain; manifest-src 'self'; object-src 'self' https://${public_url}"` | "Lax CSP ... won't need to be updated with version changes" (L206). `${public_url}` is an Apache `Define`, substituted at load. | EXPR (fixed text after substitution, about 700 bytes) | `default = { "Content-Security-Policy" = "default-src 'none'; base-uri 'self'; ... object-src 'self' https://paperless.my.domain" }`, with the host written literally. Paperless sends no CSP of its own (no CSP middleware at settings L191-202), so `default` behaves like `set`. |
| W L208 | `Header always set Permissions-Policy 'geolocation=(self "https://${public_url}"), midi=(self "https://${public_url}"), sync-xhr=(self "https://${public_url}"), microphone=(self "https://${public_url}"), camera=(self "https://${public_url}"), magnetometer=(self "https://${public_url}"), gyroscope=(self "https://${public_url}"), fullscreen=(self "https://${public_url}"), payment=(self "https://${public_url}")'` | Feature lockdown. | EXPR (fixed text) | `set = { "Permissions-Policy" = "geolocation=(self \"https://paperless.my.domain\"), ..." }` |
| W L232 | `ErrorDocument 503 '<!DOCTYPE html>...<meta http-equiv="refresh" content="15" />...'` | A custom "offline" page when Paperless is down, which reloads every 15 s. | OTHER, partly | Not a header rule. agensio answers 502/503/504 itself; **unverified** whether a custom error page body is configurable. The refresh is a `<meta>` in the body, not the `Refresh` header that the design refuses. |
| W L245-L255, Caddy `:80` site | `@login path /accounts/login/` / `reverse_proxy @login http://localhost:8000 { header_down Referrer-Policy "same-origin" }` / `@signup path /accounts/signup/` / `reverse_proxy @signup ... { header_down Referrer-Policy "same-origin" }` / `reverse_proxy http://localhost:8000 { header_down Referrer-Policy "no-referrer" }` | The same split, with exact paths. | EXPR | The same rules. Caddy's `path /accounts/login/` is exact; agensio's prefix rule is a superset, which is harmless. Or use `match = "exact"` with `/accounts/login/` (**unverified** whether a trailing slash is kept in an exact rule). |
| W L272-L283, Caddy snippet `(common)` | `header {` / `Strict-Transport-Security "max-age=31536000; includeSubdomains"` / `X-XSS-Protection 0` / `X-Content-Type-Options nosniff` / `-Server` / `X-Frame-Options "ALLOW-FROM *.example.domain"` / `Permissions-Policy "geolocation=(self  *.example.domain), microphone=(), interest-cohort=()"` / `import content-security-general` / `}` | General hardening. | Mixed, one class per field below | |
| ↳ L274 | `Strict-Transport-Security "max-age=31536000; includeSubdomains"` | HSTS | EXPR | `hsts = { max_age = "1y", subdomains = true }` |
| ↳ L275, L277 | `X-XSS-Protection 0`, `X-Content-Type-Options nosniff` | | EXPR | `set = { "X-XSS-Protection" = "0", "X-Content-Type-Options" = "nosniff" }` |
| ↳ L278 | `-Server` | Hide the server banner. | OTHER (the name is refused in rules) | `[server] server_header = ""`, server-wide |
| ↳ L280 | `X-Frame-Options "ALLOW-FROM *.example.domain"` | Allow framing from the parent domain. It conflicts with the app's own `SAMEORIGIN`. | NOT-OFFERED | `ALLOW-FROM` is refused because browsers ignore it. Its working equivalent is the CSP below (`frame-ancestors`) plus `remove = ["X-Frame-Options"]`. The app works without it. |
| ↳ L281 | `Permissions-Policy "geolocation=(self  *.example.domain), microphone=(), interest-cohort=()"` | | EXPR | fixed text |
| ↳ L286-L289, `(content-security-general)` | `Content-Security-Policy "frame-ancestors  *.example.domain"` | Allow embedding from sibling subdomains. | EXPR | `default = { "Content-Security-Policy" = "frame-ancestors *.example.domain" }` (the double space in the original is harmless). The other two CSP snippets (L293-301) are defined but not imported. |
| W L307, Caddy `reverse_proxy` | `header_up Host {http.reverse_proxy.upstream.hostport}` | Send the upstream's host as Host (the upstream is another HTTPS host). | OTHER | `proxy = { host = "upstream" }` |
| W L316-L340, Caddy with cloudflared | `@cors_preflight method OPTIONS` / `@trusted_origin header Origin https://paperless.mysite.com` / `handle @cors_preflight { header { Access-Control-Allow-Origin "https://paperless.mysite.com" Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" Access-Control-Allow-Headers "Content-Type, Authorization, X-CSRFToken, X-Requested-With" Access-Control-Max-Age "86400" Vary Origin } respond "" 204 }` / `handle { header @trusted_origin { Access-Control-Allow-Origin "{header.Origin}" Access-Control-Expose-Headers "Content-Disposition" Vary Origin } reverse_proxy localhost:8000 }` | One user's fix for "Caddy, Cloudflare tunnel and Authelia ... The WebSocket Connection fail on the System Status UI". | Preflight: NOT-OFFERED. Echo: EXPR as a fixed value. | **Preflight**: a synthetic 204 for OPTIONS with ACA-* fields needs a method condition and a synthetic answer. Neither is in the design; a typed `cors` setting is deferred. The app answers CORS itself through django-cors-headers: `CorsMiddleware` (settings L194), `CORS_ALLOWED_ORIGINS` from `PAPERLESS_CORS_ALLOWED_HOSTS` or `PAPERLESS_URL`, `CORS_ALLOW_CREDENTIALS = True` and `CORS_EXPOSE_HEADERS = ["Content-Disposition"]` ([P/.../settings/__init__.py#L434-L449](https://github.com/paperless-ngx/paperless-ngx/blob/c4d1b0c7325ea8782d87c64b6738ac39d313df2e/src/paperless/settings/__init__.py#L434-L449)). So it works once `PAPERLESS_URL` is set. **Echo**: because the matcher allows only one fixed origin, the echo equals `set = { "Access-Control-Allow-Origin" = "https://paperless.mysite.com", "Access-Control-Expose-Headers" = "Content-Disposition" }`. `Vary` is a refused name; it is not needed for a constant value (inferred). Note that the page origin is the same site, so CORS should not be needed at all (inferred). |

### Other directives (existing features)

- **WebSocket.**
  - nginx `proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade";` (W L27-29, L49-51; "required for WebSockets to work").
  - Apache `RewriteCond %{HTTP:UPGRADE} ^WebSocket$ [NC]` / `RewriteCond %{HTTP:CONNECTION} Upgrade$ [NC]` / `RewriteRule ^/?(.*) "ws://${local_url}:${local_port}/$1" [P,L]` (L222-224).
  - The app's route is `ws/status/` ([P/src/paperless/urls.py#L429-L430](https://github.com/paperless-ngx/paperless-ngx/blob/c4d1b0c7325ea8782d87c64b6738ac39d313df2e/src/paperless/urls.py#L429-L430)).
  - agensio upgrades automatically. Upgraded tunnels have no idle timeout by default; set `proxy = { tunnel_timeout = ... }` if one is wanted. NPM's `proxy_send_timeout 600m; proxy_read_timeout 600m;` (L131-134) exists so WebSockets with no updates for 90 s are not cut.
- **Location rewriting.** `proxy_redirect off;` (L31, L53) → `proxy = { redirects = "pass" }`. Apache `ProxyPassReverse` (L230) → `redirects = "rewrite"`.
- **Request fields.**
  - `Host $host` (L54) is the default.
  - `Host $host:$server_port` (L32, login location) → Host passed through as the client sent it. **Unverified**: whether agensio adds the port when the client did not.
  - `X-Real-IP $remote_addr` (L33, L55) → `proxy = { headers = { "X-Real-IP" = "$remote_addr" } }`.
  - `X-Forwarded-Host $server_name` (L35, L57) → `proxy = { headers = { "X-Forwarded-Host" = "$server_name" } }`.
  - `X-Forwarded-For` and `X-Forwarded-Proto` are automatic.
  - Apache `RequestHeader set Front-End-Https "On"` (L179) and `X-Forwarded-Proto 'https' env=HTTPS` (L186) → `proxy.headers` and automatic.
  - `SetEnvIf Cookie "(^|;\ *)csrftoken=([^;\ ]+)" csrftoken=$2` / `RequestHeader set X-CSRFToken "%{csrftoken}e"` (L219-220): a request field built from a cookie. agensio has no cookie variable. It is not needed: the Angular front end sends `X-CSRFToken` itself (inferred).
- **XFF workaround.** `proxy_set_header X-Forwarded-For "$proxy_add_x_forwarded_for, 127.0.0.1";` (L101-107), so that python-ipware sees a trusted last hop. agensio has no `$proxy_add_x_forwarded_for` variable. **Unverified**: whether `proxy.headers` may override X-Forwarded-For. The wiki's own alternative works with agensio: `PAPERLESS_ALLAUTH_TRUSTED_CLIENT_IP_HEADER=X-Real-IP` with X-Real-IP set by `proxy.headers` (L114-122).
- **Encoded slashes.** Apache `AllowEncodedSlashes On` (L217): agensio passes the raw target.
- **Timeouts.** Apache `Timeout 360`, `ProxyTimeout 600`, `ProxyPass ... connectiontimeout=6 timeout=60` (L173, L176, L229); HAProxy `timeout server 1h; timeout tunnel 1h` (L368-372) → `proxy = { connect_timeout, read_timeout, tunnel_timeout }`.
- **Body size.** `client_max_body_size 10M;` (L15, "maximum size for file uploads") → `max_body_size = "10MB"`.
- **Subpath.** `location /paperless/ { proxy_pass http://localhost:8000; }` with `PAPERLESS_FORCE_SCRIPT_NAME=/paperless` (L70-79; configuration.md L558-577). In agensio: `[[site.location]] path = "/paperless"`, `upstream = "http://localhost:8000"`, with no URI part so the path is passed unchanged. The wiki says "ensure the proxy_pass setup strips that prefix", but its own example (no URI on `proxy_pass`) does not strip it; inferred to be a wiki inconsistency.
- **Traefik.** Labels only (L352-361), with no headers or redirects.

### App guidance

- **Trusting the proxy.**
  - `PAPERLESS_URL` is required behind a proxy (setup.md L296-299; wiki L3, L67-68). It sets `ALLOWED_HOSTS`, `CORS_ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` (configuration.md L468-480).
  - The wiki suggests `PAPERLESS_USE_X_FORWARD_HOST=true`, `PAPERLESS_USE_X_FORWARD_PORT=true` and `PAPERLESS_PROXY_SSL_HEADER='["HTTP_X_FORWARDED_PROTO", "https"]'` (configuration.md L681-701, "has security implications").
  - `PAPERLESS_TRUSTED_PROXIES` (L519-530) controls client-IP logging and allauth's proxy count.
  - **Security**: with `PAPERLESS_ENABLE_HTTP_REMOTE_USER` or `_API`, the proxy must strip a client-sent `Remote-User` header (configuration.md L629-657). In agensio that is the request-field feature: `proxy = { headers = { "Remote-User" = "" } }`.
- **Referrer-Policy and CSRF.** The wiki's troubleshooting (L376-434) is the key app-specific finding:
  - `Referrer-Policy: no-referrer` makes browsers send `Origin: null` on the same-origin login POST.
  - Django's CSRF check then rejects it: "Origin checking failed - null does not match any trusted origins".
  - So **a site-wide `set` of `no-referrer` breaks Paperless login** unless `/accounts/login/`, `/accounts/signup/` and `/accounts/2fa/` get `same-origin`.
  - agensio's baseline (`strict-origin-when-cross-origin` as `default`) is safe: it sends the origin on same-origin POSTs, and Django's own `same-origin` wins anyway.
- **Frame fields.** The app sends `X-Frame-Options: SAMEORIGIN` because the UI embeds PDFs in a same-origin frame (settings L424-425). A proxy `DENY` would break PDF preview (inferred).
- **CSP.** None from the app and none in the official docs. The wiki's community CSPs are lax by its own description.
- **HSTS.** None in the docs. The wiki has Apache `max-age=15552000; preload` and Caddy `max-age=31536000; includeSubdomains`.
- **CORS.** Handled by the app (django-cors-headers, `PAPERLESS_CORS_ALLOWED_HOSTS`, credentials allowed). The proxy should not add CORS.
- **.well-known.** Nothing beyond ACME (the Apache L159 exemption).

---

## 21. Grafana

**Version read:** v13.2.3, released 2026-09-29. Tag object 5dff8abc, commit `6193dc03311b631b9727b560d24369e683dc396e`.

**Sources:**
- Tutorial "Run Grafana behind a reverse proxy" (published at grafana.com/tutorials/run-grafana-behind-a-proxy/):
  https://github.com/grafana/grafana/blob/v13.2.3/docs/sources/tutorials/run-grafana-behind-a-proxy/index.md.
  It covers nginx (root and subpath), HAProxy, IIS, Apache and Traefik. **There is no Caddy section.** I confirmed that against
  the live page on 2026-10-13, so the hint was wrong.
- Tutorial "Use IIS with URL Rewrite as a reverse proxy":
  https://github.com/grafana/grafana/blob/v13.2.3/docs/sources/tutorials/iis/index.md
- What Grafana sends itself:
  - `conf/defaults.ini`
  - `pkg/middleware/middleware.go`
  - `pkg/middleware/csp.go`
  - `pkg/api/http_server.go`
  - `pkg/middleware/validate_host.go`
  - `pkg/middleware/subpath_redirect.go`
  - `pkg/api/api.go`
  - `pkg/api/user.go`
  - `pkg/web/context.go`
  - The configuration docs `docs/sources/setup-grafana/configure-grafana/_index.md` and `.../configure-security/configure-security-hardening/index.md`

  All read at the same tag.

### Redirect and response-header directives in the official proxy configurations

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what's missing |
|---|---|---|---|---|
| [proxy tutorial L104-107](https://github.com/grafana/grafana/blob/v13.2.3/docs/sources/tutorials/run-grafana-behind-a-proxy/index.md#L104-L107), nginx subpath, `server { ... }` | `location /grafana/ { proxy_set_header Host $host; proxy_pass http://grafana; }` | **Implicit** in nginx: a prefix location ending in `/` and handled by `proxy_pass` answers the bare `/grafana` with a 301 to `/grafana/` (nginx core docs, "location"). The tutorial does not mention this (inferred). | EXPRESSIBLE | `[[site.redirect]]` `from = "/grafana"`, `match = "exact"`, `to = "/grafana/"`, `status = 301`. agensio has no automatic slash redirect for a proxied prefix location: `Router::location` is a plain `starts_with` (`src/core/router.hpp` L46), so `/grafana` falls to `/`. **Unverified:** that an exact `from` does not also match `/grafana/`. |
| [L120-124](https://github.com/grafana/grafana/blob/v13.2.3/docs/sources/tutorials/run-grafana-behind-a-proxy/index.md#L120-L124), "Add a rewrite rule to each location block" (`/grafana/` and `/grafana/api/live/`) | `rewrite  ^/grafana/(.*)  /$1 break;` | Strips the subpath before proxying. This is an internal rewrite (`break`), not a redirect. | NOT A REDIRECT/HEADER RULE | `upstream` with a URI part: `[[site.location]]` `path = "/grafana/"`, `upstream = "http://127.0.0.1:3000/"`. `/grafana/x` goes to `/x`, and the WebSocket path `/grafana/api/live/` needs no location of its own. |
| [L137-148](https://github.com/grafana/grafana/blob/v13.2.3/docs/sources/tutorials/run-grafana-behind-a-proxy/index.md#L137-L148), HAProxy `frontend http-in` / `backend grafana_backend` | `use_backend grafana_backend if { path /grafana } or { path_beg /grafana/ }` and `http-request set-path %[path,regsub(^/grafana/?,/)]` | Subpath strip. Here the bare `/grafana` is *rewritten* to `/`, not redirected. | NOT A REDIRECT/HEADER RULE | The same location with a URI part covers `/grafana/...`. For the bare `/grafana`, agensio exact locations cannot rewrite (configuration.md "Target"), so use the exact redirect of the first row. The behaviour differs (301, not an internal rewrite), and the application works either way. |
| [L167-176](https://github.com/grafana/grafana/blob/v13.2.3/docs/sources/tutorials/run-grafana-behind-a-proxy/index.md#L167-L176) and [iis tutorial L104-111](https://github.com/grafana/grafana/blob/v13.2.3/docs/sources/tutorials/iis/index.md#L104-L111), IIS `web.config` `<rewrite><rules>` | `<rule name="Grafana" enabled="true" stopProcessing="true"> <match url="grafana(/)?(.*)" /> <action type="Rewrite" url="http://localhost:3000/{R:2}" logRewrittenUrl="false" /> </rule>`, with "Ignore case" and "Append query string" checked | ARR proxy with the subpath stripped (capture `{R:2}`). It is a Rewrite, not a Redirect. The pattern is unanchored and case-insensitive (inferred). | NOT A REDIRECT/HEADER RULE | Location `/grafana/` with `upstream = "http://127.0.0.1:3000/"`. agensio's prefix match is case-sensitive. |
| [L193-197](https://github.com/grafana/grafana/blob/v13.2.3/docs/sources/tutorials/run-grafana-behind-a-proxy/index.md#L193-L197), Apache inside `<VirtualHost>` | `ProxyPassReverse / http://your_grafana_server:3000` | Rewrites the origin's `Location` (and `Content-Location`, `URI`) response headers to the proxy's address. | NOT A REDIRECT/HEADER RULE | `proxy = { redirects = "rewrite" }`, which is the default. agensio rewrites `Location` only. Whether Grafana ever sends `Content-Location` is **unverified**. |
| [L205-211](https://github.com/grafana/grafana/blob/v13.2.3/docs/sources/tutorials/run-grafana-behind-a-proxy/index.md#L205-L211), Apache subpath | `ProxyPassReverse /your_path http://your_grafana_server:3000` and `ProxyPassReverse / http://192.168.250.5:3000/your_path` | Location rewrite for the subpath mapping. The second pair maps `/` to Grafana's `/your_path`, which looks like a doc error (inferred). | NOT A REDIRECT/HEADER RULE | Location `/your_path/` with `upstream = "http://127.0.0.1:3000/"` and the default `redirects = "rewrite"`. |

No HSTS, `add_header`, `Header` or HTTP→HTTPS directive appears anywhere in the tutorials. Every example listens on port 80.
The nginx admonition at L126-130 says "If nginx is performing TLS termination, then you must set the
`root_url` and `protocol` configuration accordingly" and gives no config.

### Other directives (existing agensio features)

- **WebSocket** (`map $http_upgrade $connection_upgrade` L46-49; `location /api/live/ { proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection $connection_upgrade; ... }` L66-72 and L110-116): automatic in agensio, with no config and no idle limit by default (`tunnel_timeout`).
- **Host** (`proxy_set_header Host $host` L61, 70; Apache `ProxyPreserveHost on` L194; IIS `appcmd ... -preserveHostHeader:true`, iis tutorial L114-118, required since Grafana 8.3.5, otherwise "origin not allowed"): agensio passes Host by default (`proxy.host = "pass"`).
- **Upstream** (`upstream grafana { server localhost:3000; }` L51-53; Apache `ProxyPass`; Traefik `loadbalancer.server.port: 3000` L224 and `servers: - url: http://192.168.30.10:3000` L246-247): `upstream = "http://127.0.0.1:3000"` (`app = "proxy"`).
- **Traefik routers** (`Host(...)`, `Host(...) && PathPrefix(/grafana)` L223-261): `server_name` plus a prefix location. Without StripPrefix, this needs Grafana's `serve_from_sub_path = true` (tutorial L263-279), and then the agensio upstream has no URI part.
- `root /usr/share/nginx/html; index index.html index.htm;` (L57-58, 101-102): the static site around the subpath, i.e. agensio static `root`/`index`.
- nginx `worker_connections` advice for Grafana Live (L80): agensio `server.max_connections`.

### App guidance (what Grafana does itself)

- **Headers on every answer, its own errors included:** a `Before` hook on all responses ([middleware.go L32-101](https://github.com/grafana/grafana/blob/v13.2.3/pkg/middleware/middleware.go#L32-L101)).
  - `Cache-Control: no-store` on dynamic paths (Pragma and Expires deleted).
  - `X-Frame-Options: deny` unless `allow_embedding = true` or the handler set `X-Allow-Embedding: allow`.
  - `X-Content-Type-Options: nosniff` (`x_content_type_options = true` by default).
  - `X-XSS-Protection: 1; mode=block` (`x_xss_protection = true` by default).
  - Operators can add their own fields through `[server.custom_response_headers]` ([defaults.ini L108-110](https://github.com/grafana/grafana/blob/v13.2.3/conf/defaults.ini#L108-L110)). Those are added only if the field is absent (middleware.go L103-118), the same semantics as agensio's `default`.
- **HSTS:** `strict_transport_security = false` by default, `strict_transport_security_max_age_seconds = 86400`, `..._preload = false`, `..._subdomains = false` ([defaults.ini L518-529](https://github.com/grafana/grafana/blob/v13.2.3/conf/defaults.ini#L518-L529)).
  - When enabled it is sent on every answer, whatever the scheme (middleware.go L73-82).
  - The docs say: "Only use this when HTTPS is enabled in your configuration, or when there is another upstream system that ensures your application does HTTPS (like a frontend load balancer)" (configure-grafana `_index.md` L782-784).
  - agensio's `hsts` replaces Grafana's field. A Grafana admin who set `preload` loses it under agensio `hsts` (preload NOT OFFERED ON PURPOSE).
- **CSP:** off by default (`content_security_policy = false`, defaults.ini L540-556). When on, the template carries `$NONCE`, a fresh nonce per request ([csp.go L45-53](https://github.com/grafana/grafana/blob/v13.2.3/pkg/middleware/csp.go#L45-L53)), and `$ROOT_PATH`. A proxy-set fixed CSP cannot reproduce this. The hardening doc recommends enabling Grafana's own CSP (L78-91).
- **X-Frame-Options vs embedding:** `allow_embedding` (defaults.ini L515-516; docs L776-780). A proxy-set frame field would break `allow_embedding = true` and the per-URL `X-Allow-Embedding` exceptions.
- **Static caching:** [http_server.go L856-871](https://github.com/grafana/grafana/blob/v13.2.3/pkg/api/http_server.go#L856-L871).
  - `/public/build/` (hashed build output): `Cache-Control: public, max-age=31536000`, without `immutable`.
  - Other `/public/` files: `public, max-age=3600`.
- **CORS:** not examined beyond the files above, which hold none.
- **Grafana's own redirects (not the proxy's):**
  - `enforce_domain = true` sends a 301 to `root_url` + RequestURI when Host differs from `domain` ([validate_host.go L22-50](https://github.com/grafana/grafana/blob/v13.2.3/pkg/middleware/validate_host.go#L22-L50); hardening doc L143-150, "might help to mitigate some DNS rebinding attacks"). agensio's `canonical` does the same at the edge.
  - `serve_from_sub_path = true` sends a 301 for a non-API request missing the subpath ([subpath_redirect.go L13-26](https://github.com/grafana/grafana/blob/v13.2.3/pkg/middleware/subpath_redirect.go#L13-L26)).
- **.well-known:** `/.well-known/change-password` answers a 302 to `/profile/password` ([api.go L98](https://github.com/grafana/grafana/blob/v13.2.3/pkg/api/api.go#L98), [user.go L592-594](https://github.com/grafana/grafana/blob/v13.2.3/pkg/api/user.go#L592-L594)). It must reach Grafana. No security.txt or openid route.
- **Trusting the proxy:** Grafana has no trusted-proxy setting.
  - `RemoteAddr()` takes `X-Real-IP` first, then the first `X-Forwarded-For` entry, from any peer ([pkg/web/context.go L71-92](https://github.com/grafana/grafana/blob/v13.2.3/pkg/web/context.go#L71-L92)).
  - agensio replaces `X-Forwarded-For` from untrusted clients, but forwards a client-sent `X-Real-IP` unchanged ("every other field"). Grafana would therefore log and rate-limit on a spoofable address. The IP-based login protection is off by default (`disable_ip_address_login_protection = true`, defaults.ini L506-507), and the effect on the `[auth.proxy]` whitelist is **unverified**.
  - Recommendation, an existing feature: `proxy = { headers = { "X-Real-IP" = "$remote_addr" } }`, or `"X-Real-IP" = ""` to drop it.
  - Required for correct links: `root_url`, `domain` and `protocol` (tutorial L25-34, L126-130). Grafana Live checks Origin against `root_url` unless `[live] allowed_origins` is set (defaults.ini L2251-2253).
  - Secure cookies: `cookie_secure = true` "if you host Grafana behind HTTPS" (defaults.ini L509-510).
- **agensio TOML for the whole recommended setup:**
  ```toml
  [[site]]
  server_name = ["grafana.example.com"]
  tls = "auto"                      # http = "redirect" is the default for a TLS site on 443
  app = "proxy"
  upstream = "http://127.0.0.1:3000"
  proxy = { headers = { "X-Real-IP" = "$remote_addr" } }
  ```
  Subpath variant:
  ```toml
  [[site.location]]
  path = "/grafana/"
  upstream = "http://127.0.0.1:3000/"      # the nginx `rewrite ^/grafana/(.*) /$1 break`

  [[site.redirect]]                        # nginx's implicit /grafana -> /grafana/
  from = "/grafana"
  match = "exact"
  to = "/grafana/"
  status = 301
  ```

---

## 22. Uptime Kuma

**Version read:** 2.5.6, released 2026-10-09, commit `7ca4a3debd76443d8452da95d4040200a1479af4`.
- The wiki page "Reverse-Proxy" at its latest revision `b820a50a4f28460d77f0376c2f5c2c277527e5fe` (edited 2026-04-24):
  https://github.com/louislam/uptime-kuma/wiki/Reverse-Proxy/b820a50a4f28460d77f0376c2f5c2c277527e5fe.
  Line numbers are those of `https://raw.githubusercontent.com/wiki/louislam/uptime-kuma/Reverse-Proxy.md` fetched 2026-10-13. The wiki has no line anchors, and a raw fetch pinned to that SHA returned 404.
- Also read: the wiki pages "Status-Page", "Environment-Variables" and "Reverse-Proxy-with-Cloudflare-Tunnel" (fetched 2026-10-13), and
  `server/server.js`, `server/uptime-kuma-server.js`, `server/util-server.js`, `server/routers/api-router.js` and
  `server/routers/status-page-router.js` at tag 2.5.6.
- The wiki covers nginx (with SSL, without SSL, Certbot), Nginx Proxy Manager, Apache (with and without SSL), Caddy (plain and
  caddy-docker-proxy), https-portal, Synology, Traefik, Cloudflare, Cloudflare Tunnels, OpenLiteSpeed and HAProxy.
- **"Uptime Kuma does not support a subdirectory"** (L5-6). The wiki has no subpath config.

### Redirect and response-header directives

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what's missing |
|---|---|---|---|---|
| Reverse-Proxy L132-136, Caddy "without docker" | `subdomain.domain.com { reverse_proxy 127.0.0.1:3001 }` | **Implicit:** a site address without a scheme turns on Caddy's automatic HTTPS, which redirects HTTP (port 80) to HTTPS (caddyserver.com/docs/automatic-https, fetched 2026-10-13). The status code is not stated there: Caddy uses 308 (**unverified**). The wiki itself says "If using caddy these certificates will be auto-generated" (L9). | EXPRESSIBLE | `tls = "auto"` with `http = "redirect"` (the default for a TLS site on 443): 308, path and query kept, ACME exempt. |
| L153-155, caddy-docker-proxy labels | `caddy: status.example.org` / `caddy.reverse_proxy: "* {{upstreams 3001}}"` | Same implicit HTTP→HTTPS redirect. | EXPRESSIBLE | As above. |
| L11 and L81-84, nginx "With SSL (Certbot)" | Prose: "run certbot on it and it will automatically configure auto-HTTPS redirection"; `sudo certbot --nginx -d your_domain ...` | Certbot writes the redirect server block. The directive is **not shown on the page**: what Certbot writes (`return 301 https://$host$request_uri;`) is **unverified** here. | EXPRESSIBLE | `http = "redirect"`: 308 instead of 301, which keeps the method too. |
| L188-193, https-portal `environment` | `DOMAINS: "status.domain.com -> http://uptime-kuma:3001"` | https-portal redirects HTTP to HTTPS by default (**unverified**, from https-portal's README, not read). | EXPRESSIBLE | `http = "redirect"`. |
| L279-283, OpenLiteSpeed "Context tab" `proxy` context | `Header Operations:` `Upgrade websocket` / `Connection upgrade` | Intent: a WebSocket upgrade. As written, these are entered as the context's *header operations*. OLS applies those to responses unless they are written as `RequestHeader`; how OLS parses lines with no verb is **unverified**. | NOT A REDIRECT/HEADER RULE | WebSocket upgrade is automatic in agensio. As response fields, `Connection` and `Upgrade` are on the design's refused list, and they are meaningless on a response. |
| L226-227, Synology | "Click `Create` -> `Websockets`, this automatically fills in the required headers for websockets." | Request headers for the upgrade. | NOT A REDIRECT/HEADER RULE | Automatic upgrade. |
| L104-110 and L118-123, Apache `<VirtualHost>` | `RewriteCond %{HTTP:Upgrade} =websocket` / `RewriteRule /(.*) ws://localhost:3001/$1 [P,L]` / `RewriteCond %{HTTP:Upgrade} !=websocket` / `RewriteRule /(.*) http://localhost:3001/$1 [P,L]` (with SSL); `RewriteRule ^/?(.*) "ws://localhost:3001/$1" [P,L]` (without SSL) | `[P]` means proxy, not redirect: the routing of WebSocket requests. | NOT A REDIRECT/HEADER RULE | `upstream` plus the automatic upgrade. |

No `add_header`, `Header`, HSTS or explicit `return 301` appears on the page.

### Other directives (existing agensio features)

- **nginx** `proxy_set_header X-Real-IP $remote_addr; X-Forwarded-For $proxy_add_x_forwarded_for; Host $host; proxy_http_version 1.1; Upgrade $http_upgrade; Connection "upgrade"` (L33-41, L52-58, L70-78):
  - agensio sets `X-Forwarded-For` and `X-Forwarded-Proto` itself and passes Host.
  - It does not send `X-Real-IP`. Kuma reads that only as a fallback after `X-Forwarded-For`, so it is not needed. If wanted: `proxy = { headers = { "X-Real-IP" = "$remote_addr" } }`.
  - The upgrade is automatic. Note that nginx's `Connection "upgrade"` is sent unconditionally.
- **TLS and protocols:**
  - `listen 443 ssl http2`, `ssl_certificate*` (L25-30) and Apache `SSLEngine` with `Protocols h2 http/1.1` (L99-103): agensio `tls` / `tls = "auto"`, with HTTP/2 through `[server] protocols`.
  - Traefik `entrypoints=https`, `tls=true`, `tls.certresolver=myresolver` and `loadBalancer.server.port=3001` (L232-238): `tls = "auto"` plus `upstream`. No redirect middleware is shown.
- **Upstream:** Apache `ProxyPreserveHost on` and `ProxyPass / http://localhost:3001/` (L104-105, L118-119): Host is passed by default, plus `upstream`.
- **HAProxy** "`timeout tunnel`" and "`timeout client-fin`" (L303-306): `proxy.tunnel_timeout` (none by default).
- Nginx Proxy Manager "WebSockets Support" (L90), Cloudflare "Enable WebSockets" (L246-248) and https-portal `WEBSOCKET: "true"` (L193): automatic upgrade.
- OpenLiteSpeed "Web Socket Proxy Setup" (L286-290): automatic upgrade.

### App guidance (what Kuma does itself)

- **X-Frame-Options:** `X-Frame-Options: SAMEORIGIN` on every Express answer unless `UPTIME_KUMA_DISABLE_FRAME_SAMEORIGIN` / `--disable-frame-sameorigin` is set. The same middleware removes `X-Powered-By` ([server.js L164-165, L216-222](https://github.com/louislam/uptime-kuma/blob/2.5.6/server/server.js#L216-L222)).
  - The wiki's iframe recipe for status pages requires that variable and warns about clickjacking (Status-Page L36-43; Environment-Variables L25).
  - So a proxy frame field would override the owner's choice. This matches the design's statement in headers.md L281/L308.
- **No HSTS, no CSP, no Referrer-Policy** from Kuma (none in server.js or uptime-kuma-server.js).
- **CORS:** `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS` and `Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept` on the badge endpoints ([util-server.js L632-636](https://github.com/louislam/uptime-kuma/blob/2.5.6/server/util-server.js#L632-L636); api-router.js L147-148, 220-221, 284-285, 347-348, 411-412, 494-495). Everything else gets CORS only in development.
- **Redirects Kuma does itself:**
  - `/` gets a 302 to `/dashboard` or `/status/<slug>` (server.js L264-286; Express `redirect()` defaults to 302).
  - `/.well-known/change-password` gets a 302 to `https://github.com/louislam/uptime-kuma/wiki/Reset-Password-via-CLI` ([server.js L367-369](https://github.com/louislam/uptime-kuma/blob/2.5.6/server/server.js#L367-L369)). It must reach Kuma.
- **Status-page domains:** the wiki says to "forward the header `X-Forwarded-Host` or `Host`" (Status-Page L26). agensio passes Host. Kuma reads `X-Forwarded-Host` only with Trust Proxy on (server.js L266-271, api-router.js L32-33).
- **Trusting the proxy:** "Settings → Reverse Proxy → HTTP Headers → Trust Proxy = Yes" (wiki L13-18).
  - Kuma then takes the first `X-Forwarded-For` entry, else `X-Real-IP` ([uptime-kuma-server.js L383-399](https://github.com/louislam/uptime-kuma/blob/2.5.6/server/uptime-kuma-server.js#L383-L399)).
- **WebSocket Origin check:** with `UPTIME_KUMA_WS_ORIGIN_CHECK` at its default `cors-like`, the Origin host must equal the `Host` header (uptime-kuma-server.js L163-195; Environment-Variables L26). Host must therefore reach Kuma unchanged, which is agensio's default `host = "pass"`. `host = "upstream"` would break the dashboard.
- **Static assets:** `express-static-gzip("dist", { enableBrotli: true })` (server.js L357-362). Kuma serves precompressed twins itself. Cache-Control is the serve-static default (`public, max-age=0`, **inferred**, not read).
- **agensio TOML:**
  ```toml
  [[site]]
  server_name = ["status.example.com"]
  tls = "auto"
  app = "proxy"            # or app = "node" for a Kuma installed by agensio (tests/kuma-install.sh)
  upstream = "http://127.0.0.1:3001"
  ```

---

## 23. BookStack

**Versions read:**
- Application v26.09.1, released 2026-09-29, commit `31d94dd8b98e3334dc01b66bed6d514719a2f85d` (tag object 95554b7d). Cloned from
  `codeberg.org/bookstack/bookstack`, whose tag matches GitHub's `BookStackApp/BookStack` tag.
- **The docs and configs moved to Codeberg.** The GitHub `BookStackApp/website` repository's `main` was last committed 2024-07-27, so I read Codeberg:
  - `codeberg.org/bookstack/website` main at `ad8ed71094b9258e18d673b5624428b0b10d7221` (2026-10-09).
  - `codeberg.org/bookstack/devops` main at `a81361d7bf226d78007996422d3287c3d4df4f89` (2026-10-10).
- The installation docs link the "Example Apache VirtualHost" and "Example Nginx Server block" in devops (website `content/docs/admin/installation.md` L76-79).

**Sources:**
- devops `config/apache/bookstack.conf`, `config/nginx/ubuntu-1604-install-config`, `config/nginx/subpath-proxy-config` and `config/lsio-docker/docker-compose.yml`.
- The web-server blocks the official install scripts write: `scripts/installation-ubuntu-26.04.sh` (Apache), `-debian-13.sh` (Apache), `-almalinux-10.sh` (nginx) and `-alpine-3-24.sh` (Caddy).
- In the release: `public/.htaccess`, `public/uploads/.htaccess` and `public/web.config` (IIS).
- Website `content/docs/admin/subdirectory-setup.md`, `security.md` and `upload-config.md`.
- In the app: `app/Http/Middleware/ApplyCspRules.php`, `PreventResponseCaching.php`, `TrustProxies.php` and `app/Http/DownloadResponseFactory.php`.

There is no Traefik or HAProxy config. The Docker route is the linuxserver.io image, and BookStack's compose example says "Commonly you'd have a reverse proxy in front of this" (devops lsio compose L51-54) without giving one.

### Redirect and response-header directives

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what's missing |
|---|---|---|---|---|
| [devops apache/bookstack.conf L34-37](https://codeberg.org/bookstack/devops/src/commit/a81361d7bf226d78007996422d3287c3d4df4f89/config/apache/bookstack.conf#L34-L37), inside `<Directory /var/www/bookstack/public/>` `<IfModule mod_rewrite.c>` | `# Redirect Trailing Slashes If Not A Folder...` / `RewriteCond %{REQUEST_FILENAME} !-d` / `RewriteCond %{REQUEST_URI} (.+)/$` / `RewriteRule ^ %1 [L,R=301]` | Its comment: "Redirect Trailing Slashes If Not A Folder". A 301 to the path without its trailing slash, query kept (mod_rewrite default). The target is a **regex capture** (`%1`), and the rule has a **filesystem condition** (`!-d`). | NOT OFFERED ON PURPOSE | There is no site-wide trailing-slash policy (redirects.md 5.4) and no captures. **The app still works:** Laravel's `UriValidator` matches `rtrim($request->getPathInfo(), '/')` (laravel/framework v12.69.3, the version in BookStack's composer.lock, `src/Illuminate/Routing/Matching/UriValidator.php` L19). `/books/` serves the same page as `/books`, at the cost of duplicate URLs, exactly as under BookStack's own nginx configs, which have no such rule. A single page could get an exact `[[site.redirect]]`. |
| [public/.htaccess L12-15](https://codeberg.org/bookstack/bookstack/src/tag/v26.09.1/public/.htaccess#L12-L15) (also [GitHub mirror](https://github.com/BookStackApp/BookStack/blob/v26.09.1/public/.htaccess#L12-L15)) | `# Redirect Trailing Slashes If Not A Folder...` / `RewriteCond %{REQUEST_FILENAME} !-d` / `RewriteCond %{REQUEST_URI} (.+)/$` / `RewriteRule ^ %1 [L,R=301]` | Same rule, shipped in the release for `AllowOverride` setups. | NOT OFFERED ON PURPOSE | As above. agensio never reads `.htaccess`. |
| [public/web.config L10-16](https://codeberg.org/bookstack/bookstack/src/tag/v26.09.1/public/web.config#L10-L16), IIS `<rewrite><rules>` | `<rule name="Imported Rule 1" stopProcessing="true"> <match url="^(.*)/$" ignoreCase="false" /> <conditions> <add input="{REQUEST_FILENAME}" matchType="IsDirectory" ignoreCase="false" negate="true" /> </conditions> <action type="Redirect" redirectType="Permanent" url="/{R:1}" /> </rule>` | The IIS twin of the trailing-slash rule: a 301 with capture `{R:1}`. | NOT OFFERED ON PURPOSE | As above. |
| [scripts/installation-ubuntu-26.04.sh L204-207](https://codeberg.org/bookstack/devops/src/commit/a81361d7bf226d78007996422d3287c3d4df4f89/scripts/installation-ubuntu-26.04.sh#L204-L207) (same in `installation-debian-13.sh` L179-182) | `RewriteCond %{REQUEST_FILENAME} !-d` / `RewriteCond %{REQUEST_URI} (.+)/$` / `RewriteRule ^ %1 [L,R=301]` | The same rule, written by the official install scripts into `/etc/apache2/sites-available/bookstack.conf`. | NOT OFFERED ON PURPOSE | As above. |
| [website subdirectory-setup.md L58-60](https://codeberg.org/bookstack/website/src/commit/ad8ed71094b9258e18d673b5624428b0b10d7221/content/docs/admin/subdirectory-setup.md#L58-L60), Apache subpath, `<Directory "/var/www/bookstack/public">` under `Alias "/bookstack" "/var/www/bookstack/public"` | `# Redirect Trailing Slashes If Not A Folder...` / `RewriteCond %{REQUEST_FILENAME} !-d` / `RewriteRule ^(.*)/$ /$1 [L,R=301]` | Trailing-slash removal for the subdirectory install. Inferred, not tested: in per-directory context mod_rewrite matches the path relative to the directory, so the target `/$1` appears to drop the `/bookstack` prefix. | NOT OFFERED ON PURPOSE | As above. For the subpath itself, see the next row and "Other directives". |
| [devops nginx/subpath-proxy-config L49-52](https://codeberg.org/bookstack/devops/src/commit/a81361d7bf226d78007996422d3287c3d4df4f89/config/nginx/subpath-proxy-config#L49-L52) (= [subdirectory-setup.md L133-138](https://codeberg.org/bookstack/website/src/commit/ad8ed71094b9258e18d673b5624428b0b10d7221/content/docs/admin/subdirectory-setup.md#L133-L138)), in `server { listen 80; server_name example.com; ... }` | `location /bookstack/ { proxy_pass http://localhost:8080/; proxy_redirect off; }` | (a) **Implicit** nginx 301 from `/bookstack` to `/bookstack/` (location ends in `/` and uses `proxy_pass`; inferred, not mentioned). (b) `proxy_pass` with a URI strips the prefix. (c) `proxy_redirect off` leaves the origin's `Location` alone, because BookStack builds absolute URLs from `APP_URL=https://example.com/bookstack` (L20-24). | (a) EXPRESSIBLE; (b) and (c) NOT A REDIRECT/HEADER RULE | (a) `[[site.redirect]]` `from = "/bookstack"`, `match = "exact"`, `to = "/bookstack/"`, `status = 301`. (b) `[[site.location]]` `path = "/bookstack/"`, `upstream = "http://127.0.0.1:8080/"`. (c) `proxy = { redirects = "pass" }`. The default `"rewrite"` would also be harmless: BookStack never answers with `http://localhost:8080/...`. |
| [scripts/installation-alpine-3-24.sh L171-176](https://codeberg.org/bookstack/devops/src/commit/a81361d7bf226d78007996422d3287c3d4df4f89/scripts/installation-alpine-3-24.sh#L171-L176), Caddyfile | `http://$DOMAIN { root * /var/www/bookstack/public; php_fastcgi 127.0.0.1:9000; file_server; encode }` | (a) **Implicit:** `php_fastcgi`'s expanded form contains `redir @canonicalPath {http.request.orig_uri.path}/ 308` (caddyserver.com php_fastcgi docs, fetched 2026-10-13), adding a slash for a directory holding `index.php`. In BookStack's `public/` only the root has an `index.php`, so it never fires. (b) `encode` compresses on the fly and sets `Content-Encoding` and `Vary`. (c) `http://` disables automatic HTTPS, so there is no HTTP→HTTPS redirect. | (a) NOT A REDIRECT/HEADER RULE; (b) NOT A REDIRECT/HEADER RULE | (a) agensio already adds the slash to a real directory (redirects.md L509). (b) agensio has no on-the-fly compression, only precompressed `.br`/`.gz` twins (`cache.precompressed`). BookStack's `dist/*.js` and `.css` are served uncompressed unless twins are generated. That gap lies outside this design. |

### Other directives (existing agensio features)

- **Front controller:**
  - Apache `RewriteCond %{REQUEST_FILENAME} !-d` / `!-f` / `RewriteRule ^ index.php [L]` (bookstack.conf L39-42; .htaccess L17-20; web.config L17-24 "Rewrite" to `index.php`).
  - nginx `try_files $uri $uri/ /index.php?$query_string;` and `location ~ \.php$ { include snippets/fastcgi-php.conf; fastcgi_pass ...; }` (ubuntu-1604-install-config L10-17; subpath-proxy-config L28-36; almalinux script L158-165).
  - Caddy `php_fastcgi`.
  - All of these are `app = "laravel"`: root is the project, the preset serves `public/`, only `/index.php` runs, and `try_files = ["$uri", "$uri/", "/index.php?$query_string"]` (configuration.md section 3).
- **Authorization:** `# Handle Authorization Header` / `RewriteCond %{HTTP:Authorization} .` / `RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]` (bookstack.conf L30-32; .htaccess L8-10). agensio's FastCGI handler forwards every request field as `HTTP_*`, Authorization included (`src/handlers/fastcgi.cpp` `append_http_params`).
- **Directory listings:** `Options -MultiViews -Indexes` (bookstack.conf L24-26; .htaccess L2-4); `public/uploads/.htaccess` `Options -Indexes`; security.md L74-94 nginx `location /uploads { autoindex off; }` and Apache `<Location "/uploads"> Options -Indexes </Location>`. agensio has no directory listing at all.
- **Static files:** `DocumentRoot /var/www/bookstack/public/`, `root /var/www/bookstack/public;`, `index index.php index.html;`, Caddy `file_server` are agensio static via the preset.
- **Upload size:** upload-config.md L213-218 nginx `client_max_body_size 100m;` is `server.max_body_size` (default 1 MB), or the managed site's `settings.max_body_size`. PHP's own `upload_max_filesize` and `post_max_size` are still needed.
- **Subdirectory hosting:**
  - Apache `Alias "/bookstack" "/var/www/bookstack/public"` and `<Directory "/var/www/bookstack"> Require all denied` (subdirectory-setup.md L50, L69-72).
  - agensio: either the nginx pattern (a second, local agensio site plus a proxy location with a URI part, as above), or an `alias` location with a FastCGI location inside the parent site. The preset applies site-wide, so this subpath form is hand-written (no preset).

### App guidance (what BookStack does itself)

- **CSP** (security.md L297-330, [app/Http/Middleware/ApplyCspRules.php L26-39](https://codeberg.org/bookstack/bookstack/src/tag/v26.09.1/app/Http/Middleware/ApplyCspRules.php#L26-L39)):
  - Every app response carries a CSP with `frame-ancestors 'self'` (plus `ALLOWED_IFRAME_HOSTS`), `frame-src ...`, `script-src http: https: 'nonce-...' 'strict-dynamic'` (nonce regenerated per request), `object-src 'self'`, `base-uri 'self'`, `style-src 'self' 'unsafe-inline' http: https:` and `img-src 'self' data: blob: http: https:`.
  - It is set with `headers->set('Content-Security-Policy', $cspHeader, false)`, i.e. *added beside* any existing field, not replacing it.
  - **The docs say:** "If needed, you should be able to set additional CSP headers via your webserver. If there's a clash with an existing BookStack CSP header then browsers will generally favour the most restrictive policy." (security.md L329-330)
  - Under agensio, `set` would *replace* BookStack's nonce policy, losing its protections and likely blocking its nonce'd scripts. `default` is a no-op because BookStack always sends one. There is no way to add a second field line.
  - Proposed class: **NEEDS A CHANGE (optional).** The smallest change is an `add = { "Content-Security-Policy" = "..." }` that appends one more field line, limited to the CSP fields, since browsers intersect multiple policies. Alternatively it stays NOT OFFERED: BookStack's own `ALLOWED_STYLE_SOURCES`, `ALLOWED_IMAGE_SOURCES`, `ALLOWED_IFRAME_SOURCES` and `ALLOWED_IFRAME_HOSTS` options (L185-226, L332-356) tighten its CSP without the proxy.
- **Frames:** BookStack sends no `X-Frame-Options` (only CSP `frame-ancestors`). Embedding is controlled by `ALLOWED_IFRAME_HOSTS`, which also switches cookies to `SameSite=None` (L185-198). A proxy-added `X-Frame-Options: SAMEORIGIN` would be ignored by CSP3 browsers when `frame-ancestors` is present (inferred, browser behaviour), but it contradicts `ALLOWED_IFRAME_HOSTS` for older browsers.
- **No HSTS** from BookStack and no HSTS advice in its docs. Secure cookies follow automatically from an `https` `APP_URL`, or `SESSION_SECURE_COOKIE=true` (security.md L179-181).
- **Caching:** `PreventResponseCaching` sets `Cache-Control: no-cache, no-store, private` and `Expires: Sun, 12 Jul 2015 19:01:00 GMT` on every app response except `theme/` ([PreventResponseCaching.php L13-41](https://codeberg.org/bookstack/bookstack/src/tag/v26.09.1/app/Http/Middleware/PreventResponseCaching.php#L13-L41)).
  - Assets are versioned by query (`versioned_asset()`: `dist/app.js?version=<AppVersion>`, `app/App/helpers.php` L17-29), not by a hash in the name. A long `Cache-Control` on `/dist/` (`[[site.response_headers]]` with `when = "success"`) would be safe but is not in any official config.
  - Downloads carry `X-Content-Type-Options: nosniff` (DownloadResponseFactory.php L114).
- **CORS:** none (no `Access-Control-*` in `app/`, `routes/` or `config/`).
- **.well-known:** BookStack serves none. The OIDC docs refer only to the IdP's discovery URL.
- **Trusting the proxy:** `APP_PROXIES` (security.md L375-394; [TrustProxies.php L16-42](https://codeberg.org/bookstack/bookstack/src/tag/v26.09.1/app/Http/Middleware/TrustProxies.php#L16-L42)) trusts `X-Forwarded-For`, `-Host`, `-Port`, `-Proto` and AWS ELB from the listed addresses.
  - It is not needed when agensio runs BookStack over FastCGI directly (REMOTE_ADDR is the client).
  - It is needed only behind the subpath proxy pattern or a container.
  - `APP_URL` must match the public URL (security.md L27; subdirectory-setup.md L20-24).
- **agensio TOML:**
  ```toml
  [[site]]
  server_name = ["docs.example.com"]
  tls = "auto"
  root = "/var/www/bookstack"        # the preset serves public/
  app = "laravel"
  php = { socket = "unix:/run/php/php8.4-fpm.sock" }
  ```

---

## 24. Outline

**Version read:** v1.11.0, released 2026-10-12, commit `cb0207201ed2c8b641809c26e41fbe2bde297072` (tag object 8268fd37).
- **The hosting docs have no source repository.** docs.getoutline.com is an Outline instance. I read the share "hosting" through its public API on 2026-10-13: `POST /api/shares.info {"id":"hosting"}` for the tree, then `POST /api/documents.info {id, shareId:"hosting"}` for each page's markdown. Line numbers count lines of that markdown.
- **No Caddy, Traefik or Apache page exists.** The hosting tree under "Configuration" has SSL, Nginx, Redis, Horizontal scaling, File storage, and so on. The only proxy config is the Nginx page, plus https-portal in the Docker page.

**Sources (with each page's `updatedAt`):**
- "Nginx", https://docs.getoutline.com/s/hosting/doc/nginx-6htaRboR57 (updated 2025-06-13)
- "SSL", https://docs.getoutline.com/s/hosting/doc/ssl-pzk7WO8d1n (2024-03-26)
- "Docker", https://docs.getoutline.com/s/hosting/doc/docker-7pfeLP5a8t (2026-07-01)
- "Troubleshooting", https://docs.getoutline.com/s/hosting/doc/troubleshooting-HXckrzCqDJ (2026-01-12)
- "Horizontal scaling", https://docs.getoutline.com/s/hosting/doc/horizontal-scaling-hkfU5Stao7 (2025-08-28)
- Source at v1.11.0: `.env.sample`, `server/env.ts`, `server/services/web.ts`, `server/middlewares/csp.ts`, `server/routes/index.ts`, `server/routes/app.ts`, `server/routes/embeds.ts`, `server/routes/discovery/{index,mcp}.ts`, `server/services/{websockets,collaboration}.ts` and `package.json`/`yarn.lock`. Also koa-sslify 5.0.1 `index.js` from unpkg.

### Redirect and response-header directives

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what's missing |
|---|---|---|---|---|
| "Nginx" page L4, prose before the config | "once setup you can set `FORCE_HTTPS=true` in Outline's `.env` configuration and any http requests will be automatically forwarded to https." | The HTTP→HTTPS redirect is done by **the application**, not by nginx. The nginx block (L8-28) has `listen 80; listen 443 ssl;` in one server and no redirect directive. In the code ([web.ts L49-63](https://github.com/outline/outline/blob/v1.11.0/server/services/web.ts#L49-L63)), `FORCE_HTTPS` (default `true`, env.ts L360-366, `.env.sample` L145-147) uses koa-sslify 5.0.1 with `temporary: false`, `redirectMethods: ['GET','HEAD']` and `disallowStatus: 405`. Result: a 301 for GET/HEAD, and a 405 with `Allow: GET, HEAD` for other methods, whenever the request is neither TLS nor `X-Forwarded-Proto: https` (from a trusted proxy). | EXPRESSIBLE (at the edge) | `http = "redirect"` (308 for all methods) before Outline. Outline then sees agensio's `X-Forwarded-Proto: https` and does not redirect, which needs `PROXY_HEADERS_TRUSTED`, true by default. Troubleshooting L4-9, "HTTP → HTTPS redirect loop": set `FORCE_HTTPS=false` while testing on http. |
| "Nginx" L26, `location / { ... }` | `proxy_redirect off;` | Leaves `Location` alone. Outline builds absolute URLs from `URL` (inferred). | NOT A REDIRECT/HEADER RULE | `proxy = { redirects = "pass" }`. The default `"rewrite"` is also harmless. |
| "Docker" L63-83, `https-portal` service `environment` | `DOMAINS: 'docs.mycompany.com -> http://outline:3000'` / `STAGE: 'production'` / `WEBSOCKET: 'true'` / `CLIENT_MAX_BODY_SIZE: '0'` | https-portal terminates TLS, gets a Let's Encrypt certificate and redirects HTTP to HTTPS by default. The redirect default is **unverified**: https-portal's README was not read. | EXPRESSIBLE (redirect); the rest NOT A REDIRECT/HEADER RULE | `tls = "auto"` and `http = "redirect"`. `WEBSOCKET` maps to the automatic upgrade. `CLIENT_MAX_BODY_SIZE: '0'` (unlimited) maps to `server.max_body_size` / `settings.max_body_size`, which agensio defaults to 1 MB: raise it for attachments and imports. |

No `add_header`, `Header`, HSTS or explicit `return 301` appears in Outline's docs.

### Other directives (existing agensio features)

- **The "Nginx" `location /` block** (L15-27):
  - `proxy_pass http://localhost:3000/;` is the `upstream`.
  - `proxy_set_header Upgrade $http_upgrade;` and `Connection "Upgrade";` are the automatic upgrade.
  - `Host $host;` is the default `host = "pass"`.
  - `X-Forwarded-For $proxy_add_x_forwarded_for;` and `X-Forwarded-Proto $scheme;` are always set by agensio.
  - `X-Real-IP $remote_addr;` and `X-Scheme $scheme;` are not read by Outline's server code (only `PROXY_IP_HEADER` can name a different IP header, env.ts L368-374; grep of `server/`). If wanted: `proxy = { headers = { "X-Real-IP" = "$remote_addr", "X-Scheme" = "$scheme" } }`.
- **The "SSL" page:** https-portal or "your own reverse proxy with nginx... you must ensure that websockets are forwarded" (L3-8). Outline can also terminate TLS itself with `SSL_KEY`/`SSL_CERT` or `private.pem`/`public.pem` (L18-56). That has no bearing on agensio.
- **WebSocket paths:** `/realtime` (Socket.IO, `server/services/websockets.ts` L34) and `/collaboration` (`collaboration.ts` L31). Troubleshooting L12-16: "Cannot edit documents ... your proxy is not allowing websocket connections through". agensio upgrades automatically with no idle limit.

### App guidance (what Outline does itself)

- **CSP** with a per-request nonce ([csp.ts L124-168](https://github.com/outline/outline/blob/v1.11.0/server/middlewares/csp.ts#L124-L168)) on every non-API answer (web.ts L96-97): `base-uri 'none'`, `default-src 'self'`, `script-src` (URL, `<host>/static/`, the nonce), `style-src 'self' 'unsafe-inline'`, `img-src * data: blob:`, `media-src * data: blob:`, `frame-src * data:`, `worker-src 'self'`, `object-src` and `connect-src *`.
  - It comes from koa-helmet 6.1.0 → helmet 4.6.0 (yarn.lock L11996-11998). In helmet 4 `useDefaults` is false (**inferred** from helmet 4's documented default), so there is **no `frame-ancestors`**.
  - Troubleshooting L58-62: third parties that modify the HTML, such as Cloudflare Rocket Loader, break the policy. agensio rewrites no bodies.
  - A proxy-set CSP must not replace Outline's.
- **`Referrer-Policy: no-referrer`** and `X-DNS-Prefetch-Control: on` (web.ts L99-110). agensio's baseline `Referrer-Policy` is a `default`, so it leaves Outline's stricter value alone.
- **X-Frame-Options:** none on ordinary pages.
  - `/embeds/*` set `X-Frame-Options: sameorigin` (`server/routes/embeds.ts` L65, 93, 119, 156).
  - Public shares remove the field "to be embedded in iframes on other websites unless prevented by team preference" (`server/routes/app.ts` L319-324).
  - A proxy-added frame field or `frame-ancestors` would break share embedding.
- **No HSTS** (no helmet `hsts` in use; grep of `server/` finds none). agensio `hsts` is the only source.
- **CORS:** `Access-Control-Allow-Origin: *` on `/images/`, `/email/` and `/fonts/` (routes/index.ts L28-41), on `/static/` (L70-92) and on `/locales/*.json` (L107-124).
- **Asset caching** ([routes/index.ts L69-105](https://github.com/outline/outline/blob/v1.11.0/server/routes/index.ts#L69-L105)):
  - `/static/` (hashed build output): `maxAge` 365 days with `immutable`, i.e. `Cache-Control: max-age=31536000, immutable` (koa-send).
  - `sw.js`: `Cache-Control: no-cache`, plus `Service-Worker-Allowed: /` on `/static/`. agensio's design refuses `Service-Worker-Allowed` as a rule name but passes the application's own field.
  - A missing `/static/` file answers 400 so CDNs don't cache it (L93-100).
  - Images and fonts: 7 days (L37-38).
  - Locales: `public, max-age=604800` (L118).
- **Redirects Outline does itself:**
  - `/share/...` gets a 301 to `/s/...` (L56-67).
  - Team and canonical-URL redirects (L196-220).
  - `apexRedirect` applies only to `getoutline.com` (`server/middlewares/apexRedirect.ts`).
- **.well-known:** `/.well-known/oauth-authorization-server`, `.../oauth-authorization-server/mcp`, `/.well-known/oauth-protected-resource` and `.../oauth-protected-resource/mcp` (JSON, `server/routes/discovery/mcp.ts` L9-61). All must reach Outline. No security.txt or change-password route.
- **Trusting the proxy:**
  - `PROXY_HEADERS_TRUSTED` (default `true`, env.ts L376-384) sets Koa `app.proxy = true`. Outline warns that CSRF protection weakens when it is off while `URL` is https and TLS is terminated upstream (web.ts L31-47).
  - `PROXY_IP_HEADER` names the client IP header, default `X-Forwarded-For`.
  - `FORCE_HTTPS` honours `X-Forwarded-Proto` only when proxy headers are trusted (web.ts L57-60).
  - `URL` must be the proxy's public URL (`.env.sample` L20-22). `COLLABORATION_URL` defaults to it (env.ts L271-273).
- **Subpath:** none is documented (not found in the hosting pages). **Unverified** whether Outline supports one.
- **agensio TOML:**
  ```toml
  [[site]]
  server_name = ["docs.mycompany.com"]
  tls = "auto"
  app = "proxy"
  upstream = "http://127.0.0.1:3000"
  settings = { max_body_size = "100M" }   # or [server] max_body_size; https-portal used 0 = unlimited
  ```
  The syntax of `settings.max_body_size` is **unverified**; check configuration.md.

---

## 25. Metabase

**Version read:** v0.64.1, released 2026-10-07, commit `7010f2797355cb04f2bc2e82e747eaa86357a315`. That is OSS; the enterprise tag is v1.64.1, not read.

**Sources:**
- Sparse clone of `docs/`, `src/metabase/server/` and `src/metabase/request/`, plus raw `src/metabase/util.cljc` and `src/metabase/oauth_server/api/metadata.clj` at the tag.
- The Elastic Beanstalk artifact that the v0.64.1 docs still link for upgrades: `running-metabase-on-elastic-beanstalk.md` L74, https://downloads.metabase.com/v0.47.2/metabase-aws-eb.zip. Its files are dated 2023-09-19 and were read as text.
- Proxy-related docs pages:
  - `installation-and-operation/running-metabase-as-service.md` (the only nginx example)
  - `installation-and-operation/security-best-practices-self-hosting.md`
  - `troubleshooting-guide/proxies.md`
  - `configuring-metabase/environment-variables.md`
  - `configuring-metabase/settings.md`
  - `exploration-and-organization/uploads.md`
- No Apache, Caddy, Traefik, HAProxy or IIS config exists in the docs. The repository has no proxy configs (`git ls-tree` search: only a ClickHouse driver test nginx file).

### Redirect and response-header directives

| location / line | directive (verbatim) | purpose | proposed class | agensio TOML / what's missing |
|---|---|---|---|---|
| EB artifact `.platform/nginx/nginx-ssl.conf` L36-39 (zip from the docs link above), `server { listen 80 default_server; ... location / {` | `if ($http_x_forwarded_proto != "https") { rewrite ^ https://$host$request_uri? permanent; }` | HTTP→HTTPS behind the AWS load balancer, which terminates TLS and sets `X-Forwarded-Proto`. Selected when `NGINX_FORCE_SSL=1` (`.platform/hooks/postdeploy/config_nginx.sh` L2-3). The target uses **`$host` and `$request_uri`** (the trailing `?` stops nginx appending the args twice). The condition is on a **request header**, and a missing header also redirects. | EXPRESSIBLE | This is exactly redirects.md 2.4: `[server] trusted_proxies = ["<the load balancer's ranges>"]` plus `[[site]] ... http = "redirect"`. agensio believes `X-Forwarded-Proto` only from trusted proxies, and a missing field also redirects. It answers 308 instead of 301 (the method is kept, no harm), with host, path and query kept. |
| security-best-practices-self-hosting.md [L29-34](https://github.com/metabase/metabase/blob/v0.64.1/docs/installation-and-operation/security-best-practices-self-hosting.md#L29-L34) (prose) | "By terminating TLS at your trusted load balancer or reverse proxy: set `MB_SITE_URL` to `https://<hostname>` and `MB_REDIRECT_ALL_REQUESTS_TO_HTTPS` to `true`. On the proxy, send `X-Forwarded-Proto: https`. Restrict access to Metabase's HTTP port to the proxy and trusted internal systems." | An **application-side** redirect ([ssl.clj L13-54](https://github.com/metabase/metabase/blob/v0.64.1/src/metabase/server/middleware/ssl.clj#L13-L54)): a 301 for GET/HEAD and a 307 otherwise, to `https://<site-url host:port><path>`, when the site URL is https and the request is not known to be HTTPS. It **exempts `/api/health`, `/livez` and `/readyz`** (L13-15). | EXPRESSIBLE (at the edge) | `http = "redirect"` at agensio, which always sends `X-Forwarded-Proto` (https on a TLS site). Metabase's own redirect then never fires. **Observation:** agensio's `http = "redirect"` exempts only ACME, so a load-balancer health probe over plain HTTP *through agensio* would get a 308. That is a gap only if probes take that path (NEEDS A CHANGE, minor: an exempt-path list, or probe Metabase directly). |

The only nginx example in the current docs ([running-metabase-as-service.md L119-130](https://github.com/metabase/metabase/blob/v0.64.1/docs/installation-and-operation/running-metabase-as-service.md#L119-L130)) is
`server { listen 80; listen [::]:80; server_name yourdomain.example.com; location / { proxy_pass http://127.0.0.1:3000; } }`.
It has no redirect and no header directive.

### Other directives (existing agensio features)

- **EB `nginx.conf` and `nginx-ssl.conf`:**
  - `gzip on; gzip_comp_level 4; gzip_types ...` (L30-32): on-the-fly compression, which agensio does not offer. Metabase compresses itself (`ring.middleware.gzip` `wrap-gzip`, `src/metabase/server/handler.clj` L112), so nothing is lost.
  - `map $http_upgrade $connection_upgrade { default "upgrade"; }` (L24-26) and `proxy_set_header Connection $connection_upgrade; Upgrade $http_upgrade;`: the automatic upgrade.
  - `Host $host`: the default. `X-Real-IP $remote_addr` is not read by Metabase by default. `X-Forwarded-For $proxy_add_x_forwarded_for` is sent by agensio.
  - `proxy_connect_timeout 600; proxy_send_timeout 600; proxy_read_timeout 600; send_timeout 600;` (L45-48 / L49-52): `proxy = { connect_timeout = ..., send_timeout = 600, read_timeout = 600 }`. Long queries need a long `read_timeout`; agensio's default is 60 s. nginx's `send_timeout` (to the client) is agensio's connection timeouts.
  - `listen 80 default_server`: a catch-all site (`default = true`). `worker_rlimit_nofile 65936` and `worker_connections 1024` are server-level.
- **Upload size:** uploads.md L86: "the default client upload limit for NGINX is 1 MB" against Metabase's 50 MB CSV uploads. agensio's `server.max_body_size` / `settings.max_body_size` (default 1 MB) must be raised to 50 MB.
- **troubleshooting-guide/proxies.md L7-34:** WAFs (Cloudflare, Azure), Rocket Loader and PageSpeed break saving and the CSP. agensio has no body rewriting and no WAF.

### App guidance (what Metabase does itself)

**Security headers on every answer** ([security.clj L521-547 and L640-683](https://github.com/metabase/metabase/blob/v0.64.1/src/metabase/server/middleware/security.clj#L521-L547)):
- **Cache:**
  - `Cache-Control: max-age=0, no-cache, must-revalidate, proxy-revalidate`, plus `Expires: Tue, 03 Jul 2001 06:00:00 GMT` and `Last-Modified: <now>`.
  - Or, for cacheable requests, `Cache-Control: public, max-age=31536000` (L58-67). Cacheable means GET of `/app/dist/` files with a hex hash, or `/app/fonts/*.woff2?|ttf|otf|eot` (`src/metabase/request/util.clj` L72-82). There is no `immutable`.
- **HSTS:** `Strict-Transport-Security: max-age=31536000` **always**, the comment saying "This only applies if the original request was HTTPS; if sent in response to an HTTP request, this is simply ignored" (L69-72, L533).
  - agensio `hsts = true` gives the same value and replaces it.
  - Without agensio `hsts`, Metabase's own field passes through. On a site with `http = "serve"` it would also go out over plain HTTP, where browsers ignore it.
  - Removing it is allowed (`remove = ["Strict-Transport-Security"]`).
- **CSP** with a per-request nonce (`generate-nonce`, L34; L247-417) and **`frame-ancestors`** by route (L386-394, L648-651):
  - `'none'` by default, or the interactive-embedding origins (`MB_EMBEDDING_APP_ORIGINS_INTERACTIVE`, Pro and Enterprise).
  - `*` for public links and static embeds.
  - `'self'` for data apps.
  - `MB_ALLOWED_IFRAME_HOSTS` drives `frame-src`; `MB_CSP_IMG_ENABLED` and `MB_CSP_IMG_ALLOWED_HOSTS` drive `img-src` (environment-variables.md L101, L351-367).
- **X-Frame-Options** (L419-428):
  - `DENY`, or `ALLOW-FROM <first interactive origin>`.
  - `SAMEORIGIN` for data apps.
  - **Omitted** for public and embed routes, so a proxy frame field would break Metabase's public sharing and static embedding.
- `X-Permitted-Cross-Domain-Policies: none` and `X-Content-Type-Options: nosniff` (L539-542).
- Optional `Cross-Origin-Resource-Policy` and `Cross-Origin-Embedder-Policy` from `MB_CROSS_ORIGIN_RESOURCE_POLICY` and `MB_CROSS_ORIGIN_EMBEDDER_POLICY` (L543-547).

**CORS:**
- Metabase **echoes the request Origin** when approved (embedding SDK origins `MB_EMBEDDING_APP_ORIGINS_SDK` plus the MCP origins), with `Vary: Origin`, `Access-Control-Allow-Headers: *`, `Access-Control-Allow-Methods: *`, `Access-Control-Expose-Headers: Content-Disposition, X-Metabase-Anti-CSRF-Token, X-Metabase-Version, Mcp-Session-Id` and `Access-Control-Max-Age: 60` (L503-519).
- `*` on `/auth/sso` for OPTIONS, 400 and 402 (L549-555, L669-672).
- The proxy must not add CORS. This is the "CORS echo" case the design defers, and here the application already does it.

**Other app behaviour:**
- **.well-known:** `/.well-known` is mounted to the OAuth server's routes ([routes.clj L111](https://github.com/metabase/metabase/blob/v0.64.1/src/metabase/server/routes.clj#L111)): `oauth-authorization-server`, `oauth-protected-resource`, `oauth-protected-resource/api/mcp` and `oauth-protected-resource/api/metabase-mcp` (`oauth_server/api/metadata.clj` L26-84). All must reach Metabase. No security.txt or change-password route.
- **Trusting the proxy:**
  - HTTPS detection (`https-state`, `src/metabase/util.cljc` L240-268) reads `X-Forwarded-Proto`, `X-Forwarded-Protocol`, `X-Url-Scheme`, `X-Forwarded-Ssl`, `Front-End-Https` and `Origin` **from any peer**. There is no trusted-proxy list, hence the docs' "Restrict access to Metabase's HTTP port to the proxy".
  - The client address comes from `MB_SOURCE_ADDRESS_HEADER` (default `X-Forwarded-For`) unless `MB_NOT_BEHIND_PROXY=true` (environment-variables.md L1980-1985, L2761-2768).
  - `MB_SITE_URL` must be exactly the public URL (L2654-2664). `MB_SESSION_COOKIE_SAMESITE` is needed for cross-domain embedding (L2529-2539).
  - Settings → "Redirect to HTTPS" (settings.md L22-30) is the same as `MB_REDIRECT_ALL_REQUESTS_TO_HTTPS`.
- **agensio TOML:**
  ```toml
  [[site]]
  server_name = ["metabase.example.com"]
  tls = "auto"
  app = "proxy"
  upstream = "http://127.0.0.1:3000"
  proxy = { read_timeout = 600 }          # the EB config's 600 s for long queries
  # max_body_size >= 50 MB for CSV uploads (server or managed settings)
  ```

---

## 26. Cross-cutting findings

### 26.1 Redirects

- **Plain HTTP to HTTPS is nearly the only redirect a proxy configuration sends.** It appears in 18
  of the 25: Mastodon, Discourse (its container's TLS template), Ghost (the application itself,
  and Caddy's implicit one in ghost-docker), Plausible (Caddy's implicit one), Forgejo, GitLab,
  Mattermost, Rocket.Chat, Synapse (lighttpd), Vaultwarden, n8n, Jellyfin, Home Assistant,
  Nextcloud AIO, Paperless, Uptime Kuma (implicit), Outline (https-portal, or the application's
  `FORCE_HTTPS`), Metabase (Elastic Beanstalk). Every form (`return 301 https://$host$request_uri`,
  `$server_name`, a fixed name, Apache `RewriteRule ... [R=permanent]`, HAProxy
  `redirect scheme https`, Traefik entrypoint redirection, IIS) is `http = "redirect"`. The two
  that test `X-Forwarded-Proto` behind another proxy (Nextcloud AIO's nginx, Metabase's Beanstalk
  nginx) are `redirects.md` 2.4 with `trusted_proxies`, which also fixes their trust-anyone test.
  agensio answers 308 where they answer 301; none of these applications relies on a POST turning
  into a GET.
- **Canonical host**: Discourse's container, ghost-docker (www to apex and back), Mattermost and
  Nextcloud (`$server_name`), Jellyfin's Traefik `SSLHost`: all `canonical`. Discourse also
  redirects a request by IP address or for an unknown Host; the design leaves those unredirected on
  purpose (3.3), and Discourse works.
- **Path redirects at the proxy are few and simple**: Mastodon's apex `/.well-known/webfinger` (an
  exact rule, with `Access-Control-Allow-Origin: *` on the 301 itself, which the design's "every
  answer" covers), Mastodon's media migration, Nextcloud's CalDAV/CardDAV discovery and `/remote`,
  Vaultwarden's old host name, and the `/x` to `/x/` slash of three sub-path setups. None needs a
  capture: the regex in Nextcloud's Traefik example captures only the host, and the `(.*)` of
  Vaultwarden's lighttpd example is the remainder.
- **No current official configuration redirects `/` to a sub-application.** Jellyfin's docs dropped
  `location = / { return 302 .../web/; }` in 2024 because the server redirects `/` to `web/`
  itself; Keycloak (`/` to `/admin/`), Uptime Kuma (`/` to `/dashboard`) and Synapse (`/` to its web
  client) also redirect themselves. The proxy only has to forward `/`.
- **Not offered, and each application still works**: BookStack's trailing-slash removal (a capture
  plus a filesystem test; Laravel's router ignores a trailing slash, and BookStack's own nginx
  configurations have no such rule); Vaultwarden's redirect of `/admin` for clients outside private
  ranges (`[[site.access]]` gives a 403 instead); Nextcloud's redirect of Microsoft's `DavClnt`
  User-Agent at `/` (affects only a Windows WebDAV client pointed at the bare site URL); Mattermost's
  `HEAD` answered 200 on a sub-path; Jellyfin's Traefik page serving plain and TLS on one port.
- **`.well-known` paths the applications answer themselves** and the proxy must only forward:
  Gitea and Forgejo (`openid-configuration`, `webfinger`, `nodeinfo`, `change-password`, files in
  `public/.well-known/`), GitLab (`change-password`, `security.txt`, `openid-configuration`,
  `webfinger`, OAuth and MCP discovery, `terraform.json`), Grafana and Uptime Kuma
  (`change-password`), Immich (`/.well-known/immich`, which its mobile app needs), Home Assistant,
  Outline and Metabase (OAuth discovery for MCP), Vaultwarden (`apple-app-site-association`),
  Nextcloud (everything but `acme-challenge` and `pki-validation`, through `index.php`), Mastodon
  on its own host (`host-meta`, `nodeinfo`, `webfinger`). agensio intercepts only
  `/.well-known/acme-challenge/`, so all of them reach the application. Delegation from another
  domain is a redirect (Mastodon WebFinger: expressible), a proxy to another service (Ghost's
  ActivityPub `webfinger` and `nodeinfo`: a location with an upstream, blocked only when that
  upstream is a DNS name), or a fixed JSON file (Matrix: expressible today, section 11's note).
  No official configuration serves `security.txt` or `change-password` at the proxy.

### 26.2 Response headers

- **Fixed values suffice.** The only values that use a variable are debug fields of nginx's own
  proxy cache (`X-Cached` and `X-Cache-Status` in Mastodon, `X-Cache` in Plausible's script guide)
  and Mattermost's `X-Early-Data` (agensio has no 0-RTT), plus two nginx `map`s that encode a
  condition rather than a value: Ghost-CLI's (no `nosniff` on a 204) and Nextcloud's (`immutable`
  only with `?v=`). Apache `Define` (Paperless) and Caddy environment placeholders (ghost-docker) are
  fixed at load.
- **Path rules by whole-segment prefix cover the per-path cases**: Mastodon's eight static
  prefixes, Discourse's five, GitLab's `/assets`, Umami's `/stats/_next/static/`, Element's no-cache
  paths, Paperless's `/accounts/{login,signup,2fa}`, Synapse's `/.well-known/matrix`. Two habits an
  agent brings from nginx and Caddy matter: rules match the path the client asked for, so Element's
  `/` needs its own exact rule beside `/index.html`; and nginx's `location /config` and Caddy's
  `/admin*` are character prefixes, while agensio's are whole segments (Element's `config.json` and
  each `config.<name>.json` become exact rules). Also, Caddy's `header / { ... }` matches the exact
  path `/` only, so the Vaultwarden wiki's security-header block applies to one page, not the site.
- **Per-file-type rules** appear only in Discourse's inner nginx and Nextcloud's own PHP sample
  (28.4).
- **Frame fields: 21 of the 25 decide framing themselves**, most of them per route: Mastodon (its
  embed route deletes `X-Frame-Options`), Discourse (`/embed/`), Plausible (shared dashboards carry
  none), Umami (`ALLOWED_FRAME_URLS`), Gitea and Forgejo (a setting), GitLab, Mattermost
  (`FrameAncestors`), Rocket.Chat (iframe settings), Synapse, Keycloak (per realm), Vaultwarden (none
  on the WebAuthn and Duo connector pages), n8n (preview mode), Home Assistant (an option, off to
  embed it), Nextcloud, Paperless (`SAMEORIGIN` for its PDF preview), Grafana (`allow_embedding` and
  a per-URL exception), Uptime Kuma (an environment variable), BookStack (`ALLOWED_IFRAME_HOSTS`),
  Outline (shares drop it), Metabase (none on public links and embeds). A `default` frame field
  would break Vaultwarden's MFA (its connector pages have none on purpose) and every embedding
  above. Element (static files) is the one that asks the proxy for `X-Frame-Options: SAMEORIGIN` and
  `frame-ancestors 'self'`; Jellyfin's docs removed both in 2025 because the LG webOS client frames
  the web client. This confirms `headers.md` 4.1 and decision 10.2.
- **CSP: 20 of the 25 send one of their own** on some or all answers (Mastodon, Discourse,
  Plausible, Umami, Gitea, Forgejo on raw files, GitLab when enabled, Mattermost, Rocket.Chat,
  Synapse, Keycloak, Vaultwarden, n8n, Nextcloud, Grafana when enabled, BookStack, Outline,
  Metabase, Immich when enabled, Element as a `<meta>`), ten of them with a per-request nonce or
  hashes a fixed proxy value cannot reproduce (Mastodon, Gitea, GitLab, Mattermost, n8n, Nextcloud,
  Grafana, BookStack, Outline, Metabase). Proxy-set CSPs in official configurations are on
  answers no application policy covers (Mastodon's uploaded media from disk and its object-storage
  proxy, Element's static files, Jellyfin, which sends none) or are frame-only (ghost-docker). So
  `default` is the right verb for a CSP and the warning on `set` (headers.md 7) is justified.
- **Referrer-Policy as `default` is safe on all 25.** Applications send `no-referrer` (Home
  Assistant, Mattermost, Keycloak, Outline, Nextcloud), `same-origin` (Mastodon, Vaultwarden,
  Paperless through Django) or `strict-origin-when-cross-origin` (GitLab through Rails), and the
  baseline never overrides them. Paperless shows what a `set` can do: `no-referrer` site-wide makes
  browsers send `Origin: null` on the login POST and Django's CSRF check refuses it, which is why its
  wiki spends sixty lines on giving `/accounts/login/`, `/signup/` and `/2fa/` `same-origin`.
- **`nosniff`** on application answers has one recorded breakage here: Ghost-CLI keeps it off 204
  answers because iOS Safari offers an empty 204 carrying it as a download (Ghost-CLI #1858). This
  supports the baseline's choice to put `nosniff` only on agensio's own answers (28.6).
- **CORS set at the proxy is always a fixed `*`** (Mastodon's WebFinger redirect, CDN host and
  object-storage proxy; Discourse's assets; Synapse's `.well-known/matrix`; Element's `home.html`).
  Origin echo is done by the applications themselves where it is needed (Vaultwarden, Metabase,
  Gitea, Paperless through django-cors-headers); the one proxy-side echo, a user's Caddy fix in the
  Paperless wiki, is unnecessary once `PAPERLESS_URL` is set. Nothing here asks for the typed `cors`
  setting yet.
- **HSTS values published by the projects**:

  | source | value |
  |---|---|
  | Mastodon `dist/nginx.conf` (and Rails `force_ssl`) | `max-age=63072000; includeSubDomains` |
  | Discourse container, ghost-docker, Vaultwarden wiki, Nextcloud AIO (inner), Metabase (app) | `max-age=31536000` |
  | Ghost-CLI (shadowed by later `add_header` lines, inferred) | `max-age=63072000; includeSubDomains; preload` |
  | GitLab Omnibus (default, `always`) | `max-age=63072000`, `includeSubdomains` opt-in |
  | Mattermost docs / Docker repo | `max-age=15768000` / `max-age=63072000` `always` |
  | Rocket.Chat post-quantum TLS page | `max-age=63072000` `always` |
  | Keycloak (app, per realm) | `max-age=31536000; includeSubDomains` |
  | n8n Traefik, Jellyfin Traefik | `max-age=315360000; includeSubDomains; preload`, also over HTTP |
  | Home Assistant add-on (default option) | `max-age=31536000; includeSubDomains` `always` |
  | Nextcloud manual sample (commented, with a warning) | `max-age=31536000; includeSubDomains; preload` |
  | Paperless wiki | Apache `max-age=15552000; preload`, Caddy `max-age=31536000; includeSubdomains` |
  | Umami (app, with `FORCE_SSL`) | `max-age=63072000; includeSubDomains; preload` |
  | Grafana (app, opt-in) | `max-age=86400` by default |

  `preload` appears in 6 (Ghost-CLI, Umami, Jellyfin, n8n, Nextcloud's sample, Paperless's wiki) and
  none needs it; HSTS over plain HTTP in 2 (Jellyfin and n8n's Traefik `forceSTSHeader`), which
  browsers ignore. Both stay not offered (4.6, 4.1).

### 26.3 Outside this design, found on the way

- **Client-address fields a client can forge through agensio.** 17 of the 25 official
  configurations set `X-Real-IP` to the peer (`proxy_set_header X-Real-IP $remote_addr` or the
  Apache and Caddy equivalents); agensio sends none and passes a client's own unchanged
  (`proxy.cpp` L91-119). Six applications by default take the client address from a field agensio
  passes through, before or instead of `X-Forwarded-For`:
  - Vaultwarden: `IP_HEADER` defaults to `X-Real-IP`, trusted from any non-global address, and the
    address keys the login and admin rate limits (`.env.template` L331-342);
  - Rocket.Chat: `x-real-ip` first when `HTTP_FORWARDED_COUNT` is unset (REST
    `remoteAddressMiddleware.ts` L14-22; DDP `getClientAddress.ts` L10);
  - Grafana: `X-Real-IP` first, from any peer (`pkg/web/context.go` L71-78);
  - Discourse's socketed container: its inner nginx trusts the socket and reads nginx's default
    `real_ip_header`, `X-Real-IP`;
  - Plausible: `x-plausible-ip`, `cf-connecting-ip`, `b-forwarded-for` before `x-forwarded-for`;
  - Umami: `true-client-ip`, `cf-connecting-ip` and others, and `x-real-ip`, before
    `x-forwarded-for`.

  Keycloak's guide asks the proxy to strip `X-Real-IP`. Per site the fix exists today
  (`proxy = { headers = { "X-Real-IP" = "$remote_addr" } }`, `""` for the CDN fields), but the
  cookbook's Rocket.Chat recipe (`docs/examples/proxy.md` L227-273) lacks it. A default that treats
  `X-Real-IP` like `X-Forwarded-For` (replaced from untrusted peers, or dropped) and drops the CDN
  client-address fields from untrusted peers would close it for every site; that belongs to the
  proxy's request fields, not to this design.
- **Upstreams by DNS name** (refused today): Ghost's ActivityPub service (default
  `https://ap.ghost.org`), Mastodon's object-storage proxy, Plausible's tracking-script proxy (3).
- **Files from disk with a fallback to the application** (`try_files $uri @app`): Mastodon,
  Discourse (2). Per-prefix `alias` locations are the workaround.
- **Custom pages for an origin that is down**: Mastodon `/500.html`, Discourse's offline page,
  GitLab's error pages, the Paperless wiki's `ErrorDocument 503` (4). Each works with agensio's own.
- **Large or unlimited request bodies**: GitLab and Nextcloud AIO `0`, Outline's https-portal `0`,
  Immich `50000M` (4). A managed site's ceiling is `site_limits.max_body_size`, 512 MB by default.
- **Tokens in logged URLs**: GitLab filters `private_token` and others from its access log, Jellyfin
  `api_key`, Vaultwarden the WebSocket `access_token` (3).

## 27. Summary table

One row per application and directive (or group of like directives). Classes: EXPR(ESSIBLE),
CHANGE (needs a change), NOT-OFFERED (on purpose), OTHER (another existing feature). Sections 1-25
hold the verbatim directives, links and TOML.

| # | application | directive (source) | class | agensio setting, or what is missing |
|---|---|---|---|---|
| 1 | Mastodon | `return 301 https://$host$request_uri` (dist/nginx.conf L30) | EXPR | `http = "redirect"` |
| 1 | Mastodon | HSTS `max-age=63072000; includeSubDomains` (L70, per location) | EXPR | `hsts = { max_age = "2y", subdomains = true }` |
| 1 | Mastodon | `Cache-Control "public, max-age=2419200, must-revalidate"` on 7 static prefixes | EXPR | `[[site.response_headers]]` per prefix, `when = "success"` |
| 1 | Mastodon | `/system/`: immutable cache, `nosniff`, CSP `default-src 'none'; form-action 'none'` | EXPR | two rules on `/system/` |
| 1 | Mastodon | `proxy_pass_header Server` | NOT-OFFERED | `Server` is agensio's |
| 1 | Mastodon | `add_header X-Cached $upstream_cache_status` | NOT-OFFERED | no variables, no proxy cache |
| 1 | Mastodon | docs: apex `/.well-known/webfinger` 301 to the web domain, with ACAO `*` | EXPR | exact `[[site.redirect]]` + ACAO rule (reaches the 301) |
| 1 | Mastodon | docs: ACAO `*` on the CDN host | EXPR | rule on `/` of the asset site |
| 1 | Mastodon | docs: object-storage proxy, 10 × `proxy_hide_header` | OTHER | `proxy = { hide = [...] }` |
| 1 | Mastodon | docs: object-storage proxy, `expires 1y`, ACAO, `nosniff`, CSP; `X-Cache-Status` | EXPR; NOT-OFFERED | rules; the DNS-named upstream is outside (26.3) |
| 1 | Mastodon | docs: migrate `/system/` to the files host | EXPR | prefix `[[site.redirect]]` |
| 2 | Discourse | outer proxy (meta guide): none; needs `X-Real-IP` | OTHER | `proxy.headers` |
| 2 | Discourse | container: `return 301 https://${DISCOURSE_HOSTNAME}$request_uri` | EXPR | `http = "redirect"` + `canonical` |
| 2 | Discourse | container: HSTS `max-age=31536000` | EXPR | `hsts = true` |
| 2 | Discourse | container: any other Host `rewrite ... permanent` | EXPR / NOT-OFFERED | `canonical` for listed names; not for an IP or unknown Host |
| 2 | Discourse | inner: `etag off`, `add_header ETag ""` | NOT-OFFERED | `ETag` is the cache's; no dynamic gzip |
| 2 | Discourse | inner: `/favicon.ico` `return 204` | OTHER | leave to the application |
| 2 | Discourse | inner: `/assets/`, `/plugins/`, `/javascripts/`, `/images/emoji/`, `/uploads/` expires + immutable + ACAO | EXPR | prefix rules, `when = "success"` for the cache |
| 2 | Discourse | inner: fonts by extension, expires + ACAO | CHANGE | suffix condition (28.4); prefixes approximate |
| 2 | Discourse | inner: `/uploads/` images by extension, ACAO | CHANGE | suffix condition; ACAO on all `/uploads/` approximates |
| 2 | Discourse | inner: `/uploads/` `.svg` `Content-Disposition: attachment` | CHANGE | suffix condition |
| 2 | Discourse | inner: `proxy_hide_header Set-Cookie`, `X-Discourse-Username`, `X-Runtime` | OTHER | `proxy.hide` |
| 2 | Discourse | container: offline page `error_page 502` | OTHER | no custom error pages |
| 3 | Ghost | Ghost-CLI: `nosniff` on every answer except 204 (`map $status`) | CHANGE | no status condition (28.6) |
| 3 | Ghost | Ghost-CLI: HSTS `...; includeSubDomains; preload` | EXPR / NOT-OFFERED | `hsts = { max_age = "2y", subdomains = true }`; no preload |
| 3 | Ghost | Ghost-CLI: `X-Frame-Options SAMEORIGIN` | EXPR | `default`; would block a separate admin domain's previews (inferred) |
| 3 | Ghost | Ghost-CLI: `proxy_redirect off` (sub-directory) | OTHER | `proxy.redirects = "pass"` |
| 3 | Ghost | ghost-docker: HSTS 1y, `X-XSS-Protection 1; mode=block`, `nosniff`, Referrer-Policy, CSP `frame-ancestors 'self' <admin>` | EXPR | `hsts = true`; rules (CSP as `default`; X-XSS warned) |
| 3 | Ghost | ghost-docker: www and apex `redir` (302) | EXPR | `canonical` (308) |
| 3 | Ghost | ActivityPub: `/.well-known/webfinger`, `/.well-known/nodeinfo`, `/.ghost/activitypub/` proxied | OTHER | exact locations with `upstream`; default upstream is a DNS name (26.3) |
| 3 | Ghost | analytics `path_regexp` + `rewrite` | OTHER | `upstream` with a URI part |
| 4 | Plausible | Caddy implicit HTTPS redirect (wiki, community) | EXPR | `http = "redirect"` |
| 4 | Plausible | Apache `ProxyPassReverse` | OTHER | `proxy.redirects = "rewrite"` |
| 4 | Plausible | script guide `X-Cache $upstream_cache_status` | NOT-OFFERED | no variables |
| 5 | Umami | `/stats/_next/static/` from disk, `expires max` | EXPR | `alias` location + rule `when = "success"` |
| 5 | Umami | heatmaps: tracked site CSP `frame-ancestors`, remove XFO | EXPR | `default` CSP + `remove` |
| 6 | Gitea | none in 14 examples; CDN host `return 404` | OTHER | `handler = "deny"` |
| 6 | Gitea | IIS outbound rule rewriting links in HTML | OTHER | no body rewriting; `ROOT_URL` makes it unneeded |
| 6 | Gitea | (code comment invites a second CSP at the proxy) | CHANGE, optional | append verb (28.7) |
| 7 | Forgejo | HTTP to HTTPS: nginx `return 301`, Apache `R=permanent`, HAProxy, Puppet | EXPR | `http = "redirect"` |
| 7 | Forgejo | (docs name CSP as a reason for a proxy, no example) | EXPR | `default` CSP |
| 8 | GitLab | Omnibus `return 301 https://fqdn:port$request_uri`; source install `return 301` | EXPR | `http = "redirect"` |
| 8 | GitLab | Omnibus: 8 monitoring paths served over plain HTTP despite the redirect | CHANGE | exempt list (28.5), or a plain site on an internal address |
| 8 | GitLab | HSTS `max-age=63072000[; includeSubdomains]` `always`, also when `listen_https = false` | EXPR | `hsts = { max_age = "2y" }`; replaces the bundled nginx's (28.2) |
| 8 | GitLab | `proxy_hide_header Referrer-Policy` + `add_header Referrer-Policy` | EXPR | `set` |
| 8 | GitLab | docs: `Cross-Origin-Resource-Policy cross-origin` | EXPR | `set` |
| 8 | GitLab | Passenger: `/assets` `expires max` + `Cache-Control public` | EXPR | rule `when = "success"` |
| 8 | GitLab | custom error pages, `proxy_intercept_errors`; `proxy_cache` on assets | OTHER | none in agensio; the app works |
| 9 | Mattermost | `return 301 https://$server_name$request_uri` (docs, Docker, certbot) | EXPR | `http = "redirect"` (+ `canonical`) |
| 9 | Mattermost | HSTS `max-age=15768000` (docs), `63072000` `always` (Docker) | EXPR | `hsts`; seconds need 28.1 |
| 9 | Mattermost | `add_header X-Early-Data $tls1_3_early_data` | NOT-OFFERED | no variables; no 0-RTT in agensio |
| 9 | Mattermost | `proxy_set_header X-Frame-Options SAMEORIGIN` (a request field, every location) | OTHER | no effect; omit |
| 9 | Mattermost | Docker: XFO, `X-XSS-Protection`, `nosniff`, `Referrer-Policy no-referrer`, `Permissions-Policy`, `X-Robots-Tag` | EXPR | rules (XFO as `default`) |
| 9 | Mattermost | user-image `proxy_cache_valid`; sub-path `HEAD` `return 200` | OTHER | no proxy cache; no method condition, not needed |
| 10 | Rocket.Chat | `return 301` (Docker, post-quantum page), Traefik entrypoint redirect, Caddy implicit | EXPR | `http = "redirect"` |
| 10 | Rocket.Chat | post-quantum page: HSTS 2y `always`, XFO `SAMEORIGIN`, `nosniff` | EXPR | `hsts = { max_age = "2y" }`; XFO as `default` |
| 10 | Rocket.Chat | federation: `/.well-known/matrix/server` JSON on the federation domain | EXPR | `.json` file + exact location `try_files` (tested) |
| 10 | Rocket.Chat | `X-Real-IP $remote_addr` (read first by the app) | OTHER | `proxy.headers`; default gap (26.3) |
| 11 | Synapse | `.well-known/matrix/server` and `client` as fixed JSON (nginx `return 200`, Caddy `respond`, HAProxy `return`) | EXPR | `.json` file + exact location `try_files` (tested on alpha.72) |
| 11 | Synapse | `add_header Content-Type application/json`, `default_type` | OTHER | the `.json` extension gives it |
| 11 | Synapse | ACAO `*` (+ `-Methods`, `-Headers`) on `.well-known/matrix` | EXPR | rule on `/.well-known/matrix` |
| 11 | Synapse | lighttpd HTTP to HTTPS; lighttpd rewrite to `.json` files | EXPR; OTHER | `http = "redirect"`; `try_files` hop |
| 12 | Element Web | XFO `SAMEORIGIN`, `nosniff`, `X-XSS-Protection 1; mode=block`, CSP `frame-ancestors 'self'` | EXPR | rule on `/` (static site) |
| 12 | Element Web | `Cache-Control no-cache` on `/index.html`, `/version`, `/i18n/`, `/config*` | EXPR | exact rules incl. `/` and each `config.<name>.json` |
| 12 | Element Web | `home.html` ACAO `*` | EXPR | exact rule |
| 13 | Keycloak | none; exposed-path filtering | OTHER | `[[site.access]]` |
| 13 | Keycloak | strip `X-Real-IP`, `X-Original-URL`, tracing fields | OTHER | `proxy.headers` with `""` |
| 13 | Keycloak | (app sends HSTS 1y `includeSubDomains` itself) | note | `hsts = true` would drop `includeSubDomains` (28.2) |
| 14 | Vaultwarden | Caddy: redirect `/admin*` to `/` unless a private client (wiki, community) | NOT-OFFERED | `[[site.access]]` (403) |
| 14 | Vaultwarden | HSTS `max-age=31536000` (Caddy; nginx commented) | EXPR | `hsts = true` |
| 14 | Vaultwarden | `X-XSS-Protection 0`, `X-Robots-Tag`, `nosniff`, `-X-Powered-By` | EXPR | rules (the app sends the first three itself) |
| 14 | Vaultwarden | `X-Frame-Options DENY` | EXPR, harmful | breaks the WebAuthn/Duo connector pages; offer none |
| 14 | Vaultwarden | `-Server`, `-Last-Modified` | NOT-OFFERED | refused names |
| 14 | Vaultwarden | `return 301`, Traefik `redirectScheme`, NixOS `forceSSL`, Istio, Pound | EXPR | `http = "redirect"` |
| 14 | Vaultwarden | only `/vault/` redirected to HTTPS, rest of the domain plain | EXPR | TLS site `http = "off"` + plain site with `[[site.redirect]]` |
| 14 | Vaultwarden | lighttpd old host to new host, path kept | EXPR | prefix `[[site.redirect]]` from `/` |
| 14 | Vaultwarden | lighttpd `https-remap` | EXPR | 2.5 (Location upgraded) |
| 14 | Vaultwarden | Cloudflare tunnel 404 on `admin`; Caddy `abort` | OTHER | `refuse` / `handler = "deny"` |
| 15 | n8n | Traefik entrypoint redirect; `SSLRedirect` | EXPR | `http = "redirect"` |
| 15 | n8n | `STSSeconds=315360000`, `STSIncludeSubdomains` | EXPR | `hsts = { max_age = 315360000, subdomains = true }` once seconds are accepted (28.1) |
| 15 | n8n | `STSPreload`; `forceSTSHeader` | NOT-OFFERED | 4.6; never over HTTP |
| 15 | n8n | `browserXSSFilter`, `contentTypeNosniff` | EXPR | rules |
| 15 | n8n | `SSLHost` (removed in Traefik v3) | OTHER | not reproduced |
| 16 | Jellyfin | `nosniff`, `Permissions-Policy`, CSP (active) | EXPR | rules (CSP as `default`) |
| 16 | Jellyfin | HTTP to HTTPS (nginx, Apache, HAProxy, Traefik) | EXPR | `http = "redirect"` |
| 16 | Jellyfin | Caddy `redir /jellyfin /jellyfin/` | EXPR | exact rule (28.3); the server does it too |
| 16 | Jellyfin | Apache `Cache-Control no-store...` (commented) | EXPR | rule |
| 16 | Jellyfin | Traefik: `X-Robots-Tag`, `frameDeny`, `nosniff`, `X-XSS-Protection 1` | EXPR | rules; `frameDeny` discouraged (webOS) |
| 16 | Jellyfin | Traefik: STS 315360000 + subdomains; preload, `forceSTSHeader` | EXPR; NOT-OFFERED | `hsts` (28.1) |
| 16 | Jellyfin | Traefik: `ALLOW-FROM`; same-port plain and TLS | NOT-OFFERED | `frame-ancestors` via `default` CSP; use 80/443 |
| 16 | Jellyfin | `/` to `/web/` (dropped from the docs; the server does it) | OTHER | forward `/` |
| 17 | Home Assistant | add-on `return 301` (port 80 off by default) | EXPR | `http = "redirect"` or `"off"` |
| 17 | Home Assistant | add-on HSTS option `max-age=31536000; includeSubDomains` `always` | EXPR | `hsts = { max_age = "1y", subdomains = true }` |
| 17 | Home Assistant | `proxy_redirect http:// https://` | EXPR | 2.5 (Location upgraded) |
| 17 | Home Assistant | `add_header Alt-Svc`; `return 444` / `ssl_reject_handshake` | OTHER | `protocols` h3; 421 and handshake refusal |
| 18 | Immich | none; `proxy_redirect off`, `ProxyPassReverse`; `/.well-known/immich` proxied | OTHER | defaults |
| 19 | Nextcloud AIO | HTTP to HTTPS (Apache, nginx `$scheme` and `X-Forwarded-Proto` forms, Traefik, IIS) | EXPR | `http = "redirect"` (+ `trusted_proxies`) |
| 19 | Nextcloud AIO | Traefik `referrerPolicy: same-origin` | EXPR | `default` |
| 19 | Nextcloud AIO | `Alt-Svc` (commented); NPM `proxy_hide_header Upgrade` | OTHER | `protocols`; h2/h3 writers drop `Upgrade` |
| 19 | Nextcloud AIO | inner container: HSTS 1y, `-Server -X-Powered-By -Via`, CalDAV/CardDAV `redir` | OTHER | done inside AIO; EXPR if needed |
| 19 | Nextcloud (manual) | `return 301 https://$server_name...`; five security headers `always`; `fastcgi_hide_header X-Powered-By` | EXPR | `http`, `canonical`, rules, baseline |
| 19 | Nextcloud (manual) | HSTS `...; includeSubDomains; preload` (commented) | EXPR / NOT-OFFERED | no preload |
| 19 | Nextcloud (manual) | `/.well-known/carddav`, `caldav` 301; `/remote` 301; Service Discovery redirects in 6 servers | EXPR | exact and prefix `[[site.redirect]]` |
| 19 | Nextcloud (manual) | `/.well-known` catch-all 301 except `acme-challenge`, `pki-validation` | OTHER | front controller (an internal rewrite, as `.htaccess` does); as a redirect it cannot exempt a sub-path |
| 19 | Nextcloud (manual) | `DavClnt` User-Agent 302 at `/` | NOT-OFFERED | no request-header conditions |
| 19 | Nextcloud (manual) | asset `Cache-Control` by extension, `immutable` only with `?v=`; fonts `expires 7d` | CHANGE | suffix and query conditions (28.4); suffix locations + `add_headers` today |
| 20 | Paperless | Referrer-Policy `same-origin` on `/accounts/{login,signup,2fa}`, `no-referrer` elsewhere (nginx, Apache, Caddy; wiki) | EXPR | longest-path rules |
| 20 | Paperless | Apache HTTP to HTTPS except ACME | EXPR | `http = "redirect"` |
| 20 | Paperless | HSTS `15552000; preload`, `31536000; includeSubdomains` | EXPR / NOT-OFFERED | `hsts` (28.1); no preload |
| 20 | Paperless | `nosniff`, `X-Robots-Tag`, `X-XSS-Protection`, XFO, `Permissions-Policy`, CSP, P3P | EXPR | rules (CSP as `default`) |
| 20 | Paperless | XFO `ALLOW-FROM`; `-Server` | NOT-OFFERED | `frame-ancestors`; server-wide |
| 20 | Paperless | `ErrorDocument 503` page | OTHER | no custom error pages |
| 20 | Paperless | Caddy CORS preflight 204 + Origin echo | NOT-OFFERED | the app does CORS |
| 21 | Grafana | nginx `/grafana/`: implicit 301 from `/grafana` | EXPR | exact rule (28.3) |
| 21 | Grafana | `rewrite ... break`, HAProxy `set-path`, IIS rewrite; `ProxyPassReverse` | OTHER | `upstream` URI part; `proxy.redirects` |
| 22 | Uptime Kuma | Caddy, certbot, https-portal implicit HTTPS redirect (wiki) | EXPR | `http = "redirect"` |
| 22 | Uptime Kuma | OpenLiteSpeed "Header Operations" `Upgrade`/`Connection`; Apache `[P]` | OTHER | automatic upgrade |
| 23 | BookStack | trailing-slash removal `RewriteRule ^ %1 [L,R=301]` (Apache, `.htaccess`, `web.config`, install scripts) | NOT-OFFERED | no slash policy, no captures; the app works |
| 23 | BookStack | nginx sub-path: implicit `/bookstack` to `/bookstack/` | EXPR | exact rule (28.3) |
| 23 | BookStack | `proxy_pass` with URI, `proxy_redirect off`; Caddy `php_fastcgi` slash, `encode` | OTHER | `upstream` URI part, `proxy.redirects`; directory slash built in; no compression |
| 23 | BookStack | (security docs: the server may add a second CSP) | CHANGE, optional | append verb (28.7) |
| 24 | Outline | HTTPS by the app (`FORCE_HTTPS`) or https-portal | EXPR | `http = "redirect"` |
| 24 | Outline | `proxy_redirect off` | OTHER | `proxy.redirects` |
| 25 | Metabase | Beanstalk: `if ($http_x_forwarded_proto != "https") rewrite ... permanent` | EXPR | `http = "redirect"` + `trusted_proxies` (2.4) |
| 25 | Metabase | app's own redirect exempts `/api/health`, `/livez`, `/readyz` | EXPR / CHANGE (minor) | exempt list only if probes cross agensio (28.5) |

## 28. Design changes the evidence supports

Each with the number of applications whose official configuration needs it.

### 28.1 `max_age` takes seconds (4 applications)

Every configuration writes HSTS in seconds, and four publish a value that is not a whole number of
years: Mattermost `15768000` (182.5 days), Paperless's wiki `15552000`, Jellyfin's Traefik page and
n8n `315360000` (ten years). The design shows only `"2y"` and `0`, and agensio has no duration
grammar yet. Smallest change: `max_age` accepts an integer of seconds as well as a duration, and the
reference row says the units and whether more than two years is accepted.

### 28.2 Say what `hsts` does to an application's own HSTS (8 send one; 4 would be weakened)

Eight applications can send HSTS themselves: by default Keycloak, Mastodon (Rails `force_ssl`),
Metabase, Nextcloud AIO's inner Caddy and GitLab Omnibus's bundled nginx (its template emits it
even with `listen_https = false` behind another proxy, inferred from the template); when enabled Umami (`FORCE_SSL`), Grafana and
Mattermost. Since `hsts` replaces the application's field, `hsts = true` would narrow four of them:
Keycloak (drops `includeSubDomains`), Mastodon (two years with subdomains to one without), GitLab
(two years to one), Umami (drops `includeSubDomains` and `preload`). Browsers keep the latest policy
they see (RFC 6797 8.1), so the narrowing is silent. Smallest change: `path_check` and health name
the application's own value when `hsts` replaces it with a shorter `max-age` or without
`includeSubDomains`, and the cookbook recipes for these applications write the matching `hsts`. The
design should also state the case without `hsts`: the application's field passes as sent, `preload`
included, and on an `http = "serve"` site over plain HTTP too (Metabase sends it on every answer);
dropping an application's HSTS from plain-HTTP answers would make 4.1's "never over plain HTTP" hold
for every answer.

### 28.3 An exact rule from `/x` to `/x/` is legal (3 applications)

Sub-path setups need the bare prefix to gain its slash: Grafana and BookStack through nginx's
implicit 301, Jellyfin through Caddy's `redir` (its server also does it). An exact rule
`from = "/grafana"`, `to = "/grafana/"` expresses it, provided the loop and cycle checks of section 8
treat `/x` and `/x/` as different paths under an exact rule; the design should say so. Optional: a
prefix location whose path ends in `/` answers its bare form with that redirect, as nginx does, and
no rule is needed.

### 28.4 A suffix condition on response-header rules (2 applications, both outside the supported shape)

Discourse's inner nginx keys font caching, image CORS and `Content-Disposition: attachment` for
`.svg` on file extensions; Nextcloud's own PHP sample keys asset and font `Cache-Control` on them, and
`immutable` on a `?v=` query parameter (1 application). Neither is what agensio would replace:
Discourse's supported install keeps its inner nginx inside the container, and Nextcloud AIO handles
this inside its own. On static and PHP sites suffix locations with `add_headers` cover the cache
lifetimes today. If built: `match = "suffix"` on a rule, as locations have (`LocationConfig`'s
`hashed_headers` is the precedent for a file-name condition); the `?v=` condition can be dropped,
the assets then revalidate.

### 28.5 Paths exempt from `http = "redirect"` (1 application, 1 marginal)

GitLab Omnibus answers eight monitoring paths (`/-/health`, `/-/readiness`, `/-/liveness`,
`/health_check` and four below it) over plain HTTP so load balancers can probe them; Metabase's own
redirect exempts `/api/health`, `/livez` and `/readyz`, which matters only when probes cross agensio.
Smallest change: `http = { except = [exact paths] }`. Today: probe over HTTPS, probe the
application's own port, or add a plain site on an internal address (one name on two addresses is
allowed).

### 28.6 No `nosniff` on a 204 (1 application)

Ghost-CLI keeps `X-Content-Type-Options` off 204 answers because iOS Safari offers an empty 204
carrying it as a download (Ghost-CLI #1858, `/ghost/auth-frame/`). The baseline is unaffected (its
`nosniff` is on agensio's own answers); a rule the agent offers for application answers would bring
the bug back. Smallest change: the writer leaves a rule's `X-Content-Type-Options` off 204 answers.

### 28.7 Appending a second CSP (2 applications invite it, none needs it)

BookStack's security page and a comment in Gitea's code invite the proxy to add a second, narrowing
CSP beside the application's. No official configuration does it, and both applications have
settings for their own policy. The evidence does not move it into the first step (headers.md 3.8).

### No change: what the evidence confirms

- **Matrix `.well-known` JSON** (Synapse, Rocket.Chat federation; 2 applications): expressible today
  with a `.json` file and an exact location with `try_files` (run on alpha.72), plus a CORS rule on
  `/.well-known/matrix`. It needs a cookbook recipe, not a fixed-body feature. On a managed site the
  location goes into the root additions file.
- **No frame field and no CSP in the baseline**: 21 of 25 decide framing themselves and several need
  it absent on some routes; a `default` frame field breaks Vaultwarden's MFA pages.
- **`default` for a CSP, and the warning on `set`**: 20 of 25 send their own, 10 with nonces or hashes.
- **Referrer-Policy as `default`**: safe on all 25; a `set` of `no-referrer` breaks Paperless's login.
- **Preload not offered** (used by 6, needed by none); **HSTS never over plain HTTP** (2 ask, browsers
  ignore it).
- **Fixed values only**: the 3 variable values found are debug fields of a proxy cache or 0-RTT that
  agensio does not have.
- **CORS as a fixed value, echo deferred**: 4 configurations set a fixed `*`; the 4 applications that
  echo an origin do it themselves; none needs the proxy to echo.
- **No regex, captures, or conditions on client address, User-Agent or method**: one case each
  (Vaultwarden, Nextcloud's `DavClnt`, Mattermost's `HEAD`, BookStack's slash), and each application
  works without it or with `[[site.access]]`.
- **No `/` to sub-path redirect is needed at the proxy** (0 of 25): the applications that want one do
  it themselves.

### For the agent's texts (no design change)

- Rules match the path the client asked for: Element's `/` needs its own rule beside `/index.html`.
- nginx and Caddy prefixes are character prefixes; agensio's are whole segments (Element's
  `/config`, Vaultwarden's Caddy `/admin*`). Caddy's `header /` is the exact path `/`.
- Never a frame field on Vaultwarden, Grafana, Home Assistant, Uptime Kuma, Metabase or Plausible
  without asking how they are embedded; never a `set` of `Referrer-Policy: no-referrer` on Paperless
  without the `/accounts/` exceptions.
- On Keycloak, Mastodon and GitLab, write `hsts` with the application's own lifetime and
  `subdomains`, or leave it unset (28.2).
- A proxied application that reads `X-Real-IP` needs `proxy.headers` setting it (26.3).
