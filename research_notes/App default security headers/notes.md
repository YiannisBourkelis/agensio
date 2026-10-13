# Application default security headers, and what a server "set if absent" baseline would break (as of 2026-10-13)

Method. Each application's release was downloaded as a source tarball from GitHub (codeload) and searched and read as text; every source link below is pinned to the tag that was read, with line anchors. Debian 13 and Ubuntu 24.04 PHP packages were inspected inside containers, and an FPM pool was run to see when `X-Powered-By` appears. securityheaders.com grades were measured on 2026-10-12 by scanning `httpbin.org/response-headers` with chosen header sets. The MDN HTTP Observatory scoring was read from its source (`mdn/mdn-http-observatory` main at `093035e`, v1.7.1, 2026-09-03). Specs (Fetch, HTML, MIME Sniffing) were downloaded on 2026-10-12. Anything not confirmed from a primary source in this session is marked **unverified**.

Versions read (latest release on 2026-10-12, plus the versions the question named where they differ):

| Application | Read | Note |
|---|---|---|
| WordPress | 7.1.3, 6.9.10 (and `send_frame_options_header` in 6.5.5 to 6.9.0) | 7.x is current; 6.x named in the question |
| Drupal | 11.4.9, 10.6.0 | 12.0 is in beta |
| Laravel | framework v13.35.0 and v12.0.0, skeleton v13.11.0 and v12.0.0 | 11 has the same middleware layout as 12 (not re-read) |
| Grav | 2.2.6, 1.7.49.5, admin plugin 1.10.49.1, admin2 2.1.29, api 1.0.46 | Grav 1.8 shipped as 2.x |
| Statamic | v6.35.1 | |
| TYPO3 | v13.4.36, v14.3.8 | |
| Kanboard | v1.2.54 | |
| Rails | v8.1.4, v7.2.4 | |
| Redmine | 7.0.2 (Rails 8.1.4), 6.1.5 (Rails 7.2.4) | |
| Django | 6.0.9, 5.2.12 | |
| Wagtail | v8.0, v7.4.3, v6.4.2 (template only) | |
| Express | v5.3.0, finalhandler 2.1.0, serve-static 2.2.0 | |
| Uptime Kuma | 2.5.6 | |
| Puma / Gunicorn | v8.0.2 / 26.2.2 | |

## 1. What each application sends by default

### Takeaway
Only the framework-style stacks (Rails, Django, Drupal, Kanboard) put nosniff and a frame policy on every dynamic answer. WordPress protects only its admin, login, AJAX and REST endpoints. TYPO3 protects only its backend. Laravel, Statamic, Grav's front end and plain Express send none of the three fields. Static files never get these fields from any application. The exception is Apache: Drupal's and TYPO3's shipped `.htaccess` add nosniff to every file Apache serves. Behind nginx or agensio that nosniff is lost.

| App (default install) | X-Content-Type-Options | Referrer-Policy | X-Frame-Options / CSP frame-ancestors | Scope |
|---|---|---|---|---|
| WordPress 6.9+/7.1 | `nosniff` on REST and admin-ajax | `strict-origin-when-cross-origin` on wp-admin and wp-login | `SAMEORIGIN` plus `frame-ancestors 'self'` on wp-admin, wp-login, admin-ajax, admin-post and the Customizer preview | front-end pages, feeds, `/embed/` and static files: none |
| Drupal 10/11 | `nosniff` | none | `SAMEORIGIN`, only if not already set | every Drupal response; Apache `.htaccess` adds nosniff to static files |
| Laravel 11/12/13 | none | none | none (`FrameGuard` exists, not registered) | — |
| Grav 1.7 | none | none | admin plugin: `DENY` | admin only |
| Grav 2.2 | none (API media stream only) | none | none (admin2) | — |
| Statamic 6 | none | none | none (multisite Live Preview: `frame-ancestors <site origins>`) | plus `X-Powered-By: Statamic` everywhere |
| TYPO3 13/14 | `nosniff` (backend) | `strict-origin-when-cross-origin` (backend) | `SAMEORIGIN` (backend); backend CSP enforced, without frame-ancestors | frontend: none; Apache root `.htaccess` adds nosniff |
| Kanboard 1.2.54 | `nosniff` | none | `DENY`, plus CSP `default-src 'self'` | every app response |
| Rails 7.1+ defaults (7.2, 8.x apps) | `nosniff` | `strict-origin-when-cross-origin` | `SAMEORIGIN` | every ActionDispatch response, not `public/` files |
| Redmine 6/7 | `nosniff` | `strict-origin-when-cross-origin` | `SAMEORIGIN` | as Rails, with the older railtie set (below) |
| Django 5.2/6.0 `startproject` | `nosniff` | `same-origin` | `DENY` | every Django response, not static/media files served by the web server |
| Wagtail 6/7/8 | as Django | as Django (`same-origin`) | `DENY`; preview views forced to `SAMEORIGIN` | as Django |
| Express 5 | only on error pages, JSONP, redirects | none | none | plus `X-Powered-By: Express` |
| Uptime Kuma 2.5 | none | none | `SAMEORIGIN` unless the env var is set | every Express response |

### Cited findings

**WordPress (7.1.3; 6.x differences noted)**
- `send_frame_options_header()` sends `X-Frame-Options: SAMEORIGIN` and, since 6.9, `Content-Security-Policy: frame-ancestors 'self';` — [functions.php L7282-L7287 (7.1.3)](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/functions.php#L7282-L7287), [6.9.10 L7154-L7159](https://github.com/WordPress/wordpress-develop/blob/6.9.10/src/wp-includes/functions.php#L7154-L7159). In 6.5.5 to 6.8.3 it sent XFO alone (checked per tag). The CSP line came with r60657, 2025-08-23, "Security: Set the `frame-ancestors` directive in `send_frame_options_header()`", fixes #29429 — [commit 1ffab32](https://github.com/WordPress/wordpress-develop/commit/1ffab3205eee727d1f8703698e45c3868ac8220b)
- It is hooked on `login_init` and `admin_init` only — [default-filters.php L398-L399](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/default-filters.php#L398-L399), [admin-filters.php L46-L47](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-admin/includes/admin-filters.php#L46-L47). `admin_init` also fires in [admin-ajax.php L45](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-admin/admin-ajax.php#L45) and [admin-post.php L27](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-admin/admin-post.php#L27)
- `wp_admin_headers()` sends `Referrer-Policy: strict-origin-when-cross-origin`, filterable through `admin_referrer_policy` (default changed to this value in 4.9.5). It runs on the same two hooks — [functions.php L7295-L7311](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/functions.php#L7295-L7311). wp-login.php also prints `<meta name='referrer' content='strict-origin-when-cross-origin' />` — [wp-login.php L50](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-login.php#L50), [general-template.php L3806-L3810](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/general-template.php#L3806-L3810)
- `nocache_headers()`: `Expires: Wed, 11 Jan 1984 05:00:00 GMT` and `Cache-Control: no-cache, must-revalidate, max-age=0, no-store, private` — [functions.php L1508-L1514](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/functions.php#L1508-L1514). Used by admin.php, admin-ajax, admin-post and wp-login
- admin-ajax.php adds `X-Robots-Tag: noindex`, `send_origin_headers()` (echoes an allowed Origin with credentials) and `send_nosniff_header()` = `X-Content-Type-Options: nosniff` — [admin-ajax.php L25-L42](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-admin/admin-ajax.php#L25-L42), [functions.php L7168-L7170](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/functions.php#L7168-L7170)
- REST API, every response: `X-Robots-Tag: noindex`, `Link: <…>; rel="https://api.w.org/"`, and `X-Content-Type-Options: nosniff` ("Mitigate possible JSONP Flash attacks"). JSONP (`?_jsonp=`) answers use `application/javascript` — [class-wp-rest-server.php L323-L337](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/rest-api/class-wp-rest-server.php#L323-L337). CORS: any request with an Origin gets `Access-Control-Allow-Origin: <origin>`, `Access-Control-Allow-Credentials: true` and `Vary: Origin` — [rest-api.php L252](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/rest-api.php#L252), [L805-L818](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/rest-api.php#L805-L818). No-cache fields only for logged-in users (`rest_send_nocache_headers`, default `is_user_logged_in()`) — [L485-L496](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/rest-api/class-wp-rest-server.php#L485-L496)
- Customizer preview (front end loaded in the Customizer frame): `wp_headers` filter sets `X-Frame-Options: SAMEORIGIN` and `Content-Security-Policy: frame-ancestors 'self'` — [class-wp-customize-manager.php L1923, L1971-L1975](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/class-wp-customize-manager.php#L1971-L1975). It became SAMEORIGIN plus frame-ancestors in 2019 because "When `home` and `siteurl` are different, the customizer preview iframe will be blank in Chrome and Safari, due to their `X-Frame-Options` implementation quirks" (#40020) — [commit f5f5da1](https://github.com/WordPress/wordpress-develop/commit/f5f5da1fff91b298deba14ef27b33d5afa09d3dd)
- Post embeds: `/embed/` pages send `X-WP-embed: true` and no frame field. The consumer embeds them as `<iframe sandbox="allow-scripts" security="restricted" …>` on another site — [theme-compat/header-embed.php L14](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/theme-compat/header-embed.php#L14), [embed.php L510](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/embed.php#L510)
- Redirects send `X-Redirect-By: WordPress` (filterable) — [pluggable.php L1527-L1539](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/pluggable.php#L1527-L1539). Core sends no `X-Powered-By`; that comes from PHP (section 2)
- Front-end pages get none of the three fields from core. Admin control: `admin_referrer_policy` filter; `remove_action( 'admin_init' | 'login_init', 'send_frame_options_header' )`; the `wp_headers` filter for front-end pages. No settings screen

**Drupal (11.4.9, 10.6.0)**
- `FinishResponseSubscriber::onRespond()`, main request only, any status: `Content-language`, `X-Content-Type-Options: nosniff` (always set), and `X-Frame-Options: SAMEORIGIN` only `if (!$response->headers->has('X-Frame-Options'))` — [11.4.9 L105-L123](https://github.com/drupal/drupal/blob/11.4.9/core/lib/Drupal/Core/EventSubscriber/FinishResponseSubscriber.php#L105-L123), [10.6.0 L143-L146](https://github.com/drupal/drupal/blob/10.6.0/core/lib/Drupal/Core/EventSubscriber/FinishResponseSubscriber.php#L143-L146)
- `X-Generator: Drupal 11 (https://www.drupal.org)` (major version only) — [ResponseGeneratorSubscriber.php L20-L30](https://github.com/drupal/drupal/blob/11.4.9/core/lib/Drupal/Core/EventSubscriber/ResponseGeneratorSubscriber.php#L20-L30)
- The shipped `.htaccess` does `Header onsuccess unset X-Content-Type-Options` then `Header always set X-Content-Type-Options nosniff` ("Disable content sniffing for all responses"), so under Apache static files carry nosniff too — [.htaccess L193-L205](https://github.com/drupal/drupal/blob/11.4.9/.htaccess#L193-L205)
- No Referrer-Policy, CSP or HSTS in core (searched). `X-UA-Compatible` and FLoC's `Permissions-Policy: interest-cohort=()` are no longer present in 10.6/11.4 (searched)
- Admin control: code only (an event subscriber or a controller that sets or removes XFO; core keeps one already set). The contrib module Seckit makes them configurable (not read here)
- Media oEmbed "iframe domain": core's own SAMEORIGIN blocks the oEmbed iframe when it is served from the separate domain Drupal recommends. Issue "Should 'iFrame domain' also set 'X-Frame-Options' header", opened 2019-08-18, postponed, MR !7691 not merged — [drupal.org/node/3075685](https://www.drupal.org/node/3075685)

**Laravel (11/12/13)**
- Default global middleware: ValidatePathEncoding (13), InvokeDeferredCallbacks, TrustHosts (optional), TrustProxies, HandleCors, PreventRequestsDuringMaintenance, ValidatePostSize, TrimStrings, ConvertEmptyStringsToNull. The `web` group: EncryptCookies, AddQueuedCookiesToResponse, StartSession, ShareErrorsFromSession, PreventRequestForgery (13; ValidateCsrfToken in 12), SubstituteBindings. None of them sets a security field — [Middleware.php L451-L500 (v13.35.0)](https://github.com/laravel/framework/blob/v13.35.0/src/Illuminate/Foundation/Configuration/Middleware.php#L451-L500), [v12.0.0](https://github.com/laravel/framework/blob/v12.0.0/src/Illuminate/Foundation/Configuration/Middleware.php#L451-L492). The skeleton's `bootstrap/app.php` adds nothing — [laravel/laravel v13.11.0](https://github.com/laravel/laravel/blob/v13.11.0/bootstrap/app.php)
- `Illuminate\Http\Middleware\FrameGuard` (`X-Frame-Options: SAMEORIGIN`, not replacing an existing one) exists but is registered nowhere — [FrameGuard.php L20](https://github.com/laravel/framework/blob/v13.35.0/src/Illuminate/Http/Middleware/FrameGuard.php#L20)
- CORS (`HandleCors`, framework default `config/cors.php`): paths `api/*` and `sanctum/csrf-cookie`, `allowed_origins => ['*']`, `supports_credentials => false` — [cors.php L18-L32](https://github.com/laravel/framework/blob/v13.35.0/config/cors.php#L18-L32). Sanctum adds no response fields
- Signed local-disk file serving (`ServeFile`) sets `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox` and no-store — [ServeFile.php L34-L46](https://github.com/laravel/framework/blob/v13.35.0/src/Illuminate/Filesystem/ServeFile.php#L34-L46)
- The skeleton's `public/.htaccess` sets no response fields. Admin control: application code (own middleware)

**Grav**
- Core 1.7.49.5 and 2.2.6: no security fields in PHP, `.htaccess` or `webserver-configs/` (searched; 2.x adds only an immutable Cache-Control for `_app/immutable/`)
- Admin plugin (Grav 1.7 admin): every admin response gets `X-Frame-Options: DENY` ("Never allow admin pages to be rendered in <frame>, <iframe>, <embed> or <object>"). Hard-coded, no setting — [Router.php L76-L77 (1.10.49.1)](https://github.com/getgrav/grav-plugin-admin/blob/1.10.49.1/classes/plugin/Router.php#L76-L77)
- Grav 2 admin2 2.1.29: none found. The API plugin's media-stream endpoint sets `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox` and `X-Content-Type-Options: nosniff` — [MediaController.php L1174-L1176](https://github.com/getgrav/grav-plugin-api/blob/1.0.46/classes/Api/Controllers/MediaController.php#L1174-L1176)

**Statamic (v6.35.1)**
- `X-Powered-By: Statamic` on every response, via middleware pushed onto the global kernel. Config `statamic.system.send_powered_by_header` (default `true`) — [PoweredByHeader.php L20-L21](https://github.com/statamic/cms/blob/v6.35.1/src/Http/Middleware/PoweredByHeader.php#L20-L21), [AppServiceProvider.php L59-L60](https://github.com/statamic/cms/blob/v6.35.1/src/Providers/AppServiceProvider.php#L59-L60), [config/system.php L81](https://github.com/statamic/cms/blob/v6.35.1/config/system.php#L81)
- Live Preview: with multisite enabled, the previewed response gets `Content-Security-Policy: frame-ancestors <every site's scheme+host>`. Single site: no frame field (same-origin iframe from the CP) — [LivePreview.php L26-L37](https://github.com/statamic/cms/blob/v6.35.1/src/Tokens/Handlers/LivePreview.php#L26-L37)
- The CP SVG asset controller sends `Content-Security-Policy: script-src 'none'` — [SvgController.php L26](https://github.com/statamic/cms/blob/v6.35.1/src/Http/Controllers/CP/Assets/SvgController.php#L26). No XFO, nosniff or Referrer-Policy anywhere (searched). Otherwise as Laravel

**TYPO3 (v13.4.36, v14.3.8)**
- `$GLOBALS['TYPO3_CONF_VARS']['BE']['HTTP']['Response']['Headers']` defaults: `X-Frame-Options: SAMEORIGIN`, `Strict-Transport-Security: max-age=31536000`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin` — [DefaultConfiguration.php L1506-L1515 (13)](https://github.com/TYPO3/typo3/blob/v13.4.36/typo3/sysext/core/Configuration/DefaultConfiguration.php#L1506-L1515), [L1698-L1701 (14)](https://github.com/TYPO3/typo3/blob/v14.3.8/typo3/sysext/core/Configuration/DefaultConfiguration.php#L1698-L1701)
- Added to every backend response by `AdditionalResponseHeaders` (`withAddedHeader`). HSTS is dropped unless `[BE][lockSSL]` is on — [AdditionalResponseHeaders.php L35-L48](https://github.com/TYPO3/typo3/blob/v13.4.36/typo3/sysext/backend/Classes/Middleware/AdditionalResponseHeaders.php#L35-L48). Changeable in `settings.php`/`additional.php`
- Backend CSP is enforced (nonce-based; `default-src 'self'`, `script-src` nonce, `style-src 'unsafe-inline'`, `frame-src 'self'` plus YouTube/Vimeo, `base-uri 'none'`, `object-src 'none'`; no frame-ancestors). It is skipped when the response already carries a CSP — [ContentSecurityPolicyHeaders.php](https://github.com/TYPO3/typo3/blob/v13.4.36/typo3/sysext/backend/Classes/Middleware/ContentSecurityPolicyHeaders.php), [ContentSecurityPolicies.php](https://github.com/TYPO3/typo3/blob/v13.4.36/typo3/sysext/backend/Configuration/ContentSecurityPolicies.php)
- Frontend: nothing by default. Feature `security.frontend.enforceContentSecurityPolicy => false`, and `security.backend.enforceReferrer => true`: the backend requires a Referer header on its requests — [DefaultConfiguration.php L89-L91](https://github.com/TYPO3/typo3/blob/v13.4.36/typo3/sysext/core/Configuration/DefaultConfiguration.php#L89-L91). Frontend fields come from TypoScript `config.additionalHeaders` or site CSP configuration
- The root `.htaccess` template sets `X-UA-Compatible "IE=edge"` (not on assets) and `X-Content-Type-Options "nosniff"` on everything Apache serves — [root-htaccess L377-L386](https://github.com/TYPO3/typo3/blob/v13.4.36/typo3/sysext/install/Resources/Private/FolderStructureTemplateFiles/root-htaccess#L377-L386)
- Multidomain backend preview (backend on one host, site on another) is a real setup: TYPO3 Forge #99286 reports a regression there — [forge.typo3.org/issues/99286](https://forge.typo3.org/issues/99286) (**unverified**: page behind a bot wall, read through a search summary)

**Kanboard (v1.2.54)**
- Every controller response (Runner → BootstrapMiddleware): `Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src * data:;`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection: 1; mode=block`, a `P3P` field, `X-Frame-Options: DENY` (`ENABLE_XFRAME`, default true), and `Strict-Transport-Security: max-age=31536000` over HTTPS only (`ENABLE_HSTS`, default true). No Referrer-Policy — [BootstrapMiddleware.php L32-L45](https://github.com/kanboard/kanboard/blob/v1.2.54/app/Middleware/BootstrapMiddleware.php#L32-L45), [Response.php L78-L141](https://github.com/kanboard/kanboard/blob/v1.2.54/app/Core/Http/Response.php#L78-L141), [ClassProvider.php L187-L191](https://github.com/kanboard/kanboard/blob/v1.2.54/app/ServiceProvider/ClassProvider.php#L187-L191)
- Admin control: `ENABLE_XFRAME` / `ENABLE_HSTS` in `config.php` or the environment (any value other than `true` disables) — [constants.php L121-L125](https://github.com/kanboard/kanboard/blob/v1.2.54/app/constants.php#L121-L125), [config.default.php L226-L230](https://github.com/kanboard/kanboard/blob/v1.2.54/config.default.php#L226-L230)

**Ruby on Rails (v8.1.4, v7.2.4)**
- Railtie default (no `load_defaults`): `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection: 1; mode=block`, `X-Content-Type-Options: nosniff`, `X-Download-Options: noopen`, `X-Permitted-Cross-Domain-Policies: none`, `Referrer-Policy: strict-origin-when-cross-origin` — [railtie.rb L40-L47 (8.1.4)](https://github.com/rails/rails/blob/v8.1.4/actionpack/lib/action_dispatch/railtie.rb#L40-L47), [7.2.4 L33-L40](https://github.com/rails/rails/blob/v7.2.4/actionpack/lib/action_dispatch/railtie.rb#L33-L40)
- `load_defaults "7.0"` changes X-XSS-Protection to `0`. `"7.1"` (so every 7.1, 7.2, 8.0 and 8.1 app) also drops X-Download-Options. That leaves XFO SAMEORIGIN, X-XSS-Protection 0, nosniff, X-Permitted-Cross-Domain-Policies none and Referrer-Policy strict-origin-when-cross-origin — [configuration.rb L219-L230, L269-L302](https://github.com/rails/rails/blob/v8.1.4/railties/lib/rails/application/configuration.rb#L269-L302)
- Applied to every `ActionDispatch::Response` (controller answers). Files served by `ActionDispatch::Static` from `public/` get only `config.public_file_server.headers` (template: a year's Cache-Control) — [response.rb L186-L191](https://github.com/rails/rails/blob/v8.1.4/actionpack/lib/action_dispatch/http/response.rb#L186-L191), [default_middleware_stack.rb L31-L34](https://github.com/rails/rails/blob/v8.1.4/railties/lib/rails/application/default_middleware_stack.rb#L31-L34)
- HSTS only with `force_ssl` (default `max-age=63072000; includeSubDomains`) — [ssl.rb L67-L73](https://github.com/rails/rails/blob/v8.1.4/actionpack/lib/action_dispatch/middleware/ssl.rb#L67-L73). The 8.1 production template enables `force_ssl` only when generated with `--skip-kamal`; 7.2 enables it — [production.rb.tt L31-L43](https://github.com/rails/rails/blob/v8.1.4/railties/lib/rails/generators/rails/app/templates/config/environments/production.rb.tt#L31-L43). The CSP initializer is generated commented out — [content_security_policy.rb.tt](https://github.com/rails/rails/blob/v8.1.4/railties/lib/rails/generators/rails/app/templates/config/initializers/content_security_policy.rb.tt)
- `Rack::Runtime` (`X-Runtime`) and `ActionDispatch::RequestId` (`X-Request-Id`) are still in the default stack — [default_middleware_stack.rb L51-L53](https://github.com/rails/rails/blob/v8.1.4/railties/lib/rails/application/default_middleware_stack.rb#L51-L53)
- Admin control: `config.action_dispatch.default_headers` (override, add, `.clear`) — [security guide L1338-L1361](https://github.com/rails/rails/blob/v8.1.4/guides/source/security.md#configuring-the-default-headers). Per action, apps delete the field (`response.headers.delete "X-Frame-Options"`) to allow embedding; one report has this working locally but not in production behind nginx, cause unconfirmed — [Rails forum 72719 (2017)](https://discuss.rubyonrails.org/t/x-frame-options-not-allowing-my-widget-to-embed-iframe-in-other-domains-websites/72719)

**Redmine (7.0.2 on Rails 8.1.4; 6.1.5 on Rails 7.2.4)**
- `config/application.rb` never calls `load_defaults` and sets no default_headers. Redmine therefore sends the railtie set above: XFO SAMEORIGIN, `X-XSS-Protection: 1; mode=block`, nosniff, `X-Download-Options: noopen`, `X-Permitted-Cross-Domain-Policies: none`, Referrer-Policy strict-origin-when-cross-origin. Redmine's code has no other frame or CSP field (searched) — [application.rb](https://github.com/redmine/redmine/blob/7.0.2/config/application.rb), [Gemfile L5](https://github.com/redmine/redmine/blob/7.0.2/Gemfile#L5). Not checked on a running instance (**inference from source**)
- Admin control: `config/additional_environment.rb` with `config.action_dispatch.default_headers`. `force_ssl` is commented out in production.rb

**Django (6.0.9, 5.2.12)**
- Settings defaults: `X_FRAME_OPTIONS = "DENY"`, `SECURE_CONTENT_TYPE_NOSNIFF = True`, `SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"`, `SECURE_REFERRER_POLICY = "same-origin"`, `SECURE_HSTS_SECONDS = 0`. 6.0 adds `SECURE_CSP = {}` (the CSP middleware is not in the template) — [global_settings.py L443, L657-L671 (6.0.9)](https://github.com/django/django/blob/6.0.9/django/conf/global_settings.py#L657-L671), [5.2.12 L447, L661-L669](https://github.com/django/django/blob/5.2.12/django/conf/global_settings.py#L661-L669)
- The `startproject` template includes SecurityMiddleware and XFrameOptionsMiddleware — [settings.py-tpl L42-L50](https://github.com/django/django/blob/6.0.9/django/conf/project_template/project_name/settings.py-tpl#L42-L50)
- SecurityMiddleware uses set-if-absent itself: `response.headers.setdefault("X-Content-Type-Options", "nosniff")`, and likewise for Referrer-Policy and COOP — [security.py L33-L66](https://github.com/django/django/blob/6.0.9/django/middleware/security.py#L33-L66). XFrameOptionsMiddleware skips a response that already has XFO or carries `xframe_options_exempt` — [clickjacking.py L25-L48](https://github.com/django/django/blob/6.0.9/django/middleware/clickjacking.py#L25-L48)
- Scope: every response Django produces. Static and media files served by the web server get nothing. Admin control: settings, the `@xframe_options_exempt`/`_sameorigin`/`_deny` decorators

**Wagtail (8.0, 7.4.3; 6.4.2 template)**
- Project template: Django's SecurityMiddleware and XFrameOptionsMiddleware (6.4 has them in a different order). No `X_FRAME_OPTIONS` or `SECURE_*` override, so DENY, same-origin, nosniff and COOP apply — [base.py L51-L60](https://github.com/wagtail/wagtail/blob/v8.0/wagtail/project_template/project_name/settings/base.py#L51-L60)
- Preview views (same-origin iframe in the editor) force `X-Frame-Options: SAMEORIGIN`, overriding DENY: `xframe_options_sameorigin_override` — [decorators.py L62-L81](https://github.com/wagtail/wagtail/blob/v8.0/wagtail/utils/decorators.py#L62-L81), [preview.py L122, L184](https://github.com/wagtail/wagtail/blob/v8.0/wagtail/admin/views/generic/preview.py#L184). Docs: the preview iframe "requires the page in the iframe to have the X-Frame-Options header set to SAMEORIGIN (or unset)", and links clicked inside it hit pages with DENY — [releases/4.0.md L277-L287](https://github.com/wagtail/wagtail/blob/v8.0/docs/releases/4.0.md)
- 7.1+: "The preview panel can now load a cross-domain headless frontend" (wagtail-headless-preview), so that frontend is framed cross-origin by the admin — [releases/7.1.md L46-L48](https://github.com/wagtail/wagtail/blob/v8.0/docs/releases/7.1.md), [wagtail-headless-preview README](https://github.com/torchbox/wagtail-headless-preview#redirect-vs-iframe)
- Image and document serve views add `Content-Security-Policy: default-src 'none'` and nosniff — [images/views/serve.py L72-L75](https://github.com/wagtail/wagtail/blob/v8.0/wagtail/images/views/serve.py#L72-L75), [documents/views/serve.py L110-L113](https://github.com/wagtail/wagtail/blob/v8.0/wagtail/documents/views/serve.py#L110-L113)

**Express / Node (Express v5.3.0)**
- `X-Powered-By: Express` on every response, setting enabled at init — [application.js L94, L159-L162](https://github.com/expressjs/express/blob/v5.3.0/lib/application.js#L159-L162). `app.disable('x-powered-by')` turns it off. Helmet is not a dependency
- Only these answers get nosniff: `res.jsonp()` (with `text/javascript` for a callback), finalhandler's 404/error pages (`Content-Security-Policy: default-src 'none'` too), and serve-static's trailing-slash redirect page — [response.js L273-L287](https://github.com/expressjs/express/blob/v5.3.0/lib/response.js#L273-L287), [finalhandler 2.1.0 L267-L268](https://github.com/pillarjs/finalhandler/blob/v2.1.0/index.js#L267-L268), [serve-static 2.2.0 L203-L204](https://github.com/expressjs/serve-static/blob/v2.2.0/index.js#L203-L204)
- Node's `http` adds no Server field and no Content-Type of its own (**unverified in source here**; well-known behaviour)

**Uptime Kuma (2.5.6)**
- Global Express middleware: `X-Frame-Options: SAMEORIGIN` on every response unless disabled, and `res.removeHeader("X-Powered-By")` — [server.js L215-L222](https://github.com/louislam/uptime-kuma/blob/2.5.6/server/server.js#L215-L222)
- Switch: `UPTIME_KUMA_DISABLE_FRAME_SAMEORIGIN` or `--disable-frame-sameorigin`, read as `!!process.env…`, so any non-empty value (even `false`) disables it — [server.js L164-L165](https://github.com/louislam/uptime-kuma/blob/2.5.6/server/server.js#L164-L165). Wiki: "By default, Uptime Kuma is not allowed in iframe if the domain name is not the same as the parent", default `false` — [Environment-Variables](https://github.com/louislam/uptime-kuma/wiki/Environment-Variables)
- No nosniff, Referrer-Policy or CSP. Badges are `image/svg+xml`, used in `<img>`, so frame fields do not matter for them — [api-router.js L147, L213](https://github.com/louislam/uptime-kuma/blob/2.5.6/server/routers/api-router.js#L213)
- Embedding the status page in other sites is a recurring request: [#1146](https://github.com/louislam/uptime-kuma/issues/1146) (MagicMirror, error pages), [#4034](https://github.com/louislam/uptime-kuma/issues/4034), [#4047](https://github.com/louislam/uptime-kuma/issues/4047), [#4357](https://github.com/louislam/uptime-kuma/issues/4357) (ioBroker), [#5621](https://github.com/louislam/uptime-kuma/issues/5621) (intranet portal), [#5739](https://github.com/louislam/uptime-kuma/issues/5739) (own website)

## 2. Server and X-Powered-By fields

| Source | Field | Default |
|---|---|---|
| PHP upstream | `X-Powered-By: PHP/8.4.26` | `expose_php` built-in default `"1"`, PHP_INI_SYSTEM — [main.c L742](https://github.com/php/php-src/blob/PHP-8.4/main/main.c#L742), [SAPI.h L309](https://github.com/php/php-src/blob/PHP-8.4/main/SAPI.h#L309); `php.ini-production` and `-development` both `expose_php = On` ("It is no security threat in any way…") — [php.ini-production L395-L400](https://github.com/php/php-src/blob/PHP-8.4/php.ini-production#L395-L400) |
| Debian packaging | none for FPM/Apache | `debian/rules` rewrites `expose_php = On` to `Off` in the shipped `php.ini-production` (used for fpm, apache2, cgi); the CLI copy keeps On — [debian/rules L531-L534](https://salsa.debian.org/php-team/php/-/blob/debian/main/8.4/debian/rules#L531-L534). Checked: Debian 13 `php8.4-fpm 8.4.26-1~deb13u1` `/etc/php/8.4/fpm/php.ini:400 expose_php = Off` |
| Ubuntu 24.04 | none for FPM | `php8.3-common 8.3.6-0ubuntu0.24.04.11`: `php.ini-production:410 expose_php = Off`, `.cli` On (package extracted) |
| Docker official `php:*-fpm` | `X-Powered-By: PHP/x.y` | ships `php.ini-production`/`-development` but installs neither ("strongly recommended to use the production config"), so the built-in On applies — [docker-library docs](https://github.com/docker-library/docs/blob/master/php/content.md#configuration) |
| FPM pool | — | Measured in the Debian devbox (php-fpm 8.4.26): `php_admin_flag[expose_php] = on` in a pool brings the field back with php.ini Off, and `= off` removes it with php.ini On. agensio's pool flag (`src/services/pools.cpp`) does take effect |
| Statamic | `X-Powered-By: Statamic` | on (config) |
| Drupal | `X-Generator: Drupal N (https://www.drupal.org)` | on, code only |
| WordPress | `X-Redirect-By: WordPress` on redirects | on (filter) |
| Express | `X-Powered-By: Express` | on |
| Uptime Kuma | none (removes Express's) | — |
| Puma 8 | none; `puma 8.x.y` only in `SERVER_SOFTWARE` env — [const.rb L106](https://github.com/puma/puma/blob/v8.0.2/lib/puma/const.rb#L106), [binder.rb L45](https://github.com/puma/puma/blob/v8.0.2/lib/puma/binder.rb#L45) | — |
| Rails | `X-Runtime`, `X-Request-Id` (no product name) | on |
| Gunicorn 26 | `Server: gunicorn` (no version; `SERVER_SOFTWARE` env `gunicorn/26.x`) — [wsgi.py L302, L441](https://github.com/benoitc/gunicorn/blob/26.2.2/gunicorn/http/wsgi.py#L441), [__init__.py L7-L8](https://github.com/benoitc/gunicorn/blob/26.2.2/gunicorn/__init__.py#L7-L8) | on |
| Django | none (runserver's `WSGIServer/0.2 CPython/…` is dev only, **unverified here**) | — |

## 3. What browsers do without each field

- **No X-Content-Type-Options.** Fetch blocks a script-like destination only for `audio/*`, `image/*`, `video/*` and `text/csv` — [Fetch §2.10](https://fetch.spec.whatwg.org/#should-response-to-request-be-blocked-due-to-mime-type?). So a classic `<script>` served as `text/html`, `text/plain`, `application/json`, `application/octet-stream` or with no type still runs. With nosniff, a script-like destination must have a JavaScript MIME type and `style` must be `text/css`. "Only request destinations that are script-like or 'style' are considered…; considering 'image' was not compatible with deployed content" — [Fetch §3.6.1](https://fetch.spec.whatwg.org/#should-response-to-request-be-blocked-due-to-nosniff?)
- Stylesheets are blocked when not `text/css` anyway. The single exception, with or without nosniff, is a same-origin sheet in a quirks-mode document — [HTML link type stylesheet](https://html.spec.whatwg.org/multipage/links.html#link-type-stylesheet). Module scripts, classic workers and `importScripts()` always require a JavaScript MIME type (`application/wasm` for wasm modules) — [HTML webappapis](https://html.spec.whatwg.org/multipage/webappapis.html#fetch-a-single-module-script). nosniff changes nothing for those
- Documents: a missing or `unknown/unknown`/`*/*` type is sniffed with "sniff-scriptable" equal to the inverse of no-sniff. With nosniff, a type-less HTML page is not recognised as HTML — [MIME Sniffing §7](https://mimesniff.spec.whatwg.org/#determining-the-computed-mime-type-of-a-resource) (browser rendering of that case not tested)
- MDN compat data: nosniff in Chrome since 1 for scripts, full (stylesheets) since 64; Firefox 50; Safari 11 — [BCD X-Content-Type-Options.json](https://github.com/mdn/browser-compat-data/blob/main/http/headers/X-Content-Type-Options.json)
- **No Referrer-Policy.** The default is `strict-origin-when-cross-origin` in Chrome 85, Edge 85, Firefox 87 and Safari 15 (BCD `default_strict-origin-when-cross-origin`) — [BCD Referrer-Policy.json](https://github.com/mdn/browser-compat-data/blob/main/http/headers/Referrer-Policy.json). Chrome: from 85 (stable August 2020), "user-visible breakage is expected to be limited", "Server-side logging or analytics that rely on the full referrer URL being available are likely to be impacted", "only… websites that have no policy set" — [Chrome blog](https://developer.chrome.com/blog/referrer-policy-new-chrome-default). A `<meta name="referrer">` sets the document's policy after the header ("the most-recently-inserted… has an effect"), so a page's meta overrides a server header — [HTML meta referrer](https://html.spec.whatwg.org/multipage/semantics.html#meta-referrer). A module script's own Referrer-Policy response field governs its imports — [HTML fetch a single module script](https://html.spec.whatwg.org/multipage/webappapis.html#fetch-a-single-module-script)
- **No X-Frame-Options and no frame-ancestors.** Any site may frame the page. Per HTML §7.7, "if both a CSP frame-ancestors directive and an X-Frame-Options header are used in the same response, then X-Frame-Options is ignored" (enforced policies only; Report-Only does not count). `SAMEORIGIN` requires every ancestor, not just the parent, to be same-origin. `ALLOW-FROM`, `ALLOWALL` and unknown values count as no field. Two values that contradict (`SAMEORIGIN, ALLOWALL`, `SAMEORIGIN, DENY`) block. A repeated `SAMEORIGIN, SAMEORIGIN` allows same-origin — [HTML §7.7](https://html.spec.whatwg.org/multipage/speculative-loading.html#the-x-frame-options-header). BCD: "Starting in Chrome 61 [Firefox 59], this applies to all of a frame's ancestors" — [BCD X-Frame-Options.json](https://github.com/mdn/browser-compat-data/blob/main/http/headers/X-Frame-Options.json)

## 4. The three candidate fields as "set if absent": what breaks

### 4.1 `X-Content-Type-Options: nosniff`

Takeaway: for every application that already sends it (Drupal, Kanboard, Rails, Redmine, Django, Wagtail, TYPO3 backend, WordPress REST and admin-ajax), adding it when absent changes nothing on dynamic answers. The new exposure is static files and the dynamic answers of WordPress front end, Laravel, Statamic, Grav, TYPO3 frontend and Node apps. Drupal and TYPO3 expect it on static files (their `.htaccess`). What breaks is always a script whose response does not carry a JavaScript type. Stylesheets are already strict outside quirks mode.

Concrete failure modes, with reports:
- PHP that prints JavaScript without `header('Content-Type: …')` gets PHP's default `text/html` and is refused: "Refused to execute script from 'tracker.php?…' because its MIME type ('text/html') is not executable, and strict MIME type checking is enabled" — [pulsecms-tracking #23 (2018)](https://github.com/thecyman/pulsecms-tracking/issues/23). A CMS translation endpoint did the same after Apache got `Header set X-Content-Type-Options: "nosniff"` — [chameleon-system #110 (2018)](https://github.com/chameleon-system/chameleon-system/issues/110)
- JSONP served as `application/json`: an API upgrade added nosniff and "broke JSONP requests… MIME type ('application/json') is not executable" — [NREL developer API #16 (2015)](https://github.com/NatLabRockies/developer.nlr.gov/issues/16). WordPress's REST JSONP and Express's `res.jsonp` send a JavaScript type, so they are safe
- Scripts with an empty or wrong type: a Joomla 4.4.1 site went down after Admin Tools' "Reduce MIME type security risks" (nosniff via `.htaccess`) — "its MIME type ('') is not executable". The vendor: browsers won't run a script "if your server does not send the MIME type at all, or sends the wrong MIME type" — [Akeeba ticket 39956 (2023-12)](https://www.akeeba.com/support/admin-tools/39956-suddenly-getting-js-errors-bringing-site-down.html). JS in WordPress uploads served as `text/plain` with nosniff was refused although the status was 200 — [exelearning #2052 (2026-06)](https://github.com/exelearning/exelearning/issues/2052)
- Unknown extensions: agensio serves unknown extensions as `application/octet-stream` (`src/mime.cpp` L119). A classic script with an unmapped extension (`.cjs`, no extension, a template suffix) is refused under nosniff and runs without it. `.mjs` is mapped to `text/javascript` here, and module scripts need a JS type regardless. `.ts` maps to `video/mp2t`, which Fetch always blocks for scripts
- A proxied app that sends a body with no Content-Type would not be sniffed as HTML (spec reading above; not tested)

### 4.2 `Referrer-Policy: strict-origin-when-cross-origin`

Takeaway: it equals the default of every current engine (Chrome/Edge 85+, Firefox 87+, Safari 15+). A page's `<meta name="referrer">` or a per-element `referrerpolicy` still wins. Apps that set their own are not touched: Django `same-origin`, Rails and Redmine, TYPO3 backend and WordPress admin all strict-origin-when-cross-origin. The field changes behaviour only in older browsers and webviews. It raises scanner grades. No breakage traceable to sending this value was found.

- What the value itself removes (already true with the browser default): the path and query on cross-origin requests, and everything on HTTPS→HTTP. Reported impact of the 2020 default change: SharePoint Framework back ends that validated the referrer path, fixed by asking for `no-referrer-when-downgrade` per request — [dev.to, 2020-09-22](https://dev.to/estruyf/spfx-issues-with-the-new-referrer-policy-in-chrome-85-3pa8). Also analytics and logging that rely on full referrers (Chrome blog above)
- The stricter values are what break things. YouTube's embedded player requires the Referer: clients must not set a Referrer-Policy "in a way that suppresses the Referer value", and "YouTube recommends using strict-origin-when-cross-origin Referrer-Policy, which is already the default in many browsers" (last updated 2026-09-14) — [YouTube Required Minimum Functionality](https://developers.google.com/youtube/terms/required-minimum-functionality). Error 153 "Video player configuration error" (`embedder.identity.missing.referrer`) traced to Django's default `same-origin` — [Simon Willison TIL, 2025](https://til.simonwillison.net/youtube/fixing-153-embed). TYPO3's backend enforces a Referer (`security.backend.enforceReferrer`), so `no-referrer` would break it. strict-origin-when-cross-origin keeps same-origin referrers whole and sends the origin cross-origin, so neither case breaks

### 4.3 `X-Frame-Options: SAMEORIGIN` (or `Content-Security-Policy: frame-ancestors 'self'`)

Takeaway: this is the one of the three that breaks real deployments. Same-origin editors are fine with SAMEORIGIN: WordPress Customizer, Elementor, Wagtail preview and TYPO3 view module on one host. DENY is what breaks them. The breakage is cross-origin embedding that the application intends. "Set if absent" cannot tell "the app never thought about it" from "the app deliberately left it out to allow embedding", and several apps express "allow embedding" exactly by omitting the field.

Deliberate omission that a server-added SAMEORIGIN would undo:
- WordPress post embeds: `/embed/` pages are framed by other sites and carry no frame field by design (`X-WP-embed: true` marks them). With XFO SAMEORIGIN, "the embed failure causes WordPress to display a blank space without any relevant information about the embedded post". Gary Pendergast's suggested fix was a server rule keyed on `X-WP-embed` — [ethitter.com, 2016-03-21](https://ethitter.com/2016/03/fix-wordpress-post-embeds-x-frame-options/). Since r36648 the consumer shows the iframe only after it loads, so the failure now degrades to the blockquote link ("Embeds: Only display an iframe when it was successfully loaded… Fixes #35894") — [commit 3039740](https://github.com/WordPress/wordpress-develop/commit/3039740a3a44a12d8f47dd8a411942b8f3ed6d22)
- Uptime Kuma with `UPTIME_KUMA_DISABLE_FRAME_SAMEORIGIN` set: the admin's opt-out would be silently re-imposed, giving exactly the "Refused to display … because it set 'X-Frame-Options' to 'sameorigin'" reports above
- Grafana `allow_embedding = true`: Grafana then sends no XFO ("When false, the HTTP header X-Frame-Options: deny is set") — [Grafana configuration docs](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/)
- Kanboard `ENABLE_XFRAME=false`; Django views with `@xframe_options_exempt`; Rails actions that delete the field; Drupal code that removes it
- Apps that already use `frame-ancestors` instead of XFO (Statamic multisite Live Preview, Shopify embedded apps): Shopify requires apps to be "only frameable by the authenticated shop domain and the Shopify admin domain" and says "The frame-ancestors directive replaces the obsolete X-Frame-Options response header" — [shopify.dev App Bridge](https://shopify.dev/docs/apps/tools/app-bridge/getting-started/app-setup). Browsers ignore XFO when an enforced frame-ancestors is present (HTML §7.7), so a server XFO would be inert there, but it should not be added

Gaps that a server SAMEORIGIN would fill, with the cross-origin cases it breaks:
- TYPO3 frontend (the backend sends XFO, the frontend does not): the backend's page preview of a site on another host. Forge #99286 shows multidomain previews are used (unverified, see above)
- Wagtail 7.1+ headless frontends served by the web server: the admin's preview panel frames them cross-origin
- Drupal's media oEmbed iframe on a separate domain. Already broken by Drupal's own SAMEORIGIN (#3075685), so the server adds nothing new
- Laravel, Statamic, Express and Node apps meant to be embedded: widgets and booking or donation forms for partner sites, LTI and Teams tabs and other platform apps, status pages and dashboards in portals (Home Assistant, MagicMirror, intranets), and pages embedded in Notion through its iframe embed (Notion: no primary source found; behaviour follows from XFO semantics)
- Nested frames: SAMEORIGIN checks every ancestor. A same-origin page inside a third-party frame inside the same site's page is refused. The common 3-D Secure flow (merchant page → issuer iframe → redirect back to the merchant inside that same iframe) is fine, because the redirected document's only ancestor is the merchant page (spec reading; no reported case found)
- Not affected: the WordPress block editor canvas is a `blob:` URL the editor builds itself (`URL.createObjectURL(new Blob([html], {type:'text/html'}))`), not a navigation to a server response — [gutenberg iframe/index.jsx L127, L313](https://github.com/WordPress/gutenberg/blob/trunk/packages/block-editor/src/components/iframe/index.jsx#L127). Drupal Layout Builder uses dialogs, not frames (its JS only names `iframe` in a focus selector). Elementor's own help recommends SAMEORIGIN and names DENY as the cause of a blank editor — [Elementor help](https://elementor.com/help/elementor-not-loading/)

Per-application effect of a server-wide set-if-absent baseline:

| App | nosniff | Referrer-Policy | XFO SAMEORIGIN |
|---|---|---|---|
| WordPress | adds to front end and static files | adds to front end (= browser default) | adds to front end; **breaks rich post embeds on other sites** unless `/embed/` (or `X-WP-embed: true`) is exempt |
| Drupal | static files only (matches its `.htaccess`) | adds everywhere | static files only (no change for pages) |
| Laravel, Statamic | adds everywhere | adds everywhere | adds everywhere; breaks intentionally embeddable apps |
| Grav | adds | adds | adds to front end (admin 1.7 already DENY) |
| TYPO3 | frontend and static (matches `.htaccess`) | frontend | frontend; breaks a multidomain backend preview |
| Kanboard | static only | adds (none sent) | no change unless `ENABLE_XFRAME=false` (then re-imposed) |
| Rails, Redmine | `public/` files only | `public/` only | no change except actions that delete it |
| Django, Wagtail | static and media only | no change (keeps `same-origin`) | no change except `@xframe_options_exempt` views; breaks Wagtail headless preview frontends |
| Express apps | adds | adds | adds; breaks embeddable apps |
| Uptime Kuma | adds | adds | no change by default; **re-imposes it when the admin disabled it** |

## 5. Scanners: securityheaders.com and the MDN HTTP Observatory

**securityheaders.com** (operated by Snyk, "originally created by Scott Helme") — [about](https://securityheaders.com/about/). It grades six fields: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy. COEP, COOP and CORP are listed as "Upcoming Headers", not graded. `Server` and `X-Powered-By` appear as blue information. The FAQ: "To get an A+ grade your site needs to issue all the HTTP response headers that we check for". No formula is published — [FAQ](https://securityheaders.com/faq/). Measured 2026-10-12 against `httpbin.org/response-headers` with only the listed fields (every scan also warned "Response is not HTML"):

| Fields sent | Grade |
|---|---|
| none | F |
| HSTS only | D |
| nosniff + Referrer-Policy | D |
| **XFO + nosniff + Referrer-Policy** | **C** |
| the three + HSTS | B |
| nosniff + Referrer-Policy + CSP `frame-ancestors 'self'` (no XFO; XFO not reported missing) | B |
| the three + HSTS + Permissions-Policy | A |
| all six | A+ |

wordpress.org itself (XFO plus a 3600 s HSTS, "too small") scored D the same day.

**MDN HTTP Observatory** (source v1.7.1). Everyone starts at 100. Penalties are applied, and bonuses are added only if the result is 90 or more — [scanner/index.js L55-L75](https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/scanner/index.js#L55-L75), [charts.js L6-L30](https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L6-L30). Grades: A+ ≥100, A 90, A- 85, B+ 80, B 70, B- 65, C+ 60, C 50, C- 45, D+ 40, D 30, D- 25, F below — [tests and scoring](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring). Modifiers — [charts.js](https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/grader/charts.js#L105-L990):
- CSP missing −25 (`default-src 'none'` with no unsafe +10, no unsafe +5, unsafe-inline −20)
- HSTS missing −20 (under six months −10, preloaded +5)
- No redirect to HTTPS −20
- XFO missing −20 (SAMEORIGIN or DENY +5, frame-ancestors +5; frame-ancestors satisfies the test — [x-frame-options.js L57-L60](https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/analyzer/tests/x-frame-options.js#L57-L60))
- X-Content-Type-Options missing −5 (present 0)
- Referrer-Policy missing 0; `no-referrer`, `same-origin`, `strict-origin` or `strict-origin-when-cross-origin` +5; `unsafe-url`, `origin`, `origin-when-cross-origin` or `no-referrer-when-downgrade` −5. A meta http-equiv also counts — [referrer-policy.js L33-L54](https://github.com/mdn/mdn-http-observatory/blob/093035e33568f9e5a6ef85a2afb1b9c92df296e3/src/analyzer/tests/referrer-policy.js#L33-L54)
- CORP same-site or same-origin +10. COOP and COEP were added in 1.7.0 (2026-09-01): +10 each when set, 0 when absent, −5 invalid
- Cookies without Secure −20 to −40; SRI missing on insecure external scripts −50

So for an HTTPS site with a redirect but no CSP:
- without HSTS, the three fields move it from 30 (D) to 55 (C)
- with a long HSTS, from 50 (C) to 75 (B)
- the A range needs a CSP: with HSTS, the three fields and a CSP without `unsafe-*`, the score reaches 100 and then bonuses: A+

**What the baseline achieves.** C on both scanners without HSTS, B with HSTS. A needs Permissions-Policy (securityheaders.com) or a CSP (Observatory: CSP alone costs 25 points). Neither field can be added generically without knowing the application.

## 6. Points for agensio (inference from the findings above, not sourced claims)

- nosniff and strict-origin-when-cross-origin are safe as set-if-absent defaults, given correct static Content-Types and a check for responses with no Content-Type. The Referrer-Policy value must not be `no-referrer` or `same-origin` (YouTube, TYPO3 backend). Note Django sends `same-origin` itself
- XFO needs exemptions to be safe:
  - skip it when the response has an enforced CSP with `frame-ancestors`
  - skip it on WordPress `/embed/` (the `X-WP-embed: true` marker exists for this)
  - give a per-site or per-path off switch for apps that allow embedding by omitting the field (Uptime Kuma env var, Grafana, Kanboard, Django exempt views, Rails, headless previews, platform apps)
- Using `frame-ancestors 'self'` instead of XFO would not be "set if absent" safe: it would add a second CSP to an app that sends its own, and policies combine restrictively
- Adding nosniff to the static files of Drupal and TYPO3 sites restores what their own `.htaccess` gives them under Apache
- PHP pools: Debian and Ubuntu FPM already ship `expose_php = Off`; Docker's official images and upstream ini files do not. agensio's `php_admin_flag[expose_php] = off` was measured to work

## Unverified or not checked
- TYPO3 Forge #99286 content (bot wall); WordPress Trac #35894 page itself (403), read through its commit and the ethitter post
- Notion embed behaviour and any Notion documentation; Iframely's handling of XFO
- securityheaders.com's exact formula (only measured grades); whether an HTML response grades differently from httpbin's JSON
- Whether the hosted MDN Observatory already runs v1.7.x (COOP/COEP scoring)
- Laravel 11 and Wagtail 6.x read only partly (11 not opened; Wagtail 6.4 template and decorator only); Grav 1.7 admin plugin read at 1.10.49.1
- Browser rendering of a type-less HTML document under nosniff
- Redmine and Rails headers not observed on running instances
