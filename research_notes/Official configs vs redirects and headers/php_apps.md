# Official server configurations of PHP applications against agensio's redirect and header design (2026-10-13)

This note checks two proposals against the web server configurations that PHP applications publish
themselves: `docs/redirects.md` (sections 1 to 8: `http`, `canonical`, `hsts`, `[[site.redirect]]`)
and `docs/headers.md` (sections 1 to 4: `[[site.response_headers]]`, refused names, the baseline per
preset). It covers every directive in those configurations that sends a redirect, or that adds,
sets, removes or hides a response header.

## Method

- Both design documents were read in full, and `docs/configuration.md` for the features that exist
  today: `refuse`, `try_files`, `rules` (`private`, `entry_points`, `cache`, `front_controller`),
  locations with `add_headers`, `alias`, `deny_suffixes` and `allow_suffixes`, the presets, and the
  pre-compressed twins.
- Sources were taken from each project's own repository or documentation, at the newest release on
  2026-10-13. Most were fetched as raw files from GitHub with `curl`, or with sparse `git clone`.
  Every link below is pinned to a tag or a commit, with line anchors. Three sites put curl behind a
  bot challenge. Each is marked where it is used:
  - **docs.joomla.org**: read from a Wayback Machine snapshot of 2025-03-18.
  - **docs.moodle.org**: read through a fetch tool that summarises the page. Lines are quoted as
    that tool reported them.
  - **drupal.org**: read through the same fetch tool.
- Application behaviour that affects a classification was checked in the application's source:
  whether the application sends the same field itself, and whether the application still works
  without the rule. These sources are the releases above, plus the sources an earlier session
  downloaded for `research_notes/App default security headers/` (WordPress 7.1.3, Laravel framework
  13, Statamic 6).
- agensio's own behaviour, where a classification depends on it, was checked in this repository at
  the working tree of 2026-10-13. The cited lines are `src/handlers/dispatch.cpp` L469-L480,
  `src/mime.cpp` L69 and L119, and `src/handlers/fastcgi.hpp` L41.

### Classification

| mark | meaning |
|---|---|
| **E** (EXPRESSIBLE) | a setting of the two designs expresses it; the TOML is given |
| **E≈** | expressible with a stated difference that does not change what the application needs |
| **N** (NEEDS A CHANGE) | the designs lack something; the smallest change that would cover it is named |
| **O** (NOT OFFERED ON PURPOSE) | the designs exclude it, with the reason; whether the application works without it |
| **X** (NOT A REDIRECT/HEADER RULE) | it belongs to another agensio feature, which is named; **X-gap** where no agensio feature covers it today |

### Versions and sources

| application | release read | files (pinned) |
|---|---|---|
| Nextcloud | server v35.0.1, admin manual `stable35` (`c02abf851cf4`) | [nginx-root.conf.sample](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-root.conf.sample), [nginx-subdir.conf.sample](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-subdir.conf.sample), [.htaccess](https://github.com/nextcloud/server/blob/v35.0.1/.htaccess), [lib/OC.php](https://github.com/nextcloud/server/blob/v35.0.1/lib/OC.php#L656-L662) |
| Matomo | matomo-nginx `5b232af8ec1f`, matomo 5.14.1 | [matomo.conf](https://github.com/matomo-org/matomo-nginx/blob/5b232af8ec1f/sites-available/matomo.conf), [ServerFilesGenerator.php](https://github.com/matomo-org/matomo/blob/5.14.1/plugins/Installation/ServerFilesGenerator.php#L60-L66) (the `.htaccess` files Matomo writes) |
| MediaWiki | 1.46.2; Manual:Short URL/Nginx rev. 8060723 (2025-12-06) | [Short URL/Nginx](https://www.mediawiki.org/w/index.php?title=Manual:Short_URL/Nginx&oldid=8060723), [Short URL/Apache](https://www.mediawiki.org/wiki/Manual:Short_URL/Apache), [images/.htaccess](https://github.com/wikimedia/mediawiki/blob/1.46.2/images/.htaccess) |
| phpMyAdmin | 5.2.3 | [doc/faq.rst](https://github.com/phpmyadmin/phpmyadmin/blob/RELEASE_5_2_3/doc/faq.rst#L487-L492), [doc/setup.rst](https://github.com/phpmyadmin/phpmyadmin/blob/RELEASE_5_2_3/doc/setup.rst#L612-L617) |
| Magento 2 / Adobe Commerce | 2.4.9 | [nginx.conf.sample](https://github.com/magento/magento2/blob/2.4.9/nginx.conf.sample), [.htaccess](https://github.com/magento/magento2/blob/2.4.9/.htaccess), [pub/.htaccess](https://github.com/magento/magento2/blob/2.4.9/pub/.htaccess), [pub/static/.htaccess](https://github.com/magento/magento2/blob/2.4.9/pub/static/.htaccess), [pub/media/.htaccess](https://github.com/magento/magento2/blob/2.4.9/pub/media/.htaccess) |
| PrestaShop | 9.2.0; docs `9.x` `5724d75970dc` | [Configure Nginx](https://github.com/PrestaShop/docs/blob/5724d75970dc/basics/installation/advanced/nginx.md), [scale/webservers/nginx.md](https://github.com/PrestaShop/docs/blob/5724d75970dc/scale/webservers/nginx.md), [scale/webservers/httpd.md](https://github.com/PrestaShop/docs/blob/5724d75970dc/scale/webservers/httpd.md), [classes/Tools.php `generateHtaccess`](https://github.com/PrestaShop/PrestaShop/blob/9.2.0/classes/Tools.php#L2572) |
| Shopware 6 | 6.7 (recipe `shopware/core/6.7`, recipes `1df82732ec15`); docs `077f6c964c63` | [server/nginx.md](https://github.com/shopware/docs/blob/077f6c964c63/resources/references/config-reference/server/nginx.md), [server/caddy.md](https://github.com/shopware/docs/blob/077f6c964c63/resources/references/config-reference/server/caddy.md), [server/apache.md](https://github.com/shopware/docs/blob/077f6c964c63/resources/references/config-reference/server/apache.md), [public/.htaccess.dist](https://github.com/shopware/recipes/blob/1df82732ec15/shopware/core/6.7/public/.htaccess.dist), [root/.htaccess](https://github.com/shopware/recipes/blob/1df82732ec15/shopware/core/6.7/root/.htaccess) |
| Joomla | 6.1.4 | [htaccess.txt](https://github.com/joomla/joomla-cms/blob/6.1.4/htaccess.txt), [plg_system_httpheaders](https://github.com/joomla/joomla-cms/blob/6.1.4/plugins/system/httpheaders/src/Extension/Httpheaders.php#L356-L376), [docs.joomla.org/Nginx/en (Wayback 2025-03-18)](https://web.archive.org/web/20250318111356/https://docs.joomla.org/Nginx/en) |
| Moodle | 5.3.0 (repository ships no server configuration); docs 5.1 | [docs.moodle.org/501/en/Nginx](https://docs.moodle.org/501/en/Nginx), [docs.moodle.org/501/en/Apache](https://docs.moodle.org/501/en/Apache) |
| Roundcube | 1.7.4; wiki `5c6e16e3aa10` | [public_html/.htaccess](https://github.com/roundcube/roundcubemail/blob/1.7.4/public_html/.htaccess), [wiki Installation](https://github.com/roundcube/roundcubemail/wiki/Installation) |
| FreshRSS | 1.30.1 | [p/.htaccess](https://github.com/FreshRSS/FreshRSS/blob/1.30.1/p/.htaccess), [p/themes/.htaccess](https://github.com/FreshRSS/FreshRSS/blob/1.30.1/p/themes/.htaccess), [docs/en/admins/10_ServerConfig.md](https://github.com/FreshRSS/FreshRSS/blob/1.30.1/docs/en/admins/10_ServerConfig.md), [docs/en/admins/Caddy.md](https://github.com/FreshRSS/FreshRSS/blob/1.30.1/docs/en/admins/Caddy.md), [Docker/FreshRSS.Apache.conf](https://github.com/FreshRSS/FreshRSS/blob/1.30.1/Docker/FreshRSS.Apache.conf) |
| Kirby | 5.6.1; starterkit `b26a7d64c684`; getkirby.com `fd8e1c5074da` | [starterkit .htaccess](https://github.com/getkirby/starterkit/blob/b26a7d64c684/.htaccess#L58-L67), [nginx snippet](https://github.com/getkirby/getkirby.com/blob/fd8e1c5074da/site/snippets/docs/server-config/nginx.php), [Caddy snippet](https://github.com/getkirby/getkirby.com/blob/fd8e1c5074da/site/snippets/docs/server-config/caddy.php) |
| Craft CMS | 5.11.5.1; starter `craftcms/craft` `5.x` `a1747d5be2a3`; `craftcms/docker` `3d27ef3a3542` (the repository says it will be deprecated and archived) | [web/.htaccess](https://github.com/craftcms/craft/blob/a1747d5be2a3/web/.htaccess), [nginx/craftcms/security.conf](https://github.com/craftcms/docker/blob/3d27ef3a3542/nginx/craftcms/security.conf), [nginx/craftcms/general.conf](https://github.com/craftcms/docker/blob/3d27ef3a3542/nginx/craftcms/general.conf); its successor `craftcms/image` (`bf4ac41cb599`) example sets no headers |
| Symfony | docs `8.2` `8964add39f4e`; apache-pack recipe `808d08a46093` | [setup/web_server_configuration.rst](https://github.com/symfony/symfony-docs/blob/8964add39f4e/setup/web_server_configuration.rst), [apache-pack public/.htaccess](https://github.com/symfony/recipes-contrib/blob/808d08a46093/symfony/apache-pack/1.0/public/.htaccess) |
| WordPress | handbook `ddc1a907faaa` (developer.wordpress.org/advanced-administration); core 7.1.3 | [server/nginx.md](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/server/nginx.md), [server/httpd.md](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/server/httpd.md), [security/https.md](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/security/https.md), [nginx wiki recipe it links](https://github.com/nginxinc/nginx-wiki/blob/836ecd605a1b/source/start/topics/recipes/wordpress.rst) |
| Drupal | 11.4.9; nginx wiki `836ecd605a1b` | [core/assets/scaffold/files/htaccess](https://github.com/drupal/drupal/blob/11.4.9/core/assets/scaffold/files/htaccess), [nginx wiki Drupal recipe](https://github.com/nginxinc/nginx-wiki/blob/836ecd605a1b/source/start/topics/recipes/drupal.rst). drupal.org's web server requirements page links no nginx configuration; its only nginx link is nginx.org. |
| TYPO3 | v14.3.8; CoreApi docs `a8e34f3de218` | [root-htaccess](https://github.com/TYPO3/typo3/blob/v14.3.8/typo3/sysext/install/Resources/Private/FolderStructureTemplateFiles/root-htaccess), [resources-root-htaccess](https://github.com/TYPO3/typo3/blob/v14.3.8/typo3/sysext/install/Resources/Private/FolderStructureTemplateFiles/resources-root-htaccess) (written to `fileadmin/.htaccess`, [DefaultFactory.php L294-L302](https://github.com/TYPO3/typo3/blob/v14.3.8/typo3/sysext/install/Classes/FolderStructure/DefaultFactory.php#L294-L302)), [SystemRequirements nginx](https://github.com/TYPO3-Documentation/TYPO3CMS-Reference-CoreApi/blob/a8e34f3de218/Documentation/Administration/Installation/SystemRequirements/_codesnippets/_nginx.conf), [Security nginx](https://github.com/TYPO3-Documentation/TYPO3CMS-Reference-CoreApi/blob/a8e34f3de218/Documentation/Security/GuidelinesAdministrators/_codesnippets/_nginx.config), [ContentSecurityPolicy.rst](https://github.com/TYPO3-Documentation/TYPO3CMS-Reference-CoreApi/blob/a8e34f3de218/Documentation/Security/GuidelinesAdministrators/ContentSecurityPolicy.rst#L44-L73) |
| Grav | 2.2.6 | [webserver-configs/nginx.conf](https://github.com/getgrav/grav/blob/2.2.6/webserver-configs/nginx.conf), [htaccess.txt](https://github.com/getgrav/grav/blob/2.2.6/webserver-configs/htaccess.txt) (the root `.htaccess` is identical), [Caddyfile](https://github.com/getgrav/grav/blob/2.2.6/webserver-configs/Caddyfile) |
| Kanboard | 1.2.54 | [.htaccess](https://github.com/kanboard/kanboard/blob/v1.2.54/.htaccess), [docker/etc/nginx/nginx.conf](https://github.com/kanboard/kanboard/blob/v1.2.54/docker/etc/nginx/nginx.conf#L83-L87), [docs url-rewriting](https://docs.kanboard.org/v1/admin/url-rewriting/) (there is no nginx page) |
| Laravel | 13.x (docs `d8eb65fb70ae`, skeleton `f4000aeb018f`) | [deployment.md](https://github.com/laravel/docs/blob/d8eb65fb70ae/deployment.md#L58-L95), [public/.htaccess](https://github.com/laravel/laravel/blob/f4000aeb018f/public/.htaccess) |
| Statamic | 6.x (starter `83d1acda7919`, docs `65ec7a039fbd`) | [public/.htaccess](https://github.com/statamic/statamic/blob/83d1acda7919/public/.htaccess) (identical to Laravel's), [static-caching.md](https://github.com/statamic/docs/blob/65ec7a039fbd/content/collections/pages/static-caching.md#L132-L227) |

Notes on translating the directives:

- **`expires`.** nginx `expires N` and Apache `ExpiresDefault`/`ExpiresByType "access plus N"`
  both write a moving `Expires` date and `Cache-Control: max-age=N`. A rule without variables can
  only write the second. That is enough, because `max-age` overrides `Expires` (RFC 9111 5.3).
  So `expires 7d` translates to `Cache-Control = "max-age=604800"`, and `expires max` to
  `max-age=315360000`.
- **nginx `add_header` without `always`.** It applies to 2xx, 3xx and 304 answers. agensio's
  `when = "success"` covers 2xx and 304 only, which differs only on redirects.
- **The nginx inheritance trap.** In every nginx sample that repeats fields inside nested
  locations (Nextcloud, Magento, Matomo, MediaWiki, Shopware), the repetition is there because of
  the trap: `add_header` in a nested block drops every inherited field. agensio's per-field rule
  (headers.md 2.2) makes a single `/` rule enough.

## 1. Nextcloud 35

- **NC-1** [nginx-root.conf.sample L17-L27](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-root.conf.sample#L17-L27): `return 301 https://$server_name$request_uri;`. Sends plain HTTP to HTTPS on the configured name.
  **E**: `http = "redirect"`, the default for a TLS site on 443. It answers `308` and keeps the requested name; with `canonical` it goes to that name in one hop.
- **NC-2** [L49-L55](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-root.conf.sample#L49-L55) (repeated at L229-L235): `#add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`. HSTS, commented out, with a warning about preload.
  **E** `hsts = { max_age = "1y", subdomains = true }`. Preload is **O** (redirects.md 4.6), and the sample itself warns against it.
- **NC-3** [L87-L92](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-root.conf.sample#L87-L92): five lines, all with `always`:
  `add_header Referrer-Policy "no-referrer" always;`
  `add_header X-Content-Type-Options "nosniff" always;`
  `add_header X-Frame-Options "SAMEORIGIN" always;`
  `add_header X-Permitted-Cross-Domain-Policies "none" always;`
  `add_header X-Robots-Tag "noindex, nofollow" always;`
  These are security and privacy fields, "borrowed from Nextcloud `.htaccess`", on every answer including errors. Nextcloud's PHP sends the same five itself unless the server passes `modHeadersAvailable` ([lib/OC.php L654-L662](https://github.com/nextcloud/server/blob/v35.0.1/lib/OC.php#L654-L662)). The nginx sample passes it ([L202](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-root.conf.sample#L202) `fastcgi_param modHeadersAvailable true;`) so that the fields are not sent twice.
  **E**: one `/` rule with `default` (TOML below). agensio cannot pass arbitrary FastCGI parameters (none appear in the `php` options of configuration.md 7), so Nextcloud keeps sending the fields on its PHP answers. The `default` rule adds them to files, agensio's error pages and redirects, with one copy each.
- **NC-4** [L94-L95](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-root.conf.sample#L94-L95): `fastcgi_hide_header X-Powered-By;`. Removes the information leak.
  **E**: the baseline removes `X-Powered-By` for any site with `app`. The pools agensio writes also set `expose_php` off.
- **NC-5** [L119-L124](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-root.conf.sample#L119-L124): `location = / { if ( $http_user_agent ~ ^DavClnt ) { return 302 /remote.php/webdav/$is_args$args; } }`. The same rule is in [.htaccess L113-L114](https://github.com/nextcloud/server/blob/v35.0.1/.htaccess#L105-L114): `RewriteCond %{HTTP_USER_AGENT} DavClnt` / `RewriteRule ^$ /remote.php/webdav/ [L,R=302]`. Windows' WebDAV mini-redirector sends its OPTIONS to `/`, and this sends it to the DAV endpoint.
  **O**: the designs have no conditions on request fields (headers.md 3.8, redirects.md 5.4). Nextcloud works without it for every client given the full DAV address (`/remote.php/dav/files/USER/`), which is what Nextcloud's own UI shows. Only "map a drive to `https://host/`" stops working.
- **NC-6** [L140-L141](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-root.conf.sample#L140-L141): `location = /.well-known/carddav { return 301 /remote.php/dav/; }` and `location = /.well-known/caldav { return 301 /remote.php/dav/; }`. The same rules are in [.htaccess L120, L126](https://github.com/nextcloud/server/blob/v35.0.1/.htaccess#L116-L126): `RewriteRule ^\.well-known/carddav /remote.php/dav/ [R=301,L]`. This is RFC 6764 service discovery.
  **E**: two exact rules. agensio serves `/.well-known/` at the root (configuration.md 1). The Apache regex is unanchored at the end, so it also matches `/.well-known/carddavX`; exact is the intent.
- **NC-7** [L136-L149](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-root.conf.sample#L136-L149): `location /.well-known/acme-challenge { try_files $uri $uri/ =404; }`, `location /.well-known/pki-validation { try_files $uri $uri/ =404; }`, then `return 301 /index.php$request_uri;`. Apache does the same without a redirect: [.htaccess L153](https://github.com/nextcloud/server/blob/v35.0.1/.htaccess#L143-L153) `RewriteRule ^\.well-known/(?!acme-challenge|pki-validation) /index.php [L]`. Every other well-known URI (webfinger, nodeinfo, ...) goes to Nextcloud's `WellKnownController`, while certificate validation files are served from disk.
  **X**: the Apache form is an internal rewrite, which agensio's front controller (`try_files` to `/index.php`) already performs because `/.well-known/` is visible.
  If the nginx form is copied as a redirect (`from = "/.well-known"`, `to = "/index.php/.well-known"`), it is **N**: the designs cannot exempt `acme-challenge` and `pki-validation` below a prefix rule. agensio intercepts only the tokens of its own ACME manager (`dispatch.cpp` L469-L480: `acme_->lookup(...)`, else site routing goes on). A webroot ACME client (certbot `--webroot` on a site with its own certificate files), or a CA's `pki-validation` file, would therefore be redirected. See change 5.
- **NC-8** [L253-L256](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-root.conf.sample#L253-L256): `location /remote { return 301 /remote.php$request_uri; }`. Apache instead rewrites internally, [.htaccess L135](https://github.com/nextcloud/server/blob/v35.0.1/.htaccess#L128-L135) `RewriteRule ^remote/(.*) remote.php [L]`, and Nextcloud's own comment there says "Is this even used anymore? Seems a relic from <NC12".
  **E**: a prefix rule from `/remote` to `/remote.php/remote`, which keeps the remainder and the query like `$request_uri` does. nginx's prefix also catches `/remoteX`; agensio's whole-segment prefix does not, which is the intent.
- **NC-9** [L11-L15 and L225-L245](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-root.conf.sample#L225-L245): `map $arg_v $asset_immutable { "" ""; default ", immutable"; }` and `location ~ \.(?:css|js|mjs|svg|gif|ico|jpg|png|webp|wasm|tflite|map|ogg|flac|mp4|webm)$ { try_files $uri /index.php$request_uri; add_header Cache-Control "public, max-age=15778463$asset_immutable"; ...the five fields again... }`. Apache: [.htaccess L46-L54](https://github.com/nextcloud/server/blob/v35.0.1/.htaccess#L46-L54) `<FilesMatch "\.(css|js|mjs|svg|gif|png|jpg|webp|ico|wasm|tflite)$">` `<If "%{QUERY_STRING} =~ /(^|&)v=/">` `Header set Cache-Control "max-age=15778463, immutable"` `<Else>` `Header set Cache-Control "max-age=15778463"`. Assets get six months, and `immutable` when the URL carries a cache-busting `v`.
  **N**: rules match by path prefix only. A file-ending condition is needed (change 1), and the field must stay with files served from disk (change 2), because the `try_files` fallback reaches PHP. The `immutable` that depends on `?v=` is **O** (no query conditions); without it browsers revalidate with ETag, and Nextcloud works.
- **NC-10** [L247-L251](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-root.conf.sample#L247-L251): `location ~ \.(otf|woff2?)$ { try_files $uri /index.php$request_uri; expires 7d; }`. Apache: [.htaccess L56-L59](https://github.com/nextcloud/server/blob/v35.0.1/.htaccess#L56-L59) `Header set Cache-Control "max-age=604800"`. Fonts are cached for a week.
  **N**: as NC-9.
- **NC-11** [.htaccess L17-L43](https://github.com/nextcloud/server/blob/v35.0.1/.htaccess#L17-L43): pairs of `Header onsuccess unset X` / `Header always set X` for the five fields, plus `SetEnv modHeadersAvailable true`. Apache's way of sending one copy on every answer, errors included.
  **E**: `set` deletes every copy and sends one (headers.md 2.3), and `when = "always"` is the default.
- **NC-12** [.htaccess L21-L29](https://github.com/nextcloud/server/blob/v35.0.1/.htaccess#L21-L29): `<If "%{REQUEST_URI} =~ m#/login$#">` `Header always set Referrer-Policy "same-origin"` `<Else>` `Header always set Referrer-Policy "no-referrer"`. "Only on the login page we need any Origin or Referer header set."
  **E**: two exact rules, `/login` and `/index.php/login`, `set` `same-origin`, which win over the `/` rule for that field. The regex is any path ending in `/login`, which matters only for subdirectory installs. The nginx sample has no such exception and Nextcloud works with it.
- **NC-13** [.htaccess L70-L76](https://github.com/nextcloud/server/blob/v35.0.1/.htaccess#L70-L76): `AddType image/svg+xml svg svgz` / `AddEncoding gzip svgz`.
  **X-gap** (type table): agensio maps `svgz` to `image/svg+xml` with no `Content-Encoding` (`mime.cpp` L69), as nginx's `mime.types` does, so a browser cannot render a `.svgz`. The same lines are in Drupal and TYPO3. See change 9.
- **NC-14** [L22-L23, L46-L47](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-root.conf.sample#L46-L47): `server_tokens off;`.
  **X**: `[server] server_header`, a server-wide setting.

The subdirectory sample ([nginx-subdir.conf.sample](https://github.com/nextcloud/documentation/blob/c02abf851cf4/admin_manual/installation/nginx-subdir.conf.sample#L26-L27)) has the same directives under `/nextcloud`, plus `location /nextcloud { return 301 https://$server_name$request_uri; }` on port 80.

```toml
[[site]]
server_name = ["cloud.example.com"]
listen = ["0.0.0.0:443", "[::]:443"]
root = "/var/www/nextcloud"
app = "php"
tls = "auto"
hsts = { max_age = "1y", subdomains = true }          # NC-2, without preload

[[site.redirect]]                                      # NC-6
from = "/.well-known/carddav"
match = "exact"
to = "/remote.php/dav/"
status = 301

[[site.redirect]]
from = "/.well-known/caldav"
match = "exact"
to = "/remote.php/dav/"
status = 301

[[site.response_headers]]                              # NC-3, NC-11: PHP sends its own, the rule fills files and errors
path = "/"
default = { "Referrer-Policy" = "no-referrer", "X-Content-Type-Options" = "nosniff", "X-Frame-Options" = "SAMEORIGIN", "X-Permitted-Cross-Domain-Policies" = "none", "X-Robots-Tag" = "noindex, nofollow" }

[[site.response_headers]]                              # NC-12 (and the same for /index.php/login)
path = "/login"
match = "exact"
set = { "Referrer-Policy" = "same-origin" }
```

## 2. Matomo 5

- **MT-1** [matomo.conf L1-L9](https://github.com/matomo-org/matomo-nginx/blob/5b232af8ec1f/sites-available/matomo.conf#L5-L8): `location / { return 301 https://$host$request_uri; }`. Sends plain HTTP to HTTPS.
  **E**: `http = "redirect"`.
- **MT-2** [L17-L19](https://github.com/matomo-org/matomo-nginx/blob/5b232af8ec1f/sites-available/matomo.conf#L17-L19): `#add_header Strict-Transport-Security max-age=15768000 always;`. Optional HSTS for six months.
  **E**: `hsts = { max_age = 15768000 }`. The design's examples write durations (`"2y"`) and `0`; whether a bare number of seconds is accepted is not stated.
- **MT-3** [L27](https://github.com/matomo-org/matomo-nginx/blob/5b232af8ec1f/sites-available/matomo.conf#L27): `add_header Referrer-Policy origin always;`. "make sure outgoing links don't show the URL to the Matomo instance".
  **E**: `set` at `/`. Matomo's PHP sends its own `Referrer-Policy` on UI pages, `same-origin` or `no-referrer-when-downgrade` ([core/View.php L304-L310](https://github.com/matomo-org/matomo/blob/5.14.1/core/View.php#L304-L310)), and `no-referrer` on data answers ([core/Http/SecurityHeaders.php L34-L35](https://github.com/matomo-org/matomo/blob/5.14.1/core/Http/SecurityHeaders.php#L34-L35)). nginx therefore sends two fields, and `set` sends one.
- **MT-4** [L28](https://github.com/matomo-org/matomo-nginx/blob/5b232af8ec1f/sites-available/matomo.conf#L28): `add_header X-Content-Type-Options "nosniff" always;`.
  **E**: `set` or `default` at `/`.
- **MT-5** [L29](https://github.com/matomo-org/matomo-nginx/blob/5b232af8ec1f/sites-available/matomo.conf#L29): `add_header X-XSS-Protection "1; mode=block" always;`.
  **E**: `set`, but `-t` warns (headers.md 2.6). Leaving it out changes nothing in current browsers.
- **MT-6** [L66-L69](https://github.com/matomo-org/matomo-nginx/blob/5b232af8ec1f/sites-available/matomo.conf#L66-L69): `location ~ js/container_.*_preview\.js$ { expires off; add_header Cache-Control 'private, no-cache, no-store'; }`. Matomo writes the same rule as `/js/.htaccess` ([ServerFilesGenerator.php L60-L66](https://github.com/matomo-org/matomo/blob/5.14.1/plugins/Installation/ServerFilesGenerator.php#L60-L66)): `<Files ~ "^container_.*_preview\.js$">` `Header set Cache-Control "Cache-Control: private, no-cache, no-store"`. The generated value repeats the field name and is malformed. The purpose is that Tag Manager preview containers are never cached.
  **N**: a file-name pattern within one directory, `/js/container_*_preview.js`, needs a `*` within a segment in a rule's path (change 3). `no-store` is accepted without `when` (headers.md 2.4). Without it, a preview can be stale. With MT-7 translated by prefix, it would even be cached for an hour.
- **MT-7** [L71-L78](https://github.com/matomo-org/matomo-nginx/blob/5b232af8ec1f/sites-available/matomo.conf#L71-L78): `location ~ \.(gif|ico|jpg|png|svg|js|css|htm|html|mp3|mp4|wav|ogg|avi|ttf|eot|woff|woff2)$ { allow all; expires 1h; add_header Pragma public; add_header Cache-Control "public"; }`. Static assets are cached for an hour.
  **N** (change 1). `Pragma` is obsolete. This location's `add_header` also drops the server-level MT-3 to MT-5 fields for these files: the trap again.
- **MT-8** [L85-L88](https://github.com/matomo-org/matomo-nginx/blob/5b232af8ec1f/sites-available/matomo.conf#L85-L88): `location ~/(.*\.md|LEGALNOTICE|LICENSE) { default_type text/plain; }`.
  **X** (type table). agensio sends `.md` as `text/markdown` and extensionless files as `application/octet-stream` (`mime.cpp` L119). Harmless.

```toml
[[site.response_headers]]
path = "/"
set = { "Referrer-Policy" = "origin" }              # MT-3: one field instead of Matomo's plus nginx's
default = { "X-Content-Type-Options" = "nosniff" }  # MT-4
```

## 3. MediaWiki 1.46

From [Manual:Short URL/Nginx](https://www.mediawiki.org/w/index.php?title=Manual:Short_URL/Nginx&oldid=8060723) (the line numbers are those of the page's code block) and the release's [images/.htaccess](https://github.com/wikimedia/mediawiki/blob/1.46.2/images/.htaccess):

- **MW-1** `location /w/images { add_header X-Content-Type-Options "nosniff"; types { text/plain html htm shtml phtml; } }`. The uploads directory: no sniffing, and uploaded HTML served as text.
  The field is **E** (a `/w/images/` rule, and the baseline already sends `nosniff` on files agensio serves). The `types` override is **X-gap**: the type table is site-wide by ending, with no per-path type. MW-6's `sandbox` CSP covers the same risk, and `deny_suffixes` could refuse the endings.
- **MW-2** `location ~ ^/w/resources/(assets|lib|src) { try_files $uri =404; add_header Cache-Control "public"; expires 7d; }`. Core assets for a week.
  **E**: three prefix rules (`/w/resources/assets/`, `/lib/`, `/src/`) with `when = "success"` and `set` `"public, max-age=604800"`.
- **MW-3** `location ~ ^/w/(skins|extensions)/.+\.(css|js|gif|jpg|jpeg|png|svg|wasm|ttf|woff|woff2)$ { try_files $uri =404; add_header Cache-Control "public"; expires 7d; }`.
  **N** (change 1), or **E≈** with prefix rules on `/w/skins/` and `/w/extensions/` and `when = "success"`: with `rules.entry_points` limited to MediaWiki's entry points, nothing but static files answers 200 there.
- **MW-4** `location = /favicon.ico { alias /w/images/6/64/Favicon.ico; add_header Cache-Control "public"; expires 7d; }`.
  **E**: an exact rule. The `alias` is an exact location, as today.
- **MW-5** `location = / { return 301 /wiki/Main_Page; }`. "Explicit access to the root website, redirect to main page".
  **E**: exact rule `/` to `/wiki/Main_Page`, 301.
- **MW-6** [images/.htaccess L1-L15](https://github.com/wikimedia/mediawiki/blob/1.46.2/images/.htaccess): `Header set X-Content-Type-Options nosniff`; `Header set Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline' data:; font-src data:; img-src data: 'self'; media-src data: 'self'; sandbox"`; `<Files "*.pdf">` `Header set Content-Security-Policy "default-src 'none'; ...; object-src 'self'"`, because "Chrome wants no sandbox and object-src 'self' to load pdfs". This is the upload CSP.
  The directory value is **E** (a prefix rule; `default` avoids the CSP warning of headers.md 7). The PDF variant is **N**: a file-ending rule must beat the prefix rule of the same path for that field (changes 1 and 1a).
- **MW-7** `location /wiki/ { rewrite ^/wiki/(?<pagename>.*)$ /w/index.php; }`, and on Apache `RewriteRule ^/?wiki(/.*)?$ %{DOCUMENT_ROOT}/w/index.php [L]`, whose "Redirect / to Main Page" is also an internal rewrite.
  **X**: a `/wiki/` location with `try_files = ["/w/index.php?$query_string"]`.
- **MW-8** `location / { return 404; }` (every other entry point).
  **X**: refusal (`handler = "deny"` locations, `refuse`).

```toml
[[site.redirect]]                    # MW-5
from = "/"
match = "exact"
to = "/wiki/Main_Page"
status = 301

[[site.response_headers]]            # MW-6 (directory value), MW-1
path = "/w/images/"
default = { "Content-Security-Policy" = "default-src 'none'; style-src 'unsafe-inline' data:; font-src data:; img-src data: 'self'; media-src data: 'self'; sandbox" }

[[site.response_headers]]            # MW-2, and likewise /w/resources/lib/ and /w/resources/src/
path = "/w/resources/assets/"
when = "success"
set = { "Cache-Control" = "public, max-age=604800" }
```

## 4. phpMyAdmin 5.2

The documentation gives no server configuration with headers. phpMyAdmin sends its own fields from PHP: `X-Frame-Options`, `Referrer-Policy: same-origin`, `X-XSS-Protection`, `nosniff`, `X-Permitted-Cross-Domain-Policies`, `X-Robots-Tag: noindex, nofollow` and a CSP ([libraries/classes/Header.php L492-L628](https://github.com/phpmyadmin/phpmyadmin/blob/RELEASE_5_2_3/libraries/classes/Header.php#L492-L628)).

- **PMA-1** [doc/faq.rst L487-L492](https://github.com/phpmyadmin/phpmyadmin/blob/RELEASE_5_2_3/doc/faq.rst#L476-L497) (FAQ 4.8, "If you want a URL like `http://server/phpMyAdmin/database[/table][/script]`"):
  `RewriteRule ^([a-zA-Z0-9_]+)/([a-zA-Z0-9_]+)/([a-z_]+\.php)$ index.php?db=$1&table=$2&target=$3 [R]`
  `RewriteRule ^([a-zA-Z0-9_]+)/([a-z_]+\.php)$ index.php?db=$1&target=$2 [R]`
  `RewriteRule ^([a-zA-Z0-9_]+)/([a-zA-Z0-9_]+)$ index.php?db=$1&table=$2 [R]`
  `RewriteRule ^([a-zA-Z0-9_]+)$ index.php?db=$1 [R]`
  Optional "pretty" database URLs.
  **O**: the targets are built from captured path segments (redirects.md 5.4). The feature is optional, and partly stale: the same FAQ says `target` was removed in 5.1. phpMyAdmin works without it.
- **PMA-2** [doc/setup.rst L612-L617](https://github.com/phpmyadmin/phpmyadmin/blob/RELEASE_5_2_3/doc/setup.rst#L612-L617) (Traefik v1 example): `[entryPoints.http.redirect]` `regex = "(http:\\/\\/[^\\/]+\\/([^\\?\\.]+)[^\\/])$"` `replacement = "$1/"`. Adds a trailing slash for a proxied subfolder.
  **O**: a regex, site-wide trailing slash (5.4). It is the old Traefik syntax.
- **PMA-3** [doc/faq.rst L645-L671](https://github.com/phpmyadmin/phpmyadmin/blob/RELEASE_5_2_3/doc/faq.rst#L645-L671) (FAQ 1.42): user-agent conditions, then `RewriteRule .* - [F]`.
  **X**: not a redirect (403). agensio has no user-agent refusals. The `X-Robots-Tag` phpMyAdmin sends itself is the part that matters to search engines.

## 5. Magento 2.4.9 / Adobe Commerce

- **M2-1** [nginx.conf.sample L38](https://github.com/magento/magento2/blob/2.4.9/nginx.conf.sample#L38): `#add_header "X-UA-Compatible" "IE=Edge";` (commented out). [pub/.htaccess L277-L286](https://github.com/magento/magento2/blob/2.4.9/pub/.htaccess#L277-L286): `Header set X-UA-Compatible "IE=edge"`, then `<FilesMatch "\.(appcache|atom|...|xpi)$">` `Header unset X-UA-Compatible` for everything that is not HTML. This is an IE document mode, obsolete.
  **E≈**: `set` at `/`. The unset for non-HTML endings is **N** (change 1), but harmless to drop.
- **M2-2** `add_header X-Frame-Options "SAMEORIGIN";` repeated in every nested location of nginx.conf.sample: [L72](https://github.com/magento/magento2/blob/2.4.9/nginx.conf.sample#L71-L73), [L95](https://github.com/magento/magento2/blob/2.4.9/nginx.conf.sample#L94-L96), [L108](https://github.com/magento/magento2/blob/2.4.9/nginx.conf.sample#L103-L109), [L122, L130, L140](https://github.com/magento/magento2/blob/2.4.9/nginx.conf.sample#L111-L141), [L175, L181, L185](https://github.com/magento/magento2/blob/2.4.9/nginx.conf.sample#L143-L186). [pub/.htaccess L288-L289](https://github.com/magento/magento2/blob/2.4.9/pub/.htaccess#L288-L289): `Header set X-Frame-Options SAMEORIGIN`. Clickjacking protection.
  **E**: one rule at `/` with `default`. Magento's PHP sends its own (`X-Frame-Options` from `env.php`, plus `nosniff` and `X-XSS-Protection`, through `Magento\Framework\App\Response\HeaderProvider\*` in 2.4.9), so `default` keeps it. The repetition in the sample is the inheritance trap.
- **M2-3** [nginx.conf.sample L111-L127](https://github.com/magento/magento2/blob/2.4.9/nginx.conf.sample#L111-L127): `# add_header Cache-Control "public, max-age=31536000, immutable";` (L113) and, inside `/static/`, `location ~* \.(ico|jpg|jpeg|png|gif|svg|svgz|webp|avif|avifs|js|css|eot|ttf|otf|woff|woff2|html|json|webmanifest)$ { add_header Cache-Control "public, max-age=31536000, immutable"; ... }`. [pub/static/.htaccess L77-L79](https://github.com/magento/magento2/blob/2.4.9/pub/static/.htaccess#L75-L85): `Header append Cache-Control "public, max-age=31536000, immutable"`. Deployed static files are cached for a year; their URLs carry a version segment.
  **N** (change 1), or **E≈** with a `/static/` prefix rule, `when = "success"`: that also covers the few archives Magento marks `no-store` (M2-4).
- **M2-4** [nginx.conf.sample L128-L136, L179-L184](https://github.com/magento/magento2/blob/2.4.9/nginx.conf.sample#L128-L136): `location ~* \.(zip|gz|gzip|bz2|csv|xml)$ { add_header Cache-Control "no-store"; add_header X-Frame-Options "SAMEORIGIN"; expires off; }`. [pub/static/.htaccess L81-L83](https://github.com/magento/magento2/blob/2.4.9/pub/static/.htaccess#L81-L83) and [pub/media/.htaccess L82-L84](https://github.com/magento/magento2/blob/2.4.9/pub/media/.htaccess#L82-L84): `Header append Cache-Control no-store`. Exports and archives are never cached.
  **N** (change 1).
- **M2-5** [nginx.conf.sample L173-L178](https://github.com/magento/magento2/blob/2.4.9/nginx.conf.sample#L173-L178): in `/media/`, `location ~* \.(ico|jpg|...|woff2)$ { add_header Cache-Control "public"; add_header X-Frame-Options "SAMEORIGIN"; expires +1y; try_files $uri $uri/ /get.php$is_args$args; }`. [pub/media/.htaccess L78-L80](https://github.com/magento/magento2/blob/2.4.9/pub/media/.htaccess#L76-L86): `Header append Cache-Control public`. Media is cached for a year.
  **N** (change 1), or **E≈** by prefix.
- **M2-6** [pub/static/.htaccess L87-L146](https://github.com/magento/magento2/blob/2.4.9/pub/static/.htaccess#L87-L146) and [pub/media/.htaccess L88-L137](https://github.com/magento/magento2/blob/2.4.9/pub/media/.htaccess#L88-L137): `ExpiresActive On`, then per-type and per-ending lifetimes, for example `ExpiresByType text/css "access plus 1 year"`, `ExpiresByType application/json "access plus 0 seconds"`, `<FilesMatch \.(zip|gz|gzip|bz2|csv|xml)$> ExpiresDefault "access plus 0 seconds"`.
  **N**: by Content-Type or ending (change 1).
- **M2-7** [pub/.htaccess L192-L202](https://github.com/magento/magento2/blob/2.4.9/pub/.htaccess#L192-L202): `ExpiresDefault "access plus 1 year"`, `ExpiresByType text/html A0`, `ExpiresByType text/plain A0`. This file has no `ExpiresActive On`, so these lines do nothing unless the server configuration turns it on.
  Same as M2-6 when active.
- **M2-8** [pub/static/.htaccess L26-L29](https://github.com/magento/magento2/blob/2.4.9/pub/static/.htaccess#L26-L29): `<Files moxieplayer.swf>` `RewriteCond %{QUERY_STRING} !^$` `RewriteRule ^(.*)$ %{REQUEST_URI}? [R=301,L]`. Strips any query from a Flash player, an old XSS mitigation.
  **O**: a redirect to the same path, conditioned on a query. agensio would refuse it as a loop (redirects.md 8). Flash is gone, and `refuse = ["moxieplayer.swf"]` gives the protection.
- **M2-9** [pub/.htaccess L159-L160](https://github.com/magento/magento2/blob/2.4.9/pub/.htaccess#L157-L160): `RewriteCond %{REQUEST_METHOD} ^TRAC[EK]` `RewriteRule .* - [L,R=405]`.
  **X**: agensio answers TRACE with 405 already. `R=405` is a status, not a redirect.
- **M2-10** [nginx.conf.sample L115-L118, L124-L126, L137-L139](https://github.com/magento/magento2/blob/2.4.9/nginx.conf.sample#L115-L139): `location ~ ^/static/version\d*/ { rewrite ^/static/version\d*/(.*)$ /static/$1 last; }` and `if (!-f $request_filename) { rewrite ^/static/(version\d*/)?(.*)$ /static.php?resource=$2 last; }`. [pub/static/.htaccess L19-L24](https://github.com/magento/magento2/blob/2.4.9/pub/static/.htaccess#L12-L24): `RewriteRule ^version.+?/(.+)$ $1 [L]`, `RewriteRule .* ../static.php?resource=$0 [L]`. Strips the cache-busting segment, and makes missing files on demand.
  **X-gap**: internal rewrites with captures; no agensio feature strips a variable segment or builds `?resource=` from the path. Magento works with static signing off (`dev/static/sign = 0`) and every file deployed (production mode), but signed URLs 404 without it.
- **M2-11** [nginx.conf.sample L37](https://github.com/magento/magento2/blob/2.4.9/nginx.conf.sample#L37) `error_page 404 403 = /errors/404.php;` and [pub/.htaccess L247-L248](https://github.com/magento/magento2/blob/2.4.9/pub/.htaccess#L245-L248) `ErrorDocument 404 /errors/404.php`.
  **X**: error pages, not redirects.
- **M2-12** [.htaccess L1-L6](https://github.com/magento/magento2/blob/2.4.9/.htaccess): `RewriteRule .* /pub/$0 [L]` (unless `/pub/`, `/setup/`, `/update/` or `/dev/`).
  **X**: `root` is `pub/`.

```toml
[[site.response_headers]]            # M2-2: Magento's PHP sends its own, files and errors get this
path = "/"
default = { "X-Frame-Options" = "SAMEORIGIN" }

[[site.response_headers]]            # M2-3, by prefix (E≈: also the rare archives under /static/)
path = "/static/"
when = "success"
set = { "Cache-Control" = "public, max-age=31536000, immutable" }
```

## 6. PrestaShop 9.2

- **PS-1** [Configure Nginx L50-L53](https://github.com/PrestaShop/docs/blob/5724d75970dc/basics/installation/advanced/nginx.md#L50-L53): `# add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" preload; always;`, commented out. As written it is a syntax error, because `preload` is outside the quotes.
  **E**: `hsts = { max_age = "2y", subdomains = true }`. Preload is **O**.
- **PS-2** [L55-L56](https://github.com/PrestaShop/docs/blob/5724d75970dc/basics/installation/advanced/nginx.md#L55-L56): `# add_header X-XSS-Protection "1; mode=block";`.
  **E**, warned by `-t`.
- **PS-3** [L58-L59](https://github.com/PrestaShop/docs/blob/5724d75970dc/basics/installation/advanced/nginx.md#L58-L59): `# add_header X-Frame-Options "SAMEORIGIN";`.
  **E**.
- **PS-4** [L61-L62](https://github.com/PrestaShop/docs/blob/5724d75970dc/basics/installation/advanced/nginx.md#L61-L62): `# add_header X-Content-Type-Options nosniff;`.
  **E**.
- **PS-5** [L64-L65](https://github.com/PrestaShop/docs/blob/5724d75970dc/basics/installation/advanced/nginx.md#L64-L65): `# add_header Set-Cookie "Path=/; HttpOnly; Secure";`, under "Secure Cookie".
  **O**: `Set-Cookie` is refused (headers.md 2.5). The line does not do what its title says: it adds a cookie with no name, and flags none of PrestaShop's cookies.
- **PS-6** [L67-L69](https://github.com/PrestaShop/docs/blob/5724d75970dc/basics/installation/advanced/nginx.md#L67-L69): `# rewrite ^/fr$ /fr/ redirect;`. Adds the slash to a language prefix.
  **E**: exact rule `/fr` to `/fr/`, `302`, one per language.
- **PS-7** [L70-L72](https://github.com/PrestaShop/docs/blob/5724d75970dc/basics/installation/advanced/nginx.md#L70-L72): `# rewrite ^/fr/(.*) /$1;` and `# rewrite '^/((?!js|qq)[a-z]{2})/(.*)' /index.php?isolang=$1&$args last;`, commented out, "if you encounter issues".
  **X-gap** (internal rewrites with captures).
- **PS-8** [L74-L92](https://github.com/PrestaShop/docs/blob/5724d75970dc/basics/installation/advanced/nginx.md#L74-L92): `rewrite ^/(\d)(-[\w-]+)?/.+\.(jpe?g|png|webp|avif)$ /img/p/$1/$1$2.$3 last;` (eight such lines), `rewrite ^/c/([\w.-]+)/.+\.(jpe?g|png|webp|avif)$ /img/c/$1.$2 last;`, `rewrite ^/api/?(.*)$ /webservice/dispatcher.php?url=$1 last;`. The same rules are generated into `.htaccess` ([Tools.php L2722-L2745](https://github.com/PrestaShop/PrestaShop/blob/9.2.0/classes/Tools.php#L2722-L2745)). They map friendly image URLs and the webservice.
  **X-gap**: internal rewrites with captures. Without them, product and category images 404 when friendly URLs are on, and `/api/` does not reach the webservice.
- **PS-9** [L46-L47](https://github.com/PrestaShop/docs/blob/5724d75970dc/basics/installation/advanced/nginx.md#L46-L47): `error_page 404 /index.php?controller=404;`.
  **X**.
- **PS-10** [Tools.php L2707-L2719](https://github.com/PrestaShop/PrestaShop/blob/9.2.0/classes/Tools.php#L2707-L2719): for a multishop virtual URI, `RewriteRule ^shop2/?$ /shop2/index.php [L,R]` (rewrite off) or `RewriteRule ^shop2$ /shop2/ [L,R]` (302), then `RewriteRule ^shop2(.*) /$1 [L]`.
  The redirect is **E**: an exact rule on that shop's site. The internal strip is **X-gap**.
- **PS-11** [Tools.php L2773-L2782](https://github.com/PrestaShop/PrestaShop/blob/9.2.0/classes/Tools.php#L2773-L2782): `<FilesMatch "\.(ttf|ttc|otf|eot|woff|woff2|svg)$">` `Header set Access-Control-Allow-Origin "*"`, under "Serve fonts properly and avoid CORS issues".
  **N** (change 1), or **E≈** with prefix rules on the theme and module directories: a fixed `*` on any public file there is harmless (headers.md 3.3).
- **PS-12** [Tools.php L2800-L2827](https://github.com/PrestaShop/PrestaShop/blob/9.2.0/classes/Tools.php#L2800-L2827): when "Apache optimization" is on in the back office, `ExpiresActive On` plus `ExpiresByType` from a week to a year by type.
  **N** (change 1).
- **PS-13** [Tools.php L2829-L2833](https://github.com/PrestaShop/PrestaShop/blob/9.2.0/classes/Tools.php#L2829-L2833): `Header unset Etag` / `FileETag none`.
  **O**: `ETag` is a representation field that `remove` refuses (headers.md 2.5). Keeping it makes revalidation work.
- **PS-14** [scale/webservers/nginx.md L62-L65](https://github.com/PrestaShop/docs/blob/5724d75970dc/scale/webservers/nginx.md#L62-L65): `location ~* \.(?:css|eot|gif|ico|jpe?g|otf|png|ttf|woff2?)$ { expires 1M; add_header Cache-Control "public"; }`.
  **N** (change 1).
- **PS-15** [scale/webservers/httpd.md L46-L50, L64-L81](https://github.com/PrestaShop/docs/blob/5724d75970dc/scale/webservers/httpd.md#L44-L82): `<FilesMatch "\.(ico|jpe?g|png|gif|css|woff2)$">` `Header set Cache-Control "max-age=2592000, public"`, then `ExpiresDefault "access plus 7200 seconds"`, `ExpiresByType ...`, and `<FilesMatch \.php$> ExpiresActive Off`, with the comment "Do not allow PHP scripts to be cached unless they explicitly send cache headers themselves".
  **N**: changes 1 and 2. The `.php` exception is the "files only" condition.

The PrestaShop nginx sample listens on 80 and 443 in one `server` with no redirect. PrestaShop redirects to HTTPS itself when SSL is enabled in its settings; agensio's `http = "redirect"` points the same way.

## 7. Shopware 6.7

- **SW-1** [public/.htaccess.dist L20-L21](https://github.com/shopware/recipes/blob/1df82732ec15/shopware/core/6.7/public/.htaccess.dist#L20-L21): `RewriteCond %{ENV:REDIRECT_STATUS} ^$` `RewriteRule ^index\.php(?:/(.*)|$) %{ENV:BASE}/$1 [R=301,L]`. Removes `/index.php` from client URLs; `REDIRECT_STATUS` empty means a client request, not an internal one.
  **E**: prefix rule `/index.php` to `/`, `301`. Rules match only the path the client asked for, never the front controller hop (headers.md 1; redirects.md 1 step 4).
- **SW-2** [L33-L37](https://github.com/shopware/recipes/blob/1df82732ec15/shopware/core/6.7/public/.htaccess.dist#L33-L37): `RedirectMatch 302 ^/$ /index.php/`, only without mod_rewrite.
  Not needed, because agensio routes with `try_files`. **E** anyway.
- **SW-3** These lines send `script-src 'none'` on SVG files:
  - [public/.htaccess.dist L39-L43](https://github.com/shopware/recipes/blob/1df82732ec15/shopware/core/6.7/public/.htaccess.dist#L39-L43): `<FilesMatch "\.(?i:svg)$">` `Header set Content-Security-Policy "script-src 'none'"`.
  - [nginx.md L74-L76](https://github.com/shopware/docs/blob/077f6c964c63/resources/references/config-reference/server/nginx.md#L74-L76) `location ~* ^.+\.svg$ { add_header Content-Security-Policy "script-src 'none'"; }`, and the nested copy at L47-L51.
  - [caddy.md L10-L15](https://github.com/shopware/docs/blob/077f6c964c63/resources/references/config-reference/server/caddy.md#L10-L15): `@svg { file; path *.svg }` `header @svg Content-Security-Policy "script-src 'none'"`. Caddy's `file` matcher applies the field only when the file exists on disk.

  **N**: changes 1 and 2. A site-wide prefix rule would put `script-src 'none'` on Shopware's HTML.
- **SW-4** [nginx.md L37-L52](https://github.com/shopware/docs/blob/077f6c964c63/resources/references/config-reference/server/nginx.md#L37-L52): `location ~ ^/(theme|media|thumbnail|bundles|css|fonts|js|recovery|sitemap)/ { expires 1y; add_header Cache-Control "public, must-revalidate, proxy-revalidate"; ... }`. Public asset directories for a year.
  **E**: one prefix rule per directory, `when = "success"`, `set` `"public, max-age=31536000, must-revalidate, proxy-revalidate"`.
- **SW-5** [nginx.md L54-L72](https://github.com/shopware/docs/blob/077f6c964c63/resources/references/config-reference/server/nginx.md#L54-L72): `location ~* ^.+\.(?:css|cur|js|jpe?g|gif|ico|png|svg|webp|html|woff|woff2|xml)$ { expires 1y; add_header Cache-Control "public, must-revalidate, proxy-revalidate"; ... try_files $uri /index.php$is_args$args; }`.
  **N**: changes 1 and 2. In nginx the field stays with files on disk, while a missing `.xml` or `.html` goes to PHP without it. A suffix rule alone would also give PHP answers for such paths a year: Shopware's `/sitemap.xml` is answered by the application (not verified in this pass).
- **SW-6** [caddy.md L4-L8](https://github.com/shopware/docs/blob/077f6c964c63/resources/references/config-reference/server/caddy.md#L4-L8): `header { X-Frame-Options DENY  Referrer-Policy no-referrer-when-downgrade }`.
  **E**: a `/` rule. The nginx and Apache documents send neither field.
- **SW-7** [root/.htaccess L11, L14](https://github.com/shopware/recipes/blob/1df82732ec15/shopware/core/6.7/root/.htaccess#L9-L15): `RedirectMatch 404 /\\.(svn|git|hg|bzr|cvs)(/|$)` and `RedirectMatch 404 /(composer\.(json|lock|phar)|README\.md|\.gitignore|.*\.dist|\.env.*)$`.
  **X**: refusals with `RedirectMatch` used for its status; `refuse` covers them.

```toml
[[site.redirect]]                    # SW-1 (also Symfony SY-1 with 308, Drupal DR-11 with 307)
from = "/index.php"
to = "/"
status = 301

[[site.response_headers]]            # SW-4, and likewise /media/, /thumbnail/, /bundles/, /css/, /fonts/, /js/, /sitemap/
path = "/theme/"
when = "success"
set = { "Cache-Control" = "public, max-age=31536000, must-revalidate, proxy-revalidate" }
```

## 8. Joomla 6.1

- **J-1** [htaccess.txt L39-L43](https://github.com/joomla/joomla-cms/blob/6.1.4/htaccess.txt#L39-L43): `Header always set X-Content-Type-Options "nosniff"`. "Suppress mime type detection in browsers for unknown types", on every answer, PHP included.
  **E**: `set` at `/`. Joomla's PHP does not send `nosniff`. Its `httpheaders` plugin sends `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin` and `Cross-Origin-Opener-Policy: same-origin` by default, and HSTS and CSP when switched on ([Httpheaders.php L356-L398](https://github.com/joomla/joomla-cms/blob/6.1.4/plugins/system/httpheaders/src/Extension/Httpheaders.php#L356-L398)).
- **J-2** [L44-L50](https://github.com/joomla/joomla-cms/blob/6.1.4/htaccess.txt#L44-L50): `#Header always set Cross-Origin-Resource-Policy "same-origin"` / `#Header always set Cross-Origin-Embedder-Policy "require-corp"`.
  **E**.
- **J-3** [L52-L58](https://github.com/joomla/joomla-cms/blob/6.1.4/htaccess.txt#L52-L58): `<FilesMatch "\.svg$">` `Header always set Content-Security-Policy "script-src 'none'"`. "Disable inline JavaScript when directly opening SVG files".
  **N** (change 1).
- **J-4** [L70-L78](https://github.com/joomla/joomla-cms/blob/6.1.4/htaccess.txt#L64-L78): query-string exploit filters (`base64_encode`, `<script>`, `GLOBALS`, `_REQUEST`), then `RewriteRule .* index.php [F]`.
  **X-gap**: a refusal by query, which agensio does not have (`refuse` matches paths). This is defence in depth; Joomla works without it.
- **J-5** [L129-L137](https://github.com/joomla/joomla-cms/blob/6.1.4/htaccess.txt#L129-L137): `RedirectMatch 302 ^/$ /index.php/`, only without mod_rewrite.
  Not needed.
- **J-6** [L147-L172](https://github.com/joomla/joomla-cms/blob/6.1.4/htaccess.txt#L139-L172): `.css.gz`/`.js.gz` selection, `[T=text/css]`, `Header set Content-Encoding gzip`, `Header append Vary Accept-Encoding`.
  **X**: agensio's pre-compressed twins (`name.gz` beside `name`) do this natively.
- **J-7** [L79-L86](https://github.com/joomla/joomla-cms/blob/6.1.4/htaccess.txt#L79-L86): "Custom redirects ... a canonical non-www to www redirect (or vice versa)", a placeholder.
  **E**: `canonical`.
- **J-8** [docs.joomla.org Nginx (Wayback 2025-03-18)](https://web.archive.org/web/20250318111356/https://docs.joomla.org/Nginx/en):
  - `add_header X-Content-Type-Options nosniff;` is **E**.
  - `location ~* \.(ico|pdf|flv)$ { expires 1y; }` and `location ~* \.(js|css|png|jpg|jpeg|gif|swf|xml|txt)$ { expires 14d; }` are **N** (change 1).

## 9. Moodle 5.x

The repository at v5.3.0 ships no web server file. The documentation pages are behind a challenge for curl and were read through the fetch tool.

- **MO-1** [docs.moodle.org/501/en/Nginx](https://docs.moodle.org/501/en/Nginx): no `add_header`, `expires`, `rewrite` or 3xx `return`. It has `try_files $uri $uri/ /r.php$is_args$args;` for the router, and `return 404;` for dot files and internal paths.
  **X**: front controller `/r.php`, and refusals.
- **MO-2** [docs.moodle.org/501/en/Apache](https://docs.moodle.org/501/en/Apache): sixteen lines like `RewriteRule "(\/vendor\/)" - [L,R=404]`, and `FallbackResource /r.php`.
  **X**: `R=404` is a status, not a redirect, so these are `refuse` patterns. `FallbackResource` is the front controller.

## 10. Roundcube 1.7

- **RC-1** [public_html/.htaccess L3-L6](https://github.com/roundcube/roundcubemail/blob/1.7.4/public_html/.htaccess#L3-L6): `RewriteRule ^favicon\.ico$ static.php/skins/elastic/images/favicon.ico`.
  **X**: internal. An exact location, or an exact redirect to that address, does the same.
- **RC-2** [L19-L22](https://github.com/roundcube/roundcubemail/blob/1.7.4/public_html/.htaccess#L19-L22): `ExpiresActive On` / `ExpiresDefault "access plus 1 month"`.
  **E≈**: `default` `Cache-Control = "max-age=2592000"` at `/` with `when = "success"`. Roundcube's PHP sends its own: `no-cache` on pages ([rcube_output.php L136-L145](https://github.com/roundcube/roundcubemail/blob/1.7.4/program/lib/Roundcube/rcube_output.php#L136-L145)) and `public, max-age=604800` from `static.php` ([L159](https://github.com/roundcube/roundcubemail/blob/1.7.4/public_html/static.php#L156-L166)). With `default` only the files agensio serves itself get the month.
- **RC-3** [L24](https://github.com/roundcube/roundcubemail/blob/1.7.4/public_html/.htaccess#L24): `FileETag MTime Size`.
  **X**: agensio's ETag is already `"hex(mtime)-hex(size)"`.
- **RC-4** [L30-L32](https://github.com/roundcube/roundcubemail/blob/1.7.4/public_html/.htaccess#L30-L32): `Header set X-Robots-Tag "noindex, nofollow"`. Keeps webmail out of search engines.
  **E**: `set` at `/`. This is a live site with `noindex` on purpose (see change 7).
- **RC-5** [L35](https://github.com/roundcube/roundcubemail/blob/1.7.4/public_html/.htaccess#L34-L35): `#Header merge Cache-Control public env=!NO_CACHE`.
  **O**: an environment condition and a `merge` verb.
- **RC-6** [L41-L42](https://github.com/roundcube/roundcubemail/blob/1.7.4/public_html/.htaccess#L41-L42): `#Header always set Strict-Transport-Security "max-age=31536000; preload" env=HTTPS`.
  **E**: `hsts = true` is sent over HTTPS only. Preload is **O**.
- **RC-7** [L44-L46](https://github.com/roundcube/roundcubemail/blob/1.7.4/public_html/.htaccess#L44-L46): `#Header always set Public-Key-Pins ...`.
  **O**: a refused name (headers.md 2.5).
- **RC-8** [L48-L51](https://github.com/roundcube/roundcubemail/blob/1.7.4/public_html/.htaccess#L48-L51): `#Header set X-Frame-Options SAMEORIGIN`, with the comment "Already set by php code! Do not activate both options".
  **E**: `default` is exactly "not both".
- **RC-9** [L53-L55](https://github.com/roundcube/roundcubemail/blob/1.7.4/public_html/.htaccess#L53-L55): `#Header set X-Content-Type-Options "nosniff"`.
  **E**.
- **RC-10** [wiki Installation L104-L113](https://github.com/roundcube/roundcubemail/wiki/Installation): `rewrite "^/[a-zA-Z0-9]{16}/(.*)$" /$1;`, "required when using use_secure_urls=true".
  **X-gap**: an internal rewrite that strips a variable first segment. Roundcube works with `use_secure_urls` off, which is believed to be the default (not verified here).

## 11. FreshRSS 1.30

- **FR-1** [p/.htaccess L10](https://github.com/FreshRSS/FreshRSS/blob/1.30.1/p/.htaccess#L10): `FileETag None`.
  **O**: ETag is a representation field. Harmless to keep.
- **FR-2** [L27-L37](https://github.com/FreshRSS/FreshRSS/blob/1.30.1/p/.htaccess#L27-L37): `ExpiresActive on`, `ExpiresDefault "access plus 1 month"`, `ExpiresByType ...`, `<FilesMatch "\.php$"> ExpiresActive Off`.
  **N**: change 2, the `.php` exception. **E≈** with `default` at `/` and `when = "success"`.
- **FR-3** [L39-L47](https://github.com/FreshRSS/FreshRSS/blob/1.30.1/p/.htaccess#L39-L47): `<FilesMatch "\.(css|gif|html|ico|js|png|svg|woff|woff2)$">` `Header merge Cache-Control "public"` `<If "%{QUERY_STRING} =~ /^[0-9]+$/">` `Header merge Cache-Control "immutable"`.
  **N** (change 1). The `immutable` on a numeric query is **O**. With no `merge` verb, the whole value is `set` instead.
- **FR-4** [p/themes/.htaccess L16-L25](https://github.com/FreshRSS/FreshRSS/blob/1.30.1/p/themes/.htaccess#L16-L25): `ExpiresByType ... "access plus 1 month"`.
  **E≈**: a prefix rule on `/themes/` (`p/` is the root), `when = "success"`, `max-age=2592000`.
- **FR-5** [p/themes/.htaccess L27-L31](https://github.com/FreshRSS/FreshRSS/blob/1.30.1/p/themes/.htaccess#L27-L31): `<FilesMatch "\.svg$">` `Header set Content-Security-Policy "default-src 'self'; frame-ancestors 'none'; style-src 'self' 'unsafe-inline'"`.
  **E≈**: a `/themes/` prefix rule. A CSP has no effect on CSS, images or fonts, so it matters only for documents. Exact by ending is **N**.
- **FR-6** [docs/en/admins/Caddy.md L15](https://github.com/FreshRSS/FreshRSS/blob/1.30.1/docs/en/admins/Caddy.md#L13-L22): `redir /subfolder /subfolder/`. Adds the trailing slash to the subfolder.
  **E**: an exact rule. Caddy's `redir` default is 302.
- **FR-7** [docs/en/admins/10_ServerConfig.md L116-L121](https://github.com/FreshRSS/FreshRSS/blob/1.30.1/docs/en/admins/10_ServerConfig.md#L116-L121): "Avoid overwriting the `Content-Security-Policy` header with directives such as `more_set_headers ...` or `add_header ...`", and "Bad CSP: `upgrade-insecure-requests`".
  This is evidence for headers.md 2.3: `default` for a CSP on an application site.
- **FR-8** [Docker/FreshRSS.Apache.conf L84-L86](https://github.com/FreshRSS/FreshRSS/blob/1.30.1/Docker/FreshRSS.Apache.conf#L84-L86): `<Directory /var/www/FreshRSS/p/i>` `ExpiresActive Off`. The PHP front directory is excluded from the static lifetime.
  Evidence for change 2.

## 12. Kirby 5

- **K-1** [starterkit .htaccess L62-L64](https://github.com/getkirby/starterkit/blob/b26a7d64c684/.htaccess#L58-L67): `Header set Content-Type "text/plain" "expr=-z %{CONTENT_TYPE}"`. "serve files as plain text if the actual content type is not known".
  **X**: the type table. agensio's default type is `application/octet-stream` (`mime.cpp` L119), which a browser does not render either.
- **K-2** [starterkit .htaccess L65](https://github.com/getkirby/starterkit/blob/b26a7d64c684/.htaccess#L65) `Header set X-Content-Type-Options "nosniff"` and [nginx snippet L11](https://github.com/getkirby/getkirby.com/blob/fd8e1c5074da/site/snippets/docs/server-config/nginx.php#L10-L11) `add_header X-Content-Type-Options nosniff;`. Applies to every answer.
  **E**: `set` at `/`.
- **K-3** [nginx snippet L10](https://github.com/getkirby/getkirby.com/blob/fd8e1c5074da/site/snippets/docs/server-config/nginx.php#L10): `default_type text/plain;`.
  **X**: the type table.
- **K-4** [nginx snippet L13-L15](https://github.com/getkirby/getkirby.com/blob/fd8e1c5074da/site/snippets/docs/server-config/nginx.php#L13-L15): internal rewrites to `/error` and `/index.php`.
  **X**: refusals and front controller. The [Caddy snippet](https://github.com/getkirby/getkirby.com/blob/fd8e1c5074da/site/snippets/docs/server-config/caddy.php) adds no header; Caddy's automatic HTTPS corresponds to `http = "redirect"`.

## 13. Craft CMS 5

- **CR-1** [web/.htaccess](https://github.com/craftcms/craft/blob/a1747d5be2a3/web/.htaccess): only "Route 404s to index.php".
  **X**: front controller. Craft's documentation for 5.x gives no nginx configuration.
- **CR-2** [craftcms/docker nginx/craftcms/security.conf L2-L6](https://github.com/craftcms/docker/blob/3d27ef3a3542/nginx/craftcms/security.conf#L1-L6): `add_header X-Frame-Options "SAMEORIGIN" always;`, `add_header X-XSS-Protection "1; mode=block" always;`, `add_header X-Content-Type-Options "nosniff" always;`, `add_header Referrer-Policy "no-referrer-when-downgrade" always;`, `#add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;`. These come from the official images, which are being deprecated.
  **E**: a `/` rule. `X-XSS-Protection` is warned by `-t`, and a CSP goes in `default`.
- **CR-3** [general.conf L14-L19](https://github.com/craftcms/docker/blob/3d27ef3a3542/nginx/craftcms/general.conf#L14-L19): `location ~* \.(?:css(\.map)?|js(\.map)?|jpe?g|png|gif|ico|cur|heic|webp|tiff?|mp3|m4a|aac|ogg|midi?|wav|mp4|mov|webm|mpe?g|avi|ogv|flv|wmv|txt)$ { try_files $uri /index.php?$query_string; expires 7d; }`.
  **N** (changes 1 and 2).
- **CR-4** [general.conf L21-L27](https://github.com/craftcms/docker/blob/3d27ef3a3542/nginx/craftcms/general.conf#L21-L27): `location ~* \.(?:svgz?|ttf|ttc|otf|eot|woff2?)$ { try_files $uri /index.php?$query_string; add_header Access-Control-Allow-Origin "*"; expires 7d; }`. CORS on fonts.
  **N** (change 1).

## 14. Symfony

- **SY-1** [apache-pack public/.htaccess L41-L53](https://github.com/symfony/recipes-contrib/blob/808d08a46093/symfony/apache-pack/1.0/public/.htaccess#L41-L53): `RewriteCond %{ENV:REDIRECT_STATUS} =""` `RewriteRule ^index\.php(?:/(.*)|$) %{ENV:BASE}/$1 [R=308,L]`.
  **E**: prefix rule `/index.php` to `/`, `308` (as SW-1).
- **SY-2** [L62-L70](https://github.com/symfony/recipes-contrib/blob/808d08a46093/symfony/apache-pack/1.0/public/.htaccess#L62-L70): `RedirectMatch 307 ^/$ /index.php/`, only without mod_rewrite.
  Not needed.
- **SY-3** [web_server_configuration.rst](https://github.com/symfony/symfony-docs/blob/8964add39f4e/setup/web_server_configuration.rst): the FrankenPHP/Caddy, nginx and Apache sections have no redirect or header directive. nginx answers `return 404;` for every other `.php`.
  **X** (front controller, `rules.entry_points`).

## 15. WordPress

- **WP-1** [server/nginx.md L74-L79](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/server/nginx.md#L74-L79): `server { server_name _; return 302 $scheme://example.com$request_uri; }`, "Redirect everything to the main site".
  **E**: for the names the site lists, `canonical` (308). For any Host at all, a catch-all site (`server_name = ["*"]`) with a `from = "/"` rule, plain HTTP only, since no certificate can cover unknown names. The design's strict listener answers `421` to unknown names, which is the safer default.
- **WP-2** [nginx.md L175-L178](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/server/nginx.md#L175-L178), and the same in the [nginx wiki recipe L62-L65](https://github.com/nginxinc/nginx-wiki/blob/836ecd605a1b/source/start/topics/recipes/wordpress.rst#L62-L65) the page calls "more up-to-date": `location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ { expires max; log_not_found off; }`.
  **N** (change 1). The wordpress preset already gives `/wp-content/uploads/` 7 days and `/wp-includes/` 30 days by prefix (configuration.md 4). Themes' and plugins' assets would need endings, because `wp-content/plugins` also holds PHP endpoints. WordPress versions its assets with `?ver=`.
- **WP-3** [nginx.md L201-L203 and L284-L285](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/server/nginx.md#L201-L206) (multisite in subdirectories): `if (!-e $request_filename) { rewrite /wp-admin$ $scheme://$host$request_uri/ permanent; ... }`. [server/httpd.md L45, L101](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/server/httpd.md#L44-L45): `RewriteRule ^([_0-9a-zA-Z-]+/)?wp-admin$ $1wp-admin/ [R=301,L]`. Adds the slash to any subsite's `wp-admin`.
  **N**: the target holds the matched subsite segment. The single-segment `*` of redirects.md 5.4 (`from = "/*/wp-admin"`, `to = "/*/wp-admin/"`) would cover it. WordPress also redirects `<home>/wp-admin` to `admin_url()` by itself on a 404 ([canonical.php L1039-L1057](https://github.com/WordPress/wordpress-develop/blob/7.1.3/src/wp-includes/canonical.php#L1039-L1057)). But the subsite then also needs WP-4.
- **WP-4** [nginx.md L204-L205](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/server/nginx.md#L204-L205): `rewrite ^(/[^/]+)?(/wp-.*) $2 last;` `rewrite ^(/[^/]+)?(/.*\.php) $2 last;`. [httpd.md L50-L51](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/server/httpd.md#L50-L51) has the same.
  **X-gap**: internal rewrites that strip the subsite segment. Without them a subdirectory multisite cannot serve its subsites' `wp-admin`, `wp-includes` or scripts.
- **WP-5** [httpd.md L69](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/server/httpd.md#L69) (multisite on subdomains): `RewriteRule ^wp-admin$ wp-admin/ [R=301,L]`.
  **E**: an exact rule. agensio's own slash redirect for a real directory (`$uri/`) already does it.
- **WP-6** [nginx.md L373-L374](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/server/nginx.md#L373-L374): `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";`.
  **E**: `hsts = { subdomains = true }`.
- **WP-7** [nginx.md L272-L282](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/server/nginx.md#L272-L282) (multisite activated before 3.5): `location ~ ^(/[^/]+/)?files/(.+) { try_files ...; expires max; }`.
  **N** (change 3) and legacy.
- **WP-8** [httpd.md L275-L278](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/server/httpd.md#L275-L278), generic examples: `Header set X-Pingback "https://example.com/xmlrpc.php"`, `Header set Content-Language "en-US"`.
  **E**: `set`.
- **WP-9** [httpd.md L284-L288](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/server/httpd.md#L284-L288): `Header unset Pragma`, `Header always unset WP-Super-Cache`, `Header always unset X-Pingback`.
  **E**: `remove`.
- **WP-10** [security/https.md L102-L105](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/security/https.md#L96-L106), on the plain host: `RewriteRule ^/?(wp-admin/|wp-login\.php) https://example.com%{REQUEST_URI}%{QUERY_STRING} [R=301,QSA,L]`. [L119-L120, L146-L147](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/security/https.md#L112-L151): the secure host sends the public site back. This is HTTPS for the admin only.
  **O**: path redirects conditioned on the scheme. `http = "redirect"` for the whole site replaces them, and the page itself says they are "not 100% compatible with WordPress 2.8+". A `[[site.redirect]]` to `https://` on the same host would fire over HTTPS too and loop, which redirects.md 8 should refuse; see change 5a.
- **WP-11** [httpd.md L14-L23](https://github.com/WordPress/Advanced-administration-handbook/blob/ddc1a907faaa/server/httpd.md#L14-L23), the `.htaccess` block WordPress writes.
  **X**: front controller only. No redirect or header.

## 16. Drupal 11

- **DR-1** [htaccess L21-L23](https://github.com/drupal/drupal/blob/11.4.9/core/assets/scaffold/files/htaccess#L21-L23): `AddType image/svg+xml svg svgz` / `AddEncoding gzip svgz`.
  **X-gap** (type table, as NC-13).
- **DR-2** [L36-L52](https://github.com/drupal/drupal/blob/11.4.9/core/assets/scaffold/files/htaccess#L36-L52): `ExpiresActive On`, `ExpiresDefault "access plus 1 year"`, `<FilesMatch \.php$> ExpiresActive Off`, with the comment "Do not allow PHP scripts to be cached unless they explicitly send cache headers themselves".
  **N**: change 2, files only. **E≈** with `default` at `/`, `when = "success"`: Drupal's own answers carry `Cache-Control` (FinishResponseSubscriber), but not every Drupal answer was checked.
- **DR-3** [L92-L107](https://github.com/drupal/drupal/blob/11.4.9/core/assets/scaffold/files/htaccess#L92-L107), commented out: `# RewriteRule ^ http%{ENV:protossl}://www.%{HTTP_HOST}%{REQUEST_URI} [L,R=301]` (with www) and `# RewriteRule ^ http%{ENV:protossl}://%1%{REQUEST_URI} [L,R=301]` (without).
  **E**: `canonical`, which gives 308 and decides the scheme together with `http`.
- **DR-4** [L119-L123](https://github.com/drupal/drupal/blob/11.4.9/core/assets/scaffold/files/htaccess#L119-L123): `RewriteCond %{REQUEST_URI} ^(.*)?/(install\.php) [OR]` `RewriteCond %{REQUEST_URI} ^(.*)?/(rebuild\.php)` `RewriteCond %{REQUEST_URI} !core` `RewriteRule ^ %1/core/%2 [L,QSA,R=301]`. "Redirect common PHP files to their new locations".
  **E**: two exact rules, `/install.php` to `/core/install.php` and `/rebuild.php` to `/core/rebuild.php`, `301`. The query is kept, as with `QSA`. The `%1` prefix matters only to subdirectory installs.
- **DR-5** [L125-L126](https://github.com/drupal/drupal/blob/11.4.9/core/assets/scaffold/files/htaccess#L125-L126): `RewriteRule ^core/install\.php core/install.php?rewrite=ok [QSA,L]`.
  **X**: internal, the installer's clean-URL probe.
- **DR-6** [L148-L190](https://github.com/drupal/drupal/blob/11.4.9/core/assets/scaffold/files/htaccess#L148-L190): `.css.gz`/`.css.br`/`.js.*` selection, `[T=text/css]`, `Header set Content-Encoding gzip|br`, `Header append Vary Accept-Encoding`.
  **X**: pre-compressed twins.
- **DR-7** [L192-L205](https://github.com/drupal/drupal/blob/11.4.9/core/assets/scaffold/files/htaccess#L192-L205): `Header onsuccess unset X-Content-Type-Options` / `Header always set X-Content-Type-Options nosniff`. The comment says Drupal's FinishResponseSubscriber sets it too, and the unset prevents duplicates.
  **E**: `set` at `/`. The drupal baseline (files and errors) plus Drupal's own field on its answers gives the same result without a rule.
- **DR-8** [L204](https://github.com/drupal/drupal/blob/11.4.9/core/assets/scaffold/files/htaccess#L203-L204): `RequestHeader unset Proxy` (httpoxy).
  **X**: request side. agensio's FastCGI handler does not forward `Proxy` (`fastcgi.hpp` L41).
- **DR-9** [L90, L146](https://github.com/drupal/drupal/blob/11.4.9/core/assets/scaffold/files/htaccess#L90) `[F]`.
  **X** (the preset, `refuse`).
- **DR-10** [nginx wiki recipe L121-L125](https://github.com/nginxinc/nginx-wiki/blob/836ecd605a1b/source/start/topics/recipes/drupal.rst#L121-L125): `location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ { try_files $uri @rewrite; expires max; log_not_found off; }`.
  **N** (changes 1 and 2).
- **DR-11** [recipe L139-L144](https://github.com/nginxinc/nginx-wiki/blob/836ecd605a1b/source/start/topics/recipes/drupal.rst#L139-L144): `if ($request_uri ~* "^(.*/)index\.php/(.*)") { return 307 $1$2; }`. "Enforce clean URLs".
  **E≈**: prefix rule `/index.php` to `/`, `307`. agensio's prefix also redirects a bare `/index.php` (and `/index.php?…`), which nginx's regex leaves alone. That is harmless, because the front controller hop is internal. The regex also matches below subdirectories, which matters only to subdirectory installs.

## 17. TYPO3 14

- **T3-1** [root-htaccess L97-L165](https://github.com/TYPO3/typo3/blob/v14.3.8/typo3/sysext/install/Resources/Private/FolderStructureTemplateFiles/root-htaccess#L97-L165): `ExpiresActive On`, `ExpiresDefault "access plus 1 month"`, then `ExpiresByType text/css "access plus 1 year"`, `ExpiresByType text/html "access plus 0 seconds"`, `ExpiresByType application/javascript "access plus 1 year"`, images and fonts a month, feeds an hour, and `<FilesMatch "^index\.php$"> ExpiresActive Off`.
  **N**: changes 1 and 2, by type or ending, files only.
- **T3-2** [L245-L256](https://github.com/TYPO3/typo3/blob/v14.3.8/typo3/sysext/install/Resources/Private/FolderStructureTemplateFiles/root-htaccess#L245-L256): `<FilesMatch "\.(avifs?|bmp|cur|gif|ico|jpe?g|png|svgz?|webp)$">` `SetEnvIf Origin ":" IS_CORS` `Header set Access-Control-Allow-Origin "*" env=IS_CORS`. "Send the CORS header for images when browsers request it."
  **N** (change 1). The `Origin` condition is unnecessary: an unconditional `*` is equivalent for browsers.
- **T3-3** [L258-L263](https://github.com/TYPO3/typo3/blob/v14.3.8/typo3/sysext/install/Resources/Private/FolderStructureTemplateFiles/root-htaccess#L258-L263): `<FilesMatch "\.(eot|otf|tt[cf]|woff2?)$">` `Header set Access-Control-Allow-Origin "*"`. CORS on fonts.
  **N** (change 1), or **E≈** by prefix on `/_assets/`, `/fileadmin/` and `/typo3temp/assets/`.
- **T3-4** [L285-L295](https://github.com/TYPO3/typo3/blob/v14.3.8/typo3/sysext/install/Resources/Private/FolderStructureTemplateFiles/root-htaccess#L285-L295): `RewriteRule ^(.+)\.(\d+)\.(php|js|mjs|css|png|jpg|gif|svg|avif|webp|gz|xsl|ico)$ %{ENV:CWD}$1.$3 [L]`. The nginx doc has the same at [_nginx.conf L13-L16](https://github.com/TYPO3-Documentation/TYPO3CMS-Reference-CoreApi/blob/a8e34f3de218/Documentation/Administration/Installation/SystemRequirements/_codesnippets/_nginx.conf#L13-L16). It serves version numbers in file names, used only with `versionNumberInFilename`.
  **X-gap**: an internal rewrite with captures. TYPO3 works with the setting off; its default was not verified here.
- **T3-5** [L344-L346](https://github.com/TYPO3/typo3/blob/v14.3.8/typo3/sysext/install/Resources/Private/FolderStructureTemplateFiles/root-htaccess#L344-L346): `RedirectMatch 404 /\.(?:git|svn|hg)/`.
  **X**: hidden files.
- **T3-6** [L362-L367](https://github.com/TYPO3/typo3/blob/v14.3.8/typo3/sysext/install/Resources/Private/FolderStructureTemplateFiles/root-htaccess#L362-L367): `Header set X-UA-Compatible "IE=edge"` plus `<FilesMatch ...> Header unset X-UA-Compatible`.
  **E≈**, obsolete (as M2-1).
- **T3-7** [L369-L370](https://github.com/TYPO3/typo3/blob/v14.3.8/typo3/sysext/install/Resources/Private/FolderStructureTemplateFiles/root-htaccess#L369-L370): `Header set X-Content-Type-Options "nosniff"`. "Reducing MIME type security risks".
  **E**: `set` at `/`. Under Apache it reaches the frontend's PHP answers too, and TYPO3's frontend sends none itself.
- **T3-8** [L374-L377](https://github.com/TYPO3/typo3/blob/v14.3.8/typo3/sysext/install/Resources/Private/FolderStructureTemplateFiles/root-htaccess#L374-L377): `Header unset ETag` / `FileETag None`.
  **O**: a representation field.
- **T3-9** [fileadmin/.htaccess L5-L17](https://github.com/TYPO3/typo3/blob/v14.3.8/typo3/sysext/install/Resources/Private/FolderStructureTemplateFiles/resources-root-htaccess#L5-L17):
  - `<FilesMatch "\.pdf$">` `Header set Content-Security-Policy "default-src 'self' 'unsafe-inline'; script-src 'none'; object-src 'self'; plugin-types application/pdf;"`
  - `<FilesMatch "\.svg">` `Header set Content-Security-Policy "default-src 'self'; script-src 'none'; style-src 'unsafe-inline'; object-src 'none'; sandbox;"`
  - `<FilesMatch "(?<!\.(?:pdf|svg))$">` `Header set Content-Security-Policy "default-src 'self'; script-src 'none'; style-src 'none'; object-src 'none'; sandbox;"`

  This is CSP for user uploads. Its comments (L19-L34) offer `Header setifempty` instead, which is agensio's `default`.
  The "everything else" value is **E**: a `/fileadmin/` rule. The PDF and SVG variants are **N**: an ending rule more specific than the prefix (changes 1 and 1a).
- **T3-10** [_nginx.conf L1-L11](https://github.com/TYPO3-Documentation/TYPO3CMS-Reference-CoreApi/blob/a8e34f3de218/Documentation/Administration/Installation/SystemRequirements/_codesnippets/_nginx.conf#L1-L11): `location ~ \.js\.gzip$ { add_header Content-Encoding gzip; gzip off; types { text/javascript gzip; } }`, and the same for `.css.gzip`.
  **X-gap**: `Content-Encoding` belongs to the type table and the twins. TYPO3 writes `name.gzip` and links it directly, while agensio's twins are `name.gz` chosen by `Accept-Encoding`. TYPO3 works with its compression off (`compressionLevel` 0; the default was not verified here).
- **T3-11** [_nginx.conf L39-L46](https://github.com/TYPO3-Documentation/TYPO3CMS-Reference-CoreApi/blob/a8e34f3de218/Documentation/Administration/Installation/SystemRequirements/_codesnippets/_nginx.conf#L39-L46): `location = /typo3 { rewrite ^ /typo3/; }`, `location /typo3/ { absolute_redirect off; try_files $uri /index.php$is_args$args; }`.
  **X**: agensio's directory slash redirect, and `front_controller` (configuration.md 15 names `/typo3/`).
- **T3-12** [Security _nginx.config L40-L52](https://github.com/TYPO3-Documentation/TYPO3CMS-Reference-CoreApi/blob/a8e34f3de218/Documentation/Security/GuidelinesAdministrators/_codesnippets/_nginx.config#L40-L52): `location ~ /(?:fileadmin|uploads)/.*\.pdf$ { add_header Content-Security-Policy "..."; }` and `location ~ /(?:fileadmin|uploads)/.*(?<!\.pdf)$ { add_header Content-Security-Policy "..."; try_files $uri$webp_suffix $uri =404; }`, with `map $http_accept $webp_suffix` (L1-L5).
  The CSP is as T3-9. The WebP choice by `Accept` is **X-gap**: agensio chooses variants by `Accept-Encoding` only. The documented config also sends no `Vary: Accept`.
- **T3-13** [ContentSecurityPolicy.rst L44-L73](https://github.com/TYPO3-Documentation/TYPO3CMS-Reference-CoreApi/blob/a8e34f3de218/Documentation/Security/GuidelinesAdministrators/ContentSecurityPolicy.rst#L44-L73): Apache `Header set Content-Security-Policy "default-src 'self'; script-src 'none'; style-src 'none'; object-src 'none';"` in `fileadmin/.htaccess`. For nginx it uses a `map $request_uri $csp_header { ~^/fileadmin/ "..." }` and a server-level `add_header`, because "top level `add_header` declarations will be overwritten if `add_header` is used in sublevels".
  **E**: a `/fileadmin/` rule. The documentation's workaround is the trap headers.md 2.2 removes.

```toml
[[site.response_headers]]            # T3-7: as the shipped .htaccess does under Apache
path = "/"
set = { "X-Content-Type-Options" = "nosniff" }

[[site.response_headers]]            # T3-9 / T3-13, the value for files other than PDF and SVG
path = "/fileadmin/"
default = { "Content-Security-Policy" = "default-src 'self'; script-src 'none'; style-src 'none'; object-src 'none'; sandbox;" }
```

## 18. Grav 2.2

- **G-1** [nginx.conf L69-L73](https://github.com/getgrav/grav/blob/2.2.6/webserver-configs/nginx.conf#L63-L73): `location ~* /_app/immutable/.*\.(js|css|woff2?)$ { try_files $uri =404; access_log off; add_header Cache-Control "public, max-age=31536000, immutable" always; }`. [htaccess.txt L110-L112](https://github.com/getgrav/grav/blob/2.2.6/webserver-configs/htaccess.txt#L110-L112): `Header set Cache-Control "public, max-age=31536000, immutable" "expr=%{REQUEST_URI} =~ m#/_app/immutable/#"`. [Caddyfile L80, L97-L101](https://github.com/getgrav/grav/blob/2.2.6/webserver-configs/Caddyfile#L97-L101): `@immutable path_regexp (?i)/_app/immutable/` and `header @immutable Cache-Control "..."`. These are content-hashed bundles of SvelteKit plugins, at any depth.
  **N**: a segment pair at any depth (`**/_app/immutable/`, the `refuse` pattern syntax; change 3). In nginx, `always` also gives the `=404` of a missing chunk a year of `immutable`, which is the case `when = "success"` exists for (headers.md 2.4). The Caddyfile's comment says it runs after `try_files` "so a missing chunk has been rewritten to index.php by now and Grav's 404 doesn't match".
- **G-2** [nginx.conf L75-L87](https://github.com/getgrav/grav/blob/2.2.6/webserver-configs/nginx.conf#L75-L87): `location ~* \.(jpe?g|png|gif|webp|avif|bmp|ico|svg|mp4|webm|ogg|ogv|mov|mp3|wav|m4a|flac|css|js|woff2?|ttf|otf|eot)$ { try_files $uri $uri/ /index.php?$query_string; expires 30d; }`.
  **N** (change 1). The comment notes that some media comes from `index.php`, where a 30-day lifetime is also fine.
- **G-3** [htaccess.txt L31-L42](https://github.com/getgrav/grav/blob/2.2.6/webserver-configs/htaccess.txt#L28-L42): Twig and exploit query filters, then `RewriteRule .* index.php [F]`.
  **X-gap**: a refusal by query (as J-4).
- **G-4** [htaccess.txt L60-L98](https://github.com/getgrav/grav/blob/2.2.6/webserver-configs/htaccess.txt#L60-L98): `[F]` lines.
  **X**: the grav preset.
- The Caddyfile relies on Caddy's automatic HTTPS (its L1-L2 comment), which is `http = "redirect"`.

## 19. Kanboard 1.2

- **KB-1** [.htaccess L24-L29](https://github.com/kanboard/kanboard/blob/v1.2.54/.htaccess#L24-L29), commented out: `# RewriteCond %{HTTPS} !=on` / `# RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R,L]`. "force HTTPS".
  **E**: `http = "redirect"`, which answers 308 where `[R]` gives 302.
- **KB-2** [docker/etc/nginx/nginx.conf L83-L87](https://github.com/kanboard/kanboard/blob/v1.2.54/docker/etc/nginx/nginx.conf#L83-L87), the official image: `location ~* ^.+\.(ico|jpg|gif|png|css|js|svg|eot|ttf|woff|woff2|otf)$ { log_not_found off; expires 7d; etag on; }`.
  **N** (change 1), or **E≈** with a prefix rule on `/assets/`, where nothing runs (`rules.cache` does this on a managed site).
- The [URL rewriting page](https://docs.kanboard.org/v1/admin/url-rewriting/) has no redirect or header (front controller only).

## 20. Laravel 13

- **LV-1** [deployment.md L65-L66](https://github.com/laravel/docs/blob/d8eb65fb70ae/deployment.md#L58-L95): `add_header X-Frame-Options "SAMEORIGIN";` / `add_header X-Content-Type-Options "nosniff";` at server level, without `always`. They reach the PHP answers too: `location ~ ^/index\.php(/|$)` has no `add_header` of its own, so it inherits them.
  **E**: a `/` rule. Laravel's own documented server sends both on every answer the application gives, which is more than the laravel baseline of headers.md 4.2 (see change 8).
- **LV-2** [L79](https://github.com/laravel/docs/blob/d8eb65fb70ae/deployment.md#L79): `error_page 404 /index.php;`.
  **X**.
- **LV-3** [L88](https://github.com/laravel/docs/blob/d8eb65fb70ae/deployment.md#L88): `fastcgi_hide_header X-Powered-By;`.
  **E**: the baseline.
- **LV-4** [public/.htaccess L16-L19](https://github.com/laravel/laravel/blob/f4000aeb018f/public/.htaccess#L16-L19): `# Redirect Trailing Slashes If Not A Folder...` `RewriteCond %{REQUEST_FILENAME} !-d` `RewriteCond %{REQUEST_URI} (.+)/$` `RewriteRule ^ %1 [L,R=301]`.
  **O**: a site-wide trailing slash policy (redirects.md 5.4). Laravel matches `/x/` as `/x` ([UriValidator.php L19](https://github.com/laravel/framework/blob/13.x/src/Illuminate/Routing/Matching/UriValidator.php#L19), `rtrim($request->getPathInfo(), '/')`, read in the earlier session's framework 13 sources), so the application works, with two addresses per page. The documented nginx config has no equivalent either.

```toml
[[site.response_headers]]            # LV-1
path = "/"
set = { "X-Frame-Options" = "SAMEORIGIN", "X-Content-Type-Options" = "nosniff" }
```

## 21. Statamic 6

- **ST-1** [public/.htaccess](https://github.com/statamic/statamic/blob/83d1acda7919/public/.htaccess#L16-L19) is byte-identical to Laravel's.
  **O**, as LV-4. Statamic's URL helper trims trailing slashes unless `enforceTrailingSlashes()` is used (`statamic6/src/Facades/Endpoint/URL.php`, earlier session).
- **ST-2** [static-caching.md L140-L209](https://github.com/statamic/docs/blob/65ec7a039fbd/content/collections/pages/static-caching.md#L140-L209), "full measure" caching:
  - Apache: `RewriteRule .* static/%{REQUEST_URI}_%{QUERY_STRING}\.html [L,T=text/html]`
  - nginx: `if ($request_method != GET) { set $try_location @not_static; }`, `if ($args ~* "live-preview=(.*)") {...}`, `location @static { try_files /static${uri}_$args.html $uri $uri/ /index.php?$args; }`

  **X-gap**: `try_files` with the query in a file name, and conditions on method and query. Not a redirect or header. Statamic's "half measure" caching needs no server rules.
- **ST-3**: Statamic sends `X-Powered-By: Statamic` (`research_notes/App default security headers/notes.md`).
  **E**: removed by the baseline.

## 22. Cross-cutting findings

1. **Redirects whose target depends on the matched path in a way a prefix cannot express.** Only
   three applications have them:
   - WordPress multisite in subdirectories (WP-3), which is useless without the internal rewrites
     of WP-4.
   - phpMyAdmin's optional, partly stale pretty URLs (PMA-1).
   - Magento's query-conditioned self-redirect (M2-8), which is obsolete.

   Every other redirect is exact (MW-5, NC-6, DR-4, PS-6, FR-6, WP-5) or a whole-segment prefix
   that keeps the remainder (NC-8, SW-1, SY-1, DR-11). The evidence supports the design's choice
   of no regex and no captures.
2. **The `/index.php` removal redirect** appears three times (Shopware 301, Symfony 308, Drupal's
   nginx recipe 307). A prefix rule expresses it. Apache's `REDIRECT_STATUS` guard is agensio's
   rule that a redirect matches only the client's path.
3. **Headers by file type.** Every header that most applications attach to a file type is a
   cache lifetime or a security field on files served from disk. 14 of the 21 applications do it.
   The security ones:
   - CSP on SVG and PDF: Shopware, Joomla, FreshRSS, MediaWiki, TYPO3.
   - CORS on fonts and images: PrestaShop, TYPO3, Craft.
   - `no-store` on archives and preview containers: Magento, Matomo.

   nginx samples bind those fields to a location that serves files and falls back to PHP. Caddy
   uses the `file` matcher, and Apache configurations switch them off for `.php` (Drupal, TYPO3,
   PrestaShop, FreshRSS). So the condition is "this ending, and the answer is a file on disk", not
   the ending alone (changes 1 and 2).
4. **`.well-known`.** agensio's visible `/.well-known/` and front controller cover Nextcloud's
   internal handling. Its 301s for CalDAV and CardDAV are exact rules. A prefix redirect over
   `/.well-known` is dangerous: agensio answers ACME challenges ahead of the rules only for its own
   ACME manager's tokens (`dispatch.cpp` L469-L480). redirects.md 1 says "no setting here can break
   a certificate's issue or renewal", and that is true only for `tls = "auto"` (change 5).
5. **Trailing slashes.** They come in two kinds:
   - Site-wide removal: Laravel and Statamic's `.htaccess`. Not offered (5.4), and the applications
     work without it.
   - Additions on one exact path: PrestaShop `/fr`, multishop `/shop2`, FreshRSS `/subfolder`,
     WordPress `/wp-admin`. These are exact rules.
   - The one with a variable segment is WordPress multisite (WP-3).
6. **HTTPS and www.** Every one is either an HTTP-to-HTTPS redirect keeping the host (NC-1, MT-1,
   KB-1, Grav and Kirby through Caddy) or a commented-out www choice (Drupal DR-3, Joomla J-7).
   `http` and `canonical` cover them. WordPress's half-HTTPS rules (WP-10) are the only scheme
   conditions, and they are obsolete.
7. **Headers that must also reach error pages.** Some configurations ask for every answer
   explicitly:
   - nginx `always`: Nextcloud, Matomo, Craft.
   - Apache `Header always`: Nextcloud, Drupal, Joomla.

   agensio's default `when = "always"` and its single point of application cover them. The one
   `always` on a cache lifetime (Grav G-1) is the bug `when = "success"` prevents.
8. **X-Robots-Tag `noindex`** is sent on purpose on live sites by Nextcloud (NC-3), Roundcube
   (RC-4) and phpMyAdmin (its own PHP). The planned health finding "`noindex` on a site that looks
   live" (headers.md 7) would fire on all three (change 7).
9. **CORS on fonts.** PrestaShop, TYPO3 and Craft send `Access-Control-Allow-Origin: *` by ending
   only. A fixed `*` is what headers.md 3.3 allows. With prefix rules it is E≈, and exact with
   endings.
10. **Fields the application already sends.** Several configurations collide with the
    application's own fields:
    - Nextcloud: passes `modHeadersAvailable` so its PHP stays silent.
    - Drupal: unsets the `onsuccess` copy.
    - Roundcube: "Already set by php code! Do not activate both options".
    - Matomo: two `Referrer-Policy` fields under nginx.
    - Magento: the server's and PHP's `X-Frame-Options`.
    - FreshRSS: "Avoid overwriting the Content-Security-Policy header".

    `set` (one copy) and `default` (the application wins) cover every case.
11. **`nosniff` and frame fields on application answers in the vendors' own configurations.**
    - `nosniff` on every answer, PHP included: Laravel (nginx doc), Drupal, TYPO3 and Joomla
      (`.htaccess`; Apache applies `.htaccess` headers to PHP answers, as Drupal's and Nextcloud's
      own comments about the `onsuccess` table show), Kirby, Nextcloud, Matomo, Craft. That is 8
      applications.
    - `X-Frame-Options` on every answer: Laravel and Craft (`SAMEORIGIN`), Shopware's Caddy
      (`DENY`), Magento, Nextcloud.

    This bears on headers.md 4.1, where the baseline leaves both off application answers (change 8).
12. **Fields the designs refuse, and that the applications use:**
    - `ETag` removal: TYPO3, PrestaShop, FreshRSS.
    - `Set-Cookie`: PrestaShop, commented out and wrong.
    - `Public-Key-Pins`: Roundcube, commented out.
    - `Content-Encoding` and `Content-Type`: Drupal, Joomla and TYPO3 for compressed assets; Kirby
      and Matomo for text/plain defaults.

    None is needed for the application to work. The compressed-asset cases are covered by the
    twins, except TYPO3's `.gzip` naming and `.svgz` (change 9).
13. **HSTS preload** appears only commented out or as an option: Nextcloud, PrestaShop, Roundcube,
    and Joomla's plugin. Each of them warns about it. Not offering it (4.6) costs nothing.

## 23. Summary table

Classes: E, E≈, N (change number), O, X, X-gap. One row per directive or directive group above.

| app | id | directive (short) | class |
|---|---|---|---|
| Nextcloud | NC-1 | `return 301 https://$server_name$request_uri` | E (`http`) |
| Nextcloud | NC-2 | HSTS includeSubDomains preload (commented) | E (`hsts`); preload O |
| Nextcloud | NC-3 | five security fields `always` | E (`/` `default`) |
| Nextcloud | NC-4 | `fastcgi_hide_header X-Powered-By` | E (baseline) |
| Nextcloud | NC-5 | DavClnt user agent → 302 `/remote.php/webdav/` | O |
| Nextcloud | NC-6 | `.well-known/caldav`, `carddav` → 301 | E (exact) |
| Nextcloud | NC-7 | other `.well-known` → `/index.php` (nginx 301, Apache internal) | X (front controller); as a redirect N (5) |
| Nextcloud | NC-8 | `/remote` → `/remote.php$request_uri` | E (prefix) |
| Nextcloud | NC-9 | Cache-Control on asset endings, `immutable` if `?v=` | N (1, 2); query part O |
| Nextcloud | NC-10 | fonts `expires 7d` | N (1) |
| Nextcloud | NC-11 | `onsuccess unset` + `always set` pairs | E (`set`) |
| Nextcloud | NC-12 | `Referrer-Policy` same-origin on `/login` | E (exact rules) |
| Nextcloud | NC-13 | `AddEncoding gzip svgz` | X-gap (9) |
| Nextcloud | NC-14 | `server_tokens off` | X (`server_header`) |
| Matomo | MT-1 | 301 to https | E |
| Matomo | MT-2 | HSTS 6 months (commented) | E |
| Matomo | MT-3 | `Referrer-Policy origin` | E (`set`) |
| Matomo | MT-4 | `nosniff` | E |
| Matomo | MT-5 | `X-XSS-Protection "1; mode=block"` | E (warned) |
| Matomo | MT-6 | `container_*_preview.js` no-store | N (3) |
| Matomo | MT-7 | asset endings 1 h, `Pragma public` | N (1) |
| Matomo | MT-8 | `default_type text/plain` for .md | X (type table) |
| MediaWiki | MW-1 | `/w/images` nosniff; `types` text/plain | E; types X-gap |
| MediaWiki | MW-2 | `/w/resources/(assets\|lib\|src)` 7 d | E (prefixes) |
| MediaWiki | MW-3 | skins/extensions by ending 7 d | N (1) / E≈ |
| MediaWiki | MW-4 | `/favicon.ico` 7 d | E (exact) |
| MediaWiki | MW-5 | `/` → 301 `/wiki/Main_Page` | E (exact) |
| MediaWiki | MW-6 | images CSP sandbox, PDF variant | E; PDF N (1, 1a) |
| MediaWiki | MW-7 | `/wiki/` → `/w/index.php` | X (try_files) |
| MediaWiki | MW-8 | `location / { return 404; }` | X (deny) |
| phpMyAdmin | PMA-1 | pretty URLs `[R]` with captures to query | O |
| phpMyAdmin | PMA-2 | Traefik trailing-slash regex | O |
| phpMyAdmin | PMA-3 | user-agent `[F]` | X |
| Magento | M2-1 | `X-UA-Compatible`, unset by ending | E≈ |
| Magento | M2-2 | `X-Frame-Options SAMEORIGIN` everywhere | E (`/` `default`) |
| Magento | M2-3 | `/static/` year immutable by ending | N (1) / E≈ prefix |
| Magento | M2-4 | archives `no-store` | N (1) |
| Magento | M2-5 | `/media/` year by ending | N (1) / E≈ |
| Magento | M2-6 | `ExpiresByType` lists | N (1) |
| Magento | M2-7 | pub `ExpiresDefault` (inactive) | n/a |
| Magento | M2-8 | moxieplayer.swf query → self 301 | O |
| Magento | M2-9 | TRACE/TRACK `R=405` | X (built in) |
| Magento | M2-10 | `/static/version\d*/` strip; static.php `?resource=` | X-gap |
| Magento | M2-11 | `error_page` / `ErrorDocument` | X |
| Magento | M2-12 | root → `/pub/` | X (`root`) |
| PrestaShop | PS-1 | HSTS 2 y preload (commented, malformed) | E; preload O |
| PrestaShop | PS-2..4 | XSS, XFO, nosniff (commented) | E |
| PrestaShop | PS-5 | `add_header Set-Cookie` (commented) | O |
| PrestaShop | PS-6 | `/fr` → `/fr/` 302 (commented) | E (exact) |
| PrestaShop | PS-7 | language strip rewrites (commented) | X-gap |
| PrestaShop | PS-8 | friendly image URLs, `/api/` rewrites | X-gap |
| PrestaShop | PS-9 | `error_page 404` | X |
| PrestaShop | PS-10 | multishop `^shop2$` → `/shop2/` `[R]`; strip | E; strip X-gap |
| PrestaShop | PS-11 | fonts and SVG `Access-Control-Allow-Origin *` | N (1) / E≈ |
| PrestaShop | PS-12 | "Apache optimization" `ExpiresByType` | N (1) |
| PrestaShop | PS-13 | `Header unset Etag`, `FileETag none` | O |
| PrestaShop | PS-14 | nginx endings `expires 1M` | N (1) |
| PrestaShop | PS-15 | httpd endings Cache-Control; `.php` expires off | N (1, 2) |
| Shopware | SW-1 | `^index\.php(/…)` → 301 `/…` | E (prefix) |
| Shopware | SW-2 | `RedirectMatch 302 ^/$ /index.php/` (no rewrite) | n/a |
| Shopware | SW-3 | SVG `script-src 'none'` (Apache, nginx, Caddy `file`) | N (1, 2) |
| Shopware | SW-4 | asset directories year | E (prefixes) |
| Shopware | SW-5 | endings year with PHP fallback | N (1, 2) |
| Shopware | SW-6 | Caddy `X-Frame-Options DENY`, Referrer-Policy | E |
| Shopware | SW-7 | `RedirectMatch 404` | X (refuse) |
| Joomla | J-1 | `Header always set X-Content-Type-Options nosniff` | E |
| Joomla | J-2 | CORP, COEP (commented) | E |
| Joomla | J-3 | SVG CSP `script-src 'none'` | N (1) |
| Joomla | J-4 | query exploit filter `[F]` | X-gap |
| Joomla | J-5 | `RedirectMatch 302 ^/$ /index.php/` (no rewrite) | n/a |
| Joomla | J-6 | `.css.gz`/`.js.gz` Content-Encoding | X (twins) |
| Joomla | J-7 | www placeholder | E (`canonical`) |
| Joomla | J-8 | nginx doc nosniff; endings 1 y / 14 d | E; N (1) |
| Moodle | MO-1 | nginx: r.php, `return 404` | X |
| Moodle | MO-2 | Apache `[L,R=404]`, `FallbackResource /r.php` | X |
| Roundcube | RC-1 | favicon → static.php | X |
| Roundcube | RC-2 | `ExpiresDefault` 1 month | E≈ (`default`) |
| Roundcube | RC-3 | `FileETag MTime Size` | X (already agensio's) |
| Roundcube | RC-4 | `X-Robots-Tag noindex, nofollow` | E |
| Roundcube | RC-5 | Cache-Control merge `env=!NO_CACHE` (commented) | O |
| Roundcube | RC-6 | HSTS preload `env=HTTPS` (commented) | E; preload O |
| Roundcube | RC-7 | HPKP (commented) | O |
| Roundcube | RC-8, RC-9 | XFO ("set by php"), nosniff (commented) | E |
| Roundcube | RC-10 | secure-URL token strip | X-gap |
| FreshRSS | FR-1 | `FileETag None` | O |
| FreshRSS | FR-2 | `ExpiresDefault` 1 month, `.php` off | N (2) / E≈ |
| FreshRSS | FR-3 | endings `public`, `immutable` on numeric query | N (1); query O |
| FreshRSS | FR-4 | themes `ExpiresByType` | E≈ (prefix) |
| FreshRSS | FR-5 | themes SVG CSP | E≈ / N (1) |
| FreshRSS | FR-6 | Caddy `redir /subfolder /subfolder/` | E (exact) |
| FreshRSS | FR-7 | "do not overwrite the CSP" | supports `default` |
| FreshRSS | FR-8 | Docker `/p/i` `ExpiresActive Off` | evidence for 2 |
| Kirby | K-1 | Content-Type text/plain if unknown | X (type table) |
| Kirby | K-2 | `nosniff` (Apache, nginx) | E |
| Kirby | K-3 | `default_type text/plain` | X |
| Kirby | K-4 | internal rewrites to `/error`, `/index.php` | X |
| Craft | CR-1 | web/.htaccess front controller | X |
| Craft | CR-2 | XFO, XSS, nosniff, Referrer-Policy `always`; CSP (commented) | E |
| Craft | CR-3 | asset endings `expires 7d` | N (1, 2) |
| Craft | CR-4 | fonts and SVG `Access-Control-Allow-Origin *` | N (1) |
| Symfony | SY-1 | `^index\.php(/…)` → 308 | E (prefix) |
| Symfony | SY-2 | `RedirectMatch 307 ^/$ /index.php/` (no rewrite) | n/a |
| Symfony | SY-3 | docs: no redirect or header | X |
| WordPress | WP-1 | `server_name _` → 302 main site | E (`canonical`; catch-all site) |
| WordPress | WP-2 | `expires max` on asset endings | N (1) |
| WordPress | WP-3 | multisite `/<site>/wp-admin` → add slash | N (single `*` capture) |
| WordPress | WP-4 | multisite internal strip rewrites | X-gap |
| WordPress | WP-5 | `^wp-admin$` → `wp-admin/` | E |
| WordPress | WP-6 | HSTS includeSubDomains | E |
| WordPress | WP-7 | ≤3.4 multisite `files/` `expires max` | N (3), legacy |
| WordPress | WP-8 | `Header set X-Pingback`, `Content-Language` | E |
| WordPress | WP-9 | `Header unset Pragma`, `WP-Super-Cache`, `X-Pingback` | E (`remove`) |
| WordPress | WP-10 | admin-only HTTPS by scheme | O |
| WordPress | WP-11 | core `.htaccess` block | X |
| Drupal | DR-1 | `AddEncoding gzip svgz` | X-gap (9) |
| Drupal | DR-2 | `ExpiresDefault` 1 year, `.php` off | N (2) / E≈ |
| Drupal | DR-3 | www / non-www (commented) | E (`canonical`) |
| Drupal | DR-4 | `install.php`, `rebuild.php` → `/core/` 301 | E (exact) |
| Drupal | DR-5 | `install.php?rewrite=ok` | X |
| Drupal | DR-6 | `.css.gz`/`.br` Content-Encoding | X (twins) |
| Drupal | DR-7 | `onsuccess unset` + `always set nosniff` | E |
| Drupal | DR-8 | `RequestHeader unset Proxy` | X (FastCGI already) |
| Drupal | DR-9 | `[F]` | X |
| Drupal | DR-10 | nginx recipe endings `expires max` | N (1, 2) |
| Drupal | DR-11 | nginx recipe `index.php/` → 307 | E≈ (prefix) |
| TYPO3 | T3-1 | `ExpiresByType` list, `index.php` off | N (1, 2) |
| TYPO3 | T3-2 | images ACAO `*` if `Origin` | N (1); condition not needed |
| TYPO3 | T3-3 | fonts ACAO `*` | N (1) / E≈ |
| TYPO3 | T3-4 | versioned file names rewrite | X-gap |
| TYPO3 | T3-5 | `RedirectMatch 404` VCS dirs | X |
| TYPO3 | T3-6 | `X-UA-Compatible` | E≈ |
| TYPO3 | T3-7 | `nosniff` | E |
| TYPO3 | T3-8 | `Header unset ETag`, `FileETag None` | O |
| TYPO3 | T3-9 | fileadmin CSP: PDF, SVG, other | E (other); N (1, 1a) |
| TYPO3 | T3-10 | `.js.gzip`/`.css.gzip` Content-Encoding | X-gap (9) |
| TYPO3 | T3-11 | `/typo3` → `/typo3/`, `absolute_redirect off` | X |
| TYPO3 | T3-12 | security doc CSP by PDF; WebP by Accept | N (1); WebP X-gap |
| TYPO3 | T3-13 | fileadmin CSP (Apache, nginx map) | E |
| Grav | G-1 | `/_app/immutable/` year (any depth) | N (3) |
| Grav | G-2 | media endings 30 d | N (1) |
| Grav | G-3 | query filter `[F]` | X-gap |
| Grav | G-4 | `[F]` | X (preset) |
| Kanboard | KB-1 | force HTTPS `[R]` (commented) | E |
| Kanboard | KB-2 | Docker endings `expires 7d` | N (1) / E≈ |
| Laravel | LV-1 | XFO SAMEORIGIN, nosniff | E |
| Laravel | LV-2 | `error_page 404 /index.php` | X |
| Laravel | LV-3 | `fastcgi_hide_header X-Powered-By` | E (baseline) |
| Laravel | LV-4 | remove trailing slash 301 | O |
| Statamic | ST-1 | remove trailing slash 301 | O |
| Statamic | ST-2 | full-measure static cache rewrites | X-gap |
| Statamic | ST-3 | `X-Powered-By: Statamic` | E (baseline) |

Totals over the 151 rows of the 21 applications: E 52, E≈ 14, N 37, O 18, X 30, X-gap 15, n/a 4,
and 2 rows of evidence only (FR-7, FR-8). A row can carry two marks (for example "N (1) / E≈"), so
the totals overlap. The counts were made by script from this table.

## 24. Design changes the evidence supports

Ordered by how many applications need each.

1. **A file-ending condition for `[[site.response_headers]]`.** 14 applications use one: Nextcloud,
   Matomo, MediaWiki, Magento, PrestaShop, Shopware, Joomla, Craft, WordPress, Drupal, TYPO3, Grav,
   Kanboard and FreshRSS. For 9 of them it carries a security field rather than a lifetime:
   - SVG and PDF CSP: Shopware, Joomla, FreshRSS, MediaWiki, TYPO3.
   - CORS on fonts and images: PrestaShop, TYPO3, Craft.
   - `no-store`: Magento, Matomo.

   Smallest change: an optional `endings = [".css", ".js", ...]` on a rule, which narrows the rule
   to paths ending so (case-insensitive, like `deny_suffixes`). Path and per-field resolution stay
   as they are.
   - **1a. A precedence for endings.** MediaWiki (MW-6) and TYPO3 (T3-9) set a directory-wide CSP
     and a different one for `*.pdf` (and `*.svg`) in the same directory. For one field, at the
     same `path`, a rule with `endings` must beat one without, and then the longest path decides as
     now. These two applications need it.
2. **"Only on files agensio serves" as a condition.** Five applications state it explicitly:
   - Drupal, TYPO3, PrestaShop and FreshRSS turn `mod_expires` off for `.php`.
   - Shopware's Caddy uses the `file` matcher.

   Every nginx translation in change 1 needs it implicitly (Nextcloud, Shopware, Craft, Grav,
   Drupal's recipe), because there the field never follows the `try_files` fallback to PHP.
   Without it, a suffix rule would give PHP-made `.xml`, `.html` or image answers a year of
   caching. Smallest change: a third `when` value, `"files"` (2xx and 304 answers that agensio
   served from a file). The writer already makes that distinction for the baseline's `nosniff`
   (headers.md 4.1, 9). The alternative is to keep using location `add_headers` for these cases,
   which already applies only to the location's own successful answers.
3. **The `refuse` pattern syntax (`*` within a segment, one `**`) in a rule's `path`.** Two current
   applications need it: Grav's `**/_app/immutable/` and Matomo's `/js/container_*_preview.js`.
   WordPress multisite before 3.5 (WP-7) is legacy. If change 1 were written as patterns (`*.svg`)
   instead of `endings`, this one mechanism would cover changes 1 and 3. Precedence then needs a
   rule: exact, then pattern, then prefix, with the longest literal part first.
4. **Redirect captures: no change.** One application has a real case, WordPress multisite in
   subdirectories (WP-3), and it cannot run without internal rewrites that agensio lacks (WP-4).
   WordPress also issues that redirect itself (`wp_redirect_admin_locations`). phpMyAdmin's case is
   optional and stale. The single-segment `*` of redirects.md 5.4 should wait for a case that works
   without rewrites.
5. **Keep certificate validation paths out of path redirects.** One application (Nextcloud) is
   affected if its nginx sample is copied literally. The design's promise in redirects.md 1 holds
   only for agensio's own ACME (`dispatch.cpp` L469-L480). Smallest change: a `[[site.redirect]]`
   never covers `/.well-known/acme-challenge/` (and `/.well-known/pki-validation/`), and `-t`
   refuses or warns about a `from` that is a prefix of them.
   - **5a.** A rule on a site whose `to` is an absolute `https://` URL of the same host and lies
     under its own `from` loops over HTTPS (WP-10 copied). The loop check of redirects.md 8 should
     compare absolute same-host targets as paths.
6. **The `/index.php` prefix redirect: no change, a recipe.** Shopware, Symfony and Drupal's nginx
   recipe use it (3 applications), and a prefix rule expresses it. A cookbook recipe and the
   agent's texts should say so: the front controller hop is internal and never redirected.
7. **Do not flag the applications that send `noindex` on purpose.** Three applications send
   `X-Robots-Tag: noindex` on live sites: Nextcloud, Roundcube and phpMyAdmin. The planned health
   finding of headers.md 7 needs an exception before it is built. Either it skips rules that copy
   the application's own documented value, or it is raised only for `noindex` set by a rule on a
   site whose own answers do not carry it.
8. **Evidence for the baseline decision (no change requested).** The vendors' own configurations
   do more than the baseline:
   - 8 applications send `nosniff` on application answers: Laravel, Drupal, TYPO3, Joomla, Kirby,
     Nextcloud, Matomo, Craft.
   - 5 send `X-Frame-Options` on them: Laravel, Craft, Magento, Nextcloud, Shopware's Caddy
     document.

   For the `laravel` and `drupal` presets and TYPO3 under `php`, adding `nosniff` to application
   answers would match what the vendor already documents. For `laravel`, the same holds for
   `X-Frame-Options: SAMEORIGIN`. The breakage reports behind headers.md 4.1 include Joomla, whose
   own `htaccess.txt` sends `nosniff` on every answer. The owner may want to weigh that. WordPress's
   handbook sends neither.
9. **Type table: `Content-Encoding` for compound endings (not a header rule).**
   - `.svgz`: Nextcloud, Drupal and TYPO3 declare `AddEncoding gzip svgz` (3 applications). agensio
     sends `.svgz` as `image/svg+xml` with no encoding (`mime.cpp` L69), as nginx does.
   - TYPO3's `.js.gzip` and `.css.gzip` (1 application).

   Smallest change: a type-table entry may carry a `Content-Encoding`, with `svgz` having
   `image/svg+xml` plus `gzip`.
10. **Internal rewrites (outside these designs, recorded because they decide whether the
    application runs).** No agensio feature strips a variable path segment or builds a query from
    the path:
    - Magento's `/static/version<N>/` (needed when static signing is on).
    - PrestaShop's friendly image URLs and `/api/` (needed when friendly URLs are on).
    - WordPress multisite in subdirectories (needed for the feature).
    - Roundcube's secure URLs, TYPO3's versioned file names, Statamic's full-measure cache (opt-in
      features).

    That is 3 applications with a default feature affected and 3 with an opt-in one. Smallest
    change for the segment strip: a location `path` with one `*` segment and an `alias` (Magento,
    Roundcube; WordPress multisite partly). Captures into a query (PrestaShop, Magento's
    `static.php?resource=`) remain uncovered.

Not supported by the evidence:
- Conditions on request fields: one application (Nextcloud's DavClnt), and it works without.
- Conditions on the query for headers: Nextcloud and FreshRSS, cosmetic (`immutable`).
- `ETag` removal: three applications, and harmful.
- `merge` or `append` verbs: two applications, and a full `set` is equivalent.
- Scheme-conditional redirects: WordPress legacy.
- HSTS preload, `Set-Cookie`, `Public-Key-Pins`: commented examples only.

## 25. Not verified

- Some sources could not be read live and are marked where used:
  - **Joomla's nginx page**: read from a Wayback snapshot of 2025-03-18. The live page sits behind
    a Cloudflare challenge.
  - **Moodle's pages**: read through a summarising fetch tool. The `try_files`, `return 404`,
    `[L,R=404]` and `FallbackResource /r.php` lines are as that tool reported them.
  - **drupal.org**: whether the requirements page links no nginx recipe comes from the same tool.
    The nginx wiki recipe is the community one that drupal.org and most guides used to point to.
- Some application defaults were not checked:
  - Shopware 6.7 answers `/sitemap.xml` from PHP (SW-5).
  - Roundcube's `use_secure_urls` is off by default (RC-10).
  - TYPO3 v14's defaults for `versionNumberInFilename` and `compressionLevel` (T3-4, T3-10).
  - Every Drupal answer carries `Cache-Control` (DR-2).
  - Craft's `X-Powered-By: Craft CMS` default, which the baseline would remove (from memory).
- Magento's PHP header providers were listed from the 2.4.9 file names and the values in
  `XContentTypeOptions.php`, `XFrameOptions.php`, `Hsts.php` and `UpgradeInsecure.php`. Their
  registration in `di.xml` was not read.
- **Apache `.htaccess` headers reaching PHP answers.** Stated from Drupal's and Nextcloud's own
  comments about the `onsuccess` table and duplicate fields, not tested on an Apache server here.
- **How Nextcloud routes on agensio was not tested.** The fallback form `/index.php` with
  `front_controller_active`, and whether agensio can set that FastCGI parameter, may decide
  whether NC-7 works as an internal route. The `php` options in configuration.md 7 list no
  arbitrary parameters.
- **HSTS for Nextcloud's own check.** That Nextcloud's admin setup check accepts a one-year HSTS
  (it is believed to require at least 15552000 seconds) was not checked in its source.
