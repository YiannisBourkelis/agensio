# Exact rules on a script and its PATH_INFO forms: bypasses, legitimate uses, edge cases

Research date 2026-10-09. Scope: rules for one script (`/wp-login.php`, `/update.php`) that a
request beats by appending path info (`/wp-login.php/x`); how real applications use PATH_INFO,
so that a fix stays robust and does not break them; edge cases for the heuristic "also judge
each leading part that ends in a segment with a dot and is followed by `/`".

Labels: **[quote]** is verbatim from the source linked; **[measured]** is a local experiment
run for this note (commands and versions in section 1a); **[inference]** is my reading.

---

## 0. Key facts

1. Following two of WordPress's own official pages together gives a bypass on nginx and on Caddy.
   The pages are the nginx recipe (`location ~ [^/]\.php(/|$)` with `fastcgi_split_path_info`) and
   the brute-force guide (`location = /wp-login.php { allow ...; deny all; }`, Caddy
   `basicauth /wp-login.php`, `path /wp-login.php`). With them, `/wp-login.php/` and
   `/wp-login.php/x` run wp-login.php with no check **[measured]**. The same holds for Drupal: the
   nginx wiki recipe plus an exact `location = /update.php` rule leaves `/update.php/selection`
   unprotected **[measured]**.
2. Apache's `<Files "wp-login.php">` (WordPress's Apache example) applies to the file the URL maps
   to, so it already covers `/wp-login.php/x`, which is the semantics we propose **[measured]**.
   With `ProxyPassMatch` to PHP-FPM it does not apply at all, not even to `/wp-login.php`
   **[measured]**. The Apache wiki warns about this **[quote]**. `<Location "/wp-login.php">`
   covers `/wp-login.php/x` because it matches on segment boundaries **[quote]+[measured]**. An
   anchored `<LocationMatch "^/wp-login\.php$">` is bypassed **[measured]**.
3. Published cases of path info beating a check:
   - WordPress CVE-2008-2146 (`$pagenow` from PHP_SELF).
   - The osCommerce admin bypass `/admin/mail.php/login.php`.
   - OWASP CRS CVE-2021-35368: an end-anchored exclusion met through `index.php/...`.
   - PAN-OS CVE-2025-0108: `/unauth/%252e%252e/php/ztp_gate.php/PAN_help/x.css`.
   - Symfony CVE-2025-64500: PATH_INFO parsing.
   - Caddy CVE-2026-27590 and CVE-2026-45135: split_path confusion.
   - The general class is CWE-647 (non-canonical URL paths, trailing slashes).
4. The projects' own server configurations write `script(/|$)` or an unanchored prefix regex when
   they mean "this script", never an anchored exact match:
   - Laravel and Symfony: `^/index\.php(/|$)`.
   - Nextcloud: `\.php(?:$|/)`.
   - Moodle and phpBB: `\.php(/|$)`.
   - Drupal's `.htaccess`: `\.php($|/)`.
   - The nginx wiki's Drupal recipe: `^/update.php`.
   - Magento: `^/setup/index.php`.

   WordPress's `$pagenow` reads the script as `([^/]+\.php)([?/].*?)?$`. This is the proposed
   semantics.
5. Many scripts take PATH_INFO by design:
   - Drupal `update.php/{op}`.
   - Nextcloud `remote.php/dav`, `public.php/webdav`, `ocs/v2.php/...`.
   - Moodle `pluginfile.php/...`, `theme/styles.php/...`, `r.php`.
   - MediaWiki `index.php/Title`, `rest.php/v1/...`, `img_auth.php/...`.
   - Joomla `api/index.php/v1/...`.
   - WordPress `index.php/...` ("Almost Pretty") and `wp-trackback.php/<id>`.
   - Magento `update/index.php/...`.
   - phpBB `index.php/...` (earlier `app.php/...`).

   For each of them an exact rule on the script means the script with its path info. Bare
   `pluginfile.php` or `remote.php` does nothing useful. Section 2 has the full table.

---

## 1. Known bypasses and advisories

### 1a. Local experiments (2026-10-09)

Setup: the `agensio-devbox:php` image (nginx 1.26.3 Debian `1.26.3-3+deb13u9`, Caddy v2.11.4,
PHP-FPM 8.4.26) and `httpd:2.4` (Apache/2.4.69). Network `none`, loopback only. Every script in
the docroot only prints which file ran, with its `SCRIPT_NAME` and `PATH_INFO`:
`<?php echo "ran=wp-login.php SCRIPT_NAME=", $_SERVER["SCRIPT_NAME"], " PATH_INFO=", $_SERVER["PATH_INFO"] ?? "";`
The test files were under the session scratchpad (`pi/`). The configurations are reproduced
below.

**nginx, port 8001.** WordPress's path-info PHP block plus WordPress's "Deny by IP" exact location:

```nginx
location / { try_files $uri $uri/ /index.php?$args; }
location = /wp-login.php { allow 203.0.113.15; deny all; include /etc/nginx/fastcgi.conf; fastcgi_pass php; }
location ~ [^/]\.php(/|$) {
    fastcgi_split_path_info ^(.+?\.php)(/.*)$;
    if (!-f $document_root$fastcgi_script_name) { return 404; }
    include /etc/nginx/fastcgi.conf; fastcgi_param PATH_INFO $fastcgi_path_info;
    fastcgi_index index.php; fastcgi_pass php;
}
```

| request | result |
|---|---|
| `/wp-login.php` | 403 |
| `/wp-login.php/` | **200 ran=wp-login.php PATH_INFO=/** |
| `/wp-login.php/x` | **200 ran=wp-login.php PATH_INFO=/x** |
| `/wp-login.php%2Fx` | **200 ran=wp-login.php PATH_INFO=/x** (nginx decodes `%2F` before matching) |
| `/wp-login%2ephp/x` | **200 ran=wp-login.php** |
| `/WP-LOGIN.PHP/x` | 200 ran=index.php (case-sensitive regex and filesystem; on macOS or Windows this would differ) |

**nginx, port 8002.** The same exact rule with WordPress's plain `location ~ \.php$` block:
`/wp-login.php/x` gives 200 ran=index.php. That is not a bypass: the path does not end in `.php`,
so `try_files` falls back to the front controller. **[measured]** The bypass therefore needs a PHP
location that accepts path info, which WordPress's own page offers as its "with path info"
variant.

**nginx, port 8003.** The nginx wiki's Drupal recipe PHP block
(`location ~ '\.php$|^/update.php'`, `fastcgi_split_path_info ^(.+?\.php)(|/.*)$`,
`try_files $fastcgi_script_name =404`) plus an administrator's
`location = /update.php { allow 203.0.113.15; deny all; ... }`:

| request | result |
|---|---|
| `/update.php` | 403 |
| `/update.php/selection` | **200 ran=update.php** |
| `/update.php/run` | **200 ran=update.php** |
| `/update.php/results` | **200 ran=update.php** |

PATH_INFO arrived empty here because `try_files` resets `$fastcgi_path_info` (nginx trac #321,
see 1c). Drupal routes from REQUEST_URI anyway.

**Caddy, port 8004.** WordPress's own Caddy examples:

```caddy
basic_auth /wp-login.php { user1 <bcrypt> }
@blacklist { not client_ip 203.0.113.15
             path /xmlrpc.php }
respond @blacklist "Forbidden" 403
php_fastcgi unix//tmp/php.sock
```

| request | result |
|---|---|
| `/wp-login.php` | 401 |
| `/wp-login.php/` | **200 ran=wp-login.php** |
| `/wp-login.php/x` | **200 ran=wp-login.php PATH_INFO=/x** |
| `/xmlrpc.php` | 403 |
| `/xmlrpc.php/x` | **200 ran=xmlrpc.php PATH_INFO=/x** |

Why, from Caddy's source **[inference from code]**: `basic_auth` and `respond` run on the
original path, and Caddy's path matcher is exact. php_fastcgi's own file matcher then splits at
`.php`. In `modules/caddyhttp/fileserver/matcher.go` the comment reads: "the path
`/remote.php/dav/` using the split value `.php` would try the file `/remote.php`". It rewrites to
the script, and the FastCGI transport takes `PATH_INFO` from `http.matchers.file.remainder`
(`reverseproxy/fastcgi/fastcgi.go`, "Try to grab the path remainder from a file matcher").
<https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/fileserver/matcher.go>,
<https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/reverseproxy/fastcgi/fastcgi.go>

**Apache 2.4.69 with PHP-FPM 8.4.26** (separate container, shared unix socket):

| configuration | `/wp-login.php` | `/wp-login.php/` | `/wp-login.php/x` |
|---|---|---|---|
| `<FilesMatch "\.php$"> SetHandler "proxy:unix:...\|fcgi://localhost"` plus `<Files "wp-login.php"> Require ip 203.0.113.15` (WordPress's Apache example) | 403 | 403 | 403 |
| `ProxyPassMatch "^/(.*\.php(/.*)?)$" "unix:...\|fcgi://localhost/www/"` plus the same `<Files>` | **200** | **200** | **200** |
| `SetHandler` plus `<Location "/wp-login.php"> Require ip ...` | 403 | 403 | 403 |
| `SetHandler` plus `<LocationMatch "^/wp-login\.php$"> Require ip ...` | 403 | **200** | **200** |

The error log for the `<Files>` case names the file, not the URL: "AH01630: client denied by
server configuration: /www/wp-login.php". Apache decides `<Files>` on the mapped file (script plus
path_info), which is the semantics proposed for agensio.

### 1b. Published cases

**WordPress CVE-2008-2146** (published 2008-05-12) **[quote]**: "wp-includes/vars.php in
Wordpress before 2.2.3 does not properly extract the current path from the PATH_INFO
($PHP_SELF), which allows remote attackers to bypass intended access restrictions for certain
pages." <https://nvd.nist.gov/vuln/detail/CVE-2008-2146>, ticket
<https://core.trac.wordpress.org/ticket/4748>, fix r6029 ("Better $pagenow determination.
fixes #4748"), mirror
<https://github.com/WordPress/wordpress-develop/commit/5a4c102696d32de9abededb75f2e7ae5a2a38eaf>.
The diff replaced `preg_match('#([^/]+\.php)$#', $PHP_SELF, ...)` with
`preg_match('#([^/]+\.php)([?/].*?)?$#i', $PHP_SELF, ...)` for front-end pages. WordPress trunk
still names the current script that way: the `.php` segment, followed by `/`, `?` or the end,
case-insensitive and lower-cased.
<https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/vars.php>
**[inference]**: this is the in-application version of our fix, and WordPress's own idea of
"which script" matches it.

**osCommerce 2.2 admin authentication bypass** **[quote]**: "There is a page in the admin that
can be access without login AND can pass parameters!! /admin/mail.php/login.php ...
/admin/mail.php/login.php?action=send_email_to_user". <https://www.exploit-db.com/exploits/10096>.
Variants with `backup.php/login.php` and `file_manager.php/login.php` are discussed at
<https://forums.oscommerce.com/topic/374759-has-one-of-my-sites-been-hacked/> and
<https://www.exploit-db.com/exploits/15472>. **[inference]** The admin skipped its login check when
`basename($PHP_SELF)` was `login.php`, and PHP_SELF includes the PATH_INFO.

**OWASP CRS CVE-2021-35368, "Request Body Bypass via a trailing pathname"** **[quote]**:
- "The OWASP ModSecurity Core Rule Set (CRS) is affected by a request body bypass that abuses
  trailing pathname information. A backend vulnerability can thus be exploited despite being
  protected with the CRS Web Application Firewall rule set when an application server accepts
  additional path info as part of the request URI."

---

*These notes stop here: the research was interrupted on 2026-10-09 while section 1b was being
written, and the sections on legitimate uses and edge cases were never reached. The decision
they fed (finding 1 of the alpha.58 report, the precise fix in `access::script_of`) rests on
section 0, section 1a and `servers.md`.*
