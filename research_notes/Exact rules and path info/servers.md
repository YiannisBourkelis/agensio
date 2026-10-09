# Exact rules and PATH_INFO: how web servers decide a rule written for one script

Research date 2026-10-09. Question: when an access or password rule names ONE script (`/wp-login.php`,
`/update.php`, `/info.php`, `/xmlrpc.php`) and the request carries PATH_INFO after the script name
(`/wp-login.php/x`, `/update.php/selection`, `/info.php/`, `/wp-login.php/x.php`), does the rule
still apply, in nginx, Apache httpd, Caddy, LiteSpeed, HAProxy, Traefik, IIS, and what does PHP do?

Method. Three kinds of evidence, marked in the text:

- **[doc]** quoted from official documentation (URL given; Apache text read from the XML source of
  the manual on the `2.4.x` branch, commit `63d47d49`).
- **[src]** read in the source: Apache httpd `2.4.x` @ `63d47d49`, Caddy `master` @ `093fd4b7`,
  OpenLiteSpeed `master` @ `e6fb6477`, php-src `master` @ `b78055ef`, Debian's nginx packaging
  `debian/latest`.
- **[lab]** run here on 2026-10-09 in Docker on the Linux box: nginx 1.26.3, Caddy 2.11.4, PHP-FPM
  8.4.26 (all in `agensio-devbox:php`), Apache httpd 2.4.69 (`httpd:2.4`), with one `wp-login.php` and
  one `index.php` that print which script ran with `SCRIPT_NAME` and `PATH_INFO`. Configurations and
  raw output in the appendix.
- **[inferred]** my reading where neither docs nor the lab settle it.

## 1. Summary table

"Covers" means the rule is applied to the request; "bypass" means the request reached and ran
`wp-login.php` without the rule. Paths tried: `/wp-login.php/`, `/wp-login.php/x`,
`/wp-login.php/x.php`, `/wp-login.php%2Fx`.

| Server | Rule form | Covers `/wp-login.php/…`? | Why | Evidence |
|---|---|---|---|---|
| nginx | `location = /wp-login.php { deny all; }` (or `auth_basic`, or `limit_req`, as the WordPress handbook shows) | **No.** With the nginx-wiki PHP location `~ [^/]\.php(/\|$)` every variant runs wp-login.php (PATH_INFO `/`, `/x`, `/x.php`, and `/x` from `%2F`). With Debian's `~ \.php$` + `snippets/fastcgi-php.conf`, and with the nginx-wiki WordPress recipe's `~ \.php$`, `/` and `/x` fall to `index.php` but `/wp-login.php/x.php` runs wp-login.php | `=` is an exact match of the whole normalised URI; the request then goes to whichever PHP location matches, and that one splits PATH_INFO | [doc] [lab A, B, C, E] |
| nginx | `location ^~ /wp-login.php { deny all; }` | **Yes** (all variants); also catches `/wp-login.phpx`; case-sensitive | longest prefix, `^~` stops the regex search | [doc] [lab D] |
| nginx | `location ~* ^/wp-login\.php { … }` (research recommendation) | Yes if it comes before the PHP regex location (first regex wins) | regex order | [doc] [inferred, not run] |
| Apache 2.4 | `<Files "wp-login.php">` with mod_php or `<FilesMatch \.php$> SetHandler proxy:fcgi` | **Yes** (all PATH_INFO variants; `%2F` is 404 by default) | the directory walk maps the URL to `/docroot/wp-login.php` and moves the rest into `path_info`; `<Files>` matches the basename of that mapped file | [doc] [src] [lab I] |
| Apache 2.4 | `<Files "wp-login.php">` with `ProxyPassMatch ^/(.*\.php(/.*)?)$ fcgi://…` | **No, not even `/wp-login.php` itself** | mod_proxy's map_to_storage hook skips the directory and file walks, so no `<Files>` or `<Directory>` applies | [src] [doc wiki] [lab J] |
| Apache 2.4 | `<Location "/wp-login.php">` | **Yes** (all variants) | matches the path exactly, or as a prefix followed by `/` | [doc] [lab K, M] |
| Apache 2.4 | `<LocationMatch "^/wp-login\.php$">` | **No** | anchored regex on the URL | [lab L] |
| Apache 2.4 | `<FilesMatch "^wp-login\.php$">` | Yes (same basename mechanism as `<Files>`), not with ProxyPassMatch | as `<Files>` | [doc] [inferred, not run] |
| Caddy 2 | `basic_auth /wp-login.php {…}` (WordPress handbook) or `@m { path /wp-login.php … }` | **No** (`/`, `/x`, `/x.php`, `%2Fx` all run wp-login.php) | "Path matches are exact but case-insensitive"; `php_fastcgi` later splits at `.php` and runs the script with the remainder as PATH_INFO | [doc] [src] [lab F, G] |
| Caddy 2 | `path /wp-login.php /wp-login.php/*` | **Yes** (all variants, any case) | second pattern is a prefix match under the segment | [doc] [lab H] |
| Caddy 2 | `path /wp-login.php*` | Yes, but also `/wp-login.phpx` | "`/foo*` will match `/foo`, `/foobar`, `/foo/`, and `/foo/bar`" | [doc] |
| OpenLiteSpeed | plain context URI `/wp-login.php` | **Not verified.** Docs: only a URI ending in `/` "will include all sub-URIs"; the source's context tree picks the deepest context segment by segment | — | [doc] [src] gap |
| LSWS Enterprise | `.htaccess` `<Files>` | presumably as Apache (it reads Apache configuration) | — | [inferred] gap |
| HAProxy | `acl a path /wp-login.php` | **No** (exact string; the manual's own example is "/login.php") | `path_beg` covers (string prefix, also `/wp-login.phpx`); `path_dir` covers (any slash-delimited portion, also `/x/wp-login.php`) | [doc] |
| Traefik | ``Path(`/wp-login.php`)`` | **No** (exact) | ``PathPrefix`` covers but is a string prefix (matches `/products-for-sale` for `/products`); ``PathRegexp`` as written | [doc] |
| IIS | `<location path="wp-login.php">` + ipSecurity | **Not verified** | handler `allowPathInfo` defaults to `false` | [doc] gap |
| php-fpm | (not a rule engine) | runs `wp-login.php` for `SCRIPT_FILENAME=/docroot/wp-login.php/x.php` when `cgi.fix_pathinfo=1` (the default); `security.limit_extensions` tests only the final script, which ends in `.php` | stat walk back to the first regular file | [doc] [src] [lab C vs C′] |

Three things stand out:

1. **The exact forms (`location =`, Caddy `path` without `/*`, HAProxy `path`, Traefik `Path`,
   anchored `LocationMatch`) never cover PATH_INFO**, and the official WordPress hardening page
   recommends exactly these forms for nginx and Caddy. The forms that do cover it are either
   resource-based (Apache `<Files>`, as long as the filesystem mapping runs) or segment prefixes
   (Apache `<Location>`, Caddy `p p/*`, nginx `^~`, HAProxy `path_dir`).
2. **`/script.php/x.php` gets through every nginx PHP layout tried**, including the two
   (`~ \.php$`) that send `/script.php/x` to the front controller instead, because the request
   then ends in `.php` and either nginx's split (Debian snippet) or php-fpm's own
   `cgi.fix_pathinfo` walk (WordPress recipe) chooses the first script.
3. **Apache's `<Files>` is resource-based only when Apache maps the file itself**; with
   `ProxyPassMatch` it silently stops applying, even to the exact file.

## 2. nginx

### Location selection [doc]

From the `location` directive (https://nginx.org/en/docs/http/ngx_http_core_module.html#location):

> "The matching is performed against a normalized URI, after decoding the text encoded in the
> "%XX" form, resolving references to relative path components "." and "..", and possible
> compression of two or more adjacent slashes into a single slash."

> "To find location matching a given request, nginx first checks locations defined using the prefix
> strings (prefix locations). Among them, the location with the longest matching prefix is selected
> and remembered. Then regular expressions are checked, in the order of their appearance in the
> configuration file. The search of regular expressions terminates on the first match, and the
> corresponding configuration is used. […] If the longest matching prefix location has the "^~"
> modifier, then regular expressions and predicate locations are not checked."

> "Also, using the "=" modifier it is possible to define an exact match of URI and location. If an
> exact match is found, the search terminates."

So `location = /wp-login.php` matches the URI `/wp-login.php` and nothing else; `/wp-login.php/x`
is matched afresh against the other locations. Note that the decoding means `/wp-login.php%2Fx` is
matched as `/wp-login.php/x` (the lab shows it running with `PATH_INFO=/x` under layout B).

### Splitting PATH_INFO [doc]

`fastcgi_split_path_info` (https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_split_path_info):

> "Defines a regular expression that captures a value for the $fastcgi_path_info variable. The
> regular expression should have two captures: the first becomes a value of the
> $fastcgi_script_name variable, the second becomes a value of the $fastcgi_path_info variable.
> […] the "/show.php/article/0001" request, the SCRIPT_FILENAME parameter will be equal to
> "/path/to/php/show.php", and the PATH_INFO parameter will be equal to "/article/0001"."

### The three common PHP locations

- **nginx wiki "PHP FastCGI Example"** (source: https://github.com/nginxinc/nginx-wiki/blob/master/source/start/topics/examples/phpfcgi.rst;
  the old www.nginx.com/resources/wiki URLs now 301 to docs.nginx.com) [doc]:

  ```nginx
  location ~ [^/]\.php(/|$) {
      fastcgi_split_path_info ^(.+?\.php)(/.*)$;
      if (!-f $document_root$fastcgi_script_name) {
          return 404;
      }
      ...
  ```
  It tells the reader to test `/test.php/`, `/test.php/foo`, `/test.php/foo/bar.php` and notes "The
  location regex capable to handle PATH_INFO". This layout sends every `/wp-login.php/…` to
  wp-login.php. [lab B]

- **Debian's `snippets/fastcgi-php.conf`** (https://salsa.debian.org/nginx-team/nginx/-/raw/debian/latest/debian/conf/snippets/fastcgi-php.conf),
  included from the stock `location ~ \.php$` of Debian's default site [src]:

  ```nginx
  # regex to split $uri to $fastcgi_script_name and $fastcgi_path
  fastcgi_split_path_info ^(.+?\.php)(/.*)$;
  # Check that the PHP script exists before passing it
  try_files $fastcgi_script_name =404;
  ```
  `/wp-login.php/x` does not end in `.php`, so it falls to `location /` and `try_files … /index.php`;
  `/wp-login.php/x.php` ends in `.php`, is split, and wp-login.php runs with `PATH_INFO=/x.php`. [lab A]

- **nginx wiki WordPress recipe** (https://github.com/nginxinc/nginx-wiki/blob/master/source/start/topics/recipes/wordpress.rst) [doc]:

  ```nginx
  location ~ \.php$ {
      #NOTE: You should have "cgi.fix_pathinfo = 0;" in php.ini
  ```
  No split; `SCRIPT_FILENAME=$document_root$fastcgi_script_name` is `/srv/www/wp-login.php/x.php`.
  With php-fpm's default `cgi.fix_pathinfo=1` it ran wp-login.php (reported
  `SCRIPT_NAME=/wp-login.php/x.php`); with `cgi.fix_pathinfo=0` it was a 404 ("Unable to open primary
  script: /srv/www/wp-login.php/x.php"). [lab C, C′]

### nginx's own Drupal recipe acknowledges the problem [doc]

https://github.com/nginxinc/nginx-wiki/blob/master/source/start/topics/recipes/drupal.rst:

> "# In Drupal 8, we must also match new paths where the '.php' appears in
> # the middle, such as update.php/selection. The rule we use is strict,
> # and only allows this pattern with the update.php front controller.
> […]
> location ~ '\.php$|^/update.php' {
>     fastcgi_split_path_info ^(.+?\.php)(|/.*)$;
>     # Ensure the php file exists. Mitigates CVE-2019-11043
>     try_files $fastcgi_script_name =404;"

Drupal itself declares the route with PATH_INFO (`core/modules/system/system.routing.yml`, 11.x,
https://git.drupalcode.org/project/drupal/-/blob/11.x/core/modules/system/system.routing.yml) [src]:

```yaml
system.db_update:
  path: '/update.php/{op}'
  defaults:
    op: 'info'
```

So a rule written as "exact `/update.php`" protects only the landing page (`op = info`); the
working pages are `/update.php/selection`, `/update.php/start`, `/update.php/results`.

### What the WordPress handbook recommends [doc]

https://developer.wordpress.org/advanced-administration/security/brute-force/ ("Nginx (examples)"):

```nginx
location = /wp-login.php {
    limit_req zone=logins burst=20 nodelay;
    include fastcgi_params;
    # pass to PHP-FPM or upstream as usual
}
location = /xmlrpc.php {
    limit_req zone=logins burst=20 nodelay;
    ...
```
and for IP restriction `location = /wp-login.php { allow 203.0.113.15; allow 203.0.113.16; deny all; }`.
The page says nothing about PATH_INFO or trailing slashes. Under any PHP location that accepts
PATH_INFO, `/wp-login.php/x` reaches wp-login.php outside that block (lab E shows the same with
`auth_basic`). Whether a POST login through `/wp-login.php/x` then succeeds is application
behaviour; wp-login.php does not look at `REQUEST_URI` for the login itself [inferred, not run
against WordPress].

### Discussions [doc/third party]

- Rafael da Costa Santos, "Exploiting HTTP Parsers Inconsistencies" (https://rafa.hashnode.dev/exploiting-http-parsers-inconsistencies),
  reproduced in HackTricks "Proxy / WAF Protections Bypass", section PHP-FPM
  (https://github.com/HackTricks-wiki/hacktricks/blob/master/src/pentesting-web/proxy-waf-protections-bypass.md):

  ```
  location = /admin.php {
      deny all;
  }
  location ~ \.php$ {
      include snippets/fastcgi-php.conf;
      fastcgi_pass unix:/run/php/php8.1-fpm.sock;
  }
  ```
  > "Nginx is configured to block access to `/admin.php` but it's possible to bypass this by
  > accessing `/admin.php/index.php`."

  and the article: "When two `.php` files are in the same pathname of the HTTP request, PHP will
  match the first one, ignoring everything after the slash." Its prevention: "you must use the `~`
  expression Instead of the `=` expression on Nginx ACL rules, for example: `location ~* ^/admin
  { deny all; }`" (with the note that this also blocks `/admin1337`). This is exactly lab A's
  `/wp-login.php/x.php` row.
- nginx mailing list, Francis Daly, 2016-01-26 (https://mailman.nginx.org/pipermail/nginx/2016-January/049703.html),
  to a user whose `app.php/controller/method` got 404: "If you have "location ~ php$", that would
  match the second request there, but not the first. Perhaps you want "location ~ php" or "location
  /folder/app/app.php" or something else instead?" (the nginx way to cover a script with its
  PATH_INFO is a prefix location).
- Hosting providers that IP-restrict a front-controller route write both spellings, e.g. ANS for
  Magento 2 (https://docs.ans.co.uk/docs/ecommerce-stacks/magento/magento-2/restrict-file-folder/):
  `location ~* ^/(index\.php/mageadmin|mageadmin) { … allow …; deny all; … }`.
- nginx wiki "Pitfalls", "Passing Uncontrolled Requests to PHP"
  (https://github.com/nginxinc/nginx-wiki/blob/master/source/start/topics/tutorials/config_pitfalls.rst):
  "if a request is made for `/forum/avatar/1232.jpg/file.php` which does not exist but if
  `/forum/avatar/1232.jpg` does, the PHP interpreter will process `/forum/avatar/1232.jpg` instead."
  The same php-fpm walk is what runs wp-login.php for `/wp-login.php/x.php` in layout C.

I found no nginx documentation or core-developer statement saying explicitly "an exact location does
not catch PATH_INFO"; it follows from the definition of `=`.

## 3. Apache httpd 2.4

### `<Location>` [doc]

https://httpd.apache.org/docs/2.4/mod/core.html#location:

> "The enclosed directives will be applied to the request if the path component of the URL meets
> *any* of the following criteria:
> - The specified location matches exactly the path component of the URL.
> - The specified location, which ends in a forward slash, is a prefix of the path component of the
>   URL (treated as a context root).
> - The specified location, with the addition of a trailing slash, is a prefix of the path component
>   of the URL (also treated as a context root).
>
> In the example below, where no trailing slash is used, requests to /private1, /private1/ and
> /private1/file.txt will have the enclosed directives applied, but /private1other would not."

So `<Location "/wp-login.php">` covers `/wp-login.php/x` (third criterion). [lab K, M]

The same page warns: "`<Location>` sections operate completely outside the filesystem. […] Most
importantly, `<Location>` directives should not be used to control access to filesystem locations.
Since several different URLs may map to the same filesystem location, such access controls may by
circumvented."

`<LocationMatch>` "limits the scope of the enclosed directives by URL-path, just as the `<Location>`
directive does. However, it accepts a regular expression." An anchored `^/wp-login\.php$` therefore
does not cover PATH_INFO. [lab L]

### `<Files>` / `<FilesMatch>` [doc] [src]

https://httpd.apache.org/docs/2.4/mod/core.html#files: "The directives given within this section
will be applied to any object with a basename (last component of filename) matching the specified
filename."

What "filename" is: `ap_directory_walk` (`server/request.c`, 2.4.x) builds `r->filename` segment by
segment from the URL and stops at the first non-directory; "r->path_info tracks the unconsumed source
path. r->filename tracks the path as we process it". `ap_file_walk` then takes the basename of
`r->filename` (`test_file = strrchr(r->filename, '/');`, request.c:1705-1711) and matches the
`<Files>` sections. For `/wp-login.php/x`, `r->filename` is `/srv/www/wp-login.php`, `path_info` is
`/x`, and `<Files "wp-login.php">` applies. [lab I: 403 for `/`, `/x`, `/x.php`]

Note that `<Files "wp-login.php">` outside a `<Directory>` also matches a `wp-login.php` in any
directory (basename only); nesting it in `<Directory>` narrows it [doc].

### AcceptPathInfo [doc]

https://httpd.apache.org/docs/2.4/mod/core.html#acceptpathinfo:

> "This directive controls whether requests that contain trailing pathname information that follows
> an actual filename (or non-existent file in an existing directory) will be accepted or rejected.
> […] requests for /test/here.html/more and /test/nothere.html/more both collect /more as PATH_INFO."
>
> "Default: The treatment of requests with trailing pathname information is determined by the
> handler responsible for the request. The core handler for normal files defaults to rejecting
> PATH_INFO requests. Handlers that serve scripts, such as cgi-script and isapi-handler, generally
> accept PATH_INFO by default."

AcceptPathInfo decides whether the request is served; it does not change which `<Files>` or
`<Location>` sections apply (they are chosen from the mapped filename and the URL) [src, inferred].

### mod_proxy_fcgi: SetHandler versus ProxyPassMatch [doc] [src]

https://httpd.apache.org/docs/2.4/mod/mod_proxy_fcgi.html, "Proxy via Handler": "The benefit of this
form is that it allows the normal mapping of URI to filename to occur in the server, and the local
filesystem result is passed to the backend. When FastCGI is configured this way, the server can
calculate the most accurate PATH_INFO." The same page on `proxy-fcgi-pathinfo`: "When configured
via ProxyPass or ProxyPassMatch, mod_proxy_fcgi will not set the PATH_INFO environment variable."

`modules/proxy/mod_proxy.c` lines 1135-1151 (2.4.x):

```c
static int proxy_map_location(request_rec *r)
{
    ...
    /* Don't let the core or mod_http map_to_storage hooks handle this,
     * We don't need directory/file_walk, and we want to TRACE on our own.
     */
    if ((access_status = proxy_walk(r))) {
```

So under `ProxyPassMatch` neither `<Directory>` nor `<Files>` is walked. The httpd wiki page on
PHP-FPM (https://cwiki.apache.org/confluence/display/HTTPD/PHP-FPM) says it plainly: "Warning: when
you ProxyPass a request to another server (in this case, the php-fpm daemon), authentication
restrictions, and other configurations placed in a Directory block or .htaccess file, may be
bypassed." The sections page: "When the request is served by mod_proxy, the `<Proxy>` container takes
the place of the `<Directory>` container in the processing order"
(https://httpd.apache.org/docs/2.4/sections.html#merging). [lab J: `<Files "wp-login.php">` with
ProxyPassMatch served even `/wp-login.php` itself; php-fpm split `…/wp-login.php/x` back to the
script through `cgi.fix_pathinfo`]

### The Apache principle [doc]

https://httpd.apache.org/docs/2.4/sections.html#whichwhen:

> "When applying directives to objects that reside in the filesystem always use `<Directory>` or
> `<Files>`. […] It is important to never use `<Location>` when trying to restrict access to objects
> in the filesystem. This is because many different webspace locations (URLs) could map to the same
> filesystem location, allowing your restrictions to be circumvented. […] remember that there are
> many other ways to map multiple webspace locations to the same filesystem location. Therefore you
> should always use the filesystem containers when you can."

PATH_INFO is one of those "other ways": `/wp-login.php`, `/wp-login.php/`, `/wp-login.php/x` are
three URLs for one file. Apache's documented answer is to decide on the file.

## 4. Caddy 2

### The path matcher [doc]

https://caddyserver.com/docs/caddyfile/matchers#path:

> "By request path (the path component of the request URI). Path matches are exact but
> case-insensitive. Wildcards `*` may be used: At the end only, for a prefix match (`/prefix/*`) […]
> Slashes are significant. For example, `/foo*` will match `/foo`, `/foobar`, `/foo/`, and `/foo/bar`,
> but `/foo/*` will _not_ match `/foo` or `/foobar`."

> "Request paths are cleaned to resolve directory traversal dots before matching. […] the request
> path is normalized (URL-decoded, unescaped) except for those escape sequences at positions where
> escape sequences are also present in the match pattern."

### php_fastcgi runs the script with the remainder [doc] [src]

https://caddyserver.com/docs/caddyfile/directives/php_fastcgi#expanded-form:

```caddy-d
@indexFiles file {
	try_files {path} {path}/index.php index.php
	try_policy first_exist_fallback
	split_path .php
}
rewrite @indexFiles {file_match.relative}

@phpFiles path *.php
reverse_proxy @phpFiles <php-fpm_gateway> {
	transport fastcgi {
		split .php
	}
}
```
"This also has the side-effect of remembering the part of the path after `.php` (if the request path
had `.php` in it)."

Source: `MatchFile.firstSplit` (`modules/caddyhttp/fileserver/matcher.go:579`) splits at the first
`.php` that ends a path segment; the file matcher stores the rest in
`http.matchers.file.remainder`, and the FastCGI transport (`reverseproxy/fastcgi/fastcgi.go:296-315`)
uses it: "Try to grab the path remainder from a file matcher if we didn't get a split result here.
See https://github.com/caddyserver/caddy/issues/3718".

### Order: the rule sees the original path [doc]

The Caddyfile directive order (https://caddyserver.com/docs/caddyfile/directives#directive-order)
puts `basic_auth` and `respond` before `php_fastcgi`, whose rewrite is internal. A `basic_auth
/wp-login.php` therefore tests `/wp-login.php/x`, does not match, and php_fastcgi then rewrites to
`/wp-login.php` with PATH_INFO `/x`. [lab F, G: 200 and wp-login.php ran for `/`, `/x`, `/x.php`,
`%2Fx`; `/WP-LOGIN.PHP` got 401/403 because the matcher is case-insensitive]

The WordPress handbook's Caddy example is `basicauth /wp-login.php { … }` and `@blacklist { not
client_ip forwarded …; path /wp-login.php }` (same page as above), i.e. the bypassable form.

### Related Caddy advisories (split and matcher normalisation)

Caddy 2.11.1 release notes (2026-02-23, https://github.com/caddyserver/caddy/releases/tag/v2.11.1):
"fastcgi: CVE-2026-27590 […] Unicode case-folding length expansion causes incorrect split_path index
(SCRIPT_NAME/PATH_INFO confusion) in FastCGI transport" and "caddyhttp: CVE-2026-27587 […] The Path
matcher skips case normalization for escape sequences, enabling path-based route/auth bypass."
CVE-2026-45135 / GHSA-m675-2p33-xv9g (fixed in 2.11.3, 2026-05-18,
https://corgea.com/advisories/vulnerabilities/CVE-2026-45135): "Unsafe Unicode Handling in FastCGI
splitPos Allows Execution of Non-PHP Files"; the current `splitPos` comment: "Matching is strictly
ASCII case-insensitive. Bytes >= utf8.RuneSelf in path never match any split entry". Lesson: the split
that decides which script runs is security-critical, and any rule that reasons about "the script"
must use the same split.

I found no Caddy issue about an exact `path` matcher being bypassed through PATH_INFO.

## 5. LiteSpeed / OpenLiteSpeed, HAProxy, Traefik, IIS, lighttpd

### OpenLiteSpeed [doc] [src], gap

Context URI, from OLS's bundled help (`dist/docs/Static_Context.html`, master @ e6fb6477): "The URI can
be a plain URI (starting with "/") or a Perl compatible regular expression URI (starting with
"exp:"). If a plain URI ends with a "/", then this context will include all sub-URIs under this URI.
If the context maps to a directory on the file system, a trailing "/" must be added."

Source: `ContextNode::match` (`src/http/contexttree.cpp:72`) walks the request URI segment by segment
and returns the deepest node that has a context (`if (!pChild) return pLastMatch;`), and
`HttpVHost::dirMatch` then creates implicit contexts for unmatched directory segments. Whether a plain
context `/wp-login.php` ends up governing `/wp-login.php/x`, and how OLS's script handler sets
PATH_INFO, was not established (not run). LSWS Enterprise reads Apache `<Files>` in `.htaccess`; its
behaviour is presumably Apache's (unverified).

### HAProxy [doc]

`doc/configuration.txt` (master, https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt),
`path : string`: "With ACLs, it's typically used to match exact file names (e.g. "/login.php"), or
directory parts using the derivative forms." Derivatives: "path : exact string match, path_beg :
prefix match, path_dir : subdir match, path_end : suffix match […]". `-m dir`: "the patterns are looked
up anywhere inside the extracted string, delimited with slashes ("/"), the beginning or the end of the
string. […] the string "/images/png/logo/32x32.png", would match "/images", "/images/png", […]
"logo/32x32.png" or "32x32.png" but not "png" nor "32x32"." So `path /wp-login.php` misses
`/wp-login.php/x`; `path_beg` catches it and `/wp-login.phpx`; `path_dir` catches it anywhere in the
path. HAProxy does not normalise the path unless `http-request normalize-uri` is configured.

### Traefik [doc]

https://doc.traefik.io/traefik/reference/routing-configuration/http/routing/rules-and-priority/:
`Path` "Matches requests path set to `path`" (exact); `PathPrefix` "Matches requests path prefix set to
`prefix`", a string prefix (the page's example matches `/products-for-sale` for `/products`);
`PathRegexp` uses Go regular expressions. So `Path` misses PATH_INFO, `PathPrefix` over-matches.

### IIS [doc], gap

Handler mapping `<add>` (https://learn.microsoft.com/en-us/iis/configuration/system.webserver/handlers/add):
"`allowPathInfo`: Optional Boolean attribute. Specifies whether the handler processes full path
information in a URI […]. The default value is `false`." How `<location path="wp-login.php">` with
`<ipSecurity>` or URL authorization applies to `/wp-login.php/x` is not documented on the pages I read;
not verified.

### lighttpd [doc]

https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Configuration: `$HTTP["url"]` "match on url
path (not including host or query-string)". The resource-based `$PHYSICAL["path"]` ("match on the
mapped physical path of the file / cgi script to be served") was "Introduced in version 1.5.0 (note:
abandoned; never released)", so lighttpd 1.4 rules are URL-based.

## 6. PHP and php-fpm

### Ini settings [doc]

`cgi.fix_pathinfo`, default "1" (https://www.php.net/manual/en/ini.core.php#ini.cgi.fix-pathinfo):
"Provides *real* PATH_INFO/PATH_TRANSLATED support for CGI. PHP's previous behaviour was to set
PATH_TRANSLATED to SCRIPT_FILENAME, and to not grok what PATH_INFO is. […] Setting this to 1 will
cause PHP CGI to fix its paths to conform to the spec."

`security.limit_extensions`, default ".php .phar"
(https://www.php.net/manual/en/install.fpm.configuration.php): "Limits the extensions of the main
script FPM will allow to parse. This can prevent configuration mistakes on the web server side. You
should only limit FPM to .php extensions to prevent malicious users to use other extensions to execute
php code."

### How php-fpm derives SCRIPT_NAME and PATH_INFO [src]

`sapi/fpm/fpm/fpm_main.c`, `init_request_info` (comment at line 894): for
`http://localhost/info.php/test?a=b` the target is `PATH_INFO=/test`, `SCRIPT_NAME=/info.php`,
`SCRIPT_FILENAME=/docroot/info.php`. With `fix_pathinfo` on (line 1106): "if the file doesn't exist,
try to extract PATH_INFO out of it by stat'ing back through the '/' this fixes url's like
/info.php/test", i.e. it strips trailing segments until `stat` finds a regular file. The extension
check `fpm_php_limit_extensions` (`fpm_php.c:229`) compares only the end of that final path, so
`/docroot/wp-login.php` passes.

Consequences:

- PHP itself never refuses `/wp-login.php/x`; given either `SCRIPT_FILENAME=/docroot/wp-login.php` with
  `PATH_INFO=/x`, or `SCRIPT_FILENAME=/docroot/wp-login.php/x[.php]` with fix_pathinfo on, it runs
  wp-login.php. [lab B, C]
- `cgi.fix_pathinfo=0` only removes the second route (lab C′: 404); it does nothing when the server
  splits PATH_INFO itself (layouts A, B, Caddy, Apache SetHandler).

I found no PHP or php-fpm documentation telling server administrators that access control must
consider PATH_INFO; the PHP-side warnings are about executing non-PHP files (the walk above).

### CGI specification [doc]

RFC 3875 (https://www.rfc-editor.org/rfc/rfc3875):

- 3.3: "The mapping from client request URI to choice of script is defined by the particular server
  implementation and its configuration. The server may allow the script to be identified with a set of
  several different URI path hierarchies".
- 4.1.5 PATH_INFO: "It identifies the resource or sub-resource to be returned by the CGI script, and is
  derived from the portion of the URI path hierarchy following the part that identifies the script
  itself. […] The server MAY impose restrictions and limitations on what values it permits for
  PATH_INFO, and MAY reject the request with an error if it encounters any values considered
  objectionable. That MAY include any requests that would result in an encoded "/" being decoded into
  PATH_INFO". (nginx and Caddy decode `%2F` into PATH_INFO in the lab; Apache answers 404.)
- 4.1.13 SCRIPT_NAME: "MUST be set to a URI path (not URL-encoded) which could identify the CGI script
  […] No PATH_INFO segment (see section 4.1.5) is included in the SCRIPT_NAME value."
- 9.8: "".." path segments […] should be removed or resolved in the request URI before it is split
  into the script-path and extra-path."

## 7. The general principle

Quoted:

- CWE-647 "Use of Non-Canonical URL Paths for Authorization Decisions" (CWE 4.20,
  https://cwe.mitre.org/data/definitions/647.html): "If an application defines policy namespaces and
  makes authorization decisions based on the URL, but it does not require or convert to a canonical
  URL before making the authorization decision, then it opens the application to attack. For example,
  if the application only wants to allow access to http://www.example.com/mypage, then the attacker
  might be able to bypass this restriction using equivalent URLs such as: […]
  http://www.example.com/mypage/ (trailing /) […] Therefore it is important to specify access control
  policy that is based on the path information in some canonical form with all alternate encodings
  rejected (which can be accomplished by a default deny rule)." Mitigations: "Make access control
  policy based on path information in canonical form. Use very restrictive regular expressions to
  validate that the path is in the expected form." and "Reject all alternate path encodings that are
  not in the expected canonical form."
- CWE-288 "Authentication Bypass Using an Alternate Path or Channel"
  (https://cwe.mitre.org/data/definitions/288.html): "The product requires authentication, but the
  product has an alternate path or channel that does not require authentication." Mitigation:
  "Funnel all access through a single choke point to simplify how users can access a resource. For
  every access, perform a check to determine if the user has permissions to access the resource."
- CWE-424 "Improper Protection of Alternate Path" (https://cwe.mitre.org/data/definitions/424.html):
  "The product does not sufficiently protect all possible paths that a user can take to access
  restricted functionality or resources."
- OWASP Authorization Cheat Sheet
  (https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html): "Perform access
  control checks on *every* request for the *specific* object or functionality being accessed." and,
  under "Deny by Default", "the application cannot remain neutral when an entity is requesting access to
  a particular resource."
- Apache, quoted in section 3: decide on the filesystem object, because "many different webspace
  locations (URLs) could map to the same filesystem location".

A real case of exactly this shape: CVE-2025-0108, PAN-OS management interface (Searchlight Cyber,
2025-02-12, https://slcyber.io/research-center/nginx-apache-path-confusion-to-auth-bypass-in-pan-os-cve-2025-0108/):
nginx decided authentication from the URL (`if ($uri ~ ^\/unauth\/.+$) { set $panAuthCheck 'off'; }`),
Apache and mod_php then executed `/php/ztp_gate.php` with `PATH_INFO=/PAN_help/x.css.gz` for
`GET /unauth/%252e%252e/php/ztp_gate.php/PAN_help/x.css`. The rule was judged on one reading of the
path, the script was chosen from another.

My synthesis [inferred]: the decision should be made on the resource that will execute (the script,
as SCRIPT_NAME), not on the raw URL path; for a front controller, also on the route it will read from
PATH_INFO (the Magento `index.php/mageadmin` spelling). Every PATH_INFO form maps to that one
resource: `S`, `S/`, `S/anything`, `S/anything.php`, and whatever decodes to those.

## 8. Implications for agensio [inferred]

Context read in the tree today: `src/core/access.hpp` `other_readings` already judges the part after a
script ("/index.php/cp" reaches the route "/cp", `path.substr(php + 4)`), and `Router::suffix_hit`
(`src/core/router.hpp:68`) routes a `.php` suffix "at the end of the path or before a '/'", first hit,
case-sensitive. The missing reading is the script itself.

1. **Judge the script part as a reading of its own**: for a path whose router split gives script `S`
   and PATH_INFO `P` (non-empty, `/` included), judge `S` against the rules as well as the full path
   and `P`. That is Apache's `<Files>` semantics (rule follows the executed file) while keeping the
   decision before routing, and it fixes both `[[site.access]]` and `[[site.auth]]` at once. The
   alternative, letting every exact rule also cover `P/…`, matches Apache `<Location>`/Caddy `p p/*`
   but changes the meaning of exact rules on non-scripts (`/robots.txt/x` is a 404 anyway, so the
   difference is small, but the reading approach is narrower and needs no new rule syntax).
2. **Use the router's split, not a second one.** Caddy's CVE-2026-27590 and CVE-2026-45135 are what
   happens when two places split differently. The rule's split must equal `suffix_hit`'s (first `.php`
   ending a segment, the same case rule, the same normalised path). If a site has CGI or other script
   suffixes with PATH_INFO, derive the split from the location that will run the request rather than a
   hardcoded `.php/` (today `other_readings` hardcodes `.php/`).
3. **Cover all the forms the lab found**: `S/` (nginx and Apache give `PATH_INFO=/`, Caddy gives empty
   PATH_INFO and still runs `S`), `S/x`, `S/x.php` (the variant that gets through every nginx layout),
   and encoded slashes (agensio already answers 404 for `%2F` on filesystem locations; nginx and Caddy
   decode it into PATH_INFO).
4. **Exact rules are case-insensitive in agensio, script routing is case-sensitive**: judging the script
   reading with the same case-insensitive equality over-covers, which is safe.
5. **Prefix rules on a route need the after-script reading** (already there): `/index.php/admin` for a
   rule on `/admin`. Keep both readings for both rule kinds and for `refuse`.
6. **Tests worth adding** (from the lab matrix): exact rule on `/wp-login.php` against `/wp-login.php/`,
   `/wp-login.php/x`, `/wp-login.php/x.php`, `/WP-LOGIN.PHP/x` (should not route to PHP on Linux),
   `/wp-login.php%2Fx` (404), and an exact auth rule on `/update.php` against `/update.php/selection`.

## 9. Gaps

- OpenLiteSpeed and LSWS Enterprise: not run; context matching read in the source only; PATH_INFO
  handling of the script handler unknown.
- IIS: how `<location path>` applies to a URL with path info is not documented on the pages read; not
  run.
- nginx regex deny (`location ~* ^/wp-login\.php`), Apache `<FilesMatch "^wp-login\.php$">`: not run
  (behaviour follows from the documented rules).
- WordPress: that a POST login to `/wp-login.php/x` succeeds was not tested against a real WordPress;
  the lab shows only that the script runs.
- No nginx core-developer or php.net statement found that names this exact-rule/PATH_INFO gap; the
  nearest are the nginx Drupal recipe's comment, Francis Daly's list answer and the 2024 parser research.
- Traefik and HAProxy normalisation details (decoding, dot segments) were not re-checked for this
  question; see `research_notes/Web server IP access control/h2o_caddy_proxies.md`.

## Appendix: lab

Docroot `/srv/www` with `wp-login.php` and `index.php`, each:

```php
<?php echo "RAN ", basename(__FILE__), " SCRIPT_NAME=", $_SERVER['SCRIPT_NAME'] ?? '', " PATH_INFO=", $_SERVER['PATH_INFO'] ?? '', "\n";
```

php-fpm 8.4.26 pool on `0.0.0.0:9000`, stock `cgi.fix_pathinfo` (1). C′ used a second pool with
`-d cgi.fix_pathinfo=0`.

nginx 1.26.3, every server has `root /srv/www; index index.php; location / { try_files $uri $uri/
/index.php?$args; }` plus:

- A: `location = /wp-login.php { deny all; }` + `location ~ \.php$ { include snippets/fastcgi-php.conf; fastcgi_pass …; }` (Debian)
- B: `location = /wp-login.php { deny all; }` + nginx-wiki `location ~ [^/]\.php(/|$) { fastcgi_split_path_info ^(.+?\.php)(/.*)$; if (!-f $document_root$fastcgi_script_name) { return 404; } … PATH_INFO $fastcgi_path_info; }`
- C: `location = /wp-login.php { deny all; }` + WordPress-recipe `location ~ \.php$ { include fastcgi_params; fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; fastcgi_pass …; }`; C′ the same against the fix_pathinfo=0 pool
- D: `location ^~ /wp-login.php { deny all; }` + B's PHP location
- E: `location = /wp-login.php { auth_basic …; include fastcgi_params; … fastcgi_pass …; }` (handbook shape) + B's PHP location

Caddy 2.11.4, each site `root * /srv/www`, `php_fastcgi 127.0.0.1:9000`, `file_server`, plus:
F `basic_auth /wp-login.php { u <bcrypt> }`; G `@blocked { path /wp-login.php; not remote_ip
10.255.255.1 }` + `respond @blocked 403`; H the same with `path /wp-login.php /wp-login.php/*`.

Apache 2.4.69 (event MPM, mod_proxy, mod_proxy_fcgi), `<Directory /srv/www> Require all granted`, plus:
I `<Files "wp-login.php"> Require all denied` + `<FilesMatch "\.php$"> SetHandler "proxy:fcgi://lab-php:9000"`;
J `<Files "wp-login.php"> Require all denied` + `ProxyPassMatch "^/(.*\.php(/.*)?)$" "fcgi://lab-php:9000/srv/www/$1"`;
K `<Location "/wp-login.php"> Require all denied` + J's ProxyPassMatch;
L `<LocationMatch "^/wp-login\.php$"> Require all denied` + I's SetHandler;
M `<Location "/wp-login.php"> Require all denied` + I's SetHandler.

Output (status, then what ran):

```
== A nginx = deny + Debian ~ \.php$ snippet
  /wp-login.php          403
  /wp-login.php/         200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
  /wp-login.php/x        200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
  /wp-login.php/x.php    200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x.php
  /WP-LOGIN.PHP          200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
  /wp-login.php%2Fx      200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
  /wp-login.phpx         200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
== B nginx = deny + wiki [^/]\.php(/|$)
  /wp-login.php          403
  /wp-login.php/         200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/
  /wp-login.php/x        200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x
  /wp-login.php/x.php    200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x.php
  /WP-LOGIN.PHP          200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
  /wp-login.php%2Fx      200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x
  /wp-login.phpx         200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
== C nginx = deny + WP-recipe ~ \.php$ no split
  /wp-login.php          403
  /wp-login.php/         200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
  /wp-login.php/x        200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
  /wp-login.php/x.php    200 RAN wp-login.php SCRIPT_NAME=/wp-login.php/x.php PATH_INFO=
  /WP-LOGIN.PHP          200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
  /wp-login.php%2Fx      200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
  /wp-login.phpx         200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
== C' the same, php-fpm with cgi.fix_pathinfo=0
  /wp-login.php          403
  /wp-login.php/x.php    404   (error log: Unable to open primary script: /srv/www/wp-login.php/x.php)
== D nginx ^~ deny + wiki
  /wp-login.php          403
  /wp-login.php/         403
  /wp-login.php/x        403
  /wp-login.php/x.php    403
  /WP-LOGIN.PHP          200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
  /wp-login.php%2Fx      403
  /wp-login.phpx         403
== E nginx = auth_basic(+pass) + wiki
  /wp-login.php          401
  /wp-login.php/         200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/
  /wp-login.php/x        200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x
  /wp-login.php/x.php    200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x.php
  /WP-LOGIN.PHP          200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
  /wp-login.php%2Fx      200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x
  /wp-login.phpx         200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
== F caddy basic_auth /wp-login.php
  /wp-login.php          401
  /wp-login.php/         200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=
  /wp-login.php/x        200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x
  /wp-login.php/x.php    200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x.php
  /WP-LOGIN.PHP          401
  /wp-login.php%2Fx      200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x
  /wp-login.phpx         200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
== G caddy path /wp-login.php 403
  /wp-login.php          403
  /wp-login.php/         200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=
  /wp-login.php/x        200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x
  /wp-login.php/x.php    200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x.php
  /WP-LOGIN.PHP          403
  /wp-login.php%2Fx      200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x
  /wp-login.phpx         200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
== H caddy path /wp-login.php /wp-login.php/* 403
  /wp-login.php          403
  /wp-login.php/         403
  /wp-login.php/x        403
  /wp-login.php/x.php    403
  /WP-LOGIN.PHP          403
  /wp-login.php%2Fx      403
  /wp-login.phpx         200 RAN index.php SCRIPT_NAME=/index.php PATH_INFO=
== I apache Files + SetHandler
  /wp-login.php          403
  /wp-login.php/         403
  /wp-login.php/x        403
  /wp-login.php/x.php    403
  /WP-LOGIN.PHP          404
  /wp-login.php%2Fx      404
  /wp-login.phpx         404
== J apache Files + ProxyPassMatch
  /wp-login.php          200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=
  /wp-login.php/         200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/
  /wp-login.php/x        200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x
  /wp-login.php/x.php    200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x.php
  /WP-LOGIN.PHP          404
  /wp-login.php%2Fx      404
  /wp-login.phpx         404
== K apache Location + ProxyPassMatch
  /wp-login.php          403
  /wp-login.php/         403
  /wp-login.php/x        403
  /wp-login.php/x.php    403
  /WP-LOGIN.PHP          404
  /wp-login.php%2Fx      404
  /wp-login.phpx         404
== L apache LocationMatch ^...$ + SetHandler
  /wp-login.php          403
  /wp-login.php/         200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/
  /wp-login.php/x        200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x
  /wp-login.php/x.php    200 RAN wp-login.php SCRIPT_NAME=/wp-login.php PATH_INFO=/x.php
  /WP-LOGIN.PHP          404
  /wp-login.php%2Fx      404
  /wp-login.phpx         404
== M apache Location + SetHandler
  /wp-login.php          403
  /wp-login.php/         403
  /wp-login.php/x        403
  /wp-login.php/x.php    403
  /WP-LOGIN.PHP          404
  /wp-login.php%2Fx      404
  /wp-login.phpx         404
```
