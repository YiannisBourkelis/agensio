# HTTP Basic authentication in nginx and Apache httpd 2.4

Scope note on versions (checked 2026-10-08): nginx's changelog now tops out at mainline **1.31.6 (15 Sep 2026)**; 1.31.0 shipped 13 May 2026 and 1.29.8 on 7 Apr 2026, so "1.27-1.29" is already one mainline series behind — [nginx CHANGES](https://nginx.org/en/CHANGES). The httpd 2.4.x branch CHANGES file starts with "Changes with Apache 2.4.70", with 2.4.67 carrying a 2026 CVE, so 2.4.6x/2.4.70 is current. 2.4.70 may still be unreleased (not verified) — [httpd 2.4.x CHANGES](https://github.com/apache/httpd/blob/2.4.x/CHANGES). Where these notes say "source", the code was read from GitHub master (nginx) or 2.4.x (httpd) on 2026-10-08.

## 1. Configuration syntax and scoping

### Takeaway
nginx sets auth per configuration level (http/server/location/limit_except). Only one location ever handles a request, so a sibling regex location such as `location ~ \.php$` silently escapes auth set on `location /admin/`. Apache merges every matching section in a fixed order (Directory, then Files, then Location, then If). Authorization in a later section replaces the earlier one unless `AuthMerging` is set. A protected `<Directory>` therefore covers PHP files too, but a `<Location>` can silently override it.

### Cited Findings
**nginx**
- `auth_basic string | off;` defaults to `auth_basic off;`. It is allowed in `http, server, location, limit_except`, and its parameter is the realm. Variables are allowed since 1.3.10/1.2.7. "The special value off cancels the effect of the auth_basic directive inherited from the previous configuration level." — [nginx auth_basic docs](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html)
- `auth_basic_user_file file;` has no default and the same contexts; the file name can contain variables — [nginx auth_basic docs](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html)
- **Source:** both values merge with `ngx_conf_merge_ptr_value`, so a child level inherits the parent's realm and file unless it sets its own. The handler returns `NGX_DECLINED` (no auth) when either is unset, or when the realm *evaluates at run time* to the literal `off`, so a variable that expands to "off" also disables auth. The handler is pushed onto `NGX_HTTP_ACCESS_PHASE` — [ngx_http_auth_basic_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_auth_basic_module.c)
- Location selection: nginx first finds the longest matching prefix location. It then checks regular expressions in configuration order, and the first regex match wins. Only "if the longest matching prefix location has the '^~' modifier" are regexes skipped — [nginx core docs, location](https://nginx.org/en/docs/http/ngx_http_core_module.html#location). (The current docs also mention "predicate locations", checked after regexes.)
- The regex-location pitfall, as described on the nginx mailing list: "nginx will only ever execute one location", so the auth directives must also cover the PHP location. Valentin V. Bartenev's recommended fix nests the PHP location inside a protected `^~` prefix location:
  ```
  location ^~ /passwordprotected {
      auth_basic "foo"; auth_basic_user_file foo;
      location ~ \.php$ { fastcgi_pass foo; include fastcgi_params; } }
  ```
  — [nginx mailing list, 2011-12](https://mailman.nginx.org/pipermail/nginx/2011-December/031004.html)
- Official pattern for protecting the whole site except one area: `auth_basic` and `auth_basic_user_file` at `server` level, plus `location /public/ { auth_basic off; }` — [NGINX admin guide: HTTP Basic auth](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-http-basic-authentication/)
- Change in 1.31.0 (13 May 2026): "the ngx_http_tunnel_module; support for authenticating to proxies in the 'auth_basic', 'satisfy', and 'auth_delay' directives" — [nginx CHANGES](https://nginx.org/en/CHANGES). In source, `ngx_http_proxy_auth(r)` is defined as `(r)->method == NGX_HTTP_CONNECT`. For CONNECT, auth_basic reads `Proxy-Authorization` and answers 407 with `Proxy-Authenticate` — [ngx_http_request.h](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_request.h), [ngx_http_core_module.c](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.c). (In 1.21.1, "now nginx always returns an error for the CONNECT method" — [CHANGES](https://nginx.org/en/CHANGES).)
- Neither nginx's shipped `nginx.conf` nor any default protects the password file: the `location ~ /\.ht { deny all; }` block is shipped *commented out* ("deny access to .htaccess files, if Apache's document root concurs with nginx's one") — [nginx conf/nginx.conf](https://github.com/nginx/nginx/blob/master/conf/nginx.conf)

**Apache httpd 2.4**
- The directives are `AuthType None|Basic|Digest|Form`, `AuthName`, `AuthBasicProvider` (default `file`), `AuthUserFile` and `Require`. All work in `directory, .htaccess` context (Override `AuthConfig`) — [mod_authn_core](https://httpd.apache.org/docs/2.4/mod/mod_authn_core.html), [mod_auth_basic](https://httpd.apache.org/docs/2.4/mod/mod_auth_basic.html), [mod_authn_file](https://httpd.apache.org/docs/2.4/mod/mod_authn_file.html)
- "When authentication is enabled, it is normally inherited by each subsequent configuration section, unless a different authentication type is specified." `AuthType None` disables it, and the official example uses `<Directory "/www/docs/public"> AuthType None / Require all granted </Directory>`. Caveat: "clients which have already authenticated ... will typically continue to send authentication HTTP headers" — [mod_authn_core AuthType](https://httpd.apache.org/docs/2.4/mod/mod_authn_core.html#authtype)
- `AuthName` accepts expression syntax since 2.4.55 (e.g. `AuthName "%{HTTP_HOST}"`), as does `AuthType`. "Most modern browsers no longer show the realm string, as it could be abused for phishing", but the realm "is still used to scope credentials" — [mod_authn_core](https://httpd.apache.org/docs/2.4/mod/mod_authn_core.html)
- `AuthMerging Off | And | Or` defaults to Off. Authorization "is normally inherited by each subsequent configuration section, unless a different set of authorization directives is specified". With And/Or, a section's authorization is combined with "the nearest predecessor" as if both sat inside `<RequireAll>` or `<RequireAny>` — [mod_authz_core AuthMerging](https://httpd.apache.org/docs/2.4/mod/mod_authz_core.html#authmerging). A nested section with `Require all granted` (AuthMerging Off) therefore replaces the parent's `Require valid-user`.
- Merge order: (1) `<Directory>` (non-regex) and `.htaccess`, (2) `<DirectoryMatch>`, (3) `<Files>`/`<FilesMatch>`, (4) `<Location>`/`<LocationMatch>`, (5) `<If>`. `<Directory>` goes from shortest path to longest; the other groups follow configuration order. `<VirtualHost>` sections apply after the main server's, and for mod_proxy `<Proxy>` takes the place of `<Directory>` — [httpd sections: How the sections are merged](https://httpd.apache.org/docs/2.4/sections.html#merging)
- Security warning: authorization in `Location` sections that overlap filesystem content "overwrite[s] authorization configuration in Directory, and Files sections" — [mod_authz_core Require](https://httpd.apache.org/docs/2.4/mod/mod_authz_core.html#require)
- "Caution: `<Limit>` inside `<Location>` can silently grant access": for methods not listed, the enclosing Location "is treated as having no authorization requirements — which effectively grants access and overrides any `<Directory>` restrictions"; use `<LimitExcept>` — [httpd sections](https://httpd.apache.org/docs/2.4/sections.html)
- Apache's default `httpd.conf` ships `<Files ".ht*"> Require all denied </Files>` — [httpd docs/conf/httpd.conf.in](https://github.com/apache/httpd/blob/2.4.x/docs/conf/httpd.conf.in). The AuthUserFile docs still say to store the file "outside the document tree ... Otherwise, clients may be able to download the AuthUserFile" — [mod_authn_file](https://httpd.apache.org/docs/2.4/mod/mod_authn_file.html)

### Inferences
- In Apache, `<Directory /var/www/admin>` with `Require valid-user` still applies to `/admin/x.php` handed to PHP-FPM through a `<FilesMatch \.php$> SetHandler proxy:fcgi...`, because sections merge rather than one being chosen. The nginx pitfall does not exist there in that form. The Apache equivalent is a `<Location>` or `<LimitExcept>`/`<Limit>` that overrides or empties the Directory's authorization.
- nginx's `off` check works by comparing the evaluated realm string. A design that copies it should treat "off" as a keyword, not as a realm value.

### Gaps
- I did not verify whether nginx re-runs the access phase (and so auth_basic) after an internal redirect from `try_files` or `error_page` into a location with different auth settings. The nginx docs do not say.

## 2. Password file formats and hash algorithms

### Takeaway
Both servers implement apr1 MD5 and {SHA} themselves, and nginx also implements {SSHA} and {PLAIN}; everything else goes to the system `crypt()`. Apache bundles its own bcrypt (`$2y$`/`$2a$`) through APR, so bcrypt works on any platform. nginx verifies bcrypt, sha256/512-crypt and yescrypt only if the libc's or libxcrypt's `crypt_r()` supports them. Today's Linux libxcrypt and musl do support bcrypt. `htpasswd` still defaults to apr1 MD5; `-B` (bcrypt, default cost 5) is opt-in.

### Cited Findings
**nginx**
- File format: `# comment`, `name1:password1`, `name2:password2:comment`. Supported types: crypt() (generated "using the htpasswd utility ... or the openssl passwd command"); apr1; and RFC 2307 `{scheme}data` (1.0.3+). The implemented schemes are PLAIN ("an example one, should not be used"), SHA (1.3.13; "plain SHA-1 hashing, should not be used ... vulnerable to rainbow table attacks"; added "only to aid in migration") and SSHA ("used by ... OpenLDAP and Dovecot") — [nginx auth_basic docs](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html)
- **Source:** `ngx_crypt()` checks the prefixes `$apr1$`, `{PLAIN}`, `{SSHA}` and `{SHA}`; anything else is the "fallback to libc crypt()" — [ngx_crypt.c](https://github.com/nginx/nginx/blob/master/src/core/ngx_crypt.c). `ngx_libc_crypt()` calls `crypt_r()` with a stack `struct crypt_data` when `NGX_HAVE_GNU_CRYPT_R`, else plain `crypt()`, and otherwise returns an error. A failure is logged at crit as `"crypt_r() failed"` — [ngx_user.c](https://github.com/nginx/nginx/blob/master/src/os/unix/ngx_user.c)
- **Source:** the computed hash is compared with `ngx_strcmp(encrypted, passwd->data)`, which is not constant-time — [ngx_http_auth_basic_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_auth_basic_module.c)
- Maxim Dounin (nginx, 2017): "In nginx there is no native support for bcrypt passwords as produced by Apache's htpasswd. On the other hand, nginx can use all password schemes supported by crypt(3) on your OS ... it would be enough to change the prefix in the password hashes from Apache-specific $2y$ to the one supported by your OS." — [nginx mailing list, 2017-06](https://mailman.nginx.org/pipermail/nginx/2017-June/054130.html)
- libxcrypt supports "yescrypt, gost-yescrypt, sm3-yescrypt, scrypt, bcrypt, sha512crypt, sha256crypt, sm3crypt, md5crypt, SunMD5, sha1crypt, NT, bsdicrypt, bigcrypt, and descrypt" through the classic `crypt`/`crypt_r` API — [libxcrypt README](https://github.com/besser82/libxcrypt/blob/develop/README.md). From its crypt(5): "The alternative prefix '$2y$' is equivalent to '$2b$'"; bcrypt's maximum passphrase length is 72 characters; yescrypt (`$y$`) is "Recommended for new hashes"; sha512crypt's default cost is 5000 — [libxcrypt crypt.5](https://github.com/besser82/libxcrypt/blob/develop/doc/crypt.5)
- glibc: libcrypt was "no longer built by default" in 2.38, and in 2.39 "libcrypt has been removed from the GNU C Library ... The replacement for libcrypt is libxcrypt" — [glibc NEWS](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=NEWS;hb=HEAD)
- musl's `crypt_blowfish.c` handles the `$2y$` prefix ("Prefix "$2y$": bug = 0, safety = 0") — [musl src/crypt/crypt_blowfish.c](https://git.musl-libc.org/cgit/musl/plain/src/crypt/crypt_blowfish.c)
- Historical nginx fixes: 1.3.10 "'crypt_r() failed' errors might appear if the 'auth_basic' directive was used on Linux"; 1.5.6 "Bugfix: in the ngx_http_auth_basic_module when using '$apr1$' password encryption method"; 1.31.3 "Bugfix: in the ngx_http_auth_basic_module on Solaris" — [nginx CHANGES](https://nginx.org/en/CHANGES)
- A Docker docs pull request is titled "nginx does not support bcrypt when using auth_basic" (contents not reviewed) — [docker/docs PR #4332](https://github.com/docker/docker.github.io/pull/4332/files)

**Apache**
- Five Basic formats: bcrypt (`$2y$` + APR's crypt_blowfish); MD5 (`$apr1$`, "iterated (1,000 times) MD5 digest" with a random 32-bit salt); SHA1 (`{SHA}` + base64 SHA-1, "Insecure"); CRYPT ("Unix only", "first 8 characters", "Insecure"); PLAIN TEXT ("Windows & Netware only. Insecure"). "OpenSSL knows the Apache-specific MD5 algorithm" (`openssl passwd -apr1`) — [httpd password formats](https://httpd.apache.org/docs/2.4/misc/password_encryptions.html)
- **Source, `apr_password_validate()`:**
  - `$2a$`/`$2y$` go to APR's built-in `_crypt_blowfish_rn`.
  - `$apr1$` goes to `apr_md5_encode`.
  - `{SHA}` goes to `apr_sha1_base64`.
  - Anything else goes to the system `crypt_r()`. If only `crypt()` exists, it runs under a mutex.
  - On WIN32/BEOS/NETWARE/Android the stored value is compared as plaintext.
  - All comparisons use `strneq_timingsafe`/`streq_timingsafe`.

  — [apr-util crypto/apr_passwd.c (1.6.x)](https://github.com/apache/apr-util/blob/1.6.x/crypto/apr_passwd.c). So `$5$`, `$6$` and `$y$` work in Apache only where the system crypt supports them, the same as in nginx.
- `htpasswd` options and defaults — [htpasswd docs](https://httpd.apache.org/docs/2.4/programs/htpasswd.html):
  - `-m` MD5: "This is the default (since version 2.2.18)".
  - `-B` bcrypt: "currently considered to be very secure".
  - `-C cost`: bcrypt only, "default: 5, valid: 4 to 17". "The apr-util library enforces a maximum number of rounds of 17 in version 1.6.0 and later."
  - `-2`/`-5`: SHA-256/SHA-512 crypt, "supported on most Unix platforms".
  - `-r rounds`: default 5,000.
  - `-d` crypt: "limits the password length to 8 characters ... insecure ... used to be the default algorithm until version 2.2.17".
  - `-s` SHA-1: "insecure".
  - `-p` plaintext: the daemon accepts it only on Windows/Netware.
  - `-v` verify: 2.4.5+.
  - `-i` reads the password from stdin. `-b` puts the password on the command line ("discouraged").
  - Usernames are limited to 255 bytes and may not contain `:`.
- Source confirms the default `ctx.alg = ALG_APMD5` and `BCRYPT_DEFAULT_COST` for `-B` — [support/htpasswd.c](https://github.com/apache/httpd/blob/2.4.x/support/htpasswd.c), [support/passwd_common.c](https://github.com/apache/httpd/blob/2.4.x/support/passwd_common.c)
- Version history from the CHANGES file — [httpd CHANGES](https://github.com/apache/httpd/blob/2.4.x/CHANGES):
  - htpasswd/htdbm gained bcrypt in 2.4.4 ("requires apr-util 1.5 or higher").
  - htpasswd gained SHA-2 passwords in the 2.4.59 section ("htpasswd: Add support for passwords using SHA-2").
  - htpasswd has used MD5 by default on all platforms since the 2.3.3 section.
- Doc inconsistency: htpasswd's page says "The MD5 algorithm used by htpasswd is specific to the Apache software; passwords hashed using it will not be usable with other Web servers" — [htpasswd docs](https://httpd.apache.org/docs/2.4/programs/htpasswd.html). nginx's docs contradict this, since apr1 is a supported type — [nginx auth_basic docs](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html).
- mod_authn_file: one line per user, `user:hash`. "If the same user ID is defined multiple times, mod_authn_file will use the first occurrence"; "searching large text files is very inefficient; AuthDBMUserFile should be used instead"; Basic and Digest data cannot be mixed in one file — [mod_authn_file](https://httpd.apache.org/docs/2.4/mod/mod_authn_file.html). htdbm manages the DBM files used by mod_authn_dbm — [htdbm docs](https://httpd.apache.org/docs/2.4/programs/htdbm.html)
- `AuthBasicUseDigestAlgorithm MD5` (2.4.7+) checks Basic passwords against Digest-style `user:realm:password` MD5 stores, so a site can move from Digest to Basic without resetting passwords — [mod_auth_basic](https://httpd.apache.org/docs/2.4/mod/mod_auth_basic.html#authbasicusedigestalgorithm)

### Inferences
- A file written with `htpasswd -B` (`$2y$05$...`) verifies in nginx on Linux distributions whose libcrypt is libxcrypt, and on musl. It fails (500, "crypt_r() failed") where the libc crypt lacks Blowfish, e.g. old glibc-only libcrypt. Which distro images ship libxcrypt was not checked one by one.
- nginx's plain `strcmp` of the hash output leaks little in practice (the attacker compares hashes, not passwords). It is still weaker hygiene than APR's timing-safe compare; nginx's `auth_delay` (section 6) addresses response timing more broadly.

### Gaps
- I found no official nginx statement listing which crypt schemes the official nginx.org packages or Docker images support. That depends on the build host's libc and is not documented.
- I did not fetch htdbm's algorithm options in detail.

## 3. How verification runs: per request or cached, and what it costs

### Takeaway
Neither server caches a successful verification in its released code. For every request, including each image and stylesheet on a protected page, nginx opens and reads the password file and runs the hash inside the worker's event-loop thread. Apache 2.4 does the same per request inside a worker thread. Only httpd trunk (unreleased) adds a per-connection memo of the last (password, hash, result). `mod_authn_socache` caches the provider's stored hash to spare SQL/LDAP lookups, but it still runs the hash on every request. bcrypt therefore costs per request: about 4 ms at cost 5, doubling with each cost step.

### Cited Findings
- **nginx source, per request:** the handler calls `ngx_open_file()` on the user file and reads it in `NGX_HTTP_AUTH_BUF_SIZE` (2048-byte) chunks with `ngx_read_file()`. It scans line by line for the user, calls `ngx_crypt()` synchronously, closes the file and zeroes the buffer (`ngx_explicit_memzero`). There is no cache of the file or of results anywhere in the module — [ngx_http_auth_basic_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_auth_basic_module.c)
- nginx file errors: `ENOENT` gives 403 with an error-level log line; any other open error gives 500 at crit (`open() "..." failed`) — [same source](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_auth_basic_module.c)
- Cost measured by an nginx developer: "with 2^5 rounds (default used by htpasswd) it takes about 4 milliseconds here on a test box". The test was 1,000 iterated `crypt()` calls of `$2b$05$` in 3.884 s user time. This answered a question about whether bcrypt "would block nginx causing it to slow down severely"; Dounin replied that "All password hashing schemes are intentionally slow ... The question is how slow a particular hashing scheme is, and if it is acceptable for a particular use case." — [nginx mailing list, 2017-06](https://mailman.nginx.org/pipermail/nginx/2017-June/054130.html)
- **Apache source, per request:** mod_authn_file's `check_password` runs `ap_pcfg_openfile()`, scans with `ap_cfg_getline()`, closes the file, then calls `apr_password_validate()` (2.4.x) — [mod_authn_file.c 2.4.x](https://github.com/apache/httpd/blob/2.4.x/modules/aaa/mod_authn_file.c)
- Apache's own docs: "your username and password must be verified every time you request a document from the server ... for every image on the page ... proportional to the size of the password file, because it has to open up that file, and go down the list of users ... you can expect to see slowdowns once you get above a few hundred entries" — [httpd auth howto, Possible problems](https://httpd.apache.org/docs/2.4/howto/auth.html)
- **httpd trunk only:** `ap_password_validate(r, user, passwd, hash)` keeps a `struct pw_cache` in `r->connection->notes`. If the same password and hash come again on the connection, it returns the cached result without re-hashing — [httpd trunk server/util.c](https://github.com/apache/httpd/blob/trunk/server/util.c). The 2.4.x `util.c` has no `ap_password_validate`, and 2.4.x mod_authn_file and mod_authn_socache call `apr_password_validate` directly — [2.4.x server/util.c](https://github.com/apache/httpd/blob/2.4.x/server/util.c), [2.4.x mod_authn_socache.c](https://github.com/apache/httpd/blob/2.4.x/modules/aaa/mod_authn_socache.c)
- mod_authn_socache "Maintains a cache of authentication credentials, so that a new backend lookup is not required for every authenticated request". It was motivated by mod_authn_dbd load, where a page with "hundreds of objects" triggers hundreds of authenticated requests. "Authentication by file (mod_authn_file) or dbm (mod_authn_dbm) are unlikely to benefit"; mod_authnz_ldap has its own cache. Configuration: list `socache` before the real provider in `AuthBasicProvider`, plus `AuthnCacheProvideFor dbd`. Further settings — [mod_authn_socache](https://httpd.apache.org/docs/2.4/mod/mod_authn_socache.html):
  - `AuthnCacheTimeout` defaults to 300 s.
  - `AuthnCacheContext` defaults to `directory` ("the most conservative") and is not allowed in .htaccess, because shared contexts can become "a vector for cross-site or cross-application security breaches".
  - `AuthnCacheSOCache` picks a dbm, dc, memcache or shmcb backend.
- **Source, what the cache stores:** providers call `AUTHN_CACHE_STORE(r, user, NULL, file_password)` with the *stored hash*. On a hit, socache's `check_password` retrieves the hash and still calls `apr_password_validate(password, val)` — [mod_authn_file.c](https://github.com/apache/httpd/blob/2.4.x/modules/aaa/mod_authn_file.c), [mod_authn_socache.c](https://github.com/apache/httpd/blob/2.4.x/modules/aaa/mod_authn_socache.c)
- socache history: the maximum cached string grew from 100 to 256 in 2.4.42 (PR 62149). CVE-2026-33007, "A NULL pointer dereference in the mod_authn_socache in Apache HTTP Server 2.4.66 and earlier allows an unauthenticated remote user to crash a child process in a caching forward proxy configuration", is fixed in 2.4.67 — [httpd CHANGES](https://github.com/apache/httpd/blob/2.4.x/CHANGES)
- Field report (Apache, MediaWiki behind Basic auth with htpasswd bcrypt): page loads with all assets took 5.68 s at cost 10, 6.77 s at 12, 10.78 s at 14, 25.72 s at 16 and 88.85 s at 18. Recommendation: "For basic auth, use something very fast: perhaps 9 or less" — [End Point Dev blog, 2016](https://www.endpointdev.com/blog/2016/02/bonked-by-basicauth-because-bcrypt/)
- Other servers face the same issue: Traefik has an issue titled "improve basic auth performance by caching expensive password hashing computations" (contents not reviewed) — [traefik #7897](https://github.com/traefik/traefik/issues/7897)
- libxcrypt describes itself as "intended to be fast and lightweight enough for use in servers that must field thousands of login attempts per minute" — [libxcrypt README](https://github.com/besser82/libxcrypt/blob/develop/README.md)

### Inferences
- In nginx, a bcrypt check stalls every connection on that worker for its duration: about 4 ms at cost 5, about 128 ms at cost 10, scaling as 2^cost from Dounin's figure. One worker can then serve at most about 250 cost-5 authenticated requests per second per core, plus a file open/read/close for each. In Apache's threaded MPMs it ties up one worker thread instead.
- apr1 (1,000 MD5 iterations) and {SSHA} are orders of magnitude cheaper per request, which is why such deployments do not notice the per-request design. I did not find benchmark numbers for apr1.
- The trunk per-connection memo removes the cost for keep-alive and HTTP/2 connections that resend the same header. A per-worker cache keyed by (hash of the Authorization value, file identity) would do the same across connections, at the price of holding verified credentials in memory.

### Gaps
- No published nginx benchmark of req/s with bcrypt vs apr1 auth_basic. The openHAB community thread "NGINX Basic Auth extremely slow with OH3 Main UI" appeared in search but was not read.
- I could not tell whether nginx uses thread pools (`aio threads`) for this file read. The code calls `ngx_read_file` directly, so in practice it is a synchronous pread.

## 4. Combining with IP allow lists

### Takeaway
nginx: `satisfy all` (default) requires every access module (allow/deny, auth_basic, auth_request, auth_jwt, ...) to pass. `satisfy any` lets the first one that passes grant access, and a 401 takes precedence over a 403 so that the browser still prompts. Apache: several `Require` lines in one section are an implicit `<RequireAny>`. So `Require ip ...` plus `Require valid-user` means IP **or** password, a common surprise; `<RequireAll>` gives AND.

### Cited Findings
**nginx**
- `satisfy all | any;` defaults to `all` and works in `http, server, location`. It "Allows access if all (all) or at least one (any) of the ngx_http_access_module, ngx_http_auth_basic_module, ngx_http_auth_request_module, ngx_http_auth_jwt_module (1.13.10), or ngx_http_auth_oidc_module (1.27.4) modules allow access." The example is `satisfy any; allow 192.168.1.0/32; deny all; auth_basic ...` — [nginx core docs, satisfy](https://nginx.org/en/docs/http/ngx_http_core_module.html#satisfy)
- Admin guide: both scenarios ("must be both authenticated and have a valid IP address" / "either authenticated, or have a valid IP address"); "Note that the allow and deny directives will be applied in the order they are defined." — [NGINX admin guide](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-http-basic-authentication/)
- **Source, `ngx_http_core_access_phase`:**
  - Under `SATISFY_ALL`, each handler must return OK; any 401 or 403 finalizes the request.
  - Under `any`, the first OK sets `r->access_code = 0`, clears the pending `WWW-Authenticate`/`Proxy-Authenticate` headers (`h->hash = 0`) and skips the remaining access handlers.
  - A 403, 401 or 407 is remembered in `r->access_code`, with 401/407 never overwritten by 403, and the next handler runs.
  - A final 401/407 goes through `ngx_http_core_auth_delay()`.

  — [ngx_http_core_module.c](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.c)
- 1.5.7 bugfix: "the 'satisfy any' directive might return 403 error instead of 401 if auth_request and auth_basic directives were used" — [nginx CHANGES](https://nginx.org/en/CHANGES)
- `ngx_http_auth_jwt_module` "is available as part of our commercial subscription" — [nginx auth_jwt docs](https://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html)

**Apache**
- "When multiple Require directives are used in a single configuration section and are not contained in another authorization directive like `<RequireAll>`, they are implicitly contained within a `<RequireAny>` directive. Thus the first one to authorize a user authorizes the entire request" — [mod_authz_core Require](https://httpd.apache.org/docs/2.4/mod/mod_authz_core.html#require)
- Result states: each provider returns Granted, Denied or Neutral. `<RequireAny>` is granted if at least one grants. `<RequireAll>` is granted if none denies and at least one grants. `<RequireNone>` never grants. Negated `Require not` "can never independently authorize a request" and is not permitted inside `<RequireAny>`/`<RequireNone>` — [mod_authz_core, Authorization containers and result states](https://httpd.apache.org/docs/2.4/mod/mod_authz_core.html#logic)
- Generic providers: `Require all granted|denied`, `env`, `method`, `expr`. mod_authz_host adds `Require ip 10 172.20 192.168.2` and `Require forward-dns` — [mod_authz_core](https://httpd.apache.org/docs/2.4/mod/mod_authz_core.html#require)
- The 2.2 directives `Order`, `Allow`, `Deny` and `Satisfy` moved to mod_access_compat. "Mixing old directives like Order, Allow or Deny with new ones like Require is technically possible but discouraged" — [httpd auth howto](https://httpd.apache.org/docs/2.4/howto/auth.html)
- `AuthzSendForbiddenOnFailure On` sends 403 instead of 401 "if authentication succeeds but authorization fails" (2.3.11+). The security warning: it "reveals to a possible attacker, that his guessed password was right" — [mod_authz_core](https://httpd.apache.org/docs/2.4/mod/mod_authz_core.html#authzsendforbiddenonfailure)

### Inferences
- The two servers default to opposite combination modes. nginx's `satisfy all` is AND across modules. Apache's implicit RequireAny is OR across `Require` lines in one section.
- A combined design should name the mode explicitly, e.g. `allow = [...]` plus `password = ...` with `mode = "any" | "all"`. It should also return 401, not 403, when either path could still succeed, matching nginx's access_code precedence, so browsers show the prompt.

### Gaps
- I did not collect specific Server Fault threads on the RequireAny confusion; the official doc wording above is the primary source.

## 5. What the upstream/backend receives

### Takeaway
By default both servers forward the client's `Authorization` header to HTTP backends: nginx `proxy_pass`, and Apache `mod_proxy_http`, which strips only `Proxy-Authorization` after authenticating. They differ for FastCGI and CGI. nginx passes it as `HTTP_AUTHORIZATION`, so PHP-FPM fills `PHP_AUTH_USER`/`PHP_AUTH_PW`, but nginx's shipped `fastcgi_params` sets no `REMOTE_USER`. Apache sets `REMOTE_USER`/`AUTH_TYPE` but hides `Authorization` from CGI/FastCGI unless `CGIPassAuth On`. The front server's Basic credentials collide with a backend that uses `Authorization` itself, because a client has only one such header.

### Cited Findings
**nginx**
- `proxy_pass_request_headers on;` is the default: it "Indicates whether the header fields of the original request are passed to the proxied server" — [nginx proxy docs](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass_request_headers). The proxy module has no special handling of `Authorization` (grep of [ngx_http_proxy_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_proxy_module.c)).
- "If the value of a header field is an empty string then this field will not be passed to a proxied server" — [proxy_set_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header). Igor Sysoev answered a user whose `proxy_hide_header Authorization` did not work with "`- proxy_hide_header Authorization;` / `+ proxy_set_header Authorization "";`" — [nginx mailing list, 2010-12](https://mailman.nginx.org/pipermail/nginx/2010-December/023966.html)
- Collision example, nginx Basic in front of Apache with LDAP Basic: with the header forwarded, the backend tried the nginx credentials ("auth_ldap authenticate: user <NGINX USER> authentication failed"). Backend credentials sent by the client instead failed at nginx with `user "<BACKEND USER>" was not found in "/etc/nginx/htpasswd"` — [nginx mailing list, 2011-08](https://mailman.nginx.org/pipermail/nginx/2011-August/028874.html)
- `fastcgi_pass_request_headers on;` is the default — [nginx fastcgi docs](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_pass_request_headers). **Source:** a request header is sent as `HTTP_<NAME>` unless a `fastcgi_param` of that name exists in the params hash, in which case the header is skipped (`ignored[header_params++]`) — [ngx_http_fastcgi_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_fastcgi_module.c)
- The shipped `fastcgi_params` contains REMOTE_ADDR, REMOTE_PORT, SERVER_*, REQUEST_SCHEME, HTTPS etc., but **no** `REMOTE_USER` or `AUTH_TYPE` — [nginx conf/fastcgi_params](https://github.com/nginx/nginx/blob/master/conf/fastcgi_params)
- `$remote_user` is the "user name supplied with the Basic authentication" — [nginx core docs, variables](https://nginx.org/en/docs/http/ngx_http_core_module.html#var_remote_user). **Source:** the variable calls `ngx_http_auth_basic_user()`, which only decodes the header. It is set whether or not the password was verified, and in locations without auth_basic — [ngx_http_variables.c](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_variables.c). The default `combined` format is `$remote_addr - $remote_user [$time_local] ...` — [ngx_http_log_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_log_module.c)
- PHP-FPM reads `HTTP_AUTHORIZATION` and calls `php_handle_auth_data()`, which base64-decodes a `Basic ` value into `auth_user`/`auth_password` (`PHP_AUTH_USER`/`PHP_AUTH_PW`) — [php-src sapi/fpm/fpm/fpm_main.c](https://github.com/php/php-src/blob/master/sapi/fpm/fpm/fpm_main.c), [php-src main/main.c](https://github.com/php/php-src/blob/master/main/main.c)

**Apache**
- **mod_proxy source:** `if (r->user != NULL /* we've authenticated */ && !apr_table_get(r->subprocess_env, "Proxy-Chain-Auth")) apr_table_unset(r->headers_in, "Proxy-Authorization");` Only Proxy-Authorization is removed; `Authorization` is forwarded — [proxy_util.c 2.4.x](https://github.com/apache/httpd/blob/2.4.x/modules/proxy/proxy_util.c)
- `CGIPassAuth On|Off` (default Off, 2.4.13+): "Normally these HTTP headers are hidden from scripts. This is to disallow scripts from seeing user ids and passwords used to access the server when HTTP Basic authentication is enabled". It replaces the compile-time `SECURITY_HOLE_PASS_AUTHORIZATION` and applies to everything using `ap_add_common_vars()`: mod_cgi, mod_cgid, mod_proxy_fcgi, mod_proxy_scgi, mod_include, mod_ext_filter — [httpd core, CGIPassAuth](https://httpd.apache.org/docs/2.4/mod/core.html#cgipassauth)
- **Source, `ap_add_common_vars`:** `Authorization`/`Proxy-Authorization` are skipped unless `cgi_pass_auth == AP_CGI_PASS_AUTH_ON`. `REMOTE_USER` is added from `r->user` (plus `REDIRECT_REMOTE_USER`), and `AUTH_TYPE` from `r->ap_auth_type` — [server/util_script.c 2.4.x](https://github.com/apache/httpd/blob/2.4.x/server/util_script.c)
- `AuthBasicFake username [password]` (2.4.5+) builds an Authorization header from expressions "which is passed to the server or service behind the webserver" (e.g. from `%{SSL_CLIENT_S_DN_Email}`); `AuthBasicFake off` disables it — [mod_auth_basic](https://httpd.apache.org/docs/2.4/mod/mod_auth_basic.html#authbasicfake)
- The Apache idiom `RequestHeader unset Authorization` (mod_headers) for stripping the header before a backend is referred to in the nginx thread above ([2010-12](https://mailman.nginx.org/pipermail/nginx/2010-December/023966.html)); the mod_headers page itself was not fetched.

### Inferences
- PHP-FPM behind Apache `mod_proxy_fcgi` sees `REMOTE_USER` but **not** `PHP_AUTH_USER`/`PHP_AUTH_PW` unless `CGIPassAuth On`, because PHP derives those only from `HTTP_AUTHORIZATION`. Behind nginx it is the reverse: `PHP_AUTH_*` are present and `REMOTE_USER` is not, unless the admin adds `fastcgi_param REMOTE_USER $remote_user;`.
- Because nginx's `$remote_user` is not verified, anything passing it on, or logging it on 401s, carries an attacker-chosen string. Apache's `%u` has the same caveat (section 6).
- Based on the hash-skip logic, `fastcgi_param HTTP_AUTHORIZATION "" if_not_empty;` should drop the header from FastCGI. That is the same mechanism as the httpoxy mitigation `fastcgi_param HTTP_PROXY "";`, but I have not tested it.

### Gaps
- I did not verify current PHP mod_php (apache2handler) behaviour, which sets PHP_AUTH_* from Apache's request record directly. It is not relevant to FPM setups.

## 6. Responses, logging and fail2ban

### Takeaway
Both servers answer 401 with exactly `WWW-Authenticate: Basic realm="..."`, with no `charset="UTF-8"` parameter (RFC 7617), and compare raw bytes. nginx logs unknown-user and wrong-password at error level and missing credentials at info. Apache logs AH01617/AH01618 and nothing for a request that simply had no credentials. fail2ban ships `nginx-http-auth` and `apache-auth` filters keyed on those exact strings.

### Cited Findings
**nginx**
- **Source:** the challenge is built as `"Basic realm=\"" + realm + "\""` into `WWW-Authenticate`, or into `Proxy-Authenticate` with 407 for CONNECT, and returns `NGX_HTTP_UNAUTHORIZED`. No charset parameter is ever added — [ngx_http_auth_basic_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_auth_basic_module.c)
- **Source, header parsing (`ngx_http_auth_basic_user`):**
  - The scheme `Basic ` is matched case-insensitively and leading spaces are skipped.
  - The value is base64-decoded and split at the first `:`.
  - An empty user (`len == 0`), a missing colon, bad base64 or another scheme all count as "no credentials" and get a fresh 401.

  — [ngx_http_core_module.c](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.c)
- Log lines (source):
  - info: `no user/password was provided for basic authentication`
  - error: `user "%V" was not found in "%s"`
  - error: `user "%V": password mismatch`
  - crit: `crypt_r() failed`
  - err or crit: `open() "<file>" failed`, giving 403 or 500

  — [ngx_http_auth_basic_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_auth_basic_module.c), [ngx_user.c](https://github.com/nginx/nginx/blob/master/src/os/unix/ngx_user.c). 1.5.7 changed "a logging level of auth_basic errors about no user/password provided ... from 'error' to 'info'" — [nginx CHANGES](https://nginx.org/en/CHANGES)
- Real log sample: `2011/08/31 13:01:19 [error] 6541#0: *5 user "<BACKEND USER>" was not found in "/etc/nginx/htpasswd", client: <my IP>, server: <NGINX IP>, request: "GET / HTTP/1.1", host: "<NGINX IP>"` — [nginx mailing list, 2011-08](https://mailman.nginx.org/pipermail/nginx/2011-August/028874.html)
- `auth_delay 0s;` (1.17.10+, http/server/location) "Delays processing of unauthorized requests with 401 response code to prevent timing attacks when access is limited by password, by the result of subrequest, or by JWT" — [nginx core docs](https://nginx.org/en/docs/http/ngx_http_core_module.html#auth_delay). 1.31.0 extended it to proxy auth — [CHANGES](https://nginx.org/en/CHANGES)
- fail2ban `nginx-http-auth.conf` details — [fail2ban filter.d/nginx-http-auth.conf](https://github.com/fail2ban/fail2ban/blob/master/config/filter.d/nginx-http-auth.conf):
  - `mdre-auth = ^user "<F-USER>...</F-USER>":? (?:password mismatch|was not found in "[^\"]*")$`, plus a PAM variant.
  - Prefix and suffix come from `nginx-error-common.conf` with `, client: <ADDR>`.
  - Aggressive mode adds `SSL_do_handshake() failed` lines.
  - `journalmatch = _SYSTEMD_UNIT=nginx.service + _COMM=nginx`.
  - The dev notes say: "Extensive search of all nginx auth failures not done yet."

**Apache**
- **Source:** `note_basic_auth_failure()` sets `WWW-Authenticate` (or `Proxy-Authenticate` for proxy requests) to `Basic realm="<AuthName>"` in `err_headers_out`, with no charset — [mod_auth_basic.c 2.4.x](https://github.com/apache/httpd/blob/2.4.x/modules/aaa/mod_auth_basic.c)
- Log messages (source, 2.4.x) — [mod_auth_basic.c](https://github.com/apache/httpd/blob/2.4.x/modules/aaa/mod_auth_basic.c):
  - No Authorization header: 401 with **no** log line.
  - `AH01614: client used wrong authentication scheme: %s`
  - `AH01617: user %s: authentication failure for "%s": Password Mismatch`
  - `AH01618: user %s not found: %s`
  - `AH01615: need AuthName: %s`, giving 500.
  - `AH01620: Could not open password file: %s`, giving AUTH_GENERAL_ERROR and 500.

  Note that `get_basic_auth()` sets `r->user` "even though the user is unauthenticated at this point".
- 2.4.36: "mod_auth_basic: Be less tolerant when parsing the credencial. Only spaces should be accepted after the authorization scheme. \t are also tolerated." — [httpd CHANGES](https://github.com/apache/httpd/blob/2.4.x/CHANGES)
- Provider chain: providers are "queried in order until a provider finds a match for the requested username ... A failure to verify the password does not result in control being passed on to subsequent providers" — [mod_auth_basic AuthBasicProvider](https://httpd.apache.org/docs/2.4/mod/mod_auth_basic.html#authbasicprovider)
- Access log `%u`: "Remote user if the request was authenticated. May be bogus if return status (%s) is 401 (unauthorized)." It is part of the Common Log Format `"%h %l %u %t \"%r\" %>s %b"` — [mod_log_config](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html)
- fail2ban `apache-auth.conf` matches — [fail2ban filter.d/apache-auth.conf](https://github.com/fail2ban/fail2ban/blob/master/config/filter.d/apache-auth.conf), [apache-common.conf](https://github.com/fail2ban/fail2ban/blob/master/config/filter.d/apache-common.conf):
  - `client (?:denied by server configuration|used wrong authentication scheme)`
  - `user <F-USER>...</F-USER> (?:auth(?:oriz|entic)ation failure|not found|denied by provider)`
  - `Authorization of user ... to access ... failed`
  - `user X: password mismatch`
  - several Digest nonce/realm errors and SNI mismatches, with an optional `AH\d+: ` prefix.

  Its notes: "An unauthorized response 401 is the first step for a browser to instigate authentication however apache doesn't log this as an error. Only subsequent errors are logged."

**Charset (RFC 7617)**
- RFC 7617 lets servers send `charset="UTF-8"` in the challenge, the only allowed value, e.g. `WWW-Authenticate: Basic realm="foo", charset="UTF-8"`. The parameter cannot appear in the credentials — [RFC 7617](https://rfc-editor.org/rfc/rfc7617)
- Firefox 59 switched Basic credentials from ISO-8859-1 to UTF-8. The bug discussion notes "the rest of the ecosystem (Chrome, curl, nginx, and likely others) have settled on utf8", and the change "actually broke some sites" — [Mozilla bug 1419658](https://bugzilla.mozilla.org/show_bug.cgi?id=1419658)

### Inferences
- Neither server normalises (NFC) or transcodes credentials: both compare the decoded bytes against the hash input. Non-ASCII passwords work only when the hash was made from the same UTF-8 bytes the browser sends. Sending `charset="UTF-8"` would be a pure improvement that neither incumbent offers.
- nginx's realm accepts variables and is wrapped in quotes without escaping. A realm containing `"` could inject extra challenge parameters, which is a hack for adding charset and also a header-integrity concern if the realm ever came from request data. I did not test this or find it documented.
- For fail2ban compatibility, a new server that reuses nginx's error-log wording (`user "X": password mismatch`, `user "X" was not found in "file"`, followed by `, client: ADDR`) would match `nginx-http-auth` unchanged.

### Gaps
- I found no official nginx or Apache statement on charset support. The absence is inferred from source.

## 7. HTTPS: does either refuse or warn about Basic over plain HTTP?

### Takeaway
Neither refuses or warns. Both accept auth_basic/AuthType Basic on plain-HTTP listeners, and neither the configuration check nor the run time complains. Apache's howto advises mod_ssl. nginx's module page says nothing about transport security.

### Cited Findings
- Apache howto: "Basic authentication sends the password from the client to the server unencrypted. This method should therefore not be used for highly sensitive data, unless accompanied by mod_ssl." On Digest: it "was intended to be more secure. This is no longer the case and the connection should be encrypted with mod_ssl instead." Also: "If your data really needs to be secure, consider using mod_ssl in addition to any authentication." — [httpd auth howto](https://httpd.apache.org/docs/2.4/howto/auth.html)
- nginx's auth_basic page lists directives, file format and hash warnings only, with no HTTPS caveat — [nginx auth_basic docs](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html). The NGINX admin guide example protects an `api` location on `listen 192.168.1.23:8080` (plain) — [NGINX admin guide](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-http-basic-authentication/)
- **Source:** neither `ngx_http_auth_basic_handler` nor `authenticate_basic_user` checks the connection's TLS state — [ngx_http_auth_basic_module.c](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_auth_basic_module.c), [mod_auth_basic.c](https://github.com/apache/httpd/blob/2.4.x/modules/aaa/mod_auth_basic.c)

### Inferences
- A newer server could warn at `-t` (or refuse unless overridden) when a password-protected area is reachable on a plain listener without a redirect to HTTPS. Neither incumbent does, so there is no compatibility constraint here.

### Gaps
- Browser behaviour for Basic over HTTP (e.g. "Not secure" warnings in the prompt) was not researched.

## 8. Delegating to an external authentication service

### Takeaway
nginx's `auth_request` (1.5.4+, not built by default) makes a subrequest per request to an internal location. 2xx allows, 401/403 deny (the subrequest's `WWW-Authenticate` is passed on), and anything else is an error. It combines with Basic and IP rules through `satisfy`. Apache's built-in counterpart is `mod_authnz_fcgi` (FastCGI authorizer, TCP only), alongside provider modules for DBM, SQL (dbd) and LDAP, all chained with `AuthBasicProvider`.

### Cited Findings
**nginx**
- auth_request rules — [nginx auth_request docs](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html):
  - "If the subrequest returns a 2xx response code, the access is allowed. If it returns 401 or 403, the access is denied with the corresponding error code. Any other response code returned by the subrequest is considered an error. For the 401 error, the client also receives the 'WWW-Authenticate' header from the subrequest response."
  - It needs `--with-http_auth_request_module`.
  - Contexts are `http, server, location`, and the directive takes `auth_request uri | off`.
  - `auth_request_set $variable value` can read `$upstream_http_*`.
  - "Before version 1.7.3, responses to authorization subrequests could not be cached".
  - The example uses `proxy_pass_request_body off; proxy_set_header Content-Length ""; proxy_set_header X-Original-URI $request_uri;`.
- "As the request body is discarded for authentication subrequests, set the proxy_pass_request_body directive to off and also set the Content-Length header to a null string"; the subrequest runs "for each request to /private" — [NGINX admin guide: subrequest authentication](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/)
- 1.23.0 bugfix: with "multiple 'WWW-Authenticate' header lines in the backend response and ... the 'auth_request' directive was used, nginx only sent the first of the header lines" — [nginx CHANGES](https://nginx.org/en/CHANGES)
- `auth_jwt` is commercial (NGINX Plus) — [nginx auth_jwt docs](https://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html). `ngx_http_auth_oidc_module` (1.27.4) is listed under `satisfy` — [nginx core docs](https://nginx.org/en/docs/http/ngx_http_core_module.html#satisfy). Whether it is open source was not verified.

**Apache**
- mod_authnz_fcgi "allows FastCGI authorizer applications to authenticate users and authorize access to resources". It supports generic FastCGI authorizers (one phase) and httpd-specific authenticators/authorizers. Its modes are authn via `AuthBasicProvider`, authz via `Require`, and authnz via `check_user_id`. Limitations: "Only TCP sockets are currently supported"; no mod_authn_socache support; providers registered `AP_AUTH_INTERNAL_PER_CONF` — [mod_authnz_fcgi](https://httpd.apache.org/docs/2.4/mod/mod_authnz_fcgi.html)
- Basic providers: mod_authn_dbm, mod_authn_file, mod_authn_dbd, mod_authnz_ldap and mod_authn_socache. `AuthBasicAuthoritative Off` passes to "non-provider-based modules" (third-party) when no provider matched — [mod_auth_basic](https://httpd.apache.org/docs/2.4/mod/mod_auth_basic.html)
- `AuthType Form` is provided by mod_auth_form — [mod_authn_core AuthType](https://httpd.apache.org/docs/2.4/mod/mod_authn_core.html#authtype)

### Inferences
- nginx's model (an HTTP subrequest per request, no built-in result cache unless `proxy_cache` is configured on the auth location) costs the same per request as Basic with bcrypt plus a round trip. It is the usual way nginx deployments put SSO (oauth2-proxy, Authelia) in front of an application.

### Gaps
- Third-party Apache modules (mod_auth_openidc, mod_authnz_external) and nginx's community modules (PAM, LDAP) were not researched.
- I did not verify the license or availability of nginx's `auth_oidc`.
