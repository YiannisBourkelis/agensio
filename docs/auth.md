# Passwords in agensio: `[[site.auth]]`

How agensio puts an HTTP password (Basic authentication, RFC 7617) in front of a path: what
a rule says, how a request is decided, where the passwords live and who may change them,
what the application, the caches, the logs and fail2ban see, what health checks, and every
edge case we know of with what happens in it. Configuration examples are in section 10.

The reference for each key is `docs/configuration.md` section 19b (and section 15 for a
managed site's `rules.auth`); the design and its reasons are `docs/design-site-operations.md`
section 25; the survey of how nginx, Apache, Caddy, Traefik, HAProxy and others do it, and what
administrators complain about, is `reports/Web server basic authentication.md`. This document
describes what the code does as of 0.1.0-alpha.58.

## 1. What it is for, and what it is not

A password in front of a path, asked by the browser's own dialog, for things that have no
login of their own or should not be public yet:

- a staging copy of a site, the whole site behind a password;
- the admin area of a tool that has none (a statistics page, a phpMyAdmin, a file manager);
- a preview for a client, with an end date;
- a WordPress or Drupal admin, as a second wall, only when the owner asks for it.

It is not a user system: every user of a file reaches every path its rules protect (no
per-user paths), there is no logout (section 9), no two-factor, no LDAP or single sign-on,
no time-limited links. For those, an application's own login or a forward-auth gateway in
front is the answer.

Built only with libxcrypt (`crypt_rn`) and OpenSSL; a build without them refuses a
configuration that has a `[[site.auth]]` rule, so a path is never left open because the
check could not run (`agensio -t` says so).

## 2. Quick start

A hand-written site:

```sh
agensio passwd anna >> /etc/agensio/staging.users      # asks twice, prints anna:$y$...
chown root:agensio /etc/agensio/staging.users && chmod 640 /etc/agensio/staging.users
```

```toml
[[site]]
server_name = ["staging.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/staging/web"
tls = "auto"

[[site.auth]]
path = "/"
users = "/etc/agensio/staging.users"
realm = "Staging"
```

`agensio -t`, then `agensio reload`.

A managed site (the control plane, `agensio ctl` or the MCP tools):

```sh
agensio ctl site-auth-user-set staging.example.com anna --generate --yes --reason "staging"   # answers the password once
agensio ctl site-update staging.example.com --auth / --auth-realm Staging --yes --reason "staging behind a password"
```

## 3. A rule: `[[site.auth]]`

| key | type | default | meaning |
|---|---|---|---|
| `path` | string | required | the protected path; a prefix covers whole segments (`/private` covers `/private` and `/private/x`, never `/privately`), in any capitalisation; `/` is the whole site |
| `match` | `"prefix"` or `"exact"` | `"prefix"` | `exact`: this path, and the requests agensio runs as that script (section 5.1) |
| `users` | path | required, unless `open` | the users file (section 4); relative to the file the rule is in |
| `realm` | string, 1 to 64 characters, no `"`, `\` or control | the site's first name, or `"agensio"` | the name the browser's dialog shows; also separates the browser's remembered passwords |
| `open` | boolean | false | no password on this path below a protected one (a health check, a webhook); takes no `users` |
| `skip_for` | list of addresses, ranges or `@sets` | none | these clients are let in without a password (the office, a monitor); never `"any"` |
| `plain_http` | `"refuse"` or `"allow"` | `"refuse"` | `allow`: ask over plain HTTP from other hosts too (section 5.3) |
| `credentials` | `"pass"` or `"strip"` | `pass` on a site with a FastCGI location, else `strip` | whether the application receives the `Authorization` field (section 7) |
| `forward_user` | a header name | none | on a proxied site, the verified user name in this field; a client's own field of that name is dropped |

At most 32 rules per site (16 through `rules.auth`); the same path and match twice is refused.
The longest rule covering a path decides, as with the access rules, so a longer `open` rule
frees a path inside a protected one and a longer protected rule can use another file or realm.

## 4. The users file

One line per user, the htpasswd format with two optional fields:

```
# comments and blank lines are ignored
anna:$y$j9T$...:expires=2026-10-22:note=Anna, Acme (client review)
jose:$2b$12$...
old:$y$j9T$...:expires=2020-01-01
bob:!$y$j9T$...
```

- `name:hash`: a name of 1 to 255 bytes with no `:` or space (the tools write ASCII names of
  letters, digits and `._@+-`, so every client can send them).
- Accepted hashes (libxcrypt): yescrypt `$y$` (and `$gy$`), scrypt `$7$`, bcrypt `$2b$`
  `$2y$` `$2a$`, sha512crypt `$6$`, sha256crypt `$5$`. Refused at load, with the command to
  use instead: MD5 (`$apr1$`, htpasswd's old default, and `$1$`), `{SHA}`, `{SSHA}`, `{PLAIN}`,
  DES, `$2x$`. `htpasswd -B` (bcrypt) and `mkpasswd -m yescrypt` files read as they are;
  `agensio passwd [--method yescrypt|bcrypt|sha512] [--cost N] USER` writes a line.
- `:expires=YYYY-MM-DD`: from 00:00 UTC of that day the login is refused, right password or
  not. The day must exist (no 2026-02-30) and be 1970 or later.
- `:note=`: whose login it is, to the end of the line (colons allowed); shown by the tools.
- A hash of `!` or `*`, or one starting with `!`, is a locked user: every login refused. The
  tools lock by putting `!` before the hash, so an unlock gives the same password back.

Who may read it: the loader refuses a file that is a symlink, not a regular file, owned by
anyone but the owner of the main configuration (root on a packaged install), writable by its
group or others, readable by others (its hashes could be guessed offline), larger than 1 MB,
or with any line it cannot read (naming the line). A file with no user at all is refused too.
Root's, the server's group, `0640` is the shape: the server reads it after dropping its
privileges, nobody else can. A file several rules or sites name is read once per load.

## 5. How a request is decided

### 5.1 The order

For every request, before any location is chosen, in this order:

1. the path is normalised (percent-decoding, dot segments, duplicate slashes);
2. an ACME HTTP-01 challenge is answered (so `tls = "auto"` works on a protected site);
3. the site is found by its host; a site with `redirect = "https"` redirects;
4. `refuse` patterns (404);
5. the access rules, `[[site.access]]` (403);
6. **the password rules**;
7. the location, the method policy and the handler.

The rule that decides is the strictest over every reading of the path an application could
see (a `;parameter` in a segment, a second percent-decoding, the path after a script name),
the same readings the access rules judge. Each internal redirect (`try_files` fallbacks, a
front controller) and a directory's index file is checked again, so `/private/` serving
`/private/index.php`, a fallback to `/index.php`, or a `.php` location cannot step around a
rule (nginx's per-location `auth_basic` does not hold for a regex `.php` location; agensio's
rules are not attached to locations at all). Every method is covered, OPTIONS and TRACE too.

An exact rule covers its path and every request agensio runs as that same script: a PHP
location with path info runs `/wp-login.php/x` as `/wp-login.php`, a CGI location runs
`/cgi-bin/report/2026` as `/cgi-bin/report` when `report` is the file, and PHP serving
`/legacy/` runs `/legacy/index.php`; an exact rule on the script asks for the password on each
of them. The split is the PHP and CGI handlers' own (`core/script_split.hpp`), so nothing else
widens the rule: `/wp-login.phpx/y`, a static `/info.html/x` or a location with
`path_info = false` are not that script. On a proxied location agensio runs no script and an
exact rule covers its path alone; `-t` and health say so for a `.php` path there
(`exact_rule_proxied_script`), and a prefix rule covers both forms. Before 0.1.0-alpha.59 an
exact rule covered the path alone, and `/wp-login.php/x` reached the login page without a
password (the alpha.58 report).

### 5.2 Inside a protected path

1. `skip_for`: a client in the list is let in without a password and without a user name.
   Behind a proxy in `[server] trusted_proxies` the client is the one `X-Forwarded-For` names.
2. Plain HTTP (section 5.3).
3. No `Authorization` field, or another scheme (`Bearer ...`): `401` with the challenge.
4. A malformed one (bad base64, no colon, an empty user, a control character, a user over
   255 or a password over 512 bytes): `401`, and one `auth failed` line.
5. The connection's last verified value, the same bytes, for the same file, within five
   minutes: in, at the cost of one comparison (section 6).
6. The worker's cache of verified logins (an HMAC, section 6): in.
7. Otherwise the password is verified on the pool, off the worker's loop; the request waits,
   other requests on the worker go on. A success is remembered; a failure is one `auth failed`
   line and `401`. A full pool or eight verifications already in flight on the worker: `503`
   with `Retry-After: 1`.

The answers:

- `401 Unauthorized` with `WWW-Authenticate: Basic realm="<realm>", charset="UTF-8"` (the
  browser sends the password in UTF-8, RFC 7617 2.1) and `Cache-Control: no-store`; one page
  for a missing, a malformed and a wrong login and an unknown user, so the answer tells
  nothing about who exists.
- `403 Forbidden` for plain HTTP (below), with a page saying to use https.
- `503 Service Unavailable` with `Retry-After: 1` when verifications are saturated.

### 5.3 Plain HTTP

A password sent over plain HTTP can be read by anyone on the network path, and the browser
sends it again with every request. So unless the rule says `plain_http = "allow"`, a request
that is not on TLS, not from this host (loopback) and not forwarded as https by a trusted
proxy gets `403` with a page that says to use https, and is never asked. nginx and Apache ask
anyway. Behind a trusted proxy (`server.trusted_proxies`) the proxy's report decides, never its
own address: `X-Forwarded-Proto: https` makes the request https, and only a client it names in
`X-Forwarded-For` that is this host makes it local. So a tunnel or TLS terminator on the same
host (cloudflared, HAProxy) relaying a remote client's plain-HTTP request gets `403`, and one
that relays https must say so in `X-Forwarded-Proto` (every common proxy does; nginx needs
`proxy_set_header X-Forwarded-Proto $scheme`). Before 0.1.0-alpha.61 such a proxy's loopback
address got every client it relayed asked over plain HTTP (the alpha.58 report). On a managed site with https the plain listener only redirects (step 3 above), so this
applies to hand-written plain listeners and sites without https.

## 6. Verification and what it costs

The hash is slow by design (yescrypt and bcrypt take milliseconds to tens of milliseconds),
so it never runs on a worker's loop and is paid once per login, not per request:

- **The pool**: `clamp(cores / 4, 1, 4)` threads with a queue of 256; results posted back to
  the worker. At most eight verifications in flight per worker; beyond, `503`.
- **The worker's cache**: a verified login is remembered as HMAC-SHA256, under a key made
  once per process, of the user, the stored hash and the password: never the password itself.
  1,024 entries per worker (256 sets of four), five minutes each or until the user's
  `expires`, whichever is first. Because the stored hash is part of the key, a changed
  password, a lock and another file with the same user name never match. Failures are never
  remembered: every wrong password is verified again.
- **The connection's memo**: the last verified `Authorization` value with the file's load id,
  so the browser's next requests on the connection cost one comparison. A reload gives the
  file a new id, so the memo falls back to the cache.
- **An unknown user** is verified against a real entry of the file, the first one that is not
  locked, so the time an answer takes tells nothing about who exists, as long as every hash
  of the file is of one kind (method and cost). A file that mixes them, `htpasswd -B -C 5`
  lines next to yescrypt ones say, lets a guesser tell the names on the other kind apart:
  a wrong password for them answers faster or slower than an unknown name. `agensio -t` and
  health name those users (`auth_users_mixed_methods`, section 12); `agensio passwd NAME`
  writes yescrypt, which the control plane's tools always use.
- `status` reports `auth_verifications`, the hashes run since the start.

Measured (one worker, `bench/ab.sh -A`, `bench/results/ab-20261008-171903.md`): a protected
page with a remembered login costs 1.07 of the same page open, about 0.14 us per request;
sites without `[[site.auth]]` pay nothing.

## 7. What the application, the caches and the logs see

- **The `Authorization` field**: passed to PHP (`credentials = "pass"`, the default on a site
  with a FastCGI location: WordPress's loopback calls need it), stripped before any other
  application (`"strip"`). A client let in by `skip_for` was never asked, so its field is always
  stripped, whatever `credentials` says: PHP builds `PHP_AUTH_USER` and `PHP_AUTH_PW` from that
  field, and one nobody verified must not look like a login (before 0.1.0-alpha.61 it passed on
  a site that passes credentials, the alpha.58 report). An application that runs its own HTTP
  Basic login below a `skip_for` rule therefore gets no login from those clients: give its path
  `open = true`.
- **The user**: PHP and CGI get `REMOTE_USER` and `AUTH_TYPE = Basic`; a proxied application
  gets the name in the field `forward_user` names, and a client's own field of that name is
  dropped, so it cannot claim to be someone. A client let in by `skip_for` has no user.
- **Caches**: every answer on a protected path is one no shared cache (a CDN, Varnish, a
  caching proxy) may keep, so none serves it to someone without the password:
  - a file agensio serves itself carries `Cache-Control: private`, in place of a preset's
    `public` on uploads, `/build/` or `/static/`;
  - an answer of PHP, CGI or a proxied application keeps its own `Cache-Control` directives
    except `public`, `s-maxage` and `proxy-revalidate` (the ones only shared caches act on), and
    gets `private`: `public, max-age=3600` becomes `private, max-age=3600`, `no-store` becomes
    `private, no-store`, none becomes `private`; several fields become one;
  - the fields only CDNs act on are dropped: `CDN-Cache-Control` and every targeted field named
    `*-Cache-Control` (a CDN that follows one ignores `Cache-Control` and `Expires`, RFC 9213 2.2),
    `Surrogate-Control`, `Edge-Control`.

  Why it matters: a shared cache may reuse an answer to a request with a password when the answer
  says `public`, `s-maxage` or `must-revalidate` (RFC 9111 3.5), which a page-cache plugin does; and
  a client let in by `skip_for` sends no password at all, so its answers are ordinary ones to a
  cache. Before 2026-10-09 only the files agensio served itself were made private: a protected
  WordPress page with a cache plugin, behind a CDN, could have been served to anyone.
- **The access log**: the user field (`%u`, the third field; JSON `"user"`) is the verified
  user, `-` otherwise, never a name a refused request claimed.
- **The error log**: one `warn` line per failed login, the client first and what the client
  chose escaped after it, never the password:
  `auth failed: client 198.51.100.4 site shop.example realm "Shop staging" user "anna" (wrong password) GET /cart`.
  The reasons: `wrong password`, `unknown user`, `locked user`, `expired`, `malformed
  credentials`. The challenge writes nothing.

## 8. Managed sites: the users, the rule, the tools

### 8.1 The users file

The control plane keeps one file per managed site, `<config dir>/auth/<site>.users`, root's,
the server's group, `0640`, in a `0750` directory of root's, written by the provisioning helper
through a temporary file and a rename that never follows a symlink. Without the helper (a
server that runs as one account) the server's own account writes it.

| command | MCP tool | what it does |
|---|---|---|
| `agensio ctl site-auth-users NAME` | `site_auth_users` | names, hash methods, expiry, notes, locks; never a hash; `used`: whether a rule reads the file |
| `agensio ctl site-auth-user-set NAME USER --generate` | `site_auth_user_set` with `generate: true` | a new password made by the server, answered once |
| `agensio ctl site-auth-user-set NAME USER --prompt` | none | the password asked on this terminal (twice, not echoed; or one line of stdin) and hashed here; only the hash is sent |
| `--expires YYYY-MM-DD`, `--no-expiry`, `--note TEXT`, `--no-note`, `--lock`, `--unlock` | `expires`, `note`, `locked` | change a user without a new password |
| `agensio ctl site-auth-user-delete NAME USER` | `site_auth_user_delete` | removes one |

- A password never travels to the server. The generated one is sixteen lower-case letters and
  digits in four groups, `xxxx-xxxx-xxxx-xxxx`, without `0`, `1`, `l` or `o` (80 bits), hashed
  with yescrypt and kept nowhere. The API refuses a `password` field; the MCP bridge drops a
  `hash` an agent sends, so an agent can only generate.
- A new user needs `--generate` or `--prompt`. A new password unlocks a locked user.
- Every call is admin only and audited with the user's name and what changed, never a password
  or a hash.
- When a rule of the running configuration reads the file, a change reloads the server at
  once: a new password refuses the old one on the next request, a lock or a deletion takes
  effect on the next request. The last user of such a file cannot be deleted (lock it, or
  remove the rule first), because an empty file would make the next load refuse.

### 8.2 The rule: `rules.auth`

`site_update` with `rules.auth`, or on the command line:

```sh
agensio ctl site-update NAME --auth PATH [--auth-exact PATH] [--auth-open PATH] \
    [--auth-realm TEXT] [--auth-skip ADDR[,ADDR...]] [--auth-plain-http] --yes --reason "..."
agensio ctl site-update NAME --no-auth --yes --reason "..."
```

A list of `{"path": "/", "realm": "...", "skip_for": [...], "plain_http": true}` and `{"path":
"/health.html", "match": "exact", "open": true}`, rendered into the site file as `[[site.auth]]`
tables marked `# rules: auth`, reading `users = "../auth/<site>.users"`. The checks: at most 16
rules; the path syntax of the access rules; the same path twice refused; an open rule must lie
below a protected one and takes nothing else; `skip_for` never `"any"`; no `users` key (the
file is the site's own); the realm as in section 3.

The order is decided: **the site exists, then its first user, then its rule.** `rules.auth` is
refused while the site's users file is missing or empty (the answer names the command for the
first user), and refused on `site_create` altogether. So a rule never meets a file the loader
would refuse, and a deleted site's old file can never come into force unseen.

`site_show` lists every rule in force (`auth`: path, match, realm, users file, `users_count`,
`usable`, `skip_for`, `plain_http`, `from`: `rules`, `preset:wordpress` or nothing for a
hand-written one). `path_check SITE PATH` names the rule that decides a path (`auth`,
`auth_note`).

### 8.3 Deleting and restoring a site

`site_delete` with its files moves the users file into the trash with the rest of the site
(piece `auth`), and `site_restore` puts it back into the `0750` directory; so a site created
again under the name starts with no users. `site_delete` without its files leaves the file:
health reports it (`auth_users_orphan`) and `site_create` under the same name warns that it
exists, since a password rule would let its users in.

### 8.4 What the agent is told

The MCP texts tell an agent: offer a password for a staging copy, a tool without a login of its
own, a client's preview; never in front of a WordPress or Drupal admin unless the user asks;
add the first user, then the rule; relay a generated password once with the user name and
never repeat it; set `plain_http` only when the user asks, after saying the password then
crosses the network readable; a lost password is replaced, never recovered; a user who wants
to choose their own password runs `agensio ctl site-auth-user-set SITE USER --prompt` on the
server.

## 9. Edge cases

| situation | what happens |
|---|---|
| the users file is missing when the server starts or `agensio -t` runs | the configuration is refused (`[[auth]] #1.users: cannot open ...`); the server does not start (the packaged unit runs `agensio -t` first, so the message is in the journal) |
| the file has comments only, or no line at all | refused: `no users: the file needs at least one line name:hash` |
| the file is removed or broken while the server runs | nothing changes for requests: the running server keeps the users it loaded. `agensio reload` sets the site's file aside and keeps its running version (`docs/configuration.md` 12c), the other sites' changes apply; a restart would start without the site. Health reports `auth_users_unloadable` (an error). A site in the main file: the reload is refused and a restart would not start the server |
| the file has a wrong owner, a symlink, mode `0644` or `0660` | refused at load, with the `chown` or `chmod` to run |
| every user is locked or expired | the file loads; every login fails and the browser keeps asking. Health: `auth_no_valid_user` |
| a user expires while logged in | refused from 00:00 UTC of the day: the cache and the connection's memo never last past `expires` |
| a password changes (by hand and `reload`, or through the tools, which reload) | the old password is refused on the next request: the stored hash is part of the cache key |
| a user is deleted or locked | refused on the next request after the reload |
| `agensio reload` without a change | remembered logins stay valid (the cache survives; the memo falls back to it) |
| a browser asks again after a wrong password | each attempt is one `auth failed` line; a typo costs one hash |
| many wrong passwords from one address | each is verified (no failure is cached) and logged; the `agensio-auth` fail2ban jail bans after ten in ten minutes (section 11) |
| a flood of logins that each cost a hash | at most eight in flight per worker and a bounded queue; beyond, `503` with `Retry-After: 1`; the worker's loop never waits for a hash |
| an unknown user name | verified against a real entry, the same time as a known one; the same 401 |
| a users file whose hashes differ in method or cost (yescrypt next to sha512, bcrypt cost 5) | a wrong password for a user of another kind answers in another time than an unknown name, so the name can be told apart; `-t` and health note it (`auth_users_mixed_methods`) with the users to hash again |
| a non-ASCII password | the challenge says `charset="UTF-8"`, so browsers send UTF-8; it is hashed as those bytes. A file made with another encoding does not match |
| a password longer than 72 bytes with bcrypt | bcrypt uses the first 72 bytes only; yescrypt (the tools' choice) uses all of it |
| a password with a NUL or another control character | refused as malformed (a NUL would cut it for `crypt`) |
| `Authorization: Bearer ...` or another scheme on a protected path | treated as no credentials: `401` with the challenge. An API with its own tokens below a protected path needs an `open` rule or `skip_for` |
| an application with its own Basic login behind a protected path | a client sends one `Authorization` field: the outer rule takes it (and passes it on with `credentials = "pass"`), so both need the same user and password, or the application's path needs `open` |
| a monitor or an uptime check | give its path `open = true`, or its address `skip_for` |
| the ACME challenge (`tls = "auto"`) | answered before any rule, so certificates renew on a protected site |
| `/private` protected, request for `/PRIVATE/x`, `/private/./x`, `//private/x`, `/%70rivate/x` | all asked: the path is normalised and matched in any capitalisation |
| `/private` protected, request for `/privately` | not covered: a prefix covers whole segments |
| exact `/wp-login.php`, request for `/wp-login.php/x` or `/wp-login.php/` | asked: PHP runs `/wp-login.php` with path info, so the rule covers it (section 5.1) |
| exact `/cgi-bin/report` on a CGI location, request for `/cgi-bin/report/2026` | asked: the CGI handler runs `report` with `PATH_INFO = /2026` |
| exact `/info.php`, request for `/info.phpx/y` or `/info.php.bak/x` | not covered: no such script runs |
| exact `/x.php` on a proxied location, request for `/x.php/y` | not covered: agensio runs nothing there and cannot know what the application does; `-t` and health note it (`exact_rule_proxied_script`); use a prefix rule |
| `/private/` whose index file lives under another rule | the index is routed as its own request and decided by its own rule |
| a `.php` location or a `try_files` fallback to `/index.php` | checked on every hop, so a fallback cannot step from an open path into a protected one |
| HEAD, OPTIONS, TRACE, POST | all asked; the rules come before the method policy |
| plain HTTP from another host | `403` and a page saying to use https, unless `plain_http = "allow"`; loopback and trusted https-forwarding proxies are asked |
| a tunnel or TLS terminator on this host (in `trusted_proxies`) relaying a remote client's plain HTTP | `403`: the proxy's `X-Forwarded-Proto` and the client it names decide, not its own loopback address; with `X-Forwarded-Proto: https` the client is asked (before 0.1.0-alpha.61 it was asked either way) |
| behind a CDN or a proxy | `skip_for` judges the client `X-Forwarded-For` names only when the proxy is in `trusted_proxies`; otherwise the proxy's address |
| WordPress with `/wp-admin` protected | `admin-ajax.php`, the login page's `load-styles.php` and `load-scripts.php` (exactly) and its files under `/wp-admin/css`, `js` and `images` stay open (the public site and the login page call them; before 0.1.0-alpha.61 the two scripts were asked, and the login page came unstyled); not when the whole site is protected |
| HTTP/2 and HTTP/3 | the same rules, the same answers; the memo is per connection |
| several sites name one file | read once per load; each site's rules decide for that site |
| the same user name in two files | independent: different hashes, different cache keys |
| a managed site's rule before its first user | refused, with the command for the first user |
| `rules.auth` on `site_create` | refused: the first user comes after the site |
| a site deleted without its files, then created again | the old users file is still there: `site_create` warns, health says `auth_users_orphan`, and a rule added later would let those users in |
| a build without libxcrypt or OpenSSL | a configuration with `[[site.auth]]` is refused; nothing is left open |
| a shared cache (a CDN, Varnish) in front, and the application says `public, max-age=3600` | the answer goes out `private, max-age=3600`, so the cache does not keep it; a CDN's own field (`CDN-Cache-Control`, `Surrogate-Control`) is dropped |
| a client let in by `skip_for`, with a shared cache in front | the same: its answers are private too, though its request carries no password |
| a client let in by `skip_for` that sends `Authorization` anyway (a cached login, or a name it chose) | the field is removed before the application: PHP gets no `PHP_AUTH_USER`, `PHP_AUTH_PW` or `HTTP_AUTHORIZATION`, and no `REMOTE_USER` |
| the application sends `Cache-Control: no-store` | `private, no-store`: the browser keeps nothing either |
| logging out | Basic authentication has none: the browser keeps the password until it is closed (some keep it longer). To end someone's access, lock or delete the user, or change the password |

## 10. Configuration examples

**A staging copy behind a password, the office let in without one:**

```toml
[[site.auth]]
path = "/"
users = "/etc/agensio/auth/shop.users"
realm = "Shop staging"
skip_for = ["@office"]          # [addresses] office = ["203.0.113.0/24", "2001:db8:5::/64"] in the main file

[[site.auth]]
path = "/health"
match = "exact"
open = true                     # the load balancer's check needs no password
```

Managed: `agensio ctl site-update shop.example --auth / --auth-realm "Shop staging" --auth-skip @office --auth-open /health`.

**A client's review, with an end date:**

```sh
agensio ctl site-auth-user-set shop.example client --generate --expires 2026-10-22 --note "Acme, design review" --yes --reason "review"
```

**The admin area of a tool that has no login of its own:**

```toml
[[site.auth]]
path = "/stats"
users = "/etc/agensio/auth/stats.users"
realm = "Statistics"
```

**A second wall in front of WordPress's admin, when the owner asks for it:**

```toml
[[site.auth]]
path = "/wp-admin"
users = "/etc/agensio/auth/blog.users"
realm = "Blog admin"
# admin-ajax.php and the login page's own files stay open; the login page itself
# (/wp-login.php) is WordPress's; add a rule for it only if no visitor ever logs in there
```

**A tool on a trusted LAN over plain HTTP** (the password crosses the network readable):

```toml
[[site]]
server_name = ["nas.lan"]
listen = ["192.168.1.10:80"]
root = "/srv/nas-ui"

[[site.auth]]
path = "/"
users = "/etc/agensio/auth/nas.users"
plain_http = "allow"            # health keeps auth_plain_http as a warning
```

**A proxied application that wants the user's name:**

```toml
[[site]]
server_name = ["grafana.example.com"]
listen = ["0.0.0.0:443"]
tls = "auto"
app = "proxy"
upstream = "http://127.0.0.1:3000"

[[site.auth]]
path = "/"
users = "/etc/agensio/auth/grafana.users"
forward_user = "X-WEBAUTH-USER"   # the client's own X-WEBAUTH-USER is dropped
```

**A PHP application that reads `REMOTE_USER`:** nothing to add; PHP gets `REMOTE_USER` and
`AUTH_TYPE`, and `Authorization` too (the default `credentials = "pass"` on a PHP site).

**An API below a protected site:**

```toml
[[site.auth]]
path = "/"
users = "/etc/agensio/auth/app.users"

[[site.auth]]
path = "/api"
open = true                     # the API's own tokens (Authorization: Bearer) reach it
```

## 11. fail2ban

The `agensio-auth` jail reads the error log's `auth failed` lines, as fail2ban's own
`nginx-http-auth` and `apache-auth` read their servers' error logs, and bans after ten in ten
minutes for an hour. It counts a wrong password, an unknown or locked user and malformed
credentials; not an expired user's right password, and never the challenge: a `401` in the
access log is mostly every browser's first request to a protected path (and one per directory
on a site protected as a whole, RFC 7617 2.2), so counting `401`s would ban the people who have
the password. The filter is anchored at the date and `[warn] auth failed: client <ADDR>`, so a
user name holding `auth failed: client 1.2.3.4` cannot get someone else banned. It needs the
error log in a file at `warn` (`[log] error = "/var/log/agensio/error.log"`, the package's
default); otherwise the jail is rendered disabled with root's line. `403`s are `agensio-denied`'s
jail, over the access logs. A script or a monitor that keeps sending an old password is banned
like a guesser: give it the new password, an `open` path or `ignoreip`. `docs/fail2ban.md`
section 2c has the rest; `protection_show` renders the jail for the host.

## 12. Health

| code | severity | when | what to do |
|---|---|---|---|
| `auth_users_unloadable` | error | a rule's users file the next load would refuse (the loader's own checks, run against a scratch configuration) | put the file back or correct what the message names; `agensio -t` says when it loads. Until then a reload keeps the site's running version and a restart does not serve the site (a site in the main file: a reload is refused and a restart does not start) |
| `auth_no_valid_user` | warn | every user of a rule's file is locked or expired | unlock or extend one, add one, or remove the rule |
| `auth_users_expired` | info | users past their `expires` | delete those who are gone, or give a later date |
| `auth_plain_http` | warn | a rule with `plain_http` on a listener the network reaches (judged by the address: `[::1]` is loopback; `-t` says it too) | serve over https and drop `plain_http`, unless the network is trusted |
| `auth_users_mixed_methods` | info | a users file whose hashes differ in method or cost: a wrong password for a user of another kind answers in another time than an unknown name | hash those users again with one method (`agensio passwd NAME`, yescrypt), then `agensio reload` |
| `auth_users_orphan` | info | a users file under `<config dir>/auth/` no site owns | delete it as root, unless the site comes back |
| `exact_rule_proxied_script` | info | an exact rule on a `.php` path that a proxied location serves: agensio runs no script there and judges the path alone | if the application runs `/x.php/anything` as the same script, make the rule a prefix rule |
| `fail2ban_auth_challenges` | warn | the installed `agensio-auth` filter is an older build's that counts every `401` | install the filters again and render the jail |
| `fail2ban_auth_unseen` | warn | a site has a password and nothing counts its failed logins | the fix names the log setting or the jail to install |

## 13. Where it is in the code

| piece | file |
|---|---|
| users file parser, `Authorization` parser, verification, cache key, cache, pool | `src/core/auth.*` |
| `[[site.auth]]` parsing, the users file's checks, the WordPress openings, `--explain`, `auth_users_problem` | `src/config.cpp` (`parse_auth`, `load_auth_users`, `finalize_site`) |
| the rule matcher | `src/core/access.hpp` (`auth_rule_for`, `auth_protecting_rule`; `script_of`: the script a path runs, judged too) |
| the script and path info split, one copy for the handlers and the rules | `src/core/script_split.hpp` |
| the request path: the check, the challenge, the pool hand-off, the failure lines | `src/handlers/dispatch.cpp` (`check_auth`, `start_auth`, `auth_challenge`, `auth_failed_line`) |
| waiting for a verification | `src/http1/connection.hpp`, `src/http2/connection.hpp`, `src/http3/connection.hpp` (`HandlerKind::auth`) |
| `REMOTE_USER`, `forward_user`, the index rule | `src/handlers/fastcgi.cpp`, `proxy.cpp`, `static.cpp` |
| no answer a shared cache may keep: `Cache-Control: private`, the targeted fields dropped | `src/core/private_cache.hpp`, used by `handlers/upstream_common.cpp` (PHP, CGI, proxy) and `handlers/static.cpp` |
| a managed site's users file | `src/services/authusers.*`; the helper's `auth_users_op` in `src/services/provision.cpp` |
| the control API and the tools | `src/control/handler.cpp` (`site_auth_users`, `site_auth_user_change`, `auth_users_needed`), `src/control/mcp.cpp`, `src/main.cpp` (`agensio passwd`, `ctl`) |
| `rules.auth` | `src/control/sites.cpp` (`check_rules`, `render_site`) |
| `site_show`, `path_check`, health | `src/control/commands.cpp` (`auth_rule_json`, `path_check`, `auth_findings`) |
| fail2ban | `src/control/protection.cpp` (`kFilterAuth`, the `agensio-auth` jail), `packaging/fail2ban/` |
| tests | unit `test_auth_core`, `test_auth_config`, `test_exact_script_rules`, `test_auth_users`, `test_auth_managed`, `test_protection`; `tests/auth.sh`, `tests/provision.sh`, `tests/control.sh`, `tests/trash.sh`, `tests/protection.sh` |
