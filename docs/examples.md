# Configuration cookbook

Practical recipes for the jobs a system administrator does with agensio: a site on HTTPS, a PHP
application, an application behind the proxy, an admin kept to the office, a staging site
behind a password, a shared host with one account per site. Each recipe is a complete
configuration that loads as shown; `tests/examples.sh` holds every one of them to the binary,
so a recipe that stops working fails the test suite instead of misleading you.

The cookbook shows how to do a job. The reference says what every key does:
[configuration.md](configuration.md) section by section, [keys.md](keys.md) as one table,
and `agensio ctl reference` (MCP `config_reference`) with the values the running server uses.

## How a recipe reads

- **When:** the situation it is for, in a sentence or two.
- **The configuration:** one or two TOML blocks. Each starts with a comment naming the file it
  goes in: `/etc/agensio/agensio.toml` is the main file (root's), a site goes into
  `/etc/agensio/sites.d/<domain>.toml`. When a recipe needs something in the main file (a set
  of addresses, `[server] acme` for automatic certificates) it shows that part in its own
  block; the rest of your main file stays as it is.
- **What it does:** what a request meets, and the parts that are easy to get wrong.
- **Check it:** `agensio -t`, `agensio ctl path-check`, `curl`: how to see that it works.
- **On a managed site:** the same through the control plane, for a site that `site-create`
  wrote (`agensio ctl` in a shell, the MCP tools for an agent). A managed site's file is
  rewritten by the tools: change it through them, never by hand. What no tool covers goes into
  the site's root additions file ([configuration.md 15](configuration.md#15-control-socket)).
- **Reference:** the section of the reference that explains every key used.

Names and addresses are the documentation ranges (`example.com`, `203.0.113.0/24`,
`198.51.100.0/24`, `2001:db8::/32`), so nothing here points at a real host. Sites live under
`/var/www/<domain>/`, the default `sites_root`. A recipe on HTTPS shows its TLS site; the
plain-HTTP site that redirects port 80 to it is the same for every domain and shown once, in
[basics](examples/basics.md#https-with-a-certificate-agensio-obtains-itself).

## Applying a recipe

```sh
agensio -t -c /etc/agensio/agensio.toml          # validates everything, names any problem; --strict fails on a site file set aside
agensio -t --explain -c /etc/agensio/agensio.toml   # the effective configuration, presets expanded
agensio reload                                   # applies it; no connection is dropped
```

`agensio -t` warns when a php-fpm pool or an application it should talk to is not running yet;
start them and the warning goes. What a key needs (a reload, a restart, root) is in the
`applies` and `via` columns of [keys.md](keys.md).

## Basics: static sites, HTTPS, headers, logs

[examples/basics.md](examples/basics.md)

- [A static site](examples/basics.md#a-static-site): the smallest site; what `index` and hidden files do, and `/.well-known/` served anyway.
- [HTTPS with a certificate agensio obtains itself](examples/basics.md#https-with-a-certificate-agensio-obtains-itself): `[server] acme`, `tls = "auto"`, and the port-80 redirect every other recipe assumes.
- [HTTPS with certificate files you manage](examples/basics.md#https-with-certificate-files-you-manage): `tls = { cert, key }`, renewal by `agensio reload`, and a key the server's account can read.
- [Certificates from certbot](examples/basics.md#certificates-from-certbot): a wildcard over DNS-01, the key the server's account must read, renewals loaded by themselves or by a deploy hook, an existing `--webroot` certbot.
- [One canonical host](examples/basics.md#one-canonical-host): the bare name redirected to www in one hop, or the reverse.
- [Several sites on one address, and the catch-all](examples/basics.md#several-sites-on-one-address-and-the-catch-all): sites matched by name, certificates by SNI, 421 for unknown names, and one catch-all.
- [A mistake in one site's file](examples/basics.md#a-mistake-in-one-sites-file): one file set aside, the other sites served, its last good version kept on reload; `-t --strict`, health.
- [Long cache lifetimes for assets, and HSTS](examples/basics.md#long-cache-lifetimes-for-assets-and-hsts): `add_headers` per location, and when a location joins the preset's instead of replacing it.
- [A single-page application](examples/basics.md#a-single-page-application): `try_files` to the shell, with missing assets still answered 404.
- [An access log per site, and JSON logs](examples/basics.md#an-access-log-per-site-and-json-logs): `access_log`, `[log] format`, log rotation, and why JSON costs you fail2ban.
- [Larger uploads for one site](examples/basics.md#larger-uploads-for-one-site): a site's own `max_body_size`, the 413 and its error-log line, and the PHP pool's upload limits.
- [Pre-compressed files for clients that accept them](examples/basics.md#pre-compressed-files-for-clients-that-accept-them): `.br` and `.gz` copies beside a file, and `[cache] precompressed`.

## PHP applications

[examples/php.md](examples/php.md)

- [WordPress on its own account](examples/php.md#wordpress-on-its-own-account): `user` and the php-fpm pool agensio generates, what the preset runs and refuses, `agensio pools` and the php-fpm reload.
- [Laravel](examples/php.md#laravel): the project as `root` with `public/` served, only `/index.php` runs, and the project's secrets kept private.
- [Drupal](examples/php.md#drupal): the PHP that Drupal's own `.htaccess` lets run, `sites/default/files`, and `site-install` plus `site-copy` for `settings.php`.
- [Grav](examples/php.md#grav): only `index.php` runs, Grav's private directories, and why the preset must be the application's.
- [A PHP application without a preset, from its own rules](examples/php.md#a-php-application-without-a-preset-from-its-own-rules): `app = "php"` narrowed to Kanboard's entry points, front controller, cached assets and `refuse` patterns, or the same as `rules`.
- [Use a php-fpm pool you already run](examples/php.md#use-a-php-fpm-pool-you-already-run): `php = { socket }`, socket permissions, and pool keys that need a generated pool.
- [php-fpm in a container](examples/php.md#php-fpm-in-a-container): `remote_root`, a port published on 127.0.0.1 only, and `keep_conn` kept off through Docker.
- [Raise the upload and PHP limits of one site](examples/php.md#raise-the-upload-and-php-limits-of-one-site): `max_body_size`, the pool's PHP limits and `read_timeout`, or `--set` within `site_limits`.
- [Send PHP's output as it is produced](examples/php.md#send-phps-output-as-it-is-produced): `buffering = false` and what it costs in PHP children.
- [PHP in one directory of a static site](examples/php.md#php-in-one-directory-of-a-static-site): a final `/` and a `.php` suffix location, so scripts run under `/forms/` only.
- [Add headers to a preset's directory without losing its shield](examples/php.md#add-headers-to-a-presets-directory-without-losing-its-shield): an `add_headers`-only location joins the preset's; one more key replaces it. Root additions on a managed site.

## Applications behind the proxy

[examples/proxy.md](examples/proxy.md)

- [A Node.js application](examples/proxy.md#a-nodejs-application): `app = "node"`, the project's files refused at the edge, Node's 5 s keep-alive, the rendered unit.
- [A Rails application behind Puma](examples/proxy.md#a-rails-application-behind-puma): `app = "rails"`, precompiled assets from disk, Puma kept on loopback.
- [Django or Wagtail behind Gunicorn](examples/proxy.md#django-or-wagtail-behind-gunicorn): `app = "wagtail"`, `/static/` and `/media/` from disk, the upload limit.
- [A chat server with WebSockets (Rocket.Chat)](examples/proxy.md#a-chat-server-with-websockets-rocketchat): what needs nothing, `tunnel_timeout` when wanted, large uploads.
- [An IoT platform with device telemetry (ThingsBoard)](examples/proxy.md#an-iot-platform-with-device-telemetry-thingsboard): many small device posts, the per-worker pool and queue.
- [One path of a PHP site sent to another service](examples/proxy.md#one-path-of-a-php-site-sent-to-another-service): an `/api/` location with the prefix replaced, `final`, the root additions file.
- [Two application servers with passive health](examples/proxy.md#two-application-servers-with-passive-health): an upstream list, `max_fails`, restarts one at a time.
- [An origin over HTTPS](examples/proxy.md#an-origin-over-https): `proxy.tls` with `ca` and `server_name`, and why the name matters.
- [Choose the headers the origin and the client see](examples/proxy.md#choose-the-headers-the-origin-and-the-client-see): `host`, `headers`, `hide`, `forwarded`, merged per location.
- [Stream server-sent events and long downloads](examples/proxy.md#stream-server-sent-events-and-long-downloads): `buffering = false`, `request_buffering = false`, `handler = "proxy"`.
- [A legacy CGI script](examples/proxy.md#a-legacy-cgi-script): a CGI location, its interpreter, its index, the account it runs as.

## Protection: addresses, passwords, refused paths, fail2ban

[examples/protection.md](examples/protection.md)

- [Keep the WordPress admin to the office](examples/protection.md#keep-the-wordpress-admin-to-the-office): an address rule on `/wp-admin`, the public parts kept open.
- [Protect one script exactly, the login page included](examples/protection.md#protect-one-script-exactly-the-login-page-included): exact rules, and what PHP runs as the same script.
- [Try an address rule before it locks anyone out](examples/protection.md#try-an-address-rule-before-it-locks-anyone-out): report mode.
- [A staging site behind a password, the office without one](examples/protection.md#a-staging-site-behind-a-password-the-office-without-one): `[[site.auth]]`, `skip_for`, an open health check.
- [Temporary access for a client](examples/protection.md#temporary-access-for-a-client): a generated password with an end date.
- [A password in front of a proxied tool that wants the user's name](examples/protection.md#a-password-in-front-of-a-proxied-tool-that-wants-the-users-name): `forward_user`, the password kept from the application.
- [Refuse what an application never serves](examples/protection.md#refuse-what-an-application-never-serves): `refuse` patterns.
- [Judge the real client behind a CDN or load balancer](examples/protection.md#judge-the-real-client-behind-a-cdn-or-load-balancer): `trusted_proxies`.
- [Let fail2ban count failed logins](examples/protection.md#let-fail2ban-count-failed-logins): `login_paths` and the rendered jails.

## Hosting: accounts, the control plane, agents

[examples/hosting.md](examples/hosting.md)

- [The main file of a shared host](examples/hosting.md#the-main-file-of-a-shared-host): `[server] user`, `include`, logs in files, `[control]` with its role groups, `sites_root`, `trash_keep`, and a catch-all site.
- [One account per site](examples/hosting.md#one-account-per-site): `user` on each site, the generated php-fpm pools, `agensio pools`, and what `agensio -t` refuses.
- [Create a site through the control plane](examples/hosting.md#create-a-site-through-the-control-plane): `site-create` from its open questions through `--dry-run` to the file it writes, with or without the root helper.
- [Install an application into a managed site](examples/hosting.md#install-an-application-into-a-managed-site): `site-install` from the preset's archive, an https URL or an upload, plus a drop-in copied with `site-copy`.
- [Something no field covers: the root additions file](examples/hosting.md#something-no-field-covers-the-root-additions-file): an alias outside the root, a header on one path and another upstream, in `<domain>.root.toml`.
- [Delete a site and get it back](examples/hosting.md#delete-a-site-and-get-it-back): disable, `site-delete --files`, the trash, `site-restore`, `trash_keep`.
- [Who may do what: roles and the audit log](examples/hosting.md#who-may-do-what-roles-and-the-audit-log): admins, operators and viewers by group, the reads only an admin gets, and the audit line.
- [Let an AI agent manage the host](examples/hosting.md#let-an-ai-agent-manage-the-host): `agensio mcp` over SSH on a key that may run the bridge and nothing else.
- [A host a panel manages](examples/hosting.md#a-host-a-panel-manages): site files a panel writes in the recommended layout, and `host_protection = "external"`.

## Protocols and capacity: HTTP/2, HTTP/3, limits

[examples/protocols.md](examples/protocols.md)

- [HTTP/2 on every HTTPS site](examples/protocols.md#http2-on-every-https-site): on by default over TLS, what a client gets, `max_concurrent_streams`.
- [Switch HTTP/2 off while a client misbehaves](examples/protocols.md#switch-http2-off-while-a-client-misbehaves): `protocols = ["h1"]`, and the info lines that name the trouble.
- [HTTP/2 without TLS on a backend network](examples/protocols.md#http2-without-tls-on-a-backend-network): h2c on one private listener behind a load balancer.
- [HTTP/3 next to HTTP/2](examples/protocols.md#http3-next-to-http2): `"h3"`, UDP in the firewall, the buffer sysctl, `alt_svc` and `retry`.
- [Different protocols for one site](examples/protocols.md#different-protocols-for-one-site): a site's own `protocols`, and why it needs an address of its own.
- [Workers and connection limits on a small VPS](examples/protocols.md#workers-and-connection-limits-on-a-small-vps): `workers`, `max_connections`, `idle_timeout`, and what a refused client gets.
- [Request size and time limits](examples/protocols.md#request-size-and-time-limits): `max_header_size`, `max_body_size` per site, `body_timeout`; 431 and 413.
- [The file cache for a site with many large files](examples/protocols.md#the-file-cache-for-a-site-with-many-large-files): `[cache]` sizes, open descriptors, revalidation.
- [Reload without dropping a connection](examples/protocols.md#reload-without-dropping-a-connection): what a reload applies and what needs a restart.

## Adding a recipe

A change that adds or changes something an administrator configures adds or updates its
recipe in the same change (CLAUDE.md, working agreement). A recipe is a `## ` heading in the
category's file, listed here with a one-line summary. Its TOML blocks must load with
`agensio -t` as written: `tests/examples.sh build/agensio` moves the paths they name into a
scratch tree, creates the directories, certificates and users files there, and fails on any
warning but an unreachable php-fpm or origin. A recipe that shows a warning on purpose names
it on a `# expect: TEXT` line; one that shows a refused configuration, on a
`# expect-error: TEXT` line. `agensio ctl` lines are checked against `agensio ctl --help`, the
names on a `**MCP:**` line against the MCP server, and every link, anchor included.
