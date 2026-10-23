# Changelog

## 0.1.0-alpha.112

- **`server_status` says what waits for a restart** (the test host's note on alpha.111). While HTTP/3
  waits for a restart after a reload that could not bind it, only the listener's protocol list
  (`["h2","h1"]`) showed it: `protocols` rightly says the build supports h3. Now:
  - status carries the reload's own `restart_needed`, both the restart-only keys changed on disk and
    `h3 on udp ADDRESS`;
  - that listener carries `h3_waiting` with the bind's reason.

## 0.1.0-alpha.111 (2026-10-23)

- **Docs: a file counts as still being written for one to two seconds, not one** (the test host's
  report on alpha.110). The guard of alpha.110 compares modification times in whole seconds, so a file
  written in second N gets `no-store` through second N+1 and its lifetime from N+2. A file first asked
  for 1.2 s after its write was still `no-store`. This is the safe direction, one answer more without
  a lifetime, so the code stays. `docs/configuration.md` 1 and the code's comment now say so, with an
  example.

- **A reload that turns HTTP/3 on at 443 no longer ends the server** (the test host's report on
  alpha.110).
  - What happened: root added `"h3"` to `[server] protocols` on the live host, which was started as
    root and runs as `server.user`. The reload aborted the server (`terminate called`), and systemd
    restarted it, with a few seconds of refused connections. agensio's error log said nothing.
  - Why: a reload opened the UDP sockets of a listener that gained `h3` after the switch. The
    `agensio` account cannot bind a privileged port, and the failed bind was thrown out of worker 0's
    loop. Reproduced in the devbox once low ports are privileged there
    (`--sysctl net.ipv4.ip_unprivileged_port_start=1024`; Docker's default lets anyone bind them).
  - Now the reload opens them before the switch, beside the new TCP addresses. One it cannot bind
    keeps that listener's HTTP/3 off until a restart: it serves HTTP/2 and HTTP/1 and advertises no
    `alt-svc`. Everything else in the reload applies.
  - The reload's answer lists `h3 on udp ADDRESS` under `restart_needed`, the error log says why
    ("Permission denied (a privileged port, and the server no longer runs as root)"), and health
    gives `h3_waits_for_restart` (warning) until a restart binds it as root.
  - An exception that ends a worker's loop is now written to the error log (`fatal: worker N stopped
    by an exception: ...`) before agensio exits.
  - `tests/provision.sh` holds the case: a reload turning h3 on at 443 as `server.user`, then a
    restart. It runs with the sysctl above, and its usage line says so.

## 0.1.0-alpha.110 (2026-10-23)

- **`server_status` says which HTTP protocols this build serves** (the owner's request).
  - A `protocols` object gives:
    - `supported`: h1, h2c, h2 with TLS, and h3 with OpenSSL 3.5.1 or later on Linux;
    - the OpenSSL loaded;
    - without HTTP/3, `h3_unavailable` with why and what would give it.
  - Each listener's own protocols stay under `listeners`.
  - Health's new `http3_package_available` (information) fires when a TLS site runs on a build without
    HTTP/3 on a system whose OpenSSL has the QUIC API: the Debian 12 package, or the APT repository's
    build, on Debian 13. The fix is the release's `deb13` package. Health is silent on Debian 12 and
    Ubuntu 22.04 and 24.04, which have no HTTP/3 by decision.
  - The MCP texts of both tools say so.

- **Each release carries a Debian 13 `.deb` with HTTP/3.** The release packages were built on Ubuntu
  22.04, whose OpenSSL 3.0 has no QUIC TLS API, so no released `.deb` or `.rpm` had HTTP/3, not even
  on Debian 13.
  - A new `debian13` job builds `agensio_<version>+deb13_amd64.deb` in a `debian:trixie` container
    against Debian 13's OpenSSL 3.5, proves that the build loads `"h3"`, and smoke-installs it. It
    installs on Debian 13 and later only.
  - The Debian 12-compatible `.deb` is built as before. The two jobs run in parallel, neither
    waiting for the other: whichever finishes first creates the release
    (`packaging/release-upload.sh`).
  - The APT repository still carries the Debian 12-compatible build.
  - HTTP/3 is built only with OpenSSL 3.5.1 or later. In 3.5.0 the QUIC transport parameters were lost
    when the SNI callback switched the context, which agensio's certificate selection does.
  - In CMake, `-DAGENSIO_DEB_SUFFIX=NAME` gives the Debian package the version suffix `+NAME`.
  - `docs/install.md` names the two files, and no longer mentions a static tarball, which no
    workflow builds.

- **`[server] server_header` follows a reload, as the reference says** (the test host's report on
  alpha.109).
  - What happened: after `server_header = ""` or `"web"` and a reload, `config_reference` showed the
    new value, but every answer still carried `Server: agensio`: static, PHP, proxied, redirects,
    404s, over HTTP/1, HTTP/2 and HTTP/3. Nothing named a restart. Only a fresh start changed it.
  - Why: each worker built its `Server` line once at start, and HTTP/2 and HTTP/3 read the start's
    configuration.
  - Now each worker takes the value on its own loop at a start and at every reload's switch, with
    its HTTP/1 line, its HTTP/2 insert and the HTTP/3 field. A connection's encoder keeps indexing
    what it already sent, so each connection stays consistent, and new ones carry the new value.
    Nothing per request changed.
  - The connection ceiling's 503 said `Server: agensio` whatever the key said, even at a start with
    `""`; it now carries the worker's field too.

- **A static file still being written is never cached and never leaves with a lifetime.** An update
  made in place (`npm run build` into `public/build`, an unzip over the root) is served while it
  writes. On a cache miss agensio read the size `fstat` gave, so a file still growing was cached as a
  prefix and served to every client for up to a second. It went with the location's
  `Cache-Control`: on Laravel's `/build/` that is `immutable` for a year, so a browser kept the broken
  asset, whose hashed name never changes.
  - Now a file modified within the last second, or one whose size or modification time changed while
    it was read (`file_settled`, one `fstat` of the open descriptor on a miss), is served once as
    read. It is not cached and carries `Cache-Control: no-store`, which no location's `add_headers`
    and no rule's cache field replaces.
  - A twin still being written is passed over, and the revalidation picks it up once it settled.
  - A cache hit costs nothing more. An mtime more than a second ahead (an archive's, a skewed NFS
    clock's) counts as settled.
  - nginx has the same hazard per request, and Laravel's own nginx configuration gives `/build/` no
    lifetime, so agensio's preset had made it worse.

- **A credential an update left readable no longer takes its site down.** An update made in place
  loosens files:
  - `cp .env.example .env` leaves `0644`;
  - Laravel's common `chmod -R 775 storage` gives `storage/` to the server's group;
  - `rsync -a` and `tar x` put an archive's modes back.

  The hosting rules then set the site aside at the next reload, whatever caused that reload: another
  site's change through the control plane, a SIGHUP. Shown as root in the devbox: after `ctl reload`
  the site answered 421 and its `.env` stayed `0644`. A site stopped makes the file no more private.
  - A credential file readable by others or by a group not the site's now sets nothing aside, at a
    start or on reload, for the main file's sites too.
  - The provisioning helper's new `credentials_tighten` makes it private as the site's account,
    with the installer's modes (a file `0600`, a directory without its group's read and write). It
    runs at a start and on every reload of a server started as root. It decides from the
    configuration and files on disk, follows no link, changes no other account's file, and touches
    only what the rule flags.
  - The error and audit logs say `tightened PATH from 0644 as USER`.
  - What is left is health's `credential_exposed` error with the `chmod` or `chown` to run. `-t`
    warns and passes, and `validate` lists `credentials_exposed`.
  - The rules for what another account could write (a root or `open_basedir` directory not the
    site's, or writable by others) stay fail-closed.
  - nginx and php-fpm check no file mode at all; Apache's suEXEC refuses a script writable by others.

## 0.1.0-alpha.109 (2026-10-22)

- **An exact `.php` location decides its script's path-info form too** (found while building
  `served_dir`, 2026-10-22). PHP runs `/install.php/x` as `/install.php` with `PATH_INFO=/x`, but an exact
  location matched its literal path only.
  - On a site whose `.php` suffix location runs any script (`app = "php"`, `wordpress`), the path-info
    form of a script an exact location refuses reached that suffix location and ran. This covered a
    `rules.private` `.php` file, a hand-written exact `deny`, and WordPress's `wp-content/db.php`,
    `advanced-cache.php`, `object-cache.php` and `wp-config.php`. Shown on php-fpm: `/install.php` 404,
    `/install.php/x` ran it.
  - An entry point's path-info URLs (`/index.php/old/link` on a site with `rules.entry_points`) were 404
    there, or went round `try_files` without their `PATH_INFO` (Laravel).
  - Now the exact location takes them: a denied script is 404 however it is spelled, an entry point
    runs with its `PATH_INFO`. A longer exact location naming the whole path still wins, and an exact
    path with `.php/` inside takes only itself.
  - The access and password rules judged the script already (alpha.59).
  - nginx has the same trap: `location = /install.php { deny all; }` beside `location ~ [^/]\.php(/|$)`.
  - `bench/ab.sh -A` gains the row `exact`: sixteen exact locations before a cached file.

- **A plain PHP site can serve a directory of its project: `served_dir`** (a report from the test host,
  2026-10-22: an application keeping `index.php` in `public/` and its code in `src/` beside it could not be
  hosted on `app = "php"`. With `root` set to `public/`, PHP's `open_basedir` left out the `src/` that
  `index.php` requires. With `root` set to the project, `src/` and `.env` had URLs. And a managed site could
  not be created before `public/` existed, though `site_install` only fills an empty directory.)
  - `served_dir = "public"` on an `app = "php"` site serves that directory of the project. `root` stays the
    project directory: PHP's `open_basedir`, `site_install`'s target, the `composer.json` health reads.
  - The project's `.env` and `.git` are held to the hosting rules as credentials, as Laravel's are.
  - A plain relative path, refused when it leaves the project (through `..`, or a symlink once resolved)
    and on any other preset. A served directory that does not exist yet loads and answers 404; health says
    `served_dir_missing` (a warning) until it is there.
  - Managed: `site_create` and `site_update` take `served_dir` (`agensio ctl --served-dir DIR`), and
    `site_show` gives `served_dir` and `project_directory`.
  - Health's new `php_any_script_runs` (information): on `app = "php"` every `.php` under the served
    directory runs, one a user uploaded included. It stays until the site names its scripts
    (`rules.entry_points`, or a `.php` location that denies) or refuses `.php` where uploads go. The MCP
    texts tell the agent to set the entry points for an application that takes uploads.
  - Docs: `docs/configuration.md` 2, the cookbook recipe "A PHP application with a public/ directory",
    `docs/mcp.md`.

## 0.1.0-alpha.108 (2026-10-21)

- **The MCP texts say that moving a site to another PHP version is a tool call** (the test host,
  2026-10-21: an agent read `php_versions`' "installing or removing a PHP version is root's" as covering
  the switch, and handed the user `agensio ctl site-update ... --php-version 8.5` to run as root, while
  `site_update` would have done it). The server instructions name PHP versions under `site_update`;
  `php_versions` says that moving a site to a version it lists is never root's or a terminal's work, and
  that only installing or removing one is; the `installing` field of its answer says the same; and
  `site_update`'s `php_version` says the call is the switch. `test_mcp_texts` holds all four.
- **An error-log entry is one line** (the alpha.107 upgrade on the test host). A message holding a
  program's output kept its line breaks, so the start's "php-fpm pools at start: ..." spread over lines
  with no time or prefix: a grep for the entry showed its first line ("created /var/lib/agensio/ag1/php")
  and not the pools written and removed, and `logs_query` read the rest as other entries. The writer
  now turns a message's line breaks into "; " (trailing ones dropped), for every entry, so no text
  inside one can start a line of its own either (fail2ban's `agensio-auth` filter reads the error log
  by line). A unit test failing before, `tests/provision.sh`'s start check holding the whole output to
  the entry's line.

## 0.1.0-alpha.107 (2026-10-21)

- **The packaged logrotate configuration numbers its rotations on every system** (`nodateext`). RHEL's,
  Fedora's and Rocky's `/etc/logrotate.conf` turn `dateext` on for every program, so agensio's rotated
  logs were named `access.log-20261021.gz` there. The log queries read only the numbered names, so
  `logs_query` and health's `recent_errors` saw only the current file and said "nothing older is kept".
  Debian and Ubuntu number them already. The unit test holds every block of the file to it.
- **What an application needs of its PHP is checked** (the fourth step of `docs/design-php-versions.md`).
  - **The table.** Each PHP preset carries its application's published requirements: PHP minimum,
    recommended and newest supported, required and recommended extensions. They were read 2026-10-21 from
    WordPress's, Drupal's, Laravel's and Grav's own pages, and each row keeps its link and date
    (`docs/configuration.md` 7b).
  - **Required is only what the application enforces**: `composer.json`'s `require`, or for WordPress its
    `version.php`. Cache back ends and an application's own run-time checks never count: Grav asks for
    redis and runs without it. So WordPress requires hash and json, and mysqli is recommended (a site on
    SQLite runs without it).
  - **The installed release's own declaration wins**: `composer.json`'s `require.php` and `ext-*` (Drupal's
    `core/composer.json` too), or WordPress's `$required_php_version`. Composer's constraints are read by
    a new parser, fuzzed by `fuzz_php_constraint`.
  - **Extensions** are those the version's php-fpm loads (`php-fpm -m`), named as it prints them; finding
    the package is the administrator's or the agent's.
  - **A site moving to another version** is refused when the version is outside the range or does not
    load a required extension; the new `ignore_requirements` (`--ignore-requirements`) goes ahead. A
    missing recommended extension, a version newer than the application supports, and an extension the
    old version loads and the new does not are warnings. A new site only gets warnings.
  - **`site_install`** judges the release after unpacking and takes it out again when the site's PHP
    cannot run it, unless `ignore_requirements`; `facts.php` says what the release declares.
  - **Health**: `php_extensions_missing` (an error for a required extension, info for a recommended one),
    `php_version_unsupported_by_app` (warning), `php_version_eol` (info past active support, a warning
    past security support, an error a year after).
  - **`php_versions`** says which presets each version fits; **`presets_list`** shows each preset's
    requirements.
  - **Tests**: unit tests (constraints, declarations, the judgement, the table, the preflight, health with
    a fake php-fpm) and `tests/provision.sh` (a refused move and its override, an install refused and taken
    out, then installed with the override). Security page row 46.
- **A site's PHP version switches without downtime, and a start puts the pools in step** (the third step
  of `docs/design-php-versions.md`, and its section 6.2 agreed today). Every reload that gives a site a
  new pool socket now runs one ordered switch off the workers: a preflight, the new pool up, agensio's
  switch, the old pool gone. This covers `site_update` with `php_version`, `site_create`, enabling or
  restoring a site, `reload`, and SIGHUP after a hand edit.
  - The preflight: the version installed; for a moving site, its php-fpm running and
    `process_control_timeout` in both versions' `php-fpm.conf`. A failed one changes nothing and gives
    root's line. On the control plane a missing timeout is a refusal that the new `cut_requests: true`
    (`--cut-requests`) overrides; on SIGHUP it is a warning.
  - The new pool: written beside the old one, tested by its own php-fpm, the version reloaded and the
    socket awaited (at most 30 s). A failure puts the files back, and the site never leaves its version.
  - The answer's `done` lists each phase with its time. Until now the site's PHP answered 502 between
    agensio's reload and php-fpm's.
  - A version without a systemd unit, or a host without systemd, is reloaded with SIGUSR2 to the master
    named by its own `php-fpm.conf`'s pid file, checked through `/proc` to be that version's binary. A
    stopped php-fpm is a note for a new pool: it is read when the master starts.
  - At a start as root, the helper first makes every version's pool directory match the configuration,
    reloads what changed and waits for the sockets, before the listeners accept requests. This covers an
    upgrade that renamed or changed pools, an edit before a restart, and a newer PHP for the sites that
    follow the newest. A start whose files match changes nothing.
  - One reload at a time: another is refused while one switches, and a SIGHUP runs after it.
  - New health finding `php_fpm_inactive` (error): a version whose service is down while it runs sites.
  - Unit tests (the switches, the preflight, the up phase and its put-back, the pid file); `tests/provision.sh`
    on two real masters: a switch and its way back under load with no failed request, the refusals, the
    start. `docs/configuration.md` 7b, the cookbook recipe, the MCP texts and `docs/mcp.md`, security
    page row 45.
- **A php-fpm pool per site, in the php-fpm of the site's PHP version** (the second step of
  `docs/design-php-versions.md`). Until now an account's sites shared one pool, so they had to agree on
  every pool key, the version included, and all pools went into one directory (`server.pools` or the
  newest found). Each site with a user now has its own pool, `agensio-<user>-<8 hex digits of the
  domain>`, with its own limits, version, `open_basedir`, `tmp/` and `sessions/`
  (`<state_dir>/<user>/php/<domain>/`), and a socket that carries the version
  (`agensio-<user>-<8 hex>-<version>.sock`). A site's version is its `php = { version }`, else the new
  `[server] php_version`, else the newest installed; `site_show` says which and why (`php.version`,
  `php.version_from`). `agensio pools`, and the provisioning helper after `site_create` and
  `site_update`, make every version's pool directory hold exactly its pools: each site's file written
  into its version's directory, every other file agensio generated removed (a site moved to another
  version included), each directory that changed tested by that version's own `php-fpm -t` as root and
  put back as it was when php-fpm refuses it, and only the versions that changed reloaded (the helper),
  or their reload lines printed (`agensio pools`). Health: `php_version_missing` (error: a version not
  installed, the site's PHP answers 502), `php_default_unpinned` (info: sites follow the newest PHP
  installed, so a newer one moves them), `pools_stale` across the versions naming each file, and
  `php_fpm_hard_reload` per version. `server.pools` (refused, naming `[php.runtimes]`) and `agensio pools
  --out` are gone; the trash takes a site's PHP state with it when its account serves other sites.
  Unit tests (names, sockets, the versions' order, placement across two versions, a move, a refused test
  put back, a missing version, health), `tests/pools.sh` and `tests/provision.sh` on a real php-fpm as
  root through `[php.runtimes]`; `docs/configuration.md` 7b and 11, a cookbook recipe (Run one site on
  another PHP version), the reference (`docs/keys.md`), security page row 44. **Every pool is renamed**:
  after the upgrade run `agensio pools` as root and reload php-fpm (the PHP sites answer 502 until then),
  and remove the old per-account `sessions/` under `<state_dir>/<user>/` (the account's `tmp/` stays: site
  tasks use it); PHP sessions start anew, so users logged in through them log in again.
- **`php_versions`: the PHP versions installed, and those the repositories can install** (the first step
  of PHP versions per site, `docs/design-php-versions.md`). agensio finds every installed php-fpm from the
  distributions' layouts (Debian and Ubuntu `/etc/php/X.Y/fpm`, Remi's `/etc/opt/remi/phpXY`, Alpine
  `/etc/phpXY`, Homebrew), or from root's new `[php.runtimes."X.Y"]` (`fpm`, `conf`, `pools`, `unit`, `cli`)
  for one it does not, and reads each one's facts from its own programs, off the workers: the exact
  version (`php-fpm -v`), the extensions its FPM side loads (`-m`), its opcache settings (`-i`), its
  service's state (`systemctl show`), and, through the provisioning helper as root, its configuration test
  and `process_control_timeout` (`-tt`), with `reload_cuts_requests` when a reload would cut requests in
  flight. Each carries its support status from PHP's release table (php.net, checked 2026-10-20), the
  agensio pools its directory holds and their sites. The versions the configured repositories offer come
  from `apt-cache policy` (read-only), each with root's install line; supported ones they do not, with
  where root gets them (Ondřej Surý's repository on Debian, the ondrej/php PPA on Ubuntu). Installing stays
  root's. MCP `php_versions` (viewer), `agensio ctl php`, `GET /v1/php`.
  Unit tests (discovery on described machines, the programs' output, the support table, apt-cache, the
  configuration table, the answer), an integration check through `ctl`; `docs/configuration.md` 7b, the
  reference (`docs/keys.md`), `docs/mcp.md`.

## 0.1.0-alpha.106 (2026-10-20)

- **`--hsts false` is told what replaces it; `hsts = "application"` is refused on a static site** (the
  alpha.104 and .105 reports). `agensio ctl` sends `--hsts`'s value as text, so `--hsts false` reached the
  lifetime parser and got "'false' is no lifetime", where the loader and MCP say that `false` is gone and
  what replaces it; the texts `"false"` and `"true"` now get the same answers as the booleans. And
  `"application"` on an `app = "static"` site, which has no application, silenced health's suggestion and
  showed `application` in `site_show` while nothing sent HSTS; it is refused there, at load and through
  the control plane, naming `"none"`. Unit tests failing before, an integration check through `ctl`;
  `docs/redirects.md` 4.2, the MCP text.
- **A lifetime after `"application"` keeps the application's lifetime for a later clearing** (the
  alpha.105 report, item 1). Where the application's field goes out (no `hsts` line, `"application"`)
  nothing watches it, and the control plane asked the application for `/` only on a change to `"none"` or
  `"application"`: so `"application"`, then `"1w"`, then `"none"` cleared for agensio's week, while
  browsers that had received the application's two years before the change hold them for two years (RFC
  6797 8.1). Any change of `hsts` with nothing of the application's seen since the start now asks it
  first, so the change that ends such a period counts its field. The integration check fails before
  (the clearing ended after a week) and passes; `docs/redirects.md` 4.5.

## 0.1.0-alpha.105 (2026-10-20)

- **A clearing waits for what browsers received** (the alpha.104 report, item 1; RFC 6797 8.1: a browser
  holds the field it received last over HTTPS, for its `max-age` from then). The date until which a
  managed site sends `max-age=0` counted the application's lifetime whenever its field had been seen,
  also where agensio's own lifetime had replaced it on every answer, so no browser ever received it: a
  site at `"2s"` whose application sent two years cleared for two years, `"none"` was refused that long
  and the certificate findings stayed errors. The application's lifetime now counts only for the time its
  field went out (no `hsts` line, `"application"`), from the change that ended it; a field browsers ignore
  (no valid `max-age`) counts for nothing. Unit tests failing before, an integration check through the
  report's case; `docs/redirects.md` 4.5.
## 0.1.0-alpha.104 (2026-10-20)

- **`hsts = "none"` is none on any answer; `hsts = "application"` leaves HSTS to the application;
  `hsts = false` is gone** (the alpha.103 report, item 1, and the owner's review of what each value
  means). `false` meant only "agensio adds none": an application's own field went out unchanged, so a
  site that said `false`, and whose `site_show` said `off`, could commit browsers to two years with
  every subdomain (Writebook on the test host). Now:
  - no `hsts` line: not decided, the application's own field goes out unchanged; health suggests HSTS,
    or says the application sends one; `site_show` says `undecided`;
  - `hsts = "application"` (`site_update` with `hsts: "application"`, `agensio ctl --hsts application`):
    the same on the wire, decided, which silences the suggestion; on a managed site it hands over at
    once, during a clearing too, and the answer's `hsts_note` says what the application sends, or that it
    sends none and browsers keep the site's old lifetime until its date;
  - `hsts = "none"` (`hsts: "none"`, `--no-hsts`, `--hsts none`): no HSTS on any answer, an
    application's own removed, for a site that must stay reachable over plain HTTP or whose application
    would add one unasked; on a managed site whose answers carry HSTS (agensio's, or the application's)
    it clears first, `max-age=0` replacing the application's field too, until the last lifetime has run
    out;
  - `hsts = false` is refused, at load and through the control plane, naming `"application"`, which is
    what it did, and `"none"`. A managed site that decided no before is read as `"application"`, so its
    next rendering writes that; on an upgrade its file, which still says `false`, is set aside until
    `agensio ctl site-update NAME --yes` (health's repair) writes it again.
  The application's field is no longer watched on every answer of a site with no line: health reads it
  from its own request for `/`, off the workers (a field sent on other pages only is not seen), so such
  a site costs nothing per answer; `"none"` costs one header-name compare per application header, as a
  lifetime always did to replace it. Health's `hsts_suggested`, `hsts_from_application` and
  `hsts_narrows_application` fixes name the two values. Unit tests failing before; integration checks
  for the removal (HTTP/1 and HTTP/2), the pass-through, the hand-over, the clearing of an application's
  field and the refusal of `false`; `docs/redirects.md` 4.2 and 4.5, `docs/configuration.md` 14,
  `docs/tls.md` 2.7 and 5, the cookbook, the MCP texts, `agensio ctl`'s help, the reference
  (`docs/keys.md`).

## 0.1.0-alpha.103 (2026-10-19)

- **`logs_query` and health's `recent_errors` read the rotated logs** (the alpha.101 report). They read
  only the current files, so after the nightly rotation (`daily`, `delaycompress`) a window reaching
  back before it held only the hours since, with `truncated: false` and nothing said: `since: "12h"` at
  08:13 gave lines from 00:51 on, and health's "errors in the last 24 hours" counted since midnight. A
  query now reads on into `FILE.1`, then `FILE.2.gz` and older (through zlib), newest first, until
  `since` or the line limit, up to 8 MB of text and 64 MB inflated per log, on a thread rather than
  worker 0; `files` lists every file read, each source its `rotated` ones, and `incomplete` says from
  when the lines go back and why when that is later than asked (nothing older kept, the read limit, no
  zlib in the build). `recent_errors` reads the `.1` (plain, on the worker). Unit test and integration
  check failing before; `docs/configuration.md` 8, `docs/mcp.md`, the MCP text of `logs_query`.

- **`site_show` shows `hsts`** (the alpha.101 and .102 reports: an agent could not see what a site
  commits browsers to before proposing a change). `site_show` and `agensio ctl site NAME` carry `hsts`:
  `state` (`on`, `clearing`, `cleared`, `off` for a decided no, `none`), the field sent with `max_age`
  and `subdomains`, on a managed site the `lifetime` as written, `since`, and `until` (a clearing's end)
  or `held_until` (a longer lifetime browsers may still hold), and `application`, the application's own
  when seen. The ramp of alpha.102 gets its integration check with it. Unit test failing before;
  `docs/redirects.md` 4.1, `docs/mcp.md`, the MCP text of `site_show`.
- **Health's fix for a managed file written with `hsts = true` names the lifetime** (the alpha.101 and
  .102 reports). Such a file is set aside (old forms are not read), and health's `site_file_held_back`
  said that a bare `agensio ctl site-update NAME --yes` renders it again, which the control plane then
  refused until the change named a lifetime. For such a file the fix is now `agensio ctl site-update
  NAME --hsts 1y --yes` (`site_update` with `hsts: "1y"`, the year `true` meant; `hsts: false` clears it
  instead), and `site_update`'s MCP text says so. Unit test failing before, an integration check
  through the whole repair; `docs/redirects.md` 4.1.
- **`false` on a site whose application sends its own HSTS hands over after a restart too** (the
  alpha.102 report). agensio knew an application's `Strict-Transport-Security` only from its answers
  since the start, so after every restart, upgrades included, `false` (`site_update`, `--no-hsts`) on a
  managed application site that sends HSTS began a clearing, and `max-age=0` replaced the application's
  own field on every answer, so each returning browser forgot an HSTS the application still meant; a
  second `false` was then refused although health's `hsts_narrows_application` named it as the fix.
  When nothing of the application's was seen since the start, the control plane now asks it for `/`
  through the site's own listener first, on a thread as health's probe does (the request path notes the
  field), and hands over when it sends one; an application seen only once a clearing has begun is handed
  over to by the next `false`, whatever the date. The integration check fails before (`hsts = 0`,
  `max-age=0` served) and passes; unit tests for the hand-over during a clearing and the probe;
  `docs/redirects.md` 4.5, `docs/configuration.md` 14, the MCP text.

## 0.1.0-alpha.102 (2026-10-19)

- **`includeSubDomains` in stages: health names the next one** (hstspreload.org's deployment advice:
  five minutes, a week, a month, then a year or more, each run for its whole lifetime, since a mistake
  binds every subdomain, on other servers too, for as long as the lifetime). A managed site's spec
  records since when its current lifetime has been sent (`hsts_since`; the same value given again, in
  any spelling, keeps the date), and health's `hsts_ramp` (info) names the next stage once a site with
  `subdomains` has sent its stage for the whole of it with no certificate finding, with the
  `site_update` and `agensio ctl` lines; the agent asks the user whether anything broke first. Turning
  `subdomains` on with more than five minutes says the stages in the answer's `hsts_note`. A site file
  from before has no date and gets the finding after its next change of `hsts`; a host-only lifetime
  has no finding (the texts advise a week first, then a year). Unit tests failing before;
  `docs/redirects.md` 4.4, `docs/configuration.md` 14, `docs/tls.md` 5, the cookbook, the MCP texts,
  `agensio ctl`'s help.
- **Turning HSTS off on a managed site clears it first** (RFC 6797 6.1.1 and 8.1: browsers keep a
  lifetime from the last answer that carried it, and an answer without the field changes nothing, so
  `hsts = false` left every visitor who had seen it enforcing it until their lifetime ran out, with no
  way left to end it). `false` (`site_update`, `--no-hsts`) on a site that sends a lifetime now renders
  `hsts = 0`, sent as `max-age=0`, which each returning browser takes as "forget this host", until the
  latest moment a browser may still hold what the site sent: the spec keeps it across changes
  (`hsts_held_until`, raised at each change of `hsts` to the change's time plus the lifetime sent until
  then, so a site that went from a year to a week still waits for the year). The answer's `hsts_note`,
  the file's comment and health's `hsts_clearing` name the date, `hsts_cleared` says when it has
  passed; a second `false` before it is refused naming it, after it writes `hsts = false`; a lifetime
  given meanwhile ends the clearing. The certificate findings stay errors until the date and are
  warnings after it. When the site's application sends its own HSTS (noted on its answers since the
  start, now on sites with `hsts` too), `false` hands over to it at once and says so; its lifetime
  counts for a later clearing. A hand-written `hsts = 0` is unchanged and unnamed by health. Unit tests
  failing before (an injected clock), an integration check through a five-second lifetime;
  `docs/redirects.md` 4.5, `docs/configuration.md` 14, `docs/tls.md` 2.7 and 5, the cookbook, the MCP
  texts, `agensio ctl`'s help.

## 0.1.0-alpha.101 (2026-10-19)

- **`hsts` is a lifetime; `hsts = true` is refused** (RFC 6797 11.2: the lifetime is the site's
  commitment, set willfully). `true` named none and meant a year, the commitment browsers keep for
  that year with no way for a user to click past a certificate error (12.1), chosen without anyone
  writing it. The site key is now the lifetime: seconds (`hsts = 604800`, the form applications
  publish) or a duration (`"300s"`, `"1w"`, `"1y"`, `"2y"`; at most ten years), `0` to make browsers
  forget it (6.1.1), `false` off and decided, or `{ max_age, subdomains }` for `includeSubDomains`;
  `true` is refused at load with the form to write. A managed site takes the same through
  `site_update`'s `hsts` (a string, seconds, `false`, or `{max_age, subdomains}`; `true` refused; at
  most two years, the longest a preload list asks) and `agensio ctl --hsts LIFETIME
  [--hsts-subdomains]`, rendered as written. Health's `hsts_suggested` fix names `"1y"`, `"1w"` first
  when unsure; `hsts_from_application`'s names the value that matches the application's, with a note
  when that is above the managed cap. RFC 6797 in `docs/rfc/`. Unit tests failing before, integration
  checks through `-t` and `agensio ctl`; `docs/redirects.md` 4, `docs/configuration.md` 14,
  `docs/tls.md` 2.7, the cookbook, the MCP texts, `agensio ctl`'s help.
- **A long lifetime where a single-page fallback answers is noted** (the review of 2026-10-14, D8's
  second part: `docs/headers.md` 3.5 and 7 promised it). On a site whose `try_files` falls back to a
  file agensio serves (an application's shell, `/index.html`), a `[[site.response_headers]]` rule
  giving a path there a day or more, or `immutable`, without `no-store` or `no-cache` reaches the
  shell's answer for a path that is no file (a mistyped or removed bundle), which browsers and CDNs
  then keep as HTML under the bundle's address; so does a location's `add_headers` where that location
  answers its own fallback. `-t`, the error log and health note it (`header_cache_over_fallback`),
  naming the fix: the directory's own location with `try_files = ["$uri", "=404"]`, as the cookbook's
  single-page application recipe has it. An ending rule counts only for the shell's ending, a
  fallback to an application (PHP) not at all. `path_check`'s preview notes it the same way. Unit
  test failing before, an integration check through `-t`; `docs/headers.md` 3.5 and 7,
  `docs/configuration.md` 14c, the cookbook, the MCP text.
- **`immutable` in a managed site's `rules.cache`** (the review of 2026-10-14, defect D8: `docs/headers.md`
  3.5 and 11.2 promised it, decided 2026-10-13 and never built). An entry takes `"immutable": true`,
  rendered as `public, max-age=N, immutable` (RFC 8246: while the lifetime lasts a browser's reload asks
  nothing; Firefox and Safari honour it over HTTPS), and `agensio ctl --cache PATH=SECONDS,immutable`.
  For a directory whose names change with their content; refused with `max_age` 0, the extension holding
  only while the answer is fresh (RFC 8246 2). An entry's other fields are refused, naming the nearest:
  `immutable` was dropped before, so the control API answered ok for a lifetime the file did not carry.
  The cookbook's advice to put `immutable` into root's additions file, wrong since managed sites take
  `response_headers` (alpha.94), now names `rules.cache` and `site_update`'s `response_headers`. RFC
  8246 in `docs/rfc/`. Unit tests failing before; `docs/configuration.md` 15, `docs/headers.md` 3.5,
  the cookbook, the MCP text of `rules.cache`, `agensio ctl`'s help.
- **A CORS preflight on a password-protected file is answered** (the review of the redirects, HSTS and
  response-header work, 2026-10-14, defect D7). A preflight, the `OPTIONS` with `Origin` and
  `Access-Control-Request-Method` a browser sends before another origin's page may call a path, never
  carries credentials (Fetch 3.3.5) and blocks the call on any status but `2xx` (4.8); agensio asked it
  for the password, so a page on another origin could not call a protected path at all. On a path
  agensio serves itself the preflight now gets the `OPTIONS` answer before the password: `204`,
  `Allow` and the site's `[[site.response_headers]]`, the same whether a file is there or not; the
  call that follows is asked as before. A plain `OPTIONS` and a preflight on an application's path
  (PHP, a proxied application, CGI) are still asked: an application that does not look at the method
  would answer an `OPTIONS` with the protected page (Apache's common `<LimitExcept OPTIONS>` recipe
  lets it through). The password suite's checks failing before; `docs/auth.md` 5.1 and 9,
  `docs/configuration.md` 19b.

## 0.1.0-alpha.100 (2026-10-18)

- **Content types: root's `[mime_types]` and a site's `mime_types`** (`docs/configuration.md` 6c; the
  review's gap 8, designed with the owner on 2026-10-18). The `Content-Type` of the files agensio
  serves came from a compiled table no one could change (CLAUDE.md said "overridable from config";
  it was not): a file without an ending (`/.well-known/apple-app-site-association`), a format the
  table does not know, or what an application's `.htaccess` sets with `AddType` and `AddEncoding`
  (TYPO3's `.js.gzip`) came out wrong. Now three layers, each adding and overriding entries, never
  replacing the table below (an nginx `types` block in a nested level does): a site's `mime_types`
  (its file, or `site_update` and `agensio ctl --mime-type`), root's `[mime_types]` in the main file,
  the built-in table. An entry is by ending (any case, the longest of a file's name first) or exact
  path, a type with at most a `charset`, and `encoding` (`gzip`, `br`) for a file stored compressed.
  Refused: a site giving an ending a type browsers run scripts in (HTML, XML, SVG, JavaScript) when
  its built-in type is not one (`txt` as `text/html` makes every upload a page; a compressed file is
  judged by its inner ending, so `js.gzip` is JavaScript), which root's table may do with a note
  (`mime_type_scriptable`); an encoding on a bare compressed or archive ending (`gz`, `zip`,
  `tar.gz`: the browser would unpack the download, Apache's `AddEncoding x-gzip .gz` trap); a
  `[mime_types]` in an included file. Resolved once per site at load and read at cache fill, so a hit
  pays nothing and a reload applies it; an application's answers keep their own type. `path_check`
  names the type and its layer (`content_type`, `content_encoding`, `content_type_from`),
  `site_show` lists the table, `-t --explain` prints both layers. Unit tests, integration checks
  over HTTP/1 and HTTP/2 and through `agensio ctl`, a cookbook recipe.
- **`.svgz` is served so browsers render it, and the SVG files agensio serves run no script** (the
  review of the redirects, HSTS and response-header work, 2026-10-14, defect D6). A `.svgz` is
  gzip-compressed SVG (SVG 1.1 1.2); agensio sent it as `image/svg+xml` with no `Content-Encoding`, as
  nginx's `mime.types` does, so browsers got gzip bytes they must not render (SVG 1.1 G.8) and the
  `.svgz` images of Nextcloud, Drupal and TYPO3 (whose `.htaccess` says `AddEncoding gzip svgz`) were
  broken; no rule could fix it, `Content-Encoding` being the representation's (RFC 9110 8.4). The type
  table gains an encoding column (`mime_info`), `gzip` for `svgz`: the line goes into the cache entry's
  block for HTTP/1, HTTP/2 and HTTP/3, the file's one representation, so no `Vary` and no
  pre-compressed twin (a second coding would be `gzip, br`); a client refusing gzip outright still
  gets it, as from Apache, there being no other form. Once it renders, a `.svgz` opened alone runs its
  scripts on the site's origin as a `.svg` does, and an `svg` ending rule does not reach it; so the
  security baseline of every site with `app` now sends `Content-Security-Policy: script-src 'none'`
  (a default) on the `.svg` and `.svgz` files agensio serves: in `<img>` an SVG never runs one, so pages
  look the same; an SVG opened alone or framed with `<object>` or `<iframe>` loses its scripts, which
  closes the stored-XSS path of an uploaded one (an upload filter that blocks `.svg` but not `.svgz`
  included). A site's own rule for the field decides instead. Integration checks over HTTP/1 and
  HTTP/2 (the coding, no `Vary`, the CSP on both, the body decoding to the SVG; a site whose rule
  names only `svg`) failing before; unit tests; `docs/headers.md` 3.3 and 4.1,
  `docs/configuration.md` 14c, the MCP text, `-t --explain`.
- **A tool without arguments says so when given one** (the alpha.99 report). MCP `health_check`
  with `{"verbose": true}` answered "unknown argument 'verbose' for health_check; its arguments are.
  Nothing was done.", a sentence that stops; it now ends "for health_check, which takes no arguments.
  Nothing was done.". Unit test failing before.
- **The cache guards of alpha.99 hold for `Vary`, a removed `Cache-Control`, `Expires` and every CDN
  field** (the alpha.99 report; `docs/headers.md` 2.4). With a rule's `set` of `Cache-Control: public,
  max-age=3600`, `CDN-Cache-Control`, `Surrogate-Control` and `Expires`:
  - an answer with `Vary: Cookie` (Django's session pages, which send no `Cache-Control`) or `Vary: *`
    went out `public`: an answer that varies on `Cookie` or `Authorization`, or is `Vary: *`, is now one
    user's like a cookie's (RFC 9110 12.5.5, RFC 9111 4.1), so it gets the lifetime as `private` and no
    rule's CDN fields or `Expires`;
  - a cookie's answer under `remove = ["Cache-Control"]` went out with none, which a cache may keep by
    heuristic (4.2.2): where the rules leave one user's answer without `Cache-Control`, by a `remove`
    as by a lifetime left out, it says `private`, as the alpha.99 entry promised;
  - a rule's `Expires` was sent over the application's restriction (over a bare `private` a date in 2099
    became the browser's lifetime), and a rule's `Surrogate-Control` over the application's
    `CDN-Cache-Control: no-store`, though Fastly and Varnish read `Surrogate-Control`, not
    `CDN-Cache-Control` (RFC 9213 2.2: a CDN reads the first field of its own list): a restriction in
    any of the application's CDN fields now holds for every CDN field a rule adds, and a rule's
    `Expires` gives way to any restriction in `Cache-Control` or a CDN field, as Akamai's own "honor
    origin" mode ignores `Expires` there.
  `path_check` says each. Checked against the RFCs and against what Varnish (its built-in rules),
  Fastly, Akamai and Cloudflare do; unit tests, `fuzz_response_headers` invariants (a rule's CDN field
  or `Expires` never over a restriction; `Vary` in what is one user's) with a seed, integration checks
  with PHP fixtures failing before; `docs/headers.md` 2.4, `docs/configuration.md` 14c, the MCP
  texts.
- **A directory asked for without its slash is redirected as every other redirect is** (the review
  of the redirects, HSTS and response-header work, 2026-10-14, defect D5). The static handler's 301
  wrote the decoded path as it was, so a directory `My Files` gave `Location: /My Files/` (no URL), `a#b`
  gave `/a#b/` (a fragment: the browser went to `/a`), a Greek name raw UTF-8, and a directory named
  `\evil.example` gave `/\evil.example/`, which browsers read as `//evil.example/`, another host (the
  class of Tomcat's CVE-2018-11784; the directory must exist under the root). The query was dropped
  (`/docs?page=2` to `/docs/`) and there was no lifetime, so Chromium kept the 301 for good and a
  directory later turned into a page kept redirecting. Now `redirect::directory_location` writes it
  with the rules' writer: the path encoded again (`/My%20Files/`, `/a%23b/`, `/%5Cevil.example/`), the
  query kept, relative, and `Cache-Control: max-age=86400`, the lifetime of agensio's other permanent
  redirects; status 301 as before. nginx, Apache, Caddy and h2o keep the query, nginx escapes there
  since 1.21.0 (the same bug), Caddy only non-ASCII bytes; none of them sends a lifetime. `path_check`
  names the Location (`redirect_location`) and the lifetime. Unit test, a `fuzz_redirect` invariant
  for every target (relative, never `//` or `/\`, decoding back to the path with its slash) and a
  seed, integration checks over the default lookup and `try_files`' `$uri/`, failing on alpha.99;
  `docs/configuration.md` 1, `docs/redirects.md` 1, the MCP text of `path_check`.

## 0.1.0-alpha.99 (2026-10-18)

- **Response-header rules refuse what can only break or mislead** (the review of the redirects,
  HSTS and response-header work, 2026-10-14, defects D1 to D3):
  - `remove = ["Location"]` (and `Refresh`) was accepted, and agensio's own redirects, a directory
    without its slash and every `[[site.redirect]]` answer, went out as a 301 with no target: refused
    in every verb, naming `[[site.redirect]]`.
  - `remove = ["Server"]` was accepted and did nothing, `Server: agensio` staying on every answer
    while `path_check` said "removed": refused, naming `[server] server_header = ""`. A remove of
    `Alt-Svc` or `Strict-Transport-Security` strips an application's copy only, and `path_check` now
    says so ("removed from an application's answer only; agensio's own ... stays").
  - `Access-Control-Allow-Origin: "null"` was accepted, also with `Access-Control-Allow-Credentials:
    true`: it is the origin of sandboxed frames, `data:` URLs and local files, which any page can
    claim, so any site could read the answers, with credentials a signed-in visitor's (MDN). Refused,
    naming a real origin or `*` without credentials.
  In a site file and through `site_update` and `path_check`'s preview alike (one parse). Unit tests
  failing on alpha.98; `docs/headers.md` 2.5 and 2.6, `docs/configuration.md` 14c, the MCP text of
  the `response_headers` field.
- **A response-header rule never makes an application's answer one a cache hands to another
  visitor** (the same review, D4; `docs/headers.md` 2.4). `set = { "Cache-Control" = "public,
  max-age=3600" }` over a PHP path replaced PHP's session answer (`no-store, no-cache,
  must-revalidate`), WordPress's signed-in pages and an answer setting a session cookie alike, so a
  CDN could keep a signed-in page or hand the cookie to the next visitor; nginx's `add_header`
  appends, so a configuration translated from nginx meant the application's value to stay. Now, on
  an application's answer (RFC 9111):
  - its `Cache-Control` saying `no-store`, `private` or `no-cache` (5.2.2.5, 5.2.2.7, 5.2.2.4) stands
    over a rule's `set` or `remove` whose value does not say them too (`no-store` says all three, so a
    stricter rule still replaces), and a rule's lifetime in `CDN-Cache-Control`, `Surrogate-Control` or
    `Edge-Control`, which a CDN follows in place of `Cache-Control` (RFC 9213 2.2), is left out over
    it; an application's own CDN field with such a restriction stands too;
  - an answer that sets a cookie (which does not stop a cache, 7.3) or answers a request with
    `Authorization` (3.5) gets a rule's `Cache-Control` lifetime as `private` with the browser's
    directives (`private, max-age=3600`), no rule's `Expires` or CDN lifetime, and `Cache-Control:
    private` where that leaves it none (a rule's `remove` of it included). A lifetime: `public`, `s-maxage` (else `max-age`) above 0,
    `stale-while-revalidate` or `stale-if-error` above 0 (RFC 5861, now in `docs/rfc/`).
  A `set` of a lifetime over an application site is noted at load (`header_cache_set`: use `default`,
  on public pages' paths), since a page the application marks with nothing is still kept; `path_check`
  says what gives way. The answer's fields are read once more before the upstream loop only where a
  rule decides a cache field: `bench/ab.sh -P -A` has a `proxy-cache` row for it, flat (0.996). Unit test of every case, a fuzz invariant (the application's
  restrictions are never lost; one user's answer gets no rule's lifetime), integration checks over
  HTTP/1 and HTTP/2 with PHP's session answer, a cookie and `Authorization`, failing on the commit
  before; `docs/headers.md` 2.4, 7 and 9, `docs/configuration.md` 14c, the MCP texts.
- **A field a proxy location hides gives way to a rule's `default`** (found reviewing D4). The upstream
  loop asked the response-header rules about each of the origin's fields before `proxy = { hide }`
  dropped it, so a hidden field counted as the application's copy and a `default` for it was not sent:
  with `hide = ["X-Frame-Options"]` and `default = { "X-Frame-Options" = "SAMEORIGIN" }` the answer
  carried neither, a page any site could frame. `hide` now runs first, so a hidden field is gone
  before the rules, the password guard's `Cache-Control` and the HSTS notes read it (a hidden HSTS was
  noted as the application's own). Integration check over HTTP/1 and HTTP/2 failing before;
  `docs/configuration.md` 12, `docs/headers.md` 2.3.
- **An unknown tool argument or site field is refused, naming the nearest** (the alpha.98 report).
  MCP `site_update` with `"bogus_field"`, a misspelt `"public_archive"` or the old
  `"archives_accepted"` answered ok and wrote nothing, so an agent told the user the change was made;
  `site_show` and `health_check` took any argument too. Every tool's schema is closed
  (`additionalProperties: false`), and the bridge refuses an argument the schema does not list
  ("unknown argument 'public_archive' (did you mean 'public_archives'?) ... Nothing was done."), with
  `user_confirmed` and `client` (the bridge's after the user's answer) and an agent's password `hash`
  refused for what they are, where they were dropped before. The control API's `site-create` and
  `site-update` answer 400 for a field they do not read (`control::site_request_fields`), so `agensio
  ctl` and any other client meet the same; the loader's "did you mean" is the one `nearest_name`.
  Unit tests failing on alpha.98 (the bridge driven over a pipe, `apply_request`); integration checks
  through MCP and the socket; the dialog check now expects an agent's `user_confirmed` refused;
  `docs/mcp.md`, `docs/configuration.md` 15.
- **The tar shorthands and the other compressions are archive endings** (the same report). On a static
  site `b.sql.tar.zst`, `b.sql.tbz2`, `b.sql.txz` and `b.sql.tzst` were served and named nowhere, and on
  a PHP site `site.tar.zst` was no archive. `archives_in_root` knows `.tbz`, `.tbz2`, `.txz`, `.tar.zst`,
  `.tzst`, `.tar.lz4`, `.tar.lzma`, `.tar.lz` and `.tlz` as archives, and takes them off, with `.lz4`,
  `.lzma` and `.lz`, before looking for a dump inside. Unit test failing on alpha.98.

## 0.1.0-alpha.98 (2026-10-17)

- **`public_archives`, and every found archive judged by what a request for it gets** (the alpha.97
  report's Grav probe, and the discussion after it). Health warned the same way about a dump anyone
  could download and about an application's own file the preset refused, and the one key to silence
  either, `archives_accepted`, meant "published on purpose", which the second is not. Two changes:
  - `archives_accepted` is renamed `public_archives` (the managed field, `agensio ctl site-update
    --public-archive PATH` and `--no-public-archives`), for files published for download on purpose; a
    file the application keeps in the tree that nobody downloads goes in the existing `refuse`, which
    answers 404 for it. No new key: `refuse` makes the claim true where a health-only key would silence
    the warning while the file stayed downloadable.
  - `archives_in_root` judges each file found (the first 50; any beyond, as served) by the decision
    `path_check` explains (`control::archive_exposure`): served to anyone, a warning ("anyone can
    download them"); refused by the site's own `refuse`, a managed site's `rules` or a location the
    owner wrote, nothing; refused only by the preset's defaults, or reached only from some addresses or
    with a password, information ("not served today: a change of preset or location would undo it").
    The fix tells the agent to ask the user what each file is and offers both keys with the path as
    served; never a backup or a dump of the site's data as public.
  A path in `public_archives` that the site's `refuse` answers 404 is named by `-t` and health
  (`public_archive_refused`). `docs/configuration.md` 1 (the table of what health says) and 4c, the
  reference row and `docs/keys.md`, the MCP texts of `health_check` and the field, and the cookbook
  recipe (now "Dumps and archives under a site's root: published, or kept private"). Unit tests for
  each kind of exposure, the contradiction and the rename; the integration checks' severities.

- **A dump inside an archive is a dump** (the alpha.97 report from the test host). On a static site
  phpMyAdmin's zipped export `db/export.sql.zip`, a `db/export.sql.7z` and a `db/backup.sql.tar.gz`
  were served and `archives_in_root` named none of them, taking them for downloads; on a PHP site
  `app.sqlite.gz` and `pg.dump.xz` matched no ending at all. A name that ends like a dump (`.sql`,
  `.sqlite`, `.sqlite3`, `.db`, `.dump`) once one archive or compression ending is taken off (`.zip`,
  `.7z`, `.rar`, `.tar` and its compressed forms, `.gz`, `.bz2`, `.xz`, `.zst`) is a dump on every
  site; any other archive on a static site stays a download. Unit test, failing on alpha.97; the MCP
  text of `health_check`, `docs/configuration.md` 1 and the cookbook recipe say it.
- **Data written as table definitions counts** (the same report). A lone `CREATE TABLE s AS SELECT
  'sk_live_abc' AS k;`, MySQL's `CREATE TABLE s SELECT ...`, PostgreSQL's `CREATE TABLE s AS VALUES
  (1, 'sk_live_abc');` and `CREATE VIEW v AS SELECT 'sk_live_abc' AS k;` were taken for a schema by
  their first two words and served on a static site unnamed. The scanner (`control/sql_scan.hpp`)
  now counts a `CREATE TABLE` (or `CREATE TEMPORARY TABLE`) holding the word `SELECT` or `VALUES`
  outside quotes and comments, and a `CREATE VIEW` whose body holds a `'...'` literal; a quoted
  `DEFAULT`, a generated column, a plain view and a partial index's `WHERE` stay definitions. Unit
  cases failing on alpha.97, a new seed for `fuzz_sql_scan` and ten minutes of it on every core;
  the MCP text of `health_check` and `docs/configuration.md` 4c.
- **An `archives_accepted` entry that can never match is refused or named** (the same report).
  `["/db/*.sql"]` loaded and accepted nothing, the dump still named; `["/db"]`, a directory, did the
  same, since only `/db/` covers what is below it. `*`, `?` and `[` are refused at load ("exact paths
  and directories only, no wildcards"), on a site file and through `site_update` alike, and the
  finding names an entry that is a directory on disk without its `/` ("'/db' is a directory: write
  '/db/'"). Unit tests failing on alpha.97; the reference row, `docs/keys.md`, the MCP field's text and
  `docs/configuration.md` 1.
- **`site_show` lists `archives_accepted`, and `null` clears it** (the same report). Neither MCP
  `site_show` nor `agensio ctl site NAME` carried the list, while `site_update` and
  `--archive-accepted` replace it whole, so an agent adding one path could not see the ones it would
  drop; and `site_update` with `"archives_accepted": null` answered ok and kept the list. The site's
  answer carries `archives_accepted`, and `null` clears it as `[]` does (as it does `response_headers`);
  `login_paths` takes `null` the same way. Unit tests failing on alpha.97; the MCP texts of
  `site_show` and of both fields, `docs/configuration.md` 1.
- **A path's value never starts with `-`** (the same report). `agensio -c -t` took `-t` for the
  configuration file (exit 1, "File could not be opened"), as `--out -x` wrote a file named `-x` and
  `mcp --socket -x` dialled one: the value check treated only `--` words as flags, while the top
  level's are `-c`, `-t`, `-v`. The value of `-c`, `--config`, `--out` and `--socket`, on every
  command, is no value when it starts with `-`: "WHO: FLAG needs a value", exit 2; a file so named is
  written `./-name`. Other values may still start with one (`--set k=-1`, a `--note`). Integration
  check, failing on alpha.97.
- **Grav's exposure probe is the application's own** (the same report). On the live Grav site health
  warned about `user/data/grav-security-probe.zip`, 32 bytes, which Grav's API plugin writes (with
  `.dat`, `.json` and `.txt` siblings) to check that `user/data/` is not public, and writes again when
  deleted: health had the owner delete it on 2026-10-16, and Grav's next update put it back. It was
  never served (the preset answers 404 there). On an `app = "grav"` site that path, up to 1 KB, is not
  counted (`kProbeFiles` in `control/commands.cpp`, by preset, path as served and size); the same name
  on another site, a larger file of that name and any other archive in `user/data/` still are. Unit
  test failing on alpha.97; the MCP text of `health_check` (never tell the user to delete it) and
  `docs/configuration.md` 4c.
- **A site change's next steps judge the jail as health does** (the same report). With the installed
  jail differing from the rendering in comment lines only (`installed_jail: comments`), `agensio ctl
  site-update ag4.edoc.gr --set pm=ondemand` answered that the jail was "older than this change",
  with the re-render and reload line, for a change of the PHP process manager. alpha.96 taught health
  and `protection_show` the comment-blind comparison and missed this third reader. The step is now
  `control::protection_steps`, a pure function over the installed files that compares them as health
  does: a step only when the jail's (or the ruleset's) rules differ, a filter install line only when a
  filter's rules do, and the note that rendering replaces the file and an administrator's own lines go
  into `jail.d/agensio.local`. Unit test; the MCP text of `site_update`.

## 0.1.0-alpha.97 (2026-10-17)

- **A flag's value is never the next flag, nor empty** (the alpha.96 report from the test host).
  `agensio ctl protection --jail --out --nft` exited 0 and wrote the jail into a file named `--nft`,
  `ctl site-unit NAME --out --raw` one named `--raw`, `ctl logs --since --limit 3` took `--limit` as the
  duration, `--socket ""` fell back to the configured socket, and the commands said a missing value
  three ways (`agensio pools ... --out` with its whole 7 KB usage on stdout). One helper now reads every
  flag's value in `agensio ctl`, `protection`, `pools`, `mcp`, `passwd` and the top level: the last word,
  an empty word or one starting with `--` is no value, "WHO: FLAG needs a value" on one line of stderr,
  exit 2, nothing on stdout (a value that truly starts with `--` is written `./--name`); an unknown
  top-level argument prints the usage on stderr. Integration check, failing on alpha.96.
- **A `.sql` file is exempt from `archives_in_root` only when it defines tables** (the same report: a
  `db/fix.sql` of `UPDATE wp_users SET user_pass='$P$B...'` and `UPDATE wp_options SET
  option_value='sk_live_...'`, no `INSERT`, was taken for a schema by alpha.96's keyword rule). The
  rule is inverted: `control/sql_scan.hpp` splits the text into statements on `;` outside quotes and
  comments and judges each by its first two words; a file is exempt only when every statement is
  `CREATE TABLE`, `CREATE INDEX` (`UNIQUE`, `FULLTEXT`, `SPATIAL`), `CREATE VIEW`, `CREATE TEMPORARY
  TABLE`, `ALTER TABLE`, `DROP TABLE`, `DROP INDEX` or `DROP VIEW`. Anything else counts: `UPDATE`, `SET`,
  `GRANT`, `CREATE USER ... IDENTIFIED BY` (a password in DDL), `PRAGMA`, MySQL's executable `/*! ... */`
  comments (so a mysqldump without its rows counts), and a file that ends inside a quote. Comments are
  not read. The scanner is header-only, linear and has its fuzz target, `fuzz_sql_scan` (a comment
  appended changes nothing; a data statement after any text not ending in a quote or a comment is
  found; 45 minutes on one core and 15 on twenty-four, 356 M runs, clean). Unit test, failing on alpha.96; the MCP text of `health_check` and
  `docs/configuration.md` 4c say it.
- **`scripts/fuzz-all.sh` uses the whole machine.** It ran half the cores, so the twenty-one targets
  went in two waves of `-t` each, and a target alone (the hour after a parser change) on one core. Now
  it starts as many processes as the cores, or as the free memory holds at 600 MB each, runs every
  target at once when they fit, and shares the processes left over among the targets through
  libFuzzer's `-jobs` on one corpus each (`-w` sets them by hand): the campaign of twenty-one targets
  takes one `-t` (22 s for `-t 20`), and `fuzz_sql_scan` alone 1.2 M runs a second on 24 processes
  against 47 k on one. `-print_funcs=0` stops a symbolizer starting for every newly covered function,
  which with every target starting at once stalled six of them for half a minute; a crash's report is
  still symbolized. `docs/security-control-plane.md` says it with the procedure.
- **The jail finding names a hand edit, and where the administrator's own settings go** (the alpha.96
  report). With a `# test` line added by hand, health said the jail's comments were "an older build's
  text (an upgrade reworded them)", and its fix, rendering again, deleted the note. The comparison
  cannot tell an upgrade's wording from a note: `fail2ban_jail_stale` now says "only comment lines
  differ from this build's rendering (an upgrade reworded them, or comments were added by hand)", a
  stale jail's reasons include "edited by hand", and both fixes say that rendering replaces the file
  and that settings and notes of one's own go into `/etc/fail2ban/jail.d/agensio.local`, which
  fail2ban reads after it (jail.conf(5)) and agensio never writes; the filter finding likewise, with
  `filter.d/NAME.local`. The rendered jail's header says it too (the packaged copy rendered again):
  on an upgraded host health names the jail's comments once, as information. The MCP texts of
  `protection_show` and `health_check` tell the agent to ask about the user's own lines before giving
  root the render; `docs/fail2ban.md` and `docs/configuration.md` 18. Unit test, failing on alpha.96.
- **Dumps on static sites, the other dump formats, and `archives_accepted`** (the alpha.96 report:
  on a static site and one without `app`, a `db/dump.sql` with a password hash, a `.sql.gz` and a
  backup `.zip` were all downloadable and health said nothing, while a PHP site, which refuses
  `.sql`, got the finding). `archives_in_root` now searches static sites and sites without `app`
  for database dumps, and its message says they are served as they stand; archives there (`.zip`,
  `.tar.gz`, ...) are downloads offered on purpose and are not named. The dumps it knows grow from
  `.sql` and `.sql.gz` to `.sql.bz2`, `.sql.xz`, `.sql.zst`, `.sqlite`, `.sqlite3`, `.db` (not
  Windows' `Thumbs.db`) and pg_dump's `.dump`, on every site. The new site key `archives_accepted`
  records what the owner publishes on purpose, by its path as served (a directory ending in `/` for
  all below it; never `/` alone, at most 64): health counts those as accepted in the message instead
  of naming them, and nothing about serving changes. Every finding names its example with the path
  as served, the form the key takes. Managed: `site_update` `archives_accepted`, `agensio ctl
  site-update NAME --archive-accepted PATH` (repeatable, the list replaced) and
  `--no-archives-accepted`; the MCP texts tell the agent to set it only after the user confirmed the
  file is meant for anyone. `docs/configuration.md` 1 (dumps served as they stand) and 4c, the
  reference row and `docs/keys.md`, and a cookbook recipe (a dataset or a sample database offered for
  download). Unit tests (the three kinds of site, the new endings, the accepted paths, the key's
  refusals, the managed field) and an integration check (a managed static site's dump named, accepted
  through `site-update`, named again once cleared), failing on alpha.96.

## 0.1.0-alpha.96 (2026-10-16)

- **A flag without its value is a usage error** (the alpha.95 report from the test host). `agensio
  ctl` skipped a flag given last without its value, so `agensio ctl protection --jail --out "$F" &&
  fail2ban-client reload` with `F` unset printed the jail, exited 0, and the reload ran with the file
  never written; `--out ""` did the same. Now any `ctl` flag without its value exits 2 with "needs a
  value", and an empty `--out` exits 2 on `agensio ctl`, `agensio protection` and `agensio pools`
  (which wrote into the distro's pool directory in its place), nothing on stdout, nothing written.
  Integration check, failing on alpha.95.
- **Raw output is the text alone** (the same report). `agensio ctl site-unit NAME --raw > f` of a
  refused call (a WordPress site's 409, a site that does not exist) exited 1 with the server's JSON
  error in `f`. Now in every raw mode (`--raw` of `site-unit`, `site-service-logs` and
  `site-task-output`; `protection --nft`, `--jail`, `--unit`, `--filter NAME`) anything but the text
  goes to stderr and stdout stays empty. `docs/configuration.md` says it beside the command table, with
  the exit codes, and its `site-unit` row no longer suggests `--raw > /etc/systemd/system/...`;
  `tests/tasks.sh` expected that form as the unit's first root step, which alpha.95 replaced with
  `--out`. Units rendered before alpha.95 carry the old line in their header: render them again with
  `--out`. Integration check, failing on alpha.95.
- **An upgrade that rewords comments no longer calls the jail stale** (the same report). alpha.95 changed
  only comment lines of the jail (its install line, a disabled jail's steps), and on every upgraded
  host health reported `fail2ban_jail_stale`, "a site, a log or a login path was added since", with
  nothing added; `protection_show` gave the ruleset `file_current: false` for the same reason. The
  jail file, the filters and the ruleset file are now compared without their comment lines (a line
  whose first non-blank character is `#`, a comment to fail2ban, jail.conf(5), and to nft; every
  other line counts, a blank one included), with a third state, `comments`: `installed_jail`,
  `installed_filters.state` (and its `comments` list) and the ruleset's `firewall.file_state`, which
  replaces `file_current` (`same`, `comments`, `stale`). A jail whose comments alone are an older
  build's is still named, as information, with the true reason and the render line without a reload;
  a filter likewise (`fail2ban_filter_stale` as info, the install line alone). A stale jail's message
  now names an upgrade that changed a jail beside a site, a log or a login path added. Unit test, failing on
  alpha.95; the MCP texts of `protection_show` and `health_check`, `docs/fail2ban.md`,
  `docs/configuration.md` 18 and `tests/protection.sh` follow.
- **The lists of root's steps say how to run them** (the same report). alpha.95's note that every
  command root is given chains its steps with `&&` held for the one-line fixes (a finding's `fix`,
  `failure_jails` `needs`, the unit's header), not for the lists: `protection_show`'s
  `fail2ban.install`, `firewall.trial` and `firewall.keep` and `site_service_unit`'s `run_as_root` are
  steps one per item, and `protection_show`'s description said each ran only when the one before it
  worked, which holds only when they are run that way. The lists stay one step per item, to show and
  run one at a time; the MCP texts of `protection_show` and `site_service_unit` now tell the agent
  to give them in order, each only after the one before it succeeded, stopping at one that fails;
  `docs/configuration.md` 18, `docs/mcp.md`'s example and the security page's row 37 say the same.
  With `--out` a render that fails leaves the file as it was, so a step run after a failed one no
  longer damages anything.
- **`agensio pools --dry-run` says it would fix a mode** (the same report). A pool file of a loose
  mode (`0664`) was listed as "fixing the mode of" under `--dry-run`, which left it `0664`; now the
  dry run says "would fix the mode of" and the real run "fixed the mode of", beside "would write" and
  "wrote". Unit test (the dry run, then the run, of a `0664` pool file whose text is current), failing
  on alpha.95.
- **`archives_in_root` no longer counts the SQL an application ships** (the test host's health:
  `typo3/sysext/extbase/ext_tables.sql`, a TYPO3 extension's table definitions, named as a database
  dump). Not counted now: TYPO3's reserved `ext_tables.sql` and `ext_tables_static+adt.sql` in an
  extension's directory (beside its `ext_emconf.php` or `composer.json`; the same name elsewhere is
  still found), and an uncompressed `.sql` file of up to 64 KB with no data statement (no `INSERT`,
  `REPLACE` or `COPY ... FROM stdin`, any case), which defines tables and holds no rows. A larger file,
  a compressed one and anything else that may hold rows still counts. The MCP text of `health_check`
  and `docs/configuration.md` 4c say it. Unit test (`test_archives_in_root`), failing on alpha.95.

## 0.1.0-alpha.95 (2026-10-16)

- **Files root loads are written by agensio itself, whole and `0644`: `--out`** (the alpha.94 report
  from the test host; `docs/configuration.md` 18, security page row 37). The commands root was given
  wrote the fail2ban jail, the firewall ruleset, the firewall unit and the sites' application units
  with a shell's `>`. The file then took root's umask: on the test host, whose root shell had `0002`,
  all of them were `0664`, writable by root's group, and root loads or runs each of them. And the
  shell emptied the file before `agensio ctl` ran, so a failed render (the server stopped, the socket
  unreachable, a refused call) left an empty jail that the `; fail2ban-client reload` after it loaded,
  dropping every agensio jail without a word; a refused call (any answer but 200) even wrote the
  server's JSON error into the jail. Now `--out FILE` on `agensio ctl protection --jail`, `--nft`,
  `--unit` and `--filter NAME`, on `agensio protection` and on `agensio ctl site-unit NAME` writes the
  file through `write_file_atomic` (`file.cpp`): a hidden temporary file beside it, created with
  `O_EXCL | O_NOFOLLOW` and given its mode with `fchmod` whatever the umask, flushed to disk and
  renamed over the target (which also replaces a `0664` file with a `0644` one); on any failure the
  old file is untouched, nothing is left beside it, and the command exits non-zero. `agensio pools`
  writes its pool files the same way (before, the temporary file took the umask's mode until a
  `chmod`) and rewrites one of a loose mode even when its text is current, without calling that
  stale. Every command root is given chains its steps with `&&` (bash, dash and fish 3 or later), so a
  reload never follows a render that failed; stopping the firewall trial's timer keeps its `;`, since it
  fails harmlessly once the timer has fired. Changed: `protection_show` (`fail2ban.install`,
  `firewall.trial` and `keep`, `failure_jails` `needs`, every finding's fix), the answers of
  `site_create`/`site_update` that ask for a re-render, `site_service_unit`'s `run_as_root` and the
  unit's header, the jail's and the ruleset's header comments and their packaged copies, the MCP texts
  (`protection_show` and `site_service_unit` tell the agent never to rewrite them as a `>`), the
  `ctl` usage, `docs/configuration.md` 18, `docs/fail2ban.md`, the cookbook, the root suites. Health
  `root_file_writable` (warn, error when anyone may write; `control::root_file_findings`, a `stat`
  each) names the jail, the ruleset, the firewall unit, a site's application unit or a generated pool
  that its group or anyone may write, with the `chmod go-w` that fixes it.

## 0.1.0-alpha.94 (2026-10-14)

- **Health names what a live site's home page goes without: `response_headers_suggested`**
  (`docs/headers.md` 7; the test host's request's last part). For each live HTTPS site (TLS, an `app`,
  a real certificate served for a week, as for `hsts_suggested`) health asks the home page once, over
  loopback on its own thread (`control::header_probes`, `run_header_probes` over the probes'
  `fetch_heads`), and reports, as info, the fields of headers.md 4.1 its real answer lacks: a frame
  field (`X-Frame-Options`, or `frame-ancestors` in a CSP), a CSP (report-only counts),
  `Permissions-Policy`, `nosniff`; an application's own fields count (Uptime Kuma, Django send theirs),
  a redirect or an error is not judged, HSTS stays `hsts_suggested`'s (`judge_header_answer`). The fix
  sends the agent to offer them one at a time with `path_check`'s `response_headers_offer`. A site so
  asked needs no HSTS probe of its own: the same request notes an application's HSTS. The new site key
  `response_headers_offer_declined` records the fields the owner refused (the four names, any case,
  kept in their canonical spelling; HSTS is `hsts = false`'s); the finding and `path_check`'s offer leave
  them out, and it sends and removes nothing. Managed: the `site_update` field of the same name,
  `agensio ctl site-update --decline-response-header NAME` (the list replaced) and
  `--no-declined-response-headers`; `site_show` and `path_check` show the list. Reference row,
  `docs/keys.md`, the MCP texts (`health_check`, `path_check`, `site_update`), the cookbook.
- **Response headers on managed sites** (`docs/headers.md` 6, step 4 of its section 12; asked for by the
  test host: a managed WordPress site graded D on securityheaders.com, and neither `site_update`, its
  root additions file nor a hand edit could carry `[[site.response_headers]]`). `site_create` and
  `site_update` take `response_headers`, the rules as objects (`path`, `match`, `when`, `endings`, `set`,
  `default`, `remove`), sent whole (`[]` or `null` clears them), judged by the load's own parse and
  checks (`load_response_header_rules`, as `path_check`'s preview is) on the site's app, and
  `response_headers_baseline` (`false` off, `true` or `null` back to the default); the managed file
  carries them as `[[site.response_headers]]` tables (keys and values through `toml_string`, so a
  value's quotes and backslashes load back as written) and `response_headers_baseline = false`;
  `site_show` lists the written rules in the form `site_update` takes with the baseline's state; the
  change's answer carries `response_header_notes`. `agensio ctl site-update`: `--response-header "PATH
  set|default NAME=VALUE"`, `--response-header-remove "PATH NAME"`, `--response-headers-file F.json` (for
  `match`, `when`, `endings`), `--no-response-headers`, `--no-response-headers-baseline`,
  `--response-headers-baseline`; the flags of one command make the whole list, one prefix rule per path,
  as `--redirect` does. `path_check` on a page lists `response_headers_offer`: the fields of headers.md
  4.1 nothing the site decides sends there (a frame field, a CSP, `Permissions-Policy`, `nosniff` on an
  application's answer, HSTS on a TLS site without `hsts`), each with what it could break. The MCP
  texts carry section 6: what to offer one at a time and what each breaks, what other servers do
  differently (the most specific rule decides; `set` replaces; `default` for a CSP; lifetimes need
  `when = "success"`), preview with `path_check` before and confirm after; the server instructions'
  map names response headers under `site_create` and `site_update`. The reference rows name the
  managed fields; `docs/headers.md` is installed with the guides; the cookbook's header recipes show
  the managed way.
- **The security baseline: a site with `app` sends what cannot break a page, without a rule**
  (`docs/headers.md` 4, step 3 of its section 12; `docs/configuration.md` 14c). `Referrer-Policy:
  strict-origin-when-cross-origin` on every answer that has none (an application's own wins),
  `X-Content-Type-Options: nosniff` on the files and error pages agensio serves (never on an
  application's answer, where a script sent with the wrong type would stop working), `X-Powered-By`
  removed, and on `app = "static"` `Cache-Control: no-cache` on the `.html` and `.htm` files it serves,
  successful answers only, so a deploy shows at once. Built as rules at `/` marked as the baseline's
  (`HeaderRule::baseline`), resolved below every written rule at their path, its `endings` rule
  included, so a `[[site.response_headers]]` rule naming one of the fields decides; `nosniff` and
  `no-cache` are `default`s, so a location's `add_headers` copy stands (a cached directory's own
  lifetime), and `nosniff` is marked for agensio's own answers (`FieldDecision::own_only`), which the
  upstream loop leaves as the application sent them. The site key `response_headers_baseline` (first named
  `security_headers`, which did not say whether it covers requests or responses; renamed before the release; `false` turns it
  off, `true` gives a site without `app` the static site's); a site without `app`, the benchmark
  templates among them, gets none. Together with a site's rules it names at most 64 fields. `-t
  --explain` says it in a comment; `path_check` names it as each field's source (`(baseline
  wordpress)`, `nosniff` "on the files and error pages agensio serves", left out of an application's
  answer), and its preview keeps it under proposed rules. A managed static site's file now names `app
  = "static"`, which the renderer left out, so it gets the static baseline; an existing one gains the
  line at its next change. `fuzz_response_headers` models the baseline (its site is php, static or
  without app by the input's length; fifteen minutes on ten processes, 14.8 M runs, 3,066 edges, clean). The cookbook's "The security baseline a preset site gets";
  `bench/ab.sh -A` has the row `baseline` (a static site's cached page).

## 0.1.0-alpha.93 (2026-10-14)

- **`fuzz_response_headers`: the response header rules under libFuzzer** (`tests/fuzz/`, seeds in
  `tests/fuzz/regressions/response_headers/`). Rules and probes from the input load as `path_check`'s
  preview loads them (the parse, the checks and the resolution of a site file, endings included) and
  are applied as the writers and the upstream loop apply them, held to their invariants: no value a
  rule sends holds a byte outside printable ASCII and no rule sends a field the server owns; `set`
  leaves one copy, `remove` none, `default` adds one only into a gap, an undecided field passes in
  order; the password guard's cache fields and agensio's own block stand; HTTP/1's prebuilt lines are
  what the general path writes; the node's decisions agree with a scan of every rule. Twenty minutes
  in the campaign of 2026-10-14: 5.0 M runs, 2,905 edges, clean (`docs/security-control-plane.md`).
- **HTTP/2: a response head larger than one frame goes out as CONTINUATION frames** (RFC 9113 4.2,
  6.2, 6.10; `docs/design-http2.md` 6.1). The writer put any head in one HEADERS frame, so a block
  over the client's `SETTINGS_MAX_FRAME_SIZE` (16,384 bytes unless it asks for more) was a
  `FRAME_SIZE_ERROR` that closed the client's connection and every stream on it: an application's
  large head, and since alpha.89 a site's `[[site.response_headers]]`, whose 16 KB of values fit one
  answer. Found by the security pass over the response headers: 16 KB of rule fields arrived whole
  over HTTP/1 and not at all over HTTP/2. `Writer::close_headers` now writes HEADERS (with
  END_STREAM when due) and CONTINUATION frames, contiguous, within the client's frame size, the last
  with END_HEADERS; a head that fits is one frame as before, and only the rare large one pays a
  copy of its tail. The integration check failed on alpha.92 and passes; h2spec passes on both
  listeners; `fuzz_h2_conn`'s site gains response header rules and a head over one frame on `/dir`,
  under its frame-size checks. A/B against alpha.92 with the HTTP/2 rows, three rounds
  (`bench/results/ab-20261014-045459.md`): every row 0.93 to 1.02, the HTTP/2 rows 0.93 to 1.01.
- **A server with TLS read freed memory on its way out** (`src/server.hpp`). The certificate
  watch's timer (step T3, alpha.64) runs on worker 0's context but was declared before the workers,
  so it was destroyed after that context had freed its timer service: a heap use-after-free in
  `~Server` at every stop of a server serving TLS, after every request was answered and the
  listeners were closed, never on a request. It is the same fault the restart and trash timers had
  until 2026-10-09; the watch's timer now sits beside them, after `workers_`. Found by the sanitizer
  build in the security pass: the HTTP/3 attack suite counted the report as a failed row, while the
  integration suite never read its main server's stderr. It does now: SIGTERM must stop that server
  with exit 0 and no sanitizer report, a check that failed on the unfixed tree (`1 1`) and passes.
- **Four integration checks no longer depend on the timing of a pipe**: `agensio -t` or `ctl`
  piped into `grep -q` under `pipefail` failed when grep matched and exited while the binary, whose
  stderr is unbuffered, still had a line to write (SIGPIPE): the sanitizer build failed the two
  unreachable-upstream warnings this way, though `-t` printed both, and the pip_install dry run's
  check could have passed with the warning present. They match the captured text now, as the
  rendered-file checks do since 2026-10-07. And the unit tests of a build without OpenSSL pass
  again: since alpha.84 one check expected a TLS site among the canonical probes, which such a build
  leaves out on purpose (it has no TLS client to ask with).
- **The certificate watch can be seen at work: `certificate_watch` in status,
  `certificate_watch_stalled` in health** (`docs/tls.md` 3.3 and 5). The hourly check of the
  certificate and key files wrote to the error log only when it loaded a pair or could not, so
  nothing showed that it ran. `agensio ctl status` (MCP `server_status`) carries
  `certificate_watch`: its interval, the pairs it watches, its runs since the start, how long ago it
  last ran (null before the first run, an hour after the start) and when it runs next, the pairs
  loaded and failed since the start, and what the last run found (changed, loaded, unchanged,
  failed); null in a build without TLS. Health warns `certificate_watch_stalled` for the server when
  the watch has not run for two of its intervals, since a file another tool renews then waits for
  `cert-renew`. The MCP texts say where the certificates' state is: every site's at once in
  `sites_list`, the watch in `server_status` (the server instructions' map names both), what is wrong
  in `health_check`, whose `certificate_not_loaded` no longer says a reload loads the file (the hourly
  check or `cert_renew` does). No log line per run: a run that finds nothing is silent, as before.
  Nothing on the request path: the hourly timer counts its runs, on worker 0.

## 0.1.0-alpha.92 (2026-10-14)

- **`path_check` names every field a path's answer gets, and previews proposed rules**
  (`docs/headers.md` 7, configuration.md 14c; step 2c of headers.md 12). Its answer carries
  `response_headers`: each field the site decides (its `[[site.response_headers]]` rules and `hsts`)
  with its verb, value, the deciding rule (`path`, `match`, `when`, `endings`) and a line to tell the
  user (`cache-control: public, max-age=3600 (rule /embed, success only)`); for a file it serves the
  fields for its ending, for agensio's own 404 or redirect those of a non-success answer, for an
  application's answer those of a successful one and `response_headers_on_error` where other
  statuses get other fields. With proposed rules (the control API's `response_headers` query, MCP
  `path_check` `response_headers`, the rules as objects) it answers as if they replaced the site's,
  judged by the loader's own parse and checks (`load_response_header_rules`), with
  `response_header_notes`, and changes nothing. The MCP texts say what the fields mean and what other
  servers do differently. The integration checks (the embed page, a PHP answer, a 404, a preview, a
  refused proposal, MCP) failed on alpha.91. Control-plane code only: no A/B.

## 0.1.0-alpha.91 (2026-10-14)

- **Health knows an application's own HSTS before any visitor came** (the alpha.87/88 report's
  note; `docs/redirects.md` 4.2). The request path notes an application's HSTS only once an HTTPS
  answer has carried it, so after a start health suggested the site's own over it until the first
  visitor (a reload keeps the note: the store outlives generations). Health now asks each site where
  the suggestion could show (no `hsts` line, not `http = "serve"`, an application behind it, a real
  certificate served for a week, nothing noted yet) once for `/`, by its canonical name, on its own
  thread (`control::hsts_probes`, `run_hsts_probes`); the answer goes through the request path,
  which notes the field, and `hsts_from_application` follows. A site already noted is never asked
  again. The probes' requests, the canonical ones too, now go out in parallel, so health waits for
  the slowest site, not the sum. The integration check (a managed site whose application sends HSTS
  on `/`, health's first call) failed on alpha.90. Control-plane code only: no A/B.

## 0.1.0-alpha.90 (2026-10-14)

- **`endings` on `[[site.response_headers]]`: fields by kind of file** (`docs/headers.md` 2.1, 3.3,
  configuration.md 14c; step 2b of headers.md 12). `endings = ["svg"]` (any case, a leading dot
  allowed, `tar.gz` too) applies a rule only to the files agensio serves whose name ends so, read
  where the static handler answers with a file (after `try_files` and a directory's index, the name
  before a pre-compressed twin), never to an application's answer or an error page. At one path a
  rule whose endings the file has decides before one without, a longer path before both; an ending
  inside another counts for it (`gz` for `a.tar.gz`). Each node holds one pair of sets per ending its
  rules name; a request that served a file points at the pair for its ending. Refused at load: two
  rules at one path naming one field with endings that meet (the same, or one inside the other), an
  ending the site never serves itself (`php` where PHP runs it, one its preset answers 404 for); a
  CSP `set` with endings is no longer noted (it never meets the application's answer). The cookbook's
  Fields by kind of file (an SVG that runs no script, fonts for another origin). The integration
  checks (an SVG, an HTML file and a directory's index, a deeper path's rule winning, a PHP answer
  and a 404 untouched, HTTP/2, the load's refusals) failed on alpha.89; the unit test's brute-force
  reading now draws endings and served files too (400 rule sets). `bench/ab.sh HEAD -A -P -2`
  (`ab-20261014-000223.md`, a noisy run: the base's own rounds 2.00 to 2.26 on the 1 KB row):
  0.93 to 1.06 but for `proxy /slow` (1.139) and `headers` (1.078); the access rows again with three
  rounds (`ab-20261014-001005.md`): `headers` (an endings rule against the same field from a rule
  without one) 1.008, the rest 0.96 to 1.03.

## 0.1.0-alpha.89 (2026-10-14)

- **`[[site.response_headers]]`: fields a site sets, defaults or removes by path** (`docs/headers.md` 2,
  configuration.md 14c; step 2a of headers.md 12). `path`, `match`, `set` (replaces every copy, the
  application's and a location's `add_headers` too), `default` (only where the answer has none),
  `remove`, `when = "always" | "success"`. Per field the most specific rule naming it decides (the
  longest path, an exact rule before a prefix one), rules naming different fields all apply, and
  the order they are written in never matters; on an error a success-only rule gives way to the
  next rule naming the field. On every answer the site gives: files, PHP, CGI, a proxied
  application, agensio's own error pages, redirects, 401 and 403, over HTTP/1, HTTP/2 and HTTP/3.
  Resolved at load into one node per rule path (`core/response_rules.hpp`), found once per request
  behind a first-byte bitmap; an application's answer is decided in the upstream loop, agensio's own
  where each writer sends its extra fields (`core/response_fields.hpp`), a cached file over HTTP/1
  taking the node's lines as one prebuilt block. The guards stand: behind a password the rules leave
  `Cache-Control` and the CDN fields to it, and agensio's own `no-store` and `Retry-After` on its 401,
  403 and 503 are never replaced. Refused at load with the setting to use: the framing and
  representation fields, `Location`, HSTS in `set` or `default` (`hsts`), `Server`, `Alt-Svc`,
  `Set-Cookie` and the other fields of section 2.5; a value that is empty, over 4 KB, holds a control
  character or a `$`; a cache lifetime without `when = "success"`; a frame field other than `DENY` or
  `SAMEORIGIN`; a CORS origin list, `*` with credentials; a field twice at one path or in two verbs;
  more than 64 rules or names or 16 KB of values. Noted by `-t`, the error log and health: a CSP
  `set` on an application site, `X-XSS-Protection` other than `0`. `-t --explain` prints them. The
  cookbook's Security fields by path, and its cache recipe now a success-only rule. The integration
  checks (a PHP fixture whose own fields are replaced, kept or dropped, a deeper rule, a 404, a 403,
  HTTP/2 and HTTP/3, the load's refusals and notes) failed on alpha.88; the unit test reads 300
  random rule sets by brute force against the nodes. `bench/ab.sh HEAD -A -P -2`
  (`ab-20261013-231522.md`): the static, HTTP/2 and proxy rows 0.95 to 1.03, `proxy-hdr` (the
  upstream behind set, default and remove rules) 0.997; the new `headers` row against the same
  fields from a location's `add_headers`, three rounds (`ab-20261013-232830.md`): 0.969, the rules'
  prebuilt block cheaper than `add_headers`; `-3` three rounds (`ab-20261013-233320.md`): the h3
  rows 0.96 to 1.06, the 100 KB one the loopback-loss row.

## 0.1.0-alpha.88 (2026-10-14)

- **The COPR spec builds and installs on Fedora** (`packaging/rpm/agensio.spec`; COPR is not
  enabled yet, the release's `.rpm` comes from CPack and was not affected). Built from the alpha.87
  tree in `fedora:latest` (Fedora 44), it failed three ways: `%files` owned `/var/log/agensio`,
  `/var/lib/agensio` and `/var/www/html`, which nothing in `%install` made (since the spec was
  written); its own `%doc` list left the guides CMake installs (`tls.md`, `keys.md`, `redirects.md`,
  the cookbook, `LICENSE`) as files no package owned; and Fedora's rpm requires `user(agensio)` and
  `group(agensio)` for the owners in `%files`, which only a sysusers.d file provides. The spec now
  makes the directories, packs the documentation directory CMake fills, and installs
  `packaging/agensio.sysusers` as `/usr/lib/sysusers.d/agensio.conf`; `%pre` still makes the account
  where rpm reads no sysusers.d (EPEL 9). `tests/rpm.sh` (new; docker, the first run fetches the
  build dependencies) builds it from the working tree, installs it and checks the guides, the
  owners and `agensio -t`: it failed on the old spec and passes now. Packaging only: no A/B.

## 0.1.0-alpha.87 (2026-10-14)

- **Health says an application already sends HSTS instead of suggesting the site's over it** (the
  alpha.86 report; `docs/redirects.md` 4.2). Kanboard (`ENABLE_HSTS`) and Rails (`force_ssl`) send
  their own `Strict-Transport-Security`, and `hsts_suggested` advised `hsts = true`, which replaces
  the field and, for Rails' two years with `includeSubDomains`, with a weaker one that
  `hsts_narrows_application` then reported. On a site with no `hsts` line the application's field
  goes out as it is and is noted on the first HTTPS answer that carries it, once per generation of
  the site (`SiteFields::watch_application` and `application_noted`; until then one size
  comparison per response field, nothing on a site with `hsts` or without an upstream); health then
  gives `hsts_from_application` (info) in place of the suggestion: the value, that nothing is needed,
  `hsts = false` to record it, and, when the application's commits to more than a year for this
  host, the `hsts = { max_age, subdomains }` table that matches it and why `hsts = true` would weaken
  it. The integration check (a managed site with a month-old certificate and an application sending
  two years with `includeSubDomains`) failed on alpha.86's code. `bench/ab.sh HEAD -A -P`
  (`ab-20261013-220307.md`, two rounds): 0.975 to 1.032; again with three rounds
  (`ab-20261013-220852.md`): 0.975 to 1.015 but for the 20 ms proxy row at 1.064, whose base alone
  moved 6.50 to 6.99 us between the runs; that row and the other proxy rows with five rounds
  (`ab-20261013-221738.md`): 1.012 to 1.019, the rounds of both sides overlapping.

- **The redirects guide installed, and the `/index.php/` recipe** (`docs/redirects.md` 12.3, 13
  step 5). `docs/redirects.md` is built (alpha.75 to alpha.86), so it is installed with the other
  guides that point to its sections (health's fixes, `docs/tls.md`, configuration.md 14), and its
  status says what is not built yet. The cookbook's new recipe, Old addresses with /index.php/ in
  them (`docs/examples/php.md`), is Drupal's nginx `rewrite ^/index.php/(.*) /$1 permanent;` as one
  rule from `/index.php/` to `/`: a `from` ending in `/` covers only the paths below it, so
  `/index.php` itself, where forms post, runs as before (a unit check holds the matching to it).
  The MCP `redirects` text says the same for an agent migrating such a site. Documentation and
  texts only: no A/B.

## 0.1.0-alpha.86 (2026-10-14)

- **Health names what only requests show: a proxy that sends no scheme, an application's stronger
  HSTS** (`docs/redirects.md` 2.4, 4.1). `proxy_scheme_missing` (warn): a proxy in `trusted_proxies`
  whose requests carry no `X-Forwarded-Proto`, to a site whose plain HTTP redirects; agensio takes
  them as plain HTTP (never as HTTPS on a guess) and redirects them, so visitors who used HTTPS at
  the proxy loop. Noted on the redirect itself, each worker at most once a minute per site; health
  names it for an hour while the site still redirects and still trusts the proxy, and the error log
  once a minute, with the proxy's setting as the fix. `hsts_narrows_application` (warn): the
  application's `Strict-Transport-Security` commits browsers to more than the site's `hsts` (a
  longer `max-age`, `includeSubDomains`, `preload`; RFC 6797 6.1), which replaces it; noted on the
  first such answer of each generation of the site (one relaxed load per later answer carrying the
  field), named by health while it is still stronger than the site's, and by the error log;
  `hsts = false` lets the application's through. Both through one store
  (`core/site_notices.hpp`); a request that meets neither never reaches it. The MCP `health_check`
  text, `docs/mcp.md`, `docs/tls.md` and configuration.md 14 name them. The two integration checks
  failed on alpha.85. `bench/ab.sh HEAD -A -P` (`ab-20261013-204420.md`): every row 0.93 to 1.02 of
  alpha.85's CPU per request, the proxy rows 0.96 to 1.00.

## 0.1.0-alpha.85 (2026-10-13)

- **The load's redirect notes in the answer of the change that made them** (the alpha.83 report;
  `docs/redirects.md` 8). `site_create` and `site_update` answered `ok` with `warnings: []` for rules
  in a chain, which `-t`, health and `site_show` then noted; their answers now carry
  `redirect_notes` (`{code, text}`: `redirect_chain`, `redirect_soft_404`,
  `redirect_under_protection`, `redirect_skips_validation`), taken from the site as the reload just
  loaded it, with its protections, refuse patterns and ports, as `path_check`'s preview gives them.
  The MCP `redirects` text said the answer's warnings named a chain; it names `redirect_notes` now.
  The integration check failed on alpha.84. Control-plane code only: no A/B.

## 0.1.0-alpha.84 (2026-10-13)

- **Health: HSTS suggested once HTTPS has proven itself, certificate findings raised with it, and an
  application that loops against `canonical`** (`docs/redirects.md` 3.4, 4.2; `docs/tls.md` 5).
  `hsts_suggested` (info): a TLS site with no `hsts` line, not `http = "serve"`, whose real
  certificate (not the placeholder) has served for 7 days with no certificate finding open; the fix
  says what HSTS commits to. `hsts = false` is a decided no that silences it: a managed site renders
  it (`hsts_decided` in the spec line, set whenever `site_update` sends `hsts`), and `agensio ctl
  --no-hsts` sends it. With `hsts` on, `certificate_expiring` and `acme_renewal_failed` are errors
  and say why: a visitor can no longer click past an expired certificate.
  `app_redirects_elsewhere` (warn): for each site with `canonical`, health asks the site's own
  listener once for the canonical home page (`GET /`, Host and SNI the canonical name, three seconds
  per step) and reports an answer redirecting to another of the site's names, a loop with
  agensio's redirect back, with the application's setting to change (WordPress's `home` and
  `siteurl`, Laravel's `APP_URL`, Drupal's `$base_url`, Grav's `custom_base_url`, Django's and
  Wagtail's, Redmine's host name). The requests block, so health runs them on a thread of its own
  and answers when they are done (`Server::health_async`, `control/probe.*`), never on a worker that
  may have to answer them; a server with no such site answers as before. The MCP `health_check`
  text and `docs/mcp.md` name the three. The integration check for the loop failed on alpha.83.
  Control-plane code only: no A/B.

## 0.1.0-alpha.83 (2026-10-13)

- **Path redirects on a managed site, and `path_check` for them** (`docs/redirects.md` 5, 8,
  configuration.md 14b). `site_create` / `site_update` take `redirects`, the site's rules as
  objects (`from`, `to`, `status`, `match`, `remainder`, `query`, `cache`), the list sent whole
  (`[]` clears it), judged by the loader's own parse and checks before the file is written and by
  the reload after, which undoes a refused change; they are rendered as the file's
  `[[site.redirect]]` tables. `agensio ctl --redirect "FROM TO STATUS"`, `--redirect-exact`,
  `--gone FROM`, `--redirects-file rules.json` (a migration's list), `--no-redirects`; given together
  they replace the list. `path_check` names the rule that decides a path (`decision` redirect or
  gone, `redirect`, `redirect_location`, and `plain_http` the one hop from plain HTTP), after
  `refuse` and before the access rules as a request meets them; with proposed rules (`ctl
  path-check NAME PATH --redirect ...`, MCP `path_check` `redirects`) it answers as if they applied,
  checked as the loader would, and changes nothing (`preview: true`, the load's notes). `site_show`
  lists the rules in force and their notes. The MCP texts carry what other platforms do
  differently (the most specific rule decides, not the first; a status always given; a placeholder
  at the end of a target is a prefix rule; a status 200 line is a rewrite). Security page row 42.
  The integration checks (a managed site's rules through `site_create`, the `ctl` flags,
  `path-check` and a preview through `ctl` and MCP) failed on alpha.82. Control-plane code only:
  no A/B.

## 0.1.0-alpha.82 (2026-10-13)

- **Path redirects: `[[site.redirect]]`** (`docs/redirects.md` 5, configuration.md 14b). A rule
  sends a path or a section elsewhere: `from` (a normalised path, case-sensitive; an exact rule may
  name the query parameters it requires, in any order), `match` (`"prefix"`, whole segments, or
  `"exact"`), `to` (a path of the site or an http(s) URL), a required `status` (301, 302, 307, 308,
  or 410 with no target), `remainder` and `query` (`"keep"` or `"drop"`), `cache` (how long browsers
  keep a permanent one, a day by default). The most specific rule decides, never the order:
  exact rules are looked up in a hash table, prefix rules longest first behind a test of the path's
  first byte. Rules stand after `refuse` and before the access and password rules; from plain HTTP
  the scheme, the host (`canonical`) and a rule are one hop with the rule's status. agensio writes
  the Location byte by byte (`core/redirect.hpp`): a target of the site stays relative, the rest of
  the path and the query are encoded again, one `/` at the join, never `//` or `/\` at the start,
  an absolute one names exactly the host of `to`; a path that spelled a separator as `%2F` is not
  redirected by a prefix; certificate validation over plain HTTP is never redirected. The load
  refuses a rule under its own target or rules in a circle (each target followed through the
  site's rules, on the site's own names and ports), the same `from` twice, a rule `refuse` makes
  unreachable, a `to` with a user name, another scheme, `..`, a space or a control character,
  `cache` on a temporary status, more than 1,000 rules; it notes chains, a rule from `/` dropping
  the rest (a soft 404), a rule under an access or password rule, one over the validation paths
  (`-t`, the error log, health). A new fuzzer, `fuzz_redirect`, holds the Location to those
  promises and the index to a scan of every rule. Breaking: the string key `redirect =
  "https://host"` is refused, naming the rule to write (`from = "/"`); a site a rule from `/`
  answers whole needs no root. Managed sites get rules through `site_update` in the next release.
  The integration checks (the design's examples, the order against refuse and an access rule,
  case and encoded separators, one hop with `canonical`, a domain that moved, the load's
  refusals and a chain) failed on alpha.81. `bench/ab.sh HEAD -A -2` (`ab-20261013-171835.md`, two new rows: 1,000 exact
  rules on a path none names against the same site without rules, and a rule from `/` against the
  old key's 301): every row 0.96 to 1.05, alpha.81 against itself 0.98 to 1.07
  (`ab-20261013-164453.md`); the gate's rows again with three rounds (`ab-20261013-172448.md`):
  the miss 0.990, the hit 1.010 (with its `Cache-Control`, which the old answer did not carry).

## 0.1.0-alpha.81 (2026-10-13)

- **One name for a site: `canonical`** (`docs/redirects.md` 3, configuration.md 14). A site lists
  every name in one block and `canonical` names the one the others redirect to: a `308`, path and
  query kept, kept a day; over plain HTTP the scheme and the host in one hop, or with `hsts` the
  name's own HTTPS first so it learns HSTS too (4.3); over HTTPS, and on a site that serves plain
  HTTP, the scheme and the port the client used kept. It must be one of the site's exact names;
  only listed names redirect (a catch-all's names and IP addresses are answered as before), and
  certificate validation over plain HTTP is answered on every name. The base URL handed to Django
  and the tasks is the canonical one. Managed sites: `site_create` / `site_update` `canonical`
  (the domain or an alias, refused otherwise, checked again when the aliases change), `agensio
  ctl --canonical NAME` / `--no-canonical`, so the cookbook's canonical-host recipe is one site
  file instead of two, managed. A site without it, or without `http` redirects, still pays one
  flag test before routing. The integration checks (three hand-written sites and a managed one)
  failed on alpha.80, where the key did not load. `bench/ab.sh HEAD -A -2`
  (`ab-20261013-162519.md`): every row 0.96 to 1.05, within the same session's baseline of alpha.80
  against itself (`ab-20261013-161306.md`, 0.94 to 1.07).

## 0.1.0-alpha.80 (2026-10-13)

- **`site-update` says why it cannot help with a hand-written file set aside** (the alpha.78
  report's notes). It answered "no such site" for a site whose hand-written file did not load; it
  now answers 409 with the file and the loader's error, since only an edit by hand mends it. The
  site is found by the names its file claims, read as the loader reads a file set aside (its text
  scanned when it is not TOML), on that error path only. The texts that said a managed file set
  aside is written again "with no other field" now say what alpha.78 does: with any fields or none.
  The integration check (a hand-written file in a refused form) failed on alpha.79 with 404.
  Control-plane code only: no A/B.

## 0.1.0-alpha.79 (2026-10-13)

- **An application's own `http://` redirects go out as `https://`** (`docs/redirects.md` 2.5). An
  application that does not trust agensio as its proxy builds its redirects from what it sees,
  plain HTTP, so on an HTTPS site every such redirect sent the visitor through the plain port's
  `308` first. On a site whose `http` is `"redirect"`, a Location naming one of the site's names
  (no port, port 80 or the TLS port, as the Host the application was given) now goes out as
  `https://` on the site's TLS port, for proxied, PHP and CGI answers alike, after the proxy's own
  rewrite of a Location naming the origin; any other Location passes as sent. The integration
  checks (a PHP script and a proxied origin redirecting to `http://` plus the Host they were given)
  failed on alpha.78. `bench/ab.sh HEAD -A -2 -P` (`ab-20261013-155027.md`): every row 0.96 to
  1.04, the proxy rows 0.99 to 1.01; alpha.78 against itself (`ab-20261013-153721.md`) moved 0.95
  to 1.05.

## 0.1.0-alpha.78 (2026-10-13)

- **`site-update` repairs a managed file a newer version refuses.** When a release changes the form
  of the files the control plane writes (alpha.75's `hsts`, alpha.76's plain block), a managed file
  written before is set aside like any file that does not load, and `site-update` answered "no
  such site" for it, so root had to edit the file by hand before upgrading (the alpha.76 report's
  note). `site-update NAME` now also reaches a managed file the running configuration set aside,
  by its domain or an alias, and with no other field writes it again in this version's form from
  its first line, validates and reloads; health's `site_file_held_back` names `agensio ctl
  site-update NAME --yes` for such a file (not for one set aside for its certificate). No
  automatic migration: while agensio is in alpha a release may still change these forms. The
  integration check (a managed file with a body this version refuses, never loaded) failed on
  alpha.77 with 404.

## 0.1.0-alpha.77 (2026-10-13)

- **Over plain HTTP the certificate validation prefixes reached the site's applications.** alpha.76
  let `/.well-known/acme-challenge/` and `/.well-known/pki-validation/` past a site's redirect so
  a file there could be served, but the request then went through the site's whole routing: on
  the test host a missing path ran Kanboard's front controller, which redirected to its login and
  set a session cookie over plain HTTP, Drupal answered its own 404, a Node application was
  proxied and answered 200, and a `.php` file there would have run. Those requests now get one
  location of the site built at load: a regular file under the root, else `404`, with no index, no
  fallback, nothing run and the PHP endings and source backups refused; a proxied preset (rails,
  redmine, django, wagtail, node, proxy), whose root is a project directory, answers `404` to all
  of it. agensio's own ACME tokens are answered before any site as before, and over HTTPS the site
  is unchanged. `path_check` gives `plain_http` on an HTTPS site: what the same GET gets over plain
  HTTP. Reported from the alpha.76 test host; the integration checks (a managed WordPress site: a
  missing path, the directory and a `.php` file under the challenge prefix, and a proxied site in
  front of a dead origin, which answered 502) failed on alpha.76. `bench/ab.sh HEAD -A -2`
  (`ab-20261013-150429.md`): every row 0.93 to 1.03, within the same session's baseline of alpha.76
  against itself (`ab-20261013-145128.md`, 0.93 to 1.08).

## 0.1.0-alpha.76 (2026-10-13)

- **One block for HTTP and HTTPS: a site's `http` key** (`docs/redirects.md` 2, configuration.md
  14). A TLS site on port 443 now also listens on port 80 at the same addresses and answers plain
  HTTP itself with a `308` to the same name, path and query over HTTPS, with `Cache-Control:
  max-age=86400` (Chromium keeps a permanent redirect without a lifetime forever; a name only a
  catch-all took gets `no-store`). `http = "serve"` serves both schemes (refused with `hsts`),
  `"off"` opens no plain listener, and `http = { listen = [...] }` names the plain addresses of a
  TLS site on another port, whose redirect then names the TLS port (`mode = "serve"` serves
  them). Without TLS, `http = "redirect"` is for a proxy in front that holds the certificate:
  what a trusted proxy marks `X-Forwarded-Proto: https` is served, the rest redirected. Fixed
  with it: certificate validation is answered from the site's files before the redirect
  (`/.well-known/acme-challenge/`, `/.well-known/pki-validation/`), where the separate plain
  block had no root and redirected them, so certbot's webroot mode needed the HTTPS site already
  serving and a CA's file check failed; and a managed site whose TLS port is not 443 redirected
  to port 443. Breaking: `redirect = "https"` is refused, naming `http`; a plain `[[site]]` for
  the same names on port 80 now meets the TLS site's own port 80 and is refused as a name claimed
  twice (the message names `http = "off"`); managed files are rendered as one block, and one
  written before does not load (the new binary sets it aside, so `site-update` cannot reach it):
  delete its plain block before the upgrade, adding `http = "serve"` to the TLS block when that
  block served instead of redirecting, or `http = { listen = [...] }` when its address was not port
  80 beside 443; that is the new rendering. The `https://host` prefix of `redirect` stays until
  `[[site.redirect]]`; its port 80 comes with port 443 and goes straight to the prefix. Sites on
  one plain address now agree on `h2c` alone (a plain listener speaks nothing else). The
  integration check (a managed HTTPS site on port 8453 with its plain port on 8454: a challenge
  and a pki-validation file, a missing one, the redirect and its lifetime) failed on alpha.75
  with a 301 for all of them, to port 443. `bench/ab.sh HEAD -A -2` (`ab-20261013-141422.md`): the
  1 KB and request-path rows 0.94 to 1.01 (plain, TLS, h2c, h2, access, refuse, hsts, auth), the
  10 MB streams 1.00 and 1.05, within the run to run of the baseline of the same code
  (`ab-20261013-133912.md`).

## 0.1.0-alpha.75 (2026-10-13)

- **HSTS reached neither a managed site's PHP pages nor its error answers.** `hsts: true` on a
  managed site was rendered as a `/` location with `add_headers`, and a location's fields go only
  on that location's successful file answers: a WordPress page (the `.php` location), a file under
  `/wp-includes/` (a location of its own) and every 404 went without it, and an HSTS the
  application sent passed beside it. `hsts` is now a `[[site]]` key (`true`, `false`, or `{
  max_age, subdomains }`, `max_age` as seconds or a duration, at most ten years, 0 to make browsers
  forget it) sent on every answer the site gives over HTTPS, or that a trusted proxy marks https:
  files, PHP, CGI, proxied applications, error pages and redirects, over HTTP/1, HTTP/2 and HTTP/3,
  replacing the application's own; never over plain HTTP or h2c. The value is built at load; the
  request points at it once the site is known (`SiteFields`, the mechanism the coming
  `[[site.response_headers]]` reuses, `docs/headers.md`); the HTTP/1 head copies the line beside
  `alt-svc`, HTTP/2 inserts it once per connection by its static name and then sends one index
  byte, HTTP/3 sends the default value as QPACK's static entry, one byte. Breaking:
  `Strict-Transport-Security` in `add_headers` is refused, naming the key, and managed files are
  rendered with `hsts = true`; re-render a managed site with `agensio ctl site-update NAME --hsts`.
  The integration check (a managed WordPress site over TLS: its front page, login page, a static
  file, a 404 and a script sending its own `max-age=5`, over HTTP/1, HTTP/2 and HTTP/3, and its
  plain block) failed on alpha.74. `bench/ab.sh HEAD -A -2 -3 -r 3` (`ab-20261013-130052.md`, a new
  `hsts` row: a TLS site with the key against the same field through `add_headers` on the base):
  every row 0.98 to 1.04, the HTTP/2 and HTTP/3 rows of sites without hsts flat, the hsts row 1.010.

## 0.1.0-alpha.74 (2026-10-13)

- **A field with `_` in its name reached a proxied origin.** The client-address fix of alpha.73
  dropped `X-Real-IP`, `Client-IP` and the CDN fields under their dashed names, but Rack and
  Puma build their environment CGI-style, so `Client_IP` reached a Rails application as the
  `HTTP_CLIENT_IP` it checks against `X-Forwarded-For`: one request answered 500 on every page
  (`ActionDispatch::RemoteIp::IpSpoofAttackError`, seen on Writebook and Redmine), and with the
  check off `Client_IP` chose the address Rails saw; `X_Remote_User` passed beside the field
  `forward_user` writes, so a client let in by `skip_for` or on an open path could name a user.
  Every client field with `_` in its name is now dropped toward a proxied origin, from any peer,
  as FastCGI and CGI already did and nginx does by default (`underscores_in_headers off`).
  Reported from the alpha.73 test host; the unit test of the forwarded head failed before the
  change, and an integration check sends the fields through the proxy. `bench/ab.sh HEAD -P -r 3`
  (`ab-20261013-111454.md`): proxy `/json` 1.004, 100 KB 1.012, the static rows 0.95 to 0.99; the
  20 ms-origin row 1.090, a row that read 1.073 with the same code on both sides in the baseline run
  before the change (`ab-20261013-110321.md`).

## 0.1.0-alpha.73 (2026-10-13)

- **An explicit `status=5xx` showed every access-log line.** The logs query read a status by its
  first digit through `atoi`, so `5xx`, the documented default given explicitly (as an agent does
  through MCP `logs_query`), became "status 5 and above": 2xx and 3xx lines came back as if they
  were errors; any other value it did not know was misread too. A class (`5xx`, `4xx`, `3xx`,
  `2xx`, any case) now means that class and above, `all` everything, a status of at most three
  digits that status and above; anything else is refused with a 400 naming the forms
  (`control::status_filter`, the control handler). Reported from the alpha.72 test host; the
  unit test failed with the old parsing moved unchanged into the function, and an integration
  check reads the 4xx and 2xx lines the suite wrote through the socket.
- **A site names the proxies that speak for it** (`docs/redirects.md` 2.4, decided 2026-10-13).
  With several proxies in `[server] trusted_proxies` every site believed all of them, and a CDN's
  addresses are shared by all its customers, so a customer of one CDN could name the client and
  the scheme of a site behind another. `trusted_proxies` on a `[[site]]` narrows the server's list
  for that site (`[]` believes none, for a site visitors reach directly): a request from a proxy
  the server trusts and the site does not is the peer's own, its address the client of the access
  rules, the logs, fail2ban, `REMOTE_ADDR` and the origin's `X-Real-IP`, its scheme the
  connection's. Each entry must lie within the server's list, which only root widens. Both lists
  take the `[addresses]` sets (`@cdn_a`). `site_update` and `site_create` take `trusted_proxies`
  (`null` back to the server's list), `agensio ctl` `--trusted-proxy`, `--no-trusted-proxies` and
  `--trusted-proxies-default`; `site_show` and `sites_list` show it; health reports
  `site_trusts_every_proxy` when the server lists two or more sets and a site names none. A site
  without the key pays one test of a flag per request: `bench/ab.sh HEAD -A` (`ab-20261013-021721.md`)
  0.96 to 1.03 on every row, the access rows 0.99 to 1.03, within noise.
- **fail2ban could ban a trusted proxy for the whole host.** A proxy in `[server] trusted_proxies`
  reaches the access log under its own address when it sends a request without
  `X-Forwarded-For`, and the rendered jails counted it like any client, so ten posts to a login
  path through it banned the proxy in the host's firewall and cut off every visitor it carries,
  for every site behind it. On a host with trusted proxies every agensio jail now lists them, with
  loopback, in `ignoreip`. The line is plain: `%(default/ignoreip)s` or `%(known/ignoreip)s` in
  agensio's file stops fail2ban altogether where `[DEFAULT]` defines no `ignoreip`, the stock
  configuration (tried on 1.1.0). A jail's own line wins over `[DEFAULT]`'s, so on such a host an
  administrator's own addresses go into the jails they could trip, with `known/`, in a file read
  after agensio's (`docs/fail2ban.md` 4). A host without trusted proxies renders as before. Render
  the jail again after upgrading; health reports the installed one stale. The unit test of the
  renderer failed before the change; `tests/protection.sh` loads the file into fail2ban and reads
  the lists back.
- **`proxy = { headers = { ... } }` is now `request_headers`** (breaking): the fields agensio sends
  to the origin with the request, named for the way they go, beside the response fields of the
  coming `[[site.response_headers]]` (`docs/headers.md`). There is no alias: the old name is
  refused at load like any unknown key (`.proxy: unknown key 'headers'`, with the table's keys
  listed), so a main file that uses it does not start and a site file that uses it is set aside
  until renamed. Check before upgrading with the new binary's `agensio -t`. Also: a field error in
  `add_headers`, a proxy's request fields, `cgi.env` or `php.extra` named `add_headers` whichever
  table it was in; it now names the table written.
- **A client could choose the address a proxied application saw.** agensio passed a client's own
  `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP`, `Client-IP` and the like to the origin
  unchanged unless the site set the field itself, and an application behind agensio sees
  agensio's loopback address as its peer and believes such a field from there: Vaultwarden keys
  its login rate limits on `X-Real-IP`, Grafana and Rocket.Chat read it first, Umami and
  Plausible read the CDN fields before `X-Forwarded-For`, Rails reads `Client-IP`. Every proxied
  request now carries `X-Real-IP` with the client agensio believes (the address of its own logs
  and access rules, as 17 of the 25 applications' proxy guides reviewed ask), a client's own
  copy is never passed on, and the fields in which a CDN names the client pass only from a peer in
  `trusted_proxies`. `proxy = { request_headers = { "X-Real-IP" = "" } }` stops agensio's own, and
  `forwarded = "off"` sends none. Found by the review of applications' proxy configurations
  (`docs/redirects.md` 12.4); the unit test of the forwarded head failed before the fix, and two
  integration checks send the fields from a trusted and an untrusted address. `bench/ab.sh HEAD
  -P` (`ab-20261013-011921.md`): the proxy rows 1.012 (`/json`), 1.031 (100 KB) and 0.929 (a
  20 ms origin), within the spread of the baseline run before the change (`ab-20261013-010522.md`,
  `/json` 4.65 to 5.07 us on unchanged proxy code); the static rows flat. The origin parses one
  more field, about 30 bytes.

- **A trash restore could succeed with a log directory the server cannot enter.** When a restore
  has to create the directory of a log or a password users file again, the root helper gives it
  the server's group (`0750`), through which the server reaches the file after the privilege
  drop; the result of that `chown` was never checked, so a failure left the directory root's
  alone and the restore still answered ok. It is now checked (on the directory opened without
  following a symlink), and a failure ends the restore with the reason and puts back what it
  moved. Found through GCC's unused-result warning; root's `chown` does not fail in the test
  machine, so no test shows the old behaviour, and `tests/trash.sh` now checks the path itself
  (the users files' directory removed while the site is in the trash comes back root's, the
  server's group, `0750`).

## 0.1.0-alpha.72 (2026-10-12)

- Four new fuzz targets for parsers of client and administrator input that had none:
  `fuzz_refuse` (the `refuse` patterns and their index against normalised paths),
  `fuzz_fields` (`Range`, `If-Range`, `Accept-Encoding`, `X-Forwarded-For` and `-Proto` behind
  trusted proxies, CIDRs), `fuzz_auth_users` (password files, their dates, the Basic field) and
  `fuzz_log_line` (the three log formats `agensio ctl logs` reads back, moved for it from
  `control/commands.cpp` into `control/loglines.*`, behaviour unchanged). Each asserts what its
  parser promises, not only memory safety. All seventeen targets ran five minutes each under
  ASan and UBSan, with no finding but the undefined behaviour of the next entry
  (`docs/security-control-plane.md`, "Sanitizer and fuzz record"); the weekly job installs
  libxcrypt so `fuzz_auth_users` runs there too.
- **A fuzz run with undefined behaviour was reported clean.** UBSan in the fuzz builds printed
  its report and let the target go on, so libFuzzer exited 0 and `scripts/fuzz-all.sh` counted
  the run clean; the campaign above missed four reports from `fuzz_log_line` that way. Every fuzz
  target is now built with `-fno-sanitize-recover=undefined`, so undefined behaviour stops the
  run and keeps its input like a memory error, and the record is corrected.
- **`fuzz_h2_conn`, the HTTP/2 connection fuzzed with the server behind it.** The real
  connection over a socket pair, in front of the server's own dispatcher, handlers, cache and
  logs, driven by a script of requests, frames of any shape, raw bytes, reading stopped and
  resumed, windows replenished or not, and time moved by a fuzz-build hook (`fuzz_age`; the
  release code is byte-identical). It checks what the server sends against RFC 9113 and 7541
  and that the connection ends with its client. 49 M runs on twenty processes found five
  server bugs, each fixed in an entry below.
- **HTTP/2: `memcpy` from a null pointer when a connection began.** After ALPN the connection
  is handed no bytes read yet, as an empty view whose pointer may be null, and the constructor
  copied them with `memcpy`, which may not be given a null pointer even for nothing (undefined
  behaviour; harmless with glibc, flagged by UBSan). The copy now runs only when there are
  bytes. Shown first by `fuzz_h2_conn` (the input `preface-socket`).
- **HTTP/2: a closed stream could be queued again and go back to the pool still queued.** A
  stream closed while its bytes were in flight (cut by the idle check, reset) stays in the
  table until the write completes; a WINDOW_UPDATE for it or for the connection, a SETTINGS
  change of the initial window, or a body read completing put it back in the writer's queue.
  When the write completed it was reset into the pool while the queue still linked it. Seen
  with a client that stopped reading a large file and later sent a window update: after the
  stream's RST_STREAM the server sent a `200` head with nothing but `server` and `date` on it.
  By the code, the rest of the queue could be lost behind it, and with the pool full (or shed
  when idle) the queue held a freed stream. The writer now refuses a closed stream, a body read
  that completes on one releases it, and a fuzz build asserts that no queued stream is reset.
  Shown first by `fuzz_h2_conn` (the input `closed-stream-requeued`).
- **HTTP/2: a second GOAWAY could name a higher last stream id than the first.** When a client's
  misbehaviour passed the first threshold of its budget the server sent a GOAWAY naming the last
  stream it had taken; a HEADERS the client had already sent on a higher id was refused, but
  when the connection then closed on a protocol error its GOAWAY named that id. RFC 9113 6.8 forbids
  raising it: the client may already have retried those requests elsewhere. Every GOAWAY now
  names the lower of the highest stream opened and what an earlier GOAWAY named. Shown first by
  `fuzz_h2_conn` (the input `goaway-last-id-raised`).
- **HTTP/2: a request on a stream the server had reset while idle was served.** A PRIORITY frame
  making an idle stream depend on itself is answered with RST_STREAM (RFC 7540 5.3.1, which
  h2spec still checks), which closes that stream for the server (RFC 9113 5.1); a HEADERS the
  client then sent on it was answered as a new request. The id is now remembered with the other
  streams the server reset, and such a HEADERS is decoded, to keep the header table in step, and
  dropped. Shown first by `fuzz_h2_conn` (the input `headers-after-idle-reset`).
- **HTTP/2: an empty DATA frame could draw a WINDOW_UPDATE of zero.** When a DATA frame's bytes
  are taken (read by the handler, or dropped after the response) the server returns them to the
  client's windows, and once a window ran low it sent the update whatever the amount, so a frame
  of no bytes (an empty DATA with END_STREAM, as clients end an upload) drew an increment of
  zero: a stream error for the client, and on stream 0 a connection error (RFC 9113 6.9). A frame
  of no bytes now returns nothing. Shown first by `fuzz_h2_conn` (the input `window-update-zero`).
- **Listening on both `0.0.0.0:P` and `[::]:P` worked only with SO_REUSEPORT.** A `[::]` listener
  takes IPv4 too, so without SO_REUSEPORT (macOS, where agensio runs one shared acceptor, or
  `reuse_port = "off"`) the second bind failed and the server did not start (`cannot bind
  :::P: Address already in use`), though `-t` said OK. Next to an IPv4 listener on its port,
  `[::]` is now opened IPv6-only there, as nginx does; with SO_REUSEPORT nothing changes, the
  kernel already gave IPv4 connections to the IPv4 socket. That also confirmed the cookbook
  writers' suspicion: a site on `[::]:P` alone next to sites on `0.0.0.0:P` was never reached
  over IPv4, and `-t` and health now say so (`listen_ipv6_only`). Without SO_REUSEPORT a
  running socket's families cannot change: a reload adding `0.0.0.0:P` beside a `[::]:P` that
  was opened alone is refused with the reason, one removing it leaves `[::]:P` IPv6-only with a
  warning; a restart applies either. HTTP/3's UDP sockets bound both already. Shown first by
  `tests/integration.sh` (the start that failed, each family's site, the two reloads) and a unit
  check (the notice).
- **`agensio ctl logs --since` with a huge number, and a JSON access line with an absurd
  status, were undefined behaviour.** `since=99999999999999999999s` or `999999999999999w`
  overflowed a signed integer while the bound was computed, and a JSON line's `status` of 1e30
  or -1 was converted to `int` as it was. A relative time further back than a century now means
  from the beginning, and a status outside 0 to 999 is 0 (unknown). Shown first by unit checks
  (the bounds wrapped, the statuses came out as INT_MIN and -1) and by the three inputs, now
  under `tests/fuzz/regressions/log_line/`, that stopped `fuzz_log_line`.

## 0.1.0-alpha.71 (2026-10-11)

From the alpha.70 report:

- **A TLS handshake refused for its name was in no log and no counter.** On a listener without a
  catch-all, a client sending no SNI (a scanner probing port 443 by address) or a name no site has
  is refused during the handshake (`unrecognized_name`, so no certificate is shown); there is no
  request, so no access log line, and nothing counted it. `agensio ctl status` (MCP
  `server_status`) now reports `tls_handshakes_refused` with `tls_handshakes_refused_detail`: the
  addresses, most refused first, and the listeners, merged over the workers, kept as the connection
  ceiling's refusals are (a small sample per worker, nothing allocated per refusal). The handshake
  that succeeds is unchanged. Shown first by `tests/integration.sh` (two refused handshakes on a
  listener without a catch-all: not in status, now counted with 127.0.0.1).

- **`methods` on a proxy or CGI location was checked against the static handler's.** A proxy or CGI
  location passes every method an application may see (its default), but an explicit list there was
  held to the static handler's GET, HEAD and OPTIONS, so `methods = ["GET", "POST"]` was refused ("the
  proxy handler does not implement POST"). The list is now checked against what the location's handler
  serves. Shown first by unit checks (a proxy and a CGI location with POST: refused, now loaded).

- **A location with another handler's table loaded as a static location.** `proxy = { ... }`
  without `upstream` or `handler = "proxy"`, `fastcgi = { ... }` without `handler = "fastcgi"`, or a
  `cgi` table under another `handler`: the table did nothing, silently, and the location served the
  site's files where an application was meant, with `-t` saying OK. Such a location is now refused,
  naming what to add. On upgrade, a site file holding one is set aside (the other sites serve) and a
  main file holding one does not load: run the new binary's `agensio -t` first. Shown first by unit
  checks (the three cases loaded before).

- **A proxied application's redirect to the name agensio gave it as `Host` reached the browser
  unchanged.** With `proxy = { host = "app.internal" }` the origin is told it is `app.internal` and
  builds its redirects from that name, while only a `Location` naming the origin's address was
  rewritten to the site, so the client was sent to a name it cannot reach. A `Location` naming the
  configured `host` (either scheme, the whole name only) now points at the origin too and is
  rewritten; `redirects = "pass"` still turns rewriting off. nginx and Apache rewrite only the
  upstream's own URL unless told another name; agensio itself chose this one. Shown first by
  `tests/integration.sh` (the test origin's new `/host-redirect`, which builds its redirect from
  Host: `http://app.internal/json`, now the site's `/policy/json`).

- **A field the configuration sets toward the origin that agensio also writes went twice.**
  `proxy = { headers = { ... } }` was added after agensio's own `Host`, `X-Forwarded-For`,
  `X-Forwarded-Proto`, `X-Forwarded-Host` and `Forwarded` lines, which went anyway: the origin got
  two values for one field, and two `Host` fields, which RFC 9112 makes a 400. A field named in
  `headers` now replaces agensio's own line of that name. Shown first by `tests/integration.sh` (a
  location configuring `X-Forwarded-Proto`, `Host` and `Forwarded`: each twice, now once with the
  configured value).

- **`agensio ctl --help` named Rails where every application service applies.** `site-unit` read
  "the Puma unit of a Rails site", `site-service` "the Rails site's" service, `site-env-set` "(app =
  rails or proxy)", and the top-level help "Rails service", while units, services and environments
  cover redmine, django, wagtail and node too (Puma, Gunicorn, node), as the MCP texts already said.
  Help text only.

- **The agent was told it could add a redirect through a site's root additions, which it cannot.**
  The MCP server instructions and the `site_show` and `site_update` texts listed "a redirect" among
  what root additions cover, but a root additions file holds locations and no location key
  redirects, so an agent following them handed the user a file that could not do what it promised.
  The texts now say that a redirect of one path cannot be made yet, and give what can: a whole
  domain sent to another (`redirect = "https://new.example"`, path and query kept, 301) is a site
  file of its own that root writes, and a site's plain port to HTTPS is `site_update`'s
  `redirect_http`. `docs/mcp.md` the same. Shown first by a unit check holding the instructions to
  the reference table (no location key redirects: the instructions must say so).

- **`path_check` described a CGI request with path info as a missing script.** The CGI handler runs
  the longest leading part of the path that is a file and passes the rest as `PATH_INFO`
  (`/cgi-bin/env.cgi/extra` runs `env.cgi` with `/extra`); `path_check` (`agensio ctl path-check`,
  MCP `path_check`) took the whole path for the script and answered "404: no script". It now takes
  the script and its path info from the handler's own split (`core/script_split.hpp`), for FastCGI
  too, so the two cannot disagree. Shown first by unit checks (a CGI script with path info: 404,
  now "runs env.cgi with PATH_INFO /extra/path").

- **`strict_users` refused every HTTPS site `site-create` made.** For an HTTPS site with the plain
  port redirecting, `site-create` writes a second site on port 80 that only redirects (`redirect =
  "https"`, no root), with no `user`, and `[server] strict_users = true` refused any site without
  one, so the control plane could create no HTTPS site on such a host. A site that only redirects
  serves no file and runs no code (the dispatcher answers it before routing), so `strict_users`
  no longer asks it for a `user`; every other site still needs one. Shown first by a unit check (a
  redirect-only site under `strict_users`: refused, now loaded).

## 0.1.0-alpha.70 (2026-10-11)

- **A managed site's access log was never rotated, and a rotated site log lost the site's group.**
  `site-create` writes a site's log as `/var/log/agensio/sites/<domain>.log`, which the packaged
  logrotate rule (`/var/log/agensio/*.log`, `sites/*/*.log`) did not match, so it grew for ever; and
  the rule recreated a rotated file as `agensio:agensio`, so a site's account could no longer read
  its own log (`agensio:<site group>` `0640`). The sites' logs have a stanza of their own now,
  `sites/*.log` and `sites/*/*.log`, whose `create 0640` keeps each file's owner and group. The
  file is a configuration file in every package: an unedited one is replaced, an edited one is
  kept (dpkg asks, rpm writes `.rpmnew`, pacman `.pacnew`). Shown first by a unit test holding the
  packaged rule to the paths the server writes, and by logrotate itself on the packaged layout
  (before: the managed log not rotated, the other one recreated `agensio:agensio`; now both
  rotated, both still the site's group).

- **A CGI location without an `index` of its own ran the site's index file as a script.** Every
  location inherits the site's `index` unless it names one, so `/cgi-bin/` on a site with the
  default `index.html` asked the CGI handler to run `cgi-bin/index.html` (a 404 when missing; the
  interpreter fed an HTML file when present), while the documentation and `path_check` said
  `index.cgi`. A CGI location now defaults to `index = ["index.cgi"]`. Shown first by
  `tests/integration.sh` (a CGI location without `index`: 404, now `index.cgi`'s answer) and a unit
  check.

- **`/.well-known/` answered 404.** Dot-files and dot-directories are hidden by default, and the
  rule caught `/.well-known/` too, which is public by definition (RFC 8615): `security.txt`, app
  links, a webroot ACME client's challenge. The cookbook's way round it, a location with
  `hidden_files = true`, opened every dot path below it, and a managed site could not add one. A
  first segment that is exactly `.well-known` is now served like any directory; a dot segment
  below it (`/.well-known/.x`) and a `.well-known` further down (`/sub/.well-known/`) stay hidden.
  The two cookbook recipes no longer need the location. Shown first by `tests/integration.sh`
  (`/.well-known/security.txt` 404, now 200) and unit checks.

- **A request no site took was in no log, so fail2ban never saw a scanner probing by address.**
  On a listener without a catch-all site, a request for a name no site answers (the bare IP
  address, a scanner's guess) is answered `421`, and the access log was written only for a site:
  the line was dropped, and the `agensio-scan` jail counted only 404s anyway. Such a request is now
  written to `[log] access` (unless it is `"off"`), over HTTP/1, HTTP/2 and HTTP/3; the jails read
  that file even when every site has a log of its own; and `agensio-scan` counts a 421 as it counts
  a 404. The filter shipped under `/usr/share/agensio/fail2ban/` changed: health's
  `fail2ban_filter_stale` names an installed old copy with root's lines to reinstall it. Shown first
  by `tests/integration.sh` (a 421 over HTTP/1 and HTTP/2 on the strict listener: no line; now one
  each) and unit checks.

- **PHP requests could wait until `read_timeout` (504) on a generated `static` or `dynamic` pool
  with fewer children than the server has workers** (availability; the same failure as the
  `ondemand` one fixed in alpha.68). Each worker gets `children / workers` connections to the
  pool, at least one, and kept them: 4 workers before a pool of 2 children held 4 connections, a
  php-fpm child holding a kept connection takes no other, and a request on the connections no
  child took waited in the pool's backlog until agensio gave up. Such a pool now gets no kept
  connections (`keep_conn = false` unless set by hand); a pool with at least one child per worker
  keeps them. `keep_conn = true` set by hand where `max_connections` x workers exceeds the
  children is a warning from `-t`, the error log and health (`php_keep_conn_exceeds_children`).
  Measured with `bench/php/pool.sh` (now with `-w` workers, `-n` children and `-b` the burst; the
  two builds alternated, `bench/results/php-pool-20261011-161150.md`), a static pool of 2 children
  behind 4 workers: 16 requests of a 150 ms script over 8 connections gave 4 to 8 x 504 in 15 to
  20 s, now none in 1.2 s; a small script 2,100 to 3,500 req/s (most connections waiting), now
  85k. Shown first by `tests/pools.sh` (4 workers before a static and a dynamic pool of 2 children:
  4 and 8 x 504; now none) and unit checks.

## 0.1.0-alpha.69 (2026-10-11)

- **`scripts/release.sh` stops a release that would publish the wrong notes or skip a version**
  (the alpha.68 report: alpha.68 shipped a list of commit subjects as its notes, and alpha.67's
  were left under a heading never released). A version string with no tag of its own, set by a
  run that stopped before tagging, is suggested again rather than the next one, and skipping it
  needs a confirmation in a terminal; another version's section without a release date
  ("(unreleased)") stops the run until it is renamed or merged; and the draft the script inserts
  from the commit subjects carries a marker line, so a section still holding it is refused until
  the notes are written.

## 0.1.0-alpha.68 (2026-10-11)

0.1.0-alpha.67 was never published: its release stopped at a failing unit test, and its changes
ship here.

From the alpha.66 report:

- **PHP requests on a generated pool could wait until `read_timeout` (504) when several opened
  at once** (availability; seen in production on alpha.56, .65 and .66). A generated pool is
  `pm = ondemand` by default and agensio kept its FastCGI connections. php-fpm forks an ondemand
  child per edge-triggered event on the pool's socket, so connections arriving together can get
  one child between them (php bugs #69724 and #72935, open since 2015), and a child on a kept
  connection never accepts another: the rest waited in the socket's backlog until agensio gave
  up. Without keep-alive a child that finishes takes the next connection, so nothing waits
  longer than a request; nginx, h2o, Apache and Caddy all open a connection per request by
  default. An `ondemand` pool now gets `keep_conn = false`; `static` and `dynamic` keep it, as
  their children wait in accept(). A `keep_conn = true` set by hand on an `ondemand` pool is a
  warning from `-t`, the error log and health (`php_keep_conn_ondemand`). Measured with the new
  `bench/php/pool.sh` (the two builds alternated, 8 children, `bench/results/php-pool-20261011-103217.md`):
  120 requests of a 150 ms script over 30 connections gave 3 to 5 x 504 at 5.7 to 6.1 s, now none
  at 2.41 s; keep-alive off costs about 11 us of CPU per request (agensio 7.0 to 11.4, php-fpm 24.5
  to 31.4 on a script that only echoes, 142k to 87k req/s there; under 0.5 % of a request that
  runs an application), and cuts p99 from 1.75 ms to 0.21 to 0.31 ms. Shown first by
  `tests/pools.sh` (the burst on a cold ondemand pool: 5 x 504; now none) and unit checks. On the
  live host (the alpha.68 report) 120 requests at once to a Drupal site's pool took 2.23 s with no
  504, where alpha.66 waited 60 s and answered 4 x 504.

- **`site-create`'s refusal carried `detail` in two shapes**: a list when the site waited for a
  restart (a port the running server cannot bind), a string on every other refusal. It is one
  text everywhere now, the errors joined with `; `. Shown first by `tests/isolation.sh`.

Documentation and tooling:

- **`docs/third-party-bugs.md`**, the upstream bugs agensio works around: php-fpm's `ondemand`
  forking too few children (bugs #69724 and #72935, behind the change above) and a child on a kept
  connection killed after `request_terminate_timeout` (bug #78405, which generated pools do not
  set), each with how it showed, what agensio does and where, and what to change once it is fixed,
  and the procedure for checking them. A developer's document, not installed with the package.

- **`scripts/release.sh` adds the RPM changelog entry once**, so a run that stopped before its
  commit can run again (the alpha.67 runs left the entry twice).

## 0.1.0-alpha.66 (2026-10-11)

- **`agensio ctl validate` and health did not load certificates.** They say what the next reload
  would do with the files on disk, but ran only the loader and the hosting rules: a site file whose
  certificate and key do not load was named only after the reload set it aside, and `site-create`
  of a site waiting for a restart (a privileged port the running server cannot bind) answered
  "written and valid" for a key that is not a key, which the restart then set aside. Both now load
  each pair as the reload does, as the server's account: `held_back` lists such a file with
  `certificate: true` (also in the reload's answer, which gains `hosting_rule` too), whether its
  running version keeps serving, and the `site-create` above is refused with the loader's error and
  its file removed. A served site whose renewed files do not load stays one finding,
  `certificate_not_loaded`, which now says why ("the server loads it at its next hourly check" was
  said of a key it could not read). About 0.1 ms per certificate per call. Shown first by
  `tests/isolation.sh` (four checks: validate, health, the restart `site-create` and the renewal,
  each failing before).

- **A build without libxcrypt or without OpenSSL did not link.** The server always kept the
  password verification pool of `[[site.auth]]`, whose code is compiled only with both libraries,
  so any build without them (no OpenSSL, or no libxcrypt, for example a Mac without Homebrew's)
  stopped at the link with `auth::Verifier::~Verifier()` undefined, since 0.1.0-alpha.58. The pool exists
  only in a build with passwords now (`status` says `auth_verifications: 0` without), and the unit
  tests run in all three builds: two of them assumed TLS (a proxy to an `https://` origin, an
  install's checksum) and now check what a build without OpenSSL answers instead. The builds
  without OpenSSL and without libxcrypt are on the list of checks before a release.

From the alpha.65 report (correcting the alpha.64 report's second finding):

- **A start without the record of the site files served said nothing at the default log level.**
  Without the record (the first start, a lost state directory, the file deleted) load order
  decides a conflict between site files, so a contested name may go to another file than the one
  served before; the only line saying so was at level `info`, written whether a conflict was
  decided or not, and the alpha.64 notes claimed the error log says it. Now each conflict load order
  decided at a start is a warning naming the name, its address and the file that kept it
  (`no record of the site files served before (...): load order decided: a.test on 127.0.0.1:8080
  is claimed by two sites (0dup.toml and a.toml); ...; 0dup.toml keeps its place`), and `agensio -t`
  prints the same; with no such conflict the line stays at `info`. A `-t` run as an account that
  cannot read the record says that instead of "no record". Shown first by `tests/isolation.sh`
  (the record deleted and the server restarted: nothing at `warn`; now a line for `a.test` and one
  for `b.test`, in the error log and from `-t`) and unit checks.

## 0.1.0-alpha.65 (2026-10-11)

From the alpha.64 report:

- **`agensio -t` passed a site the start sets aside for its certificate.** `-t` only looked for
  the certificate and key files, while the start loads each pair: a key that is not a key, a key
  that is not the certificate's, or a key the account cannot read set the site's file aside at the
  start while `-t` said OK and `--strict` exited 0, so CI and the unit's `ExecStartPre` passed a
  configuration whose site would not be served. `-t` (also with `--explain`, and `agensio reload`
  before it signals) now loads each pair as the start does, through the same code, and a pair that
  does not load sets its file aside with the start's message: a warning, `--strict` fails, and for
  a site of the main file an error. An automatic certificate not issued yet is not loaded (the
  start writes a placeholder). `-t` reads the files as whoever runs it, as the start does; run as
  an account other than root while `server.user` names another, it cannot read a key only root
  reads, which the start reads as root, and says so (`note: ... not checked`) instead of setting
  the site aside. Shown first by `tests/isolation.sh` (the three keys: `-t` said OK for all five
  sites and `--strict` exited 0; now three files set aside and exit 1).

## 0.1.0-alpha.64 (2026-10-11)

From the alpha.63 report:

- **A restart could give a name to another file than the running server served** (security).
  On reload the file the server serves keeps a contested name; at start nothing was served yet,
  so the later file in load order yielded: a file added while running that sorted earlier took
  the name at the next boot (the report: a new `0dup.toml` served `a.test` without `a.toml`'s
  access rule), and a new broken file sorting earlier took a served site down. The server now
  keeps a record of the site files it serves, `<state_dir>/.server/served` (each file with a
  digest of the text its sites came from), rewritten after every start and reload; a start and
  `agensio -t` rank conflicts with it as a reload does with the running configuration. Without
  the record load order decides, as before, and the error log says so. Shown first by
  `tests/isolation.sh` (the report's two cases, a restart after the reload: `200` from the
  duplicate and `b.test` down; now `403` and `b.test` served, and `-t` predicting it) and unit
  checks.

- **Health named one hosting problem twice after the reload that took its site down**: once as
  the running server's (with "the version loaded before breaks it too") and once as what the next
  reload would do, the same rule without that history. The second is now left out when one text
  contains the other. Shown first by `tests/isolation.sh` (two findings for the file, now one).

Certificates (the certificate work, steps T1 to T4):

- **`docs/tls.md`, the administrator's guide to certificates.** Automatic certificates and your
  own files side by side, what the server does from the first order to renewal and failure,
  who must be able to read a key and the layouts that work, how a new certificate reaches the
  clients without a reload, every health finding with what to do, and troubleshooting. The
  cookbook gains [Certificates from certbot](docs/examples/basics.md#certificates-from-certbot):
  a wildcard over DNS-01 with a deploy hook, certbot's directories and key opened to the
  server's account, and an existing `--webroot` certbot renewing through agensio.

- **A renewed certificate is loaded by itself, and nothing can hold it back.** Nothing watched the
  certificate files: a renewal from certbot or another client waited for a reload, and the ACME
  manager's own renewals went through a reload, which a broken main file refused. The server now
  has a certificate refresh: the running configuration's certificates loaded again from their
  files, no configuration file read, a pair that does not load keeping the certificate served
  with its error for health. The ACME manager uses it after every order; an hourly watch (one stat
  per certificate and key file) runs it for the pairs whose files changed; and `agensio ctl
  cert-renew NAME` (MCP `cert_renew`) on a site with its own files runs it at once and answers what
  happened (loaded with the new date, unchanged, or why not, `409`), where it used to be refused.
  `certificate_not_loaded` says when the server loads a waiting file, or why it could not. Shown
  first by `tests/isolation.sh` (with the main file broken, `cert-renew` loads a site's new
  certificate, says `unchanged`, and refuses with why for a key it cannot read; a server whose
  watch runs every second, `AGENSIO_CERT_WATCH_SECONDS=1`, picks a renewed file up by itself) and
  `tests/acme.sh` (a renewal while the main file is broken is served).

- **Health judges the certificate served, not the file on disk.** It read the certificate files,
  so a renewal written but not loaded (no reload yet, or a key the server could not read) looked
  fine while the old, expiring certificate kept being served; and a failing automatic renewal said
  nothing until the certificate had expired. Health now reads each site's certificate from the
  server's memory: expiry and the placeholder are the served one's; `certificate_not_loaded` (a
  warning, an error under 7 days left) names a newer file on disk with why (a reload loads it, or
  the server could not load it, with the error); `acme_renewal_overdue` (an error) is an automatic
  certificate a day past its renewal point, a third of its lifetime left, with the CA's error from
  the last failed order, which the manager now keeps; `acme_renewal_failed` (a warning) is a
  failed order before that point. Shown first by `tests/isolation.sh` (a short-lived certificate
  served while a longer one waits on disk: health reported nothing; now the served one's expiry
  and the waiting one, cleared by a reload; a newer one whose key the server cannot read: named
  with why) and unit checks on described facts.

- **A key only root can read is named before it costs a renewal.** With `server.user` the start
  reads the certificates as root and every reload after that as that account, so a key only root
  can read (certbot's `0600` key in its `0700` directories) worked at boot and was never read again:
  every renewal waited for a restart, silently since step C3 kept the old certificate. `agensio
  -t`, the start and health (`tls_key_unreadable`) now check that the server's account can read
  each certificate and key, every directory on the way included, through its group and its
  supplementary groups (as `initgroups` gives them), and give root's `chgrp` and `chmod` lines; a
  reload that meets such a key says the same beside `the certificate loaded before keeps serving`.
  The loader no longer fails a site whose key it may not look at with `filesystem error: status:
  Permission denied`; the certificate step explains it. Shown first by `tests/pools.sh` (a root-only
  key under `server.user`: nothing said at `-t` or on reload before; now both name it with the fix,
  and the fix applied, the next reload loads it) and unit checks.

Site isolation, step C3:

- **A certificate one site's server cannot load no longer stops the others.** A certificate or
  key that did not load (a file the server's account cannot read, not PEM, a key that is not the
  certificate's, a broken renewal) refused the whole reload, every other site's change and every
  renewal with it, and at start kept the server from starting. Each pair is now loaded once per
  start or reload before the listeners are built: one that does not load sets its site's file
  aside like a file with an error, and a site that was serving keeps the certificate it loaded
  before (its listeners' new contexts take that material from memory, never from the files
  again), so the cookbook's case, a key only root can read after the privilege drop, keeps the
  site on its start-time certificate with a warning instead of blocking the host. Shown first
  by `tests/isolation.sh` (a start with a key that is not a key: the server did not start; a
  key made unreadable, and an edit to a broken pair, each with another site's change in the
  same reload: refused before, now the site keeps its certificate and the change applies).

## 0.1.0-alpha.63 (2026-10-11)

From the alpha.62 report:

- **At start a duplicate took over the name of a file set aside, without its rules.** A file
  claiming a name another file serves on the same address yields to it; but when that file had
  an error of its own at the next start, its sites were out before the conflict was looked at,
  so the duplicate served the name: other content, and none of the broken file's access rules,
  passwords or root additions (the report: `a.test` from 127.0.0.2 answered 200 "site dup"
  instead of 403). A file set aside for its own error now keeps a claim on its names: a file
  claiming one on the same address yields with it when it would have yielded to the file
  loaded (not served by the running server, later in load order), and the name answers 421
  there until the broken file loads; a site the server serves keeps its name, so a new broken
  file never takes one down. The names come from the file's `[[site]]` tables, or from its
  `server_name`, `listen` and `default` lines when it is not TOML at all. Shown first by
  `tests/isolation.sh` (a server started with the report's files: 200 from the duplicate before,
  421 now) and unit checks; the same suite now also covers `site-update` and `site-enable`
  refusing and undoing a change whose own file would be set aside, which the report could not
  provoke on the live host.

Site isolation, step C2:

- **A hosting rule one site breaks no longer stops the others** (design section 26, step C2). A
  site with its own account (`user`) whose root others can write into, whose credential file is
  readable by others or whose socket belongs to another account refused the whole start or
  reload, so one tenant's `chmod` kept every site down at the next boot and blocked every reload.
  Such a site's file is now set aside like a file with an error, and the other sites load. A site
  is served only by a version that passes every rule now: on reload an edit that breaks a rule
  keeps the version that runs, while a root opened to others while the site serves takes that
  site down until it is fixed (its running version breaks the rule too). Two accounts sharing a
  root, a log or a state directory set the newer file aside. The server's own account and the
  main file's sites still refuse it all. Health reports these as `hosting_rule` with the owner or
  mode to fix and what the site serves meanwhile; `validate`'s `held_back` marks them
  `hosting_rule`. The control plane's writers (`site-install`, `site-copy`, `site-task`) count a
  site set aside as a refused state, so they never answer ok to one. Shown first by
  `tests/isolation.sh` (four checks with a site of the test's own account, failing on the step
  before) and unit checks on a described machine.
- **A pool file was removed while its site's file was set aside.** `agensio pools` and the
  helper's `pools_apply` (run after every PHP site change) took the pool of an account whose site
  file did not load for stale, removed it and reloaded php-fpm, so a site still serving its last
  good version lost its PHP. While any site file is set aside no pool file is removed now.

## 0.1.0-alpha.62 (2026-10-10)

From the alpha.61 report:

- **A proxied redirect named the location's prefix twice.** A location without a URI part on
  its upstream (`path = "/app/"`, `upstream = "http://127.0.0.1:3000"`) passes the path
  untouched, so the origin's redirects already carry `/app/`; the rewrite of a `Location`
  pointing at the origin replaced the origin's root by the location's prefix and sent
  `/app/app/landing`. The origin's root is now the site's root there and only the scheme and
  host change, as nginx's `proxy_redirect default` does; with a URI part nothing changes. A
  location at `/`, every proxy preset's, was not affected. Plain-HTTP origins had it since D2;
  alpha.61's rewrite for `https://` origins brought it there too. Shown first by an integration
  check (`/whole/to-landing`, `/tlswhole/go/x`: `/whole/whole/landing` and
  `/tlswhole/tlswhole/landing` on alpha.61).
- **The note on a users file mixing hash methods came once per site and never reached the error
  log.** A domain's plain and TLS sites both read its users file, so `-t` and health named the
  file twice; and the error log took only the configuration notes that are warnings, so this one
  (information) was in no log at all, though alpha.61's entry said so. It is now one note per
  file naming the sites that read it, and every information note (this one, a site restricted
  as a whole) goes to the error log at level `info`, at start and at each reload. Shown first by
  `tests/auth.sh` (a plain and a TLS site on one file: `-t` 2, the error log at level `info` 0 on
  alpha.61; now 1 and 1) and a unit check.
- **`agensio ctl reload` now names the restart-only keys it kept.** A reload keeps the running
  value of a key that needs a restart; the error log, `validate` and health said which, the
  reload's own answer did not. It carries them now in `restart_needed`, and its message says
  they wait for a restart; the MCP `reload` tool tells the agent to pass that on.

- **One broken site file no longer stops every site.** The configuration loaded all or nothing:
  one mistake in any file under `sites.d/` (a misspelt key, a broken TOML line, a root additions
  file left group-writable) failed `agensio -t`, which the packaged unit runs before it starts,
  so after a reboot every site on the host stayed down; on a running server it refused every
  reload, another customer's changes and renewed certificates included. Each included site file
  now loads on its own (`docs/configuration.md` 12c, design section 26): a file that does not
  load is set aside with its error and the other sites are served; on reload a file whose sites
  were served keeps its last good version while the other files' changes apply; a site whose
  root additions file or `[[site.auth]]` users file does not load is set aside whole, never
  served without them. The main file stays all or nothing. `agensio -t` warns and exits 0,
  `agensio -t --strict` exits 1; health reports each file (`site_file_held_back`, an error,
  with the loader's message and what serves meanwhile), as do the error log, `status`
  (`site_files_held_back`), `validate` and the reload command's answer (`held_back`).
  `site-create`, `site-update` and `site-enable` refuse and undo a change whose own file would
  be set aside, as before for a refused reload. Shown first by `tests/isolation.sh` (eleven
  checks, all failing on alpha.61, where the server did not start).
- **Two sites claiming one name on one address are refused.** The loader accepted them and the
  first one answered, so the second file's site was silently never served (a cookbook finding);
  two catch-all sites on one address likewise. Now one of the two files is set aside and named:
  the one the running server serves keeps its place, at start the later file in load order
  yields; inside the main file the load fails.

## 0.1.0-alpha.61 (2026-10-10)

From the alpha.58 report:

- **A password could be asked over plain HTTP behind a proxy on the same host.** The rule that
  nobody is asked over plain HTTP except from this host judged the connection's peer: a tunnel
  or TLS terminator on the same host in `trusted_proxies` (cloudflared, HAProxy) is loopback, so
  every client it relayed was asked, a remote one's plain-HTTP request included, and the
  password crossed the network in clear. Behind a trusted proxy its report decides now: the
  request is https only with `X-Forwarded-Proto: https`, and local only when the client it names
  in `X-Forwarded-For` is this host. Shown first by `tests/auth.sh` (from 127.0.0.3, trusted, for
  203.0.113.9: plain, `X-Forwarded-Proto: http`, `https`, and a client 127.0.0.1 answered
  `401 401 401 401` on alpha.60, now `403 403 401 401`).
- **A client let in by `skip_for` could hand PHP any user name.** It is never asked, so nothing it
  sends as `Authorization` is verified, yet on a site that passes credentials (`credentials =
  "pass"`, the default where PHP runs) the field went on to PHP, which built `PHP_AUTH_USER` and
  `PHP_AUTH_PW` from it: an application that trusts `PHP_AUTH_USER` as the server's verified user
  took such a client as whoever it named. The field is now always removed for a `skip_for`
  client, whatever `credentials` says; a client that was asked and verified keeps it, and
  `PHP_AUTH_USER` with it (WordPress's loopback check). An application with its own HTTP Basic
  login below a `skip_for` rule gets no login from those clients: give its path `open = true`.
  Shown first by `tests/auth.sh` (a PHP site, `-u admin:x` from the `skip_for` address: PHP saw
  `PHP_AUTH_USER=admin PHP_AUTH_PW=x` and the header on alpha.60, now none of them).
- **Health took `[::1]` for a public address.** The warning that a rule asks for passwords over
  plain HTTP on a listener the network reaches (`auth_plain_http`) looked for `[::1]` while the
  loader stores IPv6 listen addresses unbracketed (`::1:18080`), so a site on the IPv6 loopback
  was warned about. Listeners are now judged by the parsed address (`loopback_listen`: 127.0.0.0/8,
  `::1`, `localhost`), shared with the host-protection renderer, and the warning is one of the
  access notices, so `agensio -t` and the error log say it too (the reference said `-t` warned;
  it did not). Addresses are printed as written, `[::1]:18080`.
- **A users file mixing hash methods told a guesser which names exist.** An unknown name is
  checked against the file's first usable entry so it takes a real user's time; a user hashed
  with another method or cost (sha512 or bcrypt cost 5 next to yescrypt) answers a wrong password
  faster or slower, and stands out. `agensio -t`, the error log and health now note such a file
  (`auth_users_mixed_methods`, information) with the users to hash again (`agensio passwd`,
  yescrypt); the control plane's own files are always yescrypt.
- Both shown first by the unit test `test_auth_notes` (alpha.60 warned about the `[::1]` site, said
  nothing at `-t` for a public one, and had no note for a mixed file).
- **The WordPress login page came unstyled below a protected `/wp-admin`.** WordPress concatenates
  the login page's styles and scripts (`script_concat_settings` on `login_init`) through
  `/wp-admin/load-styles.php` and `/wp-admin/load-scripts.php`, which were not among the paths the
  preset keeps open below a `/wp-admin` rule, so with an address rule, `rules.admin` or a password
  on `/wp-admin` the login page's stylesheet was refused or asked for a password. Both are open
  now, exactly (`/wp-admin/load-styles.php/x` stays restricted), for address rules and passwords
  alike from one list (`kWordPressOpenings`, where two copies were). They are WordPress core
  scripts every installation keeps public: no plugin, no database, no login, only core styles or
  scripts named in the query. Shown first by the unit tests and `tests/integration.sh` (below a
  restricted `/wp-admin`, `load-styles.php` and `load-scripts.php` answered 403 on alpha.60, now
  200, the path-info form 403).

Found while writing the cookbook (`docs/examples.md`), each shown first by a test that failed on
alpha.60:

- **Keys the reference said a reload applies kept their start values.** `[cache]`
  `revalidate_interval`, `precompressed`, `sendfile_min_size`, `stream_chunk_size`,
  `evict_fraction` and `max_open_files`, and `[server]` `sendfile_max_chunk` and `tcp_nodelay`,
  are read from the configuration the server started with (the static handler, the HTTP/1
  writer, the accept path, the shared file cache), so a reload changed nothing while the
  reference, `keys.md` and `config_reference` said "reload", and neither the reload's warning
  nor `validate` named them. They are restart keys now, so the hot path stays as it is; the
  reload's warning, `agensio ctl validate` and health's `restart_needed` name every restart-only
  key the file changed (`reload: cache.precompressed, tcp_nodelay changed on disk and take effect
  at a restart ...`, where it said "cache sizes" or nothing), and a unit test holds the
  reference's restart rows to that list. The control plane's role groups (`admins`, `operators`,
  `viewers`), documented as reload keys and looked up once at start, now apply on reload: the
  next connection to the socket is judged by them, and the socket's mode follows. Shown first by
  the unit test (of the restart-only keys changed one at a time, alpha.60 named ten not at all and
  two only as "cache sizes")
  and `tests/control.sh` (a viewer group added by a reload gave its member nothing, socket still
  0660; now a viewer, 0666).

- **A misspelt configuration key was ignored.** Only `[[site.auth]]`, `[[site.access]]` and the
  `http2` and `http3` tables refused a key they did not know; everywhere else (the top level,
  `[server]`, `[cache]`, `[log]`, `[control]`, `[[site]]`, locations and their `php`, `fastcgi`,
  `proxy`, `tls` and `cgi` tables) it loaded without a word, so `refsue = ["/vendor/"]` refused
  nothing, `max_body_sise` left the 1 MB limit and a misspelt `include` loaded no site file.
  Every table now refuses a key the reference table does not give it, naming the nearest one
  (`unknown key 'refsue' (did you mean 'refuse'?)`) and the table's keys; a top-level key found
  inside a table says to move it above the first `[table]` header, and a `[server]` in an
  included file is refused rather than ignored. The reference table is the one list: the loader,
  `docs/keys.md`, `agensio ctl reference` and the MCP tool `config_reference` read it. A reload
  with such a key is refused and the running configuration stays; a start fails with the message
  (the packaged unit runs `agensio -t` first). Found with it: the reference listed a location
  key `php` that the parser never read (a location's FastCGI table is `fastcgi`), and the sample
  `config/agensio.toml` had its `include` under `[cache]`, where it did nothing. Shown first by
  the unit test `test_unknown_keys`: of its nineteen misspellings alpha.60 loaded seventeen without
  a word and refused two only because a required key was then missing.

- **TLS to an origin checked no name unless `proxy.tls.server_name` was set.** Upstreams are IP
  addresses, and with an empty `server_name` agensio verified that a trusted CA had signed the
  origin's certificate but not whose it was, so any certificate a public CA issued, for any
  domain, passed (`keys.md` said the name defaulted to the origin's host). Without
  `server_name` the certificate must now name the upstream's address (an IP address entry), as
  nginx and Caddy check by default; most certificates name hosts, so such an origin answers
  `502` and the error line says to set `server_name` to the name the certificate carries.
- **Kept origin connections were shared across TLS policies.** They were pooled by
  `https://address:port` alone, so a connection a `verify = false` location had opened was lent
  to a location that verifies, whose check never ran. The pool key now carries the location's
  TLS policy (`verify`, `ca`, `server_name`), computed once at load.
- With the same cause, the key carrying the scheme: a redirect from an `https://` origin to its
  own address was never rewritten to the site, and `proxy.host = "upstream"` sent
  `Host: https://address:port`. Both use the origin's `address:port` now.
- Found while writing the cookbook; shown first by `tests/integration.sh` against a small HTTPS
  origin (`tests/tls-origin.py`, a certificate naming `*.wild.test` only): no `server_name`
  answered `200` on alpha.60, `502` now with the line naming the fix; `verify = false` then the
  system store on one client connection gave `200 200`, now `200 502`; `host = "upstream"` sent
  `https://127.0.0.1:9131` and the origin's redirect reached the browser as
  `https://127.0.0.1:9131/landing`, now `127.0.0.1:9131` and the site's own
  `http://127.0.0.1:8091/tlshost/landing`.

- **`agensio ctl site-update --cache` (or `--private`, `--entry-point`, `--front-controller`)
  given alone removed the site's other rules.** The server takes a site's `rules` whole, and
  `agensio ctl` read the current rules and sent them back only for `--restrict`, `--refuse`,
  `--restrict-admin` and the `--auth` flags; the four application-rule flags sent their own part
  alone, so adding a cached directory dropped the site's passwords, address rules, admin rule
  and refused paths without a word. Every rule flag of `site-update` now replaces its own part
  and keeps the rest; `--no-rules` still clears everything. The MCP tool was not affected (its
  description has the agent send the current rules with the change). Found while writing the
  cookbook; shown first by `tests/integration.sh` (`--cache` and `--private` after `--restrict`
  and `--refuse`: the site was left with `private` alone, each flag dropping even the one before it; now `cache private refuse restricted`)
  and `tests/auth.sh` (`--cache` after `--auth /`: the rule was gone and the site answered 200,
  now it asks, 401).

## 0.1.0-alpha.60 (2026-10-09)

**The configuration cookbook** (`docs/examples.md`): practical recipes for the jobs an
administrator does, one file per category under `docs/examples/` (basics, PHP applications,
applications behind the proxy, protection, hosting and the control plane, protocols and
capacity). Each recipe is a complete configuration with what a request meets, how to check it,
and the same change on a managed site through `agensio ctl` and the MCP tools. `tests/examples.sh`
(run by the integration suite) loads every recipe with `agensio -t`, checks every `agensio ctl`
line against the binary's help, every MCP name against the server and every link and anchor,
so a recipe that stops working fails the suite. The proxy examples of `docs/examples/*.toml` are
recipes now. CLAUDE.md's working agreement: a feature an administrator configures gets its recipe
in the same change.

## 0.1.0-alpha.59 (2026-10-09)

From the alpha.58 report:

- **An exact rule missed its script run with path info.** `match = "exact"` on `[[site.access]]`
  and `[[site.auth]]` (and the exact rules `rules.restricted`, `rules.auth` and `rules.admin`
  write, such as WordPress's `/wp-login.php` with `login: true`) compared the request path alone,
  but PHP runs `/wp-login.php/x` as `/wp-login.php` with `PATH_INFO = /x`, Drupal's
  `/update.php/selection` as `/update.php`, and a CGI location `/cgi-bin/report/2026` as `report`:
  the login page or the script answered past the rule. An exact rule now covers its path and
  every request agensio runs as that same script, and nothing else: the script is taken from
  the split the FastCGI and CGI handlers use themselves, now one copy in
  `core/script_split.hpp`, so the rules and the handlers cannot disagree (Caddy's CVE-2026-27590
  and CVE-2026-45135 came from two splits), and `/info.phpx`, `/info.php.bak/x`, a static path
  or a location with `path_info = false` stay outside the rule. In front of a proxied application
  agensio runs no script, so an exact rule there judges its path alone, and `-t`, the error log
  and health say so for a `.php` path (`exact_rule_proxied_script`, info: a prefix rule covers
  both forms). `path_check` names the script a path runs (`script`). nginx's `location =`,
  Caddy's exact `path` and HAProxy's `path` cover the path alone, the forms WordPress's own
  hardening page gives; the research is in `research_notes/Exact rules and path info/`. A site
  without exact rules pays a flag test (`SiteConfig::exact_rules`), and one with them no
  allocation: `bench/ab.sh 75fec4e -A -r 3` (`ab-20261009-144743.md`, the `access` row's site now
  with an exact rule, so its `/` asks the router which script a directory runs) 1.012 on
  `access`, 1.000 `access-all`, 0.994 `refuse`, 1.012 `auth`, the static rows 0.96 to 1.03,
  against 1.011 / 1.019 / 1.030 / 1.020 for the same code compared with itself
  (`ab-20261009-142357.md`). Shown first by `tests/auth.sh`
  (exact rules on CGI scripts: `/run/cache.cgi/extra` and `/run/report/2026` answered 200 on
  alpha.58, 401 now) and `tests/integration.sh` (exact access rules on PHP scripts: the path-info
  forms and the directory answered 201 and 200, 403 now).

## 0.1.0-alpha.58 (2026-10-09)

From the alpha.57 report:

- **A client that went away mid-response was logged with no address.** An HTTP/1 request whose
  client reset the connection before the answer was out, over plain HTTP and TLS alike, was
  written to the access log as `- - - [...] "GET /wp-includes/js/dist/editor.min.js ..."`: the
  address was asked of the socket when it was first needed, which for a request no access rule
  and no trusted proxy looked at was the log line, after the reset. So fail2ban could not
  attribute a client that pulled most of a large file and reset (the error log's `request line did
  not parse from -` the same). The address is now the one `accept(2)` returns with the
  connection, written by that call itself, so it is always known and the `getpeername` a logged
  connection cost is gone; the connection ceiling's refusal sample uses it too. HTTP/2 kept its
  address already, HTTP/3 has the datagram's. Shown first by `tests/integration.sh` (a client that
  reads 64 KB of a large file and resets, over plain HTTP, TLS and IPv6: `- - -` before, `127.0.0.1
  127.0.0.1 ::1` after).
- Item 2.2 of the security audit (alpha.57) is verified on the test VPS: a 3 MB cached file at
  300 KB/s with idle_timeout 2 was cut at 0.77 MB over TLS on alpha.56 and arrives whole on
  alpha.57; the audit's status table records it. Its automated reproduction test is still to write.

**Passwords: `[[site.auth]]`** (the security audit's second feature gap; docs/configuration.md
19b, design section 25, the research in `reports/Web server basic authentication.md`). A
password in front of a path, for a staging site, an admin area or a tool without a login of
its own:

- **Rules like the access rules:** checked before any location, after `refuse` and the access
  rules, on every internal redirect and on a directory's index, so no `.php` location,
  fallback or index steps around them (nginx's per-location `auth_basic` does not hold for a
  regex `.php` location, the trap hosting panels still ship). `open = true` frees a path below a
  protected one; `skip_for` lets addresses in without a password; WordPress keeps
  `admin-ajax.php` and the login page's own files open below a protected `/wp-admin`.
- **Strong hashes only,** through the system's libxcrypt: yescrypt, bcrypt, sha-crypt, scrypt.
  MD5 (`$apr1$`, htpasswd's old default), `{SHA}`, `{PLAIN}` and DES are refused at load with the
  command to use instead. The user file is htpasswd's format, so `htpasswd -B` files work, with
  two optional fields: `expires=YYYY-MM-DD` (refused from that day) and `note=` (whose login it
  is). Root's, not readable by others. `agensio passwd USER` writes a line without Apache's tools.
- **The slow hash is never paid per request, and never on a worker's loop.** nginx, Apache,
  Traefik and HAProxy hash the password for every request (nginx inside its worker: about 4 ms
  at bcrypt cost 5); Caddy remembers results with the plaintext password and failures in
  memory. Here a verified login is remembered per worker for five minutes as an HMAC of the
  user, the stored hash and the password (never the password; never a failure; a changed
  password or another area never matches; a reload keeps it), and a new one is verified on a
  small thread pool while the request waits; at most eight per worker at a time, 503 beyond.
  An unknown user is verified against a real entry, so timing does not tell who exists.
  Each connection also remembers its last verified `Authorization` value, so a browser's
  next requests on it cost one comparison. `status` counts the hashes run. Measured
  (`ab-20261008-171903.md`): a protected page with a logged-in client costs 1.072 of an open
  one, about 0.14 us; every other row of `ab-20261008-171002.md` is flat, so a site without
  `[[site.auth]]` pays nothing.
- **No password asked over plain HTTP** unless the rule says `plain_http = "allow"`: a request
  that is not on TLS, not from this host and not forwarded as https by a trusted proxy gets 403
  with a page that says to use https (nginx and Apache ask anyway).
- **The answers and what others see:** 401 with `realm`, `charset="UTF-8"` (RFC 7617) and
  `no-store`, one page for every kind of failure; PHP gets `REMOTE_USER` and `AUTH_TYPE`;
  `Authorization` reaches PHP (WordPress's loopback calls) and is stripped before any other
  application (`credentials` to choose); `forward_user` sends the verified name to a proxied
  one; the access log's user field is the verified user; each failed login is one `auth
  failed: client ...` line, the challenge none.
- **No protected answer is one a shared cache may keep** (`core/private_cache.hpp`): a file
  agensio serves carries `Cache-Control: private`; an answer of PHP, CGI or a proxied application
  loses `public`, `s-maxage` and `proxy-revalidate` and gains `private` (`public, max-age=3600`
  becomes `private, max-age=3600`, none becomes `private`), and the fields only CDNs act on
  (`CDN-Cache-Control` and its `*-Cache-Control` vendor forms, `Surrogate-Control`, `Edge-Control`)
  are dropped. A shared cache may reuse an answer to a request with a password when the answer
  says `public` or `s-maxage` (RFC 9111 3.5), a CDN follows its targeted field over
  `Cache-Control` (RFC 9213 2.2), and a client let in by `skip_for` sends no password at all: with
  a CDN in front, a protected WordPress page with a cache plugin could have been served to anyone.
  Shown first by `tests/auth.sh` (the protected answers came out `public, max-age=3600` with three
  CDN fields), five checks; RFC 9111 and 9213 added to `docs/rfc/`.
- **Built only with libxcrypt and OpenSSL** (a new dependency row); a build without them refuses
  a configuration with `[[site.auth]]` instead of leaving the paths open.
- **fail2ban counts failed passwords, not challenges** (`docs/fail2ban.md` 2c). The
  `agensio-auth` jail now reads the error log's `auth failed` lines (a wrong password, an unknown
  or locked user, malformed credentials; not an expired user's right password), as fail2ban's
  own `nginx-http-auth` and `apache-auth` read theirs. Until now it counted every 401 and 403 in
  the access logs, and a 401 is the challenge: every browser's first request to a protected path,
  one per directory on a site protected as a whole (RFC 7617 2.2, now in `docs/rfc/`), one per
  request for a client that does not send the password unasked; so a password-protected site
  would have banned the people who had its password (shown by the new checks of
  `tests/protection.sh`: twelve challenges and twelve right passwords of an expired user counted
  24 failures and banned the address). The 403s, which the access rules rely on, go to a new
  jail `agensio-denied` over the access logs, unchanged. The jail needs the error log in a file
  at `warn`, the package's defaults; otherwise it is rendered disabled with root's line. Health:
  `fail2ban_auth_challenges` (warn) while the old filter is installed on a host with a
  password-protected site, `fail2ban_auth_unseen` when nothing counts a site's failed passwords;
  `protection_show` answers `auth` (the sites, the log, whether a jail reads it). **Upgrading:**
  root installs the filters again and renders the jail (`fail2ban_filter_stale` gives the three
  lines).
- **A managed site's users through the control plane and MCP** (`docs/configuration.md` 19b):
  `agensio ctl site-auth-user-set NAME USER (--generate | --prompt) [--expires D] [--note T]
  [--lock | --unlock]`, `site-auth-user-delete`, `site-auth-users`, and the MCP tools
  `site_auth_user_set`, `site_auth_user_delete`, `site_auth_users`, admin only and audited by
  user name. The file is `<config dir>/auth/<site>.users`, root's, the server's group, `0640`,
  written by the root helper. A password never travels to the server: `--generate` makes one
  (`xxxx-xxxx-xxxx-xxxx`, 80 bits, nothing that looks alike) and answers it once, kept nowhere;
  `--prompt` asks on the terminal and sends only the hash; an agent can only generate (the API
  refuses a `password` field, the bridge drops a `hash`). The listing never shows a hash. A lock
  keeps the password for an unlock; a change to a file a rule reads reloads the server at once,
  and that file's last user is kept.
- **`rules.auth` on managed sites** (`docs/configuration.md` 15 and 19b, `docs/auth.md`): `site_update`
  with `{"path": "/", "realm", "skip_for", "plain_http"}` or `{"path", "open": true}`, rendered as
  `[[site.auth]]` reading the site's users file; `agensio ctl site-update NAME --auth PATH
  [--auth-exact | --auth-open] [--auth-realm T] [--auth-skip A] [--auth-plain-http]`, `--no-auth`.
  Refused until the site has a user, so a rule never meets a missing or empty file (which would
  make the next load refuse the whole configuration), and on `site-create`, so a deleted site's old
  file never comes into force unseen (`site-create` warns when one exists). `site_show` lists the
  rules with their users file and how many users can log in; `path_check` names the rule. Deleting
  a site with its files takes its users file into the trash and a restore brings it back.
- **`docs/auth.md`** (new, installed with the other administrator documents): the whole password
  feature in one place: the rule, the users file, how a request is decided, verification and its
  cost, what applications, caches and logs see, the managed tools, fail2ban, health, every edge
  case found so far with what happens in it, and configuration examples.
- **Health reads the users files the way the next load will**: `auth_users_unloadable` (an error:
  a file gone or broken under a running server, which keeps its users, but a reload is refused
  and a restart would not start), `auth_no_valid_user` (every user locked or expired: every login
  fails), `auth_users_expired`, `auth_plain_http` (passwords asked over plain HTTP on a listener
  the network reaches), `auth_users_orphan` (a users file no site owns).
- **Fixed: a use-after-free at every exit with the root helper running** (since F12b,
  2026-10-01). Two timers of the server (the trash expiry, the restart) were destroyed after the
  worker's `io_context` that had freed their service; the sanitizer build reported it, a release
  build read freed memory on the way out. They are declared after the workers now, and
  `tests/provision.sh` stops the server and fails on any sanitizer report in its stderr.
- `protection.cpp` compared the failure tier's application name with `"drupal"` by address
  (a `const char*`), right only because the compiler merges equal literals; it compares the text
  now, and the two compiler warnings are gone.

Tests: unit (the user file, the Authorization parser, verification, the cache key and cache,
the pool, the configuration and its refusals) and `tests/auth.sh` (16 checks against a
one-worker server: one verification for a login followed by fifty requests on one connection
and five new ones, every failure verified again, an unknown user verified too, the challenge,
expiry, UTF-8, `open`, `skip_for`, the bypass spellings, plain HTTP from another host, TLS,
`Cache-Control: private`, the access log's user, the failure lines, a request answered while
a slow verification runs, a reload keeping the cache, a changed password); `tests/protection.sh`
(real fail2ban and nftables: twelve challenges and twelve right passwords of an expired user
counted nothing, eleven wrong passwords banned the address through `agensio-auth` over the error
log, eleven 403s banned it through `agensio-denied`, the old filter warned about), 31 checks;
for the users tools, unit `test_auth_users`, eleven more checks in `tests/auth.sh` (the tools and
MCP without the helper: the file's mode, the generated and the typed password logging in where a
rule reads the file, a lock, a new password refusing the old one at once, the last user kept, no
password or hash in any log), four in `tests/provision.sh` (through the helper: `root:agensio
0640` in `root:agensio 0750`, a symlink in the file's place refused) and one in
`tests/control.sh` (admin only; its tool counts were stale since `access_check` and
`path_check`, now 16, 20 and 38); for `rules.auth`, unit `test_auth_managed` (the checks, the
rendering read back by the loader, the site detail, `path_check`, each health finding), ten more
checks in `tests/auth.sh` (37 in all) and two in `tests/trash.sh` (the listing of an entry's pieces now has `auth`).

## 0.1.0-alpha.57 (2026-10-08)

From the security audit of 2026-10-07 (docs/security-audit-2026-10-07.md), item 2.2:

- **A large cached file over HTTPS reached a slow client only if it arrived within one idle
  timeout** (availability). A cached body went out as one write and the idle clock moved only
  when all of it had gone, so with the defaults a cached file of up to 4 MB to a client slower
  than about 2.2 Mbit/s (a phone on a weak link) was cut at 15 s, on every HTTPS site; the
  same on plain HTTP for a large entry not sent with sendfile (`sendfile = false`). The rest
  of a body beyond the first write and one piece now goes out in pieces of
  `stream_chunk_size` (64 KB), each refreshing the idle clock, as files and HTTP/2 already
  did; the access log counts the bytes actually handed over. Small answers are written
  exactly as before. Fixed in code, not yet proven by a test: the suites, the sanitizer
  build and the A/B show the change breaks nothing; the reproduction test of the audit's
  section 5, item 2 is still to write, and must fail on alpha.56 and pass from alpha.57.

## 0.1.0-alpha.56 (2026-10-08)

From the security audit of 2026-10-07 (docs/security-audit-2026-10-07.md), item 2.1:

- **HTTP/2: the per-stream timeout check could stop a worker** (security). When the check
  reset a stream whose bytes the writer still held, or whose next chunk was still being read
  from its application, `close_stream` deferred the stream's release and left it in place;
  the check then met the same stream again on every pass, reset it again, and never returned
  to the event loop, so every site on that worker stopped. A stream already closed is now
  skipped. And a stream waiting for its application's next bytes is no longer cut by the
  client's idle clock: the upstream's `read_timeout` bounds it, as HTTP/1 always did, so a
  streamed answer from a FastCGI or proxied application that pauses longer than
  `idle_timeout` between two chunks arrives whole over HTTP/2 too. Verified with the unit and
  integration suites (h2spec on both listeners), the sanitizer build and the `-2` A/B, which show the
  change breaks nothing; none of them reaches the failing state, so the fix is not yet
  proven by a test: the reproduction test the audit describes (section 5, item 1) is still to
  write, and must fail on alpha.55 and pass from alpha.56.
- **The sanitizer build's server could crash in `malloc_trim`** (test builds only): the idle
  trim called glibc's `malloc_trim` while AddressSanitizer owned the allocator, and a
  `tests/reload.sh` run died with a SEGV there now and then. AddressSanitizer builds skip the
  trim; release builds are unchanged.

## 0.1.0-alpha.55 (2026-10-08)

From the alpha.54 report (TYPO3 13.4 configured live from its documentation with the new
`refuse` patterns and `path_check`: 57 patterns, eight files that were served now 404, the
frontend, backend, install tool and assets working), one gap:

- **A directory whose index the site refuses is answered as if it had none.** TYPO3's nginx
  configuration sends the existing directory `/typo3/` to `/index.php`; a managed site could
  not, because since alpha.54 a directory whose `index.php` is not an entry point answered 404,
  so the backend needed TYPO3 13's deprecated `typo3/index.php` listed as an entry point. A
  directory's index is now a file the site would answer by name: one it refuses (a `refuse`
  pattern, a `deny` location such as the rules' "no other PHP", a refused ending, a dotfile, a
  protected name's backup) is passed over as if missing, and `try_files` goes on to the front
  controller, or `=404`, or 403 without `try_files`. The refused file is still never served or
  run, and is 404 by name. nginx, Apache and Caddy choose an index by existence alone and leave
  the refusal to a later rule, which is why their documented configurations special-case such
  directories by hand; here it is one decision (`refused_request`, shared by the static handler
  and `path_check`), with nothing to configure. TYPO3 needs `entry_points` `/index.php` and
  `/typo3/install.php` only. Behaviour change: a directory holding a stray `index.php` on the
  drupal, laravel and grav presets is now answered by the application (its 404 page, unless it
  has a route there) instead of agensio's 404. Integration checks for every preset and the
  TYPO3 end-to-end test (now as TYPO3 13 documents it) failed first.
- **An access rule on a directory's index file now holds at the directory** (security, found
  while making the change above): with `[[site.access]] path = "/index.html", match = "exact"`,
  a client outside the rule was refused `/index.html` but served the same file at `/`, because
  the index was taken from the same location without asking the rules. An index that another access
  rule decides than the directory is now routed as a request for it by name, so that rule
  judges the client, as nginx's internal redirect to the index re-matches `location =
  /index.html`. When one rule covers both (a site restricted whole) the client has passed it
  already and the answer stays cached under the directory: the first form of this fix routed
  every such index again and cost the restricted-site A/B row 1.77x, caught by the gate. Sites
  without access rules take the same path as before. Integration check, failing first.

## 0.1.0-alpha.54 (2026-10-08)

From the alpha.53 report (a live host and a private instance: Drupal's script rule, the
WordPress refusals and openings, report mode, ports in X-Forwarded-For, the site_update notes
and rules.admin confirmed), three findings: two fixed, each reproduced by a test that failed
first, and the third answered by the way an application without a preset is configured
(below):

- **A directory's index.php was served as source where the preset refuses it by name**
  (security): `/sub/` answered `sub/index.php` as `application/octet-stream` while
  `/sub/index.php` was 404, on the drupal preset (new with alpha.53's script rule; a TYPO3
  tree on it served `typo3/index.php` at `/typo3/`) and, the suite found, on laravel and grav
  since their "only index.php runs" rule. The index lookup now asks the same question as a
  request by name (`refused_by_name`, one predicate for both): an index another location owns
  is routed there, one the location refuses gets its 404, never a file. Integration checks
  for every preset with a script rule, twice so the cached answer is held too; WordPress still
  runs a directory's index.php.
- **An X-Forwarded-For port out of range** (`198.51.100.7:99999`) was taken as the address. A
  port is 1 to 65535 now; any other is garbage and stops the walk, so the client is the
  proxy. Unit test and an integration check.

Applications without a preset of their own (finding 3: a TYPO3 site on the drupal preset) are
configured from their own documentation, on `app = "php"`; the server now gives the agent
what that needs (docs/configuration.md 6b, design section 24):

- **`refuse`**, on any site (`rules.refuse` on a managed one): gitignore-style path patterns
  answered 404 whichever location would serve them. `/vendor/` from the root, `composer.json`
  or `*.yaml` a name in any directory, `*` within one segment
  (`/typo3/sysext/*/Resources/Private/`), `**` any number of directories. No regex, no order,
  no exception, so nothing can be shadowed the way an nginx regex location is; checked before
  routing, on every internal redirect and on a directory's index file, case and trailing dots
  ignored. A bad pattern is refused with what to write instead, and one that would refuse
  the site's index, a `try_files` target or an entry point is refused when the configuration
  is checked. TYPO3 13.4's documented deny rules are 48 patterns and cost 2 to 92 ns per
  request on that site; a site without patterns pays nothing measurable (A/B row `refuse`).
  `agensio ctl site-update --refuse PATTERN` / `--no-refuse`.
- **`path_check`** (MCP, viewer; `agensio ctl path-check SITE PATH`): what a site does with one
  path and why, as the server decides it: refused (by which pattern or refusal by name), the
  file served, the script run, the application it goes to, with every step on the way.
- **The agent's instructions** say how: find the application's official web server
  configuration for the version in use, translate it into `entry_points`, `front_controller`,
  `private` and `refuse`, show it with its source, dry run, `path_check` the paths the
  documentation names, apply only with the user's agreement, check again.

## 0.1.0-alpha.53 (2026-10-07)

From the alpha.52 report (a live host and a private instance: the client-address fixes and the
access rules confirmed, twenty spellings of a restricted path refused, report mode and the
managed rules as documented), three findings, each reproduced by a test that failed first:

- **Report mode could hide the clients it exists to name.** Its lines shared the refusal
  limiter of one line a second per worker, so a refusal elsewhere in the same second, or a
  second client, left them unwritten. Report mode has a limiter of its own now: each rule and
  client is named once a minute (32 remembered per worker, at most 16 new lines a second, the
  rest counted), with the requests it made since its last line. The refusals held back are
  counted "since the last such line" (the line said "in the last second" about counts seconds
  old), and the count is written by the worker's one-second tick when no refusal follows; before,
  it waited for the next refusal, perhaps for ever. Three integration checks.
- **site_update said nothing of what -t notes about a site's access rules**: a dry run of a
  whole-site rule answered `warnings: null`. `site_create` and `site_update` (dry run and real)
  now answer the same notes as warnings: a site restricted as a whole, an entry that holds a
  trusted proxy or loopback, an IPv4-only list on an IPv6 listener, a single IPv6 address.
- **An X-Forwarded-For entry with a port** (`198.51.100.7:1234`, as some load balancers write
  it) was garbage, so the client became the proxy itself. `a.b.c.d:port` and `[v6]:port` (or
  `[v6]`) are the address alone now; a bad port still stops the walk. Unit test and an
  integration check.

The WordPress and Drupal presets after the access rules (design section 23), following each
application's own documents; an admin panel stays reachable from anywhere until its owner
restricts it. Each change was reproduced by a test that failed first:

- **Drupal runs PHP where Drupal's own `.htaccess` lets it** (security): a script directly in
  the web root, directly in `core/`, and `core/modules/statistics/statistics.php`. Any other
  `.php` (a module's, a theme's, a library's) ran before, as in most nginx recipes for Drupal;
  it is 404 now and never reaches php-fpm. `autoload.php` is refused by name, and the names
  its `FilesMatch` protects in any directory are refused too: `.sh` scripts, `composer.json`,
  `composer.lock`, `package.json`, `package-lock.json`, `yarn.lock`, `web.config` (the root's
  `package.json`, `yarn.lock` and a `deploy.sh` were served). `--explain` shows the rule as `#
  only a script directly in /`; `presets_list` says it. A module that documents a script of
  its own gets an exact location in the site's root additions.
- **WordPress refuses `wp-admin/includes/` and `wp-includes/theme-compat/`**, as WordPress's
  hardening guide does: library scripts that print errors with paths when run directly.
- **With `/wp-admin` restricted, the login page kept its look**: `/wp-admin/css/`,
  `/wp-admin/js/` and `/wp-admin/images/` stay open beside `admin-ajax.php` (wp-login.php
  loads its styles, scripts and logo from there; WooCommerce's password meter too). Those
  three directories run no script, so a `.php` planted there is 404, restricted or not.
- **`rules.admin`**: restricting an admin panel by address is one field on a managed WordPress
  or Drupal site, `{"allow": ["@office"]}` with optional `"login": true` (the login page too),
  `"languages": ["fr"]` (Drupal's URL prefixes: `/fr/admin` answers like `/admin`) and
  `"mode": "report"`, rendered from the preset's administration paths (WordPress `/wp-admin`,
  `/wp-login.php`; Drupal `/admin`, `update.php`, `core/install.php`, `core/authorize.php`,
  `core/rebuild.php`, `/user/login`), which `presets_list` lists as `admin_paths`. Never set
  by default; the MCP texts tell an agent to apply it only on request, after `access_check`
  with the user's own address, in report mode first. `agensio ctl site-update
  --restrict-admin ADDR,... [--admin-login] [--admin-language L] / --no-restrict-admin`.

## 0.1.0-alpha.52 (2026-10-07)

Three bugs in how agensio decides who the client is, found by the research behind the coming
access-by-address feature (`reports/Web server IP access control.md`). Each was reproduced by
a test that failed first; they matter today for the access log, PHP's `REMOTE_ADDR` and what
fail2ban bans, and would have decided the coming address rules.

- **Several `X-Forwarded-For` lines** (security): behind a trusted proxy only the first line
  was read. A proxy that adds a line of its own, as HAProxy's `option forwardfor` does, puts
  the client it saw on the last line, so the client's own first line chose the address agensio
  logged and handed to PHP. The lines are now one list (RFC 9110 5.3) read from the end of the
  last line; `X-Forwarded-Proto` counts the last value of its last line, so a client's earlier
  `https` no longer turns `HTTPS` on; a proxy location forwards a trusted chain whole, every
  line in order, where it kept only the last line (a field the client listed in `Connection`
  is still dropped). Unit test, and integration checks over HTTP/1, HTTP/2 and the proxy.
- **IPv4 clients of a `[::]` listener** were recorded as `::ffff:a.b.c.d` in the logs and in
  `REMOTE_ADDR`, and an IPv6 entry with zero leading bits (`::/8`) matched every IPv4 client.
  The address is unmapped once per connection over HTTP/1, HTTP/2 and HTTP/3 and in
  `X-Forwarded-For` entries; an entry written in mapped form means its IPv4 range; zone ids
  (`fe80::1%eth0`) are refused in address lists. Found with it: HTTP/1 filled the peer's text
  in two places, and when the access log filled it first a later forwarded step judged the
  peer from an unset address; one function sets text, port and address together now.
- **A reload that changes `trusted_proxies`** did not reach connections already open: each
  cached its verdict on its peer for its life, so a proxy taken off the list kept choosing the
  client address (HTTP/1, HTTP/2, HTTP/3), and with the list emptied an HTTP/1 connection kept
  the previous request's forwarded address. Three reload-suite checks, failing before.

From the alpha.51 report (a live host and a private instance; the alpha.51 fixes confirmed:
the reference's defaults, TLS 1.2 renegotiation refused, the JSON range answered `-32700
number out of range` with the bridge going on, the connection limits applied on reload over
HTTP/1 and HTTP/2, nothing active cut), two low findings, each reproduced by a test first:

- **A kept HTTP/1 connection kept its old idle deadline after a reload** that shortened
  `idle_timeout`. alpha.51 said a kept connection takes the timeouts at its next request; it
  took the value, but the timer armed before the reload (the 2 s shed tick arms it for the rest
  of the old limit) still fired at the old deadline: 15 s to 2 s, a request after the reload,
  closed 10.5 s later where HTTP/2 closed after 2 s. A shorter limit now re-arms the timer from
  that request (only at a reload boundary). Reload-suite check: 10.3 s before, under 3.5 s now.
- **`docs/mariadb.md` was not in the package**, so the administrator it is written for could
  not read it on the host. It is installed with the other guides now, and a unit test holds
  every guide in `docs/` to the install list (developer documents are named in the test). The
  package suite checks the installed file; it also tests the newest `.deb` in `build/` (an older
  one sorted first and was the one installed) and had two stale expectations, `/var/lib/agensio`
  0750 (0751 since site users traverse to their state directories) and the version `alpha.1`,
  which it now reads from the package.

**Access by client address** (`docs/configuration.md` 19, design section 22, the security
audit's first feature gap): a path, or a whole site, answered only to some client addresses,
everyone else getting `403`.

```toml
[addresses]
office = ["203.0.113.7", "2001:db8:5::/64"]

[[site.access]]
path = "/wp-admin"
allow = ["@office"]
```

- Checked on the normalised path after the site is found and before any location is chosen,
  so whichever location would serve the request (a `.php` suffix, a proxy, a `try_files`
  fallback) is covered: the trap where nginx's `allow` in `location /wp-admin/` is bypassed
  by `location ~ \.php$` cannot happen. A prefix covers whole segments in any capitalisation;
  the longest rule decides; `allow = ["any"]` reopens a path below; `match = "exact"`;
  `path = "/"` restricts a site. The other ways an origin may read the same path are judged
  too: a `;parameter` segment (Tomcat's `..;/`), a second decoding, the path after a script.
- Allow lists only; an empty list, an unknown key (a misspelt one would leave the path open), an
  unknown `@set`, a zone id and an unnormalised path are refused at load. At most 32 rules a
  site and 64 addresses a rule; longer lists are the firewall's.
- WordPress: with `/wp-admin` restricted (and not the whole site), the preset keeps
  `/wp-admin/admin-ajax.php` open for the public pages that call it.
- The refusal is a `403` with `Cache-Control: no-store` naming the address that was tested;
  the error log gets one `warn` line a second per worker naming the site, the rule and the
  client, with the count of lines not written; `mode = "report"` logs `access would refuse:`
  and serves everyone.
- Managed sites: `rules.restricted` through `site_update` (admin), `agensio ctl site-update
  --restrict PATH=ADDR,... / --restrict-exact / --no-restrict` (the other rules kept);
  `access-check SITE PATH ADDRESS` and the MCP tool `access_check` (viewer) say what the rules
  decide for one client; `site_show` lists the rules in force with where each comes from;
  `config_reference` shows root's address sets with their entries and the trusted proxies'
  ranges (it showed a count); an unknown `@set` in `site_update` is answered with the sets that
  exist. The MCP server's instructions, `site_create`, `site_update`, `logs_query` and the
  `new_site` prompt tell an agent when to offer a restriction, to check the user's own address
  first, and where refusals appear.
- `-t`, the error log and health warn about an entry that holds a trusted proxy, a loopback
  entry with no local proxy trusted, IPv4-only lists on IPv6 listeners, single IPv6 addresses,
  and a site restricted as a whole.
- Cost: a site without rules pays one test per request; a page no rule can cover, one bit
  test; the client's address is read only when a rule covers the path. `bench/ab.sh <ref> -A`
  adds the two rows for sites with rules.
- A server before this one ignores `[[site.access]]` without a word (the suite's sixteen
  checks all failed on it, PHP under a restricted path ran): after an upgrade, `agensio -t
  --explain` lists the rules.

The new `-t --explain` check captures the output before `grep -q`, the pipefail trap found in
alpha.51 (the writer of a long output dies of SIGPIPE when grep stops at its match).

## 0.1.0-alpha.51 (2026-10-07)

`docs/mariadb.md`: a short guide for the administrator who installs MariaDB on the same
Debian 13 VPS as agensio, from MariaDB's Knowledge Base and Debian's package notes: what the
package already secures (root over the unix socket, loopback only, no test database, and why
`mariadb-secure-installation` is not needed there), a hardening file, the few parameters worth
tuning with sizes for a shared VPS, a database and an account per site for WordPress and the
other PHP presets, everyday commands, nightly dumps and what to look at when something is
wrong. Documentation only; nothing in the server changed.

Security audit against the nginx comparison (`docs/security-audit-2026-10-07.md`): an outside
model's claims about what a fast server leaves out, checked against the code, with what was
found and what remains to verify live. Fixed from it, each with a test that failed first:

- **Reload applies the connection limits.** HTTP/1 and HTTP/2 connections took
  `idle_timeout`, `body_timeout` and `max_header_size` from the configuration the server
  booted with, so a reload changed none of them until a restart, although the key reference
  says "reload" (HTTP/3 already read the live configuration). They now come from the
  connection's generation: a connection accepted after a reload gets the new values, a kept
  connection takes the timeouts at its next request and the receive buffer's size at its next
  idle shed. `tests/reload.sh` reloads to `idle_timeout = 2` and times a new connection over
  HTTP/1 and HTTP/2: open after 9 s before, closed within 4 s now (20 checks).
- **The key reference stated wrong defaults** for the `php` and `proxy` tables: `max_fails`
  1 (the parser's is 3), `send_timeout` 60 (30), `queue_wait` 10 (5), the pool sizes 32 /
  256 / max_connections (PHP 16 / 64 / 8, proxy 256 / 1024 / 64), `priority_reserve` a count
  of connections (a share from 0 to 1), and `proxy.forwarded = append | replace | off |
  rfc7239` (the parser takes `x-forwarded | forwarded | both | off`, default `x-forwarded`).
  `docs/configuration.md` was right; the table that `agensio keys`, `config_reference` and
  `docs/keys.md` print was not. A unit test now holds every numeric default of both tables to
  a parsed configuration (15 mismatches before).
- **TLS 1.2 renegotiation**: the audit suspected client-initiated renegotiation was allowed;
  the test showed OpenSSL 3 refuses it by default, so nothing changed in the server. The
  integration suite keeps the check (checked against an `s_server` that allows it), so an
  option or library change cannot turn it back on.
- The HTTP/2 and HTTP/3 design notes said what the timers should do; they now say what the
  code does (the HTTP/3 handshake deadline and per-stream timers are not built; the HTTP/2
  head and drain checks run only while a stream is open), and that `h2-attacks.py` was never
  committed.
- **JSON numbers out of range** (found by `fuzz_json` in the audit's campaign): a literal
  whose exponent overflows a double (`1e999`) parsed to infinity and was written back as
  `inf`, which is not JSON, and writing a whole number above 2^63 converted it to `long long`
  out of range, which is undefined behaviour. The parser now refuses such a literal (RFC 8259
  section 6 lets a parser limit the range), and the writer checks the range before the integer
  form and writes `null` for infinity and NaN. The parser reads MCP messages, control replies,
  ACME answers, an archive's `package.json` and the root helper's requests. The input is
  `tests/fuzz/regressions/json/overflow-exponent`, and the unit tests now replay the JSON
  corpus with the fuzzer's round-trip rule (five failures before the fix).
- **The fuzzers checked their invariants for the first time.** The targets state them with
  `assert()`, and a Release or RelWithDebInfo fuzz build defines `NDEBUG`, so every recorded
  run until now tested memory safety only (the binaries contained no assertion). The fuzz
  targets are compiled with `-UNDEBUG` now.
- **The integration suite passes on a default build again.** Two sites that seven SNI,
  authority and status checks need were defined only when the binary had the HttpArena
  handler (off by default, so CI and the sanitizer build failed those checks since
  2026-09-24), and four checks piped `agensio ctl protection` into `grep -q`, which under
  pipefail fails whenever the writer is still writing when grep exits at its first match
  (the sanitizer build's `ctl` was killed by SIGPIPE in 50 of 50 tries). Both fixed in the
  suite; the server did nothing wrong. The sanitizer build now passes 588 checks with nothing
  on the server's stderr, the Release build 596.
- `scripts/fuzz-all.sh` runs every fuzzer for a set time on its checked-in corpus and prints
  one table (runs, coverage, corpus, verdict); `.github/workflows/fuzz.yml` runs it weekly
  with the sanitizer build through the unit and integration suites, and the before-tag list in
  `docs/security-control-plane.md` now names it instead of two fuzzers.

## 0.1.0-alpha.50 (2026-10-05)

From the alpha.49 report (security, medium): the failure jails reading the journal matched on
`SYSLOG_IDENTIFIER`, which is whatever a writer passes to `openlog()` or `logger -t`, so any
account on the host (another site's compromised plugin, a shell user) could have fed five
forged Drupal lines and had any address banned from the web ports for an hour, a visitor's or
Let's Encrypt's; the WordPress match was an `or` of the php-fpm unit and the plugin's identity,
and the 30-day `journal_seen` check trusted the same field. The match is now a group per site
account, `SYSLOG_IDENTIFIER=drupal _UID=<uid>` for Drupal and `_SYSTEMD_UNIT=<php-fpm unit>
_UID=<uid>` for WordPress (the uid a field journald sets from the sender's credentials; the
plugin's identity, which carries the client's Host header, is left to the filter), groups
joined with `+`; the helper's probe asks the journal with the same words. A site without an
account of its own, or whose account is not on the host, has no trusted field: the jail lists
it as not read (`unidentified` in `protection_show`), is disabled when no site has one, and
health's `fail2ban_failures_unseen` names it with the account as the fix, and `site_install`'s
next steps for such a site say so too. With a syslog daemon the files carry no uid, fail2ban's
usual position; `docs/fail2ban.md` says so.

fail2ban's own documentation is in the tree now, `docs/fail2ban-ref/` (the 1.1.0 manuals as
text, the shipped `jail.conf`, path and filter files, the nftables actions, the journal
backend's source, the project wiki's pages on regexes, best practice and troubleshooting, and
the WP fail2ban plugin's three filters), with a README mapping each to agensio's renderers and
the facts that bind them, the way `docs/rfc/` serves the protocol layers. Two of those facts
changed the rendering: fail2ban's systemd backend reads the system journal alone by default
(`journalflags` 4) and journald files the lines of an account with an ordinary uid under that
user's journal, so a failure jail over such an account is rendered `backend =
systemd[journalflags=1]` (a system account as agensio creates them needs nothing); and
fail2ban's `drupal-auth` filter pins no identity itself, so the `SYSLOG_IDENTIFIER=drupal` word
of the match is what selects Drupal's lines, the WP fail2ban filters requiring theirs in the
line (`_daemon = (?:wordpress|wp)`). `docs/fail2ban.md` gained a section on testing a filter
with `fail2ban-regex` and reading fail2ban's merged configuration.

## 0.1.0-alpha.49 (2026-10-04)

From the alpha.48 report: on a journald-only host the Drupal failure jail was rendered enabled
at once (fail2ban ships its filter and the journal is always there), so health stopped saying
that the Syslog module was still off. The helper's `host_protection` now asks the journal,
with fixed arguments, for one line under each journal-reading jail's identity
(`SYSLOG_IDENTIFIER=drupal`, `wordpress(<site>)`; not the php-fpm unit, whose own notices
would count) from the last 30 days; while there is none, `fail2ban_failures_unseen` stays,
saying that Drupal's Syslog module is not enabled or the WP fail2ban plugin not active yet,
with the application's step as the fix; `protection_show` reports `journal_seen` per jail.

The same report confirmed alpha.48's fix on the live host (no freeze with a vanished client
over TLS and plain, WebSocket and a 6 MB download, the worker in `epoll_wait`, every socket
`O_NONBLOCK`) and its watcher's capture of the third stall under alpha.47 shows the path the
fix changed: the only worker thread inside `write(2)` of one 16,406-byte TLS record under
`sk_stream_wait_memory`, the peer silent for 648 s with 128 KB queued, the accept queue
growing to 17.

## 0.1.0-alpha.48 (2026-10-04)

A stalled TLS client no longer stops the server (2026-10-04 live incident: a phone vanished
mid-WebSocket over TLS and every site on the host stopped answering for fifteen minutes,
until the kernel gave the dead connection up). Every accepted socket ran in blocking mode:
Asio 1.38 passes `MSG_DONTWAIT` to each of its own receive and send calls and so never sets
`O_NONBLOCK` on a stream socket on Linux (`needs_non_blocking` is false there), and Linux's
`accept(2)` does not inherit the listener's flag as BSD does. Asio's own operations never
noticed; OpenSSL's socket BIO (`write(2)`, no flags) and `sendfile(2)` do notice when the
send buffer is full, and slept in the worker's loop. Every
accepted socket, TCP and the control socket's, is now made non-blocking at accept, one
`ioctl` per connection; the integration suite holds a TLS WebSocket client that stops reading
against a plain request answered meanwhile and checks every socket's flags.

From the alpha.47 report on the live host: on a host where no syslog daemon writes files
(journald only, Debian 13's default; a left-over `auth.log` that nothing writes had passed
for a log) the failure jails read the journal, `backend = systemd` with a `journalmatch` on
Drupal's identity or on the php-fpm unit and the WP fail2ban plugin's identity per site
name, so neither application needs rsyslog and `agensio-drupal-auth` is enabled at once
there; `protection_show` reports `journal` and `journalmatch` per jail. The WordPress filter
files are taken from the plugin's release on wordpress.org rather than from the site's
directory, which the site's account can write (a planted filter bans whom it likes or
carries a regex that freezes fail2ban); reading the site's copies first is the alternative.
`docs/fail2ban.md` and `docs/configuration.md` 18 say which host gets which.

## 0.1.0-alpha.47 (2026-10-03)

From the alpha.46 report: the login jail's regex for a path routed through the query string
(`/?controller=AuthController&action=check`) still backtracked, with the cube of the line's
length, since the root's separator run met a trailing-slash quantifier and two lookaheads
scanned before the literal `?`; a 10 KB line of slashes cost minutes with fail2ban's lock
held, every jail standing still. The run is the whole path now with nothing after it, the
literal `?` comes first so a line without a query fails at once, the parameters are looked
for once after it, and path info after a `.php` script stops at a `?`; the root suite times
ten pathological lines, with and without a query, under five seconds. The rendered login
regex is a quarter of its size (the owner's objection): the separator grammar is the
filter's `sep` variable, referenced as `<sep>` from the shipped default and from every
host's jail parameter, which fail2ban substitutes, and a letter's two percent codes are one
hex class (`(?:c|\x25[46]3)`); coverage unchanged, proven by the same spelling and timing
checks. The failure tier (research into what fail2ban ships and the application communities
use): for a preset whose application logs its own failed logins, the jail file carries a jail
over that log with the filter fail2ban or the application ships, counting failures rather
than attempts: `agensio-wordpress-soft` and `-hard` over the auth log with the WP fail2ban
plugin's filters, `agensio-drupal-auth` over the system log with fail2ban's own filter; each
enabled only when its filter file and its log exist, else disabled with the user's steps
(the plugin from the WordPress admin panel and root's copy of its filters, Drupal's Syslog
module), which `site_install` puts in `next_steps` and health reports as
`fail2ban_failures_unseen`; agensio installs no plugin and changes no application, the
owner's rule. `docs/fail2ban.md` is the administrator's guide to all of it: how agensio uses
fail2ban, the two tiers, what each application type gets and what to add in the application
(the WP fail2ban plugin, Drupal's Syslog module and flood control, django-axes, Kanboard's
lockout), the local overrides and the limits; shipped with the package.

## 0.1.0-alpha.46 (2026-10-02)

From the alpha.45 report on the login jail's regex: its dot-segment grammar was ambiguous
and a 16 KB request line of `./` cost 2.3 s of fail2ban's time, so the branches are disjoint
now and such a line costs linear time (a timed check in the root suite); a letter is matched
under either case's percent code and slashes and dots encoded too, which closes nine more
spellings; `/index.php` is an optional prefix of a PHP preset's login path and never a login
by itself, path info is allowed only after a `.php` file and a `.format` suffix only on Rails
and Redmine paths, so Joomla's and Kanboard's ordinary form posts are not counted; and there
is one `agensio-login` jail per access log with the paths of the sites writing it
(`login_jails` in `protection_show`), so one application's paths are not counted on another
site's log. And, as the report suggested and the owner agreed: a separator spelled as a
percent escape in the path (`%2F`, `%5C`) is 404 on every location that resolves paths on
disk, Apache's `AllowEncodedSlashes Off`, so `/x%2F..%2Fwp-login.php` never reaches the
script; a proxied location hands the raw target to its origin undecoded, as nginx does
(docs/configuration.md 1, CLAUDE.md hardening item 2). The site key `encoded_slashes =
"allow"` (`site_update`, `--encoded-slashes`) restores the lookup for a PHP application
behind a front controller that encodes a slash inside a path segment and reads
`REQUEST_URI`, Apache's `NoDecode` in effect; nginx has no such switch.

## 0.1.0-alpha.45 (2026-10-02)
From the alpha.44 report: the installed fail2ban filters are compared with the text this
build ships (`installed_filters`, `fail2ban_filter_stale`, and the install line ahead of
every re-render when they differ), since an upgrade had changed `agensio-login` and the old
copy ran on; and `site_update` of a site whose certificate is issued no longer tells the
user to make the name resolve and open port 80. The login jail matches every spelling of a
login path (the report's eleven evasions: percent-encoding, repeated slashes, dot segments,
case, a trailing slash, `/index.php`, a `.format` suffix, query order): the renderer turns
each path into a regex of its spellings (`spelling_regex`, `%` written `\x25`), the filter
is case-insensitive, and the decision stayed fail2ban's, the owner's call, with nothing
added to the server.

## 0.1.0-alpha.44 (2026-10-02)
From the alpha.43 report on the live host: the access log escapes every byte from 0x7F up as
`\xHH` in the combined format (nginx's `ngx_http_log_escape`) and a JSON line writes a byte
that is not well-formed UTF-8 the same way, and `logs_query` escapes what it reads, so its
answer is valid text whatever a client sent (a TLS ClientHello to port 80 broke a 1.7 MB
answer); the WordPress preset's login paths include `/xmlrpc.php`; `login_paths` accepts a
path with the start of its query (`/?controller=AuthController&action=check` for Kanboard,
`/?_task=login` for Roundcube, `/ucp.php?mode=login` for phpBB), matched from the query's
start; `protection_show` lists only the file count of a jail that is not agensio's (a Samba
jail with 1,976 logs made an 86 KB answer); `logs_query` for a site that does not exist is a
404 rather than an empty answer. From the addendum: a site change that leaves the installed
jail file or the kept ruleset older than the sites (a login path added, a new public port)
puts root's re-render line into the answer's `next_steps`, where before only health said so.

## 0.1.0-alpha.43 (2026-10-02)

Host protection rendered, never applied (hardening step 2 of CLAUDE.md, item 6;
`docs/configuration.md` 18; design section 21). Per-address limits are the firewall's and
brute force fail2ban's, so agensio now ships both for its host and checks them: `agensio ctl
protection`, the MCP tool `protection_show` and the offline `agensio protection -c FILE`
render an nftables ruleset in a table of its own (`inet agensio`, over the public ports:
more than 30 new connections a second from one address dropped, the 201st connection held
refused, more than 50 QUIC handshakes a second dropped, IPv6 per /64; no policy, nothing
outside the table touched, so it cannot lock root out and coexists with a panel's rules) with
root's commit-confirmed commands (a trial that a `systemd-run` timer undoes in ten minutes,
then `agensio-firewall.service` for boot), and four fail2ban jails over the access logs
(`agensio-login` counts credentials posted to the login paths, ten in ten minutes bans an
hour; `agensio-auth` 401/403, `agensio-scan` 404, `agensio-post` any POST, the catch-all)
with four static filters. The login paths come from the presets (wordpress, drupal,
laravel, grav, redmine, django, wagtail) and from a new `[[site]]` key `login_paths`, which
`site_create`/`site_update` (`--login-path`) write for an application without a preset of
its own, after the agent asked the user. Health asks the root helper's new read-only
`host_protection` (fixed arguments: `nft -j list ruleset`, `systemctl show`, `fail2ban-client
status`) and reports `firewall_limits_missing` (a per-source limit in any table counts: a
panel's host is never nagged), `firewall_limits_trial`, `firewall_limits_unsaved`,
`firewall_quic_unlimited`, `fail2ban_missing`, `fail2ban_jail_stale` (a site added since the
jail was installed), `fail2ban_log_format`, `fail2ban_blind` and `protection_unchecked`, each
with root's commands; `[control] host_protection = "external"` makes them informational on a
host a panel protects, `"off"` skips the probe; nothing is reported for loopback-only
listeners. Packaged inactive under `/usr/share/agensio/firewall/`, `/usr/share/agensio/fail2ban/`
and `/usr/lib/systemd/system/agensio-firewall.service`; the unit test holds the shipped files
to the renderers. `tests/protection.sh` runs the real nft and fail2ban in the
`agensio-devbox:host` image. Security page row 37.

`logs_query` labels the server-wide access log honestly (the alpha.42 report: 292 lines of the
port-80 catch-all and the redirects carried the first site's name, so a reader took that site
for the one being scanned). Lines of the `[log] access` file, which every site without an
`access_log` of its own writes into, have the source `access`; a site's name appears only on a
file it alone writes; `sources` lists every file read with the sites writing into it; a query
for a site that shares the server-wide file answers `shared: true` with a note, its JSON
lines filtered to the site's host names, combined lines (no host in them) left as they are.

## 0.1.0-alpha.42 (2026-10-02)

A connection ceiling per worker (`server.max_connections`, hardening item 5 of CLAUDE.md,
`docs/configuration.md` 18): by default `(open-file limit - 2048) / workers`, at least 128,
so a worker can never run itself out of descriptors. A connection accepted above it is
refused at once, a plain client with a prebuilt 503 and `Retry-After: 2`, a TLS client by a
close before any handshake work; the error log says so once per worker per ten seconds,
`server_status` shows `max_connections` and `connections_refused`, health reports
`connections_refused` with the two fixes. Decided with it: per-address connection and rate
limits are the firewall's and fail2ban's job, not the server's; section 18 says where each
limit belongs. The refusals carry their context (the owner's question: an agent must be able
to tell an attack from a low ceiling from a bug): each worker keeps the addresses it refused
most, the listeners and the times, with no allocation on the refusal path; the log line says
how many connections the worker holds and how many have been idle for two seconds or more
(counted when a connection sheds its buffers, so the request path pays nothing), the
refusals since the last line and since start, the addresses and the listener; `server_status`
adds `connections_idle` and `workers_detail`; the health finding's fix follows from the
shape: one address behind most refusals (the firewall), workers full of idle connections
(slow or stuck clients), or load from many addresses (raise the limit).

## 0.1.0-alpha.41 (2026-10-02)

From the alpha.40 report (Kanboard secured through MCP alone, the rules verified end to
end): `site_show` labels the locations a managed site's rules render with `from: "rules"`
(they said nothing, like hand-written ones, beside `preset:<app>` and `root:<file>`), through
`control::rule_locations`, which the renderer now uses too; and `site_install` puts the
`.htaccess` rules advice first in its next steps, ahead of "open the site in a browser",
since the site is exposed until the rule runs.

## 0.1.0-alpha.40 (2026-10-02)

An application's own server guidelines through the control plane (the Kanboard proposal
against alpha.39, `docs/design-site-operations.md` section 19). A managed PHP or static
site carries `rules`: `private` paths answered 404 whatever exists, `entry_points` (the
only `.php` files that run; every other `.php` is 404, never served as source), `cache`
(directories served from disk with `Cache-Control: public, max-age=N`, nothing running
there, no source backup served) and a `front_controller` (one of the entry points, reached
by every missing path with its query string). The object is validated against the preset
(and again on every later change, so an `app` the rules no longer fit is refused until
`rules: {}`) and rendered into ordinary locations marked `# rules:` in the site file, so a
rule can only narrow what the preset serves and `--explain` shows the result; `handler =
"deny"` is the one new site-file value. `agensio ctl site-create` / `site-update` take
`--private`, `--entry-point`, `--cache PATH=SECONDS`, `--front-controller`, `--no-rules`;
MCP `site_create` / `site_update` take `rules`; `site_show` reports them.

`site-install` reads an archive's `.htaccess` files once, for whole-directory denials
(`Require all denied` / `Deny from all` outside `<Files>` blocks, `<IfVersion>` and
`<IfModule>` transparent, which is how Kanboard writes them), reports the directories as
`facts.htaccess_denied` and suggests the matching `private` rule in its next steps; the
server never applies it by itself and never reads `.htaccess` when serving.

The php preset refuses `.sqlite`, `.sqlite3`, `.db` (every PHP preset's root and shields,
through `kSourceBackups`) and `/web.config`: under alpha.39 Kanboard's `data/db.sqlite` was
downloadable. `deny_suffixes` accepts `"~"` (an editor's `name~` backup), the one ending
without a dot, which the presets already refused internally.

Tests: unit (every accepted and refused rule shape, render and load back, the router's
answers, the `.htaccess` parser), `tests/integration.sh` (a php site with rules on the
wire, the refusals, `site_show`), `tests/kanboard-install.sh` (Kanboard 1.2.54 through the
control plane in the `agensio-devbox:php` image: the bare preset runs `app/Core/Base.php`,
the rules stop it, login page, jsonrpc, healthcheck, cached assets, nice URLs, the database
private). Security page row 35. No request-path change.

Root additions to a managed site (`sites.d/<domain>.root.toml`, design section 20, the
owner's question about ISPConfig's nginx directives): a root-owned file beside the managed
one, `site = "<domain>"` on its first line and `[[location]]` tables with any location key,
merged into the site before its preset as hand-written locations, so root has the whole
location grammar on a site the tools manage while `site-update` keeps regenerating only its
own file. The loader refuses a symlink, a file not owned by the main configuration's owner
or writable by others, and a path the site file already has; a file whose site is disabled
or deleted is kept and ignored with a warning (`-t`, the error log, health
`root_additions_orphan`). `--explain` marks the locations `# from root:<file>`; `site-show`
and MCP `site_show` report `root_additions` (the file, present or not, what it added); the
trash moves the file with the site and restore brings it back; a plain `site-delete` sets
it aside as `.bak` beside the site file's `.bak` (still root's, `root_additions_set_aside` in
the answer, so no orphan is left behind); the MCP texts send an agent asked for what no field
covers to that file, never to the managed one. A reference row for the file's `site` key.

## 0.1.0-alpha.39 (2026-10-01)

Deleting a site with its files (F12b of `docs/design-site-operations.md`, the owner's
decisions of 2026-09-30):

- **`site_delete` with `files: true`** (`agensio ctl site-delete NAME --files`) moves
  everything of a site into root's trash, `<sites_root>/.trash/<domain>-<date>-<time>/`
  (0700): its directory, the account's state directory (or the site's virtualenv alone when
  another site shares the account), its access log with its rotations, its environment file
  with its secrets, and the site file's text in the entry's manifest. Everything moves by
  rename; nothing is copied or deleted. The account is kept. Refused while the site's
  service runs, with the `systemctl` lines for root. Without `files` the delete is what it
  was: the configuration alone.
- **`trash_list`, `site_restore`, `trash_delete`** (`agensio ctl trash`, `site-restore ENTRY`,
  `trash-delete ENTRY`). A restore puts every piece and the site file back, into an empty
  place only, and needs the account at the uid the files carry. `trash_list` shows each
  entry's size, expiry and whether its account is still in use.
- **`[control] trash_keep`**, 60 days by default: worker 0 removes expired entries every
  hour; `agensio ctl trash-expire` does it now; 0 keeps entries until `trash-delete`.
- A deleted site's access log is no longer recreated, empty, at every reload: the log
  registry now opens only the files the configuration names.
- A files-delete of a PHP site applies the php-fpm pools through the helper, so the
  account's pool file goes with the site.

## 0.1.0-alpha.38 (2026-09-28)

From the Node report against alpha.36 (Uptime Kuma 2.5.5 on an `app = "proxy"` site, where
nothing after `site_install` could run):

- **`app = "node"`**: every request goes to the application (WebSockets included), and
  agensio answers the project's manifests, `node_modules/`, `.env`, and databases and logs
  by their ending with a 404 itself. `entry` names the file `node` runs; `site_install`
  guesses it from `package.json`.
- **Two tasks, run as the site's account with npm's cache and configuration in its
  home.** `npm_ci` installs the dependencies exactly as `package-lock.json` pins them.
  `npm_run` runs one script of the project's `package.json` by name, such as Kuma's
  `download-dist`. `site_tasks_list` names `apt-get install -y nodejs npm` when the
  runtime is missing.
- **The unit** from `site_service_unit` runs root's `node` on the entry, with `HOST` and
  `PORT` from the upstream. A Node site's environment cannot set `HOST`, `PORT` or
  `NODE_ENV`, so it cannot move the application off loopback; `NPM_CONFIG_*` is refused
  on every site. Service status, logs, health and restart lines work as for Rails and
  Django.
- **An archive's facts**: its `package.json` name, scripts, lockfile and guessed entry,
  and the Node it asks for against the runtime's `node --version`. The next steps give the
  whole chain, never "open the browser" while nothing runs; for Uptime Kuma they add
  `DATA_DIR` in the account's home, `UPTIME_KUMA_DB_TYPE=sqlite`, and the warning that
  the first visitor becomes its admin. A Node archive on an `app = "proxy"` site is named
  in the warnings.
- `tests/kuma-install.sh` installs Uptime Kuma 2.5.5 with Debian's node and npm and checks
  its pages, socket.io's polling and its WebSocket upgrade through agensio over TLS.

## 0.1.0-alpha.37 (2026-09-28)

- presets_list and the reference: a headers-only location joins the preset's; Wagtail's static caching

## 0.1.0-alpha.36 (2026-09-28)

Found while fixing the alpha.35 report:

- **A site with `hsts` behind a proxy preset served its project directory from disk.** A
  managed site file carries HSTS as a hand-written `/` location with `add_headers`, and a
  hand-written location replaced the preset's location at the same path. For `rails`,
  `redmine`, `django` and `wagtail` that meant the application was never reached, and the
  project's files were answered from disk, source included (a `settings.py` came back
  200). `app = "proxy"` sites lost their application the same way, and a PHP preset lost
  its front controller (WordPress permalinks and Laravel routes answered 404). A
  hand-written location that sets only `add_headers` now joins the preset's location at
  its path. Site files on disk are read the new way at once; nothing needs rewriting.
  The alpha.35 site of the report had no `hsts` and was not affected.

From the alpha.35 report (Wagtail 8.0 installed and serving through MCP, end to end):

- **`/static/` caching follows the name.** A name that carries its content's hash
  (`base.85e6f9d19e42.css`, Django's `ManifestStaticFilesStorage`) is cached for a year and
  `immutable`; any other name for five minutes, then revalidated by `ETag`. Before, every
  file was pinned for a year, and a plain Django project's upgrade never reached browsers.
  A/B against alpha.35 flat (`ab-20260927-234745.md`, 0.979 to 1.006).
- **Secure cookies and a meaningful `check_deploy`.** `agensio_settings.py` makes the
  session and CSRF cookies https-only on a TLS site. It silences `security.W008` when the
  site redirects to https and `security.W004` when it has `hsts`, since agensio does both
  at the edge and Django's check cannot see it. `django_settings` run again replaces
  agensio's own earlier version of the file (kept as `.bak`), so an existing site gets
  this with one task.
- `check_deploy`'s summary names the checks: "4 warnings: security.W004, ...".
- `site_service_logs`' hint speaks of a Python traceback on a Django site.
- `site_env_set` of `DJANGO_SUPERUSER_PASSWORD` says only `createsuperuser` reads it and
  no restart is needed.
- The rendered unit names each `PATH` directory once.

## 0.1.0-alpha.35 (2026-09-28)

From the Django report against alpha.33 (Wagtail 8.0 on an `app = "proxy"` site, where
nothing after `site_create` could run):

- **`app = "django"` and `app = "wagtail"`**, with the site field `project` (the project's
  Python package, required, asked by `site_create`). agensio serves `/static/` and `/media/`
  from the project directory and sends the rest to Gunicorn. Uploads get `nosniff` and a
  script-blocking Content-Security-Policy, and Wagtail's `/media/documents/` is refused.
  The project's files are 404 at the edge.
- **Python tasks in a virtualenv of the site's own.** `venv_create`, `pip_install`,
  `startproject`, `pip_install_requirements`, `django_settings`, `migrate`,
  `collectstatic`, `createsuperuser` and `check_deploy`. `startproject` runs the preset's
  own command: `wagtail start` or `django-admin startproject`. Every row runs root's
  `python3` of `[control] runtimes` under the virtualenv's name, so the program stays
  root's and the packages are the site's. A Debian host without `python3-venv` is told so
  before `venv_create` runs, with the package command.
- **`pip_install` installs any packages, and the user confirms every run in person.** The
  value can only be package names with extras and versions, passed to pip after `--`. The
  MCP bridge asks in the client's own dialog (MCP elicitation) before it sends the task;
  an agent's `confirm` is not enough. A client that cannot show the dialog, or a decline,
  gets the `agensio ctl` command for the user to run in a terminal, where the warning is
  printed and `--yes` confirms. The control API refuses the task without either, and the
  audit log records which it was. `docs/mcp.md` shows how to limit the agent's SSH key to
  `agensio mcp`, which the confirmation depends on.
- **The production settings agensio writes.** `django_settings` writes a fixed
  `agensio_settings.py`: the project's own settings, then `DEBUG` off, the secret from
  `DJANGO_SECRET_KEY`, the host names and origins from the site, the forwarded https, the
  served paths, and a database from `DATABASE_URL`. It holds no secret.
- **The first admin's password never passes through the agent.** It is generated into the
  site's environment, revealed only on request, and the rendered Gunicorn unit unsets it.
- **The Gunicorn unit** from `site_service_unit`; `site_service_status`, `site_service_logs`,
  health and the restart lines cover Django sites as they do Rails sites.
- **Installs from an archive** of a Django project generate `DJANGO_SECRET_KEY`, list the
  tasks, and warn when the archive's package is not the site's `project`.
- `PIP_*`, `VIRTUAL_ENV`, `DJANGO_SETTINGS_MODULE` and `AGENSIO_*` are reserved in a site's
  environment. The MCP schema no longer advertises the Rails pattern for every `version`.
- A task's credential patterns follow the site's preset: a Redmine site running a Rails
  task now gets Redmine's.
- `tests/wagtail-install.sh` installs Wagtail 8.0 with real pip and Gunicorn behind agensio
  over TLS and logs into its admin.

- `site_env`'s hint follows the preset. A proxy site without an environment file is told
  how to set what its application reads and to generate a random secret, and that its
  unit loads the file with `EnvironmentFile=`. The hint no longer mentions Rails'
  `SECRET_KEY_BASE` or tasks the site does not have. The refusal for other presets now
  names `redmine` among the presets that have an environment.

## 0.1.0-alpha.34 (2026-09-27)

From the alpha.33 report (Redmine 7.0.1 installed and serving through MCP; the service
behind it was the blind spot, and task answers were too large for the MCP host):

- **The application service is visible.** `site_service_status` (viewer; `agensio ctl
  site-service NAME`) reads a Rails or Redmine site's `agensio-app-USER.service` through the
  root helper with `systemctl show` and fixed properties (loaded, active, failed, since
  when, pid, exit status, memory, restarts, enabled at boot), with a summary and next
  steps: `site_service_unit` when no unit is installed, `site_service_logs` and root's
  restart line when it failed. `site_service_logs` (admin, audited; `agensio ctl
  site-service-logs NAME [--lines N] [--since 3h]`) returns the unit's journal
  (`journalctl -u` with fixed options, 1 to 1000 lines, a bounded `since`). The unit
  comes from the site's account in the configuration on disk, never from the call.
  Starting and restarting it stays root's.
- **Health reports a service that does not run.** One `systemctl show` for every Rails
  site with its own account (helper op `app_check`, never waited for while a task holds
  the helper): `site_service_missing` (info), `site_service_down` and
  `site_service_failed` (warnings with the logs tool and the root line).
- **Task answers are short.** A task keeps up to 1 MB of its output (its first 256 KB and
  last 768 KB beyond that). The answer carries the last 4 KB on success, and the first
  4 KB and last 12 KB on a failure, with `truncated` and a summary where the output has
  one: the migrations applied, `Bundle complete!`, Redmine's default data, the number of
  files in `public/assets`. `site_task_output` (admin; `agensio ctl site-task-output NAME
  [--offset N] [--length N] [--raw]`) reads the whole output in 64 KB slices until the
  next task or a restart. The alpha.33 run's 68 KB answers overflowed the MCP host.
- **Restart lines where they apply.** After `bundle_install`, `db_migrate`, `db_prepare`,
  `plugins_migrate` or `assets_precompile` on a Rails site with its own account,
  `next_steps` carries `systemctl restart agensio-app-USER.service`. `site_env_set`'s step
  names the unit `site_service_unit` renders, not `docs/examples/puma.service`.
- **Smaller fixes from the same report.**
  - A Redmine site's next steps list only the steps still open on disk: `database.yml`,
    `Gemfile.local`, `vendor/bundle` and `public/assets` decide.
  - The body-limit line is gone for a site with its own `max_body_size`.
  - `Gemfile.local` says why Bundler warns about Puma twice.
  - `/Gemfile.local` is refused at the edge like `/Gemfile`.

## 0.1.0-alpha.33 (2026-09-27)

From "wall 1", Redmine 7.0.1 through MCP alone (its archive ships only
`config/database.yml.example`, keeps Puma in its test group, and its Gemfile picks the
database driver from `database.yml`):

- **`database_config`, a task with no program.** A new kind of task row writes one fixed
  file below the site's directory as the site's account, only when it is missing, never
  through a symlink: `database_config` writes `config/database.yml` (0600) from a template
  that takes the database from `DATABASE_URL` in the site's environment and the adapter
  from its scheme, so no password is kept in the tree and a Gemfile that reads it bundles
  the right driver. It needs `DATABASE_URL` set first (`site_env_set`) and says so.
- **`app = "redmine"`.** Built on `rails` (its tasks for an existing application, its
  refusals and credential files) plus `gemfile_local` (a fixed `Gemfile.local` adding
  Puma), `load_default_data` (a typed language parameter as `REDMINE_LANG`) and
  `plugins_migrate`; `site-install --version 7.0.1` fetches redmine.org's release archive.
  `tests/redmine-install.sh` installs Redmine 7.0.1 through `agensio ctl` alone and serves
  its login page over TLS from the rendered unit.
- **The agent is told before the wall.** `site_install`'s facts name `database_yml`,
  `database_yml_example` and `redmine`, and its next steps start with `DATABASE_URL` and
  `database_config` when the archive has no `database.yml`; a Redmine archive on a `rails`
  site gets a warning to switch it. `bundle_install` that exits 0 while the application
  says it found no database configuration answers 409 (the bundle has no driver), and a
  task that fails for the missing `database.yml` carries a hint to `database_config`.
- **`agensio ctl site-unit NAME` / MCP `site_service_unit`** renders the Puma unit of a
  Rails or Redmine site from its account, directory, loopback port, `[control] runtimes`
  (the Ruby its bundle was built with; the example unit hard-coded `/usr/bin`) and its
  environment file, with the root commands that install it; every value checked to be a
  plain path or name. Next steps point at it instead of `docs/examples/puma.service`.

From the alpha.32 report (all four alpha.32 changes confirmed on the live host):

- The exposed-orphan texts agree with their count, as the other ledger messages do: "KEY_B
  in it was readable by others ... brings that value back ... rotate it" for one name,
  the plural for several, in health's `site_env_orphan` and `site_delete`'s hint.

## 0.1.0-alpha.32 (2026-09-27)

From the alpha.31 report (the exposure ledger confirmed in every path the tester built):

- The fix of a leaked value's warning is a `site_env_set` call and no longer reads "as
  root: ..." (that steered an agent to hand the user a terminal for a tool call); the
  `chown`, `chmod` and `rm` fixes keep it.
- A deleted site's kept environment file whose values others could read and nobody
  rotated says so: health rates that `site_env_orphan` a warning naming them, and
  `site_delete`'s answer lists them under `exposed` with a hint to rotate them when the
  site comes back, instead of "keep it to bring the site back with the same secrets".
- `site_env_set` answers `still_exposed` (and a warning) with the values still as others
  could read them, so re-setting a value to itself or rotating one of two says so without
  a health call.
- Ledger entries of a name with neither a configured site nor a file are pruned by health,
  so `env/.exposed` does not grow for ever.

## 0.1.0-alpha.31 (2026-09-27)

From the alpha.30 report (both alpha.30 changes confirmed on the live host):

- **The warning to rotate a leaked secret no longer vanishes when the directory is
  closed.** With the environment directory open to others and a site's file readable,
  any task or `site_env` call on any other site closed the directory, health then rated
  the still-readable file as info ("nobody else could reach it") and the next call told the
  site "nothing to rotate". Now, in the same pass that closes the directory, every file in
  it that others could read is made 0600, named with "rotate what it holds" under
  `tightened` and in the error log, and recorded in a ledger beside the fingerprint key
  (`env/.exposed`: site, variable, the value's fingerprint, when; never a value). Health
  also records what it sees readable under an open directory, so closing it by hand keeps
  the fact. `site_env_unsafe` warns "X, Y were readable by others (seen ...) and have not
  changed since: rotate them" until every such value has changed or gone; a
  `site_env_set` that changes one drops its entry.

## 0.1.0-alpha.30 (2026-09-27)

From the alpha.29 report (all three alpha.29 changes confirmed on the live host):

- **Health rates a site's environment file by what could reach it.** A file others can
  read under a directory that is open to others too may have leaked: `site_env_unsafe`
  is now a warning for that site with the rotation advice, not info beside the
  directory's warning. Under a 0700 directory it stays info and says nobody else could
  reach it.
- **`site_delete` names the environment file only when there is one.** The helper tells
  the server which sites have a file (`env_check` answers `present`), asked while the site
  is still on disk and never waited for: the kept line and its `rm -f` appear when the
  file exists, say "if it has one" only when the helper was busy with a task, and are
  absent for a site without a file.

## 0.1.0-alpha.29 (2026-09-27)

From the alpha.28 report (every alpha.28 change confirmed on the live host):

- **Health sees the sites' environment files, not only their directory.** The server
  cannot look inside root's 0700 directory, so a 0666 file stopped a site's tasks while
  health said nothing. Health now asks the provisioning helper for a read-only pass
  (`env_check`: owner, mode, links, and what a task would meet inside) and names each file
  as `site_env_unsafe` for its site with the root line, a file the next task tightens as
  info, and a deleted site's file as `site_env_orphan` with its `rm -f`. The helper is
  never waited for: while a task holds it, health says `site_env_unchecked`.
- Unsetting a site's last variable removes its file, and the answer now says so under
  `done`.
- Rotation is advised when a file readable by others is tightened only if its directory
  was open to others too; under a 0700 directory the note says nothing could reach it.

## 0.1.0-alpha.28 (2026-09-27)

From the alpha.27 report (a second Writebook install on the live host) and what fixing it
turned up:

- **HTTP/1 wrote an answer that waited on its origin into another site's access log.** The
  line took the site the worker had routed last, so a proxied or PHP request logged under
  whichever site the same worker served meanwhile: one tenant's traffic in another
  tenant's file (reproduced with two sites and a 400 ms origin). HTTP/1 now keeps the
  request's own site, as HTTP/2 and HTTP/3 already did.
- **Every 413 is in its site's access log.** A body refused for its declared size was in
  no access log over HTTP/1, HTTP/2 or HTTP/3 (the listener's catch-all, when there was
  one, got it; alpha.27's "it was in the access log only" was wrong). **A chunked HTTP/1.1
  body past the limit now gets 413 and Connection: close** instead of a cut connection
  logged as 200, and HTTP/3 answers 413 mid-body as HTTP/2 did; the warning line says "at
  least N MB" for a body counted as it arrived.
- **`site_env` returns names, lengths and fingerprints; a value only on request.** The
  owner's decision after the report: returned values end up in the agent's context and
  transcript, so a value leaves the server only for the names in `reveal`
  (`agensio ctl site-env NAME --reveal KEY`, `?reveal=KEY` on the API), each such read
  audited as REVEALED. The fingerprint is 16 hex digits of HMAC-SHA256 under a key kept
  beside the files (`.fingerprint.key`), so the same value has the same fingerprint and a
  weak one cannot be looked up in a dictionary. `exists` says whether the site has a file.
- **An environment directory or file with a lax mode no longer stops every task silently.**
  The helper tightens a root-owned directory open to others (0700) and a root-owned file
  others could only read (0600), and says so under `tightened`; a file others could write,
  a second hard link or another owner is refused with the `chown`/`chmod` line under
  `run_as_root`; health reports `site_env_unsafe`.
- **The bridge's version note reaches hosts that show structured answers.** It leads the
  text and sits in `structuredContent.bridge` (Claude Code shows only the latter).
- **`site_install` asks the runtime's Ruby for its version** when the application pins one
  and says "they match" or which version differs, instead of "when that is another
  version".
- **`site_delete` of a Rails or proxy site names the environment file it keeps**, with the
  root line that removes it.
- The Rails refusals by ending apply in any case; `/storage/` is matched as written, as
  paths are (alpha.27's "in any case" was about the endings).

## 0.1.0-alpha.27 (2026-09-27)

- **P1: a browser's second cookie reached no application over HTTP/2 or HTTP/3.** A
  browser sends one `cookie` field per cookie there (RFC 9113 8.2.3), and request assembly
  counted every field after the first but never stored it: the proxy, FastCGI and CGI saw
  the first cookie alone. A sign-in that sets a second cookie (Rails 8's `session_token`,
  Django's `csrftoken`) "did nothing" with no error anywhere; curl, which sends one field,
  never showed it. The fields are now joined with `; ` into one, in the order received,
  and count against no field limit (16 KB decoded bounds them); the proxy also folds two
  `Cookie` lines from an HTTP/1.1 client into one (FastCGI already did). Found with
  Writebook from Firefox and Safari; reproduced against alpha.26 through the benchmark
  origin (`cookie: _writebook_session=S` alone reached it), and checked in the
  integration suite through the proxy over HTTP/2 and HTTP/1.1 and into PHP over HTTP/2
  and HTTP/3.

From Writebook (basecamp, v1.2.2), a real ONCE application installed from its GitHub
archive on a second Rails site (report against alpha.26):

- **A site's environment.** A Rails application without credentials reads
  `SECRET_KEY_BASE` from its environment (every ONCE application, every Kamal
  deployment), and nothing could give it one, so `db_prepare` stopped with "Missing
  secret_key_base". A site with `app = "rails"` or `"proxy"` now has one file for its
  variables, `env/<site>.env` beside the main configuration, root's `0600` in a
  root-owned `0700` directory, in systemd's `EnvironmentFile` syntax: the tasks get it
  after agensio's own variables and `docs/examples/puma.service` loads it. `agensio ctl
  site-env-set NAME --set K=V --unset K --generate K` and MCP `site_env_set` change it
  through the root helper (a generated value is 64 random bytes in hex; an existing one is
  kept, and `--unset K --generate K` rotates it); `site-env` and `site_env` show it to an
  admin, values included. Both are admin only and audited with names, never values. Names
  that agensio sets or that choose or load a program (`PATH`, `RAILS_ENV`, `GEM_*`,
  `BUNDLE_*` other than a gem source's credentials, `LD_*`, `RUBYOPT`, `GIT_*`, ...) are
  refused on the way in and on the way out; a file that is not root's `0600` stops the
  site's tasks with the reason.
- **An archive install of a Rails application is followed through.** `site_install`
  reports what it found (a Gemfile, Rails credentials, the Ruby `.ruby-version` pins),
  generates `SECRET_KEY_BASE` into the site's environment once when the archive came
  without credentials (never for one with them, whose own secret it would override), and
  its next steps are `bundle_install`, `db_prepare`, `assets_precompile` and Puma with the
  pinned Ruby named, instead of "open the site in a browser". A site update picks the
  Rails chain by what is on disk, and no longer suggests `rails_new` for a site that holds
  an application.
- **Known failures carry the fix.** A task that stops on Rails' missing
  `secret_key_base` answers with the `site_env_set` call that generates one; one that
  stops on "Your Ruby version is X, but your Gemfile specified Y" names `[control]
  runtimes`. `docs/configuration.md` 15 shows how root builds a pinned Ruby under `/opt`.
- **`[control] runtimes`, `task_limits` and `task_network` apply on reload.** The helper
  reads them from root's file for every task, as it already read the site from it; a new
  Ruby no longer costs every site a restart.
- **The request-body limit is said before the first upload meets it.** A new site's next
  steps and an install's state its limit (1 MB unless set) and the one call that raises
  it, and every 413 for a declared body above a site's limit writes a warning to the error
  log naming the site, the client, both sizes and the fix (it was in the access log only).
- **Rails refusals cover any layout.** Everything under `/storage/` (databases and Active
  Storage's files) and any path ending in `.sqlite3` (and its `-wal`, `-shm`, `-journal`),
  `.log`, `.key` or `.sql`, in any case, are 404 at the edge, never proxied: Writebook keeps
  its database in `storage/db/production.sqlite3`, which the exact list missed. Refused
  endings on a proxy or FastCGI location (`deny_suffixes`) are now enforced by the
  dispatcher, not only on static locations.
- Tests: unit (names, values, the file syntax both ways, the change request, the files and
  their modes, the task's environment, the hints, next steps by disk state, the reload
  keys, the 413 line, the endings), `tests/tasks.sh` (the root file, the task's
  environment, the audited read, rotation, refusals, an archive install generating the
  secret), `tests/control.sh` (a viewer and an operator get 403 on a site's environment),
  the integration suite (the same without the helper, the endings, the 413 line).

## 0.1.0-alpha.26 (2026-09-27)

From the first Rails site built through `site_task` on a live host (report against
alpha.25):

- **Rails tasks no longer depend on gems installed system-wide.** With `GEM_HOME` alone
  the system's gems stayed on the search path, so on a host where root had once run `gem
  install rails`, `gem_install_rails` installed the meta-gem only, answered ok, and
  `rails_new` failed with a bare LoadError on a missing `rails` command. Every Rails task
  now also sets `GEM_PATH` to the account's `<home>/gems`: the account sees its own gems
  and Ruby's default gems, never root's (verified with Debian's Ruby 3.3: the full tree
  installs, `rails new`, `db:prepare` and `assets:precompile` run through the default
  Bundler). An account made before this release keeps working for its application (the
  application's gems live in `vendor/bundle`); `gem_install_rails` run once more completes
  its gem directory. `docs/examples/puma.service` sets the same two variables.
- **A task that needs an earlier one's result is refused before it runs, dry run
  included**, naming the missing file and the task to run (`rails_new` needs the `rails`
  command; the bundle tasks need the application's `Gemfile`), and **a task that exits 0
  without what the next one needs answers 409**, never ok (`gem_install_rails` without the
  `rails` command).
- **`site_tasks_list` reports each task's interpreter** (the program, whether the rule
  accepts it, and the package command when it is missing, with every missing package
  listed once under `run_as_root`), so root installs `ruby-bundler` before the first task
  instead of after the third, **and the effective time limit**: the row's, capped by
  `[control] task_limits.timeout` (3600 was advertised where 1200 applied).
- **The paths scanners probe on a Rails site are refused by agensio itself**
  (`/config/master.key`, `/config/database.yml`, `/.env`, `/Gemfile.lock`, `/.git/`,
  `/.kamal/` and the rest, listed under `never_served` in `presets`), 404 with no round trip
  to Puma and no line in the application's log.
- **The bridge says when it and the server are different builds.** Every control answer
  carries `X-Agensio-Version`, and a tool result from a bridge whose version differs from
  the server's carries a note: reconnect the MCP server after an upgrade, or restart a
  server that was not. The report's `app` enum without `rails` came from a bridge started
  before the upgrade to alpha.25; the enum is generated from the preset table and always
  had it.
- Tests: unit (the environment, `check_needs` both ways, the listing's time limit and
  interpreter state, the Rails refusals, the note), `tests/tasks.sh` 29 checks (the fake
  `gem` can now leave no `rails` command behind), the integration suite (the listing, the
  version header), `tests/rails.sh` 16 checks (root installs Rails system-wide first; a
  credential path answered 404 without `x-request-id`).

## 0.1.0-alpha.25 (2026-09-27)

- **Unit tests: the missing-interpreter check no longer depends on the host.** The task
  test used `/bin` as the runtime directory and expected no `/bin/ruby` there; GitHub's
  Ubuntu runners ship Ruby and merge `/bin` into `/usr/bin`, so a root-owned `/bin/ruby`
  made the dry run succeed and failed the alpha.24 release job at its first step. The check
  now names a directory that exists nowhere and asserts the refusal names it; verified in
  a container with the same root-owned `/bin/ruby`. No change to the server.

## 0.1.0-alpha.24 (2026-09-27)

- **Site tasks (F13, `docs/design-site-operations.md` section 4)**: `agensio ctl site-task
  NAME TASK [--param KEY=VALUE]` and the MCP tool `site_task` run one named task of the
  site's preset as the site's account, in the site's directory; `site-tasks NAME` and
  `site_tasks_list` list them. A task is a row of `src/services/tasks.cpp` with a fixed
  argv and typed parameters, never a command line: no option can be given (`rails new -m
  URL` is not expressible), a parameter that does not match its pattern is refused naming
  it, and the argv the row builds is what runs, by `execve`, with an interpreter from
  `[control] runtimes` (root's file; the program, the file it resolves to and every
  directory above both must be root's and writable by root alone, outside `sites_root`,
  checked before every run). The environment is built (PATH, HOME, TMPDIR, LANG and the
  preset's variables), stdin is `/dev/null`, the umask 027, the limits `[control]
  task_limits` (`timeout` 1200 s then SIGTERM and SIGKILL to the process group,
  `processes` 512 as `RLIMIT_NPROC`) plus 4096 open files and no core; whatever the
  program leaves in its group is killed; the output comes back as its first 16 KB and last
  48 KB; one task per site; the preset's credential files are swept private and the
  configuration validated after every run; the audit log names the exact argv, the
  account and the outcome. `[control] task_network = false` refuses the tasks that
  download. Through the provisioning helper (`task_run`: the site's app, directory and
  user from the configuration on disk, the account's home `<state_dir>/<user>` created
  `0700` when missing), else as the server's own account. The first preset with tasks is
  **`app = "rails"`**: the proxy preset's routing, its credential files
  (`config/master.key`, `config/credentials/`, `config/database.yml`, `storage/`), and
  `gem_install_rails`, `rails_new`, `bundle_install`, `db_prepare`, `db_migrate`,
  `assets_precompile`, all with `RAILS_ENV=production` and the bundle in `vendor/bundle`
  without the development and test groups. `site_create` suggests `<sites_root>/<domain>/app`
  as its root; Puma is started by `docs/examples/puma.service` until agensio manages it
  (F14). Tests: unit (the table, every refusal, the exact argv and environment, the runner
  on real processes, the sweep), `tests/tasks.sh` (root devbox, fake interpreters, 24
  checks), `tests/rails.sh` (real Ruby and rubygems.org: Rails installed, a new application
  made, its databases and assets prepared, Puma as the site's account, the application
  served over TLS by agensio), integration checks; security page rows 26 and 27.
- **HTTP/1: a request whose handler takes longer than `idle_timeout` is no longer closed
  with an empty reply.** The idle timer counted from the last byte written and closed the
  connection while an upstream exchange or a control command was still working: a PHP
  script or a proxied request slower than 15 s (the default), a `site_install` download
  or a site task ended in an empty reply (found when `gem install rails` outlived the
  control connection). A connection whose handler has the request now waits for it; the
  handler's own timeouts bound it (the upstream's read timeout, the task's limit), and a
  request body the client does not send still ends it at `body_timeout`. HTTP/2 already
  worked this way. Integration check with a 1 s `idle_timeout` and a 2.5 s answer. The
  cost is one flag per request: `bench/ab.sh HEAD -P` (`ab-20260926-221141.md`, two
  rounds) has the static rows at 0.997 to 1.035 and the proxy rows at 0.98 to 1.014 of
  HEAD, within the noise band.
- **Credential directories no longer fail an install.** `site-install` made every path of
  the hosting rule's list `0600` and refused the install when one was a directory, so any
  archive carrying `.git` (or Laravel's `config/`, `storage/`) could not be installed. A
  credential directory now loses its group's read and write and everything for others
  (`secret_dir_mode`: 2750 becomes 2710, the server may pass through but never list),
  which is what the hosting rule asks; `site-copy` and the task sweep use the same rule.

- **A site that runs no PHP derives no php-fpm pool from its `user`** (live report,
  2026-09-26: a Rails site behind `app = "proxy"` with its own account was told
  `php_tmp_missing` at error severity and `pools_stale`, and `agensio pools` would have
  written `agensio-ag5.conf` for it and reloaded php-fpm). The loader derives a pool only
  when the site's `php` will serve a FastCGI handler: a PHP preset, or a hand-written
  location with `handler = "fastcgi"` and no socket of its own; pool keys in `php = { }`
  on any other site are refused naming the rule, and `settings` refuses the pool keys for
  a proxy or static site. Unit tests for the proxy and static cases, the hand-written
  FastCGI case and the refusal; `docs/configuration.md` 11.

## 0.1.0-alpha.23 (2026-09-25)

- **QPACK's dynamic table on the encoder side** (RFC 9204 sections 2.1, 4.3, 4.5;
  design 7.2's second step): our answers' `server`, `date` and `content-type` (and
  `alt-svc` once it exists) go through the peer's dynamic table, inserted once with a
  static name reference on the encoder stream and then one index byte each, the table at
  most 1 KB and at most what the peer announced (h2load, the arena's client, and browsers
  announce 4 KB; curl announces none and keeps getting literals). The encoder mirrors the
  peer's table, references entries inserted for the same section post-base (appendix
  B.2's section is reproduced byte for byte), never evicts an entry a pending section
  references (the insert is refused and the field goes as a literal), counts the sections
  that may block the peer against its `QPACK_BLOCKED_STREAMS`, and reads the peer's
  decoder stream (acknowledgements, cancellations, increments) on the connection; the
  inserts a section needs are enqueued ahead of it, so they travel in the same packet. Unit
  tests for the instruction and section bytes, the round trip through our decoder, the
  eviction rule and the blocked-streams limit; `fuzz_qpack` feeds the encoder's
  decoder-stream parser too. Measured under the arena load (`profile-encoder2.txt`):
  the bytes on the wire per answer a third of before (20 MB/s at 1.18M req/s where the
  static-only head moved 52), 0.56 us of server CPU per request against 0.54 before the
  step, 0.55 with the content-type memo (`profile-altsvc.txt`, 1.17 to 1.22M req/s,
  2.97 instructions per cycle, the static-table search gone from the profile); the first version scanned the table per field and a pending-section list per
  acknowledgement and close (0.64 us, the scans 8 % of the profile), so every field now
  remembers its entry and a section's references live in the stream that sent it, and
  nothing in the encoder scans per answer; the last of those scans, found in the profile
  after the arena run (`content-type`'s row of the static table searched per answer, the
  name by binary search and the value through the 99 rows, 3 % of the cycles), is
  remembered per value change as well. The h3 rows of the A/B on loopback, three rounds
  each (`ab-20260925-084739.md` before that last memo, `ab-20260925-085625.md` with it,
  base v0.1.0-alpha.22): 1.05 / 1.04 / 1.02 / 1.02 then 1.00 / 0.99 / 0.99 / 0.98 of
  the tag at one, ten and sixty-four streams and for the 100 KB file, so the dynamic
  head costs the server nothing per request and the client a third of the bytes; h1
  and h2 within noise throughout. The step is for the client and the path: an answer's
  head is a dozen bytes instead of fifty, which the arena's load generator decodes as
  index bytes. One worker on this box (`h3-20260925-085922.md`): 1.20M req/s at
  sixty-four streams (0.65 us), the 100 KB file 85.5k at 11.6 us, the 10 MB stream
  1.38 ms per response (nginx 1.95; 1.44 at the stability step); in the arena's harness
  `baseline-h3` 3.89 to 3.90M req/s at 2.1 cores, load-bound as before, and `static-h3`
  597 to 603k at 8.5 cores, within noise of the days before (610 to 622k).
- **`alt-svc`** (design 7.4): every HTTP/1 and HTTP/2 answer of a TLS listener that also
  speaks h3 carries `alt-svc: h3=":port"; ma=86400`, so browsers switch to HTTP/3 on
  their next connection; `http3 = { alt_svc = false }` removes it. Prebuilt per listener
  and kept off the hot paths: over HTTP/1 the line is a third buffer of the writer's
  fast path (the entry's block borrowed up to its last line, the line and the blank line
  in the tail), not an extra field that would send the answer down the general path;
  over HTTP/2 it is one index byte after the first answer of a connection through the
  HPACK encoder's memo (`hpack::Encoder::alt_svc`, a literal with a new name once, since
  the static table has no `alt-svc`), like `server` and `date`. The first version added
  it as an extra field at respond time and cost the ten-stream HTTP/2 row 9 % and the
  arena's `baseline-h2` 3 % (`ab-20260925-081753.md`); with the fast paths
  (`ab-20260925-084021.md`, base v0.1.0-alpha.22) the HTTP/1 rows are 1.00 to 1.03 and
  the HTTP/2 rows 0.96 to 1.00, the ten-stream row 1.00, so the field is free; in the
  arena's harness the same hour, `static-tls` 603k req/s against the tag's 606k and
  `baseline-h2` 11.86 to 11.99M against the tag's 12.29 to 12.42M as h2load counts
  them (load-bound, the server at 440 to 490 % either way): the field is one more
  index byte for the server and one more field for the load generator to decode per
  answer, which is where that row's 3 % goes; the arena's nginx entry sends the same
  `Alt-Svc` on its h2 and h3 port, so the entry keeps it.
- **The receive buffer on the h3 startup line**: the QUIC sockets ask for 4 MB receive
  and send buffers and Linux grants at most `net.core.rmem_max` / `wmem_max`, 208 KB on
  an untuned host; 256 connections opening at once on loopback then lose Initials to the
  full socket and their handshakes complete after the clients' probe timeouts, one to
  three seconds later (the 256-connection row of `h3-20260925-085922.md`, 326k req/s
  where the run before did 915k, its connect times p95 3.03 s, no failed request). The
  startup line and the error log now say what was granted and which sysctl to raise
  when it is less than asked; `docs/configuration.md` 17 has the command.
- **GOAWAY on reload** (design 6.9): an h3 listener that a reload removes, or whose site
  drops h3, tells its HTTP/3 connections GOAWAY and closes them with H3_NO_ERROR on their
  workers' loops, then closes its UDP sockets; a TLS listener that gains h3 in a reload
  opens its endpoints. The attack suite's `reload` row drives both directions with
  SIGHUP and an open connection.
- **`fuzz_quic_conn`**, the connection-level fuzzer of the design's 9.2: a fuzz-build hook
  puts a connection in the established state with application keys from one fixed
  secret, the harness seals the fuzzer's plaintext frame payloads with the same keys and
  steps a clock of its own through the timers, so streams, credit, acknowledgements,
  losses, probes, connection ids, key phases and the close meet arbitrary frames with
  real packet protection (`build-fuzz-quic`, a fuzz build with `-DAGENSIO_TLS=ON`). Its
  first two minutes found an ACK frame whose delay field overflowed the clock's
  arithmetic on its way to a duration; the delay is bounded before it becomes one.

- **Grav preset after Grav's user-folder-exposure guidance**
  (learn.getgrav.org/2/security/user-folder-exposure, the rules of its `nginx.conf` and
  `.htaccess`): `user/config/` and `user/env/` are never answered whatever the ending
  (they were refused by ending before), `user/accounts/` answers avatar images alone and
  `user/data/` public media, documents, fonts, css and js alone (svg out, a stored-XSS
  vector) through a new location option, `allow_suffixes`, the inverse of `deny_suffixes`
  (the endings served, everything else 404, directories and bare names included; a row of
  the reference, section 6); `images/` and `assets/` never serve scripts and a missing
  derivative reaches the front controller; `webserver-configs/` is refused whole; the
  system, vendor and user lists gain `.json` and the html spellings; the root's other
  markdown files (CONTRIBUTING, CODE_OF_CONDUCT, SECURITY) are 404; `.php2` joins the
  PHP spellings every preset refuses. Seventeen fixture files and seven checks in the
  integration suite; the presets catalogue and `site NAME` report `serves_only`.

## 0.1.0-alpha.22 (2026-09-25)

- **HTTP/3 over our own QUIC transport, the first slice** (phase I, `docs/design-http3.md`,
  accepted 2026-09-24): `src/quic/` (packets, frames, transport parameters, the keys and
  the AEAD over OpenSSL 3.5's QUIC TLS API and EVP, RFC 9002 loss detection and NewReno,
  streams with flow control, the packetiser that fills a worker-wide send batch, idle and
  close) and `src/http3/` (QPACK over the static table, the frames, the control and QPACK
  streams, request streams turned into `Stream`s through the same request assembler,
  dispatcher and pool as HTTP/2, answers as HEADERS and DATA frames with memory and file
  bodies, request bodies as the pull source with the bytes waiting in the QUIC stream's
  buffer until the handler takes them). `"h3"` in `protocols` opens QUIC on every TLS
  listener's port over UDP, on worker 0 in this slice; the UDP endpoint reads with
  `recvmmsg` after `async_wait` with GRO on and sends the wake-up's answers of every
  connection with one `sendmmsg`, consecutive datagrams to a peer folded into GSO
  messages. Measured first (`bench/udp/run.sh`, `bench/results/udp-20260924-140715.md`):
  the textbook one-datagram-per-completion Asio loop costs 1.45 to 1.60 us per datagram,
  batching the syscalls a tenth less, GRO in and GSO out 0.55 to 0.64 us, and Asio's own
  receive cannot see the GRO segment size, which decides the loop. Under the arena's
  `baseline-h3` load (the arena's own h2load over QUIC, 64 connections with 64 streams
  each, `bench/httparena/profile-h3.sh`): 1.22 to 1.25M req/s on one worker at 0.61 us of
  server CPU per request, about 3,100 cycles at 3.19 instructions per cycle, twenty-one
  answers per datagram, the kernel 4.2 % of the cycles and libcrypto 3.5 %; the devbox's
  nginx 1.26 with its http_v3 module does 402 to 433k req/s at 2.32 us on the same load
  serving a two-byte file with one worker. In the arena's own harness (`local.sh`, twelve
  workers pinned, one of them serving QUIC in this slice): `baseline-h3` 1.77 to 1.81M
  req/s and `static-h3` 98 to 108k on that one core, no failed request; the board's nginx
  entry does 4.85M and 361k on 31 and 50 cores. Three servers with one worker each on
  this box (`bench/h3/run.sh`, `h3-20260924-162836.md`): the 1 KB file at 64 connections
  and 64 streams agensio 0.90 us and 1.03M req/s, nginx 3.27 us and 305k, Caddy 26.6 us
  and 38k; at ten streams 1.05 / 2.70 / 26.8 us; the 100 KB file at ten streams 24.8 /
  31.0 / 121 us; the 10 MB stream is nginx's row (1.95 ms against our 2.72 ms per
  response: the file's 64 KB windows are read and copied per packet). `ab.sh
  v0.1.0-alpha.21 -2 -3` (`ab-20260924-162251.md`): every h1 and h2 row 0.92 to 1.01,
  the h3 rows 4.4 us at one stream per connection, 1.05 at ten, 0.88 at sixty-four,
  24.7 for the 100 KB file at ten. Open: two of 4.5 million requests stalled at 256
  connections with ten streams (the client saw a few of its own packets lost; the
  next step's loss injection on the receive side targets it). The profile's top item is the Huffman decoding of the
  request's literals (23 %): with the dynamic table at capacity 0 a client sends `:path`,
  `:authority` and `user-agent` as Huffman literals on every request where HPACK indexed
  them after the first, which is the QPACK step of the design's I3. Tests: the RFC 9001
  appendix A vectors (the client Initial opened, the server Initial and the ChaCha20
  packet sealed byte for byte), varints, ranges, frames, transport parameters, the
  deadline heap, the recovery's loss and RTT arithmetic, QPACK's static encoding and
  decoding; in the integration suite a curl over HTTP/3 through every static answer
  (bodies, the streamed 10 MB file, HEAD, 404, 405 with a body, 301, 304, 206, the
  pre-compressed twin, one connection for several requests, the access log's
  `HTTP/3.0`) when the binary and curl have it; the sanitizer suite, run over the same
  rows and under the QUIC load, caught the endpoint freeing a connection while it still
  walked that connection's own id list (every idle timeout; the release build survived
  it silently), fixed before the slice was measured again. Two more findings from the
  first rows: a response packet carried no acknowledgement of the request it answered
  (the delayed-ACK rule waited for a second packet or 25 ms), so at one stream per
  connection the client's stream could not close until an ACK-only packet followed and
  the row ran at 2,575 req/s over 64 connections; the pending acknowledgement now rides
  on any packet sent for another reason (RFC 9000 13.2.1) and the row does 212k, with
  the 100 KB row's failures partly with it. And the arena's harness resolves `localhost`
  to `::1`, which QUIC cannot fall back from the way TCP does: the endpoint on a `[::]`
  address is dual-stack like the acceptors, and the entry's TLS site listens there. Two
  more came from the 100 KB row at ten streams, whose bursts overflow the client's
  receive buffer, the loss loopback does have: a response whose last packet is lost is
  recovered only by a probe, and our probe was a one-byte PING behind a one-byte packet
  number, shorter than header protection can sample (RFC 9001 5.4.2), so the client
  could not unprotect it and never acknowledged; such packets are padded to the minimum
  now, and the tracing build (`-DAGENSIO_QUIC_TRACE=ON`) can lose every Nth datagram or
  one final packet on purpose (`AGENSIO_QUIC_DROP=N`, `AGENSIO_QUIC_DROP_TAIL=1`) to
  exercise loss detection, probes and retransmission on loopback; and a send batch that
  filled during a wake-up left the connections behind it without a send until their idle
  timeout, so it goes out when full and fills again. The arena entry subscribes
  `baseline-h3` and `static-h3`. Not in this slice (I1b to I4 of the design): streamed upstream bodies
  over h3, Retry, stateless reset, key update, path validation, path MTU discovery,
  0-RTT, ECN, `alt-svc`, the per-worker sockets.
- **HTTP/3 on every worker**: with `reuse_port` each worker opens its own UDP socket on the
  h3 listener's port and a classic BPF program attached to the group (six instructions,
  no privilege, `SO_ATTACH_REUSEPORT_CBPF`) delivers a packet to the socket whose index
  the first byte of its destination connection id names, which is the worker that issued
  the id; a client-chosen id falls back to the kernel's 4-tuple hash, so a connection
  never changes worker (design 6.1). Where the attach is refused the hash routes alone. The per-worker buffers are 1 MB in
  and 1 MB out. On the arena's rows in its harness (twelve workers pinned, twelve load
  threads): `baseline-h3` 3.86 to 3.89M req/s at 2.6 cores of server CPU (the load
  generator is the limit; one worker did 1.8M at one core), `static-h3` 541k at 8.3
  cores (one worker 98 to 108k), no failed request, 83 and 92 MiB resident; the board's
  nginx entry does 4.85M and 361k on 31 and 50 cores.
- **QPACK's dynamic table on the decoding side** (RFC 9204 sections 3, 4.3 to 4.5; design
  7.2's first step): the connection advertises a 4 KB table and 16 blocked streams, the
  client's encoder stream (set capacity, insert with a name reference, insert with a
  literal name, duplicate) fills the table, a field section's prefix names the insert
  count it needs and its base, a section ahead of the table waits and is decoded when
  the inserts arrive (a seventeenth waiting stream is QPACK_DECOMPRESSION_FAILED), and
  the decoder stream carries the section acknowledgements, stream cancellations and
  insert count increments the encoder needs. Dynamic entries keep the rules-once mark
  of HTTP/2's HPACK, so a request's field rules run once per entry. Trailers are
  decoded and discarded to keep the acknowledgements in step. The control streams' send
  buffers drop what is acknowledged in order, so a long connection's decoder stream
  stays small. Unit tests: RFC 9204 appendix B (B.1 to B.5) on the encoder stream, the
  blocked section, the decoder stream's bytes, the eviction, and the errors. Measured
  under the arena load (`profile-qpack.txt`): the Huffman share of the profile 21 % to
  7.9 %, 0.61 to 0.56 us of server CPU per request, a request's field section seven
  bytes with two dynamic references; A/B `ab-20260924-172435.md` h1 and h2 flat.
- **A stream whose id arrives after a higher one is a new stream, not a closed one**: the
  transport took a lower id for a stream it had already closed, so a client that opened
  its unidirectional streams 2, 10 and then 6 lost its QPACK encoder stream, and a
  request stream whose first packet landed after a later stream's did too (the likely
  cause of the two stalled requests in 4.5 million at 256 connections). Closed ids are
  now recorded (the last 64, as HTTP/2 keeps them) and only those are refused.
- **Larger datagrams and fewer packets per HTTP/3 request** (design 6.7): one path MTU
  probe after the handshake (a PING padded to 1,472 bytes over IPv4, 1,452 over IPv6, or
  what the client announces; acknowledged, every datagram is that size; lost, 1,200 stays;
  probed again when the client's address changes), so a 1 KB answer with its head is one
  datagram and the 10 MB stream costs 2.37 ms per response instead of 2.72 (nginx 1.95;
  `h3-20260924-174006.md`). And MAX_STREAMS no longer goes out in a datagram of its own
  after every closed stream: the trace of a client with one request at a time showed a
  31-byte packet per request that the client then acknowledged; the credit rides on the
  next packet sent for another reason and goes alone only when the peer's room is under
  a quarter of the limit. Measured with the transport step below in one A/B
  (`ab-20260924-181813.md`, every h1 row 0.99 to 1.01, the h2 rows 0.94 to 0.98): the h3
  rows against the first slice's 4.4 / 1.05 / 0.88 / 24.7 us are now 3.8 us at one
  stream per connection, 0.90 at ten, 0.80 at sixty-four and 21.7 to 22.0 for the 100 KB
  file at ten; one worker on this box (`h3-20260924-182224.md`): 1 KB at 64 connections
  and 64 streams 0.78 us and 1.08M req/s, at ten streams 0.90 us and 664k, at 256
  connections with ten 0.97 us and 546k (the row that stalled two requests in the first
  slice: none now), the 100 KB file 21.8 us and 46.0k (nginx 31.0 and 32.1k), the 10 MB
  stream 2.40 ms and 417 req/s (nginx 1.95 and 512), the one-stream row 3.78 us at 54.3k
  where nginx costs 7.57 us for 57.4k (the row is bound by h2load's per-request work,
  about a millisecond per connection in this shape: agensio, nginx and the previous
  build all sit at 52 to 57k; the same client with one connection does a request every
  148 us); in the arena's harness with twelve workers `baseline-h3` 3.85 to 3.88M req/s
  at 2.35 cores and `static-h3` 618 to 622k at 8.9 cores (541k before the datagram work).
- **The transport rows of HTTP/3's I1b** (RFC 9000 5.1, 8.1, 9, 10.3; RFC 9001 6; design
  6.3, 6.4, 6.9): address validation with Retry (`http3 = { retry = "auto" | "always" |
  "never" }`, the one HTTP/3 key: tokens sealed under a per-hour key from a per-process
  secret, bound to the client's address, the original connection id and the time, valid
  ten seconds; an Initial whose token does not open is answered with an INVALID_TOKEN
  close under the client's Initial keys and forgotten; "auto" sends Retry once a worker
  has 512 handshakes in progress and drops Initials at 1,024, "always" is for a host
  under a handshake flood, "never" for a benchmark); stateless resets for a packet whose
  id nobody knows (a server that restarted), the token of every id HMAC of the id under
  the process secret so nothing is stored and any worker can answer, the reset one byte
  shorter than the packet, none under 22 bytes, at most 1,000 per second per worker; four
  connection ids issued to the peer at the handshake and one more for each it retires
  (at most 64 per connection), the peer's own ids bounded at four; key update both ways
  (the peer's followed before its packet is acknowledged, ours at the AEAD's
  confidentiality limit; the previous keys kept three PTOs for reordered packets; a
  second update before the first is acknowledged is KEY_UPDATE_ERROR; the
  header-protection key never changes across updates, RFC 9001 6.1, which the first
  version got wrong); a client whose address changes (a NAT rebinding) keeps its
  connection: its new path is validated with PATH_CHALLENGE, sending to it is capped at
  three times what arrived on it until PATH_RESPONSE (the cap is a byte allowance, so
  the challenge goes out after a small packet), the congestion state starts over unless
  only the port changed, and the previous address is used again when the validation
  fails; the reset budget (RESET_STREAM and STOP_SENDING past `http2.max_concurrent_streams`
  in one second close with H3_EXCESSIVE_LOAD) and the glitch budget (100 credit updates
  that raise nothing). `tests/h3-attacks.py` on aioquic (now in the devbox image) drives
  thirteen rows of the design's threat table by hand over its own sockets: handshake,
  retry in both modes, invalid-token, key-update, key-update-twice, rebind, cid-retire,
  stateless-reset, forged-flood, rapid-reset, stream-flood, control-stream,
  handshake-flood (1,500 Initials in 1.1 s); the integration suite runs it where aioquic
  is installed and adds a curl through a `retry = "always"` instance. Unit tests for the
  tokens, the Retry packet and its tag, the stateless reset and the INVALID_TOKEN close.
  Two bugs the suite found before the step was measured: the header-protection key was
  re-derived at a key update (every packet after it failed to open), and the
  amplification check counted whole datagrams, so a client that had just changed its
  address could not be sent the PATH_CHALLENGE that validates it. No cost on the request
  path: the profile after the step 1.14 to 1.15M req/s on one worker at 0.58 us per
  request (`profile-transport.txt`).
- **HTTP/3 stability and the transport's remaining per-request costs** (2026-09-25).
  The path MTU search goes on upward (RFC 8899): after 1,472 bytes each acknowledged
  probe doubles the next, up to what the client announces, so loopback and jumbo-frame
  paths carry tens of KB per datagram (the trace: 1,472, 2,944, 5,888, 11,776, 23,552,
  47,104 bytes in five round trips) and a 1,500-byte path stops at 1,472; probes are
  outside the congestion window (their loss is the path's answer, not congestion) and
  a datagram larger than the window's room shrinks to it instead of waiting. Closed
  streams are a bitmap over the 64 indices below the highest opened (a bit test per new
  stream instead of a scan of 64 ids, 7.4 % of the profile). At shutdown every HTTP/3
  connection gets a GOAWAY naming the first request id it will not process and a close
  with H3_NO_ERROR, in the datagrams that go out before the workers' loops stop, so a
  client retries at once instead of waiting for its idle timeout. Stability tests: the
  loss proxy `tests/quic-lossy.py` (3 % of the datagrams dropped and 5 % delayed up to
  3 ms, both ways) sits between curl and the server in the integration suite, and the
  1 KB page and the 10 MB file arrive through it; six attack rows written as raw frames
  into aioquic's packets (101 credit updates that raise nothing, an acknowledgement of a
  packet never sent, a fifth connection id, retiring an unissued and the in-use id, data
  beyond a stream's window) and the shutdown row; the fuzzers `fuzz_quic_packet`,
  `fuzz_transport_params` and `fuzz_qpack` (20.6 M, 121 M and 11.7 M runs in two minutes
  each, no findings). Measured (`ab-20260925-013754.md` against the previous commit, h1
  and h2 rows 0.97 to 1.05): the h3 rows on loopback, where the search reaches 47 KB
  datagrams, 1.00 at one stream per connection, 0.83 at ten, 0.76 at sixty-four and 0.53
  for the 100 KB file at ten (21.2 to 11.2 us); one worker (`h3-20260925-014251.md`) 1.23M
  req/s at sixty-four streams (0.62 us), 1.09M at 256 connections with ten (0.87 us), the
  100 KB file 85k req/s at 11.7 us (nginx 32k at 31.0), and the 10 MB stream 1.44 ms per
  response against nginx's 1.95, the last row nginx held (2.72 ms in the first slice;
  the profile's datagrams there average 42 KB now); under the arena load 0.54 us per
  request (0.58 before, the closed-stream scan gone); the arena's rows, on a 1,500-byte
  path, within noise (`baseline-h3` 3.70 to 3.72M at 2.0 cores, `static-h3` 610 to
  614k). The tree as committed, with the interop fixes below, measured again
  (`ab-20260925-031102.md`, `h3-20260925-031559.md`, the interop matrix running on the
  same box): the h3 rows 1.00 / 0.84 / 0.80 / 0.55 of the previous commit, h1 and h2
  within noise. A finding for the next step: h2load, the arena's client, announces a 4 KB QPACK
  table (curl announces none), so the encoder-side dynamic head will shorten every answer
  it sends there. And the QUIC
  interop runner (`bench/quic-interop/`, design 9.2): agensio as a server implementation
  in a Debian trixie image with the runner's endpoint setup, the runner in its own image
  with tshark, `run.sh` driving both through the host's docker; the runner's `hq-interop`
  protocol (a `GET /path` line per stream, the file raw) and the `SSLKEYLOGFILE` export
  exist only in `-DAGENSIO_INTEROP=ON` builds, and `zerortt`, `ecn`, `v2` and
  `connectionmigration` exit 127 as unsupported. Its first finding, before any test
  case ran: the simulator's readiness probe is a packet with an unknown QUIC version
  expecting Version Negotiation, and the header parser read the rest of such a packet
  by version 1's rules (RFC 8999 5.1 makes everything after the ids opaque), so no
  Version Negotiation was ever sent; fixed, with a unit test. The harness runs inside a
  Docker-in-Docker daemon (the runner's compose file needs Engine 28.1 and the host has
  26.1) with the bridge netfilter hook off, because the daemon's iptables rules dropped
  every bridged frame whose IP destination lay on the other bridge, which is what the
  client's packets to the server through the simulator are. Two bugs the first matrix
  found: a request retransmitted after loss was refused as a stale stream when the
  client had opened more than 64 streams since (the closed-stream window is 1,024
  indices now; 24 of 2,000 requests of the multiplexing case), and the `[::]` socket set
  don't-fragment for IPv4 peers only, so on the simulator's 1,500-byte link the MTU
  probes went through as fragments, the search reached 11 KB datagrams, and a transfer
  crawled under fragment loss (DF is set for both families now, and a probe beyond the
  path fails at once). And a third from the multi-connection cases under 30 % loss and
  corruption: a probe timeout sent a bare PING, so a lost Handshake flight or a lost
  response was repaired only after the probe's acknowledgement declared the old packets
  lost, two or three round trips instead of one; a probe now carries the oldest
  unacknowledged data of its space again (RFC 9002 6.2.4), the original packet staying in
  the ring for its own acknowledgement. The matrix after the three fixes
  (`bench/results/interop-20260925-061102.md`): every supported case passes with quic-go
  (18 of 18) and ngtcp2 (17, plus one run of handshakeloss where the client restarted an
  attempt under the 30 % burst loss and the runner counted 51 handshakes for 50);
  `zerortt`, `ecn`, `v2` and `connectionmigration` exit 127 by choice. The results table
  is in the security page.
- **The code HTTP/2 and HTTP/3 share lifted into `src/http/`** first, as a pure refactor
  (design-http3 section 4): the Huffman code, the prefixed integers and the dynamic
  table with its rules-once marks (`field_codec`), the request assembler (`request_assembly`),
  the stream table and pool (`stream_pool`); HTTP/2 rebuilt on them, `ab.sh v0.1.0-alpha.21 -2`
  0.96 to 1.04 on every row (`ab-20260924-142634.md`), the suites unchanged. The table
  generator also emits QPACK's 99-entry static table.
- **The RFCs the protocol layers implement are in `docs/rfc/`** as text (HTTP semantics
  and HTTP/1.1, HTTP/2 and HPACK, QUIC with its TLS and recovery documents, HTTP/3 and
  QPACK, CUBIC, DPLPMTUD), with an index mapping each to the code; CLAUDE.md asks for the
  section to be read and cited.
- Benchmarks: `bench/h3/run.sh` (the HTTP/3 rows against nginx and Caddy with an h2load
  built with QUIC; `bench/docker/Dockerfile.devbox` now carries the devbox recipe with
  one under `/opt/nghttp2`), `bench/ab.sh -3` (four h3 rows; a base without h3 gets
  none), `bench/httparena/profile-h3.sh`, `bench/udp/`.

## 0.1.0-alpha.21 (2026-09-24)

- **HTTP/2 per-request cost, in three measured steps** on the arena's HTTP/2 baseline
  row (one worker, `h2load -c 64 -m 100`; the same load against h2o's arena entry on one
  thread in the same container does 2.60M req/s over TLS, `bench/httparena/profile-h2o.sh`):
  the clock read once per socket event instead of four times per request, released
  streams pooled up to the concurrency limit (a client with a hundred streams in flight
  constructed and freed a stream object with its two hundred header views per request),
  stream lookups and the writer's in-flight bookkeeping without scans, and the benchmark
  handler's continuation in the `std::function`'s own storage, 1.42M to 2.44M req/s over
  TLS; the Huffman decoder writing through a pointer, static-table fields viewed in place,
  one static-name search per encoded field and a remembered content-type index, the
  router's single-site shortcut, the normaliser's plain-target shortcut and the handler's
  HTTP/2 tail prebuilt, to 3.04M over TLS and 3.37M on h2c; and the write cycle built into
  one buffer, large payloads on plain sockets as scatter entries between its runs, so the
  answers of one read leave in one send instead of two, to 3.30M over TLS and 3.97M on h2c,
  1.27 times h2o on one core; and, once the pinned rows showed the pool's memory
  (647 MiB resident for 512 connections with a hundred streams each, h2o 65), requests
  decoded into the connection's scratch with each stream keeping an exact-size copy
  instead of a 16 KB reservation, to 3.48M and 441 MiB; and emit at respond: inside a
  read's frame loop a complete small answer goes into the cycle's buffer at once and its
  stream is closed and pooled, so a read of a hundred requests reuses one or two hot
  stream objects instead of holding a hundred cold ones until the write completes.
  Twelve workers pinned to six cores with their siblings: 2030 cycles per request
  against h2o's 3100 (instructions per cycle 3.20 against 2.74, cache misses per request
  6 against 24, 68 MiB resident against the pool's 441), one worker 3.60M req/s. On this
  box the pinned row is 12.0M against h2o's 12.4-12.9M with half of agensio's CPU idle:
  the twelve-thread load generator is the limit there. Then the request side: the field
  rules run once per dynamic-table entry (the decoder reports each field's origin and
  the entry carries a mark; a static pair skips the syntax rules; a literal is checked
  every time), the fields of interest are found by length first, and the benchmark
  handler builds only the head of the protocol in use: one worker 3.99M req/s, 1315
  cycles per request against h2o's 2054, twelve workers 1905 against 3210. In the
  arena's own harness, all rows: level with h2o on baseline-h2 (12.39M against 12.29M at
  776 % against 1001 % CPU) and on the HTTP/1 rows, ahead on json-tls (1.40) and
  static-h2 (3.22), 4.2 to 4.4 times nginx on the HTTP/2 baselines. The router and
  normaliser shortcuts and the continuation reach HTTP/1 as well. Details and the
  profiles in `docs/design-http2.md` 6.2.1, 6.4, 6.6 and 7.3 and
  `bench/results/httparena-lite-20260924-0147.md`.
- **Fixed: a control-socket request with a body leaked its connection.** The body-reading
  step of the control handler (mutations, uploads) captured itself strongly, a reference
  cycle that kept the connection, its receive buffer and the request's state alive for
  the life of the process, once per such request; LeakSanitizer found it at the end of
  the integration suite (84 connections, 15 MB). The step refers to itself weakly now and
  the read in flight keeps the chain alive.
- **Fixed: a build without OpenSSL did not compile** since `protocols` per site (the
  listener's ALPN field exists only with TLS).
- **HTTP/2 response heads through a dynamic table** (design 6.2.1): `server`, `date`,
  `content-type`, `vary`, `content-encoding` and whatever a handler's or an upstream's
  block repeats are inserted once per connection (date once per second) and cost one byte
  after; `content-length`, the validators and everything that changes per answer stay
  literal, `set-cookie` and the authorization fields are never indexed. A cache entry's
  block is now the tail of literals, still built once at insert. The table is at most 1 KB
  and never above the peer's SETTINGS_HEADER_TABLE_SIZE, shrinks with it and stops at
  zero; encoder and decoder share one table implementation, so both sides evict by the
  same code, and unit tests, a fuzz target and nghttp2's decoder hold them in step. The
  arena's HTTP/2 baseline answer went from a 48-byte HEADERS block to 8, and the row
  from 7.55M to 8.46M req/s pinned (h2o 11.06M, load-bound; agensio was at 3.26M before
  the write batching). With it, TLS
  write cycles that are coalesced before `SSL_write` are capped at 64 KB of body: once
  the write batching filled every cycle, 256 KB cycles copied and encrypted outside the
  cache and cost the arena's static-h2 row 9 %.
- **HTTP/2 answers of one read go out in one write.** The writer is held while the
  connection runs the frames of a read, so the answers to a hundred HEADERS frames leave
  in one cycle instead of one every two or three streams (the write completed inline and
  the next cycle started with whatever was ready), and a cycle of many small pieces is
  copied into one buffer, since asio hands the kernel at most 64 scatter entries per
  call. Measured on the arena's HTTP/2 baseline, one worker: sends per answer from one in
  2.4 to one in 57, 583k to 1.50M req/s on h2c and 516k to 1.61M over TLS; pinned to six
  cores plus siblings, 3.26M to 7.55M req/s at less CPU. The A/B against alpha.20 puts the
  ten-stream rows at 0.35 of the base CPU per request and every single-stream and HTTP/1
  row inside the noise band.
- **Fixed: a HEADERS frame on a stream the client had already ended was reset with
  PROTOCOL_ERROR** where RFC 9113 5.1 requires STREAM_CLOSED. Rarely visible before, since
  the answer had usually gone out inline and the frame then met a closed stream; with the
  answers of a read written after its frames, h2spec 5.1/6 caught it under the sanitizer
  build.
- **`protocols` per site**: a `[[site]]` may name its own list (`["h1"]` keeps a TLS port at
  HTTP/1.1 while another offers h2; `["h2c", "h1"]` accepts the preface on one plain
  listener), inherited from `[server]` otherwise; sites sharing an address must agree.
  `status` names each listener's own protocols.
- **`workers = 0` counts the CPUs the process may run on** (the affinity mask: a
  container's cpuset, a `taskset`) instead of every hardware thread, like nginx's
  `worker_processes auto`.
- **HttpArena benchmark handler** behind `-DAGENSIO_HTTPARENA=ON`: `handler = "httparena"`
  answers the arena's `/baseline11`, `/baseline2`, `/json/{count}?m=` and `/pipeline`
  in-process from a dataset given as `httparena = { dataset }`, as the arena's rules
  require of an infrastructure entry; a release build refuses the handler. The entry in
  `bench/httparena/` is one process with the four listeners and subscribes to every
  profile the infrastructure tier scores except the two HTTP/3 rows. The arena's validator
  passes 70 checks; in its harness on the bench box agensio is ahead of nginx on eight of
  the nine rows and level on the ninth, and ahead of or level with h2o on five of its six,
  behind only on the HTTP/2 baseline (`bench/results/httparena-lite-20260924-0147.md`).
- **Pre-compressed files are served**: a `name.br` or `name.gz` beside a cached file goes
  out with `Content-Encoding` and `Vary: Accept-Encoding` to a client whose
  `Accept-Encoding` takes it (q-values, `q=0` and `*` honoured, `br` on a tie), the file
  itself to any other; the twin is cached beside the file with its own ETag and
  Last-Modified, counts in the byte budget with it, is revalidated with it, and an older
  twin than its file is ignored as a build not redone. Conditional and Range requests work
  per representation on both protocols. `[cache] precompressed = false` turns it off.
  Motivated by HttpArena's static rows, where every request asks for `br` and nginx served
  the twins at a quarter of our bytes per response: in the arena's own harness on the
  bench box (`bench/results/httparena-lite-20260924-0147.md`, rerun section) static-h2 went
  from 304k to 955k req/s against nginx's 846k and static-tls from 269k to 687k against
  635k; the A/B against alpha.20 is flat on every HTTP/1 and HTTP/2 row.
- **Fixed: a heap use-after-free in the upstream streaming path** (FastCGI and proxy
  responses streamed to the client, `buffering = false` or past the temp-file cap): when a
  body ended short, the writer's inline completion closed the connection, dropped the body
  source and with it the last reference to the exchange while its own `pull` was still on
  the stack. Found by the sanitizer build under the integration suite; the exchange now
  holds itself alive for the length of the call.
- **HttpArena entry** (`bench/httparena/`): agensio packaged for the public HttpArena board
  (Dockerfile from the tag, the arena's port layout, `meta.json` subscribing to the pipelined,
  static-tls and static-h2 profiles) and a driver that runs the arena's own validator and lite
  benchmark on a developer machine inside Docker-in-Docker. First run against the nginx and
  h2o entries in `bench/results/httparena-lite-20260924-0147.md`: the validator passes, the
  pipelined row is level with nginx, and the static rows show the next step, pre-compressed
  `.br`/`.gz` siblings, since the arena asks for `br` on every static request.

## 0.1.0-alpha.20 (2026-09-24)

- **Fixed: a Grav site on the borrowed drupal preset served its backup** (2026-09-23,
  a live host): `logs/grav.log` was served and named the `backup/*.zip` next to it, which
  was served too, with the admin account and the signing salt inside. Three changes.
  **`app = "grav"`**, a preset from Grav's own nginx recipe: only `index.php` runs;
  `logs/`, `backup/`, `cache/`, `bin/`, `tests/` and `tmp/` are never answered, whatever
  they hold (the preset table gained whole-directory refusals, `never_served_directories`
  in the catalogue); `system/` and `vendor/` serve assets only; `user/` serves images,
  css, js and uploads while pages, accounts and configuration stay private (per-shield
  endings); the version fingerprints and composer files are 404; `site-install` fetches
  the `grav-admin` release; `site-create` detects Grav from `bin/grav` and
  `system/defines.php`. **`.log` and `.sql` are refused on every PHP preset's root and
  shields**, like `.inc` and editor backups (WordPress's `wp-content/debug.log` too).
  **`health` reports `preset_mismatch`**, a site whose files belong to another
  application than its `app` says, with the marker found and the `app` to set (the
  borrowed preset's refusals do not fit), and `site-create` warns the same way on a
  directory that already holds files; and **`archives_in_root`**, backup archives and
  database dumps under a served tree, the directories a preset never answers excepted.
  The integration suite serves a Grav fixture through both presets.
- **Fixed: `php_pool_resident` stayed silent for a pool left `static` on disk** after
  the configuration changed to `ondemand` (the same host: two such pools held 16 PHP
  processes and 681 MB). The finding now judges the pool file php-fpm runs and names a
  stale one as a warning with `agensio pools` plus a php-fpm reload as the fix; the root
  suite makes a file stale behind the configuration's back and checks both.
- HTTP/2 across a reload: a connection whose listener left the configuration, or that
  reached `max_requests_per_connection`, serves the stream in flight and only then sends
  its GOAWAY and closes, so no client has to read an answer behind a GOAWAY; a stream
  opened while the connection is leaving is refused (`REFUSED_STREAM`) so the client
  retries on a new connection. `tests/reload.sh` now drives both cases over HTTP/2 with an
  h2-library client: a connection that picks up the new generation at its next stream
  without a GOAWAY, and one on a removed listener that is served once more, told GOAWAY
  and closed.
- HTTP/2 performance pass (phase G, step G2): the four-worker comparison
  (`bench/results/h2-20260923-201044.md`: 1.59M req/s on h2c and 1.28M over TLS at ten
  streams per connection against nginx's 665k and 559k, every row ahead). **Idle
  connections cost less**, on both protocols: two seconds after its last request a
  connection sheds its buffers (the pooled HTTP/2 streams, the writer's buffers, and the
  receive buffer, whose pending read is cancelled and replaced by a readiness wait; the
  buffer comes back with the next bytes), the HPACK ring is made on a client's first
  insertion, at most four released streams stay pooled, and each worker trims the heap
  once a second after sheds or closes, since glibc keeps freed chunks mapped. Measured
  with 10,000 idle and 1,000 busy connections (`bench/h2/memory.sh`,
  `h2-memory-20260923-204605.md`): an idle HTTP/2 connection 19 KB (40 before; nginx 7.5,
  Caddy 35), an idle HTTP/1 connection 13 KB (25 before); busy, 90 MB against nginx's
  93 MB. The integration suite checks that a connection idle past the shed point still
  serves its next request on every protocol. Uploads through the WordPress and Drupal
  presets are exercised over HTTP/2 in the root suite.
- **Fixed: a heap read past the HTTP/2 receive buffer** after a connection error decided
  inside a frame handler (found by the sanitizer build under h2spec, which the release
  build survived by luck): the lingering close reset the buffer while the frame loop went
  on with its old position. The loop now stops the moment a close is decided. The
  integration harness keeps the server's stderr in `bench/tmp/server.err` so a sanitizer
  report is never discarded again.

## 0.1.0-alpha.19 (2026-09-23)

- **Generated pools default to `pm = "ondemand"`** with `pm.process_idle_timeout = 60s`
  (live host: every site with its own account kept 8 PHP processes resident around the
  clock, 150 to 200 MB per idle site). A child starts on the first request and exits after
  a quiet minute; `static` and `dynamic` stay available per site (`settings: {pm:
  "static"}`), and `static` is what a PHP benchmark should use. Existing pool files
  differ from the configuration until `agensio pools` rewrites them; `health` says so
  (`pools_stale`).
- **Kept upstream connections are closed after `idle_timeout`** (new option of `php = {}`
  and `proxy = {}`, default 30 s, 0 = never) from the pool's existing tick, so an
  `ondemand` child is not held open by an idle server and an origin with a short
  keep-alive timeout is never met dead.
- `health` `php_pool_resident`: every `static` or `dynamic` pool with the PHP processes
  it keeps and their memory (RSS and private, read from `/proc` on Linux), with the
  setting that frees it, so an agent asked why the machine is full has the number.

- **HTTP/2** (phase G, step G0; design in `docs/design-http2.md`): RFC 9113 with HPACK
  (RFC 7541) in agensio's own protocol layer, `src/http2/`, on every TLS listener through
  ALPN and, with `"h2c"` in the new `[server] protocols` key (`["h2", "h1"]` by default,
  Caddy's names; `"http/1.1"` accepted for `"h1"`), by prior knowledge on plain listeners. Every handler serves it: static files from the cache and disk, conditional
  and range answers, FastCGI, proxy, CGI, redirects, request bodies through DATA frames
  with windows that follow the site's body limit (uploads at the consumer's pace, not
  64 KB per round trip). The encoder uses static indexes and literals only, so a cache
  entry's headers are one HPACK block built at insert and copied per response; a
  worker's server and date pair is re-encoded once per second. Limits and defences
  built in from the first line: frame size, header list and compressed block sizes from
  `max_header_size`, CONTINUATION count, a glitch budget (PING, SETTINGS, empty frames,
  window-update dribbles, PRIORITY, frames on closed streams) with a graceful GOAWAY at
  three quarters, a reset counter that counts server-provoked resets too (Rapid Reset,
  MadeYouReset), no priority tree (RFC 9218 announced), stream and connection memory
  bounded by the windows and `max_header_size`. Every GOAWAY and RST_STREAM the server
  sends is an info line in the error log. `http2 = { max_concurrent_streams = 128 }`,
  `agensio ctl status` names each listener's protocols, requests log as `HTTP/2.0`,
  PHP sees `SERVER_PROTOCOL=HTTP/2.0`. HTTP/1.1 pays nothing: the hand-over sits behind
  the TLS handshake and the parser's 505 branch. Tests: RFC 7541's vectors and error
  cases, a Huffman table generated from the RFC text, `fuzz_hpack`, h2spec against both
  listeners (146 of 146 over TLS; on h2c the one case where an invalid preface is an
  HTTP/1 400), curl and an h2-library client in the integration run (the H2h coalescing
  check is live now), `bench/h2/run.sh` and `bench/ab.sh -2` (h2load). Measured, one
  worker on the Linux box: the HTTP/1 rows unchanged; HTTP/2 1 KB at 2.3 us plain and
  3.1 to 3.4 us TLS with one stream per connection, 1.6 to 1.8 and 2.0 to 2.1 us with ten
  (below HTTP/1); nginx 3.5 to 4.7 us on the same rows, Caddy 30 us. Large bodies over
  TLS: a DATA frame is exactly one record (16,375-byte payloads) and a file's frames are
  read with one preadv into a pre-framed chunk that is written as is, so the 10 MB stream
  costs 2017 us against nginx's 2771 and 100 KB at ten streams 20.5 against 28.4.

## 0.1.0-alpha.18 (2026-09-20)

- **Fixed, wordpress preset: backups of `wp-config.php` were served** (live report:
  `wp-config.php~`, `.bak`, `.save`, `.orig` and `.txt` answered 200 with the database
  password and the salts; the exact name was 404). Every name a preset never serves is
  now refused in every backup spelling within its directory, anchored on the name rather
  than on an ending: `name.bak`, `name~`, `name.txt`, `name-old`, `stem.bak`
  (`wp-config.bak`), `.name.swp`, `#name#`, in any case, whatever `hidden_files` says;
  `ads.txt` and the `/readme`, `/license` permalinks are untouched. `agensio -t
  --explain` and the presets catalogue state the rule; the MCP `presets_list` text too.
- **Fixed, every PHP preset: one shared refusal list.** WordPress's shields lacked `.inc`
  and the `~` backup form Drupal's had (live report: `x.inc`, `x.php~` under
  `wp-content/uploads` served as source). Every preset's root and shields now refuse
  `.inc` and editor backups (`.bak`, `.orig`, `.save`, `.swp`, `.swo`, `~`), and the
  root refuses the PHP spellings the `.php` suffix location does not take (`x.PHP`,
  `x.phtml` were served as source at a drupal or wordpress root; `x.php` still runs).
  The integration suite plants one table of spellings under every preset's shields and
  roots, and the backups of `wp-config.php`, `db.php` and `settings.php` in their
  directories, and asserts each is refused without a byte leaking.

## 0.1.0-alpha.17 (2026-09-20)

- MCP instructions: rule one, stated first: whatever a tool can do is done through the
  tool over the connection; a terminal command or a file edit is offered only when no tool
  covers the change (root's main file, a hand-written site file, root work handed back
  without the helper), with the reason and what follows. `config_reference`'s `via` is
  read as which tool does it.
- **Configuration reference for agents and administrators** (F11; live: the agent could
  not say how to change `workers`): one table of every key agensio reads, with type,
  default, meaning, whether a change applies on reload or needs a restart, who changes it
  (root in the main file, a site file, `site-create`, `settings`) and the section that
  explains it; `agensio keys [--markdown]`, `agensio ctl reference`, `GET
  /v1/config/reference` (with running values and the file they come from), MCP
  `config_reference`. `docs/keys.md` is generated from it and the integration suite
  fails when the file and the binary differ; the unit test fails when the parser reads a
  key the table lacks or a row names a section that does not exist. The bridge's
  instructions tell the agent to hand root's edits back as the exact line plus the
  reload or restart command, never claiming to have made them.

## 0.1.0-alpha.16 (2026-09-20)

- **Fixed: refused endings were matched case-sensitively and a trailing dot escaped
  them**, so `x.PHP`, `x.PhP` and `x.php.` under a shielded directory (Drupal's
  `files/`, WordPress's `uploads/`) were served as source (live report; nothing
  executed). The rule now ignores case and trailing dots on every shield and root, the
  PHP spellings gained `.pht`, `.phtm`, `.php3`, `.php4`, `.php6`, and the drupal preset
  refuses `~` backups too. Unit test of the rule and integration checks that plant every
  spelling under both presets and assert not a byte leaks.
- `health` `files_unreadable` picks its remedy from the example's defect: `chgrp` for a
  wrong group, `chmod -R g+r` for a right group without group read, both when both.

## 0.1.0-alpha.15 (2026-09-20)

- **Fixed, drupal preset: a missing file below `sites/default/files/` now reaches
  `index.php`** with its query string, so Drupal generates image-style derivatives
  (`?itok=`) and rebuilds aggregated css/js on first request; an existing file still
  serves statically, and PHP-like endings below `files/` stay refused (live report: a
  deleted derivative was a 404 from the server for ever, and every newly uploaded image
  would have been). The preset table's shield gained a fallback flag; `presets` lists
  the directory under `missing_reaches_front_controller`. The regression test deletes a
  derivative and an aggregate and asserts the front controller gets the URL.
- `site-create`: the log hand-over under `done` is now verified on disk (group and
  mode) and otherwise reported under `warnings` with the command; the server no longer
  logs "cannot chown" on every reload for a log that already has the right group, nor
  when the helper is the one handing it over (live report: a claimed step next to a
  warning that it failed).
- `health` `files_unreadable` names the owner and group instead of numeric ids.

## 0.1.0-alpha.14 (2026-09-20)

- **Fixed: uploaded files were unservable on every site with a site user** (live report:
  a WordPress video answered 404, no log line, no finding). PHP creates an upload in the
  pool's `tmp/`, which was `0700 user:user`, and `move_uploaded_file()` renames it into
  the document root; rename keeps the group, and a set-gid directory stamps only files
  created in it, so every upload arrived `0640 user:user`, unreadable by the server.
  `tmp/` is now `2750 user:<server group>`, like the document root, so an upload is born
  with the server's group. `agensio pools` (and the helper's pool apply) repairs an
  existing `tmp/` when run as root. **Existing uploads need one command per site**,
  e.g. `chgrp -R agensio /var/www/example.com/wp-content/uploads` (Drupal:
  `sites/default/files`); `health` now reports them as `files_unreadable` with that
  fix until it is done, sampling the preset's upload directory first. The root suite
  uploads through the php, wordpress and drupal presets and asserts the moved file's
  group and that it is served.
- **Fixed: the first POST after a php-fpm reload on a kept connection answered 502**
  (`closed_early`; a GET was retried on a fresh connection, a POST or an upload was not).
  A kept connection idle for longer than a pool tick (250 ms) is now checked with one
  non-blocking peek before a request is written to it, and a dead one is dropped for a
  fresh connection; a connection reused at once is not peeked, so the benchmark path pays
  nothing. Found by the new
  upload test in the root suite: the first upload after the pool was rewritten and
  php-fpm restarted failed exactly as the live report's upload did minutes after a
  settings change had reloaded php-fpm.
- `health`: `php_tmp_missing` / `php_tmp_not_owned` when a generated pool's private
  `tmp` or `sessions` directory is absent or not the user's: PHP then fails every upload
  and session silently, with nothing in the server's logs (live report). The root suite
  now uploads real files through a generated pool, in-memory and spilled bodies, and
  asserts `$_FILES` lands in the private tmp inside `open_basedir`, the moved file is
  byte-identical and the response after a large multipart body is complete; the docs say
  which directories the pool gives PHP.
- **Fixed: a request after a slow exchange could be parsed from stale bytes** (live
  report: one Firefox asset request logged as `GETGET /wp-admin/js/...` and answered
  405). The client-abort watch of a slow FastCGI or proxy exchange (E9) arms a read at
  the end of the request being served; the response then compacts the receive buffer,
  and when that read completed with the next request its bytes sat past the old offset
  while the count was added at the new one, so the parser saw the previous request's
  bytes first (a silent replay of a GET) and the new request's tail after. The read's
  landing offset is now tracked and its bytes moved to the buffer's end, with the
  invariant asserted in debug builds. Diagnostics: an unrecognised method token and a
  request line that does not parse are logged at warn level, hex-escaped. Tests: every
  split point of a request line on plain and TLS, 240 varied requests on one connection,
  two requests in one write, the exact trigger, a parser prefix test, the line in the
  fuzz corpus.

## 0.1.0-alpha.13 (2026-09-20)

- **Per-site limits through the control plane** (F10, live request: "raise the WordPress
  upload limit to 200 MB" could not be done without a terminal): `site-create` and
  `site-update` take `settings = {key: value}` (CLI `--set KEY=VALUE`, MCP `settings`)
  for `max_body_size` (now a site key too, driving the pool's `upload_max_filesize` and
  `post_max_size`; `[server] max_body_size` stays the default), `memory_limit`,
  `max_execution_time`, `max_input_time` (new pool key), `children`, `pm` and
  `max_requests`. Every value moves within the ceilings `[control] site_limits` sets
  (defaults 512MB, 512M, 300 s, 300 s, 32 children) and is refused above them naming the
  key, the value and the ceiling; every other ini name is refused as unknown, so
  `extra`, `open_basedir`, `sendmail_path` and the like stay in the file. `agensio ctl
  settings [NAME]`, `GET /v1/settings`, MCP `site_settings_list` publish the table with
  units, defaults, minimum, ceiling, cost and derivations, plus current values per site;
  `site NAME` reports each setting's value and source; the MCP `settings` schema is
  generated from the same table and a test asserts the three cannot drift. Answers list
  under `done` what was written and reloaded; `site-update` now applies the pool through
  the helper like `site-create` does.
- **A TLS connection serves only the names its certificate covers** (live report: with
  three sites and three certificates on one listener, a connection made with site B's
  certificate served site A's pages for `Host: A`). Host matching on a TLS connection is
  now bounded by the certificate presented at the handshake (CN, SAN DNS and IP entries,
  RFC 6125 wildcards): a Host outside it answers `421` with `Cache-Control: no-store`
  exactly like an unknown Host, a SAN or wildcard certificate covering several sites
  keeps them all reachable on one connection (the HTTP/2 coalescing case), a catch-all
  on TLS is bounded the same way, and a renewal or reload never changes what an open
  connection may serve. Plain listeners, unknown Hosts, missing Host and HTTP/1.0
  without Host are unchanged. Twelve integration checks, including the renewal-during-
  a-connection case; the HTTP/2 coalescing retry stays a written, skipped check.
- **Credential files are `0600` on every write path, and a writer validates before it
  answers** (live report: five ok answers produced a server `agensio -t` refused to start,
  because a `2750` site directory hands the server's group to every file, including the
  `wp-config.php` a `site-copy` had just written). The preset table now names each
  preset's `secrets` (`wp-config.php`; Drupal's `settings.php`, `settings.local.php`,
  `services.yml`), the hosting rule reads that list (Drupal was not covered before),
  `site-install` and `site-copy` create those files `0600` and report them under
  `secured`, check the rule on what they wrote, and compare the configuration's
  validation before and after: a new error answers `409` with `written: true` and the
  validator's message instead of ok. `presets` shows `secrets`.
- `health`: `php_fpm_hard_reload` when php-fpm.conf sets no `process_control_timeout`:
  the reload `site-create` and `agensio pools` trigger then kills PHP requests in flight
  on every site (live report: 502s on another site while a site was created); the fix
  is one line in php-fpm.conf, and `site-create`'s `done` entry says so.
- WordPress preset: the `wp-content` drop-ins `db.php`, `advanced-cache.php` and
  `object-cache.php` are answered 404 like `wp-config.php`; they run only inside
  WordPress's bootstrap and answered 500 when fetched directly (live report).

## 0.1.0-alpha.12 (2026-09-20)

- `site-copy NAME --from SUB --to SUB [--overwrite]` (MCP `site_copy`, `POST
  /v1/sites/NAME/copy`): one regular file of a site copied to another path of the same
  site as the site's account, for the drop-ins applications ship as templates
  (WordPress's `wp-content/db.php` from the SQLite plugin's `db.copy`, caching plugins'
  `advanced-cache.php`, Drupal's `settings.php`). Both paths take the install's walk
  (no `..`, no symlink on the way, no other account's directory); the destination's
  directory must exist; an existing destination needs `--overwrite` and its old size and
  mtime are reported; the new file gets the directory's pattern; written under a
  temporary name, so a refusal leaves nothing. Never across sites, never caller content,
  never a directory, no chmod or chown, and no option to relax any of that. With
  `site-create`, `site-install` and `--create-path` the WordPress-on-SQLite path now
  completes with zero terminal commands (the request that prompted it).

## 0.1.0-alpha.11 (2026-09-20)

- `site-install --path SUB --create-path` (MCP `create_path: true`): a plugin, theme or
  module goes into its own new directory below the site (`wp-content/plugins/NAME`,
  `web/modules/contrib/NAME`), created as the site's account with the parent's pattern,
  reached by a walk that refuses symlinks, `..` and another account's directories; a
  refusal removes what the call created; the answer lists `created`. `dry_run` now takes
  the same walk and reports `would_create` or the refusal instead of an unconditional ok
  (live report: the first plugin after a one-call site).
- WordPress preset: `readme.html` and `license.txt`, which name the installed version,
  are answered 404 like `wp-config.php` (from a live report: the first thing a
  vulnerability scanner reads).

## 0.1.0-alpha.10 (2026-09-20)

- **`site-install`** (F9): puts an application's files into a site's empty directory as
  the site's own account, from the preset's official archive (WordPress, Drupal;
  `--version`), any https URL, or an archive uploaded with the new `agensio ctl upload
  NAME [FILE]` (`uploads`, `uploads-delete`); MCP tools `site_install`, `uploads_list`,
  `upload_delete`. agensio's own extractor handles `.tar`, `.tar.gz` and `.zip` and
  refuses symlinks, hard links, devices, `..`, absolute paths, encrypted and zip64
  entries, bad checksums and oversize archives; the download is https only with every
  hop checked against a private-address fence; `--sha256` gates the whole thing; a
  refusal leaves the directory empty. Modes follow the target directory's own
  (`2750` gives `0640`/`2750`). `[control] install = false` turns downloads off and keeps
  uploads; `install_private` and `install_ca` are for internal mirrors and test beds;
  `upload_max` caps uploads (512 MB). The helper gained `app_install` (the child drops to
  the site's account before it reads a byte); without the helper the server installs as
  its own account into directories it owns. New dependency: zlib. Tests:
  `tests/install.sh` (root devbox, 22 checks), unit tests of the extractor and the fence,
  `fuzz_archive`, 17 integration checks.
- **Provisioning helper** (`[control] provision = true`, the default): a server started
  as root forks a small root helper before the privilege drop, and `site-create` then
  creates the account, lays out the directories, hands the site its log, writes the
  php-fpm pool and reloads php-fpm in one call, listing it under `done`; a change that
  needs a restart restarts the service after answering. The helper does exactly those
  five things, re-validates every argument, runs programs by absolute path without a
  shell, and refuses another site's directory, a symlink on the way, a system account.
  `docs/security-control-plane.md` states what a compromised server could and could not
  do through it; `provision = false` or a server not started as root keeps the previous
  behaviour of handing commands back.

## 0.1.0-alpha.9 (2026-09-20)

Sixth live report, all five items, on the way from a bare server to a working Drupal site.

- `site-create` and `site-update` report every prerequisite at once: `problems`, each
  with a `code` (`missing_account`, `missing_group`, `root_missing`, `root_unreadable`,
  `certificate_missing`) and its command, so one round of root work suffices.
- `dry_run: true` (`--dry-run` on the CLI) runs every check and returns the file that
  would be written, without writing or reloading.
- A site that adds a privileged port to a server that has dropped root answers
  `202 needs_restart`: the file is written and validated, `systemctl restart agensio`
  serves it. Before, the reload failed with what looked like a permission error.
- `next_steps` are separate commands: `agensio pools` exits 3 when it wrote files, and
  the `&&` that followed skipped the php-fpm reload exactly when it mattered.
- `site NAME` and `-t --explain` report a path answered 404 whatever exists on disk as
  handler `deny`, and a location lists the endings it `refuses`. Before, `settings.php`
  showed as `static`.
- `health` reports `log_not_readable_by_user` while a per-site log created by a reload
  is not owned by the site's group; a restart hands it over.
- The MCP `site_create` `app` options are asserted equal to what `presets_list` returns,
  so a new preset cannot ship unadvertised; the `app` description points at `presets_list`.

## 0.1.0-alpha.8 (2026-09-20)

- `presets`: `agensio ctl presets`, `GET /v1/presets` and the MCP tool `presets_list`
  describe every `app` value from the preset table (served root, which `.php` runs,
  refusals, directories that never run PHP, files never served).
- Every value that can reach a root command is validated first: account names must match
  `^[a-z_][a-z0-9_-]{0,31}$` and may not be a system account or a word for "none"; paths
  must be absolute and shell-safe. `user: "null"` is refused with the way to say "no
  account": `no_user: true` (JSON `null` still works; both together are refused). The MCP
  schema types `user` and `group`.

## 0.1.0-alpha.7 (2026-09-19)

- chore: update changelog for version 0.1.0-alpha.7
- feat!: strict host matching with 421, and SNI certificate selection per site
- fix: log sinks added by a reload, state directory access, 404 for refused paths, ctl help

**Breaking: strict host matching.** A site answers only the names in its `server_name`.
A request with any other Host, including the server's IP address, answers `421
Misdirected Request` unless the listener has a catch-all site (`server_name = ["*"]` or
`default = true`). Before, the first site on a listener silently served everything. If
your monitor checks the IP address, point it at the hostname or add a catch-all site.
The packaged default site on port 80 is a catch-all; port 443 has none unless you add one.

- TLS: each site on a listener gets its own certificate, selected by SNI (before, all
  sites shared the first site's certificate). A name no site lists is refused at the
  handshake; a client sending no name gets the catch-all's certificate or is refused.
- `status` names each listener's catch-all; `sites` marks catch-all sites; `site-create`
  warns when a listener has none.
- A log file added by a reload received nothing (per-worker buffers); fixed.
- `/var/lib/agensio` is 0751 so site users reach their own tmp/ and sessions/.
- Refused endings (`deny_suffixes`) answer 404 like hidden files.
- `agensio ctl --help`, and `--help` on every subcommand.

## 0.1.0-alpha.6 (2026-09-19)

- feat: implement PHP presets as data structure and enhance application routing

## 0.1.0-alpha.5 (2026-09-19)

- feat: enhance PHP presets for Laravel, Drupal, and WordPress
- Add A/B benchmark results and acceptance test for site creation
- docs: update installation instructions for Debian, Ubuntu, Fedora, and Arch

## 0.1.0-alpha.4 (2026-09-19)

- feat: enhance release workflow to upload RPM artifacts and add Fedora smoke tests

## 0.1.0-alpha.3 (2026-09-19)

- fix: update release workflow to use secrets for APT GPG key and enhance Arch package build process

## 0.1.0-alpha.2 (2026-09-19)

Packages and release automation; no change to the server itself.

- Debian package (`.deb`) and RPM built by CPack: binary in `/usr/sbin`, systemd unit,
  log rotation, `/etc/agensio` with a default site serving `/var/www/html`, the
  `agensio` service account and the `agensio-admin` group, start on first install when
  port 80 is free. Upgrades keep edited configuration files; purge keeps certificates
  and content. `tests/package.sh` exercises the whole cycle in a container.
- `packaging/rpm/agensio.spec` for COPR and `packaging/arch/PKGBUILD` for the AUR.
- GitHub Actions: `ci.yml` builds and tests on Ubuntu and macOS; `release.yml` builds
  both packages on every `v*` tag, checks the version against the tag, attaches the
  packages to the release and publishes a signed APT repository to GitHub Pages when the
  signing key secret is present.
- `scripts/release.sh` bumps the version everywhere, tags and pushes.
- `docs/install.md`: the package routes for Debian/Ubuntu, Fedora and Arch.

## 0.1.0-alpha.1 (2026-09-19)

First pre-alpha. Everything below is implemented and tested on Linux (Debian 13) and
macOS; Windows compiles but is not tested. Read `docs/install.md` before installing and
`README.md` for the known limitations.

### Serving
- Static files over HTTP/1.1 and HTTPS with an in-memory cache, sendfile, Range requests,
  conditional requests, per-site locations, `try_files`, path policies.
- PHP through FastCGI with presets for Laravel, Statamic (`laravel`), WordPress and plain
  PHP; per-site users with generated php-fpm pools and ownership rules checked by `-t`.
- Reverse proxy with WebSockets, upstream groups with passive health checks, TLS to the
  origin, header policy, CGI; presets and examples for Node, Rails, Rocket.Chat,
  ThingsBoard.
- Access log in combined or JSON format, error log, `SIGUSR1` reopen.

### Operating
- `agensio reload` (or `SIGHUP`): configuration switched between requests, nothing in
  flight interrupted, a bad file refused with the old configuration kept.
- `tls = "auto"`: built-in ACME client (HTTP-01) for Let's Encrypt or any RFC 8555 CA,
  renewal at a third of the lifetime left, the new certificate picked up through the
  reload path.
- `redirect = "https"` or `redirect = "https://www.example.com"` for HTTPS-only and
  canonical-host setups.
- Start as root, bind, then drop to `server.user`; per-site logs owned for the customer.

### Control plane
- `[control]`: a unix socket with peer-credential roles (admin, operator, viewer) and an
  audit log. Read commands: status, sites, site, validate, logs, health. Changes:
  reload, logs-reopen, site-create/update/disable/enable/delete, cert-renew, every one
  behind an explicit confirmation and a reason.
- `agensio ctl` for shells and panels.
- `agensio mcp`: a Model Context Protocol server on stdio for AI agent hosts, locally
  or over SSH, with the same tools gated by role; a guided site creation that asks for
  the decisions it needs and hands root work back as commands.
- Security review of the control plane in `docs/security-control-plane.md`.

### Performance
Single worker on Linux against nginx: about 1.5x less CPU per plain request, 1.3-1.6x
on TLS, proxying 13-46 % cheaper; numbers and method in `CLAUDE.md` and `bench/results/`.
