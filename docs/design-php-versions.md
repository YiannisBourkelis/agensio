# Design: PHP versions per site

Status: decided 2026-10-20 (sections 3 and 14 with the owner); being built in the steps of section 13 (steps 1 to 3 built 2026-10-20, step 4 2026-10-21). The owner's requirements: several PHP versions served
at once, each site on the version it names, switching a site's version without downtime, the
control plane and the MCP bridge able to say which versions are installed and installable, and
an agent able to pick, or ask about, the version an application needs. No migration: only the
test host runs agensio, and old forms are refused, not converted.

## 1. What exists today, and what it cannot do

- A site may name a version: `php = { version = "8.4" }` in its file, `php_version` through
  `site_update`, `agensio ctl --php-version`. `pools_dir` (`services/pools.cpp`) finds that
  version's pool directory (`/etc/php/8.4/fpm/pool.d` on Debian), and the control plane reloads
  `php8.4-fpm`.
- **Every generated pool goes into one directory.** `agensio pools` and the helper's
  `pools_apply` pick the version of the last site that names one and write every pool there.
  Setting 8.5 on one site moves every site to 8.5, or splits nothing at all.
- **Pools are per account**: `agensio-<user>`, socket `<pools_run>/agensio-<user>.sock`. The
  sites of one account share the pool, and the loader makes them agree on every pool key
  (children, `pm`, limits, version).
- **The socket's name carries no version**, so two php-fpm masters (8.4 and 8.5) cannot both
  listen for one pool, which a switch without downtime needs for a moment.
- `server.pools` names one directory for everything; there is no notion of several runtimes.

## 2. How PHP versions run on a host

Each PHP version is its own program with its own master process: `php8.4-fpm` and `php8.5-fpm`
on Debian and Ubuntu, each with its `php-fpm.conf`, its pool directory, its `php.ini` and its
extensions (`/etc/php/8.5/fpm/conf.d`). A pool belongs to exactly one master; its file in that
master's pool directory is what puts it there. Installing a version is root's and the
distribution's: Debian 13 ships 8.4, other versions come from Ondřej Surý's repository
(packages.sury.org; the ondrej/php PPA on Ubuntu), RHEL from Remi's (SCL style: `php85-php-fpm`),
Alpine as `php85-fpm`, macOS as Homebrew's `php@8.5`.

php-fpm reloads gracefully on `SIGUSR2` (`systemctl reload`): the new master inherits the
listening sockets, so connections queue during the reload and none is refused, and with
`process_control_timeout = N` in `php-fpm.conf` the old children get up to N seconds to finish
the requests they are running. Without it (the default is 0) a reload cuts every request in
flight on every pool of that master: the one thing a switch without downtime needs from root, a
line health already asks for.

## 3. Decision: a pool per site

The question was whether an account's sites share a pool (and so a version), share one per
version, or each have their own. What each costs and gives:

| | A. a pool per account (today) | B. a pool per account and version | C. a pool per site |
|---|---|---|---|
| Version per site | no: the account's sites share one | yes | yes |
| Limits per site (`memory_limit`, `max_execution_time`, children, upload size) | no: the sites must agree | only between versions | yes |
| One site's burst or slow database | takes the account's children: its other sites queue, 503 or 504 | the same within a version | stays in its own pool: the others answer |
| Warm processes | shared: a child warmed by one site serves the next | shared within a version | each site's own |
| Compiled code (opcache) | one cache per version, shared by every pool of that master | the same | the same: no extra memory per pool |
| Idle cost with `pm = "ondemand"` (the default) | none | none | none: a pool without traffic has no child |
| Resident cost with `static` or `dynamic` | children per account | children per account and version | children per site (health's `php_pool_resident` shows it) |
| `open_basedir`, temporary files, sessions | the account's sites together | per version | the site's own tree only |

Performance, in short:
- **Compiled code costs memory per version, not per pool.** opcache is one shared-memory segment
  per php-fpm master, used by all of its pools. Splitting pools costs nothing there; running two
  versions costs one cache each (`opcache.memory_consumption`, 128 MB by default).
- **Warm processes are the only thing a shared pool saves.** With `ondemand` a child lives 60 s
  after its last request, so a site with steady traffic keeps its own children warm. A quiet site
  pays one fork after a quiet minute (tens of milliseconds) either way.
- **Under load, separate pools are faster where it matters**: one site's traffic or slow queries
  can no longer hold every child of the account, so the account's other sites keep their latency.
  A shared pool only wins for two quiet sites taking turns.

Decided (the owner's requirement that one account may serve each site on a different version, at
the best performance): **C, a pool per site.** It is the only option where a site's version,
limits and capacity are its own. Its one cost, more resident processes, applies only to `static`
and `dynamic` pools, which a site chooses and health reports. The account still decides the uid
(security between accounts is unchanged); between one account's sites, a pool per site adds
`open_basedir` and private temporary and session directories, which limit PHP's own file
functions to the site's tree. PHP does not treat `open_basedir` as a security boundary, but it is
narrower than today's.

## 4. The PHP runtimes

A **runtime** is one installed PHP version that agensio can give pools to: the version, its FPM
binary, its `php-fpm.conf`, its pool directory, its service unit, its CLI binary.

**Discovery**, read-only, no root needed (the files are world-readable), never on a worker:
- Debian and Ubuntu: `/etc/php/X.Y/fpm/php-fpm.conf`, `/usr/sbin/php-fpmX.Y`, unit
  `phpX.Y-fpm`, CLI `/usr/bin/phpX.Y`.
- RHEL with Remi: `/etc/opt/remi/phpXY/php-fpm.conf`, unit `phpXY-php-fpm`; the base system's
  own `/etc/php-fpm.conf` as its one version.
- Alpine: `/etc/phpXY/php-fpm.conf`, `/usr/sbin/php-fpmXY`, service `php-fpmXY`.
- Homebrew: `<prefix>/etc/php/X.Y/php-fpm.conf`, `brew services`.
- Anything else: root names it, `[php.runtimes."X.Y"] fpm, conf, pools, unit, cli` in the main
  file (a custom build under `/opt`, a second instance for the tests, section 11). This replaces
  `server.pools`, which is refused naming it.

**Facts per runtime**, gathered on demand (health, `php_versions`, a switch's preflight) by
running fixed programs with fixed arguments, cached until the files change:
- the exact version (`php-fpmX.Y -v`) and the extensions the FPM side loads (`php-fpmX.Y -m`,
  never the CLI's, whose `conf.d` may differ);
- whether the configuration is valid (`php-fpmX.Y -t`) and whether the unit is active and
  enabled (`systemctl show`, through the helper as today);
- from its `php-fpm.conf` and `php.ini`: `process_control_timeout`, `opcache.enable`,
  `opcache.memory_consumption`, `opcache.validate_permission`;
- its support status from a compiled table of PHP's releases (active support, security fixes
  until, end of life; php.net/supported-versions), updated with each PHP release; a version
  newer than the table counts as supported.

**Installable versions**: on Debian and Ubuntu the helper's read-only `php_available` runs
`apt-cache policy` for `phpX.Y-fpm` (fixed arguments, versions from the table) and reports which
the configured repositories offer; elsewhere "unknown". When a wanted version is not installable,
the answer gives root the repository's lines (sury or the PPA, then `apt install phpX.Y-fpm` and
the extensions, section 7), never runs them: installing packages stays root's.

`[server] php_version = "8.4"` (root's, applies on reload) is the version of every site that
names none. Without it: the newest installed runtime, and `-t` notes that installing a newer PHP
would move such sites (the reason for the key).

## 5. Pools per site

- **One pool per site with PHP and its own account**, in the pool directory of its version.
  File and pool name `agensio-<site id>`; `<site id>` is the account and 8 hex digits of the
  domain's hash, because pool and socket names must stay short (a unix socket's path is at most
  107 bytes on Linux, and a domain can be 253).
- **Socket** `<pools_run>/agensio-<site id>-<version>.sock`: the version in the name lets the
  old and the new master listen for the same site during a switch (section 6).
- **Per-site state**: `<state_dir>/<account>/php/<site>/{tmp,sessions}` (a catch-all's `*` written
  `_`) with today's modes and
  ownership; `open_basedir` the site's root, its state directory and what its preset adds.
- **Every pool key is the site's own**: children, `pm`, limits, `extra`; the rule that an
  account's sites agree goes away.
- **Reconciliation**: `agensio pools` (and the helper's `pools_apply`) makes every runtime's pool
  directory hold exactly the pools the configuration assigns to it: writes each, removes any
  other `agensio-*.conf` there, runs that runtime's `php-fpm -t` before its reload (a failed test
  restores the previous files and reports php-fpm's own message), and reloads only the runtimes
  whose pools changed. A site set aside (design section 26) keeps its pool, as today.
- A site with `php.socket` (a pool agensio does not generate: a container, another host) has no
  version agensio manages; `site_show` says so.

## 6. Switching a site's version without downtime

Every path that changes which runtime serves a site goes through one ordered switch, run by the
server around its own reload: `site_update` with `php_version`, a site file edited and reloaded,
`[server] php_version` changed for the sites that follow it. For a site moving from 8.4 to 8.5:

1. **Preflight**, before anything changes:
   - the 8.5 runtime is installed and its unit active;
   - it has the extensions the site needs (section 7);
   - its configuration tests clean;
   - both masters have `process_control_timeout` (else requests in flight would be cut: refused,
     with root's one line to add and a `cut_requests: true` that proceeds anyway).

   A failed preflight changes nothing and says why.
2. **The new pool comes up beside the old one**: written into 8.5's pool directory with its own
   socket, `php-fpm8.5 -t`, then `systemctl reload php8.5-fpm`. agensio waits until the socket
   accepts a FastCGI connection.
3. **agensio switches**: the reload's new generation sends the site's requests to the 8.5 socket.
   Requests already running continue on 8.4, as every reload keeps work in flight on its
   generation.
4. **The old pool goes**: removed from 8.4's directory, `systemctl reload php8.4-fpm`; php-fpm
   lets the requests still running there finish within `process_control_timeout`.
5. **The answer** says what ran, the versions before and after, and the time each step took.

A failure at step 2 removes the new pool, and the site never left 8.4. A failure at step 3 (the
reload refused) removes the new pool as well. A failure at step 4 leaves a stale pool that serves
nothing; health names it (`pools_stale`, with the file) and the next reconciliation removes it.

The rest is honest about what it costs:
- **Cold compiled code**: the first requests on 8.5 compile their scripts into its empty
  opcache, so for seconds they are slower.
- **Sessions**: sessions written by 8.4 are read by 8.5; PHP's session format does not change
  between 8.x versions.
- **Switching back** is the same switch in reverse.
- **Changing the server's default** switches the sites that follow it in the same reload: all of
  their new pools come up, then agensio switches, then the old ones go.

The docs (the PHP section of `docs/configuration.md` and a cookbook recipe) say all of this,
including the one root line that makes it graceful.

### 6.1 How it is built (2026-10-20)

- **One switch for every reload.** The switch is the reload itself, whatever asked for it: the
  control plane (`site_update`, `site_create`, enabling or restoring a site, `reload`), or SIGHUP
  (`agensio reload`, a site file edited by hand). Worker 0 loads and checks the configuration as
  before. When the helper is there, the rest runs off the workers: the preflight, the new pools up
  (phase `up`: written, never removing, tested, their versions reloaded, their sockets awaited),
  then the switch on worker 0, then every version's directory made to match (phase `full`). A
  reload that brings no new socket skips the first phase. The control plane's answer waits for
  both phases and says what each did and how long it took.
- **One reload at a time.** While one is switching, a reload from the control plane is refused
  ("try again in a moment"), and a SIGHUP is kept and runs after it. If a certificate refresh
  switched the generation meanwhile, the configuration is loaded again before the switch.
- **The preflight**, for each site whose pool socket is new:
  - its version is installed;
  - the version's service is active, when systemd runs it (otherwise root gets
    `systemctl enable --now phpX.Y-fpm`);
  - for a site moving between versions, both versions' `php-fpm.conf` set
    `process_control_timeout`.
  
  A failed preflight refuses the reload and changes nothing. On the control plane a missing
  `process_control_timeout` is a refusal that `cut_requests: true` overrides; on a SIGHUP it is a
  warning in the error log, since nobody is there to answer.
- **A version without a systemd unit** (Alpine, a build root named in `[php.runtimes]`, the test
  beds) is reloaded by the helper with SIGUSR2 to its master. The pid is read from the pid file its
  own `php-fpm.conf` names, and the helper checks that process is that version's binary before
  signalling it.
- **The wait**: each written pool's socket must accept a connection. php-fpm brings a new pool up
  only after its running children finish, within `process_control_timeout`, so the wait is at most
  30 s. A socket that does not come up puts that version's files back, reloads it again, and refuses
  the reload.

### 6.2 At a start

When agensio starts as root with its helper, the helper reconciles every version's pool directory
before the listeners accept requests (phase `start`: phase `full`, then the written pools' sockets
awaited, at most 30 s). Clients connecting meanwhile wait in the listen backlog. A start whose pool
files already match writes and reloads nothing. This covers the paths no reload sees:
- an upgrade that changes or renames the pool files;
- a restart after a site file was edited by hand;
- a newer PHP installed for the sites that follow the newest;
- a distribution upgrade that removed a version;
- a configuration restored from a backup.

The error log names what it did. Without the helper, health's `pools_stale` names what
`agensio pools` would do.

## 7. What an application needs

**Each PHP preset gets requirements**, compiled from the application's own published
requirements, with the source and the date checked:
- the PHP versions it supports and the one it recommends;
- the extensions it requires, and those it recommends.

WordPress, Drupal, Laravel and Grav each publish theirs; the plain `php` preset requires none.
They are shown by `presets_list`, used by the preflight, and kept current like
`docs/third-party-bugs.md`: a row per application, the link, the date.

**The archive's own declaration wins** where it has one, since it matches the exact release:
`require.php` in `composer.json` (Laravel, Drupal, Grav) and `$required_php_version` in WordPress's
`wp-includes/version.php`. `site_install` reads it, reports it in its facts, and refuses or warns
when the site's version falls outside it.

**Choosing a version** (the agent's procedure, written into the MCP texts):
1. Pick the newest installed runtime within the application's range that has its required
   extensions and is not past its security support.
2. If none fits, say so to the user with what is missing: a newer PHP (root's install lines) or
   an extension (root's `apt install phpX.Y-<ext>` line). Then ask whether to install that, or to
   use the best installed version anyway, naming what it lacks.

**Extensions** are compared with what the target runtime's FPM loads. When a site switches,
those its current runtime loads and the target lacks are named too: a WordPress plugin may need
one no requirement lists.

## 8. The control plane and the MCP bridge

- **`php_versions`** (MCP, viewer; `agensio ctl php`; `GET /v1/php`). For each runtime:
  - its version, unit state, pool directory and extensions;
  - support status and dates, `process_control_timeout`, the opcache facts;
  - the sites on it, and whether it is the server's default.

  Then the versions installable from the configured repositories, and root's lines for one that
  is not.
- **`site_create`, `site_update`**: `php_version` validated against the runtimes; a change runs
  the switch of section 6 and answers with its steps; the field's text gives the procedure of
  section 7. The answer of `site_create` names the version chosen and why.
- **`site_show`**: the site's version, where it comes from (the site, or the server's default),
  its pool and socket.
- **`presets_list`**: each PHP preset's requirements.
- **`site_install`**: the archive's declared PHP requirement in its facts, and whether the site's
  version meets it.
- **Future site tasks** for PHP applications (Composer, `wp-cli`, `artisan`) run the site's own
  version's CLI from the runtime, never a `php` on the `PATH`.

## 9. Health

| finding | severity | when |
|---|---|---|
| `php_version_missing` | error | a site or the server's default names a version no runtime has: its pool cannot be written |
| `php_fpm_inactive` | error | the unit of a runtime that serves sites is not running |
| `php_extensions_missing` | error, info | a site's runtime lacks an extension its preset requires (error) or recommends (info: it runs without it) |
| `php_version_unsupported_by_app` | warn | a site's version is outside the range its application declares |
| `php_version_eol` | warn, error | a site's version is past active support (info), past security support (warn), long past it (error) |
| `php_fpm_hard_reload` | info | today's finding, per runtime that runs pools: no `process_control_timeout`, so a reload or a switch cuts requests in flight |
| `pools_stale` | warn | today's finding, across runtimes: a pool file differs, or an `agensio-*.conf` sits in a pool directory the configuration no longer assigns it to; the message names each file |
| `php_opcache_shared` | warn | a runtime serves pools of two accounts or more and its `php.ini` leaves `opcache.validate_permission` off, so one account's PHP may be served code cached from a file it cannot read |
| `php_default_unpinned` | info | sites follow the newest installed version because `[server] php_version` is not set |

## 10. Configuration keys

- **`[server] php_version`**: string, the version of every site that names none, applied on
  reload (each following site switched as in section 6).
- **`php = { version }`** on a site: unchanged, now validated against the runtimes at load.
- **`[php.runtimes."X.Y"]`**: root's table for a runtime discovery does not find: `fpm`, `conf`,
  `pools`, `unit`, `cli`.
- **`server.pools`**: removed, refused naming `[php.runtimes]`.

Each key gets its row in `control/reference.cpp`, its section of `docs/configuration.md` and a
cookbook recipe, as every key does.

## 11. Security

- **The helper keeps its rules**: fixed operations, fixed programs by absolute path, no shell.
  The new operations are:
  - `php_runtimes`: read-only, `-v`, `-m`, `-t` and `systemctl show`;
  - `php_available`: read-only, `apt-cache policy` for known package names only;
  - `pools_apply` with the ordered steps.

  A version comes from the discovered runtimes or the compiled table, never as a path from a
  caller.
- **Pool files** stay root's, `0644`, written whole (`write_file_atomic`); `php-fpm -t` before
  every reload.
- **The account is the boundary between accounts**, as today. A pool per site narrows what one
  site's PHP can reach within its account; it is not a boundary between accounts.

## 12. Tests

- **Unit tests** over a described filesystem, behind the injectable facts used for the hosting
  rules:
  - discovery per layout;
  - pool placement and reconciliation;
  - the switch's plan and each failure path;
  - the preflight's refusals;
  - the requirement checks;
  - the version choice.
- **Integration**: a second runtime from `[php.runtimes]` pointing at the devbox's own
  `php-fpm8.4` with its own `php-fpm.conf` and pool directory, standing in for "8.5". A switch
  between the two is tested with a load running (no failed request), its rollback, and the stale
  pool. An image with a real second version (sury's `php8.5-fpm`) runs the same checks when
  present.
- **A/B**: the request path does not change (a site's socket is part of its upstream, decided at
  load), but the FastCGI rows (`-P`) are run anyway.

## 13. Steps

1. **Runtimes** (built 2026-10-20): discovery, the facts, `[php.runtimes]`, `php_versions` (MCP,
   `ctl`, API).
2. **Pools per site** (built 2026-10-20): naming, sockets with the version, per-site state,
   `[server] php_version`, reconciliation across runtimes with php-fpm's test before each reload,
   `server.pools` removed; health's `php_version_missing`, `php_default_unpinned`, `pools_stale`
   and `php_fpm_hard_reload` per runtime.
3. **The switch** of section 6, through every path, with its docs and recipe (built 2026-10-20,
   section 6.1; with the start of 6.2, and health's `php_fpm_inactive`).
4. **Application requirements** (built 2026-10-21): the presets' table, the archive's declaration, the
   preflight's extension checks, the MCP procedure for choosing a version. Decided with the owner:
   agensio names extensions as `php-fpm -m` prints them and never maps them to packages (the agent's
   and root's); a move or an install that does not meet the requirements is refused with
   `ignore_requirements` past it, a new site only warned; only what an application enforces is
   required (never a cache back end, never its own run-time checks: Grav asks for redis and runs
   without it); a missing recommended extension is info in health; "long past" support is more than
   a year after security support ended.

Each step: tests first, the reference, the docs and the MCP texts in the same change, and
migration lines for the test host where a step changes what it runs (step 2 renames every pool).

## 14. Decided with the owner (2026-10-20)

- **A pool per site** (section 3, option C).
- **No opcache warming on a switch**: the first requests on the new version compile their
  scripts; that is seconds of slower answers, not errors.
- **A runtime whose unit is inactive at preflight**: the helper does not start it; the answer
  hands root the line (`systemctl enable --now phpX.Y-fpm`), as for any package.
