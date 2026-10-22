# Design: release folders, a new version of a site without downtime

Status: deferred by the owner on 2026-10-22, to a release after the first stable one (too much for
the first release); nothing is built, and the questions of section 17 are open. It answers the last item of the
test host's report of 2026-10-22: "files can only be installed into an empty directory, so a new version
can't be deployed through the tools. Install-into-a-release-folder plus a switch would cover it." The
sources are in `research_notes/Release folder deploys/notes.md` (read 2026-10-22: Capistrano 3.20.1, Deployer 8.0.5,
Ansible's `deploy_helper` as Trellis uses it, Forge and Envoyer's documentation, php-src `PHP-8.4`).

## 1. What exists today, and what it cannot do

- `site_install` unpacks an archive as the site's account into the site's directory, or into `path`
  below it, and only into an empty directory (`install::execute`: "an application is installed only into
  an empty directory"). The first install works. A second version cannot be installed: the directory
  holds the first one, and emptying it first would take the site down until the new files are in.
- The install walks the target with `O_NOFOLLOW`, creates missing levels as the account
  (`create_path`), refuses an archive entry that is a symbolic or hard link, makes the preset's
  credential files private, and judges the release's PHP requirements
  (`docs/design-php-versions.md` 7). It does not reload: the served root is resolved when the
  configuration loads.
- `served_dir` (alpha.109) and the presets' `public/` and `web/` serve a directory of the project.
  `root` stays the project directory: PHP's `open_basedir`, the install's target, the `composer.json`
  health reads.
- The loader resolves a site's root to its canonical path (`resolve_root`, `fs::canonical`) once per
  load, so a symlink in the root is followed then and not again until the next reload. PHP receives
  `DOCUMENT_ROOT` and `SCRIPT_FILENAME` built from that resolved root.
- The static cache keys an entry by its location's id, new at every reload, and the request path
  (`CacheKey`), so a reload starts a site's files afresh.

## 2. How the established tools deploy a release

Every tool in use has the same layout, made popular by Capistrano:

```
<deploy root>/
  releases/20261022101500/     one directory per version, never changed once live
  releases/20261023091200/
  shared/                      what outlives a version: .env, storage/, uploads
  current -> releases/20261023091200
```

- **Names.** Capistrano and Ansible's `deploy_helper`: a 14-digit UTC timestamp `YYYYMMDDHHMMSS`.
  Deployer: an increasing integer, with `.dep/releases_log` as the history.
- **Shared paths are symbolic links in each release.** Capistrano and Forge make absolute links;
  Deployer makes relative ones (`releases/N/storage -> ../../shared/storage`). A shared directory missing
  from `shared/` is created, seeded from the release's own copy if it has one, then the release's copy is
  removed and the link made (Deployer `deploy:shared`). Capistrano refuses a shared *file* that
  `shared/` does not hold yet. Recipe defaults:
  - Laravel: `storage/` and `.env`;
  - WordPress: `wp-config.php` and `wp-content/uploads/`;
  - Drupal: `sites/<site>/files/`, `settings.php`, `services.yml`.
- **The switch is one rename(2).** A new link to the release is made under a temporary name and renamed
  over `current`. Capistrano: `ln -s <release> releases/current; mv releases/current <root>/`. Deployer:
  `mv -T release current`. `deploy_helper`: `os.symlink` then `os.rename`. There is never a moment
  without `current`. A `current` that is a real directory stops them: the rename cannot replace it
  (Capistrano issue #1398, Deployer's `deploy:setup` refuses).
- **Rollback** points `current` at an earlier release the same way. Deployer marks the release it rolls
  back from with `BAD_RELEASE` and never picks a marked one; Capistrano archives it and deletes it.
- **Cleanup** keeps the newest N: Capistrano 5, Trellis 5 plus `current`, Forge 4, Deployer 10.
  Capistrano and `deploy_helper` never delete what `current` names; Deployer's cleanup has no guard.
- **A failed deploy leaves its directory** in `releases/` (Capistrano, Deployer), so the newest
  directory is not the live one: only `current` says which is.
- **Composer runs once per release** in the release (Deployer `deploy:vendors`: `install --no-dev
  --optimize-autoloader`). `vendor/` is never shared, since its autoloader encodes the release's own
  paths.
- **No tool reloads the web server.** They rely on the web server resolving the root per request (next
  section).

## 3. The PHP side of a switch, and why agensio's load-time resolution fits it

What goes wrong when PHP is handed a path through `current`:

- **OPcache.** With the default `opcache.revalidate_path = 0`, OPcache looks a script up by the name it
  is given. On a miss it compiles the resolved file and adds the given name as another key for it
  (`ZendAccelerator.c`, `persistent_zend_resolve_path`, `zend_accel_add_key`). After a switch,
  `.../current/public/index.php` keeps returning the old release's code. Deployer's documentation: "if
  `SCRIPT_FILENAME` contains _current_ symlink, on new deploy nothing updates". PHP bug #74268 (2017,
  open) reports old and new pages alternating.
- **The realpath cache** keeps a resolved name for `realpath_cache_ttl` (120 s), per php-fpm child. It is
  off wherever `open_basedir` is set, which every generated pool sets.

The fix every source gives is the web server handing PHP the resolved path, as `SCRIPT_FILENAME` and
`DOCUMENT_ROOT`:
- nginx: `$realpath_root`, a realpath(3) per request;
- Caddy: `resolve_root_symlink`, an `EvalSymlinks` per request;
- Apache: Etsy's mod_realdoc;
- Deployer's guide "avoid php-fpm reloading".

With it, OPcache's keys are the release's real paths, so a new release compiles afresh and nothing
needs resetting. One request stays in one release:
- `__FILE__` resolves symbolic links;
- php-fpm changes to the script's real directory, so `require __DIR__ . '/../src/x.php'` and relative
  includes stay in the release the request started in.

agensio already does this, and at no cost per request: the root is resolved once, when the
configuration loads. What that costs instead, and what the design must hold to:

1. **A switch is followed by a reload.** Until then the site serves the release resolved last, static
   files and PHP alike, which is consistent but old.
2. **The served release is never deleted while it is served**, nor while requests of the previous
   generation still run in it. A tool that cleans up by following `current` alone would delete it.
3. **`open_basedir` names the deploy root**, so releases and `shared/` are both inside it. PHP resolves
   both sides of the check, so a basedir through `current` would admit one release only, and never
   `shared/`.
4. **Shared links resolve outside the release**, so `symlinks = "deny"`, which keeps files under the
   served root, refuses them, as nginx's `disable_symlinks on` does.

## 4. Proposal: the layout

A site with releases gives `root` as its deploy root, laid out as in section 2: `releases/`, `shared/` and
`current`, all the site's account's. The application's directory is the release `current` names. Every
preset finds its own directories in it, exactly as it does in `root` today: Laravel's `public/`, Drupal's
`web/`, `served_dir` on `app = "php"`.

```toml
[[site]]
server_name = ["shop.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/shop.example.com/app"   # the deploy root: releases/, shared/, current
releases = { keep = 5 }                  # shared: the preset's (Laravel: .env and storage/)
app = "laravel"
user = "shop"
tls = "auto"
```

At load:
- `current` is resolved, and must be a link to a direct child of `<root>/releases/`; anything else is
  refused (a link to `/etc`, a real directory, a dangling link). That release is
  `SiteConfig::project_root`, and the served root is derived from it as today.
- `SiteConfig::deploy_root` holds `root` as given: PHP's `open_basedir`, the install's base, the trash's
  tree.
- A site whose `current` does not exist yet (before its first release) loads and answers 404 to
  everything, with health saying why (section 10). Its root is not the lexical path through `current`
  as `served_dir` has it, since PHP would then be handed a path through the link.

Names: agensio's own releases are the 14-digit UTC timestamp, as Capistrano and `deploy_helper` name
them, with `-2`, `-3` for a second in the same second. The loader accepts any plain name
(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`), so a deploy root another tool made loads too (section 9).

## 5. Configuration keys

| key | type | default | meaning |
|---|---|---|---|
| `[[site]] releases` | table | (none: the classic layout) | the site deploys in releases |
| `releases.keep` | integer, 2 to 50 | 5 | releases kept on disk, the current one among them |
| `releases.shared` | list of paths | the preset's | files and directories (`storage/`, ending in `/`) every release links to `shared/`; relative to the release, plain paths as `served_dir` takes them, none inside another |

The presets' defaults follow the recipes of section 2:
- `laravel`: `.env` and `storage/`;
- `drupal`: `web/sites/default/files/` and `web/sites/default/settings.php` (or without `web/` when the
  release has none);
- `php` and `static`: none.

Releases are offered for `php`, `laravel`, `drupal` and `static`, and refused for `wordpress` and `grav`
in this design (section 8). Every key gets its reference row and a cookbook recipe. Managed:
`SiteSpec::releases`, rendered as the table; `ctl --releases [--keep N] [--shared PATH]...`.

## 6. Installing a release

`site_install` on a site with releases needs no empty directory: it makes one.

1. Creates `releases/<timestamp>` as the account (the existing `create_path` walk) and unpacks the
   archive there, the same extractor, the same refusals.
2. Links the shared paths. For each entry:
   - if `shared/` lacks it, seeds it with the release's copy (a directory created empty when the release
     has none). A shared file the release does not bring either is refused, naming it (Capistrano's
     rule): a release cannot run without its `.env`;
   - then removes the release's copy and makes a relative link (`../../shared/storage`, Deployer's form,
     so the tree keeps working when the trash moves it and moves it back).

   Every step is done as the account, through descriptors opened with `O_NOFOLLOW`.
3. Makes the credential files private, now judged at their real place in `shared/` (`secret_paths`
   resolves through the links; the hosting rules' `stat` already follows them).
4. Judges the release's PHP requirements, read from the release (`composer.json`), against the site's
   version, as an install does today.
5. Writes `releases/<name>/.agensio-release`, a small JSON manifest: source, sha256, time, the account.
   It is informative only; the account could change it. A dot file, never served.
6. Activates the release (section 7), unless the call says `activate: false`; then a separate call
   activates it.

A failure at any step removes the new release directory, as a failed install empties its target today.
The site goes on serving the release it served. The archive must be complete: one that needs
`composer install` or a build is out of scope here (section 8).

## 7. The switch and rollback

`site_release_activate NAME RELEASE` (admin), and step 6 of the install:

1. **Preflight.** The release exists as a direct child of `releases/`, is not `current` already, and its
   requirements fit the site's PHP (refused unless `ignore_requirements`, as a version switch is). The
   configuration loads with `current` pointing there: the loader is run on a copy before anything
   changes, so a Laravel release without `public/` is refused here and not set aside later.
2. **The switch**, as the account: a link `current.agensio-new -> releases/<name>` (relative), then
   `renameat` over `current`.
3. **The reload** (`Server::reload_async`, the existing path). The new generation serves the new release.
   In-flight requests of the old generation finish in the old release, which still exists.
4. **Undo.** If the reload refuses the site or sets it aside, the link is switched back and the server
   reloaded, and the answer says what the release lacked. Site isolation already keeps the served
   version of a site whose file stops loading (alpha.62), so the old release is served throughout.

Rollback is the same call with an older release. The answer of every switch names the release it left,
which is the rollback target, and `site_releases` lists them all.

## 8. What fits, and what does not

- **Applications that update themselves in place** write into the release they run from: WordPress's core
  and plugin updates, Grav's GPM, Drupal's contributed Automatic Updates. Those changes vanish at the
  next release and go with the release at cleanup. Bedrock disables them (`DISALLOW_FILE_MODS`,
  `AUTOMATIC_UPDATER_DISABLED`); Deployer's WordPress recipe does not. So this design refuses releases on
  `app = "wordpress"` and `"grav"`. A Bedrock site, which is built with Composer and updates nothing in
  place, runs on `app = "php"` with `served_dir = "web"`.
- **Composer and builds.** Deployer runs `composer install` in each release; agensio has no PHP task to
  run it yet. Step 1 takes complete archives, a CI artifact or a release tarball with `vendor/`. A
  `composer_install` task, with Composer from `[control] runtimes` the way site tasks take Ruby and Node,
  is a later step of `docs/design-site-operations.md`.
- **Proxied applications** (`rails`, `django`, `node`) need their service restarted in the new release,
  which is root's (the unit). They stay on the classic layout until F14 manages units.
- **Database migrations** belong to the application's release process. Capistrano says the same: no tool
  in section 2 runs them in its switch.

## 9. A switch made by another tool

A developer deploying with Deployer or Capistrano as the site's account flips `current` themselves, and
agensio would go on serving the old release until a reload. The other tool's cleanup would later delete
that release (section 3, point 2).

**Proposed:** a watch on worker 0 that `readlink`s each release site's `current` every 5 seconds and
reloads when it names another release than the one served. This is mod_realdoc's `RealpathEvery`, with
the reload doing what a per-request realpath does elsewhere. Notes:
- it costs one `readlink` per release site per 5 seconds, nothing on the request path;
- one reload at a time, as today;
- health's `release_switch_pending` covers the seconds in between, and a watch that cannot reload;
- the alternative is no watch and a documented `agensio reload` as the tool's last step (Deployer
  `after('deploy:symlink', ...)`). The watch is safer, since a forgotten hook breaks silently.

## 10. Health

| code | severity | when |
|---|---|---|
| `release_none` | warning | releases on, no `current` yet: every request is 404 (fix: `site_install`) |
| `release_current_invalid` | error | `current` is a real directory, dangling, or points outside `releases/` |
| `release_switch_pending` | warning | `current` names another release than the one served (fix: reload, or the watch) |
| `release_shared_missing` | warning | a shared path is missing from `shared/`, or the served release's copy is not the link |
| `release_unfinished` | information | a release directory without a manifest, older than an hour, that is not current: a deploy that stopped half way |
| `releases_over_keep` | information | more releases than `keep` (another tool's, which agensio does not prune) |

## 11. Cleanup

After a successful switch, agensio removes its own releases beyond `keep`, oldest first, as the account
(the helper's `remove_tree` walk). It never removes:
- the release `current` names;
- the one the running generation serves;
- the previous one, the rollback target;
- one it did not make (no manifest), apart from an unfinished one older than a day.

Unfinished ones go first. A release still in use by requests of an older generation is safe, since the
served and the previous release are both kept.

## 12. Control plane and MCP

- `site_install` on a site with releases: the release made, the release left (rollback), the shared
  paths linked and seeded, `activate: false` to stop before the switch.
- `site_releases` (viewer): every release with its name, time, source, sha256 and size, and which is
  current, which is served, which is unfinished.
- `site_release_activate` (admin, audited): switch or roll back, with `dry_run` (the preflight alone)
  and `ignore_requirements`.
- `site_update` with `releases`: turning releases on for a site that has files is refused in step 1; the
  answer says how. Step 2's `adopt` moves the existing tree into the first release by rename (same file
  system), seeds `shared/` from it and makes `current`, as the account.
- The helper gains `release_activate` and `release_prune`. Both run as the account, with the site, the
  deploy root and the names taken from the configuration on disk and re-validated, and fixed operations
  only (`symlinkat`, `renameat`, the `remove_tree` walk). The security page gets a row.
- The MCP texts: an agent deploying a new version calls `site_install` on the release site and checks
  with `path_check`; a rollback is `site_release_activate` with the release `site_releases` marks as
  previous; never a terminal.

## 13. Security

- Every name is checked: a release is a direct child of `<deploy root>/releases/`, and `current` must
  resolve to one. Shared entries are plain relative paths inside the release, their links pointing into
  `shared/` only, and made by agensio; the archive still cannot bring a link.
- Every write is the site's account's, through `O_NOFOLLOW` walks, never root's.
- `open_basedir` is the deploy root, so PHP reads releases and `shared/` and nothing beside them.
- Credential files are judged where they are, in `shared/`, by the hosting rules and the installer.
- `symlinks = "deny"` refuses the shared paths below the served root (point 4 of section 3). The
  recipe says so, and a site with both gets an access notice.
- No request path code changes (section 14), so the access, refuse, password and header rules apply to
  the served release as to any root.

## 14. The request path

Unchanged: the root is a resolved string, as today. A switch costs one reload. The watch is a timer on
worker 0. No A/B is needed for the steps below beyond the usual check that the rows stay flat.

## 15. Tests

- **Unit:**
  - the loader: `current` resolution and its refusals, presets inside the release, `open_basedir`, the
    secrets at their shared place, the keys and their refusals;
  - the cleanup's choice of what to keep;
  - the health findings, with a fake tree.
- **Integration (as the server's account):**
  - two releases installed through the control plane, the switch under a load of requests that never
    sees an error or a mixed page (each answer names its release);
  - the old release still answering a request in flight;
  - rollback; a release that would not load refused before the switch;
  - a shared `storage/` and `.env` surviving releases.
- **Root devbox:** the same with a site account and its pool. PHP's `__DIR__`, OPcache and
  `open_basedir` behave as section 3 says: a release's script sees its release, a switch serves the new
  code at once, with no php-fpm reload.
- **Interop:** a deploy root made by Deployer's layout (integer names, relative links) loads, and the
  watch follows its switch.

## 16. Steps

1. The layout, the keys, the loader, installing a release with its shared paths, the switch with its
   preflight and undo, the cleanup, `site_releases` and `site_release_activate`, health, the recipe.
2. The watch for switches made by other tools, and `adopt` for a site that has files.
3. Later: the `composer_install` task; releases for proxied applications once units are agensio's
   (F14).

## 17. Questions for the owner

1. **The watch** (section 9): in step 1, in step 2 as proposed, or never (agensio's own switches only)?
2. **Presets:** releases for `php`, `laravel`, `drupal` and `static`, refused for `wordpress` and `grav`?
3. **Install activates by default** (one call deploys), with `activate: false` to stage? Or always two
   calls?
4. **`keep` = 5** (Capistrano, Trellis), per site in the `releases` table? Or a `[control]` default?
5. **A site before its first release answers 404.** Or a 503 with `Retry-After`, as a site being set up
   rather than missing?
