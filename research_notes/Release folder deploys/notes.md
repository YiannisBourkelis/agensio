# Release-folder deployments of PHP applications: research notes

Gathered 2026-10-22 from primary sources only. Where a statement is my reading of source code
rather than something a document says, it is marked **(inference)**. Where a source is old or
I could not confirm a point, that is said in the same place.

Versions read:
- Capistrano 3.20.1 (released 2026-05-16). `master` and the tag have the same `deploy.rake`.
- Deployer 8.0.5 (2026-05-18), compared with 7.5.12. The recipes used here (`release`,
  `symlink`, `shared`, `cleanup`, `rollback`, `vendors`, `copy_dirs`, `lock`, `setup`) are the
  same in both apart from shell-quoting helpers. Deployer 8.0.0 came out on 2026-04-26, so 8.x
  is now the current major version, not 7.x.
- PHP source: the `PHP-8.4` branch of php-src.
- nginx and Caddy: the documentation online today. Trellis: `master`. Bedrock: 1.31.7
  (2026-10-06). Forge and Envoyer: their documentation as fetched today.

Source URLs (cited below by short name):
- CAP-RAKE https://github.com/capistrano/capistrano/blob/v3.20.1/lib/capistrano/tasks/deploy.rake
- CAP-PATHS https://github.com/capistrano/capistrano/blob/v3.20.1/lib/capistrano/dsl/paths.rb
- CAP-DEF https://github.com/capistrano/capistrano/blob/v3.20.1/lib/capistrano/defaults.rb
- CAP-CONF https://github.com/capistrano/capistrano/blob/v3.20.1/lib/capistrano/configuration.rb
- CAP-TE https://github.com/capistrano/capistrano/blob/v3.20.1/lib/capistrano/dsl/task_enhancements.rb
- CAP-TPL https://github.com/capistrano/capistrano/blob/v3.20.1/lib/capistrano/templates/deploy.rb.erb
- CAP-I18N https://github.com/capistrano/capistrano/blob/v3.20.1/lib/capistrano/i18n.rb
- CAP-STRUCT https://capistranorb.com/documentation/getting-started/structure/
- CAP-CONFDOC https://capistranorb.com/documentation/getting-started/configuration/
- CAP-RB https://capistranorb.com/documentation/getting-started/rollbacks/
- DEP-x https://github.com/deployphp/deployer/blob/v8.0.5/recipe/deploy/x.php (rendered at https://deployer.org/docs/8.x/recipe/deploy/x)
- DEP-COMMON https://github.com/deployphp/deployer/blob/v8.0.5/recipe/common.php
- DEP-FPM-DOC https://deployer.org/docs/8.x/avoid-php-fpm-reloading (source: https://github.com/deployphp/deployer/blob/master/docs/avoid-php-fpm-reloading.md)

---

## 1. Capistrano 3.x and Deployer 8.x (7.x is the same here)

### 1a. Capistrano 3.20.1

**Layout** (CAP-STRUCT):
```
current -> /var/www/my_app_name/releases/20150120114500/
releases/20150080072500 ... 20150120114500
repo/          (VCS data; a raw git repository for git)
revisions.log  (one line per deploy or rollback)
shared/        (linked_files and linked_dirs)
```
- The docs say `current` "is a symlink pointing to the latest release" and that it is updated
  only after a successful deployment (CAP-STRUCT).
- Each release gets `REVISION` and `REVISION_TIME` files (`deploy:set_current_revision`,
  `set_current_revision_time` in CAP-RAKE).
- `revisions.log` is `deploy_path.join("revisions.log")` (CAP-PATHS). Lines are appended with
  `echo "...message..." >> revisions.log` (`deploy:log_revision`, CAP-RAKE). The message is
  "Branch %{branch} (at %{sha}) deployed as release %{release} by %{user}" or "%{user} rolled
  back to release %{release}" (CAP-I18N).

**Release name**: the 14-digit timestamp `YYYYMMDDHHMMSS`.
- `def now; env.timestamp.strftime("%Y%m%d%H%M%S"); end` and
  `set(:release_path, releases_path.join(timestamp))` (CAP-PATHS).
- The time is UTC: `@timestamp ||= Time.now.utc` (CAP-CONF).
- The release path is absolute. `deploy_to` defaults to `/var/www/#{application}` (CAP-DEF,
  CAP-CONFDOC).

**linked_files / linked_dirs** are linked with `ln -s` to the absolute `shared_path.join(...)`,
so the links are absolute (CAP-RAKE):
```ruby
fetch(:linked_dirs).each do |dir|
  target = release_path.join(dir)
  source = shared_path.join(dir)
  next if test "[ -L #{target} ]"
  execute :rm, "-rf", target if test "[ -d #{target} ]"
  execute :ln, "-s", source, target
end
```
- Files are handled the same way: `rm` the file, then `ln -s`.
- A linked file must already exist in `shared/`, or `deploy:check:linked_files` exits 1. Linked
  directories are created with `mkdir -p` (CAP-RAKE).
- Both lists are empty by default. The generated `deploy.rb` suggests
  `append :linked_dirs, "log", "tmp/pids", "tmp/cache", "tmp/sockets", "public/system", "vendor", "storage"`
  (CAP-TPL). Note that this is a Rails template: its `vendor` is Bundler's, not Composer's.

**keep_releases**: `set_if_empty :keep_releases, 5` (CAP-DEF). The docs say "The last `n`
releases are kept for possible rollbacks" (CAP-CONFDOC).

**Atomic switch** (`deploy:symlink:release`, CAP-RAKE, exact code):
```ruby
tmp_current_path = release_path.parent.join(current_path.basename)
execute :ln, "-s", release_path, tmp_current_path
execute :mv, tmp_current_path, current_path.parent
```
- This runs `ln -s /deploy/releases/<ts> /deploy/releases/current`, then
  `mv /deploy/releases/current /deploy/`.
- The `mv` is a rename(2) of the new symlink over `/deploy/current`. Both paths are on the same
  filesystem.
- History:
  - Issue #346 (2013), "the current rm && ln -s is NOT atomic":
    https://github.com/capistrano/capistrano/issues/346
  - PR #1097 "Make symlink:release an atomic operation", merged 2014-11-17:
    https://github.com/capistrano/capistrano/issues/1097
  - Issue #1398 (2015): the `mv` fails when `current` is a real directory, not a symlink:
    https://github.com/capistrano/capistrano/issues/1398
  - All three are old, but the code above is what 3.20.1 ships.

**Rollback** (`deploy:rollback` = starting, started, reverting, reverted, publishing, published,
finishing_rollback, finished; CAP-RAKE and the framework tasks):
- `rollback_release_path` runs `ls -xt releases` (newest modification time first). It takes
  index 1, or the `ROLLBACK_RELEASE` named in the environment, and exits if there are fewer than
  two releases. Then the same `symlink:release` runs.
- `deploy:cleanup_rollback` then takes the newest release by mtime. If `current` does not point
  at it, it runs `tar -czf <deploy>/rolled-back-release-<name>.tar.gz` on it and `rm -rf`.
- The docs say: "Capistrano creates a tarball of the failed release in the deploy path, and then
  deletes the release folder". They also say that reverting the code and redeploying usually
  makes more sense, and that "capistrano-rails ... does nothing special with database
  migrations" (CAP-RB).
- **(inference)** The ordering is by directory mtime, not by name. If a failed deploy left a
  newer directory, index 1 is the release that is current now. In that case a "rollback"
  re-points `current` at itself and only archives and deletes the failed directory.

**A release that failed half way**:
- If the failure comes before `deploy:symlink:release`, the previous release keeps running. If
  it comes after, the state "may be inconsistent ... solved by executing
  `cap [stage] deploy:rollback`" (CAP-RB).
- On an exception during a deploy, `exit_deploy_because_of_exception` invokes `deploy:failed`
  (CAP-TE), which is empty by default (`task :failed`, CAP-RAKE).
- Nothing removes the half-built `releases/<ts>`. It keeps a valid 14-digit name and counts
  toward `keep_releases` (see section 6).

### 1b. Deployer 8.0.5 (7.5.12 is the same for everything here)

**Layout**:
```
deploy_path/
  .dep/        latest_release, releases_log (JSON lines), deploy.lock, repo (bare mirror), composer.phar
  releases/1 2 3 ...
  shared/
  current -> releases/3    (relative link with GNU ln)
  release -> releases/4    (only while a deploy is in progress)
```
- `deploy:setup` creates `.dep`, `releases` and `shared`.
- It refuses to go on when `current_path` is a real directory: "There is a directory (not
  symlink) at {{current_path}}. Remove this directory so it can be replaced with a symlink for
  atomic deployments." (DEP-setup)

**Release name**: an increasing integer.
```php
set('release_name', function () { return within('{{deploy_path}}', function () {
    $latest = run('cat .dep/latest_release || echo 0'); return strval(intval($latest) + 1); }); });
```
- If `releases/<name>` already exists, the deploy throws an error and suggests
  `dep deploy -o release_name=N`.
- Each release appends `{"created_at","release_name","user","target"}` to `.dep/releases_log`.
  `releases_list` is that log (last 300 lines) intersected with the directories that exist,
  newest first. All from DEP-release.

**Symlinks**:
- `bin/symlink` is `ln -nfs --relative` when `ln` supports `--relative`, else `ln -nfs`
  (DEP-COMMON). With GNU coreutils every Deployer link is therefore relative.
- `deploy:release` runs `{{bin/symlink}} releases/N {{deploy_path}}/release` (DEP-release).
  After the switch `current` holds the same relative target `releases/N`, because `release` and
  `current` sit in the same directory.
- Shared links are relative too: `releases/N/storage -> ../../shared/storage` **(inference from
  `ln --relative` semantics)**.

**shared_dirs / shared_files** (DEP-shared). Both are empty by default.
- For a directory:
  - If `shared/<dir>` is missing, `mkdir -p` it and `cp -r` the release's copy into it when the
    release has one.
  - Then `rm -rf {{release_path}}/<dir>`, `mkdir -p` the parent, and `{{bin/symlink}}
    shared/<dir> release/<dir>`.
- For a file:
  - Copy the release's file to shared when shared has none.
  - Remove it from the release, `touch` the shared copy, then symlink.
- Nested or duplicate shared dirs are refused ("Can not share same dirs").
- Recipe defaults:
  - Laravel: `shared_dirs ['storage']`, `shared_files ['.env']`, writable `bootstrap/cache`
    and `storage` (https://github.com/deployphp/deployer/blob/v8.0.5/recipe/laravel.php).
  - WordPress: `shared_files ['wp-config.php']`, `shared_dirs ['wp-content/uploads']`
    (https://github.com/deployphp/deployer/blob/v8.0.5/recipe/wordpress.php).
  - Drupal 8: `sites/{{drupal_site}}/files` shared, plus `settings.php` and `services.yml`
    (https://github.com/deployphp/deployer/blob/v8.0.5/recipe/drupal8.php).

**keep_releases**: `set('keep_releases', 10);` (DEP-COMMON, both 7.x and 8.x).

**Atomic switch** (DEP-symlink, exact code):
```php
set('use_atomic_symlink', function () { return commandSupportsOption('mv', '--no-target-directory'); });
task('deploy:symlink', function () {
    if (get('use_atomic_symlink')) {
        run("mv -T {{deploy_path}}/release {{current_path}}");
    } else {
        // Atomic symlink does not supported.
        // Will use simple two steps switch.
        run("cd {{deploy_path}} && {{bin/symlink}} {{release_path}} {{current_path}}"); // Atomic override symlink.
        run("cd {{deploy_path}} && rm release"); // Remove release link.
    }
});
```
- `mv -T release current` renames the `release` symlink over `current`, so the `release` name
  disappears in the same step.
- On the fallback path: GNU coreutils 8.27 (2017-03-08) made `ln -f A B` stop removing B before
  it creates the new link ("there is no longer a brief moment when B does not exist",
  https://github.com/coreutils/coreutils/blob/master/NEWS).
- The fallback only runs where `mv` lacks `-T`, which in practice means non-GNU userlands. I did
  **not** verify whether BSD, macOS or busybox `ln -f` is atomic.

**Deploy order** (DEP-COMMON):
- `deploy:prepare` = info, setup, lock, release, update_code, env, shared, writable.
- `deploy:publish` = symlink, unlock, cleanup, success.
- Laravel inserts vendors, `artisan:storage:link`, `artisan:optimize` and `artisan:migrate`
  before publish, and runs `artisan:reload` after it (that command needs Laravel 12.41 or later)
  (laravel.php).

**Rollback** (DEP-rollback):
- `rollback_candidate` is the first release older than `current` in `releases_list` whose
  directory holds no `BAD_RELEASE` file. `-o rollback_candidate=N` overrides it.
- The task runs `{{bin/symlink}} releases/$candidate {{current_path}}`. That is `ln -nfs`, not
  `mv -T`.
- It writes `"<timestamp>,<user>"` into `releases/<old current>/BAD_RELEASE`.
- `DIRTY_RELEASE` is written only by `deploy:push`, which uploads local changes into `current`
  (DEP-push, DEP-release).

**A release that failed half way**:
- `fail('deploy', 'deploy:failed')`, and `deploy:failed` is empty (DEP-COMMON).
- The lock `.dep/deploy.lock` stays unless the project has
  `after('deploy:failed', 'deploy:unlock')`. That line is in the `dep init` template
  (https://github.com/deployphp/deployer/blob/v8.0.5/src/Command/InitCommand.php, line 164).
  Without it the next deploy stops with "Deploy locked by ...". See DEP-lock.
- `current` is untouched, because the switch is in publish.
- The half-built `releases/N` stays on disk and in `releases_log`. The `release` symlink stays
  until the next `deploy:release` ("Clean up if there is unfinished release": `rm release`) or
  the next `deploy:cleanup`.
- The release is not marked BAD.
- **(inference)** Once a later deploy succeeds, that unmarked half-built release sits
  just below `current` in `releases_list`, so `dep rollback` would choose it. I found no
  Deployer issue that documents this. The closest is discussion #2724, where users override the
  candidate by hand: https://github.com/deployphp/deployer/discussions/2724

---

## 2. Envoyer and Laravel Forge zero-downtime deployments

### Envoyer (docs.envoyer.io; the documentation is thin)
- **Layout**: "Envoyer creates a releases directory in which your latest code is copied ... A
  current symlink is also created that links to the latest release." For a deployment path of
  `/home/forge/app.com`, the web root should be `/home/forge/app.com/current/public`
  (https://docs.envoyer.io/quick-start).
- The hook variable `project` is "The project's root directory (the directory which contains
  current, releases and storage)". `release` is "The current release path, within releases".
  `time` is "The current deployment formatted as YmdHis"
  (https://docs.envoyer.io/projects/deployment-hooks).
- **Release directory name**: not stated in the current docs. I could not confirm that it is the
  `time` value.
- **Fixed steps**: "Clone New Release", "Install Composer Dependencies (if ...configured)",
  "Activate New Release", "Purge Old Releases".
  - "if a deployment hook exits with a non-zero status code, the entire deployment will be
    cancelled".
  - The default plan is "downloading a tarball ..., installing the Composer dependencies (if
    configured), pointing the current symbolic link at the latest release, and finally purging
    any old deployments".
  - Source: https://docs.envoyer.io/projects/deployment-hooks
- **Shared things**:
  - Uploads go in "the application's storage directory". "Manage Linked Folders" creates "a
    symbolic link from your public directory to the storage directory".
  - For non-Laravel apps, "manually create a storage directory in the deployment path of your
    application (the same directory level as the current symbolic link)"
    (https://docs.envoyer.io/projects/servers).
  - `.env`: Envoyer will "sync the variables to a .env file in your chosen project path"
    (quick-start). How that file is linked into each release is **not documented** (not
    confirmed).
- **Retention**: project settings include "how many deployments to retain for the project". No
  default is stated (https://docs.envoyer.io/projects/management).
- **Rollback**: "Seamless Deployment Rollbacks" appears in the feature list
  (https://docs.envoyer.io/introduction.md). The mechanism is **not documented**.
- **PHP-FPM**:
  - The server setting "Reload FPM After Deployments" "Determines whether the PHP-FPM service
    will be reloaded after each deployment".
  - Connection health checks include "attempting to restart PHP FPM".
  - On non-standard PHP services, users are told to switch the setting off and add a custom hook
    that reloads the right service (https://docs.envoyer.io/projects/servers).
- The docs say nothing about realpath or OPcache.

### Laravel Forge (https://laravel.com/forge/docs/sites/deployments, which forge.laravel.com/docs/... now redirects to)
- "your new code is cloned into a special `releases` directory, and then a symbolic link is used
  to 'activate' the new code". "If any step in the deployment process fails, your site will
  continue to use the previous release."
- Zero-downtime is on by default for new sites and "must be configured at the time of creation —
  they cannot be added to existing sites later".
- **Macros**:
  - `$CREATE_RELEASE()` "creates the new release directory and clones your site's code into it".
  - `$ACTIVATE_RELEASE()` "creating a symbolic link from the `current` directory to the new
    release directory".
  - `$RESTART_QUEUES()`.
  - The script runs `cd $FORGE_RELEASE_DIRECTORY` after `$CREATE_RELEASE()`.
- **FPM**: the docs give this tip: "For zero-downtime deployments, it is unnecessary to reload
  the PHP-FPM service because every deployment is deployed to a new, uncached directory."
  - That claim holds only if the web server sends PHP the resolved path.
  - Forge's nginx template is not published in the docs.
  - Laravel's own deployment page shows `root /srv/example.com/public;` with
    `fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;` and no `DOCUMENT_ROOT`
    override (https://laravel.com/docs/13.x/deployment).
- **Retention**: "By default, Laravel Forge retains the last 4 deployments", configurable under
  Settings, Deployments.
- **Shared paths**: "automatically symlinked from a shared storage location into each new release
  directory".
  - Example: `/home/forge/example.com/current/storage` links to
    `/home/forge/example.com/storage`, which sits at the site root, not under `shared/`.
  - SQLite: `database/database.sqlite` links to `/home/forge/example.com/database.sqlite`.
  - "Laravel Forge automatically configures the `.env` file as a shared path".
- **Environment variables**: `FORGE_SITE_PATH` is "e.g., `/home/forge/mysite.com/current`",
  `FORGE_SITE_ROOT` is `/home/forge/mysite.com`, and `FORGE_RELEASE_DIRECTORY` is the release
  path.
- **Gotcha in the docs**: "You should not use zero-downtime deployments when using Laravel Octane
  ... will interfere".
- **Release directory naming and Forge's rollback mechanics**: not on the page; not confirmed.
- **Laravel-specific**: `php artisan storage:link` creates "a symbolic link from source directory
  `storage/app/public` to target directory `public/storage`"
  (https://laravel.com/docs/13.x/filesystem).
  - The link is absolute unless `--relative` is given
    (https://github.com/laravel/framework/blob/13.x/src/Illuminate/Foundation/Console/StorageLinkCommand.php).
  - In a release-folder deploy this is a symlink *below the public root*. It resolves to
    `.../releases/N/storage/app/public`, and `releases/N/storage` is itself a link into the
    shared storage, so the final target is outside the release **(inference)**.

---

## 3. The PHP side of switching `current` under a running php-fpm

### 3a. Realpath cache
- Defaults: `realpath_cache_size` "4M" (16K before PHP 7.0.16 and 7.1.2) and `realpath_cache_ttl`
  "120", both INI_SYSTEM (https://www.php.net/manual/en/ini.core.php#ini.realpath-cache-size).
  The source has `"4096K"` and `"120"`
  (https://github.com/php/php-src/blob/PHP-8.4/main/main.c, around lines 842-843).
- php.net: "Duration of time (in seconds) for which to cache realpath information for a given
  file or directory."
- **"Using open_basedir will disable the realpath cache."** (same page). In the source:
  `/* Disable realpath cache if an open_basedir is set */ CWDG(realpath_cache_size_limit) = 0;`
  (main.c, around lines 1882 and 2293).
- The cache lives in `virtual_cwd_globals`, so each FPM worker process has its own
  **(inference)**. Lookups go through `realpath_cache_find`, and an entry expires at
  `t + realpath_cache_ttl`
  (https://github.com/php/php-src/blob/PHP-8.4/Zend/zend_virtual_cwd.c, lines 389-445 and 582).
- `clearstatcache(true)` also clears the realpath cache
  (https://www.php.net/manual/en/function.clearstatcache.php).

### 3b. How a request's paths get resolved (php-src)
- **chdir to the script's directory**: `php_execute_script` calls
  `VCWD_CHDIR_FILE(primary_file->filename)` unless `SAPI_OPTION_NO_CHDIR` is set (main.c, around
  line 2586).
  - On non-ZTS builds (the usual php-fpm) `VCWD_CHDIR_FILE` is `virtual_chdir_file(path, chdir)`,
    a real chdir(2) to dirname(SCRIPT_FILENAME). `VIRTUAL_DIR` is defined only `#ifdef ZTS`
    (https://github.com/php/php-src/blob/PHP-8.4/Zend/zend_virtual_cwd.h, lines 52-54 and 334).
  - So the process's cwd becomes the physical directory the symlink pointed to when the request
    started **(inference from chdir(2) semantics)**.
- **Opened files get resolved names**: the plain-files wrapper builds `opened_path` with
  `expand_filepath()` (https://github.com/php/php-src/blob/PHP-8.4/main/streams/plain_wrapper.c,
  `_php_stream_fopen`).
  - That function uses mode `CWD_FILEPATH`, defined as "resolve symlinks if file is exist
    otherwise expand" (zend_virtual_cwd.h line 211;
    https://github.com/php/php-src/blob/PHP-8.4/main/fopen_wrappers.c, line 790).
  - The resolution goes through the realpath cache.
- **`__FILE__`**: "The full path and filename of the file in which it is written, with symlinks
  resolved." `__DIR__` is `dirname(__FILE__)`
  (https://www.php.net/manual/en/language.constants.magic.php). So `__DIR__` inside
  `current/public/index.php` names `.../releases/N/public`.
- **Relative includes** (https://www.php.net/manual/en/function.include.php):
  - A bare name ("file.php") is looked up in include_path, "then in the calling script's own
    directory and the current working directory". The calling script's directory is the dirname
    of its resolved compiled name.
  - "./" and "../" paths are relative to the cwd, and include_path is ignored.
  - So relative includes land in the release that was resolved when the request started (cwd and
    `__DIR__`), not wherever `current` points at include time **(inference from the two points
    above)**.
  - An include written as an absolute path through `current/` is resolved again on each include.
    If the switch happens mid-request, such includes can cross releases **(inference)**. Rasmus
    Lerdorf names this case in his draft RFC: "requests that started on A need to be able to
    finish on A" (https://wiki.php.net/rfc/resolve_symlinks).
- **open_basedir**: `php_check_specific_open_basedir` expands the basedir with `expand_filepath`
  (symlinks resolved) on every check and realpath's the target (fopen_wrappers.c lines 142-230).
  - **(inference)** A basedir of `.../current/` therefore admits only the release `current`
    names at that instant.
  - It never admits `shared/`, which is where the release's shared links resolve to.
  - So open_basedir has to cover the deployment root (releases plus shared).

### 3c. OPcache
- Defaults: `opcache.validate_timestamps` 1 (INI_ALL), `revalidate_freq` 2, `revalidate_path` 0,
  `use_cwd` 1 (https://www.php.net/manual/en/opcache.configuration.php; source:
  https://github.com/php/php-src/blob/PHP-8.4/ext/opcache/zend_accelerator_module.c, lines
  285-300).
- What php.net says:
  - validate_timestamps: "If enabled, OPcache will check for updated scripts every
    opcache.revalidate_freq seconds. When this directive is disabled, you must reset OPcache
    manually via opcache_reset(), opcache_invalidate() or by restarting the Web server".
  - revalidate_path: "If disabled, existing cached files using the same include_path will be
    reused."
  - use_cwd: "appends the current working directory to the script key".
  - `opcache_reset()` "resets the entire opcode cache"
    (https://www.php.net/manual/en/function.opcache-reset.php).
- Keys in the source (https://github.com/php/php-src/blob/PHP-8.4/ext/opcache/ZendAccelerator.c):
  - `accel_make_persistent_key`: "CWD and include_path don't matter for absolute file names". An
    absolute SCRIPT_FILENAME is its own key, unresolved.
  - With `revalidate_path=0`, `persistent_zend_resolve_path` does "lookup by 'not-real' path",
    for the main FastCGI request and for include_once. On a miss it looks up by the real path and
    then `zend_accel_add_key(key, bucket)`: "add another 'key' for the same bucket".
  - **(inference)** Once `/srv/app/current/public/index.php` has been compiled, that unresolved
    name is an alias of release N's script, whose filename is release N's real path. After the
    switch, the same name keeps returning release N's code, and its `__DIR__` keeps pointing
    into release N.
  - `do_validate_timestamps` does compare the resolved path with the cached filename. The
    comment reads "(if part of the path is a symlink than it possible that the user will change
    it) See bug #15140". For the main FastCGI script, however, the handle's `opened_path` is
    taken from the cached script (`persistent_stream_open_function`), so the comparison can pass
    and only the old file's mtime gets checked **(inference)**.
  - Deployer's docs state the effect bluntly: "PHP Opcodes get cached. And if `SCRIPT_FILENAME`
    contains _current_ symlink, on new deploy nothing updates." (DEP-FPM-DOC).
  - PHP bug #74268 "Opcache fails to detect directory symlink changes" (2017, PHP 7.1, still
    **Open**): "Sometimes OPcache alternates between the two different home.php pages"
    (https://bugs.php.net/bug.php?id=74268). Old report; I could find no maintainer's answer on
    it.
  - `opcache_invalidate()` resolves the name it is given before invalidating (ZendAccelerator.c,
    around lines 1425-1460). **(inference)** Called with a `current/...` path after the switch,
    it invalidates the new release's entry, not the stale alias.
- **revalidate_path=1**: the lookup goes by the resolved path every time. The resolution still
  goes through the realpath cache, so it can be up to `realpath_cache_ttl` stale unless
  open_basedir is set **(inference)**. Deployer recommends this setting for Apache (DEP-FPM-DOC).

### 3d. The standard fix: hand PHP the resolved path
- nginx: `$realpath_root` is "an absolute pathname corresponding to the root or alias
  directive's value for the current request, with all symbolic links resolved to real paths"
  (https://nginx.org/en/docs/http/ngx_http_core_module.html#var_realpath_root).
  - The source calls `ngx_realpath()` (realpath(3)) each time the variable is evaluated, once per
    request, with no cache
    (https://github.com/nginx/nginx/blob/master/src/http/ngx_http_variables.c,
    `ngx_http_variable_realpath_root`).
  - nginx's plain `root` is not resolved. Static files follow the symlink at each open(2), except
    where `open_file_cache` keeps descriptors; `open_file_cache_valid` defaults to 60 s (same
    docs page).
  - `disable_symlinks on from=$document_root` refuses symlinks only below the given prefix (same
    page). With it, a `current` root can coexist with a ban on symlinks inside the tree, but the
    ban also hits shared links such as `storage` and `uploads`.
- Deployer (DEP-FPM-DOC): "The correct fix is to configure your server set `SCRIPT_FILENAME` to
  a resolved path."
  ```
  fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
  fastcgi_param DOCUMENT_ROOT $realpath_root;
  ```
  - For Caddy the same page gives `php_fastcgi ... { resolve_root_symlink }`; for Apache,
    `opcache.revalidate_path=1`.
  - Deployer's own provisioning writes a Caddyfile with `root * {{deploy_path}}/current/...` and
    `resolve_root_symlink`
    (https://github.com/deployphp/deployer/blob/v8.0.5/recipe/provision/Caddyfile).
- Caddy: `resolve_root_symlink` "enables resolving it to its actual value. This is sometimes
  used as a deployment strategy ... Disabled by default to avoid repeated system calls"
  (https://caddyserver.com/docs/caddyfile/directives/php_fastcgi).
  - The source runs `filepath.EvalSymlinks(root)` per request. Its comment reads: "using a
    symlinked directory as root this could generate errors when symlink is changed without
    php-fpm being restarted; enabling this directive will set $_SERVER['DOCUMENT_ROOT'] to the
    real directory path"
    (https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/reverseproxy/fastcgi/fastcgi.go).
- Trellis nginx: `fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
  fastcgi_param DOCUMENT_ROOT $realpath_root;` with `root .../current/web`
  (https://github.com/roots/trellis/blob/master/roles/wordpress-setup/templates/wordpress-site.conf.j2,
  lines 29 and 280-281).
- Etsy's `mod_realdoc` for Apache (repository last pushed 2023):
  - It "does a realpath on the docroot symlink and sets the absolute path as the real document
    root for the remainder of the request", with `RealpathEvery 2` to limit how often.
  - "Requests that started before the symlink change will continue to execute on the previous
    symlink target and therefore will not be vulnerable to deploy race conditions".
  - Access rules must then name the release directories: `<Directory ~ ".../releases/\d{14}">`.
  - Source: https://github.com/etsy/mod_realdoc
- Rasmus Lerdorf's RFC "Resolve Symlinks Config Flag" (Draft, 2021-03-27, never adopted) would
  stop PHP's realpath() so OPcache entries can be reused across releases. It explains the A/B
  directory scheme and the mid-request consistency requirement
  (https://wiki.php.net/rfc/resolve_symlinks).

### 3e. Who says to reload php-fpm or reset OPcache
- **Deployer, `contrib/php-fpm.php`**:
  - "Do **not** reload php-fpm. Some user requests could fail or not complete in the process of
    reloading. Instead, configure your server properly".
  - The task still exists (`sudo systemctl reload php{{ver}}-fpm`) and prints a warning
    (https://github.com/deployphp/deployer/blob/v8.0.5/contrib/php-fpm.php).
- **Deployer, `contrib/cachetool.php`**: `after('deploy:symlink', 'cachetool:clear:opcache');`
  (https://github.com/deployphp/deployer/blob/v8.0.5/contrib/cachetool.php).
- **Envoyer**: the "Reload FPM After Deployments" toggle (section 2).
- **Trellis**: does both. nginx uses `$realpath_root`, *and* the `deploy_finalize_after` hook runs
  `sudo service php{{ php_version }}-fpm reload`.
  - Sources: https://github.com/roots/trellis/blob/master/roles/deploy/hooks/finalize-after.yml
    and the docs: "deploy_finalize_after refreshes WordPress settings and reloads php-fpm"
    (https://roots.io/trellis/docs/deployments/).
  - Its php role sets `opcache.validate_timestamps = 1` and `revalidate_freq = 60`
    (https://github.com/roots/trellis/blob/master/roles/php/defaults/main.yml).
- **Forge**: no reload needed (section 2).
- php-fpm `process_control_timeout`: "Time limit for child processes to wait for a reaction on
  signals from master ... Default value: 0"
  (https://www.php.net/manual/en/install.fpm.configuration.php). I did not verify what a reload
  does to in-flight requests beyond Deployer's warning.

### 3f. Other per-path caches and stored paths
- `.user.ini` files are cached per directory path for `user_ini.cache_ttl` "300"
  (https://www.php.net/manual/en/ini.core.php). php-fpm walks them from DOCUMENT_ROOT
  (https://github.com/php/php-src/blob/PHP-8.4/sapi/fpm/fpm/fpm_main.c, lines 650-700).
- Applications store resolved release paths:
  - Trellis deletes `_site_transient_theme_roots` ("Remove WordPress transient containing old
    release path").
  - It also rewrites the WordPress options `template_root` and `stylesheet_root` from the old
    release path to the new one after every deploy (finalize-before.yml and finalize-after.yml
    in https://github.com/roots/trellis/tree/master/roles/deploy/hooks).

---

## 4. Applications that update themselves in place vs release folders

**WordPress constants** (https://developer.wordpress.org/advanced-administration/wordpress/wp-config/):
- `DISALLOW_FILE_MODS`: "This will block users being able to use the plugin and theme
  installation/update functionality from the WordPress admin area. Setting this constant also
  disables the Plugin and Theme File editor".
- `AUTOMATIC_UPDATER_DISABLED`: "There might be reason for a site to not auto-update, such as
  customizations or host supplied updates."
- `WP_AUTO_UPDATE_CORE`: `false`, `true` or `'minor'` (the default).
- `DISALLOW_FILE_EDIT` disables the editor.

**WordPress auto-updates** (https://developer.wordpress.org/advanced-administration/upgrade/upgrading/):
- Since 5.6, new installs get minor and major core auto-updates "unless WordPress detects a
  version control checkout".
- The filter `automatic_updates_is_vcs_checkout` covers ".git, .hg, .svn etc ... in the WordPress
  directory or any of its parent directories".
- **(inference)** Deployer's default `archive` strategy leaves no `.git` in the release, so that
  check does not stop updates there.

**Bedrock** (https://github.com/roots/bedrock/blob/master/config/application.php, release 1.31.7):
- Sets `AUTOMATIC_UPDATER_DISABLED` true, `DISALLOW_FILE_EDIT` true and `DISALLOW_FILE_MODS` true
  ("Disable plugin and theme updates and installation from the admin").
- `$root_dir = dirname(__DIR__)`, and `.env` is read from `$root_dir`, which is the resolved
  release root.
- Content lives in `web/app`; `web/app/uploads/*` and `web/app/plugins/*` are gitignored
  (https://github.com/roots/bedrock/blob/master/.gitignore).
- Docs: "Running composer install from the Bedrock folder must be part of your deployment
  process." (https://roots.io/bedrock/docs/deployment/).

**Trellis** (https://github.com/roots/trellis/blob/master/roles/deploy/defaults/main.yml):
- `project_shared_children` defaults to `web/app/uploads`, which links to `shared/uploads`.
- `.env` is rendered from a template into each release with mode 0600; it is not shared.
- `project_copy_folders: [vendor]`.
- Docs (https://roots.io/trellis/docs/deployments/): "By default Trellis stores five previous
  releases, not including the current release". Also: database migrations "are not included as
  part of a Trellis deploy".

**Deployer's WordPress recipe** shares only `wp-config.php` and `wp-content/uploads` and sets no
`DISALLOW_*` constant.
- **(inference)** A plugin, theme or core update made from wp-admin writes into `releases/N`.
- It disappears at the next deploy, and is deleted with the release at cleanup.
- Where PHP cannot write the release, the update fails or WordPress asks for FTP credentials
  instead.

**Grav GPM** (https://learn.getgrav.org/17/cli-console/grav-cli-gpm):
- install, update and uninstall work on the instance's own folders ("uninstalling ... means
  deleting the folder physically").
- `selfupgrade` "only upgrades portions of your Grav instance, like system/ folder, vendor/
  folder, index.php, and others. Your user and images folders will never be touched".
- "If a resource is detected as symbolic link, it will automatically be skipped."

**Drupal**:
- The admin UI for updating modules and themes was removed in 11.2.0.
- `authorize.php`, FileTransfer and Updater are deprecated and will be removed in 12.0.0, "in
  favor of using composer or the forthcoming 'Automatic Updates' feature"
  (https://www.drupal.org/node/3512364).
- The module is now named "Update Status" and only reports available updates
  (https://www.drupal.org/node/3521054).
- The contributed Automatic Updates module: "For this module to work from the browser, Drupal
  must be able to change its own code base". Its 3.x console script exists for hosts where the
  web server cannot (https://www.drupal.org/project/automatic_updates).

---

## 5. Composer in release deploys

- **Deployer `deploy:vendors`** runs once per release, in the release
  (https://github.com/deployphp/deployer/blob/v8.0.5/recipe/deploy/vendors.php):
  ```php
  set('composer_action', 'install');
  set('composer_options', '--verbose --prefer-dist --no-progress --no-interaction --no-dev --optimize-autoloader');
  run('cd {{release_or_current_path}} && {{bin/composer}} {{composer_action}} {{composer_options}} 2>&1');
  ```
  - `bin/composer` is `.dep/composer.phar`, else `composer` on the PATH, else it downloads the
    installer into `.dep/`.
  - The task is in the deploy flows of Laravel, Symfony, Craft CMS, TYPO3, Statamic and others.
  - It is not in `common` or `wordpress`, and Drupal 8's flow is `deploy:prepare` plus
    `deploy:publish` only.
- **Copying from the previous release** is the opt-in `deploy:copy_dirs`
  (https://github.com/deployphp/deployer/blob/v8.0.5/recipe/deploy/copy_dirs.php).
  - Its comment reads "List of dirs to copy between releases. For example you can copy
    `node_modules` to speedup npm install".
  - It runs `cp -af {{previous_release}}/$dir {{release_path}}/...` when `previous_release` is
    set.
  - `copy_dirs` is empty by default, and no recipe puts the task in its flow.
- **No Deployer recipe shares `vendor`.**
- Trellis copies `vendor` from the previous release. Its comment: "These should not be part of
  project_shared_children since dependencies need to be atomic and tied to a deploy" (Trellis
  defaults, above).
- **(inference)** Composer's generated autoloader works out the code paths from the `realpath()`
  of the vendor and project directories when it is generated, relative to `__DIR__`
  (https://github.com/composer/composer/blob/main/src/Composer/Autoload/AutoloadGenerator.php,
  lines 217-225 and 1215-1217). A `vendor` symlinked into `shared/` would therefore encode the
  path of the release that last ran `composer install`.
- Envoyer's "Install Composer Dependencies" step runs per release before activation
  (deployment-hooks page). Forge's script runs `composer install` after
  `cd $FORGE_RELEASE_DIRECTORY` (Forge deployments page).

---

## 6. Cleanup of old releases and its safeguards

| Tool | Default kept | Order | Current protected? | Failed releases |
|---|---|---|---|---|
| Capistrano 3.20.1 | 5 (`keep_releases`) | `ls -x` (name, which is chronological for timestamps); only `/^\d{14}$/` names count | yes: `readlink current` is removed from the deletion list ("Current release was marked for being removed but it's going to be skipped") | not marked; counted as ordinary releases |
| Deployer 8.0.5 / 7.5 | 10 | `releases_list` (releases_log order, newest first) | no explicit check | stay; counted |
| Ansible `deploy_helper` (Trellis) | 5 + current | ctime, newest first | yes, the new release is excluded ("The current version does not count") | those with `DEPLOY_UNFINISHED` deleted first |
| Forge | 4 | not documented | not documented | not documented |
| Envoyer | setting, default not documented | not documented | not documented | not documented |

**Capistrano `deploy:cleanup`** (CAP-RAKE):
- Lists `releases`, splits valid (14 digits) from invalid names, and warns "Skipping cleanup of
  invalid releases on %{host}; unexpected foldername found (should be timestamp)".
- When `valid.count >= keep_releases` it deletes `valid - valid.last(keep_releases)`, minus the
  readlink of `current`, with `rm -rf` in batches of 100.
- The current-release guard came with PR #1922, merged 2017-10-12. The issue it fixed: "If there
  are many failed deployments ... deploy:cleanup ... will delete the release that is referenced
  by the 'current' symlink" (https://github.com/capistrano/capistrano/pull/1922). Since then
  current is kept "IN ADDITION to the last X releases".
- Rollback cleanup is separate: `deploy:cleanup_rollback` archives and deletes the
  rolled-back-from release (section 1a).

**Deployer `deploy:cleanup`** (DEP-cleanup, exact code):
```php
run("cd {{deploy_path}} && if [ -e release ]; then rm release; fi");
if ($keep > 0) {
    foreach (array_slice($releases, $keep) as $release) {
        run("$sudo rm -rf {{deploy_path}}/releases/$release");
    }
}
```
- `cleanup_use_sudo` defaults to false.
- `keep_releases <= 0` deletes nothing.
- There is no guard for `current` or for the previous release. The task is safe in the standard
  flow only because it runs after `deploy:symlink`, when current is the newest release
  **(inference)**.
- After a `dep rollback`, current is the second entry. A manual cleanup with `keep_releases = 1`
  would delete it **(inference)**.

**Ansible deploy_helper**, which Trellis uses
(https://github.com/ansible-collections/community.general/blob/main/plugins/modules/deploy_helper.py):
- `state=finalize` removes the `DEPLOY_UNFINISHED` marker from the new release, then switches.
  The switch is `os.symlink(source, "current.DEPLOY_UNFINISHED")` followed by `os.rename(tmp,
  current)`, with an absolute source.
- With `clean` (default true) it then removes every release still holding the marker, and keeps
  the newest `keep_releases` by ctime, not counting the new one.
- `keep_releases` must be at least 1 on finalize. Release names default to `%Y%m%d%H%M%S`.
- Trellis's rollback writes `DEPLOY_UNFINISHED` into the release it rolls back from, so the next
  clean deletes it (https://github.com/roots/trellis/blob/master/roles/rollback/tasks/main.yml).

---

## What these facts mean for a server that resolves the root once per configuration load (my synthesis, not from the sources)

1. **Every tool switches `current` with a rename(2) of a new symlink in the deploy root.**
   - Capistrano: `mv releases/current <root>/`.
   - Deployer: `mv -T release current`.
   - deploy_helper: `os.rename`.
   - Forge and Envoyer document a symlink but not the command.
   - None of them reloads the web server, and the PHP-side fix they recommend is the web server
     resolving the root per request (nginx `$realpath_root`, Caddy `resolve_root_symlink`,
     Apache mod_realdoc). A root resolved only at load therefore stays on the old release after a
     deploy, for static files and for SCRIPT_FILENAME alike, until the next reload. After
     `keep_releases` more deploys (Forge 4, Capistrano 5, Trellis 5 plus current, Deployer 10),
     cleanup deletes that release, because their "never delete current" guards (Capistrano, Ansible)
     only know about the link, not about what the web server has pinned.
2. **Resolve per request, or detect the switch.** Resolving per request (or on a cheap periodic
   check of the link, as mod_realdoc's `RealpathEvery`) and passing the resolved path as both
   SCRIPT_FILENAME and DOCUMENT_ROOT avoids PHP's OPcache-alias and realpath-cache staleness. It
   also keeps an in-flight request in one release, which is the property Rasmus's RFC and
   mod_realdoc both name. The `current` link gets a new inode on every deploy, so an lstat or
   readlink of it detects the switch.
3. **Never infer the live release from `releases/`.** Failed deploys leave newer directories there
   (Capistrano timestamps, Deployer integers plus a dangling `release` link). Follow `current`.
4. **Shared paths are symlinks below the public root.** Examples: `storage`, `.env`,
   `wp-content/uploads`, Laravel's `public/storage`. They resolve outside the release (Capistrano
   and Forge with absolute links, Deployer with relative `../../shared/...` links). Two
   consequences:
   - A policy of "realpath must stay under the root" refuses them, and so does nginx's
     `disable_symlinks on`.
   - open_basedir has to name the deploy root (releases and shared), not `current` or one
     release, because PHP resolves both sides of the check.
5. **open_basedir disables PHP's realpath cache.** That removes one source of staleness (the
   120 s TTL) in per-site pools. The OPcache "not-real path" alias of an unresolved
   SCRIPT_FILENAME remains, so the resolved path still has to come from the web server.
