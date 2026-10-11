# Third-party bugs agensio works around

Bugs in code agensio does not own (php-fpm, OpenSSL, Asio, the kernel, the applications it
hosts) that changed what agensio does: a default, a check, a warning, a limit. Each entry says
what the bug is, how it showed here, what agensio does about it and where, and what to change
once upstream fixes it, so the workaround can be revisited instead of living on unexamined.

A change that works around a third-party bug adds its entry here in the same commit.

## How to check them

When asked to check the third-party bugs:

1. For every entry under **Open**: open each link; read the status, the latest comments and any
   linked pull request; then search the project's current tracker with the entry's search terms
   (php-src moved from bugs.php.net to GitHub issues in 2021, so a fix may live under a new
   number), and its changelog (for PHP: `NEWS` in php-src, the release announcements).
2. Fixed: note the first release that carries the fix and when the distributions agensio is
   installed on ship it (Debian stable, Ubuntu LTS, RHEL), then follow the entry's **When fixed**
   steps. Those are proposals to discuss with the owner, not changes to make on the spot.
3. Still open: say what moved since the last check (a comment, a patch, a maintainer's word).
4. Update **Last checked** and **Status** of every entry looked at, move a fixed one whose
   follow-up is done to **Checked: fixed upstream**, and report a short table: entry, status,
   what changed, what is proposed.

## Open

### php-fpm: `pm = ondemand` forks too few children for connections that arrive together

- **Upstream:** [bug #69724](https://bugs.php.net/bug.php?id=69724) "pm.ondemand forks fewer child
  workers than it should" (2015-05-28, PHP 5.5.25; patches attached, the last 2016-11-24;
  unassigned and Open since 2017-10-24); [bug #72935](https://bugs.php.net/bug.php?id=72935)
  "ONDEMAND: Race condition causes incoming connections hang" (2016-08-24, PHP 5.6.25, Open; its
  reporter calls it a possible duplicate of #69724); [PR #1308](https://github.com/php/php-src/pull/1308),
  the proposed fix (level-triggered polling, the parent taking the listening socket out of its poll
  set until a child reports its `accept()` through a per-pool pipe), closed unmerged on 2017-01-06
  because it targeted a security-only branch; in December 2024 the FPM maintainer (bukka) wrote on it
  that he had picked the issue up, "not too thrilled about introducing new pipes but can't currently
  think about better solution". No newer php-src issue or pull request found.
- **Last checked:** 2026-10-11. **Status:** open, unfixed in PHP 8.4.
- **The bug** (php-src PHP-8.4): php-fpm registers an ondemand pool's listening socket with an
  edge-triggered event (`FPM_EV_EDGE`, `EPOLLET`; `fpm_children_create_initial` in
  `sapi/fpm/fpm/fpm_children.c`) and on each event forks one child, none if a child is waiting in
  `accept()` (`fpm_pctl_on_socket_accept` in `fpm_process_ctl.c`). Connections arriving together
  can raise one event between them, so one child. Without keep-alive that costs a request's wait:
  the child that finishes calls `accept()` again and takes the missed connection. With FastCGI
  keep-alive (`FCGI_KEEP_CONN`) it does not: a child on a kept connection never calls `accept()`
  again while the connection stays open (`fcgi_accept_request` in `main/fastcgi.c`), so the missed
  connections wait in the socket's backlog until the next new connection, or until the web server
  gives up.
- **How it showed in agensio:** the alpha.66 report. Production (a Drupal site, generated pool,
  `ondemand`, 8 children): two bursts of about 120 requests within a second, each ending with
  exactly 4 x 504 at `read_timeout` (60 s); the same on alpha.56 and alpha.65. Every generated pool
  was `ondemand` with `keep_conn = true`. Reproduced with `bench/php/pool.sh`: 120 requests of a
  150 ms script over 30 connections, 3 to 5 x 504 per burst.
- **How agensio handles it** (0.1.0-alpha.67):
  - a generated pool with `pm = "ondemand"` (the default) gets `keep_conn = false` unless the site
    file sets it; `static` and `dynamic` keep it, their children waiting in `accept()`
    (`src/config.cpp`, the generated pool's FastCGI defaults);
  - `keep_conn = true` set by hand on a generated `ondemand` pool is a warning from `-t`, the error
    log and health, `php_keep_conn_ondemand` (`access_notices` in `src/config.cpp`, its fix in
    `src/control/commands.cpp`);
  - tests: `tests/pools.sh`, a burst on a cold `ondemand` pool and on a `dynamic` one; unit checks
    in `tests/tests.cpp` (the defaults, the warning once per pool);
  - documented in `docs/configuration.md` (the `php` keys table, `keep_conn`; the per-site users
    section), `docs/examples/php.md`, `docs/design-per-site-users.md`, the reference row of
    `keep_conn` (`docs/keys.md`), the MCP health text;
  - measured (`bench/results/php-pool-20261011-103217.md`, the two builds alternated): the burst
    from 3 to 5 x 504 to none (2.41 s); keep-alive off costs about 11 us of CPU per request
    (agensio 7.0 to 11.4, php-fpm 24.5 to 31.4 on a script that only echoes, 142k to 87k req/s
    there, under 0.5 % of a request that runs an application) and cuts p99 from 1.75 ms to 0.21 to
    0.31 ms (with keep-alive a child leaving after `pm.max_requests` breaks a kept connection).
  - What other servers do: nginx (`fastcgi_keep_conn off`), h2o (`fastcgi.timeout.keepalive: 0`),
    Apache `mod_proxy_fcgi` (no reuse unless `enablereuse=on`) and Caddy (a connection per request,
    no FastCGI keep-alive at all) open a connection per request by default, which is why the bug
    rarely shows behind them.
- **When fixed:**
  1. Note the first PHP release with the fix and when Debian stable and Ubuntu LTS ship it.
  2. On that PHP, run `bench/php/pool.sh BIN -m ondemand -o 'keep_conn = true'`: the burst must show
     no 504 with keep-alive.
  3. Then decide with the owner: keep-alive back for `ondemand` pools whose php-fpm carries the fix
     (the pool's `version`, `php-fpmX.Y -v`), the default staying off for older ones; or keep it
     off, since the 2026-10-11 measurement also showed a better p99 without it and a cost that only
     a near-empty script notices.
  4. Either way: the `php_keep_conn_ondemand` warning (only for a php-fpm without the fix, or
     removed), `tests/pools.sh`, the documents above, the CHANGELOG.
- **Search terms:** `ondemand`, `FPM_EV_EDGE`, `EPOLLET`, `fpm_pctl_on_socket_accept`, `69724`,
  `72935`; the history of `sapi/fpm/fpm/fpm_process_ctl.c` and `fpm_children.c`; `NEWS` lines under
  "FPM".

### php-fpm: a child holding a kept connection is killed after `request_terminate_timeout` with no request

- **Upstream:** [bug #78405](https://bugs.php.net/bug.php?id=78405) "FPM with keepalive: Kills worker
  when no request is seen for $terminate_timeout" (2019-08-12, PHP 7.3.8, moved to 8.1.3; Verified
  2022-02-25, "definitely caused by fastcgi_keep_conn being enabled"); its fix,
  [PR #8163](https://github.com/php/php-src/pull/8163) "only terminate workers that are actually
  running code", closed unmerged as stale on 2023-12-21.
- **Last checked:** 2026-10-11. **Status:** open.
- **The bug:** a child waiting on its kept connection between requests is still timed as if running
  the last request; when `request_terminate_timeout` passes before the next request on that
  connection, the master kills it ("execution timed out ... terminating" with no script). Bug
  #69860 (below) fixed the same timer for a request that does arrive; this is the case where none
  does.
- **How it affects agensio:** a generated pool never writes `request_terminate_timeout` (php-fpm's
  default is 0, off) and `extra` only sets `php_admin_value`, so generated `static` and `dynamic`
  pools, which keep their connections, are not exposed. A pool you run, with `keep_conn = true` set
  by hand and `request_terminate_timeout` in its file, is: the killed child closes the kept
  connection, agensio retries a GET or HEAD once on a dead reused connection, and another method
  answers 502. Not seen in a report yet.
- **How agensio handles it:** nothing in code; `keep_conn` is off by default for a pool agensio does
  not generate (`docs/examples/php.md` says when to turn it on). A possible step if it is ever seen:
  name `request_terminate_timeout` in that recipe's conditions for `keep_conn`.
- **When fixed:** nothing to change here; move the entry to the fixed list.
- **Search terms:** `78405`, `request_terminate_timeout keepalive`, `fpm_request_check_timeouts`.

## Checked: fixed upstream

- **php-fpm [bug #69860](https://bugs.php.net/bug.php?id=69860)** "php-fpm process accounting is
  broken with keepalive" (2015-06-17, PHP 5.5.26): a request arriving on a kept connection did not
  reset the child's start time, so the slow log and `request_terminate_timeout` counted across
  requests and killed good children. Fixed by commit `9814be4` (PRs #1426, #1427), closed
  2017-02-11; PHP 7.2 and later carry it, so the keep-alive agensio uses with `static` and
  `dynamic` pools is safe from it. Checked 2026-10-11; #78405 above is what remains.

## A new entry

```
### <project>: <the bug in one line>

- **Upstream:** links (tracker issue, pull request), dates, versions, status in its own words.
- **Last checked:** date. **Status:** open | fixed in <release>.
- **The bug:** the mechanism, with the source files and functions when known.
- **How it showed in agensio:** the report, the symptom, the reproduction.
- **How agensio handles it:** what changed (version), with the files, the warnings or health codes,
  the tests, the documents and the measurements.
- **When fixed:** what to reconsider or undo, and how to verify it first.
- **Search terms:** for the next check.
```
