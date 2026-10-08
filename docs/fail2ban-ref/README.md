# fail2ban, as its authors document it

The reference material behind `docs/fail2ban.md` and the renderers in `src/control/protection.*`:
fail2ban's own manuals, shipped configuration and the source of its journal backend, the pages
of the project wiki that bear on our use, and the filters of the WP fail2ban plugin. Kept here
the way `docs/rfc/` keeps the protocol specifications, so that a claim in a comment, a design
note or a commit message can be checked without a browser, and so that the renderers are
written against what fail2ban does rather than what one remembers it does. Read the relevant
file before changing a jail, a filter or the probe, and cite it (`jail.conf(5)`, `filtersystemd.py
addJournalMatch`).

## Provenance

| Set | Source | Version | License |
|---|---|---|---|
| `man/`, `config/`, `filtersystemd.py`, `fail2ban-README.md`, `FILTERS.txt`, `COPYING` | https://github.com/fail2ban/fail2ban, tag `1.1.0`, commit `61799e15e1dd4389dea0cc7595da0a287835a177` (2024-04-25); the version Debian 13 ships (`1.1.0-8`). 1.1.1 (2026-08-15) is the latest release. | 1.1.0 | GPL-2.0-or-later (`COPYING`) |
| `wiki/` | https://github.com/fail2ban/fail2ban/wiki (`fail2ban.wiki.git` at `196a74db8b8e2867f21cc408bc93ee87319931d5`, 2026-09-02, `wiki/COMMIT.txt`) | | the project's wiki, copyright its contributors |
| `wp-fail2ban/` | https://downloads.wordpress.org/plugin/wp-fail2ban.latest-stable.zip, `filters.d/` and `readme.txt` | plugin 5.4.2 (filters generated 2026-09-30) | GPL-3.0 (`wp-fail2ban/LICENSE`) |

The manuals are the groff sources rendered with `man -l | col -b`. Nothing here is installed by
the package (CMake installs named files from `docs/` only); it is reference text in the tree.
Refresh with the same commands when the Debian package moves to a new upstream version, and
diff `config/filter.d/` and `wp-fail2ban/` against what the renderers and `docs/fail2ban.md`
claim.

## What is where

| File | What it is | What in agensio depends on it |
|---|---|---|
| `man/jail.conf.5.txt` | the configuration reference: file order (`jail.conf`, `jail.d/*.conf`, `jail.local`, `jail.d/*.local`, alphabetical), every jail option (`backend`, `journalmatch`, `ignoreself`, `ignoreip`, `maxretry`, `findtime`, `bantime`, `banaction`, `filter[param=value]`), the filter file format (`failregex`, `ignoreregex`, `prefregex`, `datepattern`, `[Init]`, `[INCLUDES]`), the `%(name)s` and `<name>` substitutions | `render_jail` (every key it writes), the `agensio-login[paths="..."]` and `agensio-post[ignore="..."]` parameters, the rule that keeps `%` out of every rendered value (configparser interpolation) |
| `man/fail2ban-regex.1.txt` | the filter tester: a log file, a single line or `systemd-journal[journalflags=1]` as input, `-m` for a journal match, `--print-all-matched`, `-v` | how a rendered filter is checked by hand (`docs/fail2ban.md` section 4) |
| `man/fail2ban-client.1.txt`, `man/fail2ban-server.1.txt`, `man/fail2ban.1.txt` | the client (`status`, `status JAIL`, `reload`, `unban`, `-d` dumps the merged configuration, `-vvv -x start` traces a failing start), the server, the overview | the helper's `host_protection` probe (`fail2ban-client status`, `status <jail>`), `fail2ban_install_commands`, the operating section of the guide |
| `config/jail.conf` | the shipped defaults and every stock jail: `[DEFAULT]` (`ignoreself = true`, `bantime = 10m`, `findtime = 10m`, `maxretry = 5`, `backend = auto`, `banaction = iptables-multiport`), the `backend` note (`logpath` is not valid for `systemd`; a jail whose log is a file under a systemd default needs another backend and an empty `journalmatch`), the stock web jails on `port = http,https` | the thresholds and shape of our jails; the journal jails omit `logpath`; `ignoreself` is why a loopback test needs `ignoreself = false` (`tests/protection.sh`) |
| `config/fail2ban.conf` | the server's own settings (`logtarget`, `dbfile`, `dbpurgeage`) | nothing rendered; the troubleshooting hints |
| `config/paths-common.conf`, `paths-debian.conf`, `paths-fedora.conf` | the distribution path variables: `syslog_authpriv = /var/log/auth.log` (Debian) and `/var/log/secure` (Fedora/RHEL), `syslog_local0 = /var/log/messages`, `syslog_backend`, Fedora's `*_backend = systemd`; "systemd-backend does not need the logpath at all" | the log paths the failure tier looks for (`/var/log/auth.log` or `/var/log/secure`, `/var/log/syslog` or `/var/log/messages`); a future renderer could write `%(syslog_authpriv)s` instead |
| `config/filter.d/common.conf` | the prelude every syslog filter includes: `_daemon` (default `\S*`), `__prefix_line` per log type (`lt_file`, `lt_short`, `lt_journal`: `hostname daemon[pid]: `), `__daemon_re` allowing `daemon(detail)` | why a journal line is matched as `host identifier[pid]: message` and why `_daemon` is what pins the identity in a filter |
| `config/filter.d/drupal-auth.conf` | fail2ban's own Drupal filter over the Syslog module's `base_url|timestamp|type|ip|request_uri|referer|uid|link|message` line, `<ADDR>` and `<F-USER>` tags, **no `_daemon` of its own** | `agensio-drupal-auth`: the filter pins no identity, so the `SYSLOG_IDENTIFIER=drupal _UID=<uid>` words of the jail's match are what select Drupal's lines; the sample line in `tests/protection.sh` |
| `config/filter.d/sshd.conf` | the reference filter for a journal jail: `_daemon = sshd`, `journalmatch = _SYSTEMD_UNIT=sshd.service + _COMM=sshd`, `prefregex`, mode variants | the pattern of trusted fields (`_SYSTEMD_UNIT`, `_COMM`, `_UID` are journald's, `SYSLOG_IDENTIFIER` the writer's) that the alpha.49 report asked for |
| `config/filter.d/apache-auth.conf`, `nginx-http-auth.conf`, `nginx-botsearch.conf`, `nginx-bad-request.conf`, `apache-badbots.conf`, `traefik-auth.conf` | the stock web-server filters: 401 and auth failures, bot and scan paths, bad requests | the models for `agensio-auth`, `agensio-denied`, `agensio-scan` and `agensio-post` (`packaging/fail2ban/filter.d/`). `agensio-auth` reads agensio's error log as `nginx-http-auth` reads nginx's (`datepattern = {^LN-BEG}`, the same `YYYY/MM/DD HH:MM:SS` stamp), for the reason `apache-auth.conf`'s notes give: the 401 is the first step of every browser's login and no failure (alpha.58; until then it counted 401s in the access log); the others read the combined access log |
| `config/action.d/nftables.conf`, `nftables-multiport.conf`, `nftables-allports.conf` | the nftables action: its own `table inet f2b-table`, chain `f2b-chain` (hook input, priority -1, `reject` by default), a set `addr-set-<jail>` per jail; `nftables-multiport` is the `type=multiport` form | `banaction = nftables-multiport` in every rendered jail; fail2ban's table and agensio's `inet agensio` coexist, and health's probe counts a limit in any table |
| `filtersystemd.py` | the systemd backend: `journalmatch` parsing (`addJournalMatch`: words are ANDed, `+` starts an OR group), `journalflags` (default `4`, SYSTEM_ONLY, since 0.10.5 because of gh-2392; `1` reads user journals too), `journalpath`, `journalfiles`, `namespace`, and `formatJournalEntry` (the line the filter sees: `_HOSTNAME`, `SYSLOG_IDENTIFIER` or `_COMM`, `[SYSLOG_PID or _PID]:`, `MESSAGE`) | the match words `protection_input` builds and the helper's `journalctl` probe (the same words, `+` as its own argument); `backend = systemd[journalflags=1]` for an account of an ordinary uid; the `_daemon` facts above |
| `fail2ban-README.md`, `FILTERS.txt` | the project overview and the guide for writing and contributing filters (anchors, `<HOST>` vs `<ADDR>`, test cases) | the shape of the shipped filters |
| `wiki/Developing-Regex-in-Fail2ban.md` | the regex workflow with `fail2ban-regex -v`, `prefregex`, the tags (`<HOST>`, `<ADDR>`, `<F-USER>`, `<F-CONTENT>`), anchoring and catastrophic patterns | the login filter's spelling regex (alpha.45 and alpha.46: the disjoint grammar) |
| `wiki/Best-practice.md` | keep the watched log small (a web server's full access log is heavy for fail2ban: log failures to their own file), anchor regexes, order by frequency, incremental ban times | the open question of an access log for fail2ban alone (`docs/fail2ban.md` section 5) |
| `wiki/How-fail2ban-works.md`, `wiki/Troubleshooting.md`, `wiki/Proper-fail2ban-configuration.md` | `Found` without `Ban` means `maxretry`/`findtime`; `fail2ban-client -d` shows the merged configuration (`addjournalmatch` lines included); `fail2ban-client -vvv -x start` traces a failing start; never edit a `.conf` you did not write, use `.local`; `fail2ban-client unban IP` | the operating section of the guide; the `zz-local.conf` overrides it recommends |
| `wiki/How-fail2ban-substitution-resp.-runtime-interpolation-works.md` | `%(name)s` at load time, `<name>` at run time, `%(known/name)s`, parameters from the jail to the filter (`filter[param=value]`) | the `paths` and `ignore` parameters, the `%` rule |
| `wiki/Upgrading-to-v0.10.5-Breaks-WP-Fail2ban-and-Other-Jails.md` | the default `journalflags` became `4` in 0.10.5 and WP fail2ban's lines, written by php-fpm pools under user uids, vanished from the jails; the fix is `backend = systemd[journalflags=1]` | `FailureJail::user_journals` |
| `wp-fail2ban/wordpress-hard.conf`, `wordpress-soft.conf`, `wordpress-extra.conf` | the plugin's filters: `_daemon = (?:wordpress|wp)` (so the line must carry `wordpress(<host>)` or `wp`), hard failures (blocked user names, pingback errors, XML-RPC multicall, country blocks), soft failures (authentication failures, unknown users, pingback requests), extras | `agensio-wordpress-soft` and `-hard`; the WordPress section of the guide; the stand-in filters of `tests/protection.sh` |
| `wp-fail2ban/readme.txt` | the plugin's description, the syslog facility and tag options (`WP_FAIL2BAN_SYSLOG_TAG_HOST`, `WP_FAIL2BAN_AUTH_LOG`) | why the identity `wordpress(<host>)` carries the client's Host header and is not a match word |

## The facts that bind agensio

Each of these is in a file above; the renderers and the guide follow them.

1. A journal match is words ANDed within a group and groups ORed by `+`, the syntax of
   `journalctl` (`filtersystemd.py addJournalMatch`; `man/jail.conf.5.txt` sends to
   `journalctl(1)` and `systemd.journal-fields(7)`). `_UID`, `_PID`, `_COMM`, `_SYSTEMD_UNIT`
   are set by journald from the sender's credentials; `SYSLOG_IDENTIFIER` is the sender's own
   word. `config/filter.d/sshd.conf` matches on the trusted ones.
2. The systemd backend formats an entry as `hostname identifier[pid]: message`
   (`formatJournalEntry`), the identifier being `SYSLOG_IDENTIFIER` or, failing that, `_COMM`;
   a filter's `__prefix_line` matches that shape, and only a filter that sets `_daemon` pins the
   identifier (`common.conf`). `drupal-auth.conf` does not; the WP fail2ban filters do.
3. The backend opens the system journal alone by default (`journalflags` 4); `1` adds the
   users' journals, where journald files the lines of processes with an ordinary uid. The
   plugin's lines vanished for every user whose uid was 1000 or more when 0.10.5 changed the
   default (the wiki page).
4. `logpath` is invalid for a systemd jail (`jail.conf`, `paths-common.conf`); a systemd jail
   needs a `journalmatch` or it reads everything.
5. `ignoreself = true` by default: the host's own addresses are never banned; `ignoreip`
   adds more (`jail.conf.5`). Debian's `fail2ban` package depends on `python3-systemd`, so the
   backend is always available there.
6. Every value a jail or filter holds passes through configparser interpolation: `%` must be
   written `%%` or kept out (`jail.conf.5`, the interpolation page). Rendered values here never
   contain it (`check_login_path`, `spelling_regex` writes `\x25`).
7. A filter is tested with `fail2ban-regex`: a file or a single line against a filter file,
   or `systemd-journal[journalflags=1]` with `-m 'WORDS'`; `fail2ban-client -d` shows what the
   server loaded (`man/fail2ban-regex.1.txt`, the wiki).
8. The nftables action keeps its own table (`inet f2b-table`) and a set per jail; agensio's
   `inet agensio` table is another, and both may limit the same ports (`action.d/nftables.conf`).
9. Watching a busy access log is the expensive way (`Best-practice.md`); fail2ban's advice is
   a log of failures alone. agensio's attempt tier reads the combined access log as it is.
