# Changelog

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
