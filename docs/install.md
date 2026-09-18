# Installing agensio

This guide is for the administrator who installs agensio on a server, desktop or
container host. It has two parts: the **directory layout** agensio uses on each platform
(fixed and predictable, so that a hand-made setup, a package and a control panel end up
with the same shape), and the **installation steps** per platform, which are completed
with the first tagged release on GitHub.

Status: agensio is pre-alpha. Every path marked *today* is what the current binary does;
paths marked *planned* are the defaults the release packages will ship with and that the
binary will adopt on that platform. Until then, anything not marked *today* is set
explicitly in the configuration file.

## 1. Principles

- **The configuration file can live anywhere** (`agensio -c FILE`), and every path in it
  may point anywhere. Relative paths in the file are resolved against the file's own
  directory, so a whole site can be moved with its configuration.
- **Without `-c`** the binary looks, in order, for `./agensio.toml`,
  `./config/agensio.toml`, `/etc/agensio/agensio.toml`,
  `/usr/local/etc/agensio/agensio.toml` and `/opt/homebrew/etc/agensio/agensio.toml`
  (*today*). `agensio reload`, `agensio -t` and `agensio pools` use the same search, so
  on an installed system no command needs a path.
- **agensio creates only what it owns**: the pid file, its log files, the per-user state
  directories (`agensio pools`), the certificate store. It never creates document roots
  or site directories; it checks their ownership (`agensio -t`, section 3 of this guide
  and `docs/design-per-site-users.md`).
- **One directory per concern**, never mixed: configuration, logs, runtime state that
  survives a reboot (certificates, sessions), runtime state that does not (pid, sockets),
  and site content.

## 2. Directory layout per platform

### Linux (Debian, Ubuntu, RHEL, Fedora, Alpine)

Filesystem Hierarchy Standard paths. `agensio` is the service user and group; site users
are separate accounts (section 3).

| purpose | path | owner, mode | status |
|---|---|---|---|
| binary | `/usr/sbin/agensio` (package) or `/usr/local/sbin/agensio` (tarball, source build) | root 0755 | today (package) |
| main configuration | `/etc/agensio/agensio.toml` | root:agensio 0640 | today (search path) |
| one file per site | `/etc/agensio/sites.d/<domain>.toml`, pulled in by `include = ["sites.d/*.toml"]`; `agensio ctl site-create` writes here | agensio:agensio 0750 dir, files 0640 | today |
| TLS material you manage yourself | `/etc/agensio/ssl/<domain>/` (`fullchain.pem`, `key.pem` 0600) | root 0700 | convention |
| server logs | `/var/log/agensio/access.log`, `/var/log/agensio/error.log` | agensio 0750 dir, files 0640 | planned default; today `logs/` next to the configuration file |
| per-site logs | `/var/log/agensio/sites/<domain>/access.log` or the site's own `log/` (section 3) | agensio:<site group> 0640 | today via `access_log`; ownership set at start |
| pid file | `/run/agensio.pid` | root 0644 | today |
| php-fpm pool sockets | `/run/php/agensio-<user>.sock` (Debian, Ubuntu, Alpine), `/run/php-fpm/agensio-<user>.sock` (RHEL, Fedora) | <user>:agensio 0660 | today (`server.pools_run`) |
| generated php-fpm pool files | `/etc/php/<version>/fpm/pool.d/agensio-<user>.conf` (Debian), `/etc/php-fpm.d/agensio-<user>.conf` (RHEL) | root 0644 | today (`agensio pools`, `server.pools`) |
| persistent state | `/var/lib/agensio/` | agensio 0750 | today (`server.state_dir`) |
| certificates (automatic) | `/var/lib/agensio/acme/account.key`, `/var/lib/agensio/acme/<domain>/key.pem` (0600), `fullchain.pem` | agensio 0700 dir | today (`server.acme.storage`) |
| per-user PHP state | `/var/lib/agensio/<user>/tmp/`, `/var/lib/agensio/<user>/sessions/` | <user> 0700 | today (`agensio pools`) |
| temporary spill files | the system temp directory, unlinked immediately (large upstream bodies and request bodies) | agensio | today |
| site content | `/var/www/<domain>/` (section 3) | site user | convention |
| systemd unit | `/usr/lib/systemd/system/agensio.service` (package) or `/etc/systemd/system/agensio.service` | root 0644 | today (package, `packaging/agensio.service`) |
| logrotate | `/etc/logrotate.d/agensio` (`postrotate: kill -USR1 $(cat /run/agensio.pid)`) | root 0644 | today (package) |

### macOS (Homebrew)

Everything under the Homebrew prefix, `/opt/homebrew` on Apple silicon and `/usr/local`
on Intel, written `$PREFIX` below. Nothing outside the prefix, so `brew uninstall`
removes it all.

| purpose | path | status |
|---|---|---|
| binary | `$PREFIX/bin/agensio` | planned (formula) |
| configuration | `$PREFIX/etc/agensio/agensio.toml`, `$PREFIX/etc/agensio/sites.d/` | today (search path) |
| logs | `$PREFIX/var/log/agensio/` | planned default; today `logs/` next to the configuration file |
| pid file | `$PREFIX/var/run/agensio.pid` | today (`/usr/local/var/run/agensio.pid`; the `/opt/homebrew` form is planned) |
| php-fpm pool sockets and files | `$PREFIX/var/run/agensio-<user>.sock`, `$PREFIX/etc/php/<version>/php-fpm.d/` | today (detected from `$PREFIX/etc/php`) |
| state, certificates, per-user PHP state | `$PREFIX/var/lib/agensio/`, `.../acme/`, `.../<user>/` | planned default; today `/var/lib/agensio` unless `server.state_dir` is set |
| site content | `$PREFIX/var/www/<domain>/` or `~/Sites/<domain>/` for a developer machine | convention |
| service | `$PREFIX/etc/agensio/homebrew.mxcl.agensio.plist`, `brew services start agensio` | planned |

Privileged ports (80, 443) need the service started as root with `server.user` set, as on
Linux; a developer setup on 8080/8443 runs as the logged-in user.

### Windows

agensio compiles on Windows and is not benchmarked there. Service integration, the
ACME client's file ownership and the FastCGI unix-socket path are not ported yet, so
Windows is a developer target until phase H says otherwise. The layout the port will
use follows the platform conventions:

| purpose | path | status |
|---|---|---|
| binary | `%ProgramFiles%\agensio\agensio.exe` | planned |
| configuration | `%ProgramData%\agensio\agensio.toml`, `%ProgramData%\agensio\sites.d\` | planned (today: `-c` is required, or `agensio.toml` in the working directory) |
| logs | `%ProgramData%\agensio\logs\` | planned |
| state and certificates | `%ProgramData%\agensio\state\`, `...\state\acme\` | planned |
| pid file | none; the service manager owns the process | planned |
| php-fpm | TCP only (`php = { socket = "127.0.0.1:9000" }`); no generated pools | today |
| site content | `C:\inetpub\<domain>\` or `%ProgramData%\agensio\www\<domain>\` | convention |
| service | Windows service `agensio` (`sc create`), `agensio reload` through a control event instead of SIGHUP | planned |

Windows path rules (backslash, drive letters, reserved device names, trailing dots) are
already enforced on request targets.

## 3. Recommended site layout

agensio does not impose this tree, but its ownership rules, the generated php-fpm pools,
the per-site logs and the certificate store fit it, and a control panel that creates it
gets a setup `agensio -t` accepts without exceptions. One directory per domain, one
system user per customer (or per site), agensio in the customer's group only where it
needs to write.

```
/var/www/example.com/
├── web/          site user, 0750   the document root (`root`), or the project with public/ for Laravel
├── log/          agensio:client8 0750   access.log, error.log for this site (agensio writes, customer reads)
├── private/      site user, 0700   files the site reads but never serves (.env can live here, uploads to review)
├── tmp/          site user, 0700   optional; the generated pool uses /var/lib/agensio/<user>/tmp by default
└── ssl/          root 0700         only for certificates you manage yourself; automatic ones stay in /var/lib/agensio/acme
```

The matching site file, `/etc/agensio/sites.d/example.com.toml`:

```toml
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https"

[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
user = "web35"
group = "client8"
app = "wordpress"
php = { children = 6, version = "8.3" }
access_log = "/var/www/example.com/log/access.log"
tls = "auto"
```

What follows from `user = "web35"`: a php-fpm pool running as web35 on
`/run/php/agensio-web35.sock`, `open_basedir` at the site root plus the user's private
`tmp/` and `sessions/`, the log file owned `web35:agensio` mode 0640 so the customer can
read it, and the rules `agensio -t` enforces: the root owned by web35 or root and not
writable by others, secrets (`.env`, `wp-config.php`, `.git`) not readable by others, the
`log/` directory owned by agensio and not writable by the site user (so no symlink can be
planted where agensio writes), and nothing (root, socket, state directory, log) shared
between two users. A panel such as ISPConfig maps directly: its `web` is `root`, `log`
is `access_log`, `ssl` is either `tls = { cert, key }` or left to `tls = "auto"`,
`cgi-bin` is a `handler = "cgi"` location.

Small servers with one administrator and no customers can skip the users: a site
without `user` runs PHP through whatever pool `php.socket` names, and everything is
owned by `agensio`. The layout still applies; only the owners change.

## 4. Installation steps

To be completed with the first release. Each platform section will hold: getting the
binary (package, archive or source build), the service user and directories with their
owners and modes, the service definition, the first site checked with `agensio -t`,
php-fpm pools with `agensio pools`, certificates, log rotation, reload, upgrade and
rollback.

### 4.1 Linux

0. **Packages.** Every release on GitHub carries a `.deb` and an `.rpm` built by the
   release workflow; they install the binary, the unit file, log rotation, the packaged
   configuration in `/etc/agensio` with a default site serving `/var/www/html`, create
   the `agensio` account and the `agensio-admin` group, and start the service when port
   80 is free. Steps 2 and 5 below are then already done.

   ```
   # Debian 12+, Ubuntu 22.04+: from the release page
   sudo apt install ./agensio_0.1.0~alpha.1_amd64.deb
   # or the APT repository (published once the release signing key is set up):
   curl -fsSL https://yiannisbourkelis.github.io/agensio/agensio.gpg | sudo tee /usr/share/keyrings/agensio.gpg >/dev/null
   echo "deb [signed-by=/usr/share/keyrings/agensio.gpg] https://yiannisbourkelis.github.io/agensio/apt stable main" | sudo tee /etc/apt/sources.list.d/agensio.list
   sudo apt update && sudo apt install agensio
   # Fedora, RHEL 9+ (COPR, once enabled):  sudo dnf copr enable yiannis/agensio && sudo dnf install agensio
   # Arch (AUR, once published):            yay -S agensio     # packaging/arch/PKGBUILD
   ```

   Upgrades keep your edits to `/etc/agensio` (conffiles); removing the package keeps
   the configuration, logs, certificates and content; purging removes the configuration
   and logs and keeps `/var/lib/agensio` (certificates) and `/var/www`.

1. **Binary.** `.deb` and `.rpm` packages, a static tarball, or a source build:

   ```
   cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
   cmake --build build
   sudo install -m 0755 build/agensio /usr/local/sbin/agensio
   ```

   Dependencies for a source build: a C++20 compiler (GCC 12+, Clang 16+), CMake 3.20+,
   Ninja, Asio headers (`libasio-dev`) and OpenSSL 3 (`libssl-dev`).

2. **Service user and directories** (the packages do this in their post-install step):

   ```
   sudo useradd --system --home /var/lib/agensio --shell /usr/sbin/nologin agensio
   sudo install -d -o root    -g agensio -m 0750 /etc/agensio
   sudo install -d -o agensio -g agensio -m 0750 /etc/agensio/sites.d   # the control API writes site files here
   sudo install -d -o agensio -g agensio -m 0750 /var/log/agensio /var/lib/agensio
   sudo install -d -o root    -g root    -m 0755 /var/www
   ```

3. **Configuration.** `/etc/agensio/agensio.toml`:

   ```toml
   include = ["sites.d/*.toml"]

   [server]
   user = "agensio"
   acme = { email = "admin@example.com" }

   [log]
   access = "/var/log/agensio/access.log"
   error = "/var/log/agensio/error.log"
   ```

   Then one file per site in `sites.d/` (section 3), and `sudo agensio -t` until it says
   the configuration is OK. `agensio -t --explain` shows what the presets expanded to.

4. **PHP sites.** `sudo agensio pools` writes the generated pool files and the per-user
   state directories; it exits 3 when php-fpm has to be reloaded
   (`systemctl reload php8.3-fpm`).

5. **Service.** systemd unit (shipped by the packages; to be added to the repository with
   the release):

   ```ini
   [Unit]
   Description=agensio web server
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   ExecStartPre=/usr/local/sbin/agensio -t
   ExecStart=/usr/local/sbin/agensio
   ExecReload=/usr/local/sbin/agensio reload
   PIDFile=/run/agensio.pid
   Restart=on-failure
   LimitNOFILE=1048576

   [Install]
   WantedBy=multi-user.target
   ```

   agensio starts as root, binds the ports, opens the logs, prepares the certificate
   store, and switches to `server.user` before it accepts the first connection.

6. **Certificates.** `tls = "auto"` on the site needs port 80 reachable from the internet
   for the validation; the first certificate arrives seconds after the start and the
   server reloads itself onto it. Nothing to schedule.

7. **Log rotation.** `/etc/logrotate.d/agensio` with `postrotate` sending `SIGUSR1`
   (`kill -USR1 $(cat /run/agensio.pid)`): every log file is reopened, nothing is lost.

8. **Changes.** Edit, `sudo agensio -t`, `sudo agensio reload` (or `systemctl reload
   agensio`): no connection is dropped. Restart-only settings: `workers`, `reuse_port`,
   `user`, `group`, `sendfile`, cache sizes; the reload says so when they changed.

9. **Upgrade and rollback.** Install the new binary next to the old one, `agensio -t`
   with the new binary, then `systemctl restart agensio`. Keep the previous binary; a
   rollback is the same restart with it. Configuration and state directories are never
   changed by an upgrade; a release that has to migrate a file says so in its notes.

### 4.2 macOS

To be written with the Homebrew formula: `brew install agensio`, `brew services start
agensio` for the plist, configuration under `$PREFIX/etc/agensio`, and the same
`agensio -t`, `agensio pools` (Homebrew php-fpm) and `agensio reload` steps as Linux.
Until then: build from source (`brew install cmake ninja asio openssl@3`, then the same
cmake commands) and run `build/agensio -c path/to/agensio.toml`.

### 4.3 Windows

To be written with the Windows port of the service integration. Until then: build with
Visual Studio 2022 or clang-cl through CMake, run `agensio.exe -c C:\path\agensio.toml`
from a console, PHP through a TCP php-fpm (or php-cgi) socket.

## 5. Checklist for a new server

1. Service user and the four directories (`/etc/agensio`, `/var/log/agensio`,
   `/var/lib/agensio`, `/var/www`) with the owners above.
2. One site per file in `sites.d/`, following section 3.
3. `agensio -t`, then `agensio pools` if PHP is involved, then start the service.
4. Watch `/var/log/agensio/error.log` for the certificate lines and the first
   `reloaded` message.
5. Log rotation and a backup of `/etc/agensio` and `/var/lib/agensio/acme`.
