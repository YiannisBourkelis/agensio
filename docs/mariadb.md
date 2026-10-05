# MariaDB on a Debian 13 VPS, beside agensio

A short guide for the administrator who runs agensio on a Debian 13 (trixie) VPS and needs a
database for the PHP sites on it: WordPress, Drupal, Kanboard and the like. It follows
MariaDB's Knowledge Base and Debian's own package notes (`/usr/share/doc/mariadb-server/
README.Debian.gz`), and it assumes one machine: the web server, php-fpm and MariaDB on the
same host, the sites talking to the database over its unix socket, and nothing of MariaDB
reachable from outside the VPS. Debian 13 ships MariaDB 11.8, a long-term release; WordPress
asks for 10.11 or later.

## 1. Install

```sh
sudo apt update
sudo apt install mariadb-server          # pulls mariadb-client; mariadb-backup is a separate package
systemctl status mariadb                  # active (running), enabled at boot
sudo mariadb -e "SELECT VERSION();"       # 11.8.x-MariaDB-...-deb13u1
```

`sudo mariadb` is the administrator's shell: the database's `root` account is authenticated
by the unix socket, so the Linux root (or anyone with `sudo`) is in, and no password exists
to leak or forget. Keep it that way; the Debian notes say never to delete that account.

The shell snippets below are written for bash: the `<<'EOF'` blocks and `&&` do not work in
fish. A fish user types `bash` first and `exit` afterwards, or writes the files with an editor.

## 2. What is already secure, and how to check it

The Debian package installs a locked-down server. There is no need to run
`mariadb-secure-installation`: Debian's README calls it useless on this package, and the
MariaDB Knowledge Base notes that most of its reasons no longer apply. Check the three facts
instead:

```sh
ss -ltnp | grep mariadbd                  # 127.0.0.1:3306 only, never 0.0.0.0 or [::]
sudo mariadb -e "SELECT User, Host FROM mysql.user;"
#   root, mysql, mariadb.sys, all @localhost, nothing else
sudo mariadb -e "SHOW GRANTS FOR 'root'@'localhost';"
#   the server answers (nothing to run):
#   GRANT ALL PRIVILEGES ON *.* TO `root`@`localhost` IDENTIFIED VIA mysql_native_password USING 'invalid' OR unix_socket WITH GRANT OPTION
sudo mariadb -e "SHOW DATABASES;"        # information_schema, mysql, performance_schema, sys: no test database
```

Every account is bound to `localhost`, there are no anonymous accounts and no test database,
and the server listens on the loopback address only (`bind-address = 127.0.0.1` in
`/etc/mysql/mariadb.conf.d/50-server.cnf`). The grant line is the one to read: `root` has two
authentication methods, a password method whose stored hash is the literal word `invalid`, so
no password can ever match it, `OR unix_socket`, so the Linux root gets in through the socket.
The `plugin` column of `mysql.user` shows `mysql_native_password` for `root` and `mysql`; that
view, kept for compatibility, lists only the first method, and the real record is
`mysql.global_priv` (`SELECT User, Host, JSON_DETAILED(Priv) FROM mysql.global_priv;`). The
proof is at the shell: `mariadb -u root` works for root and fails with `Access denied` for any
other Linux user, whatever password it offers. `mariadb.sys` holds `USAGE` and a read of
`global_priv` only and cannot log in; `mysql` is the account Debian's start script and
logrotate use, authenticated the same way as root. Nothing on agensio's side has to change:
`agensio ctl protection` renders the firewall for the public web ports, and port 3306 is not
public. Should you ever need to reach the database from your workstation, use an SSH tunnel
(`ssh -L 3306:127.0.0.1:3306 vps`), not a public port.

## 3. Harden a little further

Put your own settings in a new file; never edit the files the package owns, which an upgrade
may replace. `/etc/mysql/mariadb.cnf` includes the directory, whose files are read in
alphabetical order with later settings overriding earlier ones, so the name `99-` puts yours
after everything the packages ship (`50-server.cnf`, `60-galera.cnf`, whose options are
commented out unless you build a cluster). The `[mariadbd]` group is the one the server reads.

```ini
# /etc/mysql/mariadb.conf.d/99-local.cnf
[mariadbd]
bind-address        = 127.0.0.1    # the default, stated so that nothing else can change it
skip-name-resolve                  # no DNS at connect time; accounts are @localhost (socket) or @127.0.0.1 (TCP), see section 5
local_infile        = 0            # LOAD DATA LOCAL INFILE off: a compromised site must not read the server's files
max_allowed_packet  = 64M          # imports and large post bodies; raise only if a restore asks for it
```

```sh
sudo systemctl restart mariadb && systemctl status mariadb
sudo mariadb -e "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('bind_address','skip_name_resolve','local_infile','max_allowed_packet');"
```

If every client on the host uses the socket (PHP's `localhost` does), `skip-networking = 1`
removes the TCP listener altogether; leave it out while any tool connects to `127.0.0.1`.

## 4. Tune the few parameters that matter

MariaDB is shipped for a desktop. On a VPS shared with agensio and the PHP pools, give it a
quarter to a third of the memory; the Knowledge Base's 80 % rule is for a dedicated database
server. Add to the same file:

```ini
[mariadbd]
innodb_buffer_pool_size      = 512M    # the working set of your databases; see the table
innodb_log_file_size         = 256M    # redo log (96M by default); larger absorbs write bursts, slower crash recovery
innodb_flush_log_at_trx_commit = 1     # durable: every commit on disk; 2 trades a second of writes for speed
max_connections              = 100     # above the sum of the php-fpm children of all sites, plus a margin
tmp_table_size               = 64M     # in-memory temporary tables for sorts and GROUP BY (WordPress loves them)
max_heap_table_size          = 64M     # the two go together
table_open_cache             = 2000    # the default; raise when SHOW GLOBAL STATUS LIKE 'Opened_tables' keeps climbing
log_slow_query               = 1       # the slow query log: what to fix first
log_slow_query_time          = 2
log_slow_query_file          = /var/log/mysql/mariadb-slow.log
```

| VPS memory | agensio + php-fpm + system | `innodb_buffer_pool_size` | `innodb_log_file_size` | `max_connections` |
|---|---|---|---|---|
| 1 GB, or MariaDB capped at about 250 MB | the rest | 128M (the server's own default) | 96M (the default) | 40 |
| 2 GB | about 1.2 GB | 384M to 512M | 128M | 80 |
| 4 GB | about 2 GB | 1G | 256M | 100 |
| 8 GB | about 3 GB | 2G to 3G | 512M | 150 |

**A memory-limited VPS.** On 1 GB, or wherever MariaDB may take no more than about 250 MB,
leave the buffer pool at its default of 128M and cut what else is allocated whether used or
not: the MyISAM key buffer and the Aria page cache are 128M each by default although a
WordPress or Drupal site stores everything in InnoDB, and every open connection may use a few
MB of sort and join buffers, so `max_connections` is a memory setting here too (the php-fpm
pools of a 1 GB VPS run a handful of children in total).

```ini
[mariadbd]
innodb_buffer_pool_size      = 128M    # the default; the ceiling you set for this machine
innodb_log_file_size         = 96M     # the default too: the redo log is disk, not memory, so nothing to save here
innodb_flush_log_at_trx_commit = 1
key_buffer_size              = 8M      # MyISAM is not in use; 128M by default
aria_pagecache_buffer_size   = 32M     # internal temporary tables; 128M by default
max_connections              = 40      # the pools' children plus a margin: each connection is memory
tmp_table_size               = 32M
max_heap_table_size          = 32M
table_open_cache             = 400
thread_cache_size            = 16
performance_schema           = OFF     # the default, stated
log_slow_query               = 1
log_slow_query_time          = 2
log_slow_query_file          = /var/log/mysql/mariadb-slow.log
```

After a day, `systemctl status mariadb` shows the resident memory; if it sits well under the
ceiling and `Innodb_buffer_pool_reads` climbs fast, move the buffer pool up in 64M steps.

The slow log's directory must exist and belong to the server before the restart
(`sudo mkdir -m 2750 /var/log/mysql && sudo chown mysql /var/log/mysql`); Debian's logrotate
rule already rotates `/var/log/mysql/*.log`. The error log goes to the journal
(`journalctl -u mariadb`). Both InnoDB sizes can also be changed at run time with `SET GLOBAL`
(the redo log since 10.9, the buffer pool within its start-up maximum), but set them in the
file too, or the next restart forgets them. Leave `performance_schema` off (the default) and
the query cache off (the default): both cost more than they give on a web server.

Check what is in effect, and how it behaves after a day:

```sh
sudo mariadb -e "SHOW GLOBAL VARIABLES LIKE 'innodb_buffer_pool_size'; SHOW GLOBAL VARIABLES LIKE 'max_connections';"
sudo mariadb -e "SHOW GLOBAL STATUS WHERE Variable_name IN ('Threads_connected','Max_used_connections','Innodb_buffer_pool_reads','Innodb_buffer_pool_read_requests','Created_tmp_disk_tables','Slow_queries');"
```

`Max_used_connections` near `max_connections` means raise it (or the pool is leaking
connections); `Innodb_buffer_pool_reads` growing fast against `read_requests` means the
buffer pool is too small; many `Created_tmp_disk_tables` means `tmp_table_size` is.

## 5. A database and a user for a WordPress site

One database and one account per site, bound to `localhost`, with rights on that database
alone: a compromised plugin on one site then reaches nothing of the others. The names below
follow the site, `wp_example_db` for the database and `wp_example_user` for the account, so
that each line shows which is which (many administrators use one word for both); the
password comes from the system's random generator.

```sh
PW=$(openssl rand -base64 24)
sudo mariadb <<SQL
CREATE DATABASE wp_example_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'wp_example_user'@'localhost' IDENTIFIED BY '$PW';
GRANT ALL PRIVILEGES ON wp_example_db.* TO 'wp_example_user'@'localhost';
SQL
echo "$PW"                                     # into wp-config.php, then forget it here (history -c)
mariadb -u wp_example_user -p wp_example_db -e "SELECT 1;"   # the account works, as the site will use it
```

The same from fish, one statement per line (`set` instead of `=`, `$PW` expands inside double
quotes, and `set -e` forgets it):

```fish
set PW (openssl rand -base64 24)
mariadb -e "CREATE DATABASE wp_example_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mariadb -e "CREATE USER 'wp_example_user'@'localhost' IDENTIFIED BY '$PW';"
mariadb -e "GRANT ALL PRIVILEGES ON wp_example_db.* TO 'wp_example_user'@'localhost';"
echo $PW
mariadb -u wp_example_user -p$PW wp_example_db -e "SELECT 1;"
set -e PW
```

`GRANT ALL ... ON wp_example_db.*` is what WordPress's own guide gives: the application creates,
alters and drops its tables and those of its plugins. Nothing is granted on `*.*`, and
`FLUSH PRIVILEGES` is not needed after `GRANT`. In `wp-config.php`:

```php
define( 'DB_NAME',     'wp_example_db' );
define( 'DB_USER',     'wp_example_user' );
define( 'DB_PASSWORD', '...' );
define( 'DB_HOST',     'localhost' );     // localhost means the unix socket, /run/mysqld/mysqld.sock
define( 'DB_CHARSET',  'utf8mb4' );
```

On a site agensio manages with its own account (`user`), `wp-config.php` belongs to that
account with mode 0600 (`site-install` keeps it so), and the site's php-fpm pool connects
through the socket as that account; the database password never leaves the file.

**An application server that connects over TCP** (Node, Rails, Django, anything configured
with a `mysql://` URL) does not use the socket, and with `skip-name-resolve` its connection
from `127.0.0.1` is matched as `127.0.0.1`, never as `localhost`. An account bound to
`localhost` alone answers it with `Host '127.0.0.1' is not allowed to connect to this
MariaDB server` (error 1130). Give such an application a second entry of its account, bound
to the loopback address, with the same password and grant:

```sql
CREATE USER 'app_user'@'127.0.0.1' IDENTIFIED BY '...';
GRANT ALL PRIVILEGES ON app_db.* TO 'app_user'@'127.0.0.1';
```

and a URL of the form `mysql://app_user:...@127.0.0.1:3306/app_db`, with the address
spelled out: `localhost` in a URL may resolve to `::1`, and the server listens on IPv4
loopback only. On a site agensio manages, that URL belongs in the site's environment file
(`agensio ctl site-env-set NAME DATABASE_URL=...`), root's and 0600, never in the tree.
Drivers that accept a socket path (`socketPath` in Node's mysql2, `socket` in a Rails
`database.yml`) can use `/run/mysqld/mysqld.sock` instead and keep the single `@localhost`
account. Test the TCP path as the application will use it:
`mariadb -u app_user -p -h 127.0.0.1 app_db -e "SELECT 1;"`. The same
three statements, with other names, serve Drupal, Kanboard or any PHP application; a
Drupal database wants `utf8mb4_general_ci` or the default collation, and its installer says
so if not.

## 6. Everyday commands

| Task | Command |
|---|---|
| the databases and their sizes | `sudo mariadb -e "SELECT table_schema, ROUND(SUM(data_length+index_length)/1048576) AS mb FROM information_schema.tables GROUP BY table_schema;"` |
| the accounts and their grants | `sudo mariadb -e "SELECT User, Host FROM mysql.user;"` then `SHOW GRANTS FOR 'wp_example_user'@'localhost';` |
| a new password for a site | `sudo mariadb -e "ALTER USER 'wp_example_user'@'localhost' IDENTIFIED BY 'new';"` then change `wp-config.php` |
| remove a site's database and account | `sudo mariadb -e "DROP DATABASE wp_example_db; DROP USER 'wp_example_user'@'localhost';"` |
| dump one database | `sudo mariadb-dump --single-transaction --quick --routines --events --triggers wp_example_db \| gzip > wp_example_db-$(date +%F).sql.gz` |
| restore it | `zcat wp_example_db-2026-10-05.sql.gz \| sudo mariadb wp_example_db` (into an existing, empty database) |
| copy a site's database to a staging one | `sudo mariadb-dump --single-transaction wp_example_db \| sudo mariadb wp_staging_db` |
| what is running now | `sudo mariadb -e "SHOW FULL PROCESSLIST;"` and `sudo mariadb -e "KILL 1234;"` for a runaway query |
| server status in one line | `sudo mariadb-admin status` and `sudo mariadb-admin extended-status \| grep -E 'Threads_connected\|Questions'` |
| the slow queries | `sudo mariadb-dumpslow -s t /var/log/mysql/mariadb-slow.log \| head -40` |
| the error log | `journalctl -u mariadb -n 100` |
| check and repair tables | `sudo mariadb-check --all-databases --check` then `--auto-repair` if it reports one |
| reload the configuration | `sudo systemctl restart mariadb` (a restart; there is no reload for `[mariadbd]` options) |
| after a package upgrade | nothing: Debian's start script runs `mariadb-upgrade` for you after the new server starts |

`mariadb-dump` with `--single-transaction` takes a consistent snapshot of InnoDB tables
without locking the site out; `--routines --events --triggers` add what the default dump
leaves out. The Debian notes warn against restoring a dump of the `mysql` system database
taken from an older version: it brings back a password-authenticated root. Dump and restore
your sites' databases, not `mysql`.

## 7. Backups

A nightly dump of every database into a directory only root reads, kept for two weeks:

```sh
sudo install -d -m 0700 /var/backups/mariadb
sudo tee /etc/cron.daily/mariadb-dump > /dev/null <<'EOF'
#!/bin/sh
set -e
d=/var/backups/mariadb
mariadb-dump --all-databases --single-transaction --quick --routines --events --triggers | gzip > "$d/all-$(date +%F).sql.gz"
find "$d" -name 'all-*.sql.gz' -mtime +14 -delete
EOF
sudo chmod 755 /etc/cron.daily/mariadb-dump
sudo /etc/cron.daily/mariadb-dump && ls -la /var/backups/mariadb
```

Copy the directory off the VPS (the VPS provider's snapshots are not a backup of the database
at a consistent point; a dump is). A restore is tested once, into a scratch database, before
it is ever needed: `zcat all-2026-10-05.sql.gz | sudo mariadb` restores every database. For
databases of tens of gigabytes, `mariadb-backup` (package `mariadb-backup`) copies the data
files physically and restores faster; the Knowledge Base has its procedure.

## 8. When something is wrong

- **The service does not start.** `journalctl -u mariadb -n 50`; the usual causes are a typo
  in `99-local.cnf` (test with `sudo mariadbd --help --verbose > /dev/null`, which parses the
  files), a full disk, or a buffer pool larger than the memory left.
- **`Too many connections`.** A site opens one connection per PHP worker; `max_connections`
  must exceed the sum of the pools' children. `SHOW FULL PROCESSLIST` shows who holds them.
- **A site cannot connect.** Its account, password and `DB_HOST = 'localhost'` in the file;
  then `mariadb -u wp_example_user -p wp_example_db -e "SELECT 1;"` as a test from the shell. A site
  on its own account connects over the socket, which is world-accessible by design.
- **`Host '127.0.0.1' is not allowed to connect to this MariaDB server`** (error 1130, before
  any password is checked): the application connects over TCP and its account exists for
  `localhost` only, which is the socket. Add the `@'127.0.0.1'` entry of section 5, or point
  the driver at the socket. `Access denied for user` (1045 or 1698) is the other case: the
  account exists for that host and the password or the Linux user is wrong.
- **Disk.** `du -sh /var/lib/mysql`; the binary log is off by default (nothing in
  `/var/log/mysql` grows unless you enabled it); `OPTIMIZE TABLE` reclaims space after large
  deletes.
- **Upgrading Debian.** A major MariaDB version changes the on-disk format and cannot be
  undone in place: take a dump first, as the Debian notes insist.

## 9. References

- MariaDB Knowledge Base: `mariadb-secure-installation` (https://mariadb.com/kb/en/mariadb-secure-installation/),
  the `unix_socket` authentication plugin, Configuring MariaDB for Optimal Performance, InnoDB
  Buffer Pool, InnoDB Redo Log, Server System Variables, `mariadb-dump`, `mariadb-upgrade`,
  Slow Query Log Overview, all under https://mariadb.com/kb/en/.
- Debian's package notes: `/usr/share/doc/mariadb-server/README.Debian.gz` (the accounts a
  new install has, why the secure-installation script is not needed, upgrades and downgrades)
  and the commented defaults in `/etc/mysql/mariadb.conf.d/50-server.cnf`.
- WordPress: requirements (https://wordpress.org/about/requirements/) and Creating a Database
  for WordPress (https://developer.wordpress.org/advanced-administration/before-install/creating-database/).
