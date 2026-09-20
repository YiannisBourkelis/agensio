#!/usr/bin/env bash
# The provisioning helper (F8): started as root with [control] provision = true (the
# default), one `site-create` with a site user creates the account, lays out the
# directories, writes the site, hands it its log and writes the php-fpm pool, with no
# terminal step. The helper's refusals are checked too: another site's directory, a
# symlink on the way, a system account name. Root only (devbox):
#   docker run --rm --init --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox tests/provision.sh build/agensio
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
[ "$(id -u)" = 0 ] || { echo "provision: needs root; skipped"; exit 0; }
FPM=$(ls /usr/sbin/php-fpm* 2>/dev/null | head -1); [ -n "$FPM" ] || { echo "provision: no php-fpm; skipped"; exit 0; }
PHPV=$(basename "$FPM" | sed 's/php-fpm//'); POOLD=/etc/php/$PHPV/fpm/pool.d
T=$(mktemp -d /tmp/agensio-provision.XXXXXX); chmod 755 "$T"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() { [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; [ -f "$T/fpm.pid" ] && kill "$(cat "$T/fpm.pid")" 2>/dev/null; rm -f $POOLD/agensio-t9.conf; for u in t9 t8; do userdel $u 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT
id -u agensio >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin agensio
mkdir -p $T/sites.d $T/logs $T/run $T/state $T/www; chown agensio:agensio $T/sites.d $T/logs $T/state; chmod 751 $T/state
cat > $T/agensio.toml <<CFG
include = ["sites.d/*.toml"]
[server]
workers = 1
user = "agensio"
pid_file = "$T/agensio.pid"
pools_run = "$T/run"
state_dir = "$T/state"
pools = "$POOLD"
[log]
access = "$T/logs/access.log"
error = "$T/logs/error.log"
level = "info"
[control]
socket = "$T/run/control.sock"
audit = "$T/logs/audit.log"
sites_root = "$T/www"
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:18197"]
root = "$T/www"
CFG
"$BIN" -c $T/agensio.toml > $T/server.out 2>&1 & for _ in $(seq 1 50); do [ -S $T/run/control.sock ] && break; sleep 0.1; done; sleep 0.2
check "the helper started before the privilege drop, the server runs as agensio" "yes agensio" "$(grep -q 'provisioning helper started' $T/logs/error.log && echo yes) $(ps -o user= -p $(cat $T/agensio.pid) | tr -d ' ')"
HP=$(pgrep -P $(cat $T/agensio.pid) | head -1)
check "the helper is a root child of the server holding one socket and no listener" "root 1 devnull" "$(ps -o user= -p $HP | tr -d ' ') $(ls -l /proc/$HP/fd | grep -c 'socket:') $(readlink /proc/$HP/fd/0 | grep -q null && echo devnull)"

# One call: account, layout, site, log, pool.
out=$("$BIN" ctl site-create --domain t9.test --app php --root "$T/www/t9.test/web" --user t9 --https none --php-children 2 --listen-plain 127.0.0.1:18198 --yes --reason provision --socket $T/run/control.sock); rc=$?
check "site-create succeeds in one call with no command handed back" "0 yes no" "$rc $(echo "$out" | grep -q '"ok":true' && echo yes) $(echo "$out" | grep -q 'useradd' && echo yes || echo no)"
check "done lists the account, the layout, the log and the pool" "yes yes yes yes" "$(echo "$out" | grep -q 'missing_account: account_add t9' && echo yes) $(echo "$out" | grep -q 'root_missing: site_layout' && echo yes) $(echo "$out" | grep -q 'readable by t9' && echo yes) $(echo "$out" | grep -q 'php-fpm pool' && echo yes)"
check "the account is a site account: system, nologin, home in the state directory" "/usr/sbin/nologin $T/state/t9" "$(getent passwd t9 | cut -d: -f7) $(getent passwd t9 | cut -d: -f6)"
check "the layout is t9:agensio 2750 from the domain directory down" "t9 agensio 2750 | t9 agensio 2750" "$(stat -c '%U %G %a' $T/www/t9.test) | $(stat -c '%U %G %a' $T/www/t9.test/web)"
check "the pool file was written by the helper with the server's group" "yes" "$(grep -q '^listen.group = agensio' $POOLD/agensio-t9.conf && echo yes)"
check "next steps no longer name agensio pools" "no" "$(echo "$out" | grep -q '"agensio pools"' && echo yes || echo no)"
printf '[global]\npid = %s/fpm.pid\nerror_log = %s/fpm.log\ninclude = %s/agensio-t9.conf\n' $T $T $POOLD > $T/fpm.conf
$FPM -y $T/fpm.conf -D; for _ in $(seq 1 50); do [ -S $T/run/agensio-t9.sock ] && break; sleep 0.1; done
printf '<?php echo "as=", posix_getpwuid(posix_geteuid())["name"];' > $T/www/t9.test/web/index.php; chown t9:agensio $T/www/t9.test/web/index.php; chmod 640 $T/www/t9.test/web/index.php
check "PHP runs as t9 through the pool the helper wrote" "as=t9" "$(curl -sS -H 'Host: t9.test' http://127.0.0.1:18198/index.php)"
sleep 1.3
check "the site's log is readable by t9 without a restart" "agensio t9 640" "$(stat -c '%U %G %a' $T/logs/sites/t9.test.log)"
h=$("$BIN" ctl health --socket $T/run/control.sock)
check "health has no error and no log finding" "yes 0 no" "$(echo "$h" | grep -q '"ok":' && echo -n yes) $(echo "$h" | grep -o '"severity":"error"' | wc -l | tr -d ' ') $(echo "$h" | grep -q log_not_readable && echo yes || echo no)"
check "every helper action is in the audit log" "yes yes yes" "$(grep -q 'provisioned missing_account' $T/logs/audit.log && echo yes) $(grep -q 'provisioned root_missing' $T/logs/audit.log && echo yes) $(grep -q 'sites (provision): created' $T/logs/audit.log && echo yes)"

# What the helper refuses.
out=$("$BIN" ctl site-create --domain t8.test --app static --root "$T/www/t9.test/web" --user t8 --https none --listen-plain 127.0.0.1:18199 --yes --reason repro --socket $T/run/control.sock)
check "another site's directory is never handed over (helper refuses)" "yes yes" "$(echo "$out" | grep -q 'another site; refused' && echo yes) $([ "$(stat -c %U $T/www/t9.test/web)" = t9 ] && echo yes)"
ln -s /etc $T/www/evil
out=$("$BIN" ctl site-create --domain evil.test --app static --root "$T/www/evil/web" --user t8 --https none --listen-plain 127.0.0.1:18199 --yes --reason repro --socket $T/run/control.sock)
check "a symlink on the way is refused, nothing created under it" "yes no" "$(echo "$out" | grep -q 'symlink' && echo yes) $([ -e /etc/web ] && echo yes || echo no)"
out=$("$BIN" ctl site-create --domain root.test --app static --root "$T/www/root.test/web" --user root --https none --listen-plain 127.0.0.1:18199 --yes --reason repro --socket $T/run/control.sock)
check "a system account name is refused before the helper is asked" "yes no" "$(echo "$out" | grep -q 'system account' && echo yes) $(grep -q 'account_add.*root' $T/logs/audit.log && echo yes || echo no)"
check "the helper answers only the server: the socketpair has no path" "0" "$(ls $T/run | grep -c helper)"
echo "provision: $pass passed, $fail failed"
[ $fail = 0 ] || { echo "--- error.log"; cat $T/logs/error.log; echo "--- audit"; cat $T/logs/audit.log; echo "--- last reply"; echo "$out"; }
[ $fail = 0 ]
