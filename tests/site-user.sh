#!/usr/bin/env bash
# Acceptance test for a site with its own user, end to end and exactly the way an
# administrator (or the agent) does it: `agensio ctl site-create` answers with the
# commands to run as root, the test runs precisely those, creates the site, runs
# `agensio pools`, starts php-fpm, and then checks that `-t` passes, that the server
# restarts on that configuration, that the health check has no error, and that PHP and
# static files are served. Regression for 2026-09-19: the validators disagreed on the
# socket group, so no ownership satisfied both `-t` and a working server.
# Root only (devbox): docker run --rm --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox tests/site-user.sh build/agensio
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
[ "$(id -u)" = 0 ] || { echo "site-user: needs root; skipped"; exit 0; }
FPM=$(ls /usr/sbin/php-fpm* 2>/dev/null | head -1); [ -n "$FPM" ] || { echo "site-user: no php-fpm; skipped"; exit 0; }
PHPV=$(basename "$FPM" | sed 's/php-fpm//'); POOLD=/etc/php/$PHPV/fpm/pool.d
T=$(mktemp -d /tmp/agensio-siteuser.XXXXXX); chmod 755 "$T"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() { [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; [ -f "$T/fpm.pid" ] && kill "$(cat "$T/fpm.pid")" 2>/dev/null; rm -f $POOLD/agensio-t1-*.conf; userdel t1 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
id -u agensio >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin agensio
mkdir -p $T/sites.d $T/logs $T/run $T/state $T/www; chown agensio:agensio $T/sites.d $T/logs $T/state
cat > $T/agensio.toml <<CFG
include = ["sites.d/*.toml"]
[server]
workers = 1
user = "agensio"
pid_file = "$T/agensio.pid"
pools_run = "$T/run"
state_dir = "$T/state"
[log]
access = "$T/logs/access.log"
error = "$T/logs/error.log"
[control]
socket = "$T/run/control.sock"
audit = "$T/logs/audit.log"
sites_root = "$T/www"
provision = false   # this suite runs the prescribed commands itself; tests/provision.sh covers the helper
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:18097"]
root = "$T/www"
CFG
start() { "$BIN" -c $T/agensio.toml > $T/server.out 2>&1 & for _ in $(seq 1 50); do [ -S $T/run/control.sock ] && break; sleep 0.1; done; sleep 0.2; }
stop() { [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; sleep 0.4; }
start
check "server up, control socket answers" "admin" "$("$BIN" ctl status --socket $T/run/control.sock | sed -n 's/.*"role":"\([a-z]*\)".*/\1/p')"

# 1. site-create with a dedicated user: first answer is the root work to do.
create() { "$BIN" ctl site-create --domain t1.test --app php --root "$T/www/t1.test/web" --user t1 --https none --php-children 2 --listen-plain 127.0.0.1:18098 --yes --socket $T/run/control.sock; }
out=$(create); rc=$?
check "site-create answers with commands to run as root (waiting)" "1 yes" "$rc $(echo "$out" | grep -q '"waiting":true' && echo yes)"
cmds=$(echo "$out" | python3 -c 'import json,sys; [print(c) for c in json.load(sys.stdin)["run_as_root"]]')
check "the commands create the account without a home in the docroot, and the layout with the server's group" "yes yes" "$(echo "$cmds" | grep -q 'useradd --system --no-create-home' && echo yes) $(echo "$cmds" | grep -q 'chown t1:agensio' && echo "$cmds" | grep -q 'chmod 2750' && echo yes)"
while IFS= read -r c; do bash -c "$c" || echo "command failed: $c"; done <<< "$cmds"
check "the layout is t1:agensio 2750" "t1 agensio 2750" "$(stat -c '%U %G %a' $T/www/t1.test/web)"
out=$(create); rc=$?
check "site-create succeeds on the second call" "0 yes" "$rc $(echo "$out" | grep -q '"ok":true' && echo yes)"
check "next step names the real php-fpm unit" "yes" "$(echo "$out" | grep -q "systemctl reload php$PHPV-fpm" && echo yes)"
check "the site file gives the user site its own access log" "yes" "$(grep -q "^access_log = \"$T/logs/sites/t1.test.log\"" $T/sites.d/t1.test.toml && echo yes)"

# 2. The pool, php-fpm, the content.
rc=0; "$BIN" pools -c $T/agensio.toml > $T/pools.out || rc=$?
# The distribution's own version, found by discovery: the pool goes into its pool.d, tested by its php-fpm.
check "agensio pools writes the site's pool into $PHPV's pool directory (exit 3) with listen.group = agensio" "3 yes" "$rc $(grep -q '^listen.group = agensio' $POOLD/agensio-t1-*.conf && echo yes)"
printf '[global]\npid = %s/fpm.pid\nerror_log = %s/fpm.log\ninclude = %s/agensio-t1-*.conf\n' $T $T $POOLD > $T/fpm.conf
$FPM -y $T/fpm.conf -D; for _ in $(seq 1 50); do [ -S $T/run/agensio-t1-*-$PHPV.sock ] && break; sleep 0.1; done
check "socket t1:agensio 0660" "t1 agensio 660" "$(stat -c '%U %G %a' $T/run/agensio-t1-*-$PHPV.sock)"
printf '<?php $f = @tempnam(sys_get_temp_dir(), "probe"); echo "PHP ", PHP_VERSION, " uri=", $_SERVER["REQUEST_URI"], " as=", posix_getpwuid(posix_geteuid())["name"], " tmp=", ($f !== false && is_file($f)) ? "ok" : "FAIL";' > $T/www/t1.test/web/index.php
echo "static ok" > $T/www/t1.test/web/s.txt
chown t1:agensio $T/www/t1.test/web/index.php $T/www/t1.test/web/s.txt; chmod 640 $T/www/t1.test/web/index.php $T/www/t1.test/web/s.txt

# 3. What the report demanded: -t passes, a restart works, health is clean, PHP and static serve.
rc=0; "$BIN" -t -c $T/agensio.toml > $T/t.out 2>&1 || rc=$?
check "agensio -t exits 0 on the running configuration" "0" "$rc"; [ $rc = 0 ] || cat $T/t.out
curl -sS -o /dev/null -H 'Host: t1.test' http://127.0.0.1:18098/s.txt; sleep 1.2
check "health names the log the reload could not hand to the site user" "yes" "$("$BIN" ctl health --socket $T/run/control.sock | grep -q '"code":"log_not_readable_by_user","site":"t1.test"' && echo yes)"
check "next steps are separate commands, the reload not hidden behind an exit code" "yes" "$(echo "$out" | grep -q '"next_steps":\["agensio pools","systemctl reload php' && echo yes)"
stop; start
check "the server restarts on that configuration" "yes" "$([ -S $T/run/control.sock ] && "$BIN" ctl status --socket $T/run/control.sock >/dev/null 2>&1 && echo yes)"
health=$("$BIN" ctl health --socket $T/run/control.sock)
check "health answers and has no error finding" "yes 0" "$(echo "$health" | grep -q '"ok":' && echo yes) $(echo "$health" | grep -o '"severity":"error"' | wc -l | tr -d ' ')"
check "after the restart the log belongs to the site user's group and the finding is gone" "t1 no" "$(stat -c %G $T/logs/sites/t1.test.log) $(echo "$health" | grep -q 'log_not_readable_by_user' && echo yes || echo no)"
check "PHP served through the user's pool as t1, its temp directory usable" "yes" "$(curl -sS -H 'Host: t1.test' http://127.0.0.1:18098/index.php | grep -q 'PHP 8.* uri=/index.php as=t1 tmp=ok' && echo yes)"
check "the state directory parent lets the site user reach its own directory" "traversable yes" "$([ $(( 8#$(stat -c %a $T/state) & 1 )) = 1 ] && echo traversable) $(su -s /bin/sh t1 -c "test -w $T/state/t1/php/t1.test/tmp" && echo yes)"
check "static file served through the server's group" "200 static ok" "$(curl -sS -o /dev/null -w '%{http_code} ' -H 'Host: t1.test' http://127.0.0.1:18098/s.txt)$(curl -sS -H 'Host: t1.test' http://127.0.0.1:18098/s.txt)"
sleep 1.2
check "the site's own log exists, agensio:t1 0640" "agensio t1 640" "$(stat -c '%U %G %a' $T/logs/sites/t1.test.log 2>/dev/null)"
check "site show returns the content site" "php" "$("$BIN" ctl site t1.test --socket $T/run/control.sock | sed -n 's/.*"app":"\([a-z]*\)".*/\1/p' | head -1)"
check "validate through the socket agrees with -t" "yes" "$("$BIN" ctl validate --socket $T/run/control.sock | grep -q '"ok":true' && echo yes)"

# 4. served_dir (2026-10-22): the project's public/ served, its src/ required by PHP; the pool's
# open_basedir is the project already, so the pool stays as it was and PHP still reads nothing
# outside the project.
install -d -o t1 -g agensio -m 2750 $T/www/t1.test/web/public $T/www/t1.test/web/src
printf '<?php require __DIR__ . "/../src/lib.php"; echo lib(), " outside=", @file_get_contents("/etc/hostname") === false ? "blocked" : "READ", " docroot=", basename($_SERVER["DOCUMENT_ROOT"]);' > $T/www/t1.test/web/public/index.php
printf '<?php function lib() { return "lib=ok"; }' > $T/www/t1.test/web/src/lib.php
chown t1:agensio $T/www/t1.test/web/public/index.php $T/www/t1.test/web/src/lib.php; chmod 640 $T/www/t1.test/web/public/index.php $T/www/t1.test/web/src/lib.php
rc=0; "$BIN" ctl site-update t1.test --served-dir public --yes --reason "served_dir" --socket $T/run/control.sock > $T/sd.out 2>&1 || rc=$?
prc=0; "$BIN" pools -c $T/agensio.toml > /dev/null 2>&1 || prc=$?
check "site-update --served-dir public applies; the pool file is unchanged (agensio pools exits 0)" "0 0 public" "$rc $prc $("$BIN" ctl site t1.test --socket $T/run/control.sock | sed -n 's/.*"served_dir":"\([a-z]*\)".*/\1/p')"
[ $rc = 0 ] || cat $T/sd.out
check "public/index.php requires the project's src/, open_basedir keeps PHP inside the project" "lib=ok outside=blocked docroot=public" "$(curl -sS -H 'Host: t1.test' http://127.0.0.1:18098/index.php)"
check "the project's other files have no URL: the old s.txt and src/lib.php are 404" "404 404" "$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: t1.test' http://127.0.0.1:18098/s.txt) $(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: t1.test' http://127.0.0.1:18098/src/lib.php)"
health=$("$BIN" ctl health --socket $T/run/control.sock)
check "health has no error finding and names the any-script note for the php site" "0 yes" "$(echo "$health" | grep -o '"severity":"error"' | wc -l | tr -d ' ') $(echo "$health" | grep -q '"code":"php_any_script_runs","site":"t1.test"' && echo yes)"
echo "site-user: $pass passed, $fail failed"
[ $fail = 0 ] || { echo "--- error.log"; cat $T/logs/error.log; echo "--- server.out"; cat $T/server.out; echo "--- health"; echo "$health"; }
[ $fail = 0 ]
