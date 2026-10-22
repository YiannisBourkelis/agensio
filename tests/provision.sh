#!/usr/bin/env bash
# The provisioning helper (F8): started as root with [control] provision = true (the
# default), one `site-create` with a site user creates the account, lays out the
# directories, writes the site, hands it its log and writes the php-fpm pool, with no
# terminal step. The helper's refusals are checked too: another site's directory, a
# symlink on the way, a system account name. Root only (devbox):
#   docker run --rm --init --user root --sysctl net.ipv4.ip_unprivileged_port_start=1024 -v "$PWD:$PWD" -w "$PWD" agensio-devbox tests/provision.sh build/agensio
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
[ "$(id -u)" = 0 ] || { echo "provision: needs root; skipped"; exit 0; }
FPM=$(ls /usr/sbin/php-fpm* 2>/dev/null | head -1); [ -n "$FPM" ] || { echo "provision: no php-fpm; skipped"; exit 0; }
PHPV=$(basename "$FPM" | sed 's/php-fpm//')
T=$(mktemp -d /tmp/agensio-provision.XXXXXX); chmod 755 "$T"
POOLD=$T/pool.d   # the version's pool directory, root's [php.runtimes] (docs/configuration.md 7b)
P9() { ls $POOLD/agensio-t9-*.conf; }   # a pool per site: agensio-<user>-<8 hex of the domain>
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() { [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; for f in $T/fpm.pid $T/fpm99.pid; do [ -f $f ] && kill "$(cat $f)" 2>/dev/null; done; for u in t9 t8 t7 t6 t5; do userdel $u 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT
id -u agensio >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin agensio
mkdir -p $T/sites.d $T/logs $T/run $T/state $T/www $POOLD $T/pool99.d; chown agensio:agensio $T/sites.d $T/logs $T/state; chmod 751 $T/state
# Each version's php-fpm runs before any site has a pool there, as a distribution's does with its www
# pool: the helper tests a version's configuration and reloads its master itself (SIGUSR2 through the pid
# file php-fpm.conf names: these masters have no systemd unit; docs/design-php-versions.md 6.1).
# A second version standing in for 8.5 (docs/design-php-versions.md 12): the same binary, its own files.
fpmconf() {  # FILE PIDFILE POOLDIR PLACEHOLDER-SOCKET
  printf '[global]\npid = %s\nerror_log = %s.log\n[placeholder]\nuser = nobody\ngroup = nogroup\nlisten = %s\npm = ondemand\npm.max_children = 1\ninclude = %s/agensio-*.conf\n' "$2" "$1" "$4" "$3" > "$1"
}
fpmconf $T/fpm.conf $T/fpm.pid $POOLD $T/run/placeholder.sock
fpmconf $T/fpm99.conf $T/fpm99.pid $T/pool99.d $T/run/placeholder99.sock
fpm_start() {  # CONF PIDFILE: a master, started and listening (its notes in CONF.start)
  $FPM -y "$1" -D 2> "$1.start"; for _ in $(seq 1 50); do [ -s "$2" ] && break; sleep 0.1; done; sleep 0.2
}
fpm_restart() { local p; p=$(cat "$2" 2>/dev/null); [ -n "$p" ] && kill "$p" 2>/dev/null; for _ in $(seq 1 50); do [ -n "$p" ] && kill -0 "$p" 2>/dev/null || break; sleep 0.1; done; rm -f "$2"; fpm_start "$1" "$2"; }
fpm_start $T/fpm.conf $T/fpm.pid
fpm_start $T/fpm99.conf $T/fpm99.pid
cat > $T/agensio.toml <<CFG
include = ["sites.d/*.toml"]
[server]
workers = 1
user = "agensio"
protocols = ["h2c", "h2", "h1"]
pid_file = "$T/agensio.pid"
pools_run = "$T/run"
state_dir = "$T/state"
php_version = "$PHPV"
[log]
access = "$T/logs/access.log"
error = "$T/logs/error.log"
level = "info"
[control]
socket = "$T/run/control.sock"
audit = "$T/logs/audit.log"
sites_root = "$T/www"
[php.runtimes."$PHPV"]
fpm = "$FPM"
conf = "$T/fpm.conf"
pools = "$POOLD"
[php.runtimes."9.9"]
fpm = "$FPM"
conf = "$T/fpm99.conf"
pools = "$T/pool99.d"
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
check "the log hand-over under done was verified on disk, and the server logged no 'cannot chown' for it" "agensio t9 640 0" "$(stat -c '%U %G %a' $T/logs/sites/t9.test.log) $(grep -c 'cannot chown .*t9.test.log' $T/logs/error.log)"
check "the account is a site account: system, nologin, home in the state directory" "/usr/sbin/nologin $T/state/t9" "$(getent passwd t9 | cut -d: -f7) $(getent passwd t9 | cut -d: -f6)"
check "the layout is t9:agensio 2750 from the domain directory down" "t9 agensio 2750 | t9 agensio 2750" "$(stat -c '%U %G %a' $T/www/t9.test) | $(stat -c '%U %G %a' $T/www/t9.test/web)"
check "the pool file was written by the helper with the server's group, one per site, tested by its php-fpm" "yes 1" "$(grep -q '^listen.group = agensio' $(P9) && echo yes) $(ls $POOLD | grep -c '^agensio-t9-[0-9a-f]\{8\}\.conf$')"
check "next steps no longer name agensio pools" "no" "$(echo "$out" | grep -q '"agensio pools"' && echo yes || echo no)"
check "the helper reloaded $PHPV's running master itself, and t9's socket was up before the answer" "yes" "$([ -S $T/run/agensio-t9-*-$PHPV.sock ] && echo "$out" | grep -q 'up before agensio switched to it' && echo yes)"
printf '<?php echo "as=", posix_getpwuid(posix_geteuid())["name"];' > $T/www/t9.test/web/index.php; chown t9:agensio $T/www/t9.test/web/index.php; chmod 640 $T/www/t9.test/web/index.php
check "PHP runs as t9 through the pool the helper wrote" "as=t9" "$(curl -sS -H 'Host: t9.test' http://127.0.0.1:18198/index.php)"
# The PHP versions through the helper (docs/configuration.md 7b): as root, php-fpm's configuration test
# runs, and its process_control_timeout says whether a reload cuts requests in flight.
check "php: through the helper the configuration test runs as root, and the reload's cost is read from it" "True 0s True" \
  "$(curl -sS --unix-socket $T/run/control.sock http://control/v1/php | python3 -c 'import json,sys; d=json.load(sys.stdin); r=[x for x in d["runtimes"] if x["version"] == "8.4"][0]; print(r.get("config_test", {}).get("ok"), r.get("process_control_timeout"), r.get("reload_cuts_requests"))')"
# A file upload through the generated pool (2026-09-20 report): the body limit accepting a
# body is not the upload working. PHP must land the file in the pool's private tmp, inside
# open_basedir, and the response after a large multipart body must arrive complete.
cat > $T/www/t9.test/web/upload.php <<'PHP'
<?php
$f = $_FILES['f'] ?? null;
echo json_encode(['error' => $f['error'] ?? 'none', 'size' => $f ? filesize($f['tmp_name']) : 0, 'tmp' => $f['tmp_name'] ?? '',
                  'upload_tmp_dir' => ini_get('upload_tmp_dir'), 'sys' => sys_get_temp_dir(), 'open_basedir' => ini_get('open_basedir'),
                  'moved' => $f ? move_uploaded_file($f['tmp_name'], __DIR__ . '/moved.bin') : false]), "\n";
echo str_repeat('x', 300000);
PHP
chown t9:agensio $T/www/t9.test/web/upload.php; chmod 640 $T/www/t9.test/web/upload.php
head -c 102400 /dev/urandom > $T/small.bin; head -c 1572864 /dev/urandom > $T/large.bin
upl() { curl -sS -o $T/upl.out -w '%{http_code} %{size_download}' -H 'Host: t9.test' -F "f=@$1" http://127.0.0.1:18198/upload.php; }
upl_report() {  # "<code> <complete?> <error> <size> <tmp ok?> <moved?>" from the last upl
  local r=$1 code size; code=${r%% *}; size=${r##* }
  local want=$(( $(head -1 $T/upl.out | wc -c) + 300000 ))
  printf '%s %s ' "$code" "$([ "$size" = "$want" ] && echo yes || echo "short:$size/$want")"
  head -1 $T/upl.out | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
    print(d["error"], d["size"], "yes" if d["tmp"].startswith("'$T'/state/t9/php/t9.test/tmp/") and d["upload_tmp_dir"]=="'$T'/state/t9/php/t9.test/tmp" and "'$T'/state/t9/php/t9.test/tmp" in d["open_basedir"] else d, "yes" if d["moved"] else "no", end="")
except Exception as e:
    print("unparsable:", sys.stdin.read()[:120], end="")'
}
check "upload: a 100 KB file (in-memory body) lands in PHP's private tmp inside open_basedir, moved into the site; response complete" "200 yes 0 102400 yes yes" "$(upl_report "$(upl $T/small.bin)")"
check "upload: 1.5 MB is refused up front while the site's limit is the server's 1 MB" "413" "$(upl $T/large.bin | cut -d' ' -f1)"
out=$("$BIN" ctl site-update t9.test --set max_body_size=4MB --yes --reason uploads --socket $T/run/control.sock); sleep 0.3  # the helper reloaded the master
check "upload: after site-update max_body_size the pool carries 4M and a 1.5 MB file (spilled body) arrives intact, response complete" "yes 200 yes 0 1572864 yes yes" "$(grep -q 'upload_max_filesize\] = 4M' $(P9) && echo -n "yes "; upl_report "$(upl $T/large.bin)")"
check "upload: the same 1.5 MB upload again (php-fpm warm) and a 600 KB one" "200 0 1572864 | 200 0 614400" "$(r=$(upl $T/large.bin); echo -n "${r%% *} "; head -1 $T/upl.out | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["error"], d["size"], end="")' 2>/dev/null; head -c 614400 /dev/urandom > $T/mid.bin; r=$(upl $T/mid.bin); echo -n " | ${r%% *} "; head -1 $T/upl.out | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["error"], d["size"], end="")' 2>/dev/null)"
check "upload: the moved file is byte-identical to what was sent last" "yes" "$(cmp -s $T/mid.bin $T/www/t9.test/web/moved.bin && echo yes)"
check "upload: PHP's tmp is 2750 t9:agensio, so a moved upload carries the server's group and is served (2026-09-20 report)" "t9 agensio 2750 | agensio | 200 614400" "$(stat -c '%U %G %a' $T/state/t9/php/t9.test/tmp) | $(stat -c %G $T/www/t9.test/web/moved.bin) | $(curl -sS -o /dev/null -w '%{http_code} %{size_download}' -H 'Host: t9.test' http://127.0.0.1:18198/moved.bin)"
# The same on the wordpress and drupal presets, each with its own user and pool.
for pair in "t7 wordpress" "t6 drupal"; do set -- $pair; u=$1; app=$2
  "$BIN" ctl site-create --domain $u.test --app $app --root "$T/www/$u.test" --user $u --https none --php-children 2 --listen-plain 127.0.0.1:18198 --yes --reason upload --socket $T/run/control.sock > /dev/null
  cp $T/www/t9.test/web/upload.php $T/www/$u.test/upload.php; chown $u:agensio $T/www/$u.test/upload.php; chmod 640 $T/www/$u.test/upload.php
  "$BIN" ctl site-update $u.test --set max_body_size=4MB --yes --reason uploads --socket $T/run/control.sock > /dev/null
done
sleep 0.3
# Idle cost (2026-09-21, a live host: 8 resident children per idle site): generated pools are
# ondemand, so a pool that has not seen a request has no child; a static pool is named by
# health with what it keeps, measured from /proc.
check "pools: generated pools are ondemand with a 60 s child idle timeout; a pool without a request has no PHP process" "3 3 0" "$(grep -l '^pm = ondemand' $POOLD/agensio-t9-*.conf $POOLD/agensio-t7-*.conf $POOLD/agensio-t6-*.conf | wc -l | tr -d ' ') $(grep -l '^pm.process_idle_timeout = 60s' $POOLD/agensio-t*.conf | wc -l | tr -d ' ') $(pgrep -c -f 'php-fpm: pool agensio-t7' || true)"
check "health: no resident finding for ondemand pools" "0" "$(curl -sS --unix-socket $T/run/control.sock http://control/v1/health | grep -o '"code":"php_pool_resident"' | wc -l | tr -d ' ')"
"$BIN" ctl site-update t9.test --set pm=static --yes --reason resident --socket $T/run/control.sock > /dev/null; sleep 0.8  # reloaded by the helper: the static children start
check "health: a static pool is named with its resident processes and memory (from /proc), the fix is pm=ondemand; the ondemand pools are not" "yes 2 yes no" "$(curl -sS --unix-socket $T/run/control.sock http://control/v1/health | python3 -c '
import json,sys,re
f=[x for x in json.load(sys.stdin)["findings"] if x["code"]=="php_pool_resident"]
t9=[x for x in f if x.get("site")=="t9.test"]
print("yes" if len(t9)==1 and "pm = static: all 2 PHP processes" in t9[0]["message"] else t9, end=" ")
m=re.search(r"now (\d+) processes, (\d+) MB RSS, (\d+) MB private", t9[0]["message"]) if t9 else None
print(m.group(1) if m else "-", "yes" if m and int(m.group(2))>0 and "--set pm=ondemand" in t9[0]["fix"] else "no", "yes" if any(x.get("site") in ("t7.test","t6.test") for x in f) else "no")')"
"$BIN" ctl site-update t9.test --set pm=ondemand --yes --reason resident --socket $T/run/control.sock > /dev/null; sleep 0.3
# The pool file on disk is what php-fpm runs (2026-09-23 live report: after the ondemand default
# arrived, two pools still static on disk held 681 MB and health said nothing, because it judged
# the configuration). t9's file goes back to static behind the configuration's back.
sed -i 's/^pm = ondemand$/pm = static/' $(P9)
fpm_restart $T/fpm.conf $T/fpm.pid; sleep 0.5
check "health: a pool still static on disk while the configuration says ondemand is a warning naming both, with its resident processes; the fix is agensio pools" "warn yes 2 yes" "$(curl -sS --unix-socket $T/run/control.sock http://control/v1/health | python3 -c '
import json,sys,re
f=[x for x in json.load(sys.stdin)["findings"] if x["code"]=="php_pool_resident" and x.get("site")=="t9.test"]
m=re.search(r"now (\d+) processes", f[0]["message"]) if f else None
print(f[0]["severity"] if f else "-", "yes" if f and "pm = static on disk (the configuration says ondemand; agensio pools has not run): all 2 PHP processes" in f[0]["message"] else f, m.group(1) if m else "-", "yes" if f and f[0]["fix"].startswith("run agensio pools, then reload php-fpm") else "no")')"
"$BIN" pools -c $T/agensio.toml > /dev/null 2>&1 || true
check "health: after agensio pools the file says ondemand again and the finding is gone" "ondemand 0" "$(grep '^pm = ' $(P9) | cut -d' ' -f3) $(curl -sS --unix-socket $T/run/control.sock http://control/v1/health | grep -o '"code":"php_pool_resident"' | wc -l | tr -d ' ')"
fpm_restart $T/fpm.conf $T/fpm.pid  # agensio pools reloads nothing: it prints the line
for pair in "t7 wordpress" "t6 drupal"; do set -- $pair; u=$1; app=$2
  # The same upload over HTTP/2 (prior knowledge): DATA frames to the pool's tmp, then served.
  check "upload over HTTP/2 ($app preset, user $u): a 600 KB multipart body reaches PHP and the file is served" "200 0 614400 | 200 614400" "$(r=$(curl -sS --http2-prior-knowledge -o $T/upl.out -w '%{http_code}' -H "Host: $u.test" -F "f=@$T/mid.bin" http://127.0.0.1:18198/upload.php); echo -n "$r "; head -1 $T/upl.out | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["error"], d["size"], end="")' 2>/dev/null; echo -n " | "; curl -sS --http2-prior-knowledge -o /dev/null -w '%{http_code} %{size_download}' -H "Host: $u.test" http://127.0.0.1:18198/moved.bin)"
  check "upload ($app preset, user $u): the moved upload has the server's group and is served" "200 0 614400 | agensio | 200 614400" "$(r=$(curl -sS -o $T/upl.out -w '%{http_code}' -H "Host: $u.test" -F "f=@$T/mid.bin" http://127.0.0.1:18198/upload.php); echo -n "$r "; head -1 $T/upl.out | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["error"], d["size"], end="")' 2>/dev/null; echo -n " | $(stat -c %G $T/www/$u.test/moved.bin 2>/dev/null) | "; curl -sS -o /dev/null -w '%{http_code} %{size_download}' -H "Host: $u.test" http://127.0.0.1:18198/moved.bin)"
done
check "health: a file under a root the server cannot read is an error finding naming it; fixed, it is gone" "files_unreadable yes 0" "$(chgrp t9 $T/www/t9.test/web/moved.bin; chmod 0640 $T/www/t9.test/web/moved.bin; h=$("$BIN" ctl health --socket $T/run/control.sock); echo -n "$(echo "$h" | grep -o '"code":"files_unreadable"' | head -1 | cut -d'"' -f4) "; echo "$h" | grep -q "moved.bin (t9:t9 0640)" && echo -n yes; chgrp agensio $T/www/t9.test/web/moved.bin; echo " $("$BIN" ctl health --socket $T/run/control.sock | grep -c files_unreadable)")"
check "health: the remedy follows the defect: chgrp for a wrong group, chmod g+r for a right group with no group read" "chgrp chmod" "$(chgrp t9 $T/www/t9.test/web/moved.bin; chmod 0640 $T/www/t9.test/web/moved.bin; "$BIN" ctl health --socket $T/run/control.sock | python3 -c 'import json,sys; f=[x for x in json.load(sys.stdin)["findings"] if x["code"]=="files_unreadable"][0]["fix"]; print("chgrp" if f.startswith("give them the server\x27s group: chgrp") and "chmod" not in f else f, end="")'; chgrp agensio $T/www/t9.test/web/moved.bin; chmod 0600 $T/www/t9.test/web/moved.bin; echo -n " "; "$BIN" ctl health --socket $T/run/control.sock | python3 -c 'import json,sys; f=[x for x in json.load(sys.stdin)["findings"] if x["code"]=="files_unreadable"][0]["fix"]; print("chmod" if f.startswith("the group is right, the mode is not: chmod -R g+r") else f, end="")'; chmod 0640 $T/www/t9.test/web/moved.bin)"
check "pools: a tmp directory of the wrong mode and group (0700 user:user) is repaired by agensio pools" "yes t9 agensio 2750" "$(chown t9:t9 $T/state/t9/php/t9.test/tmp; chmod 0700 $T/state/t9/php/t9.test/tmp; "$BIN" pools -c $T/agensio.toml 2>/dev/null | grep -q 'repaired .*state/t9/php/t9.test/tmp to 2750' && echo -n yes; echo " $(stat -c '%U %G %a' $T/state/t9/php/t9.test/tmp)")"
check "health: a missing PHP private directory is an error finding with the fix; restored, it is gone" "php_tmp_missing 0" "$(mv $T/state/t9 $T/state/t9.away; "$BIN" ctl health --socket $T/run/control.sock | grep -o '"code":"php_tmp_missing"' | head -1 | cut -d'"' -f4 | tr -d '\n'; mv $T/state/t9.away $T/state/t9; echo " $("$BIN" ctl health --socket $T/run/control.sock | grep -c php_tmp)")"
sleep 1.3
check "the site's log is readable by t9 without a restart" "agensio t9 640" "$(stat -c '%U %G %a' $T/logs/sites/t9.test.log)"
h=$("$BIN" ctl health --socket $T/run/control.sock)
# The devbox's php-fpm loads no dom, gd, SimpleXML or xml, which Drupal requires (docs/configuration.md 7b):
# t6's one error, naming them; nothing else is an error.
check "health: the Drupal site's missing required extensions are its error, naming them; no other error and no log finding" "yes yes 0 no" \
  "$(echo "$h" | grep -q '"ok":' && echo -n yes) $(echo "$h" | python3 -c 'import json,sys; f=[x for x in json.load(sys.stdin)["findings"] if x["code"]=="php_extensions_missing" and x["severity"]=="error"]; print("yes" if len(f)==1 and f[0]["site"]=="t6.test" and all(e in f[0]["message"] for e in ("dom", "gd", "simplexml", "xml")) else f)') $(echo "$h" | python3 -c 'import json,sys; print(len([x for x in json.load(sys.stdin)["findings"] if x["severity"]=="error" and x["code"]!="php_extensions_missing"]))') $(echo "$h" | grep -q log_not_readable && echo yes || echo no)"
# A credential an update loosened (2026-10-22): `cp .env.example .env` leaves it 0644, readable by the
# server's group. Before, the next reload (any site's change) set t9 aside, though stopping the site
# made the file no more private; now the reload keeps t9 serving and the helper, as t9, gives the file
# the installer's 0600, saying so in the error and audit logs. One t9 cannot change (root's) stays as
# it is, the site serving, and health names it as an error.
printf 'APP_KEY=x\n' > $T/www/t9.test/web/.env; chown t9:agensio $T/www/t9.test/web/.env; chmod 0644 $T/www/t9.test/web/.env
check "a credential an update left readable: the next reload keeps the site serving and the helper makes it 0600 as t9, in both logs" "200 t9 600 yes yes" \
  "$("$BIN" ctl reload --yes --reason loosened --socket $T/run/control.sock > /dev/null 2>&1; curl -sS -o /dev/null -w '%{http_code}' -H 'Host: t9.test' http://127.0.0.1:18198/index.php) $(stat -c '%U %a' $T/www/t9.test/web/.env) $(grep -q "tightened $T/www/t9.test/web/.env" $T/logs/error.log && echo yes) $(grep -q "tightened $T/www/t9.test/web/.env" $T/logs/audit.log && echo yes)"
chown root:agensio $T/www/t9.test/web/.env; chmod 0644 $T/www/t9.test/web/.env
check "a credential the site's account cannot change: the site keeps serving, health names it as an error with the fix" "200 error yes" \
  "$("$BIN" ctl reload --yes --reason loosened --socket $T/run/control.sock > /dev/null 2>&1; curl -sS -o /dev/null -w '%{http_code}' -H 'Host: t9.test' http://127.0.0.1:18198/index.php) $("$BIN" ctl health --socket $T/run/control.sock | python3 -c 'import json,sys; f=[x for x in json.load(sys.stdin)["findings"] if x["code"]=="credential_exposed" and x.get("site")=="t9.test"]; print(f[0]["severity"], "yes" if f and "chmod 600" in f[0]["fix"] else "no") if f else print("none")')"
rm -f $T/www/t9.test/web/.env
"$BIN" ctl reload --yes --reason loosened --socket $T/run/control.sock > /dev/null 2>&1
check "every helper action is in the audit log" "yes yes yes" "$(grep -q 'provisioned missing_account' $T/logs/audit.log && echo yes) $(grep -q 'provisioned root_missing' $T/logs/audit.log && echo yes) $(grep -q 'sites (provision): created' $T/logs/audit.log && echo yes)"

# A managed site's users through the helper (2026-10-09, design section 25, step 4b): root's file,
# the server's group, 0640 in a 0750 directory; a symlink in its place refused; the listing and the
# audit log without a hash or a password.
out=$("$BIN" ctl site-auth-user-set t9.test anna --generate --note 'Anna' --yes --reason auth --socket $T/run/control.sock)
check "site-auth-user-set through the helper: root:agensio 0640 in root:agensio 0750, the password answered once" "yes root agensio 640 root agensio 750 yes" \
  "$(echo "$out" | grep -q '"action":"created"' && echo yes) $(stat -c '%U %G %a' $T/auth/t9.test.users) $(stat -c '%U %G %a' $T/auth) $(echo "$out" | grep -qE '"password":"[a-km-np-z2-9]{4}-' && echo yes)"
mv $T/auth/t9.test.users $T/auth/kept; ln -s /etc/shadow $T/auth/t9.test.users; sum=$(sha256sum /etc/shadow)
out=$("$BIN" ctl site-auth-user-set t9.test bob --generate --yes --reason auth --socket $T/run/control.sock)
check "a symlink in the file's place is refused by the helper; /etc/shadow untouched" "yes yes" "$(echo "$out" | grep -q 'symlink' && echo yes) $([ "$(sha256sum /etc/shadow)" = "$sum" ] && echo yes)"
rm $T/auth/t9.test.users; mv $T/auth/kept $T/auth/t9.test.users
out=$("$BIN" ctl site-auth-users t9.test --socket $T/run/control.sock)
check "site-auth-users through the helper: the name and method, no hash" "yes no" "$(echo "$out" | grep -q '"name":"anna","method":"yescrypt"' && echo yes) $(echo "$out" | grep -q '\$y\$' && echo yes || echo no)"
out=$("$BIN" ctl site-auth-user-set '*' eve --generate --yes --reason auth --socket $T/run/control.sock)
check "a hand-written site is refused; the audit log names the change and holds no hash" "yes yes 0" \
  "$(echo "$out" | grep -q 'not managed' && echo yes) $(grep -q 'auth-users.*anna: created with a generated password' $T/logs/audit.log && echo yes) $(grep -c '\$y\$' $T/logs/audit.log)"

# A site's PHP version switched without downtime (docs/configuration.md 7b, docs/design-php-versions.md 6.1).
# First refused: neither php-fpm.conf sets process_control_timeout, so the reloads would cut requests in
# flight; nothing changes and the answer gives the line and cut_requests.
CS=$T/run/control.sock
printf '<?php echo posix_getppid();' > $T/www/t9.test/web/who.php; chown t9:agensio $T/www/t9.test/web/who.php; chmod 640 $T/www/t9.test/web/who.php
out=$("$BIN" ctl site-update t9.test --php-version 9.9 --yes --reason "php version" --socket $CS)
check "php switch: refused while the php-fpm.conf files set no process_control_timeout; nothing changed, cut_requests named" "yes yes 0 $PHPV" \
  "$(echo "$out" | grep -q 'process_control_timeout = 10s' && echo yes) $(echo "$out" | grep -q 'cut_requests' && echo yes) $(ls $T/pool99.d | grep -c '^agensio-t9-') $(curl -sS --unix-socket $CS http://control/v1/sites/t9.test | python3 -c 'import json,sys; print(json.load(sys.stdin)["php"]["version"])')"
for c in $T/fpm.conf $T/fpm99.conf; do sed -i 's/^\[global\]$/[global]\nprocess_control_timeout = 10s/' $c; done
fpm_restart $T/fpm.conf $T/fpm.pid; fpm_restart $T/fpm99.conf $T/fpm99.pid
# Under load: four clients ask t9's PHP without a pause while it moves to 9.9; every answer is a 200,
# the last ones from 9.9's master.
load() {  # until $T/stop.load exists: the status and the master's pid of each answer
  rm -f $T/stop.load $T/load.*; LOADP=""
  for i in 1 2 3 4; do
    ( while [ ! -e $T/stop.load ]; do curl -sS -o $T/load.body.$i -w '%{http_code} ' -H 'Host: t9.test' http://127.0.0.1:18198/who.php; cat $T/load.body.$i; echo; done ) > $T/load.$i 2>&1 &
    LOADP="$LOADP $!"
  done
  sleep 0.3
}
unload() { touch $T/stop.load; for p in $LOADP; do wait $p; done; cat $T/load.[1-4] > $T/load.all; }  # the loops only, never the server
load
out=$("$BIN" ctl site-update t9.test --php-version 9.9 --yes --reason "php version" --socket $CS)
sleep 0.3; unload
check "php switch under load: t9 moves to 9.9; every answer during the switch is a 200 (more than 20 asked), the last from 9.9's master" "yes 0 yes yes" \
  "$(echo "$out" | grep -q '"ok":true' && echo yes) $(grep -vc '^200 [0-9]*$' $T/load.all) $([ "$(wc -l < $T/load.all)" -gt 20 ] && echo yes) $([ "$(tail -1 $T/load.4 | cut -d' ' -f2)" = "$(cat $T/fpm99.pid)" ] && echo yes)"
check "php switch: done names t9's pool up on 9.9 before agensio switched, then the old one gone from $PHPV's directory" "yes 0 1 9.9 site t9.test" \
  "$(echo "$out" | grep -q 'php-fpm pool agensio-t9-[0-9a-f]\{8\} (PHP 9.9) up before agensio switched to it' && echo yes) $(ls $POOLD | grep -c '^agensio-t9-') $(ls $T/pool99.d | grep -c '^agensio-t9-[0-9a-f]\{8\}\.conf$') $(curl -sS --unix-socket $CS http://control/v1/sites/t9.test | python3 -c 'import json,sys; d=json.load(sys.stdin)["php"]; print(d["version"], d["version_from"])') $(curl -sS --unix-socket $CS http://control/v1/php | python3 -c 'import json,sys; print(" ".join(x for r in json.load(sys.stdin)["runtimes"] if r["version"] == "9.9" for x in r["sites"]))')"
# A configuration its php-fpm refuses: t7 to 9.9 while 9.9's php-fpm.conf holds an unknown entry. The new
# pool never comes up, the site never leaves its version, and the answer quotes php-fpm.
cp $T/fpm99.conf $T/fpm99.good; printf 'no_such_entry = 1\n' >> $T/fpm99.conf
out=$("$BIN" ctl site-update t7.test --php-version 9.9 --yes --reason "refused" --socket $CS)
check "php switch: 9.9's php-fpm refuses its configuration: refused, t7's file put back there, t7 still on $PHPV and answering" "yes 0 1 $PHPV 200" \
  "$(echo "$out" | grep -q "refuses its configuration.*no_such_entry" && echo yes) $(ls $T/pool99.d | grep -c '^agensio-t7-') $(ls $POOLD | grep -c '^agensio-t7-') $(curl -sS --unix-socket $CS http://control/v1/sites/t7.test | python3 -c 'import json,sys; print(json.load(sys.stdin)["php"]["version"])') $(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: t7.test' http://127.0.0.1:18198/upload.php)"
cp $T/fpm99.good $T/fpm99.conf
# Switching back is the same switch in reverse, under load too.
load
out=$("$BIN" ctl site-update t9.test --php-version $PHPV --yes --reason "back" --socket $CS)
sleep 0.3; unload
check "php switch back under load: every answer a 200, the last from $PHPV's master; agensio pools finds nothing to do" "yes 0 yes 0" \
  "$(echo "$out" | grep -q '"ok":true' && echo yes) $(grep -vc '^200 [0-9]*$' $T/load.all) $([ "$(tail -1 $T/load.4 | cut -d' ' -f2)" = "$(cat $T/fpm.pid)" ] && echo yes) $(rc=0; "$BIN" pools -c $T/agensio.toml > /dev/null 2>&1 || rc=$?; echo $rc)"
# What the site's application needs (docs/design-php-versions.md 7): t9's composer.json requires an
# extension no version loads; its move is refused naming it, nothing changes, and --ignore-requirements
# moves it with a warning.
printf '{"require": {"ext-nosuch": "*"}}' > $T/www/t9.test/web/composer.json; chown t9:agensio $T/www/t9.test/web/composer.json; chmod 640 $T/www/t9.test/web/composer.json
out=$("$BIN" ctl site-update t9.test --php-version 9.9 --yes --reason "requirements" --socket $CS)
check "requirements: a move to a version without what composer.json requires is refused, naming it and ignore_requirements; nothing changed" "yes yes $PHPV" \
  "$(echo "$out" | grep -q 'requires the PHP extension nosuch' && echo yes) $(echo "$out" | grep -q 'ignore_requirements' && echo yes) $(curl -sS --unix-socket $CS http://control/v1/sites/t9.test | python3 -c 'import json,sys; print(json.load(sys.stdin)["php"]["version"])')"
out=$("$BIN" ctl site-update t9.test --php-version 9.9 --ignore-requirements --yes --reason "requirements" --socket $CS)
check "requirements: --ignore-requirements moves it, the answer's warnings naming the extension" "yes yes 9.9" \
  "$(echo "$out" | grep -q '"ok":true' && echo yes) $(echo "$out" | python3 -c 'import json,sys; print("yes" if any("nosuch" in w for w in json.load(sys.stdin)["warnings"]) else "no")') $(curl -sS --unix-socket $CS http://control/v1/sites/t9.test | python3 -c 'import json,sys; print(json.load(sys.stdin)["php"]["version"])')"
"$BIN" ctl site-update t9.test --php-version $PHPV --ignore-requirements --yes --reason "back" --socket $CS > /dev/null
rm -f $T/www/t9.test/web/composer.json
# A release the site's PHP cannot run: an archive whose composer.json asks PHP >= 99.0 is refused and taken
# out again; with --ignore-requirements it is installed, facts.php saying what it declares.
"$BIN" ctl site-create --domain t5.test --app php --root "$T/www/t5.test/web" --user t5 --https none --listen-plain 127.0.0.1:18198 --yes --reason requirements --socket $CS > /dev/null
mkdir -p $T/rel/app; printf '{"require": {"php": ">=99.0"}}' > $T/rel/app/composer.json; echo '<?php echo "new";' > $T/rel/app/index.php; tar czf $T/rel.tgz -C $T/rel app
"$BIN" ctl upload rel.tgz $T/rel.tgz --socket $CS > /dev/null
out=$("$BIN" ctl site-install t5.test --file rel.tgz --yes --reason requirements --socket $CS)
check "requirements: site-install of a release that needs PHP >= 99.0 is refused and leaves the directory empty" "yes 0" \
  "$(echo "$out" | grep -q 'cannot run on the site.s PHP: it needs PHP >=99.0 (composer.json)' && echo yes) $(ls -A $T/www/t5.test/web | wc -l)"
out=$("$BIN" ctl site-install t5.test --file rel.tgz --ignore-requirements --yes --reason requirements --socket $CS)
check "requirements: --ignore-requirements installs it, facts.php naming the declaration and the version outside it" "True >=99.0 True" \
  "$(echo "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); p=d["facts"]["php"]; print(d["ok"], p["declared"]["php"], p["outside"])')"

# At a start (docs/design-php-versions.md 6.2): the pool files no longer match (t9's gone and its master
# reloaded without it, as after an upgrade that renamed the pools); the start writes it back and reloads
# php-fpm before the listeners accept, so the first request is answered; a start that finds them in step
# changes nothing.
srv_stop() { local p; p=$(cat $T/agensio.pid); kill -TERM $p; for _ in $(seq 1 100); do kill -0 $p 2>/dev/null || break; sleep 0.1; done; }
srv_start() { "$BIN" -c $T/agensio.toml > $T/server.out 2>&1 & for _ in $(seq 1 100); do [ -S $CS ] && break; sleep 0.1; done; }
srv_stop
rm -f $POOLD/agensio-t9-*.conf $T/run/agensio-t9-*-$PHPV.sock; fpm_restart $T/fpm.conf $T/fpm.pid
check "start: before, t9's pool is gone from php-fpm" "no" "$([ -S $T/run/agensio-t9-*-$PHPV.sock ] && echo yes || echo no)"
srv_start
check "start: the pool is written and php-fpm reloaded before the listeners accept; the first request is answered" "200 1 yes" \
  "$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: t9.test' http://127.0.0.1:18198/who.php) $(ls $POOLD | grep -c '^agensio-t9-') $(grep -q 'php-fpm pools at start: .*wrote .*agensio-t9-.*; reloaded PHP' $T/logs/error.log && echo yes)"  # one line: the whole output on the entry's line
srv_stop; srv_start
check "start: a start whose pool files match touches nothing" "1 200" \
  "$(grep -c 'php-fpm pools at start: up to date' $T/logs/error.log) $(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: t9.test' http://127.0.0.1:18198/who.php)"

# What the helper refuses.
out=$("$BIN" ctl site-create --domain t8.test --app static --root "$T/www/t9.test/web" --user t8 --https none --listen-plain 127.0.0.1:18199 --yes --reason repro --socket $T/run/control.sock)
check "another site's directory is never handed over (helper refuses)" "yes yes" "$(echo "$out" | grep -q 'another site; refused' && echo yes) $([ "$(stat -c %U $T/www/t9.test/web)" = t9 ] && echo yes)"
ln -s /etc $T/www/evil
out=$("$BIN" ctl site-create --domain evil.test --app static --root "$T/www/evil/web" --user t8 --https none --listen-plain 127.0.0.1:18199 --yes --reason repro --socket $T/run/control.sock)
check "a symlink on the way is refused, nothing created under it" "yes no" "$(echo "$out" | grep -q 'symlink' && echo yes) $([ -e /etc/web ] && echo yes || echo no)"
out=$("$BIN" ctl site-create --domain root.test --app static --root "$T/www/root.test/web" --user root --https none --listen-plain 127.0.0.1:18199 --yes --reason repro --socket $T/run/control.sock)
check "a system account name is refused before the helper is asked" "yes no" "$(echo "$out" | grep -q 'system account' && echo yes) $(grep -q 'account_add.*root' $T/logs/audit.log && echo yes || echo no)"
check "the helper answers only the server: the socketpair has no path" "0" "$(ls $T/run | grep -c helper)"
# A clean stop (2026-10-09): SIGTERM ends the server with the helper running, and a sanitizer build
# reports nothing on the way out. The trash timer, which only a server with the helper arms, was
# destroyed after the workers' contexts had freed its service: a use-after-free at every exit.
SP=$(cat $T/agensio.pid); kill -TERM $SP; for _ in $(seq 1 100); do kill -0 $SP 2>/dev/null || break; sleep 0.1; done
check "SIGTERM stops the server with the helper running; no sanitizer report on the way out" "stopped 0" \
  "$(kill -0 $SP 2>/dev/null && echo running || echo stopped) $(grep -c 'ERROR: AddressSanitizer\|runtime error:' $T/server.out)"
# HTTP/3 turned on by a reload on a privileged port (the alpha.110 report: the live server, started as
# root and running as server.user, died on that reload, a failed UDP bind thrown on worker 0 after the
# switch, with nothing in its error log). The reload now applies the rest, keeps h3 off on :443 (no
# socket, no alt-svc) and names it as waiting for a restart; a restart, made as root, opens it.
H=$T/h3priv; mkdir -p $H/www $H/run $H/logs; chown agensio:agensio $H/logs; echo ok > $H/www/index.html
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=localhost -keyout $H/key.pem -out $H/cert.pem 2>/dev/null
chgrp agensio $H/key.pem; chmod 640 $H/key.pem
h3cfg() {  # the [server] protocols list
  cat > $H/agensio.toml <<CFG
[server]
workers = 2
user = "agensio"
protocols = [$1]
pid_file = "$H/agensio.pid"
[log]
access = "off"
error = "$H/logs/error.log"
level = "info"
[control]
socket = "$H/run/control.sock"
audit = "$H/logs/audit.log"
provision = false
[[site]]
server_name = ["localhost"]
listen = ["127.0.0.1:443"]
root = "$H/www"
tls = { cert = "$H/cert.pem", key = "$H/key.pem" }
CFG
}
h3start() { rm -f $H/run/control.sock; "$BIN" -c $H/agensio.toml >> $H/server.out 2>&1 & for _ in $(seq 1 50); do [ -S $H/run/control.sock ] && break; sleep 0.1; done; sleep 0.3; }
h3protos() { "$BIN" ctl status --socket $H/run/control.sock 2>/dev/null | python3 -c 'import json,sys; print(",".join(next((l["protocols"] for l in json.load(sys.stdin)["listeners"] if l["address"] == "127.0.0.1:443"), ["-"])))' 2>/dev/null || echo none; }
h3altsvc() { curl -sk --resolve localhost:443:127.0.0.1 -D - -o /dev/null https://localhost/ | grep -ci '^alt-svc'; }
h3cfg '"h2", "h1"'
# Docker lets any user bind a low port in a container (net.ipv4.ip_unprivileged_port_start=0), so 443
# is privileged here only when the container runs with --sysctl net.ipv4.ip_unprivileged_port_start=1024.
unpriv=$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)
if [ "$unpriv" -le 443 ]; then
  echo "skip h3 privileged checks: port 443 is not privileged in this container (run it with --sysctl net.ipv4.ip_unprivileged_port_start=1024)"
elif printf '[server]\nprotocols = ["h3", "h2", "h1"]\n[[site]]\nlisten = ["127.0.0.1:1"]\nroot = "%s/www"\ntls = { cert = "%s/cert.pem", key = "%s/key.pem" }\n' $H $H $H > $H/probe.toml && "$BIN" -t -c $H/probe.toml >/dev/null 2>&1; then
  h3start
  check "h3 privileged: started as root without h3, the 443 listener serves h2 and h1, no alt-svc" "h2,h1 0" "$(h3protos) $(h3altsvc)"
  h3cfg '"h2", "h1", "h3"'
  "$BIN" ctl reload --yes --reason h3 --socket $H/run/control.sock > $H/reload.out 2>&1
  sleep 0.5
  check "h3 privileged: a reload turning h3 on at 443 after the privilege drop keeps the server up, answers ok naming h3 on 443 as waiting for a restart; the listener stays h2 and h1 with no alt-svc; the error log and health say so" \
    "alive yes h2,h1 0 yes yes" \
    "$(kill -0 "$(cat $H/agensio.pid 2>/dev/null)" 2>/dev/null && echo alive || echo dead) $(grep -q '"ok":true' $H/reload.out && grep -q 'h3 on udp 127.0.0.1:443' $H/reload.out && echo yes || echo no) $(h3protos) $(h3altsvc) $(grep -q 'h3 on udp 127.0.0.1:443.*restart' $H/logs/error.log && echo yes || echo no) $("$BIN" ctl health --socket $H/run/control.sock 2>/dev/null | grep -q '"code":"h3_waits_for_restart"' && echo yes || echo no)"
  HP=$(cat $H/agensio.pid 2>/dev/null); [ -n "$HP" ] && kill -TERM $HP 2>/dev/null; for _ in $(seq 1 100); do [ -n "$HP" ] && kill -0 $HP 2>/dev/null || break; sleep 0.1; done
  h3start
  check "h3 privileged: a restart made as root opens h3 on 443, and answers advertise it" "h2,h1,h3 1" "$(h3protos) $(h3altsvc)"
  HP=$(cat $H/agensio.pid 2>/dev/null); [ -n "$HP" ] && kill -TERM $HP 2>/dev/null; for _ in $(seq 1 100); do [ -n "$HP" ] && kill -0 $HP 2>/dev/null || break; sleep 0.1; done
else
  echo "skip h3 privileged checks (this build has no HTTP/3)"
fi
echo "provision: $pass passed, $fail failed"
[ $fail = 0 ] || { echo "--- error.log"; cat $T/logs/error.log; echo "--- audit"; cat $T/logs/audit.log; echo "--- last reply"; echo "$out"; echo "--- health"; "$BIN" ctl health --socket $T/run/control.sock; echo; echo "--- upload answer"; head -c 300 $T/upl.out; echo; echo "--- fpm.log"; cat $T/fpm.log 2>/dev/null | tail -20; }
[ $fail = 0 ]
