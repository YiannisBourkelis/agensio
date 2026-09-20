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
cleanup() { [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; [ -f "$T/fpm.pid" ] && kill "$(cat "$T/fpm.pid")" 2>/dev/null; rm -f $POOLD/agensio-t9.conf $POOLD/agensio-t7.conf $POOLD/agensio-t6.conf; for u in t9 t8 t7 t6; do userdel $u 2>/dev/null; done; rm -rf "$T"; }
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
    print(d["error"], d["size"], "yes" if d["tmp"].startswith("'$T'/state/t9/tmp/") and d["upload_tmp_dir"]=="'$T'/state/t9/tmp" and "'$T'/state/t9/tmp" in d["open_basedir"] else d, "yes" if d["moved"] else "no", end="")
except Exception as e:
    print("unparsable:", sys.stdin.read()[:120], end="")'
}
check "upload: a 100 KB file (in-memory body) lands in PHP's private tmp inside open_basedir, moved into the site; response complete" "200 yes 0 102400 yes yes" "$(upl_report "$(upl $T/small.bin)")"
check "upload: 1.5 MB is refused up front while the site's limit is the server's 1 MB" "413" "$(upl $T/large.bin | cut -d' ' -f1)"
out=$("$BIN" ctl site-update t9.test --set max_body_size=4MB --yes --reason uploads --socket $T/run/control.sock)
kill "$(cat $T/fpm.pid)"; sleep 0.5; rm -f $T/run/agensio-t9.sock; $FPM -y $T/fpm.conf -D; for _ in $(seq 1 50); do [ -S $T/run/agensio-t9.sock ] && break; sleep 0.1; done; sleep 0.3
check "upload: after site-update max_body_size the pool carries 4M and a 1.5 MB file (spilled body) arrives intact, response complete" "yes 200 yes 0 1572864 yes yes" "$(grep -q 'upload_max_filesize\] = 4M' $POOLD/agensio-t9.conf && echo -n "yes "; upl_report "$(upl $T/large.bin)")"
check "upload: the same 1.5 MB upload again (php-fpm warm) and a 600 KB one" "200 0 1572864 | 200 0 614400" "$(r=$(upl $T/large.bin); echo -n "${r%% *} "; head -1 $T/upl.out | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["error"], d["size"], end="")' 2>/dev/null; head -c 614400 /dev/urandom > $T/mid.bin; r=$(upl $T/mid.bin); echo -n " | ${r%% *} "; head -1 $T/upl.out | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["error"], d["size"], end="")' 2>/dev/null)"
check "upload: the moved file is byte-identical to what was sent last" "yes" "$(cmp -s $T/mid.bin $T/www/t9.test/web/moved.bin && echo yes)"
check "upload: PHP's tmp is 2750 t9:agensio, so a moved upload carries the server's group and is served (2026-09-20 report)" "t9 agensio 2750 | agensio | 200 614400" "$(stat -c '%U %G %a' $T/state/t9/tmp) | $(stat -c %G $T/www/t9.test/web/moved.bin) | $(curl -sS -o /dev/null -w '%{http_code} %{size_download}' -H 'Host: t9.test' http://127.0.0.1:18198/moved.bin)"
# The same on the wordpress and drupal presets, each with its own user and pool.
for pair in "t7 wordpress" "t6 drupal"; do set -- $pair; u=$1; app=$2
  "$BIN" ctl site-create --domain $u.test --app $app --root "$T/www/$u.test" --user $u --https none --php-children 2 --listen-plain 127.0.0.1:18198 --yes --reason upload --socket $T/run/control.sock > /dev/null
  cp $T/www/t9.test/web/upload.php $T/www/$u.test/upload.php; chown $u:agensio $T/www/$u.test/upload.php; chmod 640 $T/www/$u.test/upload.php
  "$BIN" ctl site-update $u.test --set max_body_size=4MB --yes --reason uploads --socket $T/run/control.sock > /dev/null
done
sed -i "s#^include = .*#include = $POOLD/agensio-t9.conf\ninclude = $POOLD/agensio-t7.conf\ninclude = $POOLD/agensio-t6.conf#" $T/fpm.conf
kill "$(cat $T/fpm.pid)"; sleep 0.5; rm -f $T/run/agensio-t*.sock; $FPM -y $T/fpm.conf -D; for _ in $(seq 1 50); do [ -S $T/run/agensio-t6.sock ] && break; sleep 0.1; done; sleep 0.3
for pair in "t7 wordpress" "t6 drupal"; do set -- $pair; u=$1; app=$2
  check "upload ($app preset, user $u): the moved upload has the server's group and is served" "200 0 614400 | agensio | 200 614400" "$(r=$(curl -sS -o $T/upl.out -w '%{http_code}' -H "Host: $u.test" -F "f=@$T/mid.bin" http://127.0.0.1:18198/upload.php); echo -n "$r "; head -1 $T/upl.out | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["error"], d["size"], end="")' 2>/dev/null; echo -n " | $(stat -c %G $T/www/$u.test/moved.bin 2>/dev/null) | "; curl -sS -o /dev/null -w '%{http_code} %{size_download}' -H "Host: $u.test" http://127.0.0.1:18198/moved.bin)"
done
check "health: a file under a root the server cannot read is an error finding naming it; fixed, it is gone" "files_unreadable yes 0" "$(chgrp t9 $T/www/t9.test/web/moved.bin; chmod 0640 $T/www/t9.test/web/moved.bin; h=$("$BIN" ctl health --socket $T/run/control.sock); echo -n "$(echo "$h" | grep -o '"code":"files_unreadable"' | head -1 | cut -d'"' -f4) "; echo "$h" | grep -q "moved.bin" && echo -n yes; chgrp agensio $T/www/t9.test/web/moved.bin; echo " $("$BIN" ctl health --socket $T/run/control.sock | grep -c files_unreadable)")"
check "pools: an older tmp directory (0700 user:user) is repaired by agensio pools" "yes t9 agensio 2750" "$(chown t9:t9 $T/state/t9/tmp; chmod 0700 $T/state/t9/tmp; "$BIN" pools -c $T/agensio.toml 2>/dev/null | grep -q 'repaired .*state/t9/tmp to 2750' && echo -n yes; echo " $(stat -c '%U %G %a' $T/state/t9/tmp)")"
check "health: a missing PHP private directory is an error finding with the fix; restored, it is gone" "php_tmp_missing 0" "$(mv $T/state/t9 $T/state/t9.away; "$BIN" ctl health --socket $T/run/control.sock | grep -o '"code":"php_tmp_missing"' | head -1 | cut -d'"' -f4 | tr -d '\n'; mv $T/state/t9.away $T/state/t9; echo " $("$BIN" ctl health --socket $T/run/control.sock | grep -c php_tmp)")"
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
[ $fail = 0 ] || { echo "--- error.log"; cat $T/logs/error.log; echo "--- audit"; cat $T/logs/audit.log; echo "--- last reply"; echo "$out"; echo "--- health"; "$BIN" ctl health --socket $T/run/control.sock; echo; echo "--- upload answer"; head -c 300 $T/upl.out; echo; echo "--- fpm.log"; cat $T/fpm.log 2>/dev/null | tail -20; }
[ $fail = 0 ]
