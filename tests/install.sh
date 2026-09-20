#!/usr/bin/env bash
# site-install through the provisioning helper (F9): as root in the devbox, a site with its
# own account gets an application's files written by that account, from an upload the
# account itself could never read (root opens it, the child drops to the account before
# it reads a byte) and from an https download fenced and verified. Refusals: a root-owned
# target, a symlink inside the archive, a wrong sha256, a private address without
# install_private, a plain http URL. Nothing is left behind after a refusal.
#   docker run --rm --init --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox tests/install.sh build/agensio
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
ROOT=$(pwd)
[ "$(id -u)" = 0 ] || { echo "install: needs root; skipped"; exit 0; }
T=$(mktemp -d /tmp/agensio-install.XXXXXX); chmod 755 "$T"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() { [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; for u in t7 t6; do userdel $u 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT
id -u agensio >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin agensio
mkdir -p $T/sites.d $T/logs $T/run $T/state $T/www $T/pub $T/certs; chown agensio:agensio $T/sites.d $T/logs $T/state; chmod 751 $T/state
cp $ROOT/bench/certs/cert.pem $ROOT/bench/certs/key.pem $T/certs/; chown agensio:agensio $T/certs/key.pem; chmod 640 $T/certs/key.pem; chmod 644 $T/certs/cert.pem
tar czf $T/pub/wp.tgz -C $ROOT/tests wordpress
tar czf $T/pub/dot.tgz -C $ROOT/tests/wordpress .
( cd $T && ln -s /etc/passwd leak && tar czf $T/pub/evil.tgz leak && rm leak )
SHA=$(sha256sum $T/pub/wp.tgz | cut -c1-64)
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
level = "info"
[control]
socket = "$T/run/control.sock"
audit = "$T/logs/audit.log"
sites_root = "$T/www"
install_ca = "$T/certs/cert.pem"
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:18297"]
root = "$T/www"
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:18298"]
root = "$T/pub"
tls = { cert = "$T/certs/cert.pem", key = "$T/certs/key.pem" }
CFG
start() { "$BIN" -c $T/agensio.toml >> $T/server.out 2>&1 & for _ in $(seq 1 50); do [ -S $T/run/control.sock ] && break; sleep 0.1; done; sleep 0.2; }
stop() { kill "$(cat $T/agensio.pid)" 2>/dev/null; sleep 0.3; }
start
CS=$T/run/control.sock
ctl() { "$BIN" ctl "$@" --socket $CS; }
check "the uploads directory belongs to the server, 0700, under the state directory" "agensio 700" "$(stat -c '%U %a' $T/state/uploads)"

# A site with its own account, made by the helper; then its files, written as that account.
out=$(ctl site-create --domain t7.test --app wordpress --root "$T/www/t7.test" --user t7 --https none --php-children 2 --listen-plain 127.0.0.1:18299 --yes --reason install)
check "site-create with a user: account and layout done by the helper" "yes t7 agensio 2750" "$(echo "$out" | grep -q '"ok":true' && echo yes) $(stat -c '%U %G %a' $T/www/t7.test)"
check "upload as root: stored, and unreadable by the site account" "0 no" "$(ctl upload wp.tgz $T/pub/wp.tgz > /dev/null; echo -n "$? "; su -s /bin/sh t7 -c "cat $T/state/uploads/wp.tgz" >/dev/null 2>&1 && echo yes || echo no)"
out=$(ctl site-install t7.test --file wp.tgz --yes --reason install); rc=$?
check "site-install from the upload succeeds through the helper" "0 wordpress" "$rc $(echo "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("unwrapped"))')"
check "every file belongs to t7 with the server's group and the layout's modes (0640 / 2750)" "t7 agensio 640 | t7 agensio 2750" "$(stat -c '%U %G %a' $T/www/t7.test/index.php) | $(stat -c '%U %G %a' $T/www/t7.test/wp-admin)"
check "the server's account can read the installed files through the group" "yes" "$(su -s /bin/sh agensio -c "cat $T/www/t7.test/index.php" >/dev/null 2>&1 && echo yes)"
check "the audit log names the install with the sha256" "yes" "$(grep -q "sites/t7.test/install (install): installed .* (sha256 $SHA)" $T/logs/audit.log && echo yes)"
check "a plugin: create_path makes the missing directories as t7 with the layout's pattern, files inside" "0 t7 agensio 2750 t7 agensio 640" "$(ctl site-install t7.test --file wp.tgz --path wp-content/plugins/demo --create-path --yes --reason plugin > $T/out; echo -n "$? "; stat -c '%U %G %a' $T/www/t7.test/wp-content/plugins/demo | tr -d '\n'; echo -n " "; stat -c '%U %G %a' $T/www/t7.test/wp-content/plugins/demo/index.php)"
check "site-copy: the plugin's drop-in lands in wp-content as t7 with the layout's pattern" "0 t7 agensio 640 yes" "$(ctl site-copy t7.test --from wp-content/plugins/demo/index.php --to wp-content/dropin.php --yes --reason dropin > $T/out; echo -n "$? "; stat -c '%U %G %a' $T/www/t7.test/wp-content/dropin.php | tr -d '\n'; echo " $(cmp -s $T/www/t7.test/wp-content/plugins/demo/index.php $T/www/t7.test/wp-content/dropin.php && echo yes)")"
mkdir -p $T/www/t7.test/wp-content/other; chown agensio:agensio $T/www/t7.test/wp-content/other
check "site-copy: a destination directory owned by another account is refused, nothing written" "1 yes no" "$(ctl site-copy t7.test --from wp-content/dropin.php --to wp-content/other/db.php --yes --reason dropin > $T/out; echo -n "$? "; grep -q 'another account' $T/out && echo -n yes; echo " $([ -e $T/www/t7.test/wp-content/other/db.php ] && echo yes || echo no)")"
check "a component owned by another account is refused, nothing created below it" "1 yes no" "$(ctl site-install t7.test --file wp.tgz --path wp-content/other/x --create-path --yes --reason plugin > $T/out; echo -n "$? "; grep -q 'another account' $T/out && echo -n yes; echo " $([ -e $T/www/t7.test/wp-content/other/x ] && echo yes || echo no)")"
rm -rf $T/www/t7.test/*
check "an archive with a symlink is refused, the directory stays empty" "1 yes 0" "$(ctl upload evil.tgz $T/pub/evil.tgz > /dev/null; ctl site-install t7.test --file evil.tgz --yes --reason evil > $T/out; echo -n "$? "; grep -q 'symbolic link' $T/out && echo -n yes; echo " $(ls -A $T/www/t7.test | wc -l | tr -d ' ')")"
check "a tarball made with 'tar -C dir .' installs (its ./ root entry is nothing to create)" "0 19" "$(ctl upload dot.tgz $T/pub/dot.tgz > /dev/null; ctl site-install t7.test --file dot.tgz --yes --reason dot > /dev/null; echo -n "$? "; find $T/www/t7.test -type f | wc -l | tr -d ' ')"
rm -rf $T/www/t7.test/*

# Downloads: fenced by address unless install_private, verified by sha256, https only.
check "a download from a private address is fenced (install_private is off)" "1 yes 0" "$(ctl site-install t7.test --url https://127.0.0.1:18298/wp.tgz --yes --reason dl > $T/out; echo -n "$? "; grep -q 'private or local address' $T/out && echo -n yes; echo " $(ls -A $T/www/t7.test | wc -l | tr -d ' ')")"
check "a plain http URL is refused" "1" "$(ctl site-install t7.test --url http://127.0.0.1:18297/wp.tgz --yes --reason dl > /dev/null; echo $?)"
stop
sed -i 's#^install_ca = #install_private = true\ninstall_ca = #' $T/agensio.toml
start
check "with install_private and install_ca the site's account downloads over https and installs" "0 yes yes" "$(ctl site-install t7.test --url https://127.0.0.1:18298/wp.tgz --sha256 $SHA --yes --reason dl > $T/out; echo -n "$? "; grep -q "\"sha256\":\"$SHA\"" $T/out && echo -n yes; echo " $([ "$(stat -c %U $T/www/t7.test/index.php)" = t7 ] && echo yes)")"
check "the download was fetched by the site account (access log shows it, temp file gone)" "yes 0" "$(sleep 1.2; grep -q 'GET /wp.tgz' $T/logs/access.log && echo yes) $(ls -A $T/www/t7.test | grep -c agensio-download)"
rm -rf $T/www/t7.test/*
check "a wrong sha256 on a download is refused and leaves nothing" "1 yes 0" "$(ctl site-install t7.test --url https://127.0.0.1:18298/wp.tgz --sha256 $(printf 'a%.0s' $(seq 1 64)) --yes --reason dl > $T/out; echo -n "$? "; grep -q 'sha256 mismatch' $T/out && echo -n yes; echo " $(ls -A $T/www/t7.test | wc -l | tr -d ' ')")"
check "a URL that answers 404 is reported, nothing installed" "1 yes" "$(ctl site-install t7.test --url https://127.0.0.1:18298/nope.tgz --yes --reason dl > $T/out; echo -n "$? "; grep -q 'HTTP 404' $T/out && echo yes)"

# The account rule: a target owned by root is refused; one owned by the server's account runs as it.
mkdir -p $T/www/t6.test/web
ctl site-create --domain t6.test --app static --root "$T/www/t6.test/web" --no-user --https none --listen-plain 127.0.0.1:18299 --yes --reason t6 > /dev/null
check "a root-owned site directory is refused with the fix" "1 yes 0" "$(ctl site-install t6.test --file wp.tgz --yes --reason t6 > $T/out; echo -n "$? "; grep -q 'belongs to root' $T/out && echo -n yes; echo " $(ls -A $T/www/t6.test/web | wc -l | tr -d ' ')")"
chown agensio:agensio $T/www/t6.test/web
check "a target owned by the server's account installs as that account" "0 agensio" "$(ctl site-install t6.test --file wp.tgz --yes --reason t6 > /dev/null; echo -n "$? "; stat -c %U $T/www/t6.test/web/index.php)"
useradd -M -s /bin/sh t6login 2>/dev/null; mkdir -p $T/www/t5.test/web; chown t6login $T/www/t5.test/web
ctl site-create --domain t5.test --app static --root "$T/www/t5.test/web" --no-user --https none --listen-plain 127.0.0.1:18299 --yes --reason t5 > /dev/null
check "a target owned by a login account is refused (only site accounts and the server's)" "1 yes" "$(ctl site-install t5.test --file wp.tgz --yes --reason t5 > $T/out; echo -n "$? "; grep -q 'login shell' $T/out && echo yes)"
userdel t6login 2>/dev/null
check "uploads-delete works and every upload action is audited" "0 yes yes" "$(ctl uploads-delete wp.tgz --yes --reason done > /dev/null; echo -n "$? "; grep -q 'uploads/wp.tgz: stored' $T/logs/audit.log && echo -n yes; echo " $(grep -q 'uploads/wp.tgz/delete (done): deleted' $T/logs/audit.log && echo yes)")"
check "the helper process is still a single root child holding one socket" "root 1" "$(HP=$(pgrep -P $(cat $T/agensio.pid) | head -1); ps -o user= -p $HP | tr -d ' ') $(ls -l /proc/$(pgrep -P $(cat $T/agensio.pid) | head -1)/fd | grep -c 'socket:')"
echo "install: $pass passed, $fail failed"
[ $fail = 0 ] || { echo "--- error.log"; cat $T/logs/error.log; echo "--- audit"; cat $T/logs/audit.log; echo "--- last out"; cat $T/out 2>/dev/null; }
[ $fail = 0 ]
