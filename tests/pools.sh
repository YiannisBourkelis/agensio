#!/usr/bin/env bash
# C3b integration test, Linux only, needs root (run it in the devbox as root:
#   docker run --rm --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox tests/pools.sh build/agensio).
# Two sites, two users: agensio generates their php-fpm pools, the distro's php-fpm runs
# them, agensio starts as root, binds, owns the logs and drops to user `agensio`. Checks:
# each site's PHP runs as its own user, open_basedir keeps it out of the other site,
# sessions land in the private directory, the access log is agensio:<site group> 0640,
# and `-t` refuses a world-readable .env, a socket with the wrong group and a run as a
# user that cannot switch.
set -euo pipefail
BIN=${1:-build/agensio}
[ "$(id -u)" = 0 ] || { echo "pools.sh: must run as root"; exit 1; }
[ -x "$BIN" ] || { echo "pools.sh: $BIN missing"; exit 1; }
FPM=$(ls /usr/sbin/php-fpm* | head -1)
PHPV=$(basename "$FPM" | sed 's/php-fpm//')
POOLD=/etc/php/$PHPV/fpm/pool.d
T=$(mktemp -d /tmp/agensio-pools.XXXXXX); chmod 755 "$T"  # mktemp gives 0700: nobody could traverse it
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$3] got [$2]"; fail=$((fail+1)); fi; }
cleanup() { pkill -f "^$BIN -c $T/" 2>/dev/null || true; pkill -f "php-fpm: master process ($T" 2>/dev/null || true; rm -f $POOLD/agensio-web*.conf; rm -rf "$T"; }
trap cleanup EXIT

for u in web1 web2 agensio; do id -u $u >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin $u; done
mkdir -p $T/run $T/state $T/logs $T/pool.d
chown agensio:agensio $T/logs; chmod 750 $T/logs
for u in web1 web2; do
  mkdir -p $T/$u/site/public
  printf '<?php session_start(); echo json_encode(["user" => posix_getpwuid(posix_geteuid())["name"], "other" => @file_get_contents("%s/%s/site/public/.env") === false ? "denied" : "READ", "session" => ini_get("session.save_path")], JSON_UNESCAPED_SLASHES);' \
    $T "$([ $u = web1 ] && echo web2 || echo web1)" > $T/$u/site/public/index.php
  echo "SECRET=$u" > $T/$u/site/public/.env   # inside the docroot: hidden by agensio, a secret for the rules
  # The layout the rules require: the site user owns it, the server's group reads it (2750).
  chown -R $u:agensio $T/$u; chmod 2750 $T/$u $T/$u/site $T/$u/site/public; chmod 644 $T/$u/site/public/index.php
  chown $u:$u $T/$u/site/public/.env; chmod 640 $T/$u/site/public/.env   # a secret keeps the user's own group
done

cat > $T/agensio.toml <<EOF
[server]
workers = 1
user = "agensio"
pools_run = "$T/run"
state_dir = "$T/state"
[log]
access = "$T/logs/access.log"
error = "$T/logs/error.log"
[[site]]
server_name = ["one"]
listen = ["127.0.0.1:18095"]
root = "$T/web1/site/public"
user = "web1"
app = "php"
php = { children = 2 }
access_log = "$T/logs/one.log"
[[site]]
server_name = ["two"]
listen = ["127.0.0.1:18095"]
root = "$T/web2/site/public"
user = "web2"
app = "php"
php = { children = 2 }
access_log = "$T/logs/two.log"
EOF

# Pools: written into the distro directory, php-fpm started with a private config that
# includes them (so the test does not depend on the system's php-fpm service).
rc=0; "$BIN" pools -c $T/agensio.toml --out $POOLD > $T/pools.out || rc=$?
check "agensio pools writes two files (exit 3)" "$rc $(ls $POOLD | grep -c '^agensio-web')" "3 2"
check "state directories owned by the user" "$(stat -c '%U %a' $T/state/web1/sessions)" "web1 700"
rc=0; "$BIN" pools -c $T/agensio.toml --out $POOLD > /dev/null || rc=$?; check "second run changes nothing (exit 0)" "$rc" "0"
printf '[global]\npid = %s/fpm.pid\nerror_log = %s/fpm.log\ninclude = %s/agensio-web*.conf\n' $T $T $POOLD > $T/fpm.conf
$FPM -y $T/fpm.conf -D
for i in $(seq 1 50); do [ -S $T/run/agensio-web1.sock ] && [ -S $T/run/agensio-web2.sock ] && break; sleep 0.1; done
check "sockets owned by the user, group agensio, 0660" "$(stat -c '%U %G %a' $T/run/agensio-web1.sock)" "web1 agensio 660"

# The rules: a clean layout passes, each violation is named.
rc=0; "$BIN" -t -c $T/agensio.toml > $T/t.out 2>&1 || rc=$?; check "-t passes on the clean layout" "$rc" "0"
chmod 644 $T/web1/site/public/.env
"$BIN" -t -c $T/agensio.toml > $T/t.out 2>&1 || true
check "-t refuses a world-readable .env" "$(grep -c 'site one: .*/.env is readable by other users' $T/t.out)" "1"
chmod 640 $T/web1/site/public/.env
chgrp web2 $T/run/agensio-web2.sock
"$BIN" -t -c $T/agensio.toml > $T/t.out 2>&1 || true
check "-t refuses a socket with the wrong group" "$(grep -c 'site two: socket .* expected group agensio' $T/t.out)" "1"
chgrp agensio $T/run/agensio-web2.sock
rc=0; "$BIN" -t -c $T/agensio.toml > $T/t2.out 2>&1 || rc=$?; check "-t passes again" "$rc $(grep -c 'configuration error' $T/t2.out || true)" "0 0"
chown web1:web1 $T/web1/site/public
"$BIN" -t -c $T/agensio.toml > $T/t.out 2>&1 || true
check "-t refuses a root the server cannot read, names the fix" "$(grep -c 'site one: root .* cannot read it.*chown web1:agensio' $T/t.out)" "1"
chown web1:agensio $T/web1/site/public

# Start as root, drop to agensio, serve both sites through their own pools.
"$BIN" -c $T/agensio.toml > $T/server.out 2>&1 &
SRV=$!
for i in $(seq 1 50); do nc -z 127.0.0.1 18095 2>/dev/null && break; sleep 0.1; done
check "server process runs as agensio" "$(ps -o user= -p $SRV | tr -d ' ')" "agensio"
one=$(curl -s -H 'Host: one' http://127.0.0.1:18095/)
two=$(curl -s -H 'Host: two' http://127.0.0.1:18095/)
check "site one answers 200" "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: one' http://127.0.0.1:18095/)" "200"
check "site one runs PHP as web1" "$(echo "$one" | grep -o '"user":"[^"]*"')" '"user":"web1"'
check "site two runs PHP as web2" "$(echo "$two" | grep -o '"user":"[^"]*"')" '"user":"web2"'
check "open_basedir keeps web1 out of web2's .env" "$(echo "$one" | grep -o '"other":"[^"]*"')" '"other":"denied"'
check "sessions in the private directory" "$(echo "$one" | grep -o "\"session\":\"[^\"]*\"")" "\"session\":\"$T/state/web1/sessions\""
check "session files written there as web1" "$([ "$(ls -l $T/state/web1/sessions | grep -c ' web1 ')" -ge 1 ] && echo yes)" "yes"
sleep 1.2  # access log flush timer
check "site log owned by agensio, group web1, 0640" "$(stat -c '%U %G %a' $T/logs/one.log)" "agensio web1 640"
check "site log has the requests" "$(grep -c 'GET / ' $T/logs/one.log)" "2"
kill $SRV; wait $SRV 2>/dev/null || true

# Started as the target user itself (systemd style) is fine; as another non-root user
# it cannot switch and says so (or cannot even open the logs, which is the same refusal).
su -s /bin/bash web1 -c "$BIN -c $T/agensio.toml" > $T/nonroot.out 2>&1 || true
check "start as a different non-root user is refused" "$(grep -c 'not root and cannot switch\|fatal:\|configuration error' $T/nonroot.out | sed 's/^[1-9][0-9]*$/1/')" "1"

echo "pools: $pass passed, $fail failed"
if [ $fail != 0 ]; then echo "--- server.out"; cat $T/server.out; echo "--- error.log"; cat $T/logs/error.log 2>/dev/null; echo "--- fpm.log"; cat $T/fpm.log 2>/dev/null | tail -5; echo "--- nonroot.out"; cat $T/nonroot.out; fi
[ $fail = 0 ]
