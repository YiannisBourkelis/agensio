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
T=$(mktemp -d /tmp/agensio-pools.XXXXXX); chmod 755 "$T"  # mktemp gives 0700: nobody could traverse it
POOLD=$T/pool.d   # the version's pool directory, root's [php.runtimes] (docs/configuration.md 7b): nothing goes into /etc
# A pool per site: agensio-<user>-<8 hex of the domain>, its socket with the version (FNV-1a of "one", "two").
S1=$T/run/agensio-web1-ba2719ef-$PHPV.sock; S2=$T/run/agensio-web2-be248829-$PHPV.sock
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$3] got [$2]"; fail=$((fail+1)); fi; }
cleanup() { pkill -f "^$BIN -c $T/" 2>/dev/null || true; pkill -f "php-fpm: master process ($T" 2>/dev/null || true; rm -rf "$T"; }
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
[php.runtimes."$PHPV"]
fpm = "$FPM"
conf = "$T/fpm.conf"
pools = "$POOLD"
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

# Pools: written into the version's pool directory and tested there by its own php-fpm (as root),
# php-fpm started with that private config (so the test does not depend on the system's service).
printf '[global]\npid = %s/fpm.pid\nerror_log = %s/fpm.log\ninclude = %s/agensio-*.conf\n' $T $T $POOLD > $T/fpm.conf
rc=0; "$BIN" pools -c $T/agensio.toml > $T/pools.out || rc=$?
check "agensio pools writes two files, one per site (exit 3), and tests them" "$rc $(ls $POOLD | grep -c '^agensio-web') $(grep -c 'error' $T/pools.out)" "3 2 0"
check "state directories owned by the user, the site's own below the account's" "$(stat -c '%U %a' $T/state/web1/php/one/sessions) $(stat -c '%U %a' $T/state/web1)" "web1 700 web1 700"
rc=0; "$BIN" pools -c $T/agensio.toml > /dev/null || rc=$?; check "second run changes nothing (exit 0)" "$rc" "0"
$FPM -y $T/fpm.conf -D
for i in $(seq 1 50); do [ -S $S1 ] && [ -S $S2 ] && break; sleep 0.1; done
check "sockets owned by the user, group agensio, 0660" "$(stat -c '%U %G %a' $S1)" "web1 agensio 660"

# The rules: a clean layout passes, each violation is named.
rc=0; "$BIN" -t -c $T/agensio.toml > $T/t.out 2>&1 || rc=$?; check "-t passes on the clean layout" "$rc" "0"
chmod 644 $T/web1/site/public/.env
"$BIN" -t -c $T/agensio.toml > $T/t.out 2>&1 || true
check "-t refuses a world-readable .env" "$(grep -c 'site one: .*/.env is readable by other users' $T/t.out)" "1"
chmod 640 $T/web1/site/public/.env
chgrp web2 $S2
"$BIN" -t -c $T/agensio.toml > $T/t.out 2>&1 || true
check "-t refuses a socket with the wrong group" "$(grep -c 'site two: socket .* expected group agensio' $T/t.out)" "1"
chgrp agensio $S2
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
check "sessions in the site's private directory" "$(echo "$one" | grep -o "\"session\":\"[^\"]*\"")" "\"session\":\"$T/state/web1/php/one/sessions\""
check "session files written there as web1" "$([ "$(ls -l $T/state/web1/php/one/sessions | grep -c ' web1 ')" -ge 1 ] && echo yes)" "yes"
sleep 1.2  # access log flush timer
check "site log owned by agensio, group web1, 0640" "$(stat -c '%U %G %a' $T/logs/one.log)" "agensio web1 640"
check "site log has the requests" "$(grep -c 'GET / ' $T/logs/one.log)" "2"
kill $SRV; wait $SRV 2>/dev/null || true

# Started as the target user itself (systemd style) is fine; as another non-root user
# it cannot switch and says so (or cannot even open the logs, which is the same refusal).
su -s /bin/bash web1 -c "$BIN -c $T/agensio.toml" > $T/nonroot.out 2>&1 || true
check "start as a different non-root user is refused" "$(grep -c 'not root and cannot switch\|fatal:\|configuration error' $T/nonroot.out | sed 's/^[1-9][0-9]*$/1/')" "1"

# A key the server's account cannot read (the certificate work, step T1): with server.user the
# server reads the certificates as root at start and as agensio on every reload after that, so a
# root-only key works at boot and no renewal is ever loaded. -t names it with the fix, a reload
# after the start says the same and keeps the certificate; the fix applied, both are quiet.
K=$T/tls; mkdir -p $K/private $K/www $K/sites.d; echo "tls site" > $K/www/index.html; chmod 755 $K $K/www $K/sites.d
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout $K/private/key.pem -out $K/cert.pem \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost -days 2 > /dev/null 2>&1
chmod 700 $K/private; chmod 600 $K/private/key.pem; chmod 644 $K/cert.pem
cat > $K/agensio.toml <<EOF
include = ["sites.d/*.toml"]
[server]
workers = 1
user = "agensio"
pid_file = "$K/agensio.pid"
[log]
access = "off"
error = "$K/error.log"
EOF
cat > $K/sites.d/tls.toml <<EOF
[[site]]
server_name = ["localhost"]
listen = ["127.0.0.1:18461"]
root = "$K/www"
tls = { cert = "$K/cert.pem", key = "$K/private/key.pem" }
EOF
touch $K/error.log; chown agensio $K/error.log
"$BIN" -t -c $K/agensio.toml > $K/t.out 2>&1 || true
check "-t: a key only root can read under server.user is named, with the fix for its directory and itself" \
  "$(grep 'cannot read the key' $K/t.out | grep -c "chgrp agensio $K/private && chmod g+x $K/private.*chgrp agensio $K/private/key.pem && chmod 640 $K/private/key.pem")" "1"
"$BIN" -c $K/agensio.toml > $K/server.out 2>&1 & KS=$!
for i in $(seq 1 50); do nc -z 127.0.0.1 18461 2>/dev/null && break; sleep 0.1; done
kill -HUP $KS; sleep 0.8
check "a reload after the drop keeps the certificate and names the fix" \
  "$(curl -sk --max-time 3 --resolve localhost:18461:127.0.0.1 https://localhost:18461/) $(grep 'the certificate loaded before keeps serving' $K/error.log | grep -c "chgrp agensio $K/private/key.pem")" "tls site 1"
chgrp agensio $K/private $K/private/key.pem; chmod 750 $K/private; chmod 640 $K/private/key.pem
"$BIN" -t -c $K/agensio.toml > $K/t2.out 2>&1 || true
kill -HUP $KS; sleep 0.8
check "the key given the server's group: -t is quiet, the next reload loads it" \
  "$(grep -c 'cannot read the key' $K/t2.out) $(grep -c 'the certificate loaded before keeps serving' $K/error.log) $(curl -sk --max-time 3 --resolve localhost:18461:127.0.0.1 https://localhost:18461/)" "0 1 tls site"
kill $KS; wait $KS 2>/dev/null || true

# A burst on cold generated pools (the alpha.66 report): php-fpm's ondemand forks one child per
# event on its socket, and a child on a kept connection never accepts again while it stays open,
# so FastCGI connections opened together waited in the backlog until read_timeout (504). 120
# requests of a 150 ms script over 30 connections, read_timeout 5 s: every one answered, on an
# ondemand pool and a dynamic one.
B=$T/burst; mkdir -p $B/run $B/state $B/pool.d
for u in web3 web4; do
  id -u $u >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin $u
  mkdir -p $B/$u/public; echo '<?php usleep(150000); echo "slow\n";' > $B/$u/public/slow.php
  chown -R $u:agensio $B/$u; chmod 2750 $B/$u $B/$u/public; chmod 644 $B/$u/public/slow.php
done
cat > $B/agensio.toml <<EOF
[server]
workers = 1
user = "agensio"
pools_run = "$B/run"
state_dir = "$B/state"
[log]
access = "off"
error = "$T/logs/burst-error.log"
[php.runtimes."$PHPV"]
fpm = "$FPM"
conf = "$B/fpm.conf"
pools = "$B/pool.d"
[[site]]
server_name = ["ondemand.test"]
listen = ["127.0.0.1:18097"]
root = "$B/web3/public"
user = "web3"
app = "php"
php = { pm = "ondemand", read_timeout = 5 }
[[site]]
server_name = ["dynamic.test"]
listen = ["127.0.0.1:18097"]
root = "$B/web4/public"
user = "web4"
app = "php"
php = { pm = "dynamic", read_timeout = 5 }
EOF
printf '[global]\npid = %s/fpm.pid\nerror_log = %s/fpm.log\ninclude = %s/pool.d/*.conf\n' $B $B $B > $B/fpm.conf
"$BIN" pools -c $B/agensio.toml > /dev/null || true
$FPM -y $B/fpm.conf -D
for i in $(seq 1 50); do [ -S $B/run/agensio-web3-*.sock ] && [ -S $B/run/agensio-web4-*.sock ] && break; sleep 0.1; done
"$BIN" -c $B/agensio.toml > $B/server.out 2>&1 & BS=$!
for i in $(seq 1 50); do nc -z 127.0.0.1 18097 2>/dev/null && break; sleep 0.1; done
cat > $B/burst.py <<'EOF'
import http.client, sys, threading, time
host, codes, lock, t0 = sys.argv[1], [], threading.Lock(), time.time()
def run():
    c = http.client.HTTPConnection("127.0.0.1", 18097, timeout=30)
    for _ in range(4):
        try:
            c.request("GET", "/slow.php", headers={"Host": host}); r = c.getresponse(); r.read(); s = r.status
        except Exception:
            s = 0; c = http.client.HTTPConnection("127.0.0.1", 18097, timeout=30)
        with lock: codes.append(s)
ts = [threading.Thread(target=run) for _ in range(30)]
for t in ts: t.start()
for t in ts: t.join()
print(codes.count(200), codes.count(504), "%.2f" % (time.time() - t0))
EOF
for h in ondemand.test dynamic.test; do curl -s -o /dev/null -H "Host: $h" http://127.0.0.1:18097/slow.php; done   # one request each first
read -r od_ok od_504 od_s < <(python3 $B/burst.py ondemand.test)
read -r dy_ok dy_504 dy_s < <(python3 $B/burst.py dynamic.test)
echo "     burst: ondemand $od_ok answered, $od_504 x 504, ${od_s} s; dynamic $dy_ok, $dy_504 x 504, ${dy_s} s"
check "a burst on a cold ondemand pool: all 120 answered, none waits for read_timeout" "$od_ok $od_504" "120 0"
check "the same burst on a dynamic pool" "$dy_ok $dy_504" "120 0"
kill $BS; wait $BS 2>/dev/null || true
kill "$(cat $B/fpm.pid)" 2>/dev/null || true

# More workers than children: each worker kept a connection to a static or dynamic pool
# (max_connections = children / workers, at least 1), so 4 workers held 4 connections to 2
# children, and a request on a connection no child would take waited until read_timeout. 8
# connections x 2 requests of the 150 ms script, read_timeout 5 s: every one answered.
W=$T/wide; mkdir -p $W/run $W/state $W/pool.d
for u in web5 web6; do
  id -u $u >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin $u
  mkdir -p $W/$u/public; echo '<?php usleep(150000); echo "slow\n";' > $W/$u/public/slow.php
  chown -R $u:agensio $W/$u; chmod 2750 $W/$u $W/$u/public; chmod 644 $W/$u/public/slow.php
done
cat > $W/agensio.toml <<EOF
[server]
workers = 4
user = "agensio"
pools_run = "$W/run"
state_dir = "$W/state"
[log]
access = "off"
error = "$T/logs/wide-error.log"
[php.runtimes."$PHPV"]
fpm = "$FPM"
conf = "$W/fpm.conf"
pools = "$W/pool.d"
[[site]]
server_name = ["static.test"]
listen = ["127.0.0.1:18098"]
root = "$W/web5/public"
user = "web5"
app = "php"
php = { pm = "static", children = 2, read_timeout = 5 }
[[site]]
server_name = ["dynamic.test"]
listen = ["127.0.0.1:18098"]
root = "$W/web6/public"
user = "web6"
app = "php"
php = { pm = "dynamic", children = 2, read_timeout = 5 }
EOF
printf '[global]\npid = %s/fpm.pid\nerror_log = %s/fpm.log\ninclude = %s/pool.d/*.conf\n' $W $W $W > $W/fpm.conf
"$BIN" pools -c $W/agensio.toml > /dev/null || true
$FPM -y $W/fpm.conf -D
for i in $(seq 1 50); do [ -S $W/run/agensio-web5-*.sock ] && [ -S $W/run/agensio-web6-*.sock ] && break; sleep 0.1; done
"$BIN" -c $W/agensio.toml > $W/server.out 2>&1 & WS=$!
for i in $(seq 1 50); do nc -z 127.0.0.1 18098 2>/dev/null && break; sleep 0.1; done
cat > $W/burst.py <<'EOF'
import http.client, sys, threading, time
host, codes, lock, t0 = sys.argv[1], [], threading.Lock(), time.time()
def run():
    c = http.client.HTTPConnection("127.0.0.1", 18098, timeout=30)
    for _ in range(2):
        try:
            c.request("GET", "/slow.php", headers={"Host": host}); r = c.getresponse(); r.read(); s = r.status
        except Exception:
            s = 0; c = http.client.HTTPConnection("127.0.0.1", 18098, timeout=30)
        with lock: codes.append(s)
ts = [threading.Thread(target=run) for _ in range(8)]
for t in ts: t.start()
for t in ts: t.join()
print(codes.count(200), codes.count(504), "%.2f" % (time.time() - t0))
EOF
read -r st_ok st_504 st_s < <(python3 $W/burst.py static.test)
read -r dw_ok dw_504 dw_s < <(python3 $W/burst.py dynamic.test)
echo "     4 workers, 2 children: static $st_ok answered, $st_504 x 504, ${st_s} s; dynamic $dw_ok, $dw_504 x 504, ${dw_s} s"
check "4 workers before a static pool of 2 children: all 16 answered, none waits for read_timeout" "$st_ok $st_504" "16 0"
check "the same before a dynamic pool of 2 children" "$dw_ok $dw_504" "16 0"
kill $WS; wait $WS 2>/dev/null || true
kill "$(cat $W/fpm.pid)" 2>/dev/null || true

echo "pools: $pass passed, $fail failed"
if [ $fail != 0 ]; then echo "--- server.out"; cat $T/server.out; echo "--- error.log"; cat $T/logs/error.log 2>/dev/null; echo "--- fpm.log"; cat $T/fpm.log 2>/dev/null | tail -5; echo "--- nonroot.out"; cat $T/nonroot.out; fi
[ $fail = 0 ]
