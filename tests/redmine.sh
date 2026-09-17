#!/usr/bin/env bash
# Live checks of a Rails application (Redmine) behind agensio's proxy preset. Skips when
# the bed is not running (bench/redmine/setup.sh). Usage: tests/redmine.sh build/agensio
set -uo pipefail
BIN=${1:-build/agensio}
curl -fs -o /dev/null http://127.0.0.1:3010/ 2>/dev/null || { echo "redmine: bed not running, skipped"; exit 0; }
"$BIN" -c bench/redmine/agensio.toml > bench/tmp/redmine-agensio.log 2>&1 & PID=$!
trap 'kill $PID 2>/dev/null' EXIT
for _ in $(seq 1 50); do nc -z 127.0.0.1 8075 2>/dev/null && break; sleep 0.1; done
B=http://127.0.0.1:8075
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }  # name expected actual
J=bench/tmp/redmine-cookies; rm -f $J
check "home page is Redmine" "200 yes" "$(curl -sS -c $J -o bench/tmp/redmine-home.html -w '%{http_code}' $B/) $(grep -qi 'redmine' bench/tmp/redmine-home.html && echo yes)"
css=$(grep -o 'href="/[^"]*\.css[^"]*"' bench/tmp/redmine-home.html | head -1 | sed 's/href="//; s/"$//')
check "stylesheet served through the proxy" "200 text/css" "$(curl -sS -o /dev/null -w '%{http_code} %{content_type}' "$B$css" | sed 's/;.*//')"
check "login page" "200" "$(curl -sS -b $J -c $J -o bench/tmp/redmine-login.html -w '%{http_code}' $B/login)"
token=$(grep -o 'name="authenticity_token" value="[^"]*"' bench/tmp/redmine-login.html | head -1 | sed 's/.*value="//; s/"$//')
check "login POST redirects, Location kept on this host" "302 http://127.0.0.1:8075/" "$(curl -sS -b $J -c $J -o /dev/null -w '%{http_code} %{redirect_url}' --data-urlencode "authenticity_token=$token" --data-urlencode 'username=admin' --data-urlencode 'password=admin' $B/login | sed 's#8075/.*#8075/#')"
check "session cookie survives the proxy: /my/account is not the login page" "yes" "$(curl -sS -b $J -c $J -L -o bench/tmp/redmine-my.html -w '%{http_code}' $B/my/account >/dev/null; grep -q 'authenticity_token' bench/tmp/redmine-my.html && ! grep -q 'name="username"' bench/tmp/redmine-my.html && echo yes)"
check "unknown route is Redmine's 404, passed through" "404" "$(curl -sS -o /dev/null -w '%{http_code}' $B/no-such-route)"
check "keep-alive on the client side" "1 0 0" "$(curl -sS -b $J -o /dev/null -o /dev/null -o /dev/null -w '%{num_connects} ' $B/login $B/login $B/login | sed 's/ $//')"
echo "redmine: $pass passed, $fail failed"; [ $fail = 0 ]
