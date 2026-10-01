#!/usr/bin/env bash
# Kanboard installed and secured through the control plane alone (2026-10-01, the proposal against
# alpha.39: a PHP application with its own server guidelines and no preset). As root in a devbox
# with php-fpm and Kanboard's extensions: a site with app = "php" and its own account gets
# Kanboard's release archive (site-install from GitHub), whose facts name the directories its
# .htaccess files deny; under the bare preset app/Core/Base.php would run, then site-update's
# rules make only index.php, jsonrpc.php and healthcheck.php run, deny Kanboard's private paths,
# cache its assets and route nice URLs to index.php; the site serves its login page over TLS
# from the generated php-fpm pool, with every private path a 404. Skipped without php-fpm, the
# pdo_sqlite extension or the network.
#   docker run --rm --init --user root --dns-option single-request-reopen --cpuset-cpus=0-3 \
#     -v "$PWD:$PWD" -w "$PWD" agensio-devbox:php tests/kanboard-install.sh build/agensio
# agensio-devbox:php is agensio-devbox plus Kanboard's PHP extensions:
#   printf 'FROM agensio-devbox\nUSER root\nRUN apt-get update && apt-get install -y --no-install-recommends php8.4-sqlite3 php8.4-mbstring php8.4-gd php8.4-xml php8.4-zip php8.4-curl && rm -rf /var/lib/apt/lists/*\n' \
#     | docker build -t agensio-devbox:php -
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
VERSION=${KANBOARD_VERSION:-1.2.54}
[ "$(id -u)" = 0 ] || { echo "kanboard: needs root; skipped"; exit 0; }
FPM=$(ls /usr/sbin/php-fpm* 2>/dev/null | head -1)
[ -n "$FPM" ] || { echo "kanboard: no php-fpm; skipped"; exit 0; }
php -m 2>/dev/null | grep -qi '^pdo_sqlite$' || { echo "kanboard: no pdo_sqlite; skipped"; exit 0; }
curl -4 -sSf -o /dev/null --max-time 60 https://github.com/ || { echo "kanboard: github.com unreachable; skipped"; exit 0; }
PHPV=$(basename "$FPM" | sed 's/php-fpm//'); POOLD=/etc/php/$PHPV/fpm/pool.d
T=$(mktemp -d /tmp/agensio-kanboard.XXXXXX); chmod 755 "$T"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() { [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; pkill -f "php-fpm: master process ($T" 2>/dev/null; sleep 0.3; rm -f $POOLD/agensio-kb.conf; pkill -9 -u kb 2>/dev/null; userdel kb 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
id -u agensio >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin agensio
mkdir -p $T/sites.d $T/logs $T/run $T/state $T/www $T/default $T/certs; chown agensio:agensio $T/sites.d $T/logs $T/state; chmod 751 $T/state
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj /CN=kb.test -addext subjectAltName=DNS:kb.test -keyout $T/certs/key.pem -out $T/certs/cert.pem 2>/dev/null
chown agensio:agensio $T/certs/key.pem; chmod 640 $T/certs/key.pem; chmod 644 $T/certs/cert.pem
cat > $T/agensio.toml <<CFG
include = ["sites.d/*.toml"]
[server]
workers = 1
user = "agensio"
pid_file = "$T/agensio.pid"
state_dir = "$T/state"
pools_run = "$T/run"
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
listen = ["127.0.0.1:18797"]
root = "$T/default"
CFG
"$BIN" -c $T/agensio.toml >> $T/server.out 2>&1 &
for _ in $(seq 1 50); do [ -S $T/run/control.sock ] && break; sleep 0.1; done; sleep 0.2
CS=$T/run/control.sock
ctl() { "$BIN" ctl "$@" --socket $CS; }
j() { python3 -c "import json,sys; d=json.load(open('$T/out')); print($1)"; }
APP=$T/www/kb.test/web
H="--resolve kb.test:18743:127.0.0.1 -k"

ctl site-create --domain kb.test --app php --root $APP --user kb --cert $T/certs/cert.pem --key $T/certs/key.pem --listen-plain 127.0.0.1:18780 --listen-tls 127.0.0.1:18743 --yes --reason live > $T/out
check "site-create: app = php with its own account and a generated php-fpm pool" "True kb yes" "$(j 'd["ok"]') $(stat -c %U $APP) $([ -f $POOLD/agensio-kb.conf ] && echo yes)"
# php-fpm with a private configuration that includes the generated pool (no systemd here).
printf '[global]\npid = %s/fpm.pid\nerror_log = %s/fpm.log\ninclude = %s/agensio-kb.conf\n' $T $T $POOLD > $T/fpm.conf
$FPM -y $T/fpm.conf -D
for _ in $(seq 1 50); do [ -S $T/run/agensio-kb.sock ] && break; sleep 0.1; done
check "the pool listens on the site's socket as kb" "kb" "$(stat -c %U $T/run/agensio-kb.sock)"
ctl site-install kb.test --url https://github.com/kanboard/kanboard/archive/refs/tags/v$VERSION.tar.gz --yes --reason live > $T/out
check "site-install from GitHub: the archive unpacked as kb; facts name the directories its .htaccess files deny; next steps carry the matching rules" "True app,data yes yes" "$(j 'd["ok"]') $(j '",".join(d["facts"]["htaccess_denied"])') $([ -f $APP/jsonrpc.php ] && [ "$(stat -c %U $APP/jsonrpc.php)" = kb ] && echo yes) $(j '"yes" if any("rules" in x and "/app/" in x and "/data/" in x and ".htaccess" in x for x in d["next_steps"]) else d["next_steps"]')"
check "under the bare php preset: the login page is served (after Kanboard's redirect), SQLite files and web.config are refused, but a PHP file of the application's internals runs" "200 404 404 yes" "$(curl -sSL $H -o $T/home.html -w '%{http_code}' https://kb.test:18743/) $(curl -sS $H -o /dev/null -w '%{http_code}' https://kb.test:18743/data/db.sqlite) $(curl -sS $H -o /dev/null -w '%{http_code}' https://kb.test:18743/web.config) $(c=$(curl -sS $H -o /dev/null -w '%{http_code}' https://kb.test:18743/app/Core/Base.php); [ "$c" != 404 ] && echo yes || echo "no ($c)")"
check "the page is Kanboard's login form" "yes" "$(grep -q 'form-login' $T/home.html && grep -q 'type="password"' $T/home.html && echo yes || head -c 200 $T/home.html | tr '\n' ' ')"
ctl site-update kb.test --private /app/ --private /data/ --private /libs/ --private /vendor/ --private /tests/ --private /docker/ --private /cli --private /web.config --private /composer.json --private /ChangeLog --private /Makefile --private /Dockerfile --entry-point /index.php --entry-point /jsonrpc.php --entry-point /healthcheck.php --cache /assets/=604800 --front-controller /index.php --yes --reason live > $T/out
check "site-update with Kanboard's rules: ok, the file carries them, site shows them" "True 3 12 yes" "$(j 'd["ok"]') $(ctl site kb.test > $T/out; j 'len(d["rules"]["entry_points"]), len(d["rules"]["private"])') $(grep -c 'handler = "deny"' $T/sites.d/kb.test.toml > /dev/null && echo yes)"
check "with the rules: the login page still, jsonrpc (a JSON-RPC answer) and healthcheck run, every other PHP file is 404, the private paths are 404, the assets are cached a week and run nothing" "200 yes 200 404 404 404 404 404 404 404 200 public, max-age=604800 404" "$(curl -sSL $H -o $T/home2.html -w '%{http_code}' https://kb.test:18743/) $(curl -sS $H -X POST https://kb.test:18743/jsonrpc.php | grep -q '"jsonrpc"' && echo yes) $(curl -sS $H -o /dev/null -w '%{http_code}' https://kb.test:18743/healthcheck.php) $(for p in /app/Core/Base.php /libs/Picodb/Database.php /vendor/autoload.php /data/db.sqlite /cli /web.config /app/; do curl -sS $H -o /dev/null -w '%{http_code} ' https://kb.test:18743$p; done)$(curl -sS $H -D $T/css.h -o /dev/null -w '%{http_code}' https://kb.test:18743/assets/css/vendor.min.css) $(grep -i '^cache-control:' $T/css.h | sed 's/^[^:]*: //' | tr -d '\r') $(curl -sS $H -o /dev/null -w '%{http_code}' https://kb.test:18743/assets/css/x.php)"
check "a nice URL reaches index.php through the front controller (Kanboard answers it, not a 404 from the file system)" "200 yes" "$(curl -sSL $H -o $T/nice.html -w '%{http_code}' https://kb.test:18743/login) $(grep -q 'form-login' $T/nice.html && echo yes || head -c 200 $T/nice.html | tr '\n' ' ')"
check "Kanboard wrote its SQLite database as kb and it stays private" "kb 404" "$(stat -c %U $APP/data/db.sqlite 2>/dev/null) $(curl -sS $H -o /dev/null -w '%{http_code}' https://kb.test:18743/data/db.sqlite)"
check "health has nothing to say about the site's files" "" "$(ctl health | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(f["code"] + ":" + f.get("message", "")[:80] for f in d["findings"] if f.get("site") == "kb.test" and f["severity"] != "info"))')"

echo "kanboard: $pass passed, $fail failed"
if [ "$fail" != 0 ]; then echo "--- error.log"; tail -20 $T/logs/error.log; echo "--- fpm"; tail -20 $T/fpm.log 2>/dev/null; fi
[ "$fail" = 0 ]
