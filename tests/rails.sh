#!/usr/bin/env bash
# The Rails workflow of F13, live: as root in a devbox with Ruby (ruby, ruby-dev,
# ruby-bundler, libyaml-dev) and access to rubygems.org, a site with app = "rails" and its
# own account is created, Rails is installed into the account's gem directory, a new
# application is made, its databases prepared and its assets built, all through site-task;
# Puma is then started as the site's account the way docs/examples/puma.service does it, and
# agensio serves the application over TLS. Minutes (gems are compiled); skipped without Ruby
# or without the network.
#   docker build -t agensio-devbox:ruby - <<'EOF'
#   FROM agensio-devbox
#   USER root
#   RUN apt-get update && apt-get install -y --no-install-recommends ruby ruby-dev ruby-bundler libyaml-dev && rm -rf /var/lib/apt/lists/*
#   EOF
#   docker run --rm --init --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox:ruby tests/rails.sh build/agensio
# About a minute when the network behaves. Two things about the network were learnt on the
# Ryzen box (2026-09-27): the container's resolver answered each parallel A/AAAA lookup in
# 5 s (--dns-option single-request-reopen fixes it; the host's resolver has the same
# quirk), and some parallel TCP connections to the gem index are silently dropped for tens
# of seconds (the host shows it too, so it is the path, not Docker). Bundler opens one
# connection per CPU and waits for the slowest, so on such a network run the container
# with --cpuset-cpus=0-3: four connections instead of twenty-four.
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
ROOT=$(pwd)
[ "$(id -u)" = 0 ] || { echo "rails: needs root; skipped"; exit 0; }
[ -x /usr/bin/ruby ] && [ -x /usr/bin/bundle ] || { echo "rails: no ruby/bundle in /usr/bin; skipped"; exit 0; }
curl -sSf -o /dev/null --max-time 10 https://rubygems.org/ || { echo "rails: rubygems.org unreachable; skipped"; exit 0; }
# Bundler resolves hundreds of names: a resolver that answers its parallel A and AAAA queries
# slowly (5 s each here, until the container ran with --dns-option single-request-reopen)
# turns a one-minute run into an hour.
ms=$(python3 -c 'import socket,time; t=time.time(); socket.getaddrinfo("index.rubygems.org", 443); print(int((time.time()-t)*1000))')
[ "$ms" -gt 1500 ] && echo "note: a name lookup takes $ms ms here; run the container with --dns-option single-request-reopen, or expect a long run"
[ "$(nproc)" -gt 8 ] && echo "note: bundler will open $(nproc) parallel connections (one per CPU); on a network that stalls some of them, run the container with --cpuset-cpus=0-3"
T=$(mktemp -d /tmp/agensio-rails.XXXXXX); chmod 755 "$T"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() { [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; pkill -9 -u r5 2>/dev/null; sleep 0.3; userdel r5 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
id -u agensio >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin agensio
mkdir -p $T/sites.d $T/logs $T/run $T/state $T/www $T/default $T/certs; chown agensio:agensio $T/sites.d $T/logs $T/state; chmod 751 $T/state
# A certificate for r5.test: agensio answers 421 to a Host its certificate does not cover.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=r5.test -addext subjectAltName=DNS:r5.test -keyout $T/certs/key.pem -out $T/certs/cert.pem 2>/dev/null
chown agensio:agensio $T/certs/key.pem; chmod 640 $T/certs/key.pem; chmod 644 $T/certs/cert.pem
cat > $T/agensio.toml <<CFG
include = ["sites.d/*.toml"]
[server]
workers = 1
user = "agensio"
pid_file = "$T/agensio.pid"
state_dir = "$T/state"
[log]
access = "$T/logs/access.log"
error = "$T/logs/error.log"
level = "info"
[control]
socket = "$T/run/control.sock"
audit = "$T/logs/audit.log"
sites_root = "$T/www"
task_limits = { timeout = 300 }   # a stalled download fails the run in minutes, not the default twenty
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:18597"]
root = "$T/default"
CFG
"$BIN" -c $T/agensio.toml >> $T/server.out 2>&1 &
for _ in $(seq 1 50); do [ -S $T/run/control.sock ] && break; sleep 0.1; done; sleep 0.2
CS=$T/run/control.sock
ctl() { "$BIN" ctl "$@" --socket $CS; }
j() { python3 -c "import json,sys; d=json.load(open('$T/out')); print($1)"; }
APP=$T/www/r5.test/app
task() {  # task NAME [--param k=v]: runs it, prints ok exit seconds, keeps the answer in $T/out
    ctl site-task r5.test "$@" --yes --reason live > $T/out
    j 'd["ok"], d.get("exit"), int(d.get("duration_ms", 0) / 1000)'
    python3 -c "import json; d=json.load(open('$T/out')); o=d.get('output', ''); print(d.get('error', '')); print(o if len(o) < 6000 else o[:3000] + '\n[...]\n' + o[-3000:])" > $T/last-$1.txt
}

# A host-wide Rails, as root installed it on the host of the 2026-09-27 report: without
# GEM_PATH isolation it satisfied every dependency and the account got no rails command.
gem install rails --no-document > $T/system-rails.log 2>&1 || { echo "rails: root's gem install rails failed"; tail -3 $T/system-rails.log; }
out=$(ctl site-create --domain r5.test --app rails --root $APP --user r5 --upstream http://127.0.0.1:18500 --cert $T/certs/cert.pem --key $T/certs/key.pem --listen-plain 127.0.0.1:18580 --listen-tls 127.0.0.1:18543 --yes --reason live)
check "site-create: app = rails with its own account, through the helper" "yes r5" "$(echo "$out" | grep -q '"ok":true' && echo yes) $(stat -c %U $APP)"
check "site-tasks: every interpreter is in place before the first task" "True" "$(ctl site-tasks r5.test | python3 -c 'import json,sys; print(all(t["interpreter"]["ok"] for t in json.load(sys.stdin)["tasks"]))')"
r=$(task gem_install_rails)
check "gem_install_rails: Rails 8 with its whole tree in the account's gem directory, despite root's system-wide Rails" "True 0 yes" "$(echo $r | cut -d' ' -f1-2) $([ -x $T/state/r5/gems/bin/rails ] && echo yes)"
echo "     gem_install_rails took $(echo $r | cut -d' ' -f3) s"
r=$(task rails_new --param name=live)
check "rails_new: a new application with its bundle in vendor/bundle" "True 0 yes yes" "$(echo $r | cut -d' ' -f1-2) $([ -f $APP/config/application.rb ] && echo yes) $([ -d $APP/vendor/bundle ] && echo yes)"
echo "     rails_new took $(echo $r | cut -d' ' -f3) s"
check "rails_new: the installers Rails skips without a bundle ran (importmap, Solid Queue)" "yes yes" "$([ -f $APP/config/importmap.rb ] && echo yes) $([ -f $APP/config/queue.yml ] && echo yes)"
check "rails_new: the key and the databases' directory are r5's alone; the server reads public/" "600 710 yes no" "$(stat -c %a $APP/config/master.key) $(stat -c %a $APP/storage) $(su -s /bin/sh agensio -c "cat $APP/public/robots.txt" > /dev/null 2>&1 && echo yes) $(su -s /bin/sh agensio -c "cat $APP/config/master.key" > /dev/null 2>&1 && echo yes || echo no)"
r=$(task db_prepare)
check "db_prepare: the production databases exist, 0600" "True 0 600" "$(echo $r | cut -d' ' -f1-2) $(stat -c %a $APP/storage/production.sqlite3 2>/dev/null)"
r=$(task assets_precompile)
check "assets_precompile: public/assets built" "True 0 yes" "$(echo $r | cut -d' ' -f1-2) $([ -f $APP/public/assets/.manifest.json ] && echo yes)"
check "the configuration validates after every task (no hosting rule broken by what Rails wrote)" "true" "$(ctl validate | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["ok"]).lower())')"

# The application without its Rails credentials, as a ONCE application's archive comes
# (2026-09-27 Writebook report): its secret comes from the site's environment, which the
# tasks and Puma both read.
mv $APP/config/credentials.yml.enc $T/credentials.yml.enc; mv $APP/config/master.key $T/master.key
r=$(task db_migrate)
check "without credentials or SECRET_KEY_BASE, db_migrate stops on Rails' missing secret and the answer's hint names the fix" "False 1 yes" "$(echo $r | cut -d' ' -f1-2) $(j '"yes" if "site_env_set with generate" in d.get("hint", "") else d.get("hint")')"
ctl site-env-set r5.test --generate SECRET_KEY_BASE --yes --reason live > $T/out
check "site-env-set: SECRET_KEY_BASE generated into root's file, 0600" "SECRET_KEY_BASE root 600" "$(j '",".join(d["generated"])') $(stat -c '%U %a' $T/env/r5.test.env)"
r=$(task db_migrate)
check "without Rails credentials, db_migrate runs on the site's environment" "True 0" "$(echo $r | cut -d' ' -f1-2)"

# Puma as the site's account, with the environment of docs/examples/puma.service: its
# Environment= lines and the site's environment file (EnvironmentFile=), here read by root.
runuser -u r5 -- /usr/bin/env -i PATH=/usr/bin:/bin HOME=$T/state/r5 TMPDIR=$T/state/r5/tmp LANG=C.UTF-8 RAILS_ENV=production \
    BUNDLE_PATH=vendor/bundle BUNDLE_WITHOUT=development:test RAILS_LOG_TO_STDOUT=1 GEM_HOME=$T/state/r5/gems GEM_PATH=$T/state/r5/gems \
    $(sed -n 's/^\([A-Z_][A-Z0-9_]*\)="\(.*\)"$/\1=\2/p' $T/env/r5.test.env) \
    /bin/sh -c "cd $APP && umask 027 && exec /usr/bin/bundle exec puma -e production -b tcp://127.0.0.1:18500" > $T/puma.out 2>&1 &
for _ in $(seq 1 100); do curl -s -o /dev/null http://127.0.0.1:18500/up && break; sleep 0.3; done
# Whose socket listens on 18500 (0x4844): the uid column of the kernel's table. ss -p and a
# /proc scan need CAP_SYS_PTRACE for another account's descriptors, which Docker withholds.
PUMA_UID=$(awk '$2 ~ /:4844$/ && $4 == "0A" {print $8; exit}' /proc/net/tcp)
check "Puma runs as r5 and listens on loopback only" "r5 127.0.0.1:18500" "$(getent passwd "${PUMA_UID:-x}" | cut -d: -f1) $(ss -ltnH 'sport = :18500' | awk '{print $4}' | head -1)"
H="--resolve r5.test:18543:127.0.0.1 -k"
check "agensio serves the application over TLS, its secret from the site's environment: /up is green" "200 yes" "$(curl -sS $H -o $T/up.html -w '%{http_code}' https://r5.test:18543/up) $(grep -q 'green' $T/up.html && echo yes)"
ASSET=$(python3 -c "import json; m=json.load(open('$APP/public/assets/.manifest.json')); v=m[sorted(m)[0]]; print(v if isinstance(v, str) else v['digested_path'])" 2>/dev/null)
check "a precompiled asset comes through agensio" "200" "$(curl -sS $H -o /dev/null -w '%{http_code}' https://r5.test:18543/assets/$ASSET)"
check "a credential path is refused by agensio itself, never proxied to Puma (no x-request-id)" "404 no" "$(curl -sS $H -D $T/probe.h -o /dev/null -w '%{http_code}' https://r5.test:18543/config/master.key) $(grep -qi '^x-request-id' $T/probe.h && echo yes || echo no)"
check "databases and logs by their ending, and all of /storage/, are refused by agensio (no x-request-id)" "404 404 no" "$(curl -sS $H -D $T/probe2.h -o /dev/null -w '%{http_code}' https://r5.test:18543/storage/production.sqlite3) $(curl -sS $H -o /dev/null -w '%{http_code}' https://r5.test:18543/x/y/production.LOG) $(grep -qi '^x-request-id' $T/probe2.h && echo yes || echo no)"
check "plain http is redirected to https" "301" "$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: r5.test' http://127.0.0.1:18580/up)"
check "the audit log has each task with the argv that ran" "5" "$(grep -c 'sites/r5.test/task (live): ran as r5 .* -> exit 0' $T/logs/audit.log)"
check "health: no PHP finding and no unreadable-files finding for the Rails site" "no" "$(ctl health | grep -q 'php_tmp_missing\|pools_stale\|files_unreadable' && echo yes || echo no)"

echo "rails: $pass passed, $fail failed"
if [ "$fail" != 0 ]; then
    for f in $T/last-*.txt; do echo "--- $f"; head -30 "$f"; echo "..."; tail -10 "$f"; done
    echo "--- puma"; tail -40 $T/puma.out
fi
[ "$fail" = 0 ]
