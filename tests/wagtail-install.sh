#!/usr/bin/env bash
# Wagtail installed through the control plane alone (2026-09-28, the Django "wall 1" report):
# as root in a devbox with python3-venv and access to pypi.org, a site with app = "wagtail",
# its own account and project = "mysite" gets its virtualenv, Wagtail, the project, its
# requirements, Gunicorn, the settings agensio writes, its schema, its static files and its
# first admin through site-task; Gunicorn is then started with the very unit `agensio ctl
# site-unit` renders (its Environment lines, its UnsetEnvironment, its `@` ExecStart, as the
# site's account), and agensio serves the site over TLS: the home page and the admin through
# Gunicorn, /static/ from disk, the admin's login POST past Django's CSRF check (the
# forwarded https), /media/documents/ refused. Skipped without python3-venv or the network.
#   docker run --rm --init --user root --dns-option single-request-reopen --cpuset-cpus=0-3 \
#     -v "$PWD:$PWD" -w "$PWD" agensio-devbox:python tests/wagtail-install.sh build/agensio
# agensio-devbox:python is agensio-devbox plus python3-venv (Debian ships venv's ensurepip apart):
#   printf 'FROM agensio-devbox\nUSER root\nRUN apt-get update && apt-get install -y --no-install-recommends python3-venv && rm -rf /var/lib/apt/lists/*\n' \
#     | docker build -t agensio-devbox:python -
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
VERSION=${WAGTAIL_VERSION:-8.0}
[ "$(id -u)" = 0 ] || { echo "wagtail: needs root; skipped"; exit 0; }
PY=$(readlink -f /usr/bin/python3)
[ -f "/usr/lib/$(basename "$PY")/ensurepip/__init__.py" ] || { echo "wagtail: no python3-venv (ensurepip); skipped"; exit 0; }
curl -sSf -o /dev/null --max-time 10 https://pypi.org/simple/wagtail/ || { echo "wagtail: pypi.org unreachable; skipped"; exit 0; }
T=$(mktemp -d /tmp/agensio-wagtail.XXXXXX); chmod 755 "$T"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() { [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; pkill -9 -u w8 2>/dev/null; sleep 0.3; userdel w8 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
id -u agensio >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin agensio
mkdir -p $T/sites.d $T/logs $T/run $T/state $T/www $T/default $T/certs; chown agensio:agensio $T/sites.d $T/logs $T/state; chmod 751 $T/state
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=w8.test -addext subjectAltName=DNS:w8.test -keyout $T/certs/key.pem -out $T/certs/cert.pem 2>/dev/null
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
task_limits = { timeout = 300 }
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:18897"]
root = "$T/default"
CFG
"$BIN" -c $T/agensio.toml >> $T/server.out 2>&1 &
for _ in $(seq 1 50); do [ -S $T/run/control.sock ] && break; sleep 0.1; done; sleep 0.2
CS=$T/run/control.sock
ctl() { "$BIN" ctl "$@" --socket $CS; }
j() { python3 -c "import json,sys; d=json.load(open('$T/out')); print($1)"; }
APP=$T/www/w8.test/app
task() {  # task NAME [--param k=v]: runs it, prints ok exit seconds, keeps the answer in $T/out
    ctl site-task w8.test "$@" --yes --reason live > $T/out
    cp $T/out $T/out-$1.json
    j 'd["ok"], d.get("exit"), int(d.get("duration_ms", 0) / 1000)'
    python3 -c "import json; d=json.load(open('$T/out')); o=d.get('output', ''); print(d.get('error', '')); print(d.get('hint', '')); print(o)" > $T/last-$1.txt
}

out=$(ctl site-create --domain w8.test --app wagtail --project mysite --root $APP --user w8 --upstream http://127.0.0.1:18808 --cert $T/certs/cert.pem --key $T/certs/key.pem --listen-plain 127.0.0.1:18880 --listen-tls 127.0.0.1:18843 --yes --reason live)
check "site-create: app = wagtail, project mysite, its own account" "yes w8" "$(echo "$out" | grep -q '"ok":true' && echo yes) $(stat -c %U $APP)"
check "site-tasks: the interpreter can make virtualenvs, nothing for root to install" "True no" "$(ctl site-tasks w8.test > $T/out; j '[t for t in d["tasks"] if t["task"] == "venv_create"][0]["interpreter"]["ok"]') $(j '"yes" if "run_as_root" in d else "no"')"
r=$(task venv_create); check "venv_create: the site's virtualenv" "True 0" "$(echo $r | cut -d' ' -f1-2)"
r=$(task pip_install --param "packages=wagtail==$VERSION gunicorn" 2> $T/pip-warning); check "pip_install wagtail==$VERSION and gunicorn from pypi.org into it, the warning on the terminal" "True 0 yes" "$(echo $r | cut -d' ' -f1-2) $(grep -q '^WARNING: Install wagtail' $T/pip-warning && echo yes)"
echo "     pip_install took $(echo $r | cut -d' ' -f3) s"
r=$(task startproject); check "startproject (wagtail start): the project mysite in the site's directory" "True 0 yes" "$(echo $r | cut -d' ' -f1-2) $([ -f $APP/mysite/settings/production.py ] && echo yes)"
r=$(task pip_install_requirements); check "pip_install_requirements" "True 0" "$(echo $r | cut -d' ' -f1-2)"
ctl site-env-set w8.test --generate DJANGO_SECRET_KEY --generate DJANGO_SUPERUSER_PASSWORD --yes --reason live > /dev/null
r=$(task django_settings); check "django_settings: agensio_settings.py from the template" "True yes" "$(echo $r | cut -d' ' -f1) $([ -f $APP/agensio_settings.py ] && echo yes)"
r=$(task migrate); check "migrate: the database, 0600" "True 0 600" "$(echo $r | cut -d' ' -f1-2) $(stat -c %a $APP/db.sqlite3 2>/dev/null)"
r=$(task collectstatic); check "collectstatic: static/ holds the admin's files" "True 0 yes" "$(echo $r | cut -d' ' -f1-2) $([ -d $APP/static/wagtailadmin ] && echo yes)"
r=$(task createsuperuser --param username=admin --param email=admin@example.com); check "createsuperuser with the password from the site's environment" "True 0" "$(echo $r | cut -d' ' -f1-2)"
r=$(task check_deploy); check "check_deploy runs against the production settings" "0" "$(echo $r | cut -d' ' -f2)"
sm() { python3 -c "import json; print(json.load(open('$T/out-$1.json')).get('summary', ''))"; }
check "the answers lead with a summary: packages, migrations, static files, the admin" "yes yes yes yes" "$(sm pip_install | grep -q '^installed [0-9]* packages' && echo yes) $(sm migrate | grep -q '^[0-9][0-9]* migrations applied$' && echo yes) $(sm collectstatic | grep -q 'static files copied' && echo yes) $([ "$(sm createsuperuser)" = 'Superuser created successfully.' ] && echo yes)"

# Gunicorn with the unit site-unit renders: its Environment lines, its EnvironmentFile (read as
# root, as systemd does) less what UnsetEnvironment names, its WorkingDirectory, and its `@`
# ExecStart (the second word is argv[0]), as its User.
ctl site-unit w8.test --raw > $T/unit
wd=$(sed -n 's/^WorkingDirectory=//p' $T/unit); ex=$(sed -n 's/^ExecStart=@//p' $T/unit); user=$(sed -n 's/^User=//p' $T/unit)
envs=$(sed -n 's/^Environment=//p' $T/unit | tr '\n' ' ')
envfile=$(sed -n 's/^EnvironmentFile=-//p' $T/unit)
unset_names=$(sed -n 's/^UnsetEnvironment=//p' $T/unit)
fileenv=$(sed -n 's/^\([A-Z_][A-Z0-9_]*\)="\(.*\)"$/\1=\2/p' "$envfile" | grep -v -E "^($(echo $unset_names | tr ' ' '|'))=" | tr '\n' ' ')
prog=${ex%% *}; rest=${ex#* }; argv0=${rest%% *}; args=${rest#* }
check "the rendered unit: w8, root's python3 as the site's virtualenv, the project's wsgi, the site's port" "w8 /usr/bin/python3 yes" "$user $prog $(echo "$argv0 $args" | grep -q "^$T/state/w8/venvs/w8.test/bin/python -m gunicorn mysite.wsgi:application --bind 127.0.0.1:18808 " && echo yes)"
runuser -u "$user" -- /usr/bin/env -i $envs $fileenv /bin/bash -c "cd $wd && umask 027 && exec -a $argv0 $prog $args" > $T/gunicorn.out 2>&1 &
for _ in $(seq 1 100); do curl -s -o /dev/null http://127.0.0.1:18808/ -H 'Host: w8.test' && break; sleep 0.3; done
gpid=$(pgrep -u w8 -o -f 'gunicorn mysite.wsgi')
# The environment as its own account reads it (root in a container without CAP_SYS_PTRACE may not).
runuser -u w8 -- cat /proc/$gpid/environ 2>/dev/null | tr '\0' '\n' > $T/gunicorn.env
check "Gunicorn runs as w8 with the unit's environment and the secret key, and never received the admin's password" "yes yes yes no" "$([ -n "$gpid" ] && echo yes) $(grep -q '^DJANGO_SETTINGS_MODULE=agensio_settings$' $T/gunicorn.env && echo yes) $(grep -q '^DJANGO_SECRET_KEY=' $T/gunicorn.env && echo yes) $(grep -q '^DJANGO_SUPERUSER_PASSWORD=' $T/gunicorn.env && echo yes || echo no)"
H="--resolve w8.test:18843:127.0.0.1 -k"
check "agensio serves Wagtail's welcome page over TLS through Gunicorn" "200 yes" "$(curl -sS $H -o $T/home.html -w '%{http_code}' https://w8.test:18843/) $(grep -qi 'wagtail' $T/home.html && echo yes)"
css=$(grep -o 'href="/static/[^"]*\.css"' $T/home.html | head -1 | sed 's/href="//; s/"$//')
check "a stylesheet the page names comes from disk under /static/, cached a year" "200 text/css yes" "$(curl -sS $H -D $T/css.h -o /dev/null -w '%{http_code} %{content_type}' "https://w8.test:18843$css" | sed 's/;.*//') $(grep -qi '^cache-control: public, max-age=31536000, immutable' $T/css.h && echo yes)"
J=$T/cookies; rm -f $J
check "the admin's login page, through Gunicorn" "200" "$(curl -sS $H -c $J -b $J -o $T/login.html -w '%{http_code}' https://w8.test:18843/admin/login/)"
token=$(grep -o 'name="csrfmiddlewaretoken" value="[^"]*"' $T/login.html | head -1 | sed 's/.*value="//; s/"$//')
pw=$(ctl site-env w8.test --reveal DJANGO_SUPERUSER_PASSWORD | python3 -c 'import json,sys; print([v for v in json.load(sys.stdin)["variables"] if v["name"] == "DJANGO_SUPERUSER_PASSWORD"][0]["value"])')
check "the admin logs in over https: Django's CSRF check accepts the origin (X-Forwarded-Proto from agensio), a redirect to /admin/" "302 /admin/" "$(curl -sS $H -c $J -b $J -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Origin: https://w8.test:18843' -e https://w8.test:18843/admin/login/ --data-urlencode "csrfmiddlewaretoken=$token" --data-urlencode 'username=admin' --data-urlencode "password=$pw" --data-urlencode 'next=/admin/' https://w8.test:18843/admin/login/ | sed 's#https://w8.test:18843##')"
check "signed in: the admin dashboard answers 200" "200" "$(curl -sS $H -c $J -b $J -o /dev/null -w '%{http_code}' https://w8.test:18843/admin/)"
mkdir -p $APP/media/documents; echo private > $APP/media/documents/private.pdf; chown -R w8:agensio $APP/media; chmod 2750 $APP/media $APP/media/documents; chmod 640 $APP/media/documents/private.pdf
check "the project's files and Wagtail's documents are refused at the edge" "404 404 404 404" "$(for p in /media/documents/private.pdf /manage.py /agensio_settings.py /db.sqlite3; do curl -sS $H -o /dev/null -w '%{http_code} ' https://w8.test:18843$p; done | sed 's/ $//')"
check "pip_install is recorded as the user's confirmation in a terminal" "1" "$(grep -c "sites/w8.test/task (live): running task pip_install packages=wagtail==$VERSION gunicorn in .*, confirmed by the user in a terminal (agensio ctl)" $T/logs/audit.log)"
check "every task and the template are in the audit log" "9" "$(grep -c 'sites/w8.test/task (live): \(ran as w8 .* -> exit 0\|wrote \)' $T/logs/audit.log)"

echo "wagtail: $pass passed, $fail failed"
if [ "$fail" != 0 ]; then
    for f in $T/last-*.txt; do echo "--- $f"; head -20 "$f"; echo "..."; tail -15 "$f"; done
    echo "--- gunicorn"; tail -40 $T/gunicorn.out
    echo "--- error.log"; tail -20 $T/logs/error.log
fi
[ "$fail" = 0 ]
