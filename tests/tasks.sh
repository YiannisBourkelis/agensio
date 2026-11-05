#!/usr/bin/env bash
# Site tasks (F13) through the provisioning helper: as root in the devbox, a rails site with
# its own account runs its preset's named tasks as that account, in its directory, with an
# interpreter from a root-owned [control] runtimes directory. The interpreters here are fake
# ruby, gem and bundle scripts that report what they were given and leave files behind, so
# every rule is checked without Ruby: the argv, the account, the directory, the environment,
# the umask, the limits, the output cap, the time limit that kills the process group, what a
# task leaves running, the credential sweep, one task per site, the audit lines, and the
# refusals. tests/rails.sh runs the same tasks with real Ruby and Rails.
#   docker run --rm --init --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox tests/tasks.sh build/agensio
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
[ "$(id -u)" = 0 ] || { echo "tasks: needs root; skipped"; exit 0; }
T=$(mktemp -d /tmp/agensio-tasks.XXXXXX); chmod 755 "$T"
RT=/opt/agensio-tasks-rt   # not below /tmp: every directory above a runtime must be writable by root alone
PYRT_TOP=/opt/agensio-tasks-py; PYRT=$PYRT_TOP/bin   # a Python laid out as a distribution's: bin/python3.13, lib/python3.13
NODERT=/opt/agensio-tasks-node                           # a node and an npm that report what they were given
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() { for b in systemctl journalctl; do [ -e /usr/bin/$b.agensio-orig ] && mv -f /usr/bin/$b.agensio-orig /usr/bin/$b; done; [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; sleep 0.3; for u in r1 r2 r3 r4 r5 r6 r9; do pkill -9 -u $u 2>/dev/null; userdel $u 2>/dev/null; done; rm -rf "$T" "$RT" "$PYRT_TOP" "$NODERT"; }
trap cleanup EXIT
id -u agensio >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin agensio
mkdir -p $T/sites.d $T/logs $T/run $T/state $T/www $T/default $RT; chown agensio:agensio $T/sites.d $T/logs $T/state; chmod 751 $T/state; chmod 755 $RT

# The fake runtime: root's files in a root-owned directory, as [control] runtimes requires.
cat > $RT/ruby <<'SH'
#!/bin/sh
# the version query of an install (install::app_facts): what the Ruby of [control] runtimes is
[ "$1" = "-e" ] && [ "$2" = "print RUBY_VERSION" ] && { printf '%s' "$(cat /opt/agensio-tasks-rt/version 2>/dev/null || echo 3.4.7)"; exit 0; }
echo "prog=ruby"; echo "args=$*"; echo "uid=$(id -un) cwd=$(pwd) umask=$(umask)"; env | sort | sed 's/^/env: /'
if [ "$2" = new ]; then
  mkdir -p config storage db public bin
  echo secret > config/master.key; chmod 644 config/master.key
  printf 'production:\n  adapter: sqlite3\n' > config/database.yml
  echo "source 'https://rubygems.org'" > Gemfile
  echo '<h1>fake rails</h1>' > public/index.html
  echo 'SECRET=1' > .env
fi
SH
cat > $RT/gem <<'SH'
#!/bin/sh
echo "prog=gem"; echo "args=$*"; echo "uid=$(id -un) GEM_HOME=$GEM_HOME GEM_PATH=$GEM_PATH HOME=$HOME TMPDIR=$TMPDIR"
[ -e "$HOME/no-binstub" ] && { echo "1 gem installed"; exit 0; }   # what a host-wide Rails made gem do before GEM_PATH was isolated
mkdir -p "$GEM_HOME/bin" && echo '# fake rails' > "$GEM_HOME/bin/rails"
SH
cat > $RT/bundle <<'SH'
#!/bin/sh
echo "prog=bundle"; echo "args=$*"
echo "uid=$(id -un) cwd=$(pwd) BUNDLE_PATH=$BUNDLE_PATH BUNDLE_WITHOUT=$BUNDLE_WITHOUT RAILS_ENV=$RAILS_ENV DUMMY=${SECRET_KEY_BASE_DUMMY:-}"
echo "limits=$(awk '/^Max processes/{p=$(NF-2)} /^Max open files/{n=$(NF-2)} /^Max core file size/{c=$(NF-2)} END{print p, n, c}' /proc/self/limits)"
echo "appenv SECRET_KEY_BASE=${SECRET_KEY_BASE:-} DATABASE_URL=${DATABASE_URL:-}"
# Redmine's Gemfile without config/database.yml: it warns and bundles no database driver, exit 0
[ "$*" = install ] && [ ! -e config/database.yml ] && echo "Please configure your config/database.yml first"
[ -e nosecret ] && [ -z "${SECRET_KEY_BASE:-}" ] && [ "$*" = "exec rails db:migrate" ] && { echo "ArgumentError: Missing \`secret_key_base\` for 'production' environment, set this string with \`bin/rails credentials:edit\`" >&2; exit 1; }
case "$*" in
  "exec rails db:prepare") echo db > storage/production.sqlite3; chmod 644 storage/production.sqlite3 ;;
  "exec rails assets:precompile")
    [ -e slow ] && { echo sleeping; exec sleep 60; }
    [ -e loud ] && { i=0; while [ $i -lt 3000 ]; do echo 0123456789012345678901234567890123456789012345678901234567890123456789; i=$((i+1)); done; }
    [ -e daemon ] && { (sleep 300 &); echo detached; }
    [ -e fail ] && { echo "cannot load such file -- bootsnap" >&2; exit 1; }
    mkdir -p public/assets; echo asset > public/assets/app.css ;;
esac
SH
chmod 755 $RT/ruby $RT/gem $RT/bundle
# The fake PHP 9.9 (2026-11-04, the grabloop.app report): a root-configured runtime whose command-line
# binary reports what Laravel's tasks gave it; an FPM side that is never started.
cat > $RT/php9.9 <<'SH'
#!/bin/sh
echo "prog=php9.9 args=$*"; echo "uid=$(id -un) cwd=$(pwd)"
if [ -e slow ]; then sleep 3; fi
# Laravel's line for a scheduled command with runInBackground() (ScheduleRunCommand::runEvent).
if [ -e bg ]; then echo "  2026-11-04 10:00:00 Running ['artisan' report:send] in background .... 1ms DONE"; fi
SH
printf '#!/bin/sh\necho "PHP 9.9.0 (fpm-fcgi)"\n' > $RT/php-fpm9.9; : > $RT/php-fpm9.9.conf; mkdir -p $RT/pool.d
chmod 755 $RT/php9.9 $RT/php-fpm9.9

# The fake Python (2026-09-28, Django and Wagtail): what venv, pip, wagtail start and manage.py
# would leave, and the environment each run got. A shebang script cannot see the argv[0] it was
# started under, so it knows its virtualenv from VIRTUAL_ENV.
mkdir -p $PYRT $PYRT_TOP/lib/python3.13; chmod 755 $PYRT_TOP $PYRT $PYRT_TOP/lib $PYRT_TOP/lib/python3.13
cat > $PYRT/python3.13 <<'SH'
#!/bin/sh
echo "prog=python args=$*"
echo "uid=$(id -un) cwd=$(pwd) VIRTUAL_ENV=${VIRTUAL_ENV:-} DSM=${DJANGO_SETTINGS_MODULE:-} HOSTS=${AGENSIO_HOSTS:-} PROJECT=${AGENSIO_DJANGO_PROJECT:-} NOUSER=${PYTHONNOUSERSITE:-} STATIC=${AGENSIO_STATIC_ROOT:-}"
echo "superuser_password=${DJANGO_SUPERUSER_PASSWORD:+set} secret_key=${DJANGO_SECRET_KEY:+set}"
case "$1 $2" in
  "-m venv") mkdir -p "$3/bin" && echo "home = /opt/agensio-tasks-py/bin" > "$3/pyvenv.cfg" && echo '#!' > "$3/bin/pip"; exit 0 ;;
  "-m pip")
    case "$*" in *"-r requirements.txt"*) echo "Requirement already satisfied: wagtail"; exit 0 ;; esac
    shift 3; [ "$1" = "--" ] && shift; done_list=""
    for p in "$@"; do
      case "$p" in
        wagtail*) echo '#!' > "$VIRTUAL_ENV/bin/wagtail"; done_list="$done_list Django-6.1.1 wagtail-8.0" ;;
        gunicorn*) echo '#!' > "$VIRTUAL_ENV/bin/gunicorn"; done_list="$done_list gunicorn-23.0.0" ;;
      esac
    done
    echo "Successfully installed${done_list}"
    exit 0 ;;
esac
case "$1" in
  */bin/wagtail)
    mkdir -p "$3/settings" && echo "print('manage')" > manage.py && printf 'Django>=6.1,<6.2\nwagtail>=8.0,<8.1\n' > requirements.txt
    echo "from .base import *" > "$3/settings/production.py"; echo '' > "$3/wsgi.py"; echo "Success! $3 has been created" ;;
  manage.py)
    case "$2" in
      migrate) echo "  Applying home.0001_initial... OK"; echo db > db.sqlite3; chmod 644 db.sqlite3 ;;
      collectstatic) mkdir -p static/css && echo 'body{}' > static/css/site.css && echo "1 static file copied to '$(pwd)/static'." ;;
      createsuperuser) echo "Superuser created successfully." ;;
      check) printf 'System check identified some issues:\n\nWARNINGS:\n?: (security.W004) no HSTS\n?: (security.W012) SESSION_COOKIE_SECURE\n\nSystem check identified 2 issues (0 silenced).\n' ;;
    esac ;;
esac
SH
chmod 755 $PYRT/python3.13; ln -sf python3.13 $PYRT/python3

# The fake Node (2026-09-28): node reports its version; npm ci leaves node_modules/, npm run
# download-dist a dist/, and both print what they were given and the environment they got.
mkdir -p $NODERT; chmod 755 $NODERT
cat > $NODERT/node <<'SH'
#!/bin/sh
[ "$1" = "--version" ] && { echo v20.19.2; exit 0; }
echo "prog=node args=$*"
SH
cat > $NODERT/npm <<'SH'
#!/bin/sh
echo "prog=npm args=$*"
echo "uid=$(id -un) cwd=$(pwd) NODE_ENV=${NODE_ENV:-} CACHE=${NPM_CONFIG_CACHE:-} USERCONFIG=${NPM_CONFIG_USERCONFIG:-}"
case "$1" in
  ci) mkdir -p node_modules/socket.io && echo '{}' > node_modules/.package-lock.json && echo "added 3 packages in 1s" ;;
  run) case "$2" in
         download-dist) mkdir -p dist && echo '<html>kuma</html>' > dist/index.html && echo "Downloading dist" ;;
         *) echo "npm ERR! Missing script: \"$2\"" >&2; exit 1 ;;
       esac ;;
esac
SH
chmod 755 $NODERT/node $NODERT/npm

write_config() {
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
runtimes = { ruby = "$RT", python3 = "$PYRT", node = "$NODERT" }
task_limits = { timeout = 5, processes = 256 }
$1
[php.runtimes."9.9"]
fpm = "$RT/php-fpm9.9"
conf = "$RT/php-fpm9.9.conf"
pools = "$RT/pool.d"
cli = "$RT/php9.9"
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:18397"]
root = "$T/default"
CFG
}
write_config ''
# LEAK must never reach a task: the environment is built, not inherited.
start() { LEAK=from-the-server "$BIN" -c $T/agensio.toml >> $T/server.out 2>&1 & for _ in $(seq 1 50); do [ -S $T/run/control.sock ] && break; sleep 0.1; done; sleep 0.2; }
stop() { kill "$(cat $T/agensio.pid)" 2>/dev/null; for _ in $(seq 1 50); do [ -S $T/run/control.sock ] || break; sleep 0.1; done; sleep 0.3; }
start
CS=$T/run/control.sock
source "$(dirname "$0")/approve-lib.sh"; gated_setup "$BIN" $T/agensio.toml $CS
ctl() { gated "$BIN" ctl "$@" --socket $CS; }
j() { python3 -c "import json,sys; d=json.load(open('$T/out')); print($1)"; }
# Approvals (docs/approvals.md): a gated ctl command is approved by the lib with a fresh approver's code;
# approve approves what waits (a change queued through the API).
approve() { python3 "$(dirname "$0")/approve-code.py" $CS $T/agensio.toml "$BIN" "$@"; }
APP=$T/www/r1.test/app

out=$(ctl site-create --domain r1.test --app rails --root $APP --user r1 --upstream http://127.0.0.1:18398 --https none --listen-plain 127.0.0.1:18399 --yes --reason tasks)
check "site-create: a rails site with its own account in one call, laid out r1:agensio 2750, no php-fpm pool" "yes r1 agensio 2750 | r1 agensio 2750 no" "$(echo "$out" | grep -q '"ok":true' && echo yes) $(stat -c '%U %G %a' $T/www/r1.test) | $(stat -c '%U %G %a' $APP) $(echo "$out" | grep -q 'php-fpm pool' && echo yes || echo no)"
check "site-tasks lists the preset's seven tasks, run as r1 in the app directory" "7 r1 yes" "$(ctl site-tasks r1.test > $T/out; j 'len(d["tasks"]), d["runs_as"], "yes" if d["directory"] == "'$APP'" else d["directory"]')"
check "site-tasks: every interpreter accepted, the effective time limit (the rows' capped at task_limits' 5 s), nothing for root" "True True 5 5 False" "$(j 'all(t["interpreter"]["ok"] for t in d["tasks"] if "interpreter" in t), d["tasks"][1]["interpreter"]["program"] == "'$RT'/ruby", int(d["tasks"][1]["timeout"]), int(d["tasks"][3]["timeout"]), "run_as_root" in d')"
ctl site-task r1.test gem_install_rails --dry-run --yes --reason dry > $T/out
check "dry run: the exact argv from the table, as r1 in its directory, the home it would make; nothing created" "$RT/gem install rails --no-document r1 $APP $T/state/r1 0 no" "$(j '" ".join(d["argv"][:4]), d["as"], d["cwd"], d["would_create"][0]') $(ls -A $APP | wc -l | tr -d ' ') $([ -e $T/state/r1 ] && echo yes || echo no)"
check "dry run of rails_new before gem_install_rails: refused as the real run would be, naming the missing rails command and the task to run" "1 yes" "$(ctl site-task r1.test rails_new --param name=blog --dry-run --yes --reason dry > $T/out; echo -n "$? "; grep -q "needs $T/state/r1/gems/bin/rails, which does not exist; run gem_install_rails first" $T/out && echo yes)"

ctl site-task r1.test gem_install_rails --yes --reason gems > $T/out
check "gem_install_rails: runs gem as r1 into the account's own gem directory, GEM_PATH isolated to it; the helper made the home 0700 r1:r1" "True install rails --no-document --version ~> 8.0 | uid=r1 GEM_HOME=$T/state/r1/gems GEM_PATH=$T/state/r1/gems HOME=$T/state/r1 TMPDIR=$T/state/r1/tmp | r1 r1 700 r1 700" "$(j 'd["ok"], " ".join(d["argv"][1:])') | $(j 'd["output"].splitlines()[2]') | $(stat -c '%U %G %a' $T/state/r1) $(stat -c '%U %a' $T/state/r1/tmp)"

ctl site-task r1.test rails_new --param name=blog --yes --reason new > $T/out
check "rails_new: as r1, in the site's directory, umask 0027, from the runtime directory" "True uid=r1 cwd=$APP umask=0027 $RT/ruby" "$(j 'd["ok"], d["output"].splitlines()[2], d["argv"][0]')"
check "rails_new: the environment is exactly the table's; nothing of the server's (LEAK) reaches the task" "HOME LANG PATH PWD BUNDLE_PATH BUNDLE_WITHOUT GEM_HOME GEM_PATH RAILS_ENV TMPDIR | no" "$(j '" ".join(sorted(set(l[5:].split("=")[0] for l in d["output"].splitlines() if l.startswith("env: ")) - {"OLDPWD","SHLVL","_"}, key=lambda k: (k not in ("HOME","LANG","PATH","PWD"), k)))') | $(grep -q LEAK $T/out && echo yes || echo no)"
check "rails_new: files belong to r1 with the server's group, served files 0640 and readable by the server" "r1 agensio 640 yes" "$(stat -c '%U %G %a' $APP/public/index.html) $(su -s /bin/sh agensio -c "cat $APP/public/index.html" > /dev/null 2>&1 && echo yes)"
check "rails_new: the credential sweep: master.key, database.yml, .env 0600, storage/ 0710 (the kernel drops set-gid for an account outside the group); the server cannot read the key" "600 600 600 710 no" "$(stat -c %a $APP/config/master.key) $(stat -c %a $APP/config/database.yml) $(stat -c %a $APP/.env) $(stat -c %a $APP/storage) $(su -s /bin/sh agensio -c "cat $APP/config/master.key" > /dev/null 2>&1 && echo yes || echo no)"
check "rails_new: the answer lists what was secured, and the configuration validates" "4 true" "$(j 'len(d["secured"])') $(ctl validate | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["ok"]).lower())')"
check "rails_new a second time: refused, the directory is not empty, nothing ran" "1 yes" "$(ctl site-task r1.test rails_new --param name=blog --yes --reason again > $T/out; echo -n "$? "; grep -q 'creates the application in an empty directory' $T/out && echo yes)"

ctl site-task r1.test bundle_install --yes --reason bundle > $T/out
check "bundle_install: production gems into vendor/bundle, the limits set (processes 256, open files 4096, no core)" "True uid=r1 cwd=$APP BUNDLE_PATH=vendor/bundle BUNDLE_WITHOUT=development:test RAILS_ENV=production DUMMY= | limits=256 4096 0" "$(j 'd["ok"], d["output"].splitlines()[2]') | $(j 'd["output"].splitlines()[3]')"
ctl site-task r1.test db_prepare --yes --reason db > $T/out
check "db_prepare: the SQLite database it made is swept to 0600" "True 600 yes" "$(j 'd["ok"]') $(stat -c %a $APP/storage/production.sqlite3) $(j '"yes" if "'$APP'/storage/production.sqlite3" in d["secured"] else d["secured"]')"
ctl site-task r1.test assets_precompile --yes --reason assets > $T/out
check "assets_precompile: SECRET_KEY_BASE_DUMMY set for it alone; assets written" "True DUMMY=1 yes" "$(j 'd["ok"], d["output"].splitlines()[2].split()[-1]') $([ -f $APP/public/assets/app.css ] && echo yes)"

# The site's environment (2026-09-27 Writebook report): a root file the tasks read, admin only.
touch $APP/nosecret
check "a task that stops on Rails' missing secret_key_base: 409 with the hint to generate one" "1 yes" "$(ctl site-task r1.test db_migrate --yes --reason nosecret > $T/out; echo -n "$? "; j '"yes" if "generate: [\"SECRET_KEY_BASE\"]" in d.get("hint", "") else d.get("hint")')"
ctl site-env-set r1.test --set DATABASE_URL=sqlite3:storage/x.sqlite3 --generate SECRET_KEY_BASE --yes --reason env > $T/out
check "site-env-set: DATABASE_URL set, SECRET_KEY_BASE generated; root's file 0600 in root's 0700 directory; no value in the answer or the audit log" "True DATABASE_URL SECRET_KEY_BASE root 600 root 700 no no" "$(j 'd["ok"], ",".join(d["set"]), ",".join(d["generated"])') $(stat -c '%U %a' $T/env/r1.test.env) $(stat -c '%U %a' $T/env) $(grep -q 'sqlite3:storage' $T/out && echo yes || echo no) $(grep -q 'sqlite3:storage' $T/logs/audit.log && echo yes || echo no)"
SKB=$(sed -n 's/^SECRET_KEY_BASE="\(.*\)"$/\1/p' $T/env/r1.test.env)
ctl site-task r1.test db_migrate --yes --reason withsecret > $T/out
check "the task gets the site's environment; its answer names the variables and shows no value" "True 128 yes sqlite3:storage/x.sqlite3 yes" "$(j 'd["ok"]') $(echo -n "$SKB" | wc -c | tr -d ' ') $(j '"yes" if "SECRET_KEY_BASE='$SKB'" in d["output"] else "no"') $(j '[l for l in d["output"].splitlines() if l.startswith("appenv")][0].split("DATABASE_URL=")[1]') $(j '"yes" if "SECRET_KEY_BASE=<site environment>" in d["env"] and not any("'$SKB'" in e for e in d["env"]) else d["env"]')"
check "site-env: names, lengths and fingerprints, no value; audited with the names" "DATABASE_URL,SECRET_KEY_BASE 128 16 False no yes" "$(ctl site-env r1.test > $T/out; j '",".join(v["name"] for v in d["variables"]), int(d["variables"][1]["length"]), len(d["variables"][1]["fingerprint"]), "value" in d["variables"][1]') $(grep -q "$SKB" $T/out && echo yes || echo no) $(grep -q 'sites/r1.test/env: read the names of DATABASE_URL, SECRET_KEY_BASE$' $T/logs/audit.log && echo yes)"
check "site-env --reveal: that one value, audited as REVEALED, never the value in the audit log" "yes False yes no" "$(ctl site-env r1.test --reveal SECRET_KEY_BASE > $T/out; j '"yes" if d["variables"][1]["value"] == "'$SKB'" else d') $(j '"value" in d["variables"][0]') $(grep -q 'env: read the names of DATABASE_URL, SECRET_KEY_BASE; REVEALED the value of SECRET_KEY_BASE' $T/logs/audit.log && echo yes) $(grep -q "$SKB" $T/logs/audit.log && echo yes || echo no)"
check "generate keeps an existing secret; unset and generate in one call rotate it" "SECRET_KEY_BASE yes" "$(ctl site-env-set r1.test --generate SECRET_KEY_BASE --yes --reason keep > $T/out; j '",".join(d["kept"])') $(ctl site-env-set r1.test --unset SECRET_KEY_BASE --generate SECRET_KEY_BASE --yes --reason rotate > /dev/null; [ "$(sed -n 's/^SECRET_KEY_BASE="\(.*\)"$/\1/p' $T/env/r1.test.env)" != "$SKB" ] && echo yes)"
check "site-env-set refuses a name that changes what runs" "1 yes" "$(ctl site-env-set r1.test --set LD_PRELOAD=/tmp/x.so --yes --reason bad > $T/out; echo -n "$? "; grep -q 'LD_PRELOAD is agensio' $T/out && echo yes)"
chmod 664 $T/env/r1.test.env
check "an environment file others could write: the task is refused naming it, with the root command; nothing runs" "1 yes yes" "$(ctl site-task r1.test db_migrate --yes --reason unsafe > $T/out; echo -n "$? "; grep -q "r1.test.env must be a regular file with one link, root's, mode 0600" $T/out && echo -n yes; echo -n ' '; j '"yes" if "chmod 0600" in d["run_as_root"][0] else d')"
check "health sees that file through the helper, though the directory is right: site_env_unsafe for r1.test with the chmod line" "yes yes" "$(ctl health > $T/out; j '"yes" if any(f["code"] == "site_env_unsafe" and f.get("site") == "r1.test" and "chmod 0600" in f.get("fix", "") for f in d["findings"]) else d["findings"]') $([ "$(stat -c %a $T/env)" = 700 ] && echo yes)"
chmod 644 $T/env/r1.test.env
check "a file others could only read is made 0600 by the helper, and the task says so; no rotation advice under a 0700 directory" "True 600 yes" "$(ctl site-task r1.test db_migrate --yes --reason readable > $T/out; j 'd["ok"]') $(stat -c %a $T/env/r1.test.env) $(j '"yes" if "made 0600" in d["tightened"][0] and "nothing to rotate" in d["tightened"][0] else d.get("tightened")')"
chmod 775 $T/env; chmod 644 $T/env/r1.test.env   # the 2026-09-27 report: a mkdir -p under a lax umask, a file readable by others
check "a file others can read under a directory open to others: health warns for the site, with the rotation advice" "warn yes" "$(ctl health > $T/out; j '[f["severity"] for f in d["findings"] if f["code"] == "site_env_unsafe" and f.get("site") == "r1.test"][0]') $(j '"yes" if any(f.get("site") == "r1.test" and "rotate what it holds" in f["message"] for f in d["findings"]) else d["findings"]')"
check "health names an environment directory open to others; the next task tightens it and says so" "yes True 700 yes" "$(ctl health | grep -q site_env_unsafe && echo yes) $(ctl site-task r1.test db_migrate --yes --reason dir775 > $T/out; j 'd["ok"]') $(stat -c %a $T/env) $(j '"yes" if "made 0700" in " ".join(d["tightened"]) else d.get("tightened")')"
rm -f $APP/nosecret

touch $APP/fail
check "a failing task: 409, the exit status and the program's own words come back" "1 False 1 yes" "$(ctl site-task r1.test assets_precompile --yes --reason fail > $T/out; echo -n "$? "; j 'd["ok"], int(d["exit"]), "yes" if "cannot load such file -- bootsnap" in d["output"] and "exited with status 1" in d["error"] else d')"
rm -f $APP/fail; touch $APP/loud
check "a loud task: the output is cut to its head and tail, the total counted" "True True yes yes" "$(ctl site-task r1.test assets_precompile --yes --reason loud > $T/out; j 'd["ok"], d["truncated"], "yes" if d["output_bytes"] >= 213000 else d["output_bytes"], "yes" if len(d["output"]) < 66000 and "bytes not shown" in d["output"] else len(d["output"])')"
check "a loud task that succeeds answers its last 4 KB, a summary and the restart line; the whole output is kept" "yes yes public/assets holds 1 file yes" "$(j '"yes" if len(d["output"]) < 4300 and d["output"].rstrip().endswith("0123456789") else len(d["output"])') $(j '"yes" if d["output_kept"] >= 213000 else d["output_kept"]') $(j 'd["summary"]') $(j '"yes" if "as root: systemctl restart agensio-app-r1.service" in d["next_steps"][0] else d.get("next_steps")')"
check "site-task-output reads the whole output in slices of 64 KB, each next_offset leading to the next" "yes 4 assets_precompile" "$(python3 - "$BIN" "$CS" <<'PY'
import json, subprocess, sys
off, text, n = 0, "", 0
while off is not None:
    d = json.loads(subprocess.run([sys.argv[1], "ctl", "site-task-output", "r1.test", "--offset", str(int(off)), "--socket", sys.argv[2]], capture_output=True, text=True).stdout)
    text += d["output"]; n += 1; off = d["next_offset"]
print("yes" if len(text) == d["kept"] and text.count("0123456789012345678901234567890123456789012345678901234567890123456789\n") == 3000 else len(text), n, d["task"])
PY
)"
check "site-task-output --raw prints the slice alone" "prog=bundle" "$(ctl site-task-output r1.test --length 11 --raw)"
touch $APP/fail
check "a loud task that fails answers its first 4 KB and its last 12 KB, the error at the end included" "1 yes yes yes" "$(ctl site-task r1.test assets_precompile --yes --reason loudfail > $T/out; echo -n "$? "; j '"yes" if len(d["output"]) < 16700 and d["truncated"] else len(d["output"])') $(j '"yes" if d["output"].startswith("prog=bundle") else d["output"][:40]') $(j '"yes" if "cannot load such file -- bootsnap" in d["output"][-200:] and "site_task_output reads the whole output" in d["output"] else d["output"][-200:]')"
rm -f $APP/fail $APP/loud; touch $APP/daemon
check "a task that leaves a process behind: it is killed with the task's process group" "True 0" "$(ctl site-task r1.test assets_precompile --yes --reason daemon > $T/out; j 'd["ok"]') $(pgrep -u r1 -c sleep || true)"
rm -f $APP/daemon; touch $APP/slow
( ctl site-task r1.test assets_precompile --yes --reason slow > $T/slow.out ) &
SLOW=$!
sleep 1
check "one task per site: a second one while the first runs is refused naming it" "409 yes" "$(curl -sS -o $T/out -w '%{http_code}' --unix-socket $CS -X POST -d '{"task":"db_migrate","confirm":true}' http://control/v1/sites/r1.test/task) $(grep -q 'already running on this site: assets_precompile' $T/out && echo yes)"
wait $SLOW   # not a bare wait: the server started by start() is a background job of this script too
check "the time limit: SIGTERM to the group at 5 s, a 409 naming the limit, nothing of r1 left running" "True yes 0" "$(python3 -c "import json; d=json.load(open('$T/slow.out')); print(d['timed_out'], 'yes' if 'time limit of 5 s' in d['error'] and 5000 <= d['duration_ms'] < 15000 else d)") $(pgrep -u r1 -c . || true)"
rm -f $APP/slow
touch $T/state/r1/no-binstub; rm -f $T/state/r1/gems/bin/rails
check "gem_install_rails that exits 0 without the rails command: 409 naming what is missing, not ok" "1 False yes" "$(ctl site-task r1.test gem_install_rails --yes --reason nobin > $T/out; echo -n "$? "; j 'd["ok"], "yes" if "exited 0, but '$T'/state/r1/gems/bin/rails does not exist" in d["error"] else d["error"]')"
rm -f $T/state/r1/no-binstub
check "run again, it leaves the command behind and answers ok" "True" "$(ctl site-task r1.test gem_install_rails --yes --reason again > $T/out; j 'd["ok"]')"

chmod 775 $RT
check "a runtime directory another account could write is refused, naming it" "1 yes" "$(ctl site-task r1.test db_migrate --yes --reason rt > $T/out; echo -n "$? "; grep -q "$RT is writable by its group or by others" $T/out && echo yes)"
chmod 755 $RT; chown nobody $RT/bundle
check "a runtime file root does not own is refused" "1 yes" "$(ctl site-task r1.test db_migrate --yes --reason rt > $T/out; echo -n "$? "; grep -q "$RT/bundle belongs to nobody, not root" $T/out && echo yes)"
chown root $RT/bundle

out=$(ctl site-create --domain r2.test --app rails --root $T/www/r2.test/app --user r2 --upstream http://127.0.0.1:18400 --https none --listen-plain 127.0.0.1:18399 --yes --reason tasks)
check "db_prepare in a directory with no application: refused before anything runs, dry run or not" "1 1 yes" "$(ctl site-task r2.test db_prepare --dry-run --yes --reason noapp > /dev/null; echo -n "$? "; ctl site-task r2.test db_prepare --yes --reason noapp > $T/out; echo -n "$? "; grep -q "needs $T/www/r2.test/app/Gemfile, which does not exist; the site's directory holds no application yet" $T/out && echo yes)"
# The alpha.30 report: the directory open to others and r1's file readable by them, then a
# call on ANOTHER site closes the directory. In that same pass r1's file is made 0600 and
# recorded, and health keeps warning for r1 until its values change.
chmod 775 $T/env; chmod 644 $T/env/r1.test.env
ctl site-task r2.test db_prepare --dry-run --yes --reason other-site > $T/out
check "a call on another site closes the directory, and in the same pass r1's readable file is made 0600 and named for rotation" "700 600 yes" "$(stat -c %a $T/env) $(stat -c %a $T/env/r1.test.env) $(j '"yes" if any("r1.test.env" in n and "rotate what it holds" in n for n in d.get("tightened", [])) else d.get("tightened")')"
sleep 1.2   # the error log's buffer
check "health keeps warning for r1 after the directory closed, until the values change; the fix is a tool call, not a root command; the error log has it too" "yes yes" "$(ctl health > $T/out; j '"yes" if any(f.get("site") == "r1.test" and f["severity"] == "warn" and "readable by others" in f["message"] and f["fix"].startswith("site_env_set r1.test") for f in d["findings"]) else [f for f in d["findings"] if f["code"].startswith("site_env")]') $(grep -q 'site environment: .*r1.test.env.*rotate what it holds' $T/logs/error.log && echo yes)"
check "rotating one value: the answer names the one still to rotate" "DATABASE_URL yes" "$(ctl site-env-set r1.test --unset SECRET_KEY_BASE --generate SECRET_KEY_BASE --yes --reason rotate1 > $T/out; j '",".join(d["still_exposed"])') $(j '"yes" if "still holds the value" in d["warnings"][0] else d.get("warnings")')"
ctl site-env-set r1.test --set DATABASE_URL=sqlite3:storage/rotated.sqlite3 --yes --reason rotate2 > $T/out
check "rotating every value ends the warning, in the answer and in health" "False no" "$(j '"still_exposed" in d') $(ctl health > $T/out; j '"yes" if any(f.get("site") == "r1.test" and "readable by others" in f["message"] for f in d["findings"]) else "no"')"

# An application from an archive that came without Rails credentials (Writebook): the
# install generates its SECRET_KEY_BASE and names the steps that fit it.
mkdir -p $T/wb/writebook-1.2.2/config && echo "source 'https://rubygems.org'" > $T/wb/writebook-1.2.2/Gemfile && echo 3.4.7 > $T/wb/writebook-1.2.2/.ruby-version && echo x > $T/wb/writebook-1.2.2/config/application.rb
tar -C $T/wb -cf $T/wb.tar writebook-1.2.2
ctl upload wb.tar $T/wb.tar > /dev/null
echo 3.3.8 > $RT/version   # the runtime's Ruby, as the fake reports it: not the pinned one
ctl site-install r2.test --file wb.tar --yes --reason archive > $T/out
rm -f $RT/version
check "site-install of a Rails archive without credentials: SECRET_KEY_BASE generated into the site's environment; next steps name the pinned Ruby against the runtime's (3.3.8 here), the bundle tasks and the body limit" "yes yes yes yes 600" "$(j '"yes" if any("SECRET_KEY_BASE generated" in x for x in d.get("done", [])) else d') $(j '"yes" if any("pins Ruby 3.4.7 (.ruby-version), but the Ruby of [control] runtimes ('$RT') is 3.3.8" in x for x in d["next_steps"]) else d["next_steps"]') $(j '"yes" if any("site_task database_config, site_task bundle_install" in x for x in d["next_steps"]) else d["next_steps"]') $(j '"yes" if any("up to 1MB, the server" in x for x in d["next_steps"]) else d["next_steps"]') $(stat -c %a $T/env/r2.test.env)"
check "site-update of a site that holds an application without database.yml: the database first, then the bundle tasks, not rails_new" "yes no" "$(ctl site-update r2.test --upstream http://127.0.0.1:18401 --yes --reason next > $T/out; j '"yes" if any("in place without config/database.yml" in x and "database_config, then bundle_install" in x for x in d["next_steps"]) else d["next_steps"]') $(grep -q rails_new $T/out && echo yes || echo no)"
# database_config: a fixed template, no program, as the site's account (2026-09-27 Redmine report).
check "database_config without DATABASE_URL in the site's environment: refused naming it" "1 yes" "$(ctl site-task r2.test database_config --yes --reason db > $T/out; echo -n "$? "; grep -q 'needs DATABASE_URL in the site.s environment' $T/out && echo yes)"
ctl site-env-set r2.test --set DATABASE_URL=sqlite3:db/production.sqlite3 --yes --reason db > /dev/null
check "database_config dry run: what it would write, nothing written" "True 0600 no" "$(ctl site-task r2.test database_config --dry-run --yes --reason db > $T/out; j 'd["ok"], d["mode"]') $([ -e $T/www/r2.test/app/config/database.yml ] && echo yes || echo no)"
check "database_config writes config/database.yml as r2, 0600, from the fixed template; the audit names the template" "True r2 600 yes yes" "$(ctl site-task r2.test database_config --yes --reason db > $T/out; j 'd["ok"]') $(stat -c '%U %a' $T/www/r2.test/app/config/database.yml) $(grep -q 'ENV\["DATABASE_URL"\]' $T/www/r2.test/app/config/database.yml && echo yes) $(grep -q 'task (db): wrote .*config/database.yml (0600) as r2 from the fixed template of database_config' $T/logs/audit.log && echo yes)"
check "database_config never replaces a file" "1 yes" "$(ctl site-task r2.test database_config --yes --reason again > $T/out; echo -n "$? "; grep -q 'writes it only when it is missing' $T/out && echo yes)"
chown root $T/www/r2.test/app
check "a site directory the site's account does not own: refused before anything runs" "1 yes" "$(ctl site-task r2.test gem_install_rails --yes --reason owner > $T/out; echo -n "$? "; grep -q 'belongs to uid 0, not to r2' $T/out && echo yes)"
# Redmine from its archive: first on a rails site (the install says it is Redmine), then as
# app = "redmine" with its own tasks, the database first, and the unit rendered for root.
mkdir -p $T/rm/redmine-7.0.1/config $T/rm/redmine-7.0.1/lib/redmine && echo "source 'https://rubygems.org'" > $T/rm/redmine-7.0.1/Gemfile && echo "production:" > $T/rm/redmine-7.0.1/config/database.yml.example && echo "module Redmine; end" > $T/rm/redmine-7.0.1/lib/redmine/version.rb
tar -C $T/rm -cf $T/rm.tar redmine-7.0.1; ctl upload rm.tar $T/rm.tar > /dev/null
ctl site-create --domain r4.test --app rails --root $T/www/r4.test/app --user r4 --upstream http://127.0.0.1:18404 --https none --listen-plain 127.0.0.1:18399 --yes --reason redmine > /dev/null
ctl site-install r4.test --file rm.tar --yes --reason redmine > $T/out
check "a Redmine archive on a rails site: facts say so, the next steps start with the database, a warning names app = redmine" "True False yes yes" "$(j 'd["facts"]["redmine"], d["facts"]["database_yml"]') $(j '"yes" if "database_config" in " ".join(d["next_steps"]) else d["next_steps"]') $(j '"yes" if any("app \"redmine\"" in w for w in d.get("warnings", [])) else d.get("warnings")')"
ctl site-update r4.test --app redmine --yes --reason redmine > /dev/null
check "app = redmine: its tasks, without the new-application ones" "8 False True" "$(ctl site-tasks r4.test > $T/out; j 'len(d["tasks"]), any(t["task"] == "rails_new" for t in d["tasks"]), any(t["task"] == "gemfile_local" for t in d["tasks"])')"
check "bundle_install before the database configuration: exit 0, but 409 naming the missing database.yml" "1 False yes" "$(ctl site-task r4.test bundle_install --yes --reason early > $T/out; echo -n "$? "; j 'd["ok"], "yes" if "database_config" in d["error"] else d["error"]')"
ctl site-env-set r4.test --set DATABASE_URL=sqlite3:db/production.sqlite3 --yes --reason redmine > /dev/null
ctl site-task r4.test database_config --yes --reason redmine > /dev/null
check "gemfile_local writes Redmine's Gemfile.local with Puma, as r4, 0640" "True r4 640 yes" "$(ctl site-task r4.test gemfile_local --yes --reason redmine > $T/out; j 'd["ok"]') $(stat -c '%U %a' $T/www/r4.test/app/Gemfile.local) $(grep -q '^gem "puma"' $T/www/r4.test/app/Gemfile.local && echo yes)"
check "bundle_install with the database configured: ok" "True" "$(ctl site-task r4.test bundle_install --yes --reason redmine > $T/out; j 'd["ok"]')"
check "load_default_data: the fixed rake task with REDMINE_LANG from the typed parameter; a parameter that is not a language is refused" "exec rake redmine:load_default_data REDMINE_LANG=de 1" "$(ctl site-task r4.test load_default_data --param lang=de --dry-run --yes --reason redmine > $T/out; j '" ".join(d["argv"][1:]), [e for e in d["env"] if e.startswith("REDMINE_LANG")][0]') $(ctl site-task r4.test load_default_data --param 'lang=de;id' --dry-run --yes --reason bad > /dev/null; echo $?)"
check "site-unit renders r4's Puma unit: its account, the runtime's bundle, the loopback port, the environment file; --raw prints the unit alone" "yes yes yes yes" "$(ctl site-unit r4.test > $T/out; j '"yes" if "User=r4" in d["unit"] and "ExecStart='$RT'/bundle exec puma -e production -b tcp://127.0.0.1:18404" in d["unit"] else d') $(j '"yes" if "EnvironmentFile=-'$T'/env/r4.test.env" in d["unit"] else d["unit"]') $(j '"yes" if d["run_as_root"][0] == "agensio ctl site-unit r4.test --out /etc/systemd/system/agensio-app-r4.service" else d') $(ctl site-unit r4.test --raw | head -c 9 | grep -q '^# agensio' && echo yes)"
check "the audit log: each run with the exact argv, the account and the outcome; each refusal with its reason" "yes yes yes" "$(grep -q "sites/r1.test/task (new): ran as r1 in $APP: $RT/ruby $T/state/r1/gems/bin/rails new . --name=blog .* -> exit 0" $T/logs/audit.log && echo yes) $(grep -q "sites/r1.test/task (slow): ran as r1 .* -> stopped at the time limit" $T/logs/audit.log && echo yes) $(grep -q "sites/r2.test/task (owner): refused: .*belongs to uid 0" $T/logs/audit.log && echo yes)"
# Django and Wagtail (2026-09-28): a Wagtail site with its own account, every task in its own
# virtualenv, root's python3 run under the virtualenv's name, the settings from the template.
W5=$T/www/w5.test/app; VENV=$T/state/r5/venvs/w5.test
check "site-create of a wagtail site without its project: 422, the decision names project with a suggestion" "422 w5" "$(curl -sS -o $T/out -w '%{http_code}' --unix-socket $CS -X POST -d '{"domain":"w5.test","https":"none","user":"r5","app":"wagtail","root":"'$W5'","upstream":"http://127.0.0.1:18405","listen_plain":"127.0.0.1:18399","confirm":true}' http://control/v1/sites) $(j '[n["suggestion"] for n in d["needs"] if n["field"] == "project"][0]')"
out=$(ctl site-create --domain w5.test --app wagtail --project mysite --root $W5 --user r5 --upstream http://127.0.0.1:18405 --https none --listen-plain 127.0.0.1:18399 --yes --reason py)
check "site-create: app = wagtail with project mysite, the file names both" "yes yes" "$(echo "$out" | grep -q '"ok":true' && echo yes) $(grep -q '^project = "mysite"' $T/sites.d/w5.test.toml && echo yes)"
check "site-tasks: nine tasks, the project and the site's virtualenv; venv_create's interpreter refused, Python cannot make virtualenvs, with the package for root" "9 mysite yes False yes yes" "$(ctl site-tasks w5.test > $T/out; j 'len(d["tasks"]), d["project"], "yes" if d["virtualenv"] == "'$VENV'" else d["virtualenv"], [t for t in d["tasks"] if t["task"] == "venv_create"][0]["interpreter"]["ok"]') $(j '"yes" if "ensurepip" in [t for t in d["tasks"] if t["task"] == "venv_create"][0]["interpreter"]["error"] else d') $(j '"yes" if "apt-get install -y python3-venv" in d.get("run_as_root", []) else d.get("run_as_root")')"
check "venv_create without ensurepip: refused before it runs, dry run or not, with the package command; nothing made" "1 yes no" "$(ctl site-task w5.test venv_create --yes --reason py > $T/out; echo -n "$? "; j '"yes" if "cannot make a virtualenv" in d["error"] and d["run_as_root"] == "apt-get install -y python3-venv" else d') $([ -e $VENV ] && echo yes || echo no)"
mkdir -p $PYRT_TOP/lib/python3.13/ensurepip; chmod 755 $PYRT_TOP/lib/python3.13/ensurepip; touch $PYRT_TOP/lib/python3.13/ensurepip/__init__.py
check "venv_create: root's python3 makes the virtualenv in r5's home, outside the served tree" "True $PYRT/python3.13 -m venv $VENV r5 yes" "$(ctl site-task w5.test venv_create --yes --reason py > $T/out; j 'd["ok"], " ".join(d["argv"])') $(stat -c %U $VENV) $([ -f $VENV/pyvenv.cfg ] && echo yes)"
# pip_install names any package, so it waits for a person's approval with a code from their
# authenticator app (alpha.120; before, a user_confirmed field any process of the account could send).
check "pip_install through the API waits for approval, even with confirm and a forged user_confirmed: 202 with the server's warning; nothing ran" "202 yes 0" "$(curl -sS -o $T/out -w '%{http_code}' --unix-socket $CS -X POST -d '{"task":"pip_install","params":{"packages":"wagtail"},"confirm":true,"reason":"agent","user_confirmed":"terminal"}' http://control/v1/sites/w5.test/task) $(j '"yes" if d["pending"] and "https://pypi.org/project/wagtail/" in d["preview"] else d') $(grep -c 'running task pip_install packages=wagtail in' $T/logs/audit.log)"
ctl approve --reject "$(j 'd["id"]')" > /dev/null
check "pip_install with an option or a URL for a package: refused by its shape before anything waits, nothing ran" "400 400 no 0" "$(curl -sS -o /dev/null -w '%{http_code}' --unix-socket $CS -X POST -d '{"task":"pip_install","params":{"packages":"--index-url=https://evil.example/simple wagtail"},"confirm":true}' http://control/v1/sites/w5.test/task) $(curl -sS -o /dev/null -w '%{http_code}' --unix-socket $CS -X POST -d '{"task":"pip_install","params":{"packages":"wagtail @ https://evil.example/w.whl"},"confirm":true}' http://control/v1/sites/w5.test/task) $([ -e $VENV/bin/wagtail ] && echo yes || echo no) $(curl -sS --unix-socket $CS http://control/v1/approvals | python3 -c 'import json,sys; print(len([a for a in json.load(sys.stdin)["approvals"] if a["state"] == "waiting"]))')"
"$BIN" ctl site-task w5.test pip_install --param "packages=wagtail==8.0 gunicorn" --yes --reason py --socket $CS > $T/pending < /dev/null
check "pip_install through ctl without a terminal waits, its preview the server's warning and the exact command the dry run made" "yes yes" "$(python3 -c "import json; d=json.load(open('$T/pending')); print('yes' if d['pending'] and 'Install wagtail==8.0 gunicorn into the site w5.test?' in d['preview'] and 'look-alike' in d['preview'] else d)") $(python3 -c "import json; d=json.load(open('$T/pending')); print('yes' if 'runs: ' + '$PYRT/python3.13' in d['preview'] or '$VENV/bin/python -m pip install -- wagtail==8.0 gunicorn' in d['preview'] else d['preview'])")"
approve > $T/approved; python3 -c "import json; print(json.dumps(json.load(open('$T/approved'))['results'][0]['result']))" > $T/out
check "approved with root's approver: root's python3.13 under the virtualenv's name, the packages after --, pip's environment, a summary" "True $PYRT/python3.13 $VENV/bin/python|-m|pip|install|--|wagtail==8.0|gunicorn VIRTUAL_ENV=$VENV installed 3 packages into the site's virtualenv" "$(j 'd["ok"], d["program"], "|".join(d["argv"])') $(j '[l for l in d["output"].splitlines() if l.startswith("uid=")][0].split()[2]') $(j 'd["summary"]')"
check "the audit lines: waiting, approved by the approver, the run named as approved with a code; the program and the name it ran under" "yes yes yes yes" "$(grep -q "sites/w5.test/task (py): waits for approval [0-9a-f]\{12\}: installs the Python packages" $T/logs/audit.log && echo yes) $(grep -q "approvals ([0-9a-f]\{12\}): approved by suite-" $T/logs/audit.log && echo yes) $(grep -q "sites/w5.test/task (py): running task pip_install packages=wagtail==8.0 gunicorn in $W5, approved by suite-[0-9a-f]* with an authenticator code" $T/logs/audit.log && echo yes) $(grep -qF "sites/w5.test/task (py): ran as r5 in $W5: $PYRT/python3.13 as $VENV/bin/python -m pip install -- wagtail==8.0 gunicorn -> exit 0" $T/logs/audit.log && echo yes)"
check "startproject on a wagtail site: wagtail start, the project named by the site, in the empty directory (the virtualenv is elsewhere), as r5" "True r5 yes" "$(ctl site-task w5.test startproject --yes --reason py > $T/out; j 'd["ok"]') $(stat -c %U $W5/manage.py) $(j '"yes" if d["argv"][1:] == ["'$VENV'/bin/wagtail", "start", "mysite", "."] else d["argv"]')"
ctl site-task w5.test pip_install_requirements --yes --reason py > $T/out-pip_install_requirements
check "pip_install_requirements (no confirmation: the project's own file names the packages); gunicorn is in the virtualenv" "yes yes" "$(python3 -c "import json; d=json.load(open('$T/out-pip_install_requirements')); print('yes' if d['ok'] and d['summary'].startswith('nothing new') else d)") $([ -f $VENV/bin/gunicorn ] && echo yes)"
check "django_settings without DJANGO_SECRET_KEY: refused naming generate; nothing written" "1 yes no" "$(ctl site-task w5.test django_settings --yes --reason py > $T/out; echo -n "$? "; j '"yes" if "DJANGO_SECRET_KEY" in d["error"] and "generate" in d["error"] else d') $([ -e $W5/agensio_settings.py ] && echo yes || echo no)"
ctl site-env-set w5.test --generate DJANGO_SECRET_KEY --yes --reason py > /dev/null
check "django_settings writes agensio_settings.py from the fixed template, as r5, 0640; the environment cannot name the settings module or pip's index" "True r5 640 yes 1 1" "$(ctl site-task w5.test django_settings --yes --reason py > $T/out; j 'd["ok"]') $(stat -c '%U %a' $W5/agensio_settings.py) $(grep -q 'SECRET_KEY = os.environ\["DJANGO_SECRET_KEY"\]' $W5/agensio_settings.py && echo yes) $(ctl site-env-set w5.test --set DJANGO_SETTINGS_MODULE=x --yes --reason py > /dev/null; echo -n $?) $(ctl site-env-set w5.test --set PIP_INDEX_URL=https://evil.example/simple --yes --reason py > /dev/null; echo $?)"
ctl site-task w5.test migrate --yes --reason py > $T/out
check "migrate: the settings module agensio's, the site's names and project, no user site-packages, the secret from the site's environment; the database swept to 0600" "True DSM=agensio_settings HOSTS=w5.test PROJECT=mysite NOUSER=1 secret_key=set 1 migration applied 600" "$(j 'd["ok"]') $(j '" ".join([l for l in d["output"].splitlines() if l.startswith("uid=")][0].split()[3:7])') $(j '[l for l in d["output"].splitlines() if l.startswith("superuser")][0].split()[1]') $(j 'd["summary"]') $(stat -c %a $W5/db.sqlite3)"
check "migrate's answer carries root's restart line for the Gunicorn unit" "yes" "$(j '"yes" if "systemctl restart agensio-app-r5.service" in d["next_steps"][0] else d.get("next_steps")')"
check "collectstatic: static/ as r5, readable by the server; a summary" "True yes 1 static file copied to '$W5/static'." "$(ctl site-task w5.test collectstatic --yes --reason py > $T/out; j 'd["ok"]') $(su -s /bin/sh agensio -c "cat $W5/static/css/site.css" > /dev/null 2>&1 && echo yes) $(j 'd["summary"]')"
check "createsuperuser without DJANGO_SUPERUSER_PASSWORD: refused naming generate; with it, the password reaches the task and the answer shows no value" "1 True set yes yes" "$(ctl site-task w5.test createsuperuser --param username=admin --param email=admin@example.com --yes --reason py > $T/out; echo -n "$? "; ctl site-env-set w5.test --generate DJANGO_SUPERUSER_PASSWORD --yes --reason py > /dev/null; ctl site-task w5.test createsuperuser --param username=admin --param email=admin@example.com --yes --reason py > $T/out; j 'd["ok"]') $(j '[l for l in d["output"].splitlines() if l.startswith("superuser")][0].split()[0].split("=")[1]') $(j '"yes" if "DJANGO_SUPERUSER_PASSWORD=<site environment>" in d["env"] else d["env"]') $(j '"yes" if any("reveal" in s for s in d["next_steps"]) else d.get("next_steps")')"
check "django_settings again: agensio's own earlier version is replaced, the old one kept as .bak; the new one has https-only cookies" "True yes yes yes" "$(echo '# Written by agensio (site task django_settings); an older version' > $W5/agensio_settings.py; chown r5 $W5/agensio_settings.py; ctl site-task w5.test django_settings --yes --reason py > $T/out; j 'd["ok"]') $(j '"yes" if "kept as" in d.get("replaced", "") else d') $(grep -q 'an older version' $W5/agensio_settings.py.bak && echo yes) $(grep -q 'SESSION_COOKIE_SECURE' $W5/agensio_settings.py && echo yes)"
check "django_settings leaves a settings file someone else wrote alone; the audit line named the replacement" "1 yes yes" "$(cp $W5/agensio_settings.py $T/keep.py; echo 'DEBUG = True  # mine' > $W5/agensio_settings.py; ctl site-task w5.test django_settings --yes --reason py > $T/out; echo -n "$? "; grep -q 'mine' $W5/agensio_settings.py && echo -n 'yes'; cp $T/keep.py $W5/agensio_settings.py; chown r5 $W5/agensio_settings.py) $(grep -q "from the fixed template of django_settings, replacing agensio's earlier version" $T/logs/audit.log && echo yes)"
check "site-env-set of DJANGO_SUPERUSER_PASSWORD says only createsuperuser reads it and no restart is needed" "yes no" "$(ctl site-env-set w5.test --generate DJANGO_SUPERUSER_PASSWORD --yes --reason py > $T/out; j '"yes" if "createsuperuser alone" in d["next_steps"][0] else d["next_steps"]') $(j '"yes" if any("systemctl restart" in x for x in d["next_steps"]) else "no"')"
check "site-unit renders the Gunicorn unit: root's python3 as the virtualenv's python, the project's wsgi, the admin's password unset" "yes yes yes" "$(ctl site-unit w5.test > $T/out; j '"yes" if "ExecStart=@'$PYRT'/python3 '$VENV'/bin/python -m gunicorn mysite.wsgi:application --bind 127.0.0.1:18405" in d["unit"] else d["unit"]') $(j '"yes" if "UnsetEnvironment=DJANGO_SUPERUSER_PASSWORD" in d["unit"] else "no"') $(j '"yes" if "User=r5" in d["unit"] and "AGENSIO_HOSTS=w5.test" in d["unit"] else "no"')"
mkdir -p $W5/media/documents $W5/media/images; echo pdf > $W5/media/documents/private.pdf; echo png > $W5/media/images/x.png; echo 'b{}' > $W5/static/css/site.0123abcd9876.css; chown r5:agensio $W5/static/css/site.0123abcd9876.css; chmod 640 $W5/static/css/site.0123abcd9876.css
chown -R r5:agensio $W5/media; find $W5/media -type d -exec chmod 2750 {} +; find $W5/media -type f -exec chmod 640 {} +
touch -d '-1 minute' $W5/static/css/site.css $W5/static/css/site.0123abcd9876.css $W5/media/images/x.png $W5/media/documents/private.pdf  # deployed before served: a file a second old is not cached (alpha.110)
H5="-H Host:w5.test"
check "the edge serves /static/ (a hashed name a year, any other five minutes) and /media/ from disk with their headers; /media/documents/, manage.py and the settings are 404; the rest goes to Gunicorn (502: none runs)" "200 200 404 404 404 404 502 yes yes" "$(for p in /static/css/site.css /media/images/x.png /media/documents/private.pdf /manage.py /agensio_settings.py /mysite/settings/production.py /admin/; do curl -sS -o /dev/null -w '%{http_code} ' $H5 http://127.0.0.1:18399$p; done)$(curl -sS -D - -o /dev/null $H5 http://127.0.0.1:18399/static/css/site.css | grep -qi '^cache-control: public, max-age=300' && curl -sS -D - -o /dev/null $H5 http://127.0.0.1:18399/static/css/site.0123abcd9876.css | grep -qi '^cache-control: public, max-age=31536000, immutable' && echo -n 'yes ')$(curl -sS -D - -o /dev/null $H5 http://127.0.0.1:18399/media/images/x.png | grep -qi "^content-security-policy: script-src 'none'" && echo yes)"
check "check_deploy reports and changes nothing; its summary names the checks" "True 2 warnings: security.W004, security.W012" "$(ctl site-task w5.test check_deploy --yes --reason py > $T/out; j 'd["ok"], d["summary"]')"

# Node (2026-09-28): a Node site with its own account, an Uptime Kuma-shaped archive, npm ci
# and npm run as the account with npm's cache in its home, the entry, the unit, the edge.
N6=$T/www/n6.test/app
out=$(ctl site-create --domain n6.test --app node --root $N6 --user r6 --upstream http://127.0.0.1:18406 --https none --listen-plain 127.0.0.1:18399 --yes --reason node)
check "site-create: app = node with its own account; site-tasks lists npm_ci and npm_run, no entry yet, the interpreter accepted" "yes 2 None True" "$(echo "$out" | grep -q '"ok":true' && echo yes) $(ctl site-tasks n6.test > $T/out; j 'len(d["tasks"]), d["entry"], d["tasks"][0]["interpreter"]["ok"]')"
mkdir -p $T/kuma/uptime-kuma-2.5.5/server
cat > $T/kuma/uptime-kuma-2.5.5/package.json <<'JSON'
{"name": "uptime-kuma", "version": "2.5.5", "engines": {"node": ">= 20.4.0"},
 "scripts": {"start": "npm run start-server", "start-server": "node server/server.js", "download-dist": "node extra/download-dist.js"}}
JSON
echo '{"lockfileVersion": 3}' > $T/kuma/uptime-kuma-2.5.5/package-lock.json; echo 'console.log(1)' > $T/kuma/uptime-kuma-2.5.5/server/server.js
tar -C $T/kuma -cf $T/kuma.tar uptime-kuma-2.5.5; ctl upload kuma.tar $T/kuma.tar > /dev/null
ctl site-install n6.test --file kuma.tar --yes --reason node > $T/out
check "site-install of a Node archive: package.json read (name, the entry it starts, the lockfile), the runtime's node asked and matched against engines" "True uptime-kuma server/server.js True 20.19.2 True" "$(j 'd["ok"], d["facts"]["package_name"], d["facts"]["entry_guess"], d["facts"]["lockfile"], d["facts"]["runtime_node"], d["facts"]["engines_match"]')"
check "its next steps: the versions match, npm_ci then Kuma's download-dist, DATA_DIR in the account's home, the entry, the unit, the first-visit warning; never 'open the browser'" "yes yes yes yes yes yes no" "$(for k in 'they match' 'site_task npm_ci' 'download-dist' '"DATA_DIR": "'$T'/state/r6/data/"' 'site_update with entry "server/server.js"' 'whoever opens the site first'; do j '"yes" if any('"'$k'"' in x for x in d["next_steps"]) else "no"' | tr '\n' ' '; done)$(j '"yes" if any("open the site in a browser" in x for x in d["next_steps"]) else "no"')"
ctl site-task n6.test npm_ci --yes --reason node > $T/out
check "npm_ci: npm from runtimes.node as r6 in the project, npm ci --omit=dev, NODE_ENV and npm's cache and configuration in r6's home; a summary; the restart line" "True ci|--omit=dev|--no-audit|--no-fund uid=r6 NODE_ENV=production CACHE=$T/state/r6/.npm USERCONFIG=$T/state/r6/.npmrc added 3 packages in 1s yes" "$(j 'd["ok"], "|".join(d["argv"][1:])') $(j '" ".join([l for l in d["output"].splitlines() if l.startswith("uid=")][0].split()[i] for i in (0, 2, 3, 4))') $(j 'd["summary"]') $(j '"yes" if "systemctl restart agensio-app-r6.service" in d["next_steps"][0] else d.get("next_steps")')"
check "npm_run download-dist leaves dist/ as r6; a script name that looks like an option is refused before anything runs; a missing script names the cause" "True r6 400 1 yes" "$(ctl site-task n6.test npm_run --param script=download-dist --yes --reason node > $T/out; j 'd["ok"]') $(stat -c %U $N6/dist/index.html) $(curl -sS -o /dev/null -w '%{http_code}' --unix-socket $CS -X POST -d '{"task":"npm_run","params":{"script":"--prefix=/"},"confirm":true}' http://control/v1/sites/n6.test/task) $(ctl site-task n6.test npm_run --param script=nope --yes --reason node > $T/out; echo -n "$? "; j '"yes" if "no script" in d.get("hint", "") else d')"
check "a Node site's environment cannot move the application off loopback (HOST, PORT, NODE_ENV) nor set npm's registry; DATA_DIR is its own" "1 1 1 0" "$(for kv in HOST=0.0.0.0 PORT=80 NPM_CONFIG_REGISTRY=https://evil.example DATA_DIR=$T/state/r6/data/; do ctl site-env-set n6.test --set $kv --yes --reason node > /dev/null 2>&1; echo -n "$? "; done | sed 's/ $//')"
ctl site-update n6.test --entry server/server.js --yes --reason node > /dev/null
check "site-unit renders the node unit: root's node on the entry, HOST and PORT from the upstream, as r6" "yes yes yes" "$(ctl site-unit n6.test > $T/out; j '"yes" if "ExecStart='$NODERT'/node '$N6'/server/server.js" in d["unit"] else d["unit"]') $(j '"yes" if "Environment=HOST=127.0.0.1 PORT=18406" in d["unit"] else "no"') $(j '"yes" if "User=r6" in d["unit"] else "no"')"
check "the edge: the project's manifests, node_modules and a database are 404, never forwarded; the rest goes to node (502: none runs)" "404 404 404 404 502 502" "$(for p in /package.json /package-lock.json /node_modules/socket.io/ /data/kuma.db /api/status /socket.io/; do curl -sS -o /dev/null -w '%{http_code} ' -H Host:n6.test http://127.0.0.1:18399$p; done | sed 's/ $//')"

# The application service's state and journal through the helper (alpha.33 report): fake
# systemctl and journalctl stand in, only inside a container whose init is not systemd.
if [ -f /.dockerenv ] && [ "$(cat /proc/1/comm)" != systemd ]; then
  for b in systemctl journalctl; do [ -e /usr/bin/$b ] && [ ! -e /usr/bin/$b.agensio-orig ] && mv /usr/bin/$b /usr/bin/$b.agensio-orig; done
  cat > /usr/bin/systemctl <<SH
#!/bin/sh
echo "\$*" > $T/systemctl.args
state=\$(cat $T/unit-state 2>/dev/null || echo active)
for u in "\$@"; do
  case "\$u" in agensio-app-*) ;; *) continue ;; esac
  case "\$state" in
    missing) printf 'Id=%s\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nResult=success\n\n' "\$u" ;;
    failed) printf 'Id=%s\nLoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainStatus=1\nInactiveEnterTimestamp=Sun 2026-09-27 10:00:00 UTC\nNRestarts=0\nUnitFileState=enabled\n\n' "\$u" ;;
    *) printf 'Id=%s\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nActiveEnterTimestamp=Sun 2026-09-27 09:00:00 UTC\nUnitFileState=enabled\n\n' "\$u" ;;
  esac
done
SH
  cat > /usr/bin/journalctl <<SH
#!/bin/sh
echo "\$*" > $T/journalctl.args
echo '2026-09-27T10:00:00+00:00 host puma[42]: Puma starting in single mode...'
echo '2026-09-27T10:00:01+00:00 host puma[42]: bind(2) for "127.0.0.1" port 18398 (Errno::EADDRINUSE)'
SH
  chmod 755 /usr/bin/systemctl /usr/bin/journalctl
  check "site-service: the unit derived from the site's account, one systemctl show with fixed properties; running, pid, since" "show agensio-app-r4.service --no-pager -p | running (running) since Sun 2026-09-27 09:00:00 UTC, pid 4242" "$(ctl site-service r4.test > $T/out; cut -d, -f1 $T/systemctl.args | sed 's/ Id$//') | $(j 'd["summary"]')"
  echo failed > $T/unit-state
  check "a failed service: the summary, site_service_logs and root's restart line; health warns for the site" "yes yes warn" "$(ctl site-service r4.test > $T/out; j '"yes" if d["summary"].startswith("agensio-app-r4.service failed (exit-code, exit status 1)") else d["summary"]') $(j '"yes" if "site_service_logs r4.test" in d["next_steps"][0] and "systemctl restart agensio-app-r4.service" in d["next_steps"][1] else d["next_steps"]') $(ctl health > $T/out; j '[f["severity"] for f in d["findings"] if f["code"] == "site_service_failed" and f.get("site") == "r4.test"][0]')"
  check "health asks for every Rails site's unit in one systemctl show" "yes" "$(grep -q 'agensio-app-r1.service' $T/systemctl.args && grep -q 'agensio-app-r4.service' $T/systemctl.args && echo yes)"
  echo missing > $T/unit-state
  check "no unit installed: the answer points at site_service_unit; health says so as info" "yes info" "$(ctl site-service r4.test > $T/out; j '"yes" if "site_service_unit r4.test" in d["next_steps"][0] else d') $(ctl health > $T/out; j '[f["severity"] for f in d["findings"] if f["code"] == "site_service_missing" and f.get("site") == "r4.test"][0]')"
  check "site-service-logs on a Django site: the hint speaks of a Python traceback" "yes" "$(ctl site-service-logs w5.test > $T/out; j '"yes" if "Python traceback" in d["hint"] else d["hint"]')"
  check "site-service-logs: fixed journalctl arguments with the typed lines and since, the journal's lines, the read audited" "-u agensio-app-r4.service -n 20 --no-pager -q -o short-iso --since=-3h | yes yes" "$(ctl site-service-logs r4.test --lines 20 --since 3h > $T/out; cat $T/journalctl.args) | $(j '"yes" if "EADDRINUSE" in d["output"] else d') $(grep -q 'sites/r4.test/service/logs: read 2 lines of the journal of agensio-app-r4.service' $T/logs/audit.log && echo yes)"
  check "site-service-logs refuses lines out of range and a since that is not a duration, before the helper" "400 400" "$(curl -sS -o /dev/null -w '%{http_code}' --unix-socket $CS 'http://control/v1/sites/r4.test/service/logs?lines=5000') $(curl -sS -o /dev/null -w '%{http_code}' --unix-socket $CS 'http://control/v1/sites/r4.test/service/logs?since=3%20hours')"
  rm -f /usr/bin/systemctl /usr/bin/journalctl
  for b in systemctl journalctl; do [ -e /usr/bin/$b.agensio-orig ] && mv /usr/bin/$b.agensio-orig /usr/bin/$b; done
else
  echo "tasks: the service checks need a container without systemd as init; skipped"
fi

# r2's secret readable by others while the directory is open: health records it, then a call
# on r1 closes the directory; r2 is deleted unrotated.
chmod 775 $T/env; chmod 644 $T/env/r2.test.env; ctl health > /dev/null; ctl site-env r1.test > /dev/null
check "site-delete of a site whose kept file was exposed says so, instead of advising to keep it blindly" "SECRET_KEY_BASE,DATABASE_URL yes" "$(ctl site-delete r2.test --yes --reason exposed > $T/out; j '",".join(d["exposed"])') $(j '"yes" if "SECRET_KEY_BASE, DATABASE_URL in it were readable by others and never rotated" in d["hint"] and "rotate them then" in d["hint"] else d["hint"]')"
check "health rates that orphan a warning, naming what was never rotated" "warn" "$(ctl health > $T/out; j '[f["severity"] for f in d["findings"] if f["code"] == "site_env_orphan" and "r2.test.env" in f["message"] and "SECRET_KEY_BASE, DATABASE_URL in it were readable by others and never rotated" in f["message"]][0]')"
ctl site-create --domain r2.test --app rails --root $T/www/r2.test/app --user r2 --upstream http://127.0.0.1:18401 --https none --listen-plain 127.0.0.1:18399 --yes --reason again > /dev/null
check "site-delete of a rails site names the environment file it keeps (the helper saw it), with the root line that removes it" "yes yes yes" "$(ctl site-delete r2.test --yes --reason gone > $T/out; j '"yes" if "'$T'/env/r2.test.env" in d["kept"][0] and "if it has one" not in d["kept"][0] else d') $(j '"yes" if d["run_as_root"] == ["rm -f '$T'/env/r2.test.env"] else d') $([ -f $T/env/r2.test.env ] && echo yes)"
ctl site-create --domain r3.test --app rails --root $T/www/r3.test/app --user r3 --upstream http://127.0.0.1:18402 --https none --listen-plain 127.0.0.1:18399 --yes --reason noenv > /dev/null
check "site-delete of a rails site that has no environment file says nothing about one" "no no" "$(ctl site-delete r3.test --yes --reason gone > $T/out; j '"yes" if "kept" in d else "no"') $(j '"yes" if "run_as_root" in d else "no"')"
check "health names the deleted site's environment file as an orphan, with the rm line" "yes" "$(ctl health > $T/out; j '"yes" if any(f["code"] == "site_env_orphan" and "r2.test.env" in f["message"] and "rm -f" in f.get("fix", "") for f in d["findings"]) else [f for f in d["findings"] if f["code"].startswith("site_env")]')"
rm -f $T/env/r2.test.env; ctl health > /dev/null
check "a ledger entry with neither a site nor a file is pruned" "no" "$(grep -q '^r2.test ' $T/env/.exposed 2>/dev/null && echo yes || echo no)"
check "unsetting every variable removes the file and the answer says so" "yes no" "$(ctl site-env-set r1.test --unset DATABASE_URL --unset SECRET_KEY_BASE --yes --reason empty > $T/out; j '"yes" if d["removed"].endswith("r1.test.env") and "no variables left" in d["done"][0] else d') $([ -e $T/env/r1.test.env ] && echo yes || echo no)"
check "health: no PHP finding and no unreadable-files finding for the rails sites (nothing is served from their root); the site file names app = rails" "no yes" "$(ctl health | grep -q 'php_tmp_missing\|pools_stale\|files_unreadable' && echo yes || echo no) $(grep -q '^app = "rails"' $T/sites.d/r1.test.toml && echo yes)"

# Laravel's tasks on a php site (2026-11-04, the grabloop.app report): in the release that holds artisan,
# the nearest from served_dir up, with the site's own PHP version's command-line binary, as its account.
LV=$T/www/lv.test
out=$(ctl site-create --domain lv.test --app php --root $LV --served-dir releases/r1/public --user r9 --php-socket unix:$T/run/lv.sock --https none --listen-plain 127.0.0.1:18399 --yes --reason laravel)
# A php root runs files, so its creation waits for a person's approval (docs/approvals.md).
echo "$out" | grep -q '"pending":true' && out=$(approve)
mkdir -p $LV/releases/r1/public $LV/releases/r2/public $LV/shared; echo '<?php' > $LV/releases/r1/artisan; chown -R r9:r9 $LV/releases $LV/shared
check "a php site with served_dir on a release lists Laravel's eight tasks, in the release that holds artisan, with the site's PHP binary" "yes 8 $LV/releases/r1 $RT/php9.9 True" \
  "$(echo "$out" | grep -q '"ok":true' && echo yes) $(ctl site-tasks lv.test > $T/out; j 'len(d["tasks"]), d["directory"], [t for t in d["tasks"] if t["task"] == "optimize"][0]["interpreter"]["program"], all(t["interpreter"]["ok"] for t in d["tasks"])' | tr -d '(),' | tr -d "'")"
ctl site-task lv.test schedule_clear_cache --yes --reason locks > $T/out
check "schedule_clear_cache runs php9.9 artisan schedule:clear-cache (the locks of withoutOverlapping() commands)" "True yes" \
  "$(j 'd["ok"]') $(grep -q 'prog=php9.9 args=artisan schedule:clear-cache --no-interaction' $T/out && echo yes)"
ctl site-task lv.test migrate_force --yes --reason deploy > $T/out
check "migrate_force runs php9.9 artisan migrate --force as r9 in the release" "True yes yes" \
  "$(j 'd["ok"]') $(grep -q 'prog=php9.9 args=artisan migrate --force --no-interaction' $T/out && echo yes) $(grep -q "uid=r9 cwd=$LV/releases/r1" $T/out && echo yes)"
ctl site-update lv.test --served-dir releases/r2/public --yes --reason switch > /dev/null; approve > /dev/null
ctl site-task lv.test optimize --yes --reason deploy > $T/out
check "after a switch to a release without artisan, the task is refused before it runs, naming artisan" "False yes" "$(j 'd["ok"]') $(grep -q 'no artisan file' $T/out && echo yes)"
echo '<?php' > $LV/releases/r2/artisan; chown r9:r9 $LV/releases/r2/artisan
# Behind a symbolic link (the alpha.124 report, problem C: current -> releases/N, Deployer's layout): the
# tasks never follow it, and the refusal and the task list say so rather than "no Laravel application".
ln -s releases/r2 $LV/current; chown -h r9:r9 $LV/current
ctl site-update lv.test --served-dir current/public --yes --reason link > /dev/null; approve > /dev/null
ctl site-task lv.test optimize --yes --reason deploy > $T/out
check "a release behind a symbolic link: the task is refused before it runs, naming the link and the way" "False yes no" \
  "$(j 'd["ok"]') $(grep -q 'current is a symbolic link, which the tasks never follow' $T/out && echo yes) $(grep -q 'no Laravel application' $T/out && echo yes || echo no)"
check "the task list names the link too" "yes" "$(ctl site-tasks lv.test > $T/out; j '"yes" if "current is a symbolic link" in d.get("note", "") else d.get("note")')"
ctl site-update lv.test --served-dir releases/r2/public --yes --reason back > /dev/null; approve > /dev/null
rm $LV/current

# A Laravel site's own .env (2026-11-04, the grabloop.app answer): env_file names it; site_env_set writes it
# root's with the site's group, 0640, every other line kept; site_env shows names and lengths, no value.
printf '# mine\nAPP_NAME=Grab\nDB_PASSWORD=old\n' > $LV/shared/.env; chown r9:r9 $LV/shared/.env; chmod 600 $LV/shared/.env
check "site-env on a php site without env_file is refused with the way" "yes" "$(ctl site-env lv.test > $T/out 2>&1; grep -q 'names no env_file' $T/out && echo yes)"
ctl site-update lv.test --env-file shared/.env --yes --reason env > /dev/null
ctl site-env-set lv.test --set APP_DEBUG=false --generate APP_KEY --yes --reason env > $T/out
check "site-env-set writes the site's .env: root's, the site's group, 0640; the other lines kept; APP_KEY in Laravel's form; no value in the answer; optimize named" \
  "True root $(id -gn r9) 640 yes APP_KEY 51 no yes" \
  "$(j 'd["ok"]') $(stat -c '%U %G %a' $LV/shared/.env) $(grep -q '^# mine$' $LV/shared/.env && grep -q '^APP_NAME=Grab$' $LV/shared/.env && grep -q '^DB_PASSWORD=old$' $LV/shared/.env && grep -q '^APP_DEBUG=false$' $LV/shared/.env && echo yes) $(j '",".join(d["generated"])') $(sed -n 's/^APP_KEY=//p' $LV/shared/.env | tr -d '\n' | wc -c) $(grep -q 'base64:\|=old' $T/out && echo yes || echo no) $(j '"yes" if "optimize" in d["next_steps"][0] else d.get("next_steps")')"
ctl site-env lv.test > $T/out
check "site-env lists the .env's names with their lengths, no value, and names optimize" "APP_NAME,DB_PASSWORD,APP_DEBUG,APP_KEY 51 no yes" \
  "$(j '",".join(v["name"] for v in d["variables"]) + " " + str(int([v for v in d["variables"] if v["name"] == "APP_KEY"][0]["length"]))') $(grep -q 'base64:\|"old"\|Grab' $T/out && echo yes || echo no) $(j '"yes" if "optimize" in d["hint"] else d["hint"]')"
check "the site's account reads its .env and cannot write it in place" "yes no" "$(su -s /bin/sh r9 -c "cat $LV/shared/.env" > /dev/null 2>&1 && echo yes) $(su -s /bin/sh r9 -c "echo x >> $LV/shared/.env" 2>/dev/null && echo yes || echo no)"
# A dry run writes nothing (the alpha.125 report: site_env_set read no dry_run, and the gate let the dry
# run through unapproved, so it wrote the file), and a change its dry run refuses is answered at once,
# never stored for a person's code (problem 1: an open quote and lower-case names were queued).
cp -p $LV/shared/.env $T/env.before
"$BIN" ctl site-env-set lv.test --set DRY=1 --generate DRY_KEY --dry-run --socket $CS > $T/out
check "site-env-set --dry-run answers what it would set and generate, and writes nothing" "True True DRY DRY_KEY same" \
  "$(j 'd["ok"], d.get("dry_run")' | tr -d '(),') $(j '" ".join(d.get("set", []) + d.get("generated", []))') $(cmp -s $T/env.before $LV/shared/.env && echo same)"
printf 'MULTI="open\n' >> $LV/shared/.env
post() { curl -sS -o $T/out -w '%{http_code}' --unix-socket $CS -X POST -H 'Content-Type: application/json' -d "$2" "http://control$1"; }
waiting() { curl -sS --unix-socket $CS http://control/v1/approvals | python3 -c 'import json,sys; print(sum(1 for a in json.load(sys.stdin)["approvals"] if a["state"] == "waiting"))'; }
check "a change its dry run refuses is answered at once and waits for no one: an open quote (409), a lower-case name (400, the way to change such a line named)" "409 yes 400 yes 0" \
  "$(post /v1/sites/lv.test/env '{"set":{"NEWVAR":"1"},"confirm":true,"reason":"q"}') $(j '"yes" if "never closes" in d.get("error", "") else d') $(post /v1/sites/lv.test/env '{"set":{"e":"5"},"confirm":true,"reason":"q"}') $(j '"yes" if "site_file_edit" in d.get("hint", "") else d') $(waiting)"
for id in $(curl -sS --unix-socket $CS http://control/v1/approvals | python3 -c 'import json,sys; print(" ".join(a["id"] for a in json.load(sys.stdin)["approvals"] if a["state"] == "waiting"))'); do
  curl -sS -o /dev/null --unix-socket $CS -X POST -d '{}' http://control/v1/approvals/$id/reject
done
cp -p $T/env.before $LV/shared/.env
# A rotated service password is new to its service, and a new APP_KEY signs everyone out (the alpha.125
# report, problem 3): the person approving reads it in the preview; the answer puts root's step at the
# service first, with the line that reads the value on root's terminal, optimize after it.
post /v1/sites/lv.test/env '{"unset":["DB_PASSWORD","APP_KEY"],"generate":["DB_PASSWORD","APP_KEY"],"confirm":true,"reason":"rotate"}' > /dev/null
check "a rotation's preview notes the service's password and the new APP_KEY" "yes yes" \
  "$(j '"yes" if "note: DB_PASSWORD is a new password its service" in d.get("preview", "") else d.get("preview")') $(j '"yes" if "a new APP_KEY signs every user out" in d.get("preview", "") else d.get("preview")')"
curl -sS -o /dev/null --unix-socket $CS -X POST -d '{}' http://control/v1/approvals/$(j 'd["id"]')/reject
# The password's line starts with export here, which the rotation keeps: root's line finds it too (the
# alpha.126 report: grep '^DB_PASSWORD=' printed nothing).
sed 's/^DB_PASSWORD=/export DB_PASSWORD=/' $T/env.before > $LV/shared/.env
ctl site-env-set lv.test --unset DB_PASSWORD --generate DB_PASSWORD --unset APP_KEY --generate APP_KEY --yes --reason rotate > $T/out
check "the rotation answers root's step at the service first, optimize after, the APP_KEY warning; root's line prints the new value of an export line, which the answer does not hold" "True True True same no" \
  "$(j 'd["next_steps"][0].startswith("first, before the application needs it: root sets the new DB_PASSWORD"), "optimize" in d["next_steps"][-1], any("signs every user out" in w for w in d["warnings"])' | tr -d '(),') $(l=$(grep '^export DB_PASSWORD=' $LV/shared/.env); [ -n "$l" ] && [ "$(sh -c "$(j 'd["run_as_root"][0]')")" = "$l" ] && echo same) $(grep -qF "$(sed -n 's/^export DB_PASSWORD=//p' $LV/shared/.env)" $T/out && echo yes || echo no)"
cp -p $T/env.before $LV/shared/.env
# The MCP tool has the dry run too, without confirm (the alpha.126 report: only ctl and the socket had
# it, so an agent could not show the user the warnings before queuing the change).
check "MCP site_env_set has a dry run that needs no confirm: the rotation's warnings, nothing written, nothing waiting" "True no-confirm True yes same 0" \
  "$(python3 - "$BIN" "$CS" <<'PYT'
import json, subprocess, sys
p = subprocess.Popen([sys.argv[1], "mcp", "--socket", sys.argv[2]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def rpc(i, method, params=None):
    msg = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None: msg["params"] = params
    p.stdin.write(json.dumps(msg) + "\n"); p.stdin.flush()
    return json.loads(p.stdout.readline())
rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})
schema = {t["name"]: t for t in rpc(2, "tools/list")["result"]["tools"]}["site_env_set"]["inputSchema"]
out = [str("dry_run" in schema["properties"]), "no-confirm" if "confirm" not in schema.get("required", []) else "confirm-required"]
r = rpc(3, "tools/call", {"name": "site_env_set", "arguments": {"name": "lv.test", "unset": ["DB_PASSWORD"], "generate": ["DB_PASSWORD"], "dry_run": True, "reason": "preview"}})
sc = r["result"].get("structuredContent", {})
out.append(str(bool(sc.get("dry_run")) and not r["result"]["isError"]))
out.append("yes" if any("DB_PASSWORD is a new password" in w for w in sc.get("warnings", [])) else r["result"]["content"][0]["text"][:200].replace(" ", "_"))
p.stdin.close(); p.wait()
print(" ".join(out))
PYT
) $(cmp -s $T/env.before $LV/shared/.env && echo same) $(waiting)"

# The scheduler (2026-11-04, the grabloop.app answer): the timer asks for schedule_run with --scheduled;
# it holds no task slot, is skipped while a task runs, keeps the deploy's output, and the audit log
# names it only when its outcome changes.
ctl site-task lv.test schedule_run --scheduled --yes --reason scheduler > $T/out
ctl site-task lv.test schedule_run --scheduled --yes --reason scheduler > $T/out.quiet
check "a scheduled schedule_run runs php9.9 artisan schedule:run in the live release; twice, one audit line; the deploy's output kept" "True yes 1 yes" \
  "$(j 'd["ok"]') $(grep -q 'args=artisan schedule:run --no-interaction' $T/out && echo yes) $(grep -c 'scheduled schedule_run ran' $T/logs/audit.log) $(ctl site-task-output lv.test > $T/out2; grep -q 'migrate --force' $T/out2 && ! grep -q 'schedule:run' $T/out2 && echo yes)"
# The journal gets a run's record only when the audit log would (the alpha.125 report: 5,760 lines a day).
check "the first scheduled run prints its record (outcome_changed), the second, like it, prints nothing" "True 0" \
  "$(j 'd["outcome_changed"]') $(wc -c < $T/out.quiet | tr -d ' ')"
check "--scheduled is for schedule_run alone" "400" "$(curl -sS -o /dev/null -w '%{http_code}' --unix-socket $CS -X POST -H 'Content-Type: application/json' -d '{"task":"optimize","scheduled":true,"confirm":true}' http://control/v1/sites/lv.test/task)"
touch $LV/releases/r2/slow; chown r9:r9 $LV/releases/r2/slow
ctl site-task lv.test optimize --yes --reason deploy > $T/out.bg & BG=$!; sleep 1
ctl site-task lv.test schedule_run --scheduled --yes --reason scheduler > $T/out; RC=$?
wait $BG
# A skip exits 0, its record printed (the alpha.126 report: exit 1 had systemd mark the unit failed for
# each minute a deploy's task ran).
check "while a deploy task runs, the minute's scheduled run is skipped (printed, exit 0), and the deploy task is not refused for it" "True yes 0 True" \
  "$(j 'd["skipped"]') $(grep -q 'a task runs on the site' $T/out && echo yes) $RC $(python3 -c "import json; print(json.load(open('$T/out.bg'))['ok'])")"
rm -f $LV/releases/r2/slow
ctl site-unit lv.test > $T/out
check "site-unit renders the scheduler: two units, the service asking agensio as the server's account, nothing naming a release; --out writes the one it names" "scheduler 2 yes yes 0 2" \
  "$(j 'd["kind"], len(d["units"])' | tr -d '(),' | tr -d "'") $(j '"yes" if "User=agensio" in d["units"][0]["unit"] and "ctl site-task lv.test schedule_run --scheduled" in d["units"][0]["unit"] and "releases" not in d["units"][0]["unit"] else d["units"][0]["unit"]') $(j '"yes" if "OnCalendar=*-*-* *:*:00" in d["units"][1]["unit"] else d["units"][1]["unit"]') $(mkdir -p $T/units; ctl site-unit lv.test --out $T/units/agensio-schedule-lv.test.timer > /dev/null; echo $?) $(ctl site-unit lv.test --out $T/units/other.timer > /dev/null 2>&1; echo $?)"
if [ -f /.dockerenv ] && [ "$(cat /proc/1/comm)" != systemd ]; then
  [ -e /usr/bin/systemctl ] && [ ! -e /usr/bin/systemctl.agensio-orig ] && mv /usr/bin/systemctl /usr/bin/systemctl.agensio-orig
  cat > /usr/bin/systemctl <<SH
#!/bin/sh
state=\$(cat $T/sched-state 2>/dev/null || echo missing)
for u in "\$@"; do
  case "\$u" in agensio-schedule-*) ;; *) continue ;; esac
  if [ "\$state" = missing ]; then printf 'Id=%s\nLoadState=not-found\nActiveState=inactive\n\n' "\$u"
  else printf 'Id=%s\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\nFragmentPath=/etc/systemd/system/%s\nLastTriggerUSec=Wed 2026-11-04 10:00:00 UTC\n\n' "\$u" "\$u"; fi
done
SH
  chmod 755 /usr/bin/systemctl
  ctl site-service lv.test > $T/out
  check "site-service on a Laravel site: no scheduler installed, nothing in cron, the two runs recorded, the way to render one" "False 0 2 yes" \
    "$(j 'd["scheduler"]["installed"], len(d["scheduler"]["cron"]), d["runs"]["since_start"]' | tr -d '(),') $(j '"yes" if "site_service_unit lv.test" in d["next_steps"][0] else d["next_steps"]')"
  mkdir -p /var/spool/cron/crontabs; printf '# m h dom mon dow command\n* * * * * cd %s/releases/r2 && php artisan schedule:run >> /dev/null 2>&1\n' "$LV" > /var/spool/cron/crontabs/r9
  ctl site-service lv.test > $T/out
  check "a cron line of the site's account that runs schedule:run is named by file and line, never by its text; make no other" "/var/spool/cron/crontabs/r9 2 no yes" \
    "$(j 'd["scheduler"]["cron"][0]["file"], int(d["scheduler"]["cron"][0]["line"])' | tr -d '(),' | tr -d "'") $(grep -q 'php artisan' $T/out && echo yes || echo no) $(j '"yes" if "make no other" in d["next_steps"][0] else d["next_steps"]')"
  echo installed > $T/sched-state
  check "agensio's timer installed beside the cron line: site-service says duplicate, health warns site_schedule_duplicate" "True warn" \
    "$(ctl site-service lv.test > $T/out; j 'd["duplicate"]') $(ctl health > $T/out; j '[f["severity"] for f in d["findings"] if f["code"] == "site_schedule_duplicate" and f.get("site") == "lv.test"][0]')"
  # A command started with runInBackground() is ended when schedule:run exits (the alpha.126 report,
  # problem 4): site-service names it from the run's output, with what the application changes.
  ctl site-service lv.test > $T/out
  check "before a run starts a command in background, site-service names none, health warns of none" "None no" \
    "$(j 'd["runs"].get("background")') $(ctl health > $T/out.health; python3 -c "import json; print('yes' if any(f['code'] == 'site_schedule_background' for f in json.load(open('$T/out.health'))['findings']) else 'no')")"
  for r in r1 r2; do touch $LV/releases/$r/bg; done
  ctl site-task lv.test schedule_run --scheduled --yes --reason scheduler > /dev/null
  rm -f $LV/releases/r1/bg $LV/releases/r2/bg
  ctl site-service lv.test > $T/out
  check "a scheduled run that started a command in background: site-service names it, the summary says agensio ends it, a step says what to change and schedule_clear_cache" "yes 1 yes yes" \
    "$(j '"yes" if d["runs"]["background"]["command"] == "\x27artisan\x27 report:send" else d["runs"]') $(j 'int(d["runs"]["background"]["runs"])') $(j '"yes" if "agensio ends it when schedule:run exits" in d["summary"] else d["summary"]') $(j '"yes" if any("runInBackground()" in s and "schedule_clear_cache" in s and "queue" in s for s in d["next_steps"]) else d["next_steps"]')"
  # Health says so too (the alpha.127 report, S3): the run was quiet and ok, so the journal got nothing
  # and nothing sent anyone to site-service.
  ctl health > $T/out
  check "health warns site_schedule_background for it, naming the command, with the application's change and schedule_clear_cache" "warn yes yes" \
    "$(j '[f["severity"] for f in d["findings"] if f["code"] == "site_schedule_background" and f.get("site") == "lv.test"][0]') $(j '"yes" if any("report:send" in f["message"] for f in d["findings"] if f["code"] == "site_schedule_background") else d["findings"]') $(j '"yes" if any("schedule_clear_cache" in f["fix"] and "runInBackground()" in f["fix"] for f in d["findings"] if f["code"] == "site_schedule_background") else "no"')"
  # The reads and the approval codes have a helper of their own (the alpha.126 report, problem 3): a
  # task holding the main helper for three seconds (task_limits' 5 s leaves room on a loaded host)
  # makes site-service answer neither busy nor late, and a code is checked at once (a wrong one here,
  # for a reveal left waiting), not after the task.
  touch $LV/releases/r2/slow; chown r9:r9 $LV/releases/r2/slow
  ctl site-task lv.test optimize --yes --reason deploy > $T/out.bg & BG=$!; sleep 0.5
  T0=$(date +%s%N); ctl site-service lv.test > $T/out; RC=$?; T1=$(date +%s%N)
  RID=$(curl -sS --unix-socket $CS "http://control/v1/sites/r1.test/env?reveal=SECRET_KEY_BASE" | python3 -c 'import json, sys; print(json.load(sys.stdin).get("id", ""))')
  T2=$(date +%s%N)
  CODE=$(curl -sS -o $T/out.code -w '%{http_code}' --unix-socket $CS -X POST -H 'Content-Type: application/json' -d "{\"code\":\"000000\",\"ids\":[\"$RID\"]}" http://control/v1/approvals)
  T3=$(date +%s%N)
  wait $BG
  rm -f $LV/releases/r2/slow
  check "while a task holds the helper: site-service answers at once from the reader, not busy; a code is checked at once; the task itself ran" "0 False yes yes 403 yes True" \
    "$RC $(j 'd.get("busy", False)') $([ $(( (T1 - T0) / 1000000 )) -lt 2000 ] && echo yes || echo $(( (T1 - T0) / 1000000 ))ms) $([ -n "$RID" ] && echo yes) $CODE $([ $(( (T3 - T2) / 1000000 )) -lt 2000 ] && echo yes || echo $(( (T3 - T2) / 1000000 ))ms) $(python3 -c "import json; d = json.load(open('$T/out.bg')); print(d['ok'] or str(d.get('error', d))[:300].replace(' ', '_'))")"
  rm -f /var/spool/cron/crontabs/r9 /usr/bin/systemctl
  [ -e /usr/bin/systemctl.agensio-orig ] && mv /usr/bin/systemctl.agensio-orig /usr/bin/systemctl
fi

stop
write_config 'task_downloads = false'
start
check "task_downloads = false: a task that downloads is refused, one that does not still runs" "1 yes 0" "$(ctl site-task r1.test bundle_install --yes --reason net > $T/out; echo -n "$? "; grep -q 'task_downloads = false' $T/out && echo -n yes; echo -n ' '; ctl site-task r1.test db_migrate --yes --reason net > /dev/null; echo $?)"
stop

echo "tasks: $pass passed, $fail failed"
[ "$fail" = 0 ]
