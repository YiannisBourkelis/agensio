#!/usr/bin/env bash
# One broken site never stops the others (design section 26, 2026-10-10). Site files under
# sites.d/ are loaded each on its own: a file with an error is set aside and the other sites
# serve; on reload a file set aside keeps its last good version; a file claiming a running
# site's name on its address is set aside, the running one keeping its place; a site whose root
# additions file cannot be loaded is set aside whole; -t exits 0 with a warning, --strict 1;
# health names each file; the control plane never reports a change it set aside as done.
# usage: tests/isolation.sh build/agensio
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
ROOT=$(pwd)
T=$ROOT/bench/tmp/isolation; rm -rf "$T"; mkdir -p "$T/sites.d" "$T/logs" "$T/www/a" "$T/www/a2" "$T/www/b" "$T/www/c" "$T/www/d" "$T/www/e"
for s in a a2 b c d e; do echo "site $s" > "$T/www/$s/index.html"; done
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
body() {  # host port: the site's answer for that name, or "none"
  local out code
  out=$(curl -sS --max-time 3 -w '\n%{http_code}' -H "Host: $1" "http://127.0.0.1:$2/" 2>/dev/null) || { echo "none"; return; }
  code=${out##*$'\n'}
  [ "$code" = 200 ] && echo "${out%$'\n'*}" || echo "none"
}
CS="$T/control.sock"
cat > "$T/agensio.toml" <<EOF
include = ["sites.d/*.toml"]
[server]
workers = 1
pid_file = "$T/agensio.pid"
[log]
access = "off"
error = "$T/logs/error.log"
[control]
socket = "$CS"
sites_root = "$T/www"
provision = false
EOF
site() {  # file name root [extra lines]
  printf '[[site]]\nserver_name = ["%s"]\nlisten = ["127.0.0.1:%s"]\nroot = "%s"\n%s\n' "$1" "$2" "$3" "${4:-}"
}
site a.test 18301 "$T/www/a" > "$T/sites.d/a.toml"
site b.test 18302 "$T/www/b" 'refsue = ["/x/"]' > "$T/sites.d/b.toml"   # a misspelt key: the file has an error
health() { "$BIN" ctl health --socket "$CS" 2>/dev/null; }
held() {  # file: the health finding's message for that file, or "none"
  health | python3 -c "
import json, sys
try: d = json.load(sys.stdin)
except ValueError: d = {'findings': []}
m = [f['message'] for f in d.get('findings', []) if f['code'] == 'site_file_held_back' and sys.argv[1] in f['message']]
print(m[0] if m else 'none')" "$1"
}
reload() { kill -HUP "$SRV"; sleep 0.6; }

# At start: the broken file is set aside, the other site serves.
"$BIN" -t -c "$T/agensio.toml" > "$T/t.out" 2>&1; T_EXIT=$?
"$BIN" -t --strict -c "$T/agensio.toml" > "$T/strict.out" 2>&1; STRICT_EXIT=$?
check "-t exits 0 with a warning naming the file set aside; -t --strict exits 1" "0 yes 1" \
  "$T_EXIT $(grep -q 'b.toml' "$T/t.out" && grep -qi 'set aside' "$T/t.out" && echo yes) $STRICT_EXIT"
"$BIN" -c "$T/agensio.toml" > "$T/server.out" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null' EXIT
for _ in $(seq 1 50); do [ -S "$CS" ] && nc -z 127.0.0.1 18301 2>/dev/null && break; sleep 0.1; done
check "a broken site file at start: the other site serves, the broken one is not served" "site a none" \
  "$(body a.test 18301) $(body b.test 18302)"
check "health names the file, the loader's error and that its sites are not served" "yes yes yes" \
  "$(held b.toml | grep -q 'b.toml' && echo yes) $(held b.toml | grep -q "refsue" && echo yes) $(held b.toml | grep -q 'not served' && echo yes)"
check "the error log says it at start" "yes" "$(grep -q 'b.toml' "$T/logs/error.log" && grep -qi 'set aside' "$T/logs/error.log" && echo yes)"

# Fixed and reloaded: it serves.
site b.test 18302 "$T/www/b" > "$T/sites.d/b.toml"
reload
check "fixed and reloaded, the site serves; health is clear of it" "site b none" "$(body b.test 18302) $(held b.toml)"

# Broken again in the same reload as another site's change: the last good version of the broken
# file keeps serving, the other change applies.
site b.test 18302 "$T/www/b" 'refsue = ["/x/"]' > "$T/sites.d/b.toml"
site a.test 18301 "$T/www/a2" > "$T/sites.d/a.toml"
reload
check "a running site's file broken on reload: its last good version keeps serving; another site's change applies" "site b site a2" \
  "$(body b.test 18302) $(body a.test 18301)"
check "health says the version loaded before keeps serving" "yes" "$(held b.toml | grep -q 'keeps serving' && echo yes)"
site b.test 18302 "$T/www/b" > "$T/sites.d/b.toml"

# A newcomer claiming a running site's name on its address: set aside, though it loads first.
site a.test 18301 "$T/www/c" > "$T/sites.d/0c.toml"
reload
check "a file claiming a running site's name on its address is set aside; the running site keeps its place" "site a2 yes" \
  "$(body a.test 18301) $(held 0c.toml | grep -q 'a.test' && echo yes)"
rm -f "$T/sites.d/0c.toml"

# A site whose root additions file cannot be loaded is set aside whole, never served without it.
site d.test 18304 "$T/www/d" > "$T/sites.d/d.toml"
printf 'site = "d.test"\n[[location]]\npath = "/private/"\nhandler = "deny"\n' > "$T/sites.d/d.test.root.toml"
chmod 666 "$T/sites.d/d.test.root.toml"   # writable by others: the loader refuses it
reload
check "a site whose root additions file is refused is not served, and health says why" "none yes" \
  "$(body d.test 18304) $(held d.toml | grep -q 'd.test.root.toml' && echo yes)"
rm -f "$T/sites.d/d.test.root.toml" "$T/sites.d/d.toml"
reload

# The control plane: a site-create whose file would be set aside (its alias claims a running
# site's name on the same address) is refused and its file removed, never reported as done.
"$BIN" ctl site-create --domain e.test --alias a.test --app static --no-user --https none --root "$T/www/e" \
  --listen-plain 127.0.0.1:18301 --yes --reason isolation --socket "$CS" > "$T/create.out" 2>&1; CREATE_EXIT=$?
check "site-create whose file would be set aside: refused, the file removed, the running site unchanged" "1 no site a2" \
  "$([ $CREATE_EXIT -ne 0 ] && echo 1 || echo 0) $([ -f "$T/sites.d/e.test.toml" ] && echo yes || echo no) $(body a.test 18301)"

# A broken main file still refuses the reload, as before: the main file is all or nothing.
cp "$T/agensio.toml" "$T/agensio.toml.good"
printf 'workres = 2\n' >> "$T/agensio.toml"
reload
check "a broken main file refuses the reload; every site keeps serving" "site a2 site b" "$(body a.test 18301) $(body b.test 18302)"
mv "$T/agensio.toml.good" "$T/agensio.toml"

echo "isolation: $pass passed, $fail failed"
[ $fail -eq 0 ]
