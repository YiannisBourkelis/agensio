#!/usr/bin/env bash
# One broken site never stops the others (design section 26, 2026-10-10). Site files under
# sites.d/ are loaded each on its own: a file with an error is set aside and the other sites
# serve; on reload a file set aside keeps its last good version; a file claiming a running
# site's name on its address is set aside, the running one keeping its place; a site whose root
# additions file cannot be loaded is set aside whole, and so is a site that breaks a hosting rule
# or whose certificate cannot be loaded;
# -t exits 0 with a warning, --strict 1;
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
m = [f['message'] for f in d.get('findings', []) if f['code'] in ('site_file_held_back', 'hosting_rule') and sys.argv[1] in f['message']]
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

# site-update and site-enable the same way (the alpha.62 report: not covered): an update adding an
# alias another file serves on the address is refused and the previous file put back; enabling a
# site whose name another file serves meanwhile is refused and the file disabled again.
"$BIN" ctl site-create --domain f.test --app static --no-user --https none --root "$T/www/e" \
  --listen-plain 127.0.0.1:18301 --yes --reason isolation --socket "$CS" > "$T/f.out" 2>&1
"$BIN" ctl site-update f.test --alias a.test --yes --reason isolation --socket "$CS" > "$T/fu.out" 2>&1; UPDATE_EXIT=$?
check "site-update adding an alias another file serves: refused, the previous file back, both sites serving" "1 no site e site a2" \
  "$([ $UPDATE_EXIT -ne 0 ] && echo 1 || echo 0) $(grep -q 'a\.test' "$T/sites.d/f.test.toml" && echo yes || echo no) $(body f.test 18301) $(body a.test 18301)"
"$BIN" ctl site-disable f.test --yes --reason isolation --socket "$CS" > /dev/null 2>&1
site f.test 18301 "$T/www/b" > "$T/sites.d/f-hand.toml"; reload   # another file serves f.test meanwhile
"$BIN" ctl site-enable f.test --yes --reason isolation --socket "$CS" > "$T/fe.out" 2>&1; ENABLE_EXIT=$?
check "site-enable of a site whose name another file serves meanwhile: refused, the file disabled again, the other one serving" "1 yes site b" \
  "$([ $ENABLE_EXIT -ne 0 ] && echo 1 || echo 0) $([ -f "$T/sites.d/f.test.toml.disabled" ] && [ ! -f "$T/sites.d/f.test.toml" ] && echo yes || echo no) $(body f.test 18301)"
rm -f "$T/sites.d/f-hand.toml" "$T/sites.d/f.test.toml.disabled"; reload

# A new file with an error of its own claiming a served name: set aside, the served site keeps it
# (its claim never outranks a site the server serves).
site a.test 18301 "$T/www/c" 'refsue = 1' > "$T/sites.d/0n.toml"; reload
check "a new broken file claiming a served name: set aside, the served site keeps the name" "site a2 yes" \
  "$(body a.test 18301) $(held 0n.toml | grep -q 'refsue' && echo yes)"
rm -f "$T/sites.d/0n.toml"; reload

# At start (the alpha.62 report, finding 1): a file set aside for its own error keeps a claim on its
# names, so a later file that conflicted with it does not take them over without its rules (its
# access rule here): the name answers 421 on that address until the broken file loads. Also when
# the broken file is not TOML at all: its names are read from its server_name and listen lines.
S2=$T/start; mkdir -p "$S2/sites.d" "$S2/logs"
cat > "$S2/agensio.toml" <<EOF
include = ["sites.d/*.toml"]
[server]
workers = 1
pid_file = "$S2/agensio.pid"
[log]
access = "off"
error = "$S2/logs/error.log"
EOF
{ site a.test 18311 "$T/www/a" 'refsue = 1'; printf '[[site.access]]\npath = "/"\nallow = ["127.0.0.1"]\n'; } > "$S2/sites.d/a.toml"
site a.test 18311 "$T/www/c" > "$S2/sites.d/z-dup.toml"
site o.test 18311 "$T/www/b" > "$S2/sites.d/o.toml"
"$BIN" -t -c "$S2/agensio.toml" > "$S2/t.out" 2>&1
"$BIN" -c "$S2/agensio.toml" > "$S2/server.out" 2>&1 & S2PID=$!
for _ in $(seq 1 50); do nc -z 127.0.0.1 18311 2>/dev/null && break; sleep 0.1; done
check "at start, a duplicate of a broken file's name is set aside with it: the name answers 421, the other site serves, -t says why" "421 site b yes" \
  "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 -H 'Host: a.test' http://127.0.0.1:18311/) $(body o.test 18311) $(grep -q 'z-dup.toml set aside.*a.test on 127.0.0.1:18311 is claimed by a.toml, which is set aside' "$S2/t.out" && echo yes)"
kill $S2PID; wait $S2PID 2>/dev/null
{ site a.test 18311 "$T/www/a"; printf '[[site.access]\npath = "/"\n'; } > "$S2/sites.d/a.toml"   # not TOML: a broken header
"$BIN" -t -c "$S2/agensio.toml" > "$S2/t2.out" 2>&1
check "a broken file that is not TOML keeps its names too, read from its lines" "yes" \
  "$(grep -q 'z-dup.toml set aside.*a.test on 127.0.0.1:18311 is claimed by a.toml, which is set aside' "$S2/t2.out" && echo yes)"

# The hosting rules (design section 26, step C2) for a site with an account (the one running this
# test): a site whose root others can write into is set aside and the others serve; a site is served
# only by a version that passes every rule now, so a served one whose root is opened to others goes
# down at the next reload, while an edit pointing it at such a root keeps the version that passes.
ME=$(id -un 2>/dev/null || true)
if [ -n "$ME" ]; then
  mkdir -p "$T/www/h" "$T/www/h2"; echo "site h" > "$T/www/h/index.html"; echo "site h2" > "$T/www/h2/index.html"
  chmod 757 "$T/www/h"
  site h.test 18305 "$T/www/h" "user = \"$ME\"" > "$T/sites.d/h.toml"
  reload
  check "a site whose root others can write into is set aside, the other sites serve; health names the rule" "none site a2 yes" \
    "$(body h.test 18305) $(body a.test 18301) $(held h.toml | grep -q 'writable by other users' && echo yes)"
  check "health reports it as hosting_rule (an owner or a mode to fix); validate marks it, which the writers count as refused" "hosting_rule True" \
    "$(health | python3 -c 'import json,sys; print(" ".join(f["code"] for f in json.load(sys.stdin)["findings"] if f["code"] in ("site_file_held_back", "hosting_rule") and "h.toml" in f["message"]) or "none")') $("$BIN" ctl validate --socket "$CS" 2>/dev/null | python3 -c 'import json,sys; print([h.get("hosting_rule") for h in json.load(sys.stdin).get("held_back", []) if h["file"].endswith("h.toml")])' | tr -d "[]'")"
  chmod 755 "$T/www/h"; reload
  check "the root fixed and reloaded: it serves, health is clear of it" "site h none" "$(body h.test 18305) $(held h.toml)"
  chmod 757 "$T/www/h"; reload
  check "its root opened to others while it serves: the next reload takes it down, the version running breaks the rule too" "none yes" \
    "$(body h.test 18305) $(held h.toml | grep -q 'not served' && echo yes)"
  chmod 755 "$T/www/h"; reload
  chmod 757 "$T/www/h2"; site h.test 18305 "$T/www/h2" "user = \"$ME\"" > "$T/sites.d/h.toml"; reload
  check "an edit pointing it at a root others can write into: the version that passes keeps serving" "site h yes" \
    "$(body h.test 18305) $(held h.toml | grep -q 'keeps serving' && echo yes)"
  rm -f "$T/sites.d/h.toml"; reload
else
  echo "skip the hosting rules: no account name for uid $(id -u)"
fi

# Certificates (design section 26, step C3): a site whose certificate or key cannot be loaded is set
# aside with its file and the others serve; a served site whose files can no longer be loaded (a key
# the server cannot read, as a root-only key after the privilege drop; a broken renewal) keeps the
# certificate it loaded before, while another site's change applies in the same reload.
CT=$T/certs; mkdir -p "$CT/t" "$CT/bad" "$T/www/t"; echo "site t" > "$T/www/t/index.html"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$CT/t/key.pem" -out "$CT/t/cert.pem" \
  -subj /CN=t.test -addext subjectAltName=DNS:t.test -days 2 > /dev/null 2>&1
cp "$CT/t/cert.pem" "$CT/bad/cert.pem"; echo "not a key" > "$CT/bad/key.pem"
tls_site() { site t.test "$2" "$T/www/t" "tls = { cert = \"$1/cert.pem\", key = \"$1/key.pem\" }"; }
tbody() { curl -sk --max-time 3 --resolve "t.test:$1:127.0.0.1" "https://t.test:$1/" 2>/dev/null || echo "none"; }
S3=$T/start-tls; mkdir -p "$S3/sites.d" "$S3/logs"
printf 'include = ["sites.d/*.toml"]\n[server]\nworkers = 1\npid_file = "%s/agensio.pid"\n[log]\naccess = "off"\nerror = "%s/logs/error.log"\n' "$S3" "$S3" > "$S3/agensio.toml"
tls_site "$CT/bad" 18313 > "$S3/sites.d/t.toml"
site o.test 18314 "$T/www/b" > "$S3/sites.d/o.toml"
"$BIN" -c "$S3/agensio.toml" > "$S3/server.out" 2>&1 & S3PID=$!
for _ in $(seq 1 50); do nc -z 127.0.0.1 18314 2>/dev/null && break; sleep 0.1; done
check "at start, a site whose key cannot be loaded is set aside, the other site serves, the error log says why" "site b none yes" \
  "$(body o.test 18314) $(tbody 18313) $(grep -q 't.toml set aside.*could not be loaded' "$S3/logs/error.log" && echo yes)"
kill $S3PID 2>/dev/null; wait $S3PID 2>/dev/null
tls_site "$CT/t" 18306 > "$T/sites.d/t.toml"; reload
check "a TLS site with its own certificate serves" "site t" "$(tbody 18306)"
chmod 000 "$CT/t/key.pem"; site a.test 18301 "$T/www/a" > "$T/sites.d/a.toml"; reload
check "its key made unreadable, then a reload with another site's change: it keeps the certificate loaded before, the change applies, health says so" "site t site a yes" \
  "$(tbody 18306) $(body a.test 18301) $(held sites.d/t.toml | grep -q 'could not be loaded' && held sites.d/t.toml | grep -q 'keeps serving' && echo yes)"
chmod 600 "$CT/t/key.pem"
tls_site "$CT/bad" 18306 > "$T/sites.d/t.toml"; site a.test 18301 "$T/www/c" > "$T/sites.d/a.toml"; reload
check "an edit pointing it at a key that cannot be loaded: its running version keeps serving, another site's change applies" "site t site c" \
  "$(tbody 18306) $(body a.test 18301)"
rm -f "$T/sites.d/t.toml"; site a.test 18301 "$T/www/a2" > "$T/sites.d/a.toml"; reload

# A broken main file still refuses the reload, as before: the main file is all or nothing.
cp "$T/agensio.toml" "$T/agensio.toml.good"
printf 'workres = 2\n' >> "$T/agensio.toml"
reload
check "a broken main file refuses the reload; every site keeps serving" "site a2 site b" "$(body a.test 18301) $(body b.test 18302)"
mv "$T/agensio.toml.good" "$T/agensio.toml"

echo "isolation: $pass passed, $fail failed"
[ $fail -eq 0 ]
