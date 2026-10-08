#!/usr/bin/env bash
# Passwords ([[site.auth]], 2026-10-08, docs/configuration.md 19b, design section 25), end to end
# against a one-worker server, so the verification counter in `status` is exact:
#   - one slow hash per login, none per request after it (the cache), every failure verified
#     again (never cached), an unknown user verified too (no timing tells who exists);
#   - the challenge (realm, charset, no-store), one answer for a wrong password and an unknown
#     user, expiry, open paths below a protected one, skip_for, the bypass spellings;
#   - no password asked over plain HTTP from another host (403), unless plain_http = "allow";
#     loopback and TLS asked as usual;
#   - Cache-Control: private on what a password protects, the verified user in the access log,
#     one `auth failed` line per failure and none for the challenge;
#   - a reload keeps the cache, a changed password refuses the old one at once;
#   - a request on the same worker answered while a slow verification runs;
#   - a managed site's users through the control socket and MCP, without the helper (step 4b).
# usage: tests/auth.sh build/agensio   (a build with authentication: libxcrypt and OpenSSL)
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
ROOT=$(pwd)
T=$ROOT/bench/tmp/auth; rm -rf "$T"; mkdir -p "$T/logs" "$T/sites.d" "$T/www/users.test"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
code() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }
if ! printf 'x\n' | "$BIN" passwd probe > /dev/null 2>&1; then echo "skip auth suite: this build has no authentication"; exit 0; fi
# Users: yescrypt (the default), a bcrypt one, an expired one, a slow one for the worker check.
{ printf 'secret\n' | "$BIN" passwd anna; echo ":note=Anna, Acme"; } | tr -d '\n' > "$T/users"; echo >> "$T/users"
printf 'p\xc3\xa4ssw\xc3\xb6rd\n' | "$BIN" passwd --method bcrypt --cost 4 jose >> "$T/users"
{ printf 'secret\n' | "$BIN" passwd old; echo ":expires=2020-01-01"; } | tr -d '\n' >> "$T/users"; echo >> "$T/users"
printf 'slow\n' | "$BIN" passwd --method bcrypt --cost 15 slow >> "$T/users"
chmod 640 "$T/users"
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
cat > "$T/agensio.toml" <<EOF
include = ["sites.d/*.toml"]
[server]
workers = 1
pid_file = "$T/agensio.pid"
[log]
access = "$T/logs/access.log"
error = "$T/logs/error.log"
[control]
socket = "$T/control.sock"
sites_root = "$T/www"
[[site]]
server_name = ["*"]
listen = ["0.0.0.0:18130"]
root = "$ROOT/tests/authsite"

[[site.auth]]
path = "/private"
users = "$T/users"
realm = "Private"

[[site.auth]]
path = "/private/health"
match = "exact"
open = true

[[site.auth]]
path = "/office"
users = "$T/users"
skip_for = ["127.0.0.1"]

[[site.auth]]
path = "/lan"
users = "$T/users"
plain_http = "allow"

[[site]]
server_name = ["*"]
listen = ["0.0.0.0:18131"]
root = "$ROOT/tests/authsite"
tls = { cert = "$ROOT/bench/certs/cert.pem", key = "$ROOT/bench/certs/key.pem" }

[[site.auth]]
path = "/private"
users = "$T/users"
realm = "Private"
EOF
"$BIN" -c "$T/agensio.toml" > "$T/server.out" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null' EXIT
for _ in $(seq 1 50); do nc -z 127.0.0.1 18130 2>/dev/null && break; sleep 0.1; done
B=http://127.0.0.1:18130
verifications() { curl -sS --unix-socket "$T/control.sock" http://control/v1/status | python3 -c 'import json,sys; print(json.load(sys.stdin).get("auth_verifications", "none"))'; }

# The challenge.
curl -sS -D "$T/h401" -o "$T/b401" $B/private/doc.html
check "no credentials: 401 with a Basic challenge naming the realm, charset UTF-8, not stored" "401|Basic realm=\"Private\", charset=\"UTF-8\"|no-store" \
  "$(head -1 "$T/h401" | cut -d' ' -f2)|$(grep -i '^www-authenticate:' "$T/h401" | tr -d '\r' | cut -d' ' -f2-)|$(grep -i '^cache-control:' "$T/h401" | tr -d '\r' | cut -d' ' -f2)"
check "the right password: 200 and the page; a wrong one and an unknown user: 401, the same page" "200 private doc|401 401 same" \
  "$(curl -sS -u anna:secret -w '%{http_code}' -o "$T/ok" $B/private/doc.html) $(cat "$T/ok")|$(code -u anna:wrong $B/private/doc.html) $(code -u nobody:secret $B/private/doc.html) $(cmp -s <(curl -sS -u anna:wrong $B/private/doc.html) <(curl -sS -u nobody:secret $B/private/doc.html) && echo same || echo differ)"

# The slow hash once per login, never per request.
n0=$(verifications)   # jose has not logged in yet: his first request is the one verification
urls=""; for i in $(seq 1 50); do urls="$urls $B/private/doc.html"; done
ok_keepalive=$(curl -sS -u 'jose:pässwörd' -o /dev/null -w '%{http_code}\n' $urls | grep -c '^200$')
ok_fresh=0; for i in 1 2 3 4 5; do [ "$(code -u 'jose:pässwörd' $B/private/)" = 200 ] && ok_fresh=$((ok_fresh+1)); done
n1=$(verifications)
check "one login then 50 requests on one connection and 5 new connections: all 200, one verification (the cache, not a hash per request)" "50 5 1" "$ok_keepalive $ok_fresh $((n1 - n0))"
for i in 1 2 3 4 5; do code -u anna:wrong$i $B/private/doc.html > /dev/null; done
n2=$(verifications)
check "five wrong passwords: five verifications (a failure is never remembered)" "5" "$((n2 - n1))"
code -u someone:secret $B/private/doc.html > /dev/null
n3=$(verifications)
check "an unknown user is verified too, against a real entry (timing does not tell who exists)" "1" "$((n3 - n2))"

# The rules.
check "expired, locked out even with the right password; a UTF-8 password works" "401 200" "$(code -u old:secret $B/private/doc.html) $(code -u 'jose:pässwörd' $B/private/doc.html)"
check "open below a protected path; skip_for lets 127.0.0.1 in without a password; the public part needs none" "200 200 200" "$(code $B/private/health) $(code $B/office/) $(code $B/)"
check "every spelling of a protected path asks: case, no slash, its index, dot segments, an encoded name" "401 401 401 401 401" \
  "$(code $B/PRIVATE/doc.html) $(code $B/private) $(code $B/private/) $(code --path-as-is $B/office/../private/doc.html) $(code $B/%70rivate/doc.html)"

# Plain HTTP from another host: never asked; from loopback and over TLS: asked.
if [ -n "$IP" ]; then
  curl -sS -D "$T/hplain" -o "$T/bplain" "http://$IP:18130/private/doc.html"
  check "plain HTTP from another host: 403 with no challenge and a page saying to use HTTPS; plain_http = \"allow\" asks anyway" "403 no-challenge yes 401" \
    "$(head -1 "$T/hplain" | cut -d' ' -f2) $(grep -qi '^www-authenticate:' "$T/hplain" && echo challenge || echo no-challenge) $(grep -qi 'https' "$T/bplain" && echo yes) $(code "http://$IP:18130/lan/")"
  check "over TLS from another host: asked, and the right password served" "401 200" "$(code -k --resolve localhost:18131:$IP https://localhost:18131/private/doc.html) $(code -k --resolve localhost:18131:$IP -u anna:secret https://localhost:18131/private/doc.html)"
else
  echo "skip plain-HTTP checks: no address but loopback"
fi

# What caches and logs see.
check "a protected answer is Cache-Control: private; a public one carries none" "private|" \
  "$(curl -sS -u anna:secret -D - -o /dev/null $B/private/doc.html | tr -d '\r' | grep -i '^cache-control:' | cut -d' ' -f2)|$(curl -sS -D - -o /dev/null $B/ | tr -d '\r' | grep -i '^cache-control:' | cut -d' ' -f2)"
sleep 1.2
check "the access log names the verified user, never the one a refused request claimed" "anna -" \
  "$(grep '/private/doc.html' "$T/logs/access.log" | grep '" 200 ' | tail -1 | cut -d' ' -f3) $(grep '/private/doc.html' "$T/logs/access.log" | grep '" 401 ' | tail -1 | cut -d' ' -f3)"
check "one auth failed line per failure, with the user, the client and the reason; none for the challenge; never the password" "yes yes 0" \
  "$(grep -q 'auth failed: client 127.0.0.1 site .* realm "Private" user "anna" (wrong password)' "$T/logs/error.log" && echo yes) $(grep -q 'auth failed: .*user "old" .*expired' "$T/logs/error.log" && echo yes) $(grep -c 'secret\|wrong1' "$T/logs/error.log")"

# A slow verification runs off the worker's loop.
( curl -sS -o /dev/null -u slow:slow $B/private/doc.html & )
sleep 0.2
t0=$(date +%s%N); r=$(code $B/); t1=$(date +%s%N)
check "while a slow verification runs, the same worker answers another request at once" "200 fast" "$r $( [ $(( (t1 - t0) / 1000000 )) -lt 150 ] && echo fast || echo slow)"
sleep 2

# A reload keeps what was verified; a changed password refuses the old one at once.
code -u anna:secret $B/private/doc.html > /dev/null
n4=$(verifications)
kill -HUP $SRV; sleep 0.5
check "after a reload the remembered login needs no new verification" "200 0" "$(code -u anna:secret $B/private/doc.html) $(( $(verifications) - n4 ))"
{ printf 'changed\n' | "$BIN" passwd anna; } > "$T/users.new"; grep -v '^anna:' "$T/users" >> "$T/users.new"; chmod 640 "$T/users.new"; mv "$T/users.new" "$T/users"
kill -HUP $SRV; sleep 0.5
check "a changed password: the old one refused at once, the new one served" "401 200" "$(code -u anna:secret $B/private/doc.html) $(code -u anna:changed $B/private/doc.html)"

# A managed site's users through the control socket (2026-10-09, design section 25, step 4b),
# without the helper: the server's own account writes <config dir>/auth/<site>.users, 0640 in a
# 0750 directory; a generated password is answered once and logged nowhere; --prompt hashes on
# this side, so only a hash crosses the socket; the listing never shows a hash; MCP generates and
# never relays a hash or a password.
CS="$T/control.sock"
ctl() { "$BIN" ctl "$@" --socket "$CS"; }
jv() { python3 -c "import json; d=json.load(open('$T/out')); print($1)"; }
cpost() { curl -sS -o "$T/out" -w '%{http_code}' --unix-socket "$CS" -X POST -d "$2" "http://control$1"; }
ctl site-create --domain users.test --app static --no-user --https none --root "$T/www/users.test" --listen-plain 127.0.0.1:18132 --yes --reason auth > "$T/out"
check "a managed static site to hold the users" "True" "$(jv 'd.get("ok")')"
ctl site-auth-user-set users.test anna --generate --expires 2099-01-01 --note 'Anna, Acme' --yes --reason staging > "$T/out"; PW=$(jv 'd.get("password", "")')
check "--generate: created; the password answered once, four groups of four; the file this account's 0640 in a 0750 directory, one line with expiry and note" \
  "True created yes 640 750 yes" \
  "$(jv 'd.get("ok"), d.get("action")') $(echo "$PW" | grep -qE '^[a-km-np-z2-9]{4}(-[a-km-np-z2-9]{4}){3}$' && echo yes) $(stat -c %a "$T/auth/users.test.users") $(stat -c %a "$T/auth") $(grep -qE '^anna:\$y\$[^:]+:expires=2099-01-01:note=Anna, Acme$' "$T/auth/users.test.users" && echo yes)"
printf 'typed-pass\n' | ctl site-auth-user-set users.test bob --prompt --yes --reason staging > "$T/out"
check "--prompt: the password read and hashed here (yescrypt); the answer carries none" "True created None yes" \
  "$(jv 'd.get("ok"), d.get("action"), d.get("password")') $(grep -q '^bob:\$y\$' "$T/auth/users.test.users" && echo yes)"
ctl site-auth-users users.test > "$T/out"
check "site-auth-users: names, methods, expiry, notes, locks; never a hash" "anna,bob yescrypt,yescrypt 2099-01-01 Anna, Acme False no" \
  "$(jv '",".join(u["name"] for u in d["users"]), ",".join(u["method"] for u in d["users"]), d["users"][0]["expires"], d["users"][0]["note"], d["users"][1]["locked"]') $(grep -q '\$y\$' "$T/out" && echo yes || echo no)"
check "refused: a password as a field, a name with a colon, a weak hash, a hand-written site, an unknown site" "400 400 400 409 404" \
  "$(cpost /v1/sites/users.test/auth-users '{"confirm":true,"user":"eve","password":"x"}') $(cpost /v1/sites/users.test/auth-users '{"confirm":true,"user":"e:ve","generate":true}') $(cpost /v1/sites/users.test/auth-users '{"confirm":true,"user":"eve","hash":"$apr1$abc$def"}') $(cpost '/v1/sites/*/auth-users' '{"confirm":true,"user":"eve","generate":true}') $(cpost /v1/sites/none.test/auth-users '{"confirm":true,"user":"eve","generate":true}')"
# A rule that uses the file (a hand-written site here; rules.auth on managed sites is the next step):
# the generated password logs in, a change through the tool applies at once (the server reloads),
# and the last user of a file a rule uses is kept.
cat >> "$T/agensio.toml" <<EOF

[[site]]
server_name = ["*"]
listen = ["127.0.0.1:18133"]
root = "$ROOT/tests/authsite"

[[site.auth]]
path = "/private"
users = "$T/auth/users.test.users"
EOF
kill -HUP $SRV; sleep 0.5
U=http://127.0.0.1:18133
check "where a rule uses the file: the generated password and the typed one log in, a wrong one does not" "200 200 401" \
  "$(code -u "anna:$PW" $U/private/doc.html) $(code -u bob:typed-pass $U/private/doc.html) $(code -u anna:wrong $U/private/doc.html)"
ctl site-auth-user-set users.test bob --lock --yes --reason leave > "$T/out"
check "--lock applies at once, the answer saying the server reloaded; --unlock gives the same password back" "401 yes 200" \
  "$(code -u bob:typed-pass $U/private/doc.html) $(jv '"yes" if any("reloaded" in x for x in d.get("done", [])) else d') $(ctl site-auth-user-set users.test bob --unlock --yes --reason back > /dev/null; code -u bob:typed-pass $U/private/doc.html)"
ctl site-auth-user-set users.test anna --generate --yes --reason rotate > "$T/out"; PW2=$(jv 'd.get("password", "")')
check "a new generated password: changed, the old one refused at once, the new one served" "changed 401 200" \
  "$(jv 'd.get("action")') $(code -u "anna:$PW" $U/private/doc.html) $(code -u "anna:$PW2" $U/private/doc.html)"
ctl site-auth-user-delete users.test bob --yes --reason gone > "$T/out"
ctl site-auth-user-delete users.test anna --yes --reason gone > "$T/out.last"
check "deleting a user: refused at once; the last user of a file a rule uses stays (lock it, or remove the rule first)" "deleted 401 False yes 200" \
  "$(jv 'd.get("action")') $(code -u bob:typed-pass $U/private/doc.html) $(python3 -c "import json; d=json.load(open('$T/out.last')); print(d.get('ok'), 'yes' if 'the last user' in d.get('error', '') else d)") $(code -u "anna:$PW2" $U/private/doc.html)"
# MCP: the three tools (admin), a generated password answered, a hash from the agent dropped.
python3 - "$BIN" "$CS" > "$T/mcp.out" <<'PYT'
import json, subprocess, sys
p = subprocess.Popen([sys.argv[1], "mcp", "--socket", sys.argv[2]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def rpc(i, method, params=None):
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}) + "\n"); p.stdin.flush()
    return json.loads(p.stdout.readline())["result"]
tools = {t["name"]: t for t in rpc(1, "tools/list")["tools"]}
out = [str(tools["site_auth_users"]["annotations"]["readOnlyHint"]), str(tools["site_auth_user_delete"]["annotations"]["destructiveHint"]),
       "hash" if "hash" in tools["site_auth_user_set"]["inputSchema"]["properties"] else "nohash"]
r = rpc(2, "tools/call", {"name": "site_auth_user_set", "arguments": {"name": "users.test", "user": "carol", "generate": True, "confirm": True, "reason": "mcp"}})
pw = r["structuredContent"].get("password", "")
out.append("pw" if len(pw) == 19 else repr(r))
h = open(sys.argv[2].replace("control.sock", "auth/users.test.users")).read().split("anna:")[1].split(":")[0].split("\n")[0]
r = rpc(3, "tools/call", {"name": "site_auth_user_set", "arguments": {"name": "users.test", "user": "dave", "hash": h, "confirm": True, "reason": "mcp"}})
out.append("dropped" if r["isError"] and "a new user needs" in r["content"][-1]["text"] else repr(r))
r = rpc(4, "tools/call", {"name": "site_auth_users", "arguments": {"name": "users.test"}})
out.append(",".join(u["name"] for u in r["structuredContent"]["users"]))
p.stdin.close(); p.wait()
print(" ".join(out))
PYT
check "mcp: site_auth_users read-only, site_auth_user_delete destructive, no hash argument; a generated password answered; a hash the agent sends is dropped" \
  "True True nohash pw dropped anna,carol" "$(cat "$T/mcp.out")"
sleep 1.2
check "the audit log names each change by user and never holds a password or a hash; no other log does either" "yes 0" \
  "$(grep -q 'auth-users.*anna: created with a generated password' "$T/logs/audit.log" && echo yes) $(cat "$T/logs/"*.log | grep -c -F -e "${PW:-no password}" -e "${PW2:-no password}" -e 'typed-pass' -e '$y$')"

echo "auth: $pass passed, $fail failed"
[ $fail -eq 0 ]
