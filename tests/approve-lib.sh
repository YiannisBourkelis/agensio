# Sourced by the suites: a control-plane command that waits for a person's approval (docs/approvals.md)
# is approved here with the code an authenticator app would show (tests/approve-code.py, a fresh
# approver each time), and the change's own answer is handed back as if the command had run at once.
#   source "$(dirname "$0")/approve-lib.sh"; gated_setup "$BIN" "$CONFIG" "$SOCKET"
#   ctl() { gated "$BIN" ctl "$@" --socket "$CS"; }      # prints the result; exit 1 when it failed
#   cpost PATH BODY                                        # prints the final status, the body in $GATED_REPLY
gated_setup() { GATED_BIN=$1; GATED_CONFIG=$2; GATED_SOCKET=$3; GATED_LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); GATED_REPLY=${GATED_REPLY:-/tmp/gated-reply.$$.json}; }

# The inner result of an approval's answer: prints it, exit 0 when its status is 2xx.
gated_result() {
    python3 - "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
r = (d.get("results") or [{}])[0]
print(json.dumps(r.get("result", d), separators=(",", ":")))  # the server's compact form, which the suites' greps expect
sys.exit(0 if 200 <= r.get("status", 0) < 300 else 1)
PY
}

gated() {
    local out rc id tmp
    out=$("$@"); rc=$?
    id=$(printf '%s' "$out" | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
    print(d["id"] if d.get("pending") else "")
except Exception:
    print("")' 2>/dev/null)
    if [ -z "$id" ]; then [ -n "$out" ] && printf '%s\n' "$out"; return $rc; fi  # nothing printed for nothing, as the command
    tmp=$(mktemp)
    python3 "$GATED_LIB_DIR/approve-code.py" "$GATED_SOCKET" "$GATED_CONFIG" "$GATED_BIN" "$id" > "$tmp"
    gated_result "$tmp"; rc=$?
    rm -f "$tmp"
    return $rc
}

# POST PATH BODY on the socket as the suites do with curl: the final status printed, the final body
# in $GATED_REPLY (an approved change's own answer, or the refusal as it came).
cpost() {
    local code id tmp
    code=$(curl -sS -o "$GATED_REPLY" -w '%{http_code}' --unix-socket "$GATED_SOCKET" -X POST -H 'Content-Type: application/json' -d "$2" "http://control$1")
    [ "$code" = 202 ] || { printf '%s' "$code"; return 0; }
    id=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["id"] if d.get("pending") else "")' "$GATED_REPLY" 2>/dev/null)
    [ -n "$id" ] || { printf '%s' "$code"; return 0; }
    tmp=$(mktemp)
    python3 "$GATED_LIB_DIR/approve-code.py" "$GATED_SOCKET" "$GATED_CONFIG" "$GATED_BIN" "$id" > "$tmp"
    python3 - "$tmp" "$GATED_REPLY" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
r = (d.get("results") or [{}])[0]
json.dump(r.get("result", d), open(sys.argv[2], "w"), separators=(",", ":"))
print(r.get("status", 500), end="")
PY
    rm -f "$tmp"
}
