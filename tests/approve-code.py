#!/usr/bin/env python3
"""Approves what waits on an agensio control socket with the code an authenticator app would show,
for the test suites (docs/approvals.md): python3 tests/approve-code.py [--raw] SOCKET CONFIG BINARY [ID ...]

A fresh approver is enrolled for the approval (agensio approver-add, as the account the suite runs as:
root with the helper, else the server's own) and removed after it, so a suite never waits for the
next 30-second step and the server's rule that a code is accepted once per approver stays whole.
Without ids, every change waiting is approved. A result the server hands out once (a secret) is
fetched by id and put in its place, unless --raw (a test of that handout itself). Prints the server's answer; exit 1 unless every change approved
ran with a 2xx answer.
"""
import base64, hashlib, hmac, json, os, secrets, struct, subprocess, sys, time


def code_at(secret, step):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000)


def api(sock, method, path, body=None):
    args = ["curl", "-sS", "--unix-socket", sock, "-X", method, "http://control" + path]
    if body is not None:
        args += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    out = subprocess.run(args, capture_output=True, text=True).stdout
    try:
        return json.loads(out)
    except ValueError:
        return {"error": out}


def main():
    args = sys.argv[1:]
    raw = "--raw" in args  # the answer as the server gives it: a secret result stays with GET /v1/approvals/ID
    args = [a for a in args if a != "--raw"]
    sock, config, binary = args[0], args[1], args[2]
    ids = args[3:]
    if not ids:
        ids = [a["id"] for a in api(sock, "GET", "/v1/approvals").get("approvals", []) if a["state"] == "waiting"]
    name = "suite-" + secrets.token_hex(3)
    subprocess.run([binary, "approver-add", name, "-c", config], check=True, capture_output=True)
    approver = os.path.join(os.path.dirname(os.path.abspath(config)), "approvers", name + ".totp")
    try:
        secret = [l.split("=", 1)[1].strip() for l in open(approver) if l.startswith("secret")][0]
        d = api(sock, "POST", "/v1/approvals", {"code": code_at(secret, int(time.time() // 30)), "ids": ids})
    finally:
        subprocess.run([binary, "approver-remove", name, "-c", config], capture_output=True)
    for r in [] if raw else d.get("results", []):
        if "handed out once" in str(r.get("result", {}).get("note", "")):
            one = api(sock, "GET", "/v1/approvals/" + r["id"])
            if "result" in one:
                r["result"] = one["result"]
    print(json.dumps(d))
    return 0 if d.get("ok") and all(200 <= r.get("status", 0) < 300 for r in d.get("results", [])) else 1


if __name__ == "__main__":
    sys.exit(main())
