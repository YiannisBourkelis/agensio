#!/usr/bin/env python3
"""Approves what waits on an agensio control socket with the code an authenticator app would show,
for the test suites (docs/approvals.md): python3 tests/approve-code.py SOCKET APPROVER_FILE [ID ...]

The code is computed from the approver's secret (RFC 6238: HMAC-SHA1, 6 digits, 30 s) for a time
step the server has not taken yet: the step after the one in NAME.step when that is still within the
server's window, else the next step, waiting for it. Prints the server's answer; exit 1 unless every
change approved ran with a 2xx answer.
"""
import base64, hashlib, hmac, json, os, struct, subprocess, sys, time


def code_at(secret, step):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000)


def main():
    sock, approver = sys.argv[1], sys.argv[2]
    ids = sys.argv[3:]
    if not ids:  # every change waiting now, named, as agensio ctl approve names what it showed
        listed = subprocess.run(["curl", "-sS", "--unix-socket", sock, "http://control/v1/approvals"], capture_output=True, text=True).stdout
        ids = [a["id"] for a in json.loads(listed)["approvals"] if a["state"] == "waiting"]
    secret = [l.split("=", 1)[1].strip() for l in open(approver) if l.startswith("secret")][0]
    step_file = approver[: -len(".totp")] + ".step"
    last = -1
    if os.path.exists(step_file):
        last = int(open(step_file).read().strip() or -1)
    now = int(time.time() // 30)
    step = max(now - 1, last + 1)
    while step > now + 1:  # every step the server would take is used: wait for the next one
        time.sleep(1)
        now = int(time.time() // 30)
    body = {"code": code_at(secret, step), "ids": ids}
    out = subprocess.run(["curl", "-sS", "--unix-socket", sock, "-X", "POST", "-H", "Content-Type: application/json",
                          "-d", json.dumps(body), "http://control/v1/approvals"], capture_output=True, text=True).stdout
    print(out.strip())
    try:
        d = json.loads(out)
    except ValueError:
        return 1
    return 0 if d.get("ok") and all(200 <= r.get("status", 0) < 300 for r in d.get("results", [])) else 1


if __name__ == "__main__":
    sys.exit(main())
