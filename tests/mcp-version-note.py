#!/usr/bin/env python3
# The MCP bridge facing a server of another version (a bridge left running across an upgrade): every
# tool answer carries the note, first in the structured answer, where a host that shows only
# structuredContent puts it before the answer's own members (0.1.0-alpha.149; the alpha.148 report:
# a bridge left on alpha.146 had its note at the bottom of every answer, unseen), and an argument the
# bridge refuses itself, never asking the server, says so too.
# Usage: tests/mcp-version-note.py BIN DIR. Prints "first <first key> note <yes|no> text <yes|no> refused <yes|no>".
import json, os, socket, subprocess, sys, threading

binary, workdir = sys.argv[1], sys.argv[2]
os.makedirs(workdir, exist_ok=True)
path = os.path.join(workdir, "fake-control.sock")
if os.path.exists(path):
    os.unlink(path)
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path)
srv.listen(8)


def serve():
    while True:
        try:
            c, _ = srv.accept()
        except OSError:
            return
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = c.recv(4096)
                if not chunk:
                    break
                data += chunk
            head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1").lower()
            length = 0
            for line in head.split("\r\n"):
                if line.startswith("content-length:"):
                    length = int(line.split(":", 1)[1])
            rest = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
            while len(rest) < length:
                chunk = c.recv(4096)
                if not chunk:
                    break
                rest += chunk
            body = json.dumps({"version": "0.0.1-other", "workers": 1, "sites": [{"server_name": ["a.test"]}] * 40,
                               "peer": {"uid": os.getuid(), "role": "admin"}}).encode()
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Agensio-Version: 0.0.1-other\r\nContent-Length: " +
                      str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        finally:
            c.close()


threading.Thread(target=serve, daemon=True).start()
p = subprocess.Popen([binary, "mcp", "--socket", path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)


def call(msg):
    p.stdin.write(json.dumps(msg) + "\n")
    p.stdin.flush()
    if "id" not in msg:
        return None
    return json.loads(p.stdout.readline())


call({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})
call({"jsonrpc": "2.0", "method": "notifications/initialized"})
r = call({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "server_status", "arguments": {}}})["result"]
# An argument this bridge's schema lacks, refused by the bridge itself: the note too.
u = call({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
          "params": {"name": "site_update", "arguments": {"name": "a.test", "stream_pathz": ["/x"], "confirm": True, "reason": "t"}}})["result"]
p.stdin.close()
p.wait(timeout=10)
srv.close()
sc = r.get("structuredContent", {})
first = next(iter(sc), "-")
note = sc.get("bridge", {}).get("note", "")
text = r["content"][0]["text"] if r.get("content") else ""
refused = " ".join(c["text"] for c in u.get("content", []))
print("first", first, "note", "yes" if "server runs 0.0.1-other" in note else "no",
      "text", "yes" if text.startswith("NOTE: this MCP bridge is agensio") else "no",
      "refused", "yes" if u.get("isError") and "server runs 0.0.1-other" in refused and "unknown argument 'stream_pathz'" in refused and "may be one the server's version added" in refused else "no")
