#!/usr/bin/env python3
"""The site's files through the control plane (F12, docs/design-site-operations.md 3 and 27.6), as a
server without the root helper runs them: its own account, its own approver and history.

Run inside the devbox: python3 tests/site-files.py BINARY
One single-worker server with [control] sites_root, a static site and a PHP site; every change waits
for approval and is approved with the code an authenticator app would show (tests/approve-code.py).
Exit 1 on any failed row.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, binary, root):
        self.binary, self.root = binary, root
        self.www = root / "www"
        self.a = self.www / "a.test" / "web"
        self.p = self.www / "p.test" / "web"
        for d in (self.a / "css", self.p, root / "sites.d", root / "state", root / "outside"):
            d.mkdir(parents=True, exist_ok=True)
        (self.a / "index.html").write_text("<html><head><title>A</title></head>\n<body>hello</body></html>\n")
        (self.a / "css" / "site.css").write_text("body { color: #333 }\n")
        (self.a / ".env").write_text("API_TOKEN=t0ps3cret\n")
        (self.p / "index.php").write_text("<?php echo 'p';\n")
        (root / "outside" / "x").write_text("outside")
        os.symlink(root / "outside", self.a / "out")
        for f in self.a.rglob("*"):
            if f.is_file() and not f.is_symlink():
                os.utime(f, (time.time() - 10, time.time() - 10))
        self.port = free_port()
        self.sock = str(root / "c.sock")
        (root / "agensio.toml").write_text(
            f'include = ["sites.d/*.toml"]\n[server]\nworkers = 1\npid_file = "{root}/agensio.pid"\nstate_dir = "{root}/state"\n'
            f'[log]\naccess = "off"\nerror = "{root}/error.log"\nlevel = "info"\n'
            f'[control]\nsocket = "{self.sock}"\naudit = "{root}/audit.log"\nsites_root = "{self.www}"\nfile_history = {{ versions = 3, days = 30 }}\n'
            f'[[site]]\nserver_name = ["a.test"]\nlisten = ["127.0.0.1:{self.port}"]\nroot = "{self.a}"\n'
            f'[[site]]\nserver_name = ["p.test"]\nlisten = ["127.0.0.1:{self.port}"]\napp = "php"\nroot = "{self.p}"\n'
            f'php = {{ socket = "unix:{root}/fpm.sock" }}\n')
        self.log = (root / "server.out").open("w")
        self.proc = subprocess.Popen([binary, "-c", str(root / "agensio.toml")], stdout=self.log, stderr=subprocess.STDOUT)
        end = time.monotonic() + 10
        while not os.path.exists(self.sock):
            assert self.proc.poll() is None and time.monotonic() < end, "the server did not come up: " + (root / "server.out").read_text()[-2000:]
            time.sleep(0.05)
        subprocess.run([binary, "approver-add", "tester", "-c", str(root / "agensio.toml")], check=True, capture_output=True)
        self.approver = str(root / "approvers" / "tester.totp")

    def api(self, method, path, body=None):
        args = ["curl", "-sS", "-o", "/dev/stdout", "-w", "\n%{http_code}", "--unix-socket", self.sock, "-X", method, "http://control" + path]
        if body is not None:
            args += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
        out = subprocess.run(args, capture_output=True, text=True).stdout.rsplit("\n", 1)
        return int(out[1]), (json.loads(out[0]) if out[0].strip() else {})

    def approve(self, *ids):
        out = subprocess.run([sys.executable, str(HERE / "approve-code.py"), self.sock, self.approver, *ids], capture_output=True, text=True).stdout
        return json.loads(out) if out.strip() else {}

    def page(self, host, path):
        return subprocess.run(["curl", "-sS", "-H", "Host: " + host, f"http://127.0.0.1:{self.port}{path}"], capture_output=True, text=True).stdout

    def mcp(self, calls):
        p = subprocess.Popen([self.binary, "mcp", "--socket", self.sock], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                                                              "clientInfo": {"name": "files-test", "version": "1"}}}) + "\n")
        p.stdin.flush()
        p.stdout.readline()
        out = []
        for i, (name, args) in enumerate(calls):
            p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 10 + i, "method": "tools/call", "params": {"name": name, "arguments": args}}) + "\n")
            p.stdin.flush()
            out.append(json.loads(p.stdout.readline()))
        p.stdin.close()
        p.wait()
        return out

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        out = (self.root / "server.out").read_text()
        assert "Sanitizer" not in out and "runtime error:" not in out, "sanitizer report:\n" + out[-4000:]


def rows(srv):
    r = {}
    st, ls = srv.api("GET", "/v1/sites/a.test/files?path=")
    names = {e["name"]: e for e in ls.get("entries", [])}
    r["list"] = bool(st == 200 and names.get(".env", {}).get("credentials") and names.get("out", {}).get("type") == "symlink" and "target" in names.get("out", {}))
    st, rd = srv.api("GET", "/v1/sites/a.test/files?path=index.html&read=1")
    r["read"] = st == 200 and rd.get("content", "").startswith("<html>") and rd.get("untrusted") is True and len(rd.get("sha256", "")) == 64
    r["read-through-symlink"] = srv.api("GET", "/v1/sites/a.test/files?path=out/x&read=1")[0] == 409
    r["escape"] = srv.api("POST", "/v1/sites/a.test/file", {"op": "write", "path": "../b.test/x", "content": "x", "confirm": True})[0] == 400
    # A write through MCP waits, previewed with its diff and what the site does with the path; nothing
    # changes until the code; then the site serves it, and the history keeps the page it replaced.
    new = "<html><head><title>A</title><meta name=\"description\" content=\"A site\"></head>\n<body>hello</body></html>\n"
    res = srv.mcp([("site_file_write", {"name": "a.test", "path": "index.html", "content": new, "overwrite": True, "confirm": True, "reason": "meta description"}),
                   ("site_file_write", {"name": "a.test", "path": "index.html", "content": new, "overwrite": True, "dry_run": True, "confirm": True})])
    sc = res[0]["result"].get("structuredContent", {})
    wid = sc.get("id", "")
    r["write-waits"] = bool(not res[0]["result"]["isError"] and sc.get("pending") and '+<html><head><title>A</title><meta name="description"' in sc.get("preview", "")
                            and "what the site does with it: 200: the file" in sc.get("preview", "") and "<meta" not in srv.page("a.test", "/"))
    dry = res[1]["result"].get("structuredContent", {})
    r["dry-run-waits-not"] = bool(dry.get("dry_run") is True and dry.get("needs_approval") and not dry.get("pending"))
    ok = srv.approve(wid)
    served = ""
    for _ in range(30):  # the cache revalidates a served file at most once a second
        served = srv.page("a.test", "/")
        if "<meta name=\"description\"" in served:
            break
        time.sleep(0.1)
    r["write-approved"] = ok.get("results", [{}])[0].get("state") == "done" and "<meta name=\"description\"" in served
    _, hist = srv.api("GET", "/v1/sites/a.test/history?path=index.html")
    r["history"] = len(hist.get("versions", [])) == 1 and hist["versions"][0].get("reason") == "replaced by a write"
    # The file changed after the person saw the change: the approved write is refused, nothing lost.
    _, q = srv.api("POST", "/v1/sites/a.test/file", {"op": "write", "path": "css/site.css", "content": "body { color: red }\n", "overwrite": True, "confirm": True, "reason": "c"})
    (srv.a / "css" / "site.css").write_text("body { color: blue }\n")
    ok = srv.approve(q.get("id", ""))
    res0 = ok.get("results", [{}])[0]
    r["stale-refused"] = res0.get("state") == "failed" and "changed since it was read" in json.dumps(res0.get("result", {})) and "blue" in (srv.a / "css" / "site.css").read_text()
    # A new file at a path PHP runs: the person is told before typing the code; rejected, nothing is written.
    st, php = srv.api("POST", "/v1/sites/p.test/file", {"op": "write", "path": "extra.php", "content": "<?php echo 'extra';\n", "confirm": True, "reason": "a page"})
    r["runs-shown"] = st == 202 and any("RUNS" in w for w in php.get("needs_approval", [])) and "RUNS:" in php.get("preview", "")
    srv.api("POST", "/v1/approvals/" + php.get("id", "x") + "/reject", {})
    r["rejected-nothing-written"] = not (srv.p / "extra.php").exists()
    # A write through a planted symlink is refused before anything waits.
    st, sym = srv.api("POST", "/v1/sites/a.test/file", {"op": "write", "path": "out/new", "content": "x", "confirm": True})
    r["symlink-refused"] = st == 409 and "symlink" in sym.get("error", "") and not (srv.root / "outside" / "new").exists()
    # A secret's read waits; neither the list nor the approval's answer carries its content; GET /v1/approvals/ID once.
    st, sec = srv.api("GET", "/v1/sites/a.test/files?path=.env&read=1")
    sid = sec.get("id", "")
    r["secret-waits"] = bool(st == 202 and sec.get("pending") and "t0ps3cret" not in json.dumps(sec))
    ok = srv.approve(sid)
    _, lst = srv.api("GET", "/v1/approvals")
    _, one = srv.api("GET", "/v1/approvals/" + sid)
    _, two = srv.api("GET", "/v1/approvals/" + sid)
    r["secret-once"] = ("t0ps3cret" not in json.dumps(ok) and "t0ps3cret" not in json.dumps(lst) and one.get("result", {}).get("content") == "API_TOKEN=t0ps3cret\n"
                        and "t0ps3cret" not in json.dumps(two))
    # A directory deleted into the history whole, and put back.
    (srv.a / "old").mkdir()
    (srv.a / "old" / "a.txt").write_text("a")
    _, d = srv.api("POST", "/v1/sites/a.test/file", {"op": "delete", "path": "old", "recursive": True, "confirm": True, "reason": "d"})
    srv.approve(d.get("id", ""))
    _, hd = srv.api("GET", "/v1/sites/a.test/history?path=old")
    versions = hd.get("versions", [])
    r["deleted-kept"] = not (srv.a / "old").exists() and len(versions) == 1 and versions[0].get("kind") == "directory"
    _, rs = srv.api("POST", "/v1/sites/a.test/file", {"op": "restore", "path": "old", "version": versions[0]["version"] if versions else "", "confirm": True, "reason": "back"})
    srv.approve(rs.get("id", ""))
    r["restored"] = (srv.a / "old" / "a.txt").read_text() == "a" if (srv.a / "old" / "a.txt").exists() else False
    # mkdir and move through ctl, each waiting and approved; the history dir is the holder's alone.
    subprocess.run([srv.binary, "ctl", "site-dir-create", "a.test", "img", "--yes", "--reason", "m", "--socket", srv.sock], capture_output=True, stdin=subprocess.DEVNULL)
    srv.approve()
    subprocess.run([srv.binary, "ctl", "site-path-move", "a.test", "css/site.css", "img/site.css", "--yes", "--reason", "m", "--socket", srv.sock], capture_output=True, stdin=subprocess.DEVNULL)
    srv.approve()
    r["ctl-mkdir-move"] = (srv.a / "img" / "site.css").exists() and not (srv.a / "css" / "site.css").exists()
    r["history-private"] = oct((srv.www / ".history").stat().st_mode & 0o777) == "0o700"
    # MCP: the reads are read-only, the delete destructive; the audit log has the changes with their sha256.
    p = subprocess.Popen([srv.binary, "mcp", "--socket", srv.sock], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}}}) + "\n")
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) + "\n")
    p.stdin.flush()
    p.stdout.readline()
    tools = {t["name"]: t for t in json.loads(p.stdout.readline())["result"]["tools"]}
    p.stdin.close()
    p.wait()
    r["annotations"] = (tools["site_file_read"]["annotations"]["readOnlyHint"] and tools["site_files_list"]["annotations"]["readOnlyHint"]
                        and not tools["site_file_write"]["annotations"]["readOnlyHint"] and tools["site_path_delete"]["annotations"]["destructiveHint"])
    audit = (srv.root / "audit.log").read_text()
    r["audit"] = "write " + str(srv.a / "index.html") + " (sha256 " in audit and "waits for approval" in audit and "read " + str(srv.a / ".env") + " (a credential file" in audit
    return r


def main():
    binary = os.path.abspath(sys.argv[1])
    with tempfile.TemporaryDirectory(prefix="agensio-files-", dir="/tmp") as d:
        srv = Server(binary, Path(d))
        try:
            results = rows(srv)
        finally:
            srv.stop()
    failed = [k for k, v in results.items() if not v]
    for k, v in results.items():
        print(("ok   " if v else "FAIL ") + k, flush=True)
    print("site files: %d passed, %d failed" % (len(results) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
