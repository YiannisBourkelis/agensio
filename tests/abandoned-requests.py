#!/usr/bin/env python3
"""Requests the client abandons, on HTTP/1.1, HTTP/2 and HTTP/3: one access-log line each.

The test VPS's report on 0.1.0-alpha.118: an abandoned request was logged "200 0" over HTTP/1.1
and HTTP/3 though no answer went out, not at all over HTTP/2 (a login attempt reset before its
answer was invisible to the jails), and an HTTP/3 download cut short was logged as the whole file.

Run inside the Linux devbox: python3 tests/abandoned-requests.py BINARY [--rows a,b]
One single-worker server for every row, a proxied location /slow to an origin in this script
that answers after 3 s and notes whether agensio closed its connection first, a 3-byte ok.txt
and a 20 MB big.bin. Each row tags its request with ?t=ROW and checks the line(s) with that tag:
exactly one, the status (499 when the client left before the head went out, 408 when its body
stopped arriving, 400 its body broken: answered over HTTP/1.1, a reset over HTTP/2, the answer's
status when the head went out) and bytes no more than the body.
Requires python3-h2 and aioquic (h3 rows), openssl. Exit 1 on any failed row.
"""
import argparse
import os
import re
import select
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import h2.config
import h2.connection
import h2.errors
import h2.events

BIG = 20 * 1000 * 1000
SLOW_S = 3.0
LEAVE_S = 0.6  # past one pool tick (250 ms), so HTTP/1's abort watch is armed (E9)

origin_seen = {}    # tag -> "answered" | "closed" (agensio closed the connection before the answer)
origin_lock = threading.Lock()


class Origin(socketserver.BaseRequestHandler):
    """HTTP/1.1 keep-alive origin: every request waits SLOW_S for the client to go away."""

    def handle(self):
        sock = self.request
        buf = b""
        while True:
            while b"\r\n\r\n" not in buf:
                data = sock.recv(65536)
                if not data:
                    return
                buf += data
            head, buf = buf.split(b"\r\n\r\n", 1)
            m = re.search(rb"(?im)^content-length:\s*(\d+)", head)
            need = int(m.group(1)) if m else 0
            while len(buf) < need:
                data = sock.recv(65536)
                if not data:
                    return
                buf += data
            buf = buf[need:]
            t = re.search(rb"[?&]t=([\w-]+)", head.split(b"\r\n", 1)[0])
            tag = t.group(1).decode() if t else "?"
            end = time.monotonic() + SLOW_S
            closed = False
            while time.monotonic() < end:
                r, _, _ = select.select([sock], [], [], max(0.0, end - time.monotonic()))
                if r:
                    try:
                        data = sock.recv(65536)
                    except OSError:
                        data = b""
                    if not data:
                        closed = True
                        break
                    buf += data
            with origin_lock:
                origin_seen[tag] = "closed" if closed else "answered"
            if closed:
                return
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Type: text/plain\r\n\r\nslow")


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def listening(port):
    with socket.socket() as s:
        s.settimeout(0.1)
        return s.connect_ex(("127.0.0.1", port)) == 0


# ---- clients ----

def tcp(port, alpn=None, rcvbuf=None):
    s = socket.socket()
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)  # before connect: the window scale
    s.settimeout(5)
    s.connect(("127.0.0.1", port))
    if alpn:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols([alpn])
        s = ctx.wrap_socket(s, server_hostname="localhost")
    return s


def h1_leave(port, method, tag, body=b"", declared=None):
    s = tcp(port)
    length = len(body) if declared is None else declared
    extra = f"Content-Length: {length}\r\n" if method == "POST" else ""
    s.sendall(f"{method} /slow?t={tag} HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n".encode() + body)
    return s


def h1_partial(port, tag):
    s = tcp(port, rcvbuf=4096)
    s.sendall(f"GET /big.bin?t={tag} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
    got = 0
    while got < 200 * 1024:
        data = s.recv(65536)
        if not data:
            break
        got += len(data)
    s.close()
    return got


class H2:
    """h2c with prior knowledge over a plain socket."""

    def __init__(self, port):
        self.sock = tcp(port)
        self.conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
        self.conn.initiate_connection()
        self.flush()

    def flush(self):
        data = self.conn.data_to_send()
        if data:
            self.sock.sendall(data)

    def request(self, method, path, body=None, end=True):
        sid = self.conn.get_next_available_stream_id()
        headers = [(":method", method), (":scheme", "http"), (":authority", "localhost"), (":path", path)]
        if body is not None:
            headers.append(("content-length", str(len(body) if end else 1000)))
        self.conn.send_headers(sid, headers, end_stream=body is None)
        if body is not None:
            self.conn.send_data(sid, body, end_stream=end)
        self.flush()
        return sid

    def pump(self, seconds, until=None):
        end = time.monotonic() + seconds
        events = []
        while time.monotonic() < end:
            r, _, _ = select.select([self.sock], [], [], max(0.0, end - time.monotonic()))
            if not r:
                continue
            data = self.sock.recv(65536)
            if not data:
                break
            for ev in self.conn.receive_data(data):
                events.append(ev)
            self.flush()
            if until and until(events):
                break
        return events

    def answer(self, sid, seconds=3):
        status, body = None, b""
        for ev in self.pump(seconds, lambda evs: any(isinstance(e, h2.events.StreamEnded) and e.stream_id == sid for e in evs)):
            if isinstance(ev, h2.events.ResponseReceived) and ev.stream_id == sid:
                status = int(dict(ev.headers)[":status"])
            if isinstance(ev, h2.events.DataReceived) and ev.stream_id == sid:
                body += ev.data
                self.conn.acknowledge_received_data(ev.flow_controlled_length, sid)
        self.flush()
        return status, body

    def close(self):
        self.sock.close()


# ---- the server ----

class Server:
    def __init__(self, binary, root):
        self.root = root
        for name, data in (("ok.txt", b"ok\n"),):
            (root / name).write_bytes(data)
        with (root / "big.bin").open("wb") as f:
            block = bytes(range(256)) * 4096
            for _ in range(BIG // len(block)):
                f.write(block)
            f.write(block[:BIG % len(block)])
        for name in ("ok.txt", "big.bin"):  # not a file still being written (handlers/static.hpp file_settled)
            os.utime(root / name, (time.time() - 10, time.time() - 10))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "1", "-subj", "/CN=localhost", "-keyout", str(root / "key.pem"),
                        "-out", str(root / "cert.pem")], check=True, capture_output=True)
        self.origin = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Origin)
        self.origin.daemon_threads = True
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        oport = self.origin.server_address[1]
        self.plain = free_port()
        self.tls = free_port()
        while self.tls == self.plain:
            self.tls = free_port()
        location = f'[[site.location]]\npath = "/slow"\nupstream = "http://127.0.0.1:{oport}"\n'
        (root / "agensio.toml").write_text(
            '[server]\nworkers = 1\nbody_timeout = 1\nprotocols = ["h1", "h2", "h2c", "h3"]\n'
            f'pid_file = "{root}/agensio.pid"\n'
            '[cache]\nmax_file_size = "1MB"\n'
            f'[log]\naccess = "{root}/access.log"\nerror = "{root}/error.log"\nlevel = "info"\n'
            f'[[site]]\nserver_name = ["localhost"]\nlisten = ["127.0.0.1:{self.plain}"]\nroot = "{root}"\n' + location +
            f'[[site]]\nserver_name = ["localhost"]\nlisten = ["127.0.0.1:{self.tls}"]\nroot = "{root}"\n'
            f'tls = {{ cert = "{root}/cert.pem", key = "{root}/key.pem" }}\n' + location)
        self.log = (root / "server.log").open("w+")
        self.process = subprocess.Popen([binary, "-c", str(root / "agensio.toml")], stdout=self.log, stderr=subprocess.STDOUT)
        end = time.monotonic() + 10
        while not (listening(self.plain) and listening(self.tls)):
            assert self.process.poll() is None and time.monotonic() < end, "the server did not come up"
            time.sleep(0.05)

    def lines(self, tag):
        path = self.root / "access.log"
        text = path.read_text(errors="replace") if path.exists() else ""
        return [l for l in text.splitlines() if f"t={tag} " in l or f"t={tag}\"" in l]

    def error_log(self):
        path = self.root / "error.log"
        return path.read_text(errors="replace") if path.exists() else ""

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.origin.shutdown()
        self.log.seek(0)
        out = self.log.read()
        assert "Sanitizer" not in out and "runtime error:" not in out, "sanitizer report:\n" + out[-4096:]


LINE = re.compile(r'"(\S+) (\S+) (HTTP/\S+)" (\d{3}) (\d+|-)')


def judge(srv, tag, status, max_bytes, min_bytes=0, protocol=None, origin=None):
    """One line for the tag, with the status and min_bytes <= bytes <= max_bytes; None or the failure."""
    found = srv.lines(tag)
    if len(found) != 1:
        return f"{len(found)} access-log lines for t={tag} (want 1): {found}"
    m = LINE.search(found[0])
    if not m:
        return f"unparsed line: {found[0]}"
    got_status, got_bytes = int(m.group(4)), 0 if m.group(5) == "-" else int(m.group(5))
    if protocol and m.group(3) != protocol:
        return f"protocol {m.group(3)} (want {protocol}): {found[0]}"
    if got_status != status:
        return f"status {got_status} (want {status}): {found[0]}"
    if not min_bytes <= got_bytes <= max_bytes:
        return f"bytes {got_bytes} (want {min_bytes}..{max_bytes}): {found[0]}"
    if origin:
        with origin_lock:
            seen = origin_seen.get(tag)
        if seen != origin:
            return f"the origin saw t={tag} as {seen} (want {origin}: agensio closes its connection when the client leaves)"
    return None


# ---- rows: each returns a function that judges once the log is flushed ----

def row_h1_get(srv):
    s = h1_leave(srv.plain, "GET", "h1-get")
    time.sleep(LEAVE_S)
    s.close()
    return lambda: judge(srv, "h1-get", 499, 0, protocol="HTTP/1.1", origin="closed")


def row_h1_post(srv):
    s = h1_leave(srv.plain, "POST", "h1-post", body=b"x" * 1000)
    time.sleep(LEAVE_S)
    s.close()
    return lambda: judge(srv, "h1-post", 499, 0, protocol="HTTP/1.1", origin="closed")


def row_h1_body_timeout(srv):
    s = h1_leave(srv.plain, "POST", "h1-body-timeout", body=b"x" * 10, declared=1000)
    time.sleep(2.5)  # body_timeout = 1
    s.close()
    return lambda: judge(srv, "h1-body-timeout", 408, 0, protocol="HTTP/1.1")


def row_h1_bad_chunk(srv):
    """A chunk size that is not hex: a 400 answered before the close, as nginx answers it (alpha.120)."""
    s = tcp(srv.plain)
    s.sendall(b"POST /slow?t=h1-bad-chunk HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nxx\r\n")
    got = b""
    try:
        while b"\r\n" not in got:
            data = s.recv(4096)
            if not data:
                break
            got += data
    except OSError:
        pass
    s.close()
    line = got.split(b"\r\n", 1)[0].decode(errors="replace")

    def check():
        if not line.startswith("HTTP/1.1 400 "):
            return f"the client got {line!r}, not a 400"
        return judge(srv, "h1-bad-chunk", 400, 4096, protocol="HTTP/1.1")
    return check


def row_h1_partial(srv):
    got = h1_partial(srv.plain, "h1-partial")
    return lambda: judge(srv, "h1-partial", 200, BIG - 1, min_bytes=got, protocol="HTTP/1.1")


def row_h2_get(srv):
    c = H2(srv.plain)
    c.request("GET", "/slow?t=h2-get")
    c.pump(LEAVE_S)
    c.close()
    return lambda: judge(srv, "h2-get", 499, 0, protocol="HTTP/2.0", origin="closed")


def row_h2_post(srv):
    c = H2(srv.plain)
    c.request("POST", "/slow?t=h2-post", body=b"x" * 1000)
    c.pump(LEAVE_S)
    c.close()
    return lambda: judge(srv, "h2-post", 499, 0, protocol="HTTP/2.0", origin="closed")


def row_h2_rst(srv):
    """The whole POST body, then RST_STREAM(CANCEL), then another request on the same connection."""
    c = H2(srv.plain)
    sid = c.request("POST", "/slow?t=h2-rst", body=b"x" * 1000)
    c.pump(LEAVE_S)
    c.conn.reset_stream(sid, h2.errors.ErrorCodes.CANCEL)
    c.flush()
    after = c.request("GET", "/ok.txt?t=h2-after-rst")
    status, body = c.answer(after)
    c.close()

    def check():
        if (status, body) != (200, b"ok\n"):
            return f"the request after the reset got {status} {body!r}"
        fail = judge(srv, "h2-rst", 499, 0, protocol="HTTP/2.0", origin="closed") or judge(srv, "h2-after-rst", 200, 3, min_bytes=3)
        if fail:
            return fail
        if not re.search(r"stream 1 \(localhost POST /slow\): reset by the client \(CANCEL\)", srv.error_log()):
            return "the error log's reset line does not name the site, the method and the path: " + \
                   " | ".join(l for l in srv.error_log().splitlines() if "reset by the client" in l)
        return None
    return check


def row_h2_body_timeout(srv):
    c = H2(srv.plain)
    c.request("POST", "/slow?t=h2-body-timeout", body=b"x" * 10, end=False)  # content-length 1000
    c.pump(2.5)  # body_timeout = 1
    c.close()
    return lambda: judge(srv, "h2-body-timeout", 408, 0, protocol="HTTP/2.0")


def row_h2_overlong(srv):
    """More DATA than the content-length: the stream reset, 400 logged, the RST line naming the request."""
    c = H2(srv.plain)
    sid = c.conn.get_next_available_stream_id()
    c.conn.send_headers(sid, [(":method", "POST"), (":scheme", "http"), (":authority", "localhost"),
                              (":path", "/slow?t=h2-overlong"), ("content-length", "10")])
    c.conn.send_data(sid, b"x" * 20, end_stream=True)
    c.flush()
    c.pump(0.5)
    c.close()

    def check():
        fail = judge(srv, "h2-overlong", 400, 0, protocol="HTTP/2.0")
        if fail:
            return fail
        if not re.search(r"stream \d+ \(localhost POST /slow\): RST_STREAM PROTOCOL_ERROR: more DATA than content-length", srv.error_log()):
            return "the RST_STREAM line does not name the request: " + \
                   " | ".join(l for l in srv.error_log().splitlines() if "more DATA" in l)
        return None
    return check


def row_h2_partial(srv):
    c = H2(srv.plain)
    sid = c.request("GET", "/big.bin?t=h2-partial")
    got = 0
    for ev in c.pump(2, lambda evs: sum(len(e.data) for e in evs if isinstance(e, h2.events.DataReceived)) >= 60000):
        if isinstance(ev, h2.events.DataReceived) and ev.stream_id == sid:
            got += len(ev.data)
    c.close()
    return lambda: judge(srv, "h2-partial", 200, BIG - 1, min_bytes=got, protocol="HTTP/2.0")


def h3_client(srv):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import importlib
    attacks = importlib.import_module("h3-attacks")
    attacks.SERVER = ("127.0.0.1", srv.tls)
    c = attacks.Client()
    assert c.connect(), "no QUIC handshake"
    return c


def row_h3_get(srv):
    c = h3_client(srv)
    c.request("/slow?t=h3-get")
    c.pump(LEAVE_S)
    c.close()
    return lambda: judge(srv, "h3-get", 499, 0, protocol="HTTP/3.0", origin="closed")


def row_h3_post(srv):
    c = h3_client(srv)
    sid = c.quic.get_next_available_stream_id()
    c.h3.send_headers(sid, [(b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"localhost"),
                            (b":path", b"/slow?t=h3-post"), (b"content-length", b"1000")])
    c.h3.send_data(sid, b"x" * 1000, end_stream=True)
    c.pump(LEAVE_S)
    c.close()
    return lambda: judge(srv, "h3-post", 499, 0, protocol="HTTP/3.0", origin="closed")


def row_h3_cancel(srv):
    """STOP_SENDING and RESET_STREAM on the request (RFC 9114 4.1.1), then another request."""
    c = h3_client(srv)
    sid = c.request("/slow?t=h3-cancel")
    c.pump(LEAVE_S)
    if hasattr(c.quic, "stop_stream"):
        c.quic.stop_stream(sid, 0x10C)  # H3_REQUEST_CANCELLED
    c.quic.reset_stream(sid, 0x10C)
    status, body = c.get("/ok.txt?t=h3-after-cancel")
    c.close()

    def check():
        if (status, body) != (200, b"ok\n"):
            return f"the request after the cancel got {status} {body!r}"
        return judge(srv, "h3-cancel", 499, 0, protocol="HTTP/3.0", origin="closed") or judge(srv, "h3-after-cancel", 200, 3, min_bytes=3)
    return check


def row_h3_partial(srv):
    from aioquic.h3.events import DataReceived
    c = h3_client(srv)
    sid = c.request("/big.bin?t=h3-partial")
    c.pump(3, lambda: sum(len(e.data) for e in c.h3_events if isinstance(e, DataReceived) and e.stream_id == sid) >= 200 * 1024)
    got = sum(len(e.data) for e in c.h3_events if isinstance(e, DataReceived) and e.stream_id == sid)
    c.close()
    return lambda: judge(srv, "h3-partial", 200, BIG - 1, min_bytes=got, protocol="HTTP/3.0")


ROWS = {
    "h1-get": row_h1_get, "h1-post": row_h1_post, "h1-body-timeout": row_h1_body_timeout, "h1-bad-chunk": row_h1_bad_chunk,
    "h1-partial": row_h1_partial,
    "h2-get": row_h2_get, "h2-post": row_h2_post, "h2-rst": row_h2_rst, "h2-body-timeout": row_h2_body_timeout,
    "h2-overlong": row_h2_overlong, "h2-partial": row_h2_partial,
    "h3-get": row_h3_get, "h3-post": row_h3_post, "h3-cancel": row_h3_cancel, "h3-partial": row_h3_partial,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--rows", default=",".join(ROWS))
    args = ap.parse_args()
    rows = [r for r in args.rows.split(",") if r]
    for r in rows:
        if r not in ROWS:
            raise SystemExit(f"unknown row {r}; rows: {','.join(ROWS)}")
    if any(r.startswith("h3-") for r in rows):
        try:
            import aioquic  # noqa: F401
        except ImportError:
            print("h3 rows skipped: aioquic is not installed")
            rows = [r for r in rows if not r.startswith("h3-")]
    failed = 0
    with tempfile.TemporaryDirectory(prefix="agensio-abandoned-") as directory:
        srv = Server(args.binary, Path(directory))
        try:
            checks = []
            for r in rows:
                try:
                    checks.append((r, ROWS[r](srv)))
                except Exception as e:  # a client that could not do its part fails the row, not the run
                    checks.append((r, lambda e=e: f"client error: {e!r}"))
            time.sleep(SLOW_S + 1.5)  # the origin's answers come back, the access log's 1 s flush
            for r, check in checks:
                fail = check()
                print(f"{r}: {'ok' if fail is None else 'FAIL ' + fail}", flush=True)
                failed += fail is not None
        finally:
            srv.stop()
    print("all rows passed" if not failed else f"{failed} of {len(rows)} rows failed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
