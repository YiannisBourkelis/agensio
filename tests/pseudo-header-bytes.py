#!/usr/bin/env python3
"""The bytes of :method, :path and :authority over HTTP/2 and HTTP/3, in front of an origin.

An HPACK or QPACK string carries any byte; HTTP/1's request line and Host field cannot hold a
space or a control character. agensio writes a proxied request's target and host into the
origin's HTTP/1.1 head, so a pseudo-header with such a byte must never become a request
(RFC 9113 8.2.1 and 10.3, RFC 9114 4.2 and 10.3). Until 0.1.0-alpha.146 the pseudo-headers were
stored unchecked and the target was looked at only up to its "?": a line break in a query or in
:authority reached the origin as a line of its own. On 0.1.0-alpha.145 every row fails.

Run inside the Linux devbox: python3 tests/pseudo-header-bytes.py BINARY
One single-worker server proxying everything to an origin in this script, which records every
byte it is sent. Rows, one per protocol (h2c, h2 over TLS, HTTP/3 when aioquic is installed):
each malformed request is answered with a stream error (HTTP/2: RST_STREAM PROTOCOL_ERROR;
HTTP/3: a reset with H3_MESSAGE_ERROR), the request after it on a new connection is answered
200, and the origin received that one request and not a byte of the others.
"""
import os
import socket
import ssl
import subprocess
import sys
import threading
import time

import h2.config
import h2.connection
import h2.events

try:
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived
    from aioquic.quic import events as qe
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    HAVE_H3 = True
except ImportError:
    HAVE_H3 = False

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = os.path.join(ROOT, "bench", "tmp", "pseudo")
TLS_PORT, PLAIN_PORT, ORIGIN_PORT = 18490, 18491, 18492
H3_MESSAGE_ERROR = 0x10E

# (what, method, path, authority or None for the row's own). The authority rows run where no
# certificate decides the name first (h2c).
BAD = [
    ("a line break in the query", b"GET", b"/q?x=1\r\nX-Injected: yes", None),
    ("a line feed in the query", b"GET", b"/q?x=1\nX-Injected: yes", None),
    ("a line break in the path", b"GET", b"/a\r\nX-Injected: yes", None),
    ("a space in the path", b"GET", b"/a b", None),
    ("a NUL in the query", b"GET", b"/q?a\x00b", None),
    ("a request line as the method", b"GET /x HTTP/1.1\r\nX-Injected:", b"/", None),
]
BAD_AUTHORITY = [
    ("a line break in :authority", b"GET", b"/", b"site.test\r\nX-Injected: yes"),
    ("a line break after a bracketed :authority", b"GET", b"/", b"[::1]\r\nX-Injected: yes"),
    ("a slash in :authority", b"GET", b"/", b"site.test/x"),
]


class Origin:
    """Records what it is sent and answers each request head with a small 200."""

    def __init__(self):
        self.received = b""
        self.lock = threading.Lock()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", ORIGIN_PORT))
        self.sock.listen(16)
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        buf = b""
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                with self.lock:
                    self.received += d
                buf += d
                while b"\r\n\r\n" in buf:
                    _, buf = buf.split(b"\r\n\r\n", 1)
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except OSError:
            pass
        c.close()

    def take(self):
        with self.lock:
            got, self.received = self.received, b""
        return got


def h2_request(tls, method, path, authority):
    """One request on a new connection: 'status N', 'RST_STREAM N', 'GOAWAY N', 'closed' or 'no answer'."""
    s = socket.create_connection(("127.0.0.1", TLS_PORT if tls else PLAIN_PORT))
    s.settimeout(3)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        s = ctx.wrap_socket(s, server_hostname="localhost")
    conn = h2.connection.H2Connection(config=h2.config.H2Configuration(
        client_side=True, header_encoding=None, validate_outbound_headers=False, normalize_outbound_headers=False))
    conn.initiate_connection()
    conn.send_headers(1, [(b":method", method), (b":scheme", b"https" if tls else b"http"), (b":path", path), (b":authority", authority)], end_stream=True)
    s.sendall(conn.data_to_send())
    result = "no answer"
    try:
        while True:
            d = s.recv(65536)
            if not d:
                result = "closed"
                break
            done = False
            for ev in conn.receive_data(d):
                if isinstance(ev, h2.events.ResponseReceived):
                    result, done = "status " + dict(ev.headers)[b":status"].decode(), True
                elif isinstance(ev, h2.events.StreamReset):
                    result, done = "RST_STREAM %d" % ev.error_code, True
                elif isinstance(ev, h2.events.ConnectionTerminated):
                    result, done = "GOAWAY %d" % ev.error_code, True
            s.sendall(conn.data_to_send())
            if done:
                break
    except (socket.timeout, OSError):
        pass
    s.close()
    return result


def h3_request(method, path, authority):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE, server_name="localhost")
    cfg.idle_timeout = 10.0
    quic = QuicConnection(configuration=cfg)
    h3 = H3Connection(quic)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.05)
    quic.connect(("127.0.0.1", TLS_PORT), time.monotonic())
    sid = quic.get_next_available_stream_id()
    h3.send_headers(sid, [(b":method", method), (b":scheme", b"https"), (b":path", path), (b":authority", authority)], end_stream=True)
    result = "no answer"
    end = time.monotonic() + 5
    while time.monotonic() < end and result == "no answer":
        for data, addr in quic.datagrams_to_send(time.monotonic()):
            sock.sendto(data, addr)
        try:
            data, addr = sock.recvfrom(65536)
            quic.receive_datagram(data, addr, time.monotonic())
        except socket.timeout:
            t = quic.get_timer()
            if t is not None and time.monotonic() >= t:
                quic.handle_timer(time.monotonic())
        while True:
            ev = quic.next_event()
            if ev is None:
                break
            if isinstance(ev, qe.StreamReset) and ev.stream_id == sid:
                result = "reset 0x%x" % ev.error_code
            elif isinstance(ev, qe.ConnectionTerminated):
                result = "connection closed 0x%x" % ev.error_code
            for h in h3.handle_event(ev):
                if isinstance(h, HeadersReceived) and h.stream_id == sid:
                    result = "status " + dict(h.headers)[b":status"].decode()
    quic.close()
    for data, addr in quic.datagrams_to_send(time.monotonic()):
        sock.sendto(data, addr)
    sock.close()
    return result


def run_row(name, origin, request, refused, authority, cases):
    """`request(method, path, authority)` sends one; `refused` is the answer a malformed one must get."""
    problems = []
    origin.take()
    for what, method, path, own in cases:
        got = request(method, path, own or authority)
        if got != refused:
            problems.append("%s: %s (expected %s)" % (what, got, refused))
    time.sleep(0.3)  # anything on its way to the origin has arrived
    leaked = origin.take()
    if leaked:
        problems.append("the origin was sent %d bytes: %r" % (len(leaked), leaked[:120]))
    good = request(b"GET", b"/ok?x=%20y", authority)
    time.sleep(0.2)
    seen = origin.take()
    if good != "status 200":
        problems.append("the request after them: %s" % good)
    if seen.count(b"\r\n\r\n") != 1 or not seen.startswith(b"GET /ok?x=%20y HTTP/1.1\r\n"):
        problems.append("the origin's view of the good request: %r" % seen[:120])
    print("%-4s %-8s %s" % ("ok" if not problems else "FAIL", name, "; ".join(problems) if problems else "%d malformed requests refused (%s), the next one answered" % (len(cases), refused)))
    return not problems


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: pseudo-header-bytes.py BINARY")
    os.makedirs(TMP, exist_ok=True)
    conf = os.path.join(TMP, "agensio.toml")
    with open(conf, "w") as f:
        f.write('[server]\nworkers = 1\nprotocols = ["h1", "h2", "h2c"%s]\npid_file = "%s/agensio.pid"\n' % (', "h3"' if HAVE_H3 else "", TMP))
        f.write('[log]\naccess = "off"\nerror = "%s/error.log"\nlevel = "info"\n' % TMP)
        f.write('[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:%d"]\napp = "proxy"\nupstream = "http://127.0.0.1:%d"\n' % (TLS_PORT, ORIGIN_PORT))
        f.write('tls = { cert = "%s/bench/certs/cert.pem", key = "%s/bench/certs/key.pem" }\n' % (ROOT, ROOT))
        f.write('[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:%d"]\napp = "proxy"\nupstream = "http://127.0.0.1:%d"\n' % (PLAIN_PORT, ORIGIN_PORT))
    origin = Origin()
    server = subprocess.Popen([sys.argv[1], "-c", conf], stdout=subprocess.DEVNULL, stderr=open(os.path.join(TMP, "stderr.log"), "w"))
    try:
        for _ in range(50):
            time.sleep(0.1)
            try:
                socket.create_connection(("127.0.0.1", PLAIN_PORT), timeout=0.2).close()
                break
            except OSError:
                pass
        else:
            raise SystemExit("the server did not come up (%s/stderr.log)" % TMP)
        failed = 0
        failed += not run_row("h2c", origin, lambda m, p, a: h2_request(False, m, p, a), "RST_STREAM 1", b"site.test", BAD + BAD_AUTHORITY)
        failed += not run_row("h2", origin, lambda m, p, a: h2_request(True, m, p, a), "RST_STREAM 1", b"localhost", BAD)
        if HAVE_H3:
            failed += not run_row("h3", origin, h3_request, "reset 0x%x" % H3_MESSAGE_ERROR, b"localhost", BAD)
        else:
            print("skip h3       (aioquic not installed)")
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
    print("all rows passed" if not failed else "%d row(s) failed" % failed)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
