#!/usr/bin/env python3
"""Answers pulled from a source over HTTP/2 (and HTTP/1.1, HTTP/3): whole, in order, and every pull answered.

The test VPS's report on 0.1.0-alpha.138 (F1): answers compressed in pieces arrived corrupt over
HTTP/2, on h2c and over TLS, and decoded whole over HTTP/1.1 and HTTP/3. Faults of the HTTP/2
writer (src/http2/writer.hpp), older than the compression, which made them common:
- h2c: a DATA payload above 2 KB is written from the stream's chunk, and once the chunk was framed
  the same cycle pulled the next one into it, before the write took the first (row h2c-pieces).
- h2 and h2c: a WINDOW_UPDATE (or a SETTINGS change of the initial window) re-queues every answering
  stream, also one whose pull is in flight, and the writer pulled it again: a second read on the
  same source into the same buffer. The upstream keeps one waiter, so the first read was never
  answered, and the connection's next answer got a second HEADERS frame
  after its END_STREAM, which the client takes as a protocol error (row h2-window-during-pull); an
  answer compressed in pieces, whose read yields through the loop every 256 KB, was answered twice
  and its bytes mixed (row h2-tls-pieces).
- A cycle whose only work was a pull answered inline (the source's last read, 0 bytes) wrote
  nothing and ran no next cycle: the END_STREAM waited until the client sent something. A client's
  WINDOW_UPDATE used to come in time; with the first fault fixed, h2c-pieces waited for good.
On 0.1.0-alpha.138 h2c-pieces, h2-window-during-pull and h2-tls-pieces fail;
h2-window-during-pull-compressed passes there too and stays as a guard.

A client that leaves a streamed answer (found by fuzz_h2_bodies, 2026-11-07): the exchange behind it
read on up to its 256 KB of read-ahead, stopped, and was freed without giving its slot back to the
location's pool, so after max_connections such clients (16 per worker by default) every request to
that origin waited queue_wait and got 503, until a restart; and while the exchange lived it held its
origin connection open, past the client's RST_STREAM or close. On 0.1.0-alpha.139 every left-* row
fails.

Run inside the Linux devbox: python3 tests/h2-streamed-bodies.py BINARY [--rows a,b]
One single-worker server, an origin in this script: /rnd/N answers N bytes of base64 (seeded) with
its length, /pause/K answers K pieces of 20 KB chunked, 0.3 s apart. Rows:
- h2c-pieces: 400 KB, 1 MB and 5 MB of base64 compressed in pieces (gzip, and zstd and brotli when
  their command-line tools are installed) over h2c, decoded and compared.
- h2-window-during-pull: ten streamed answers in turn on one h2c connection, a WINDOW_UPDATE for the
  connection and for the stream sent while each waits on the origin's pause: each whole and in time.
- h2-window-during-pull-compressed: the same, compressed (gzip) as it streams.
- h2-tls-pieces: 5 MB compressed in pieces over TLS, a WINDOW_UPDATE after every DATA frame, three times.
- left-h2-reset, left-h2-close, left-h2-reset-compressed, left-h1-close: on a site whose location has
  one upstream slot (max_connections = 1, queue_wait = 2), a client takes an event stream and leaves
  after its first DATA (RST_STREAM, the connection closed; over HTTP/1 the connection closed while
  the origin keeps sending): the origin's connection closes within 2 s (HTTP/2: the origin quiet
  after its first event), and the next request through the slot is answered 200.

HTTP/1 during a streamed answer (2026-11-08): nothing read from the client while the answer streamed
unless the origin had taken a tick (250 ms) to send its head, and the idle timer counted a stream
waiting on its origin as an idle connection.
- left-h1-quiet: the HTTP/1 client leaves after the first event of an origin that then sends nothing:
  the origin's connection closes within 2 s, the next request through the slot is answered 200.
  On 0.1.0-alpha.140 it closed only at idle_timeout.
- h1-quiet-stream: an event stream over HTTP/1.1 whose origin is quiet for 5 s, longer than the
  server's idle_timeout (3 s here), gets its second event and its end. On 0.1.0-alpha.140 it was cut
  at idle_timeout (HTTP/2 was not).
- left-h1-cgi: a CGI script on a streaming location (buffering = false) prints its whole answer with
  its length and runs on for a second; its client takes the answer and leaves at once, three times;
  the server lives on. On 0.1.0-alpha.140 the exchange, still waiting for the script's end, called its
  freed connection at its slow tick (the sanitizer build: heap-use-after-free in on_slow_exchange).

A streamed answer cut on its application's side (the alpha.141 report, F3): the client saw the cut
(HTTP/1: no last chunk; HTTP/2: RST_STREAM), and the error log said nothing over HTTP/1 and only
"response body failed mid-stream" at info over HTTP/2, where a buffered answer's 504 names the
failure and the key.
- cut-h1-logged: an origin quiet past proxy.read_timeout (1 s here) and a CGI script quiet past
  cgi.read_timeout, over HTTP/1.1: the answer ends without its last chunk and an error-log line
  names the path, read_timeout and the key. On 0.1.0-alpha.141 no line.
- cut-h2-logged: the same origin over h2c. On 0.1.0-alpha.141 only the info line, not written at the
  default level.

Streamed answers over HTTP/3 (the alpha.141 report, F1; docs/design-http3.md 7.3): on 0.1.0-alpha.141
every one was reset with H3_INTERNAL_ERROR (0x102) once its application had answered, so every h3 row
fails there before any byte. The TLS sites answer HTTP/3 too (aioquic, driven by hand; the rows are
skipped where it is not installed).
- h3-streamed: /rnd/100000 and /rnd/5000000 with their content-length, /pause/3 chunked without one,
  through buffering = false: each whole.
- h3-cgi: left-h1-cgi over HTTP/3, the client gone as soon as it has the answer, three times.
- h3-quiet-stream: h1-quiet-stream over HTTP/3, the client's own idle timeout 3 s: the keep-alive PING
  keeps the connection while the origin is quiet.
- h3-backpressure: a flood through the one-slot origin while the client reads and acknowledges nothing
  for 2 s: the server's RSS grows less than 32 MB, the answer goes on after, the slot comes back.
- left-h3-stop, left-h3-close: left-h2-* over HTTP/3, the client's STOP_SENDING or close.
- cut-h3-logged: cut-h1-logged over HTTP/3: the stream reset with H3_REQUEST_CANCELLED, the line written.
- h3-compressed-pieces: h2c-pieces over HTTP/3 (the TLS site, buffered), and /pause/3 compressed as it
  streams: each decodes to what was sent. Before 0.1.0-alpha.142 these went as they came.

A streamed answer's end over HTTP/3 (the alpha.142 report, F2): when the source ended (a CGI script's
exit) or failed (an origin that closed early, read_timeout) on a read answered later, its FIN or
RESET_STREAM was queued and nothing sent it until the connection's next turn: the keep-alive PING at
half the idle timeout (7.5 s by default), or a packet from the client (curl's acknowledgements came in
time, aioquic's do not).
- h3-ends-on-time: a CGI event stream whose script exits after 0.3 s ends within 1 s, and an origin
  that closes without its last chunk after 0.3 s is reset (H3_REQUEST_CANCELLED) within 1 s; on
  0.1.0-alpha.142 both waited for the PING, about 1.5 s here (idle_timeout 3 s).

A client that holds a streamed answer back (the alpha.142 report, F3): the application's read_timeout
ran while agensio, its read-ahead full, read nothing more, cut the answer and blamed the application;
HTTP/3 had no bound of its own on a client that takes nothing (the server's PINGs keep the connection).
On 0.1.0-alpha.142 each of these fails.
- slow-reader-whole: 2 s of no reading against a read_timeout of 1 s (/burst/K: K events of 64 KB at
  once) over HTTP/1.1, HTTP/2 and HTTP/3: the whole answer.
- h3-stalled-reader: an HTTP/3 client that acknowledges but grants no credit, on the one-slot origin:
  cancelled with H3_REQUEST_CANCELLED within idle_timeout plus the 2 s check, an info line, the slot back.
- h1-stalled-reader: an HTTP/1.1 client that stops reading: closed at the idle timeout, with an info
  line saying the client took nothing.
Requires python3-h2 and openssl (aioquic for the h3 rows). Exit 1 on any failed row.
"""
import argparse
import base64
import random
import re
import select
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from pathlib import Path

import h2.config
import h2.connection
import h2.events
import h2.exceptions

try:  # the HTTP/3 rows (the devbox image has aioquic); without it they are skipped
    from aioquic.h3 import connection as h3c
    from aioquic.h3.events import DataReceived as H3Data, HeadersReceived as H3Headers
    from aioquic.quic import events as qe
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
except ImportError:
    QuicConnection = None

PIECE = 20 * 1024
PAUSE_S = 0.3


def rnd_body(n):
    return base64.b64encode(random.Random(n).randbytes(n * 3 // 4 + 3))[:n]


def pause_piece(i):
    line = f"piece {i} of the streamed answer, paused between pieces\n".encode()
    return (line * (PIECE // len(line) + 1))[:PIECE]


def pause_body(k):
    return b"".join(pause_piece(i) for i in range(k))


class Origin(socketserver.BaseRequestHandler):
    """HTTP/1.1 keep-alive origin: /rnd/N with a length, /pause/K chunked with pauses."""

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
            target = head.split(b"\r\n", 1)[0].split(b" ")[1].decode()
            m = re.fullmatch(r"/(rnd|pause)/(\d+)", target)
            if not m:
                sock.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                continue
            n = int(m.group(2))
            if m.group(1) == "rnd":
                body = rnd_body(n)
                sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
                continue
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n")
            for i in range(n):
                if i:
                    time.sleep(PAUSE_S)
                piece = pause_piece(i)
                sock.sendall(b"%x\r\n" % len(piece) + piece + b"\r\n")
            sock.sendall(b"0\r\n\r\n")


HOLD_CLOSED = {}  # /hold/NAME: when the server closed the origin's connection


class SlotOrigin(socketserver.BaseRequestHandler):
    """One answer per connection: /quick at once; /hold/NAME an event stream's head and one event,
    then quiet until the server closes; /flood/S events of 64 KB back to back for S seconds; /later/S
    one event, S seconds of quiet, a second event and the stream's end; /gone/MS one event, MS
    milliseconds, then the connection closed without the last chunk; /burst/K K events of 64 KB as fast
    as the socket takes them, then the end."""

    def handle(self):
        sock = self.request
        buf = b""
        while b"\r\n\r\n" not in buf:
            data = sock.recv(65536)
            if not data:
                return
            buf += data
        target = buf.split(b"\r\n", 1)[0].split(b" ")[1].decode()
        if target == "/quick":
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            return
        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
        event = b"data: " + b"e" * 2000 + b"\n\n"
        m = re.fullmatch(r"/(hold|flood|later|gone|burst)/(\w+)", target)
        if not m:
            return
        if m.group(1) == "gone":
            sock.sendall(b"%x\r\n" % len(event) + event + b"\r\n")
            time.sleep(int(m.group(2)) / 1000)
            return
        if m.group(1) == "later":
            sock.sendall(b"%x\r\n" % len(event) + event + b"\r\n")
            time.sleep(int(m.group(2)))
            last = b"data: two\n\n"
            try:
                sock.sendall(b"%x\r\n" % len(last) + last + b"\r\n0\r\n\r\n")
            except OSError:
                pass
            return
        if m.group(1) == "hold":
            sock.sendall(b"%x\r\n" % len(event) + event + b"\r\n")
            sock.settimeout(10)
            try:
                while sock.recv(65536):
                    pass
            except OSError:
                pass
            HOLD_CLOSED[m.group(2)] = time.monotonic()
            return
        event = b"data: " + b"f" * 65536 + b"\n\n"
        if m.group(1) == "burst":
            try:
                for _ in range(int(m.group(2))):
                    sock.sendall(b"%x\r\n" % len(event) + event + b"\r\n")
                sock.sendall(b"0\r\n\r\n")
            except OSError:
                pass
            return
        end = time.monotonic() + int(m.group(2))
        try:
            while time.monotonic() < end:
                sock.sendall(b"%x\r\n" % len(event) + event + b"\r\n")
        except OSError:
            pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def listening(port):
    with socket.socket() as s:
        s.settimeout(0.1)
        return s.connect_ex(("127.0.0.1", port)) == 0


class H2:
    """One HTTP/2 connection: h2c with prior knowledge, or TLS with ALPN h2."""

    def __init__(self, port, tls=False):
        s = socket.create_connection(("127.0.0.1", port))
        s.settimeout(5)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            s = ctx.wrap_socket(s, server_hostname="localhost")
        self.sock, self.tls = s, tls
        self.conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
        self.conn.initiate_connection()
        self.conn.increment_flow_control_window(16 * 1024 * 1024)  # the connection never limits the answers
        self.flush()

    def flush(self):
        data = self.conn.data_to_send()
        if data:
            self.sock.sendall(data)

    def get(self, path, encoding=None, seconds=10, on_data=None):
        """(status, content-encoding, body) of one GET; status None when it did not end in time."""
        sid = self.conn.get_next_available_stream_id()
        headers = [(":method", "GET"), (":scheme", "https" if self.tls else "http"), (":authority", "localhost"), (":path", path)]
        if encoding:
            headers.append(("accept-encoding", encoding))
        self.conn.send_headers(sid, headers, end_stream=True)
        self.flush()
        status, coding, body, ended = None, None, b"", False
        end = time.monotonic() + seconds
        while not ended and time.monotonic() < end:
            if not (self.tls and self.sock.pending()):
                r, _, _ = select.select([self.sock], [], [], max(0.0, end - time.monotonic()))
                if not r:
                    continue
            data = self.sock.recv(65536)
            if not data:
                break
            for ev in self.conn.receive_data(data):
                if isinstance(ev, h2.events.ResponseReceived) and ev.stream_id == sid:
                    h = dict(ev.headers)
                    status, coding = int(h[":status"]), h.get("content-encoding")
                elif isinstance(ev, h2.events.DataReceived) and ev.stream_id == sid:
                    body += ev.data
                    self.conn.acknowledge_received_data(ev.flow_controlled_length, sid)
                    if on_data:
                        on_data(self, sid, len(body))
                elif isinstance(ev, h2.events.StreamEnded) and ev.stream_id == sid:
                    ended = True
                elif isinstance(ev, h2.events.StreamReset) and ev.stream_id == sid:
                    return f"reset {ev.error_code}", coding, body
            self.flush()
        return (status if ended else None), coding, body

    def close(self):
        self.sock.close()


class H3:
    """One HTTP/3 connection over aioquic, driven by hand as tests/h3-attacks.py drives it; the
    answers per stream as they arrive (status, fields, body, ended, the reset code)."""

    def __init__(self, port, idle=10.0):
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE, server_name="localhost")
        cfg.idle_timeout = idle
        self.quic = QuicConnection(configuration=cfg)
        self.h3 = h3c.H3Connection(self.quic)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.setblocking(False)
        self.streams, self.terminated = {}, None
        self.quic.connect(("127.0.0.1", port), time.monotonic())
        handshake = []
        self.on_event = lambda ev: handshake.append(ev) if isinstance(ev, qe.HandshakeCompleted) else None
        if not self.pump(5, lambda: handshake):
            raise AssertionError("no HTTP/3 handshake")

    def stream(self, sid):
        return self.streams.setdefault(sid, {"status": None, "fields": {}, "body": bytearray(), "ended": False, "reset": None})

    def pump(self, seconds, until=None):
        """Runs the connection for `seconds` or until `until()` is true; False when it ran out."""
        end = time.monotonic() + seconds
        while True:
            now = time.monotonic()
            for data, addr in self.quic.datagrams_to_send(now):
                self.sock.sendto(data, addr)
            while (ev := self.quic.next_event()) is not None:
                self.on_event(ev)
                if isinstance(ev, qe.ConnectionTerminated):
                    self.terminated = ev
                elif isinstance(ev, qe.StreamReset):
                    self.stream(ev.stream_id)["reset"] = ev.error_code
                for h in self.h3.handle_event(ev):
                    if isinstance(h, (H3Headers, H3Data)):
                        st = self.stream(h.stream_id)
                        if isinstance(h, H3Headers):
                            st["fields"] = {k.decode(): v.decode() for k, v in h.headers}
                            st["status"] = int(st["fields"].get(":status", 0))
                        else:
                            st["body"] += h.data
                        st["ended"] = st["ended"] or h.stream_ended
            if until and until():
                return True
            if self.terminated or now >= end:
                return False
            t = self.quic.get_timer()
            wait = end - now if t is None else max(0.0, min(end, t) - now)
            r, _, _ = select.select([self.sock], [], [], wait)
            if r:
                for _ in range(256):
                    try:
                        data, addr = self.sock.recvfrom(65536)
                    except BlockingIOError:
                        break
                    self.quic.receive_datagram(data, addr, time.monotonic())
            elif (t := self.quic.get_timer()) is not None and time.monotonic() >= t:
                self.quic.handle_timer(time.monotonic())

    def request(self, path, encoding=None):
        sid = self.quic.get_next_available_stream_id()
        fields = [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"localhost"), (b":path", path.encode())]
        if encoding:
            fields.append((b"accept-encoding", encoding.encode()))
        self.h3.send_headers(sid, fields, end_stream=True)
        return self.stream(sid), sid

    def get(self, path, encoding=None, seconds=10):
        """The stream's answer once it ended, was reset or the time ran out (then neither is set)."""
        st, _ = self.request(path, encoding)
        self.pump(seconds, lambda: st["ended"] or st["reset"] is not None)
        return st

    def close(self):
        try:
            self.quic.close()
            self.pump(0.2)
        finally:
            self.sock.close()


def h3_text(st):
    """What an answer that is not whole looks like, for a row's message."""
    if st["reset"] is not None:
        return f"reset 0x{st['reset']:x} after {len(st['body'])} bytes (status {st['status']})"
    return f"status {st['status']}, {len(st['body'])} bytes, {'ended' if st['ended'] else 'not ended'}"


def decode(coding, data):
    if coding == "gzip":
        return zlib.decompress(data, 31)
    tool = {"zstd": ["zstd", "-dqc"], "br": ["brotli", "-dc"]}.get(coding)
    if not tool:
        raise ValueError(f"coding {coding}")
    out = subprocess.run(tool, input=data, capture_output=True)
    if out.returncode:
        raise ValueError(out.stderr.decode(errors="replace").strip())
    return out.stdout


def compare(what, want, coding, got_coding, raw):
    """None when raw, in coding, decodes to want; else what went wrong."""
    if got_coding != coding:
        return f"{what}: content-encoding {got_coding} (want {coding})"
    try:
        body = decode(coding, raw) if coding else raw
    except Exception as e:  # noqa: BLE001: the decoder's message is the finding
        return f"{what}: {coding} did not decode ({len(raw)} bytes): {e}"
    if body == want:
        return None
    at = next((i for i, (a, b) in enumerate(zip(body, want)) if a != b), min(len(body), len(want)))
    return f"{what}: {len(body)} bytes decoded, {len(want)} sent, the first difference at byte {at}"


# ---- the server ----

class Server:
    def __init__(self, binary, root):
        self.root = root
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "1", "-subj", "/CN=localhost", "-keyout", str(root / "key.pem"),
                        "-out", str(root / "cert.pem")], check=True, capture_output=True)
        self.origin = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Origin)
        self.origin.daemon_threads = True
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        upstream = f'upstream = "http://127.0.0.1:{self.origin.server_address[1]}"\napp = "proxy"\n'
        self.slot_origin = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SlotOrigin)
        self.slot_origin.daemon_threads = True
        threading.Thread(target=self.slot_origin.serve_forever, daemon=True).start()
        self.cut_origin = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SlotOrigin)  # a pool of its own
        self.cut_origin.daemon_threads = True
        threading.Thread(target=self.cut_origin.serve_forever, daemon=True).start()
        slots = (f'upstream = "http://127.0.0.1:{self.slot_origin.server_address[1]}"\napp = "proxy"\n'
                 'proxy = { buffering = false, max_connections = 1, queue_wait = 2 }\n')
        self.ports = {}
        sites = ""
        # The TLS sites also answer HTTP/3 (h3 in protocols opens every TLS listener's port over UDP):
        # the h3 rows use them; the slots and the cut origin's pools are shared with the plain sites.
        tls = f'tls = {{ cert = "{root}/cert.pem", key = "{root}/key.pem" }}\n'
        for name, extra in (("buffered", 'response_compression = { enabled = true }\n'),
                            ("streamed", 'proxy = { buffering = false }\n'),
                            ("streamed-compressed", 'proxy = { buffering = false }\nresponse_compression = { enabled = true }\n'),
                            ("tls", tls + 'response_compression = { enabled = true }\n'),
                            ("h3", tls + 'proxy = { buffering = false }\n'),
                            ("h3-streamed-compressed", tls + 'proxy = { buffering = false }\nresponse_compression = { enabled = true }\n'),
                            ("slots", None),
                            ("slots-compressed", 'response_compression = { enabled = true, compress_event_streams = true }\n'),
                            ("h3-slots", tls),
                            ("cut", None),
                            ("h3-cut", tls)):
            port = free_port()
            while port in self.ports.values():
                port = free_port()
            self.ports[name] = port
            if "slots" in name:
                sites += f'[[site]]\nserver_name = ["localhost"]\nlisten = ["127.0.0.1:{port}"]\n' + slots + (extra or "")
                continue
            if "cut" in name:  # a streamed answer whose origin goes quiet past read_timeout
                sites += (f'[[site]]\nserver_name = ["localhost"]\nlisten = ["127.0.0.1:{port}"]\n'
                          f'upstream = "http://127.0.0.1:{self.cut_origin.server_address[1]}"\napp = "proxy"\n'
                          'proxy = { buffering = false, read_timeout = 1 }\n' + (extra or ""))
                continue
            sites += f'[[site]]\nserver_name = ["localhost"]\nlisten = ["127.0.0.1:{port}"]\n' + upstream + extra
        # A CGI script that prints its whole answer, with its length, and runs on for a second with its
        # output still open, on a location that streams: the client has the answer at once, and the
        # exchange's end (the child's exit) comes after the client is gone.
        (root / "www").mkdir()
        (root / "cgi").mkdir()
        script = root / "cgi" / "linger.cgi"
        script.write_text("#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\nContent-Length: 2\\r\\n\\r\\nok'\nsleep 1\n")
        script.chmod(0o755)
        quiet = root / "cgi" / "quiet.cgi"  # its head and a line, then quiet past cgi.read_timeout
        quiet.write_text("#!/bin/sh\nprintf 'Content-Type: text/event-stream\\r\\n\\r\\ndata: one\\n\\n'\nsleep 3\n")
        quiet.chmod(0o755)
        ends = root / "cgi" / "ends.cgi"  # its head and a line, then its end 0.3 s later
        ends.write_text("#!/bin/sh\nprintf 'Content-Type: text/event-stream\\r\\n\\r\\ndata: one\\n\\n'\nsleep 0.3\n")
        ends.chmod(0o755)
        for name, extra in (("cgi", ""), ("h3-cgi", tls)):
            self.ports[name] = free_port()
            while list(self.ports.values()).count(self.ports[name]) > 1:
                self.ports[name] = free_port()
            sites += (f'[[site]]\nserver_name = ["localhost"]\nlisten = ["127.0.0.1:{self.ports[name]}"]\nroot = "{root}/www"\n' + extra +
                      f'[[site.location]]\npath = "/cgi/"\nalias = "{root}/cgi"\ncgi = {{ buffering = false }}\n'
                      f'[[site.location]]\npath = "/cgi-cut/"\nalias = "{root}/cgi"\ncgi = {{ buffering = false, read_timeout = 1 }}\n')
        # idle_timeout below the quiet of /later/5, so that the HTTP/1 rows tell a stream waiting on its
        # origin from an idle connection quickly (and HTTP/3's idle timeout is the same 3 s).
        (root / "agensio.toml").write_text(
            '[server]\nworkers = 1\nprotocols = ["h1", "h2", "h2c", "h3"]\nidle_timeout = 3\n'
            f'pid_file = "{root}/agensio.pid"\nstate_dir = "{root}/state"\n'
            f'[log]\naccess = "off"\nerror = "{root}/error.log"\nlevel = "info"\n' + sites)
        self.error_log = root / "error.log"
        self.log = (root / "server.log").open("w+")
        self.process = subprocess.Popen([binary, "-c", str(root / "agensio.toml")], stdout=self.log, stderr=subprocess.STDOUT)
        end = time.monotonic() + 10
        while not all(listening(p) for p in self.ports.values()):
            if self.process.poll() is not None or time.monotonic() > end:
                self.log.seek(0)
                raise AssertionError("the server did not come up:\n" + self.log.read()[-2048:])
            time.sleep(0.05)

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.origin.shutdown()
        self.slot_origin.shutdown()
        self.cut_origin.shutdown()
        self.log.seek(0)
        out = self.log.read()
        assert "Sanitizer" not in out and "runtime error:" not in out, "sanitizer report:\n" + out[-4096:]


# ---- rows: each returns None or what failed ----

def codings():
    found = ["gzip"]
    if shutil.which("zstd"):
        found.append("zstd")
    if shutil.which("brotli"):
        found.append("br")
    return found


def row_h2c_pieces(srv):
    c = H2(srv.ports["buffered"])
    try:
        for n in (400_000, 1_000_000, 5_000_000):
            for coding in codings():
                status, got, raw = c.get(f"/rnd/{n}", coding)
                if status != 200:
                    return f"/rnd/{n} {coding}: status {status}"
                fail = compare(f"/rnd/{n} {coding}", rnd_body(n), coding, got, raw)
                if fail:
                    return fail
    finally:
        c.close()
    return None


def window_during_pause(conn, sid, received):
    """After each piece: a WINDOW_UPDATE for the connection and the stream, while the next is paused."""
    conn.conn.increment_flow_control_window(65536)
    try:
        conn.conn.increment_flow_control_window(65536, stream_id=sid)
    except h2.exceptions.StreamClosedError:  # the last piece came with the stream's end
        pass
    conn.flush()


def streamed_turns(srv, site, coding):
    c = H2(srv.ports[site])
    try:
        for turn in range(10):  # past the connection's pull budget of eight
            status, got, raw = c.get("/pause/3", coding, seconds=5, on_data=window_during_pause)
            if status != 200:
                return f"answer {turn + 1} of 10 on one connection: status {status} after {len(raw)} bytes"
            fail = compare(f"answer {turn + 1} of 10", pause_body(3), coding, got, raw)
            if fail:
                return fail
    finally:
        c.close()
    return None


def row_h2_window_during_pull(srv):
    return streamed_turns(srv, "streamed", None)


def row_h2_window_during_pull_compressed(srv):
    return streamed_turns(srv, "streamed-compressed", "gzip")


def row_h2_tls_pieces(srv):
    def every_frame(conn, sid, received):
        conn.conn.increment_flow_control_window(16384)
        conn.flush()
    for attempt in range(3):
        c = H2(srv.ports["tls"], tls=True)
        try:
            status, got, raw = c.get("/rnd/5000000", "gzip", seconds=20, on_data=every_frame)
        finally:
            c.close()
        if status != 200:
            return f"attempt {attempt + 1}: status {status} after {len(raw)} bytes"
        fail = compare(f"attempt {attempt + 1}", rnd_body(5_000_000), "gzip", got, raw)
        if fail:
            return fail
    return None


def quick(port):
    """The status line of GET /quick over HTTP/1.1, or what went wrong."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(b"GET /quick HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            data = b""
            while True:
                d = s.recv(65536)
                if not d:
                    break
                data += d
    except OSError as e:
        return f"no answer ({e})"
    return data.split(b"\r\n", 1)[0].decode(errors="replace")


def left_h2(srv, site, name, how, coding=None):
    c = H2(srv.ports[site])
    try:
        sid = c.conn.get_next_available_stream_id()
        headers = [(":method", "GET"), (":scheme", "http"), (":authority", "localhost"), (":path", f"/hold/{name}")]
        if coding:
            headers.append(("accept-encoding", coding))
        c.conn.send_headers(sid, headers, end_stream=True)
        c.flush()
        end = time.monotonic() + 5
        got = False
        while not got and time.monotonic() < end:
            for ev in c.conn.receive_data(c.sock.recv(65536)):
                got = got or (isinstance(ev, h2.events.DataReceived) and ev.stream_id == sid)
            c.flush()
        if not got:
            return "no DATA from the event stream"
        left = time.monotonic()
        if how == "reset":
            c.conn.reset_stream(sid)
            c.flush()
        else:
            c.close()
        while name not in HOLD_CLOSED and time.monotonic() < left + 3:
            time.sleep(0.05)
        closed = HOLD_CLOSED.get(name)
        if closed is None or closed - left > 2:
            return f"the origin's connection still open {time.monotonic() - left:.1f} s after the client's {how}"
    finally:
        c.close()
    status = quick(srv.ports[site])
    return None if status.startswith("HTTP/1.1 200") else f"the next request through the slot: {status}"


def row_left_h2_reset(srv):
    return left_h2(srv, "slots", "r", "reset")


def row_left_h2_close(srv):
    return left_h2(srv, "slots", "c", "close")


def row_left_h2_reset_compressed(srv):
    return left_h2(srv, "slots-compressed", "rc", "reset", "gzip")


def row_left_h1_close(srv):
    with socket.create_connection(("127.0.0.1", srv.ports["slots"]), timeout=5) as s:
        s.sendall(b"GET /flood/8 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        data = b""
        while b"\r\n\r\n" not in data or len(data) < 8192:
            d = s.recv(65536)
            if not d:
                break
            data += d
            if b"\r\n\r\n" in data and not data.startswith(b"HTTP/1.1 200"):
                return "the event stream itself: " + data.split(b"\r\n", 1)[0].decode(errors="replace")
    time.sleep(1)  # the origin keeps sending: the server's next write to the client fails
    status = quick(srv.ports["slots"])
    return None if status.startswith("HTTP/1.1 200") else f"the next request through the slot: {status}"


def row_left_h1_quiet(srv):
    with socket.create_connection(("127.0.0.1", srv.ports["slots"]), timeout=5) as s:
        s.sendall(b"GET /hold/h1q HTTP/1.1\r\nHost: localhost\r\n\r\n")
        data = b""
        while b"data: " not in data:  # the head and the first event
            d = s.recv(65536)
            if not d:
                break
            data += d
        if not data.startswith(b"HTTP/1.1 200"):
            return "the event stream itself: " + data.split(b"\r\n", 1)[0].decode(errors="replace")
    left = time.monotonic()  # the origin sends nothing more: only a watch of the client sees it leave
    while "h1q" not in HOLD_CLOSED and time.monotonic() < left + 4:
        time.sleep(0.05)
    closed = HOLD_CLOSED.get("h1q")
    if closed is None or closed - left > 2:
        return f"the origin's connection still open {time.monotonic() - left:.1f} s after the client left"
    status = quick(srv.ports["slots"])
    return None if status.startswith("HTTP/1.1 200") else f"the next request through the slot: {status}"


def row_h1_quiet_stream(srv):
    start = time.monotonic()
    with socket.create_connection(("127.0.0.1", srv.ports["slots"]), timeout=10) as s:
        s.sendall(b"GET /later/5 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        data = b""
        while not data.endswith(b"\r\n0\r\n\r\n"):
            d = s.recv(65536)
            if not d:
                break
            data += d
    if not data.startswith(b"HTTP/1.1 200"):
        return "the event stream itself: " + data.split(b"\r\n", 1)[0].decode(errors="replace")
    if b"data: two" not in data or not data.endswith(b"\r\n0\r\n\r\n"):
        return f"cut after {time.monotonic() - start:.1f} s, before the origin's second event (idle_timeout 3 s)"
    return None


def row_left_h1_cgi(srv):
    for _ in range(3):
        with socket.create_connection(("127.0.0.1", srv.ports["cgi"]), timeout=5) as s:
            s.sendall(b"GET /cgi/linger.cgi HTTP/1.1\r\nHost: localhost\r\n\r\n")
            data = b""
            while not data.endswith(b"\r\n\r\nok"):
                d = s.recv(65536)
                if not d:
                    break
                data += d
        if not data.startswith(b"HTTP/1.1 200"):
            return "the CGI answer: " + data.split(b"\r\n", 1)[0].decode(errors="replace")
    time.sleep(1.5)  # past the exchanges' slow tick and the scripts' end
    if srv.process.poll() is not None:
        return f"the server exited ({srv.process.returncode}) after clients left lingering CGI answers"
    status = quick(srv.ports["slots"])
    return None if status.startswith("HTTP/1.1 200") else f"the next request afterwards: {status}"


def logged(srv, words, seconds=4):
    """The error log's line holding every one of words, waited for; None when none came."""
    end = time.monotonic() + seconds
    while True:
        try:
            for line in srv.error_log.read_text(errors="replace").splitlines():
                if all(w in line for w in words):
                    return line
        except OSError:
            pass
        if time.monotonic() > end:
            return None
        time.sleep(0.1)


def row_cut_h1_logged(srv):
    for port, path, words in ((srv.ports["cut"], "/later/3", ["/later/3", "read_timeout", "(proxy.read_timeout)"]),
                              (srv.ports["cgi"], "/cgi-cut/quiet.cgi", ["/cgi-cut/quiet.cgi", "read_timeout", "(cgi.read_timeout)"])):
        with socket.create_connection(("127.0.0.1", port), timeout=6) as s:
            s.sendall(b"GET " + path.encode() + b" HTTP/1.1\r\nHost: localhost\r\n\r\n")
            data = b""
            while True:
                d = s.recv(65536)
                if not d:
                    break
                data += d
        if not data.startswith(b"HTTP/1.1 200"):
            return f"{path}: " + data.split(b"\r\n", 1)[0].decode(errors="replace")
        if data.endswith(b"\r\n0\r\n\r\n"):
            return f"{path}: the answer ended whole, though its application went quiet past read_timeout"
        line = logged(srv, words)
        if line is None:
            return f"{path}: cut by read_timeout, and no error-log line names it"
        print("  " + line)
    return None


def row_cut_h2_logged(srv):
    c = H2(srv.ports["cut"])
    status, _, _ = c.get("/later/4", seconds=4)
    c.close()
    if not str(status).startswith("reset"):
        return f"/later/4 over h2c: {status}, not a reset, though its origin went quiet past read_timeout"
    line = logged(srv, ["/later/4", "read_timeout", "(proxy.read_timeout)"])
    if line is None:
        return "/later/4 over h2c: cut by read_timeout, and no error-log line names why"
    print("  " + line)
    return None


# ---- HTTP/3: before 0.1.0-alpha.142 every streamed answer was reset with H3_INTERNAL_ERROR after its
# application had run (the alpha.141 report's F1) ----

def rss_kb(pid):
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0


def row_h3_streamed(srv):
    c = H3(srv.ports["h3"])
    try:
        for path, want in (("/rnd/100000", rnd_body(100_000)), ("/rnd/5000000", rnd_body(5_000_000)), ("/pause/3", pause_body(3))):
            st = c.get(path, seconds=20)
            if st["status"] != 200 or not st["ended"]:
                return f"{path}: {h3_text(st)}"
            fail = compare(path, want, None, st["fields"].get("content-encoding"), bytes(st["body"]))
            if fail:
                return fail
            length = st["fields"].get("content-length")
            if path.startswith("/rnd/") and length != str(len(want)):
                return f"{path}: content-length {length} (the origin sent {len(want)})"
            if path.startswith("/pause/") and length is not None:
                return f"{path}: content-length {length} on an answer of unknown length"
    finally:
        c.close()
    return None


def row_h3_cgi(srv):
    for _ in range(3):
        c = H3(srv.ports["h3-cgi"])
        try:
            st = c.get("/cgi/linger.cgi")
        finally:
            c.close()  # the client leaves at once; the script runs on for a second
        if st["status"] != 200 or bytes(st["body"]) != b"ok" or not st["ended"]:
            return "the CGI answer: " + h3_text(st)
    time.sleep(1.5)  # past the exchanges' slow tick and the scripts' end
    if srv.process.poll() is not None:
        return f"the server exited ({srv.process.returncode}) after clients left lingering CGI answers"
    status = quick(srv.ports["slots"])
    return None if status.startswith("HTTP/1.1 200") else f"the next request afterwards: {status}"


def row_h3_quiet_stream(srv):
    c = H3(srv.ports["h3-slots"], idle=3.0)
    start = time.monotonic()
    try:
        st = c.get("/later/5", seconds=10)
    finally:
        c.close()
    if st["status"] != 200:
        return "the event stream itself: " + h3_text(st)
    if b"data: two" not in st["body"] or not st["ended"]:
        why = f"the connection closed (0x{c.terminated.error_code:x})" if c.terminated else h3_text(st)
        return f"cut after {time.monotonic() - start:.1f} s, before the origin's second event (idle timeout 3 s): {why}"
    return None


def row_h3_backpressure(srv):
    c = H3(srv.ports["h3-slots"])
    try:
        st, _ = c.request("/flood/6")
        if not c.pump(5, lambda: len(st["body"]) >= 256 * 1024):
            return "the flood: " + h3_text(st)
        before = rss_kb(srv.process.pid)
        time.sleep(2)  # the client reads and acknowledges nothing; the origin goes on sending
        grown = rss_kb(srv.process.pid) - before
        got = len(st["body"])
        resumed = c.pump(8, lambda: len(st["body"]) >= got + 256 * 1024)
    finally:
        c.close()
    if grown > 32 * 1024:
        return f"the server grew {grown // 1024} MB in 2 s while its client read nothing"
    print(f"  the server's RSS {grown:+d} KB while the client read nothing for 2 s; {len(st['body'])} bytes in all")
    if not resumed:
        return "the answer did not go on once the client read again: " + h3_text(st)
    time.sleep(0.5)
    status = quick(srv.ports["slots"])
    return None if status.startswith("HTTP/1.1 200") else f"the next request through the slot: {status}"


def row_slow_reader_whole(srv):
    """A client that stops reading for 2 s, twice the location's read_timeout (1 s) and under the idle
    timeout (3 s), while its origin has 16 MB (HTTP/1.1, behind a 32 KB receive buffer) or 8 MB (HTTP/2,
    HTTP/3, behind their flow control) to send, gets the whole answer over HTTP/1.1, HTTP/2 and
    HTTP/3: the origin's timer waits while the client holds the answer back. On 0.1.0-alpha.142 each
    was cut at 1 s, and the error log blamed the origin (the alpha.142 report, F3)."""
    want = 128 * (len(b"data: ") + 65536 + 2)
    fails = []
    with socket.socket() as s:  # a small receive buffer and 16 MB, so the kernel's buffers do not hide the pause
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
        s.settimeout(10)
        s.connect(("127.0.0.1", srv.ports["cut"]))
        s.sendall(b"GET /burst/256 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        data, paused = bytearray(), False
        while not data.endswith(b"\r\n0\r\n\r\n"):
            d = s.recv(65536)
            if not d:
                break
            data += d
            if not paused and len(data) >= 1 << 20:
                paused = True
                time.sleep(2)
    if not data.endswith(b"\r\n0\r\n\r\n"):
        fails.append(f"http/1.1: cut after {len(data)} bytes")
    c = H2(srv.ports["cut"])
    paused = []

    def pause(conn, sid, n):
        if not paused and n >= 1 << 20:
            paused.append(n)
            time.sleep(2)

    try:
        status, _, body = c.get("/burst/128", seconds=20, on_data=pause)
    finally:
        c.sock.close()
    if status != 200 or len(body) != want:
        fails.append(f"http/2: {status}, {len(body)} of {want} bytes")
    if QuicConnection is not None:
        c3 = H3(srv.ports["h3-cut"])
        try:
            st, _ = c3.request("/burst/128")
            c3.pump(5, lambda: len(st["body"]) >= 1 << 20 or st["reset"] is not None)
            time.sleep(2)  # nothing read, nothing acknowledged
            c3.pump(20, lambda: st["ended"] or st["reset"] is not None)
        finally:
            c3.close()
        if not st["ended"] or st["reset"] is not None or len(st["body"]) != want:
            fails.append("http/3: " + h3_text(st))
    return "; ".join(fails) or None


def row_h1_stalled_reader(srv):
    """An HTTP/1.1 client that stops reading while its answer streams (16 MB through the one-slot origin,
    whose read_timeout is 60 s): the connection closes at the idle timeout (3 s here) as before, and an
    info line says the client took nothing of the answer, as HTTP/2's and HTTP/3's do. Until
    0.1.0-alpha.143 the close said nothing (the alpha.142 report, F3)."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
    s.settimeout(15)
    try:
        s.connect(("127.0.0.1", srv.ports["slots"]))
        s.sendall(b"GET /burst/256 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        got = 0
        while got < 1 << 20:
            d = s.recv(65536)
            if not d:
                return f"the answer ended after {got} bytes"
            got += len(d)
        time.sleep(6)  # nothing read
        try:
            while s.recv(1 << 20):
                pass
        except (ConnectionResetError, socket.timeout):
            pass
    finally:
        s.close()
    line = logged(srv, ["http1", "/burst/256", "no progress"])
    if line is None:
        return "the client that took nothing was closed, and no line says so"
    print("  " + line)
    time.sleep(0.5)
    status = quick(srv.ports["slots"])
    return None if status.startswith("HTTP/1.1 200") else f"the next request through the slot: {status}"


def row_h3_stalled_reader(srv):
    """A client that acknowledges what arrives (so the server's keep-alive PINGs keep the connection)
    but grants no more credit, on an event stream through the one-slot origin: the answer is cancelled
    within the idle timeout (3 s here) plus a check, the slot comes back. On 0.1.0-alpha.142 nothing but
    the origin's read_timeout (60 s by default) ended it, and once that no longer runs while the client
    holds the answer back (F3), nothing would."""
    c = H3(srv.ports["h3-slots"])
    try:
        c.quic._write_connection_limits = lambda *a, **k: None  # aioquic's MAX_DATA and MAX_STREAM_DATA
        c.quic._write_stream_limits = lambda *a, **k: None
        start = time.monotonic()
        st, _ = c.request("/flood/30")
        c.pump(12, lambda: st["reset"] is not None or st["ended"])
        took = time.monotonic() - start
    finally:
        c.close()
    if st["reset"] != 0x10C:
        return f"after {took:.1f} s: {h3_text(st)}, not cancelled though the client granted no credit"
    if took > 8:
        return f"cancelled after {took:.1f} s (idle_timeout 3 s)"
    print(f"  cancelled after {took:.1f} s, {len(st['body'])} bytes taken")
    line = logged(srv, ["http3", "/flood/30", "no progress"])
    if line is None:
        return "cancelled, and no info line names the client"
    time.sleep(0.5)
    status = quick(srv.ports["slots"])
    return None if status.startswith("HTTP/1.1 200") else f"the next request through the slot: {status}"


def left_h3(srv, name, how):
    c = H3(srv.ports["h3-slots"])
    try:
        st, sid = c.request(f"/hold/{name}")
        if not c.pump(5, lambda: len(st["body"]) > 0):
            return "no DATA from the event stream: " + h3_text(st)
        left = time.monotonic()
        if how == "stop":  # a browser's cancel of a GET: STOP_SENDING with H3_REQUEST_CANCELLED
            c.quic.stop_stream(sid, 0x10C)
            c.pump(0.2)
    finally:
        c.close()  # "close": the connection's CONNECTION_CLOSE
    while name not in HOLD_CLOSED and time.monotonic() < left + 3:
        time.sleep(0.05)
    closed = HOLD_CLOSED.get(name)
    if closed is None or closed - left > 2:
        return f"the origin's connection still open {time.monotonic() - left:.1f} s after the client's {how}"
    status = quick(srv.ports["slots"])
    return None if status.startswith("HTTP/1.1 200") else f"the next request through the slot: {status}"


def row_left_h3_stop(srv):
    return left_h3(srv, "h3s", "stop")


def row_left_h3_close(srv):
    return left_h3(srv, "h3c", "close")


def row_cut_h3_logged(srv):
    for port, path, key in ((srv.ports["h3-cut"], "/later/4", "(proxy.read_timeout)"),
                            (srv.ports["h3-cgi"], "/cgi-cut/quiet.cgi", "(cgi.read_timeout)")):
        c = H3(port)
        try:
            st = c.get(path, seconds=6)
        finally:
            c.close()
        if st["status"] != 200 or not st["body"]:
            return f"{path}: {h3_text(st)}"
        if st["reset"] != 0x10C:
            return f"{path}: {h3_text(st)}, not H3_REQUEST_CANCELLED, though its application went quiet past read_timeout"
        line = logged(srv, ["http3", path, "read_timeout", key])
        if line is None:
            return f"{path}: cut by read_timeout, and no error-log line names it"
        print("  " + line)
    return None


def row_h3_ends_on_time(srv):
    fails = []
    for port, path, how in ((srv.ports["h3-cgi"], "/cgi/ends.cgi", "end"), (srv.ports["h3-slots"], "/gone/300", "reset")):
        c = H3(port)
        start = time.monotonic()
        try:
            st, _ = c.request(path)
            c.pump(5, lambda: st["ended"] or st["reset"] is not None)
            took = time.monotonic() - start
        finally:
            c.close()
        if st["status"] != 200 or b"data: " not in st["body"]:
            fails.append(f"{path}: {h3_text(st)}")
        elif how == "end" and not st["ended"]:
            fails.append(f"{path}: {h3_text(st)}, not ended though the script exited")
        elif how == "reset" and st["reset"] != 0x10C:
            fails.append(f"{path}: {h3_text(st)}, not H3_REQUEST_CANCELLED though the origin closed early")
        elif took > 1.0:
            fails.append(f"{path}: the {how} reached the client {took:.2f} s after the request; the source ended at 0.3 s")
    return "; ".join(fails) or None


def row_h3_compressed_pieces(srv):
    """Answers compressed in pieces over HTTP/3: buffered past the 256 KB whole-answer limit, and
    streamed. Before 0.1.0-alpha.142 HTTP/3 took no streamed body, so these went as they came."""
    c = H3(srv.ports["tls"])
    try:
        for n in (400_000, 1_000_000, 5_000_000):
            for coding in codings():
                st = c.get(f"/rnd/{n}", coding, seconds=20)
                if st["status"] != 200 or not st["ended"]:
                    return f"/rnd/{n} {coding}: {h3_text(st)}"
                fail = compare(f"/rnd/{n} {coding} over HTTP/3", rnd_body(n), coding, st["fields"].get("content-encoding"), bytes(st["body"]))
                if fail:
                    return fail
    finally:
        c.close()
    c = H3(srv.ports["h3-streamed-compressed"])
    try:
        st = c.get("/pause/3", "gzip", seconds=10)
    finally:
        c.close()
    if st["status"] != 200 or not st["ended"]:
        return "/pause/3 gzip: " + h3_text(st)
    return compare("/pause/3 gzip over HTTP/3", pause_body(3), "gzip", st["fields"].get("content-encoding"), bytes(st["body"]))


ROWS = {
    "h2c-pieces": row_h2c_pieces,
    "h2-window-during-pull": row_h2_window_during_pull,
    "h2-window-during-pull-compressed": row_h2_window_during_pull_compressed,
    "h2-tls-pieces": row_h2_tls_pieces,
    "left-h2-reset": row_left_h2_reset,
    "left-h2-close": row_left_h2_close,
    "left-h2-reset-compressed": row_left_h2_reset_compressed,
    "left-h1-close": row_left_h1_close,
    "left-h1-quiet": row_left_h1_quiet,
    "h1-quiet-stream": row_h1_quiet_stream,
    "left-h1-cgi": row_left_h1_cgi,
    "cut-h1-logged": row_cut_h1_logged,
    "cut-h2-logged": row_cut_h2_logged,
    "h3-streamed": row_h3_streamed,
    "h3-cgi": row_h3_cgi,
    "h3-quiet-stream": row_h3_quiet_stream,
    "h3-backpressure": row_h3_backpressure,
    "left-h3-stop": row_left_h3_stop,
    "left-h3-close": row_left_h3_close,
    "cut-h3-logged": row_cut_h3_logged,
    "h3-compressed-pieces": row_h3_compressed_pieces,
    "h3-ends-on-time": row_h3_ends_on_time,
    "h3-stalled-reader": row_h3_stalled_reader,
    "slow-reader-whole": row_slow_reader_whole,
    "h1-stalled-reader": row_h1_stalled_reader,
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
    failed = 0
    with tempfile.TemporaryDirectory(prefix="agensio-h2-streamed-") as directory:
        srv = Server(args.binary, Path(directory))
        try:
            for r in rows:
                if "h3" in r and QuicConnection is None:
                    print(f"{r}: skip (aioquic is not installed)", flush=True)
                    continue
                try:
                    fail = ROWS[r](srv)
                except Exception as e:  # noqa: BLE001: a client that could not do its part fails the row
                    fail = f"client error: {e!r}"
                print(f"{r}: {'ok' if fail is None else 'FAIL ' + fail}", flush=True)
                failed += fail is not None
        finally:
            srv.stop()
    print("all rows passed" if not failed else f"{failed} of {len(rows)} rows failed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
