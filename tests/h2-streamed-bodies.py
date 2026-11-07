#!/usr/bin/env python3
"""Answers pulled from a source over HTTP/2: whole, in order, and every pull answered.

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
Requires python3-h2 and openssl. Exit 1 on any failed row.
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
    then quiet until the server closes; /flood/S events of 64 KB back to back for S seconds."""

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
        m = re.fullmatch(r"/(hold|flood)/(\w+)", target)
        if not m:
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
        slots = (f'upstream = "http://127.0.0.1:{self.slot_origin.server_address[1]}"\napp = "proxy"\n'
                 'proxy = { buffering = false, max_connections = 1, queue_wait = 2 }\n')
        self.ports = {}
        sites = ""
        for name, extra in (("buffered", 'response_compression = { enabled = true }\n'),
                            ("streamed", 'proxy = { buffering = false }\n'),
                            ("streamed-compressed", 'proxy = { buffering = false }\nresponse_compression = { enabled = true }\n'),
                            ("tls", f'tls = {{ cert = "{root}/cert.pem", key = "{root}/key.pem" }}\nresponse_compression = {{ enabled = true }}\n'),
                            ("slots", None),
                            ("slots-compressed", 'response_compression = { enabled = true, compress_event_streams = true }\n')):
            port = free_port()
            while port in self.ports.values():
                port = free_port()
            self.ports[name] = port
            if name.startswith("slots"):
                sites += f'[[site]]\nserver_name = ["localhost"]\nlisten = ["127.0.0.1:{port}"]\n' + slots + (extra or "")
                continue
            sites += f'[[site]]\nserver_name = ["localhost"]\nlisten = ["127.0.0.1:{port}"]\n' + upstream + extra
        (root / "agensio.toml").write_text(
            '[server]\nworkers = 1\nprotocols = ["h1", "h2", "h2c"]\n'
            f'pid_file = "{root}/agensio.pid"\nstate_dir = "{root}/state"\n'
            f'[log]\naccess = "off"\nerror = "{root}/error.log"\n' + sites)
        self.log = (root / "server.log").open("w+")
        self.process = subprocess.Popen([binary, "-c", str(root / "agensio.toml")], stdout=self.log, stderr=subprocess.STDOUT)
        end = time.monotonic() + 10
        while not all(listening(p) for p in self.ports.values()):
            assert self.process.poll() is None and time.monotonic() < end, "the server did not come up"
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


ROWS = {
    "h2c-pieces": row_h2c_pieces,
    "h2-window-during-pull": row_h2_window_during_pull,
    "h2-window-during-pull-compressed": row_h2_window_during_pull_compressed,
    "h2-tls-pieces": row_h2_tls_pieces,
    "left-h2-reset": row_left_h2_reset,
    "left-h2-close": row_left_h2_close,
    "left-h2-reset-compressed": row_left_h2_reset_compressed,
    "left-h1-close": row_left_h1_close,
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
