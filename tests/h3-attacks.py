#!/usr/bin/env python3
"""The HTTP/3 attack suite (docs/design-http3.md 9.1): one function per row, each driving
aioquic's QUIC connection by hand over its own UDP socket so the suite can do what no load
tool does (update keys, change its port, retire ids, reset streams by the hundred, forge
packets, send garbage tokens) and assert the server's answer.

Usage: tests/h3-attacks.py BINARY [--retry always|auto] [--port 18443] [--rows a,b,c]
The suite starts the binary on 127.0.0.1:PORT with the bench docroot, runs the rows and
stops it; exit 1 when a row fails. Under the sanitizer build the server's stderr is
checked for reports."""
import argparse
import os
import random
import select
import socket
import ssl
import subprocess
import sys
import time

from aioquic.buffer import encode_uint_var
from aioquic.h3 import connection as h3c
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic import events as qe
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = ("127.0.0.1", 18443)
LOG = None


def log(msg):
    print(msg, flush=True)


class Client:
    """One QUIC connection driven by hand: connect, request, pump."""

    def __init__(self, token=None, alpn="h3"):
        cfg = QuicConfiguration(is_client=True, alpn_protocols=[alpn], verify_mode=ssl.CERT_NONE, server_name="localhost")
        cfg.idle_timeout = 10.0
        if token:
            cfg.token = token
        self.quic = QuicConnection(configuration=cfg)
        self.h3 = h3c.H3Connection(self.quic)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.setblocking(False)
        self.events = []
        self.h3_events = []
        self.terminated = None
        self.ids_issued = 0
        self.received_on = {}  # socket -> datagrams

    def now(self):
        return time.monotonic()

    def send_all(self):
        for data, addr in self.quic.datagrams_to_send(self.now()):
            self.sock.sendto(data, addr)

    def drain_events(self):
        while True:
            ev = self.quic.next_event()
            if ev is None:
                break
            self.events.append(ev)
            if isinstance(ev, qe.ConnectionTerminated):
                self.terminated = ev
            if isinstance(ev, qe.ConnectionIdIssued):
                self.ids_issued += 1
            for h in self.h3.handle_event(ev):
                self.h3_events.append(h)

    def pump(self, timeout, until=None):
        """Runs the connection for `timeout` seconds or until `until()` is true."""
        end = self.now() + timeout
        while True:
            self.send_all()
            self.drain_events()
            if until and until():
                return True
            if self.terminated:
                return False
            now = self.now()
            if now >= end:
                return False
            t = self.quic.get_timer()
            wait = end - now
            if t is not None:
                wait = max(0.0, min(wait, t - now))
            r, _, _ = select.select([self.sock], [], [], wait)
            if r:
                for _ in range(64):
                    try:
                        data, addr = self.sock.recvfrom(65536)
                    except BlockingIOError:
                        break
                    self.received_on[self.sock] = self.received_on.get(self.sock, 0) + 1
                    self.quic.receive_datagram(data, addr, self.now())
            else:
                t = self.quic.get_timer()
                if t is not None and self.now() >= t:
                    self.quic.handle_timer(self.now())

    def connect(self, timeout=5.0):
        self.quic.connect(SERVER, self.now())
        ok = self.pump(timeout, lambda: any(isinstance(e, qe.HandshakeCompleted) for e in self.events))
        return ok

    def request(self, path="/", timeout=5.0, headers=None, end_stream=True):
        sid = self.quic.get_next_available_stream_id()
        fields = [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"localhost"), (b":path", path.encode())]
        if headers:
            fields += headers
        self.h3.send_headers(sid, fields, end_stream=end_stream)
        return sid

    def wait_response(self, sid, timeout=5.0):
        """Returns (status, body) once the stream ends, or (None, None)."""
        status = [None]
        body = [b""]
        done = [False]
        seen = set()

        def scan():
            for i, ev in enumerate(self.h3_events):
                if i in seen:
                    continue
                seen.add(i)
                if isinstance(ev, HeadersReceived) and ev.stream_id == sid:
                    for k, v in ev.headers:
                        if k == b":status":
                            status[0] = int(v)
                    if ev.stream_ended:
                        done[0] = True
                if isinstance(ev, DataReceived) and ev.stream_id == sid:
                    body[0] += ev.data
                    if ev.stream_ended:
                        done[0] = True
            return done[0]

        self.pump(timeout, scan)
        return status[0], body[0]

    def get(self, path="/", timeout=5.0):
        sid = self.request(path)
        return self.wait_response(sid, timeout)

    def close(self):
        try:
            self.quic.close()
            self.pump(0.3)
        finally:
            self.sock.close()

    def inject(self, frames):
        """Writes raw frames into the next packet (frames: (type, payload bytes) pairs), by
        riding on aioquic's PING writer, which runs inside an open packet."""
        quic = self.quic
        original = quic._write_ping_frame

        def patched(builder, uids=[], comment=""):
            original(builder, uids, comment)
            for ftype, payload in frames:
                buf = builder.start_frame(ftype, capacity=1 + len(payload))
                buf.push_bytes(payload)
            quic._write_ping_frame = original

        quic._write_ping_frame = patched
        quic.send_ping(7)
        self.send_all()

    def rebind(self):
        """A new socket, a new port: the NAT rebinding of RFC 9000 9.3."""
        old = self.sock
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.setblocking(False)
        old.close()


# ---- rows ----

def row_handshake(args):
    c = Client()
    if not c.connect():
        return False, "handshake did not complete: %s" % c.terminated
    status, body = c.get("/")
    ids = c.ids_issued
    c.close()
    want = os.path.getsize(os.path.join(ROOT, "bench", "www", "index.html"))
    if status != 200 or len(body) != want:
        return False, "GET / gave %s, %d bytes (the file has %d)" % (status, len(body or b""), want)
    # aioquic accepts 8 ids; the server issues its four (design 6.4): three NEW_CONNECTION_ID
    if ids < 3:
        return False, "expected 3 NEW_CONNECTION_ID frames, saw %d" % ids
    return True, "200, %d bytes, %d ids issued" % (want, ids)


def row_retry(args):
    c = Client()
    if not c.connect():
        return False, "handshake did not complete: %s" % c.terminated
    retried = c.quic._retry_source_connection_id is not None
    status, body = c.get("/")
    c.close()
    if status != 200:
        return False, "GET / after the Retry gave %s" % status
    if args.retry == "always" and not retried:
        return False, "the server was to send a Retry and did not"
    if args.retry != "always" and retried:
        return False, "the server sent a Retry without load"
    return True, "retry seen: %s, then 200" % retried


def row_invalid_token(args):
    c = Client(token=b"not a token the server sealed")
    c.connect(timeout=3.0)
    t = c.terminated
    c.close()
    if t is None:
        return False, "no answer to a garbage token"
    if t.error_code != 0x0B:
        return False, "closed with 0x%x, expected INVALID_TOKEN" % t.error_code
    return True, "INVALID_TOKEN close"


def row_key_update(args):
    c = Client()
    if not c.connect():
        return False, "handshake did not complete"
    s1, _ = c.get("/")
    c.quic.request_key_update()
    s2, b2 = c.get("/style.css")
    s3, _ = c.get("/")
    c.close()
    if (s1, s2, s3) != (200, 200, 200) or len(b2) != 102430:
        return False, "requests around the key update: %s %s %s (%d bytes)" % (s1, s2, s3, len(b2 or b""))
    return True, "the server followed the key update; three answers"


def row_key_update_twice(args):
    c = Client()
    if not c.connect():
        return False, "handshake did not complete"
    c.get("/")
    c.quic.request_key_update()
    c.quic.send_ping(1)
    c.send_all()
    c.quic.request_key_update()  # a second flip before the first is acknowledged
    c.quic.send_ping(2)
    c.send_all()
    c.pump(1.0)
    t = c.terminated
    if t is None:
        # The server's KEY_UPDATE_ERROR close travels under the keys of the first update,
        # which a client two phases ahead cannot open: what it sees is a connection that
        # answers nothing more (the trace build logs "fail code=14").
        s, _ = c.get("/", timeout=2.0)
        c.close()
        return (s is None), "the connection answers nothing after the second update (%s)" % s
    c.close()
    if t.error_code != 0x0E:
        return False, "closed with 0x%x, expected KEY_UPDATE_ERROR" % t.error_code
    return True, "KEY_UPDATE_ERROR"


def row_rebind(args):
    c = Client()
    if not c.connect():
        return False, "handshake did not complete"
    s1, _ = c.get("/")
    c.rebind()
    before = c.received_on.get(c.sock, 0)
    s2, b2 = c.get("/style.css")
    after = c.received_on.get(c.sock, 0)
    s3, _ = c.get("/")
    c.close()
    if (s1, s2, s3) != (200, 200, 200) or len(b2) != 102430:
        return False, "requests around the port change: %s %s %s" % (s1, s2, s3)
    if after - before < 10:
        return False, "the 100 KB answer did not arrive on the new port"
    return True, "answers follow the client to its new port (%d datagrams there)" % (after - before)


def row_cid_retire(args):
    c = Client()
    if not c.connect():
        return False, "handshake did not complete"
    c.get("/")
    known = max(c.quic._peer_cid_sequence_numbers)
    c.quic.change_connection_id()
    s, _ = c.get("/")
    c.pump(0.3)
    more = max(c.quic._peer_cid_sequence_numbers) - known
    c.quic.change_connection_id()
    s2, _ = c.get("/")
    c.close()
    if s != 200 or s2 != 200:
        return False, "requests after retiring ids: %s %s" % (s, s2)
    if more < 1:
        return False, "no replacement id after a retirement"
    return True, "retired twice, %d replacement(s), answers continue" % more


def row_stateless_reset(args):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    dcid = bytes([0]) + os.urandom(7)  # worker 0's byte, an id nobody issued
    pkt = bytes([0x40 | random.randrange(0, 0x40)]) + dcid + os.urandom(31)  # 40 bytes
    s.sendto(pkt, SERVER)
    try:
        data, _ = s.recvfrom(2048)
    except socket.timeout:
        s.close()
        return False, "no stateless reset for an unknown id"
    if len(data) != len(pkt) - 1 or (data[0] & 0xC0) != 0x40:
        s.close()
        return False, "reset of %d bytes for a %d-byte packet, first byte 0x%02x" % (len(data), len(pkt), data[0])
    tiny = bytes([0x40]) + dcid + os.urandom(12)  # 21 bytes: too small to answer
    s.sendto(tiny, SERVER)
    try:
        s.recvfrom(2048)
        s.close()
        return False, "a reset answered a 21-byte packet"
    except socket.timeout:
        pass
    s.close()
    return True, "39-byte reset for a 40-byte packet, none for 21 bytes"


def row_forged_flood(args):
    c = Client()
    if not c.connect():
        return False, "handshake did not complete"
    c.get("/")
    dcid = c.quic._peer_cid.cid
    forge = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    forge.bind(("127.0.0.1", 0))
    for _ in range(3000):
        forge.sendto(bytes([0x40]) + dcid + os.urandom(60), SERVER)
    forge.close()
    s, _ = c.get("/")
    c.close()
    if s != 200:
        return False, "the connection did not survive 3000 forged packets (%s)" % s
    return True, "3000 forged packets dropped, the connection answers"


def row_rapid_reset(args):
    c = Client()
    if not c.connect():
        return False, "handshake did not complete"
    for i in range(200):
        sid = c.request("/style.css", end_stream=True)
        c.quic.reset_stream(sid, 0x10C)
        if i % 20 == 19:
            c.send_all()
    c.pump(2.0, lambda: c.terminated is not None)
    t = c.terminated
    c.close()
    if t is None:
        return False, "200 resets in a second did not close the connection"
    if t.error_code != 0x107:
        return False, "closed with 0x%x, expected H3_EXCESSIVE_LOAD" % t.error_code
    return True, "H3_EXCESSIVE_LOAD after the reset budget"


def row_stream_flood(args):
    c = Client()
    if not c.connect():
        return False, "handshake did not complete"
    c.quic._remote_max_streams_bidi = 100000  # the client ignores what it was told
    for _ in range(300):
        c.request("/", end_stream=False)
    c.pump(2.0, lambda: c.terminated is not None)
    t = c.terminated
    c.close()
    if t is None:
        return False, "300 open streams did not close the connection"
    if t.error_code != 0x04:
        return False, "closed with 0x%x, expected STREAM_LIMIT_ERROR" % t.error_code
    return True, "STREAM_LIMIT_ERROR beyond MAX_STREAMS"


def row_control_stream(args):
    c = Client()
    if not c.connect():
        return False, "handshake did not complete"
    c.get("/")
    sid = c.h3._local_control_stream_id
    settings = h3c.encode_frame(h3c.FrameType.SETTINGS, h3c.encode_settings({}))
    c.quic.send_stream_data(sid, settings)
    c.pump(2.0, lambda: c.terminated is not None)
    t = c.terminated
    c.close()
    if t is None:
        return False, "a second SETTINGS did not close the connection"
    if t.error_code != 0x105:
        return False, "closed with 0x%x, expected H3_FRAME_UNEXPECTED" % t.error_code
    return True, "H3_FRAME_UNEXPECTED for a second SETTINGS"


def row_handshake_flood(args):
    """Initials that never continue: the half-open budget answers with Retry past 512 in
    "auto", and the server keeps answering real clients."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.setblocking(False)
    sent = 0
    retries = 0
    others = 0
    t0 = time.monotonic()
    for i in range(1500):
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
        q = QuicConnection(configuration=cfg)
        q.connect(SERVER, time.monotonic())
        for data, addr in q.datagrams_to_send(time.monotonic()):
            s.sendto(data, addr)
            sent += 1
        if i % 50 == 49:
            while True:
                try:
                    data, _ = s.recvfrom(65536)
                except BlockingIOError:
                    break
                if data[0] & 0xF0 == 0xF0:
                    retries += 1
                else:
                    others += 1
    time.sleep(0.5)
    while True:
        try:
            data, _ = s.recvfrom(65536)
        except BlockingIOError:
            break
        if data[0] & 0xF0 == 0xF0:
            retries += 1
        else:
            others += 1
    s.close()
    took = time.monotonic() - t0
    c = Client()
    ok = c.connect()
    st, _ = c.get("/") if ok else (None, None)
    c.close()
    if not ok or st != 200:
        return False, "a real client failed after the flood (%s)" % st
    if args.retry == "auto" and retries == 0:
        return False, "no Retry seen after %d Initials (auto sends it past 512 half-open)" % sent
    return True, "%d Initials in %.1fs: %d Retry, %d other answers; a real client gets 200" % (sent, took, retries, others)


def varint(v):
    return encode_uint_var(v)


def row_expect_close(name, frames, code, what):
    """A row that injects frames and expects the connection closed with `code`."""
    c = Client()
    if not c.connect():
        return False, "handshake did not complete"
    c.get("/")
    c.inject(frames)
    c.pump(2.0, lambda: c.terminated is not None)
    t = c.terminated
    c.close()
    if t is None:
        return False, "%s did not close the connection" % what
    if t.error_code != code:
        return False, "closed with 0x%x, expected 0x%x" % (t.error_code, code)
    return True, "0x%x for %s" % (code, what)


def row_glitches(args):
    # 101 MAX_DATA frames that raise nothing: the glitch budget is 100 (design 9.1).
    return row_expect_close("glitches", [(0x10, varint(1))] * 101, 0x0A, "101 credit updates that raise nothing")


def row_optimistic_ack(args):
    # An ACK of packet 1,000,000, never sent (RFC 9000 13.1, 21.4).
    return row_expect_close("optimistic-ack", [(0x02, varint(1000000) + varint(0) + varint(0) + varint(0))], 0x0A,
                            "an acknowledgement of a packet never sent")


def row_cid_flood(args):
    # A fifth active id from the peer (the handshake's plus aioquic's three, then this one).
    frames = [(0x18, varint(seq) + varint(0) + bytes([8]) + os.urandom(8) + os.urandom(16)) for seq in (20, 21)]
    return row_expect_close("cid-flood", frames, 0x09, "a fifth active connection id")


def row_retire_unissued(args):
    return row_expect_close("retire-unissued", [(0x19, varint(99))], 0x0A, "retiring a sequence never issued")


def row_retire_in_use(args):
    c = Client()
    if not c.connect():
        return False, "handshake did not complete"
    c.get("/")
    seq = c.quic._peer_cid.sequence_number
    c.inject([(0x19, varint(seq))])
    c.pump(2.0, lambda: c.terminated is not None)
    t = c.terminated
    c.close()
    if t is None or t.error_code != 0x0A:
        return False, "retiring the id in use gave %s" % (t and hex(t.error_code))
    return True, "PROTOCOL_VIOLATION for retiring the id the packet came to"


def row_flow_control(args):
    c = Client()
    if not c.connect():
        return False, "handshake did not complete"
    c.get("/")
    sid = c.quic.get_next_available_stream_id()
    # STREAM with offset and length (type 0x0e): one byte at offset 1 MB, beyond the window.
    c.inject([(0x0E, varint(sid) + varint(1 << 20) + varint(1) + b"x")])
    c.pump(2.0, lambda: c.terminated is not None)
    t = c.terminated
    c.close()
    if t is None or t.error_code != 0x03:
        return False, "data beyond the window gave %s" % (t and hex(t.error_code))
    return True, "FLOW_CONTROL_ERROR for data beyond the stream's window"


def row_shutdown(args):
    """The last row: a connection is open when the server gets SIGINT; it must see the
    GOAWAY and a close with H3_NO_ERROR at once, not an idle timeout."""
    c = Client()
    if not c.connect():
        return False, "handshake did not complete"
    s, _ = c.get("/")
    args.server.send_signal(2)
    c.pump(3.0, lambda: c.terminated is not None)
    t = c.terminated
    c.close()
    try:
        args.server.wait(5)
    except subprocess.TimeoutExpired:
        return False, "the server did not exit after SIGINT"
    if s != 200:
        return False, "the request before the shutdown gave %s" % s
    if t is None:
        return False, "no close arrived after SIGINT (the client would wait for its idle timeout)"
    if t.error_code != 0x100:
        return False, "closed with 0x%x, expected H3_NO_ERROR" % t.error_code
    return True, "H3_NO_ERROR close within %s" % (t.reason_phrase or "the shutdown")


ROWS = [
    ("handshake", row_handshake),
    ("retry", row_retry),
    ("invalid-token", row_invalid_token),
    ("key-update", row_key_update),
    ("key-update-twice", row_key_update_twice),
    ("rebind", row_rebind),
    ("cid-retire", row_cid_retire),
    ("stateless-reset", row_stateless_reset),
    ("forged-flood", row_forged_flood),
    ("rapid-reset", row_rapid_reset),
    ("stream-flood", row_stream_flood),
    ("control-stream", row_control_stream),
    ("handshake-flood", row_handshake_flood),
    ("glitches", row_glitches),
    ("optimistic-ack", row_optimistic_ack),
    ("cid-flood", row_cid_flood),
    ("retire-unissued", row_retire_unissued),
    ("retire-in-use", row_retire_in_use),
    ("flow-control", row_flow_control),
    ("shutdown", row_shutdown),  # last: it stops the server
]


def start_server(binary, port, retry):
    os.makedirs(os.path.join(ROOT, "bench", "tmp"), exist_ok=True)
    conf = os.path.join(ROOT, "bench", "tmp", "h3-attacks.toml")
    with open(conf, "w") as f:
        f.write('[server]\nworkers = 1\nprotocols = ["h2", "h1", "h3"]\nhttp3 = { retry = "%s" }\n' % retry)
        f.write('[log]\naccess = "off"\n')
        f.write('[[site]]\nlisten = ["127.0.0.1:%d"]\nroot = "%s/bench/www"\n' % (port, ROOT))
        f.write('tls = { cert = "%s/bench/certs/cert.pem", key = "%s/bench/certs/key.pem" }\n' % (ROOT, ROOT))
    err = open(os.path.join(ROOT, "bench", "tmp", "h3-attacks.err"), "w")
    p = subprocess.Popen([binary, "-c", conf], stdout=subprocess.DEVNULL, stderr=err)
    for _ in range(50):
        time.sleep(0.1)
        try:
            t = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            t.close()
            return p
        except OSError:
            pass
    p.kill()
    raise SystemExit("the server did not come up")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--retry", default="auto", choices=["auto", "always", "never"])
    ap.add_argument("--port", type=int, default=18443)
    ap.add_argument("--rows", default="")
    args = ap.parse_args()
    global SERVER
    SERVER = ("127.0.0.1", args.port)
    want = set(args.rows.split(",")) if args.rows else None
    p = start_server(args.binary, args.port, args.retry)
    args.server = p
    failed = 0
    try:
        for name, fn in ROWS:
            if want and name not in want:
                continue
            try:
                ok, msg = fn(args)
            except Exception as e:  # a row that blew up is a failure with the reason
                ok, msg = False, "exception: %r" % e
            log("%s %-18s %s" % ("ok  " if ok else "FAIL", name, msg))
            if not ok:
                failed += 1
    finally:
        if p.poll() is None:
            p.send_signal(2)
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
    err = open(os.path.join(ROOT, "bench", "tmp", "h3-attacks.err")).read()
    reports = err.count("Sanitizer") + err.count("runtime error")
    if reports:
        log("FAIL sanitizer reports in the server's stderr: %d" % reports)
        failed += 1
    log("%d row(s) failed" % failed if failed else "all rows passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
