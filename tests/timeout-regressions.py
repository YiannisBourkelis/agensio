#!/usr/bin/env python3
"""Security audit 2026-10-07, section 5 timeout, stalled-writer and health checks.

Run inside the Linux devbox: python3 tests/timeout-regressions.py BINARY [--rows a,b]
Rows: h2-stalled,fastcgi,h1-sendfile,cached-tls,h2-idle. Each owns a single-worker server.
h2-idle (audit 2.3) fails on alpha.115 and passes from the fix in alpha.116.
Also h2-header-block; opt-in h2-window-flood measures audit section 5 item 8.
Audit 5 items 12/10: h2-stalled-chatty (held past 21 s before alpha.116's fix), h2-stalled-silent,
h2-goaway-stalled. Item 9: opt-in health-{head,body,h2}-dribble and health-idle.
Requires python3-h2, openssl and (for fastcgi and the body-health rows) php-fpm.
Exit 1 on any failed row.
"""
import argparse
from contextlib import contextmanager, ExitStack
import json
import os
from pathlib import Path
import select
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

import h2.config
import h2.connection
import h2.events
import h2.settings
from hyperframe.frame import HeadersFrame, ContinuationFrame, WindowUpdateFrame


MIB = 1024 * 1024
RATE = 100 * 1024
BLOCK = bytes(range(256)) * 256


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_ready(process, ready):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        assert process.poll() is None, f"process exited with {process.returncode} before readiness"
        if ready():
            return
        time.sleep(0.05)
    raise AssertionError("process did not become ready within 10 s")


def listening(port):
    with socket.socket() as sock:
        sock.settimeout(0.1)
        return sock.connect_ex(("127.0.0.1", port)) == 0


@contextmanager
def server(binary, row):
    with tempfile.TemporaryDirectory(prefix="agensio-timeouts-") as directory:
        root = Path(directory)
        for name, size in (("large.bin", 10 * MIB), ("cached.bin", 2 * MIB), ("index.html", 256)):
            path = root / name
            path.write_bytes((BLOCK * (size // len(BLOCK) + 1))[:size])
            # Current builds deliberately do not cache a file still being written.
            os.utime(path, (time.time() - 10, time.time() - 10))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-keyout", str(root / "key.pem"),
                        "-out", str(root / "cert.pem")], check=True, capture_output=True)
        plain, tls = free_port(), free_port()
        while tls == plain:
            tls = free_port()
        php = None
        process = None
        with (root / "server.log").open("w+") as log, (root / "php.log").open("w+") as php_log:
            try:
                location = ""
                health_row = row.startswith("health-")
                if row in ("fastcgi", "health-body-dribble", "health-h2-dribble"):
                    fpm = next((p for name in ("php-fpm8.4", "php-fpm8.3", "php-fpm")
                                if (p := shutil.which(name))), None)
                    assert fpm, "FastCGI regression requires php-fpm"
                    script = "body.php" if health_row else "pause.php"
                    (root / script).write_text(
                        '<?php $n = strlen(file_get_contents("php://input")); '
                        'header("Content-Length: " . strlen((string)$n)); echo $n;\n' if health_row else
                        '<?php header("Content-Type: application/octet-stream");'
                        'echo str_repeat("a", 65536); flush(); sleep(8);'
                        'echo str_repeat("b", 65536); flush();\n')
                    (root / "fpm.conf").write_text(
                        f"[global]\nerror_log = {root}/php-error.log\ndaemonize = no\n"
                        f"[test]\nlisten = {root}/fpm.sock\npm = static\npm.max_children = 1\n"
                        "php_admin_value[output_buffering] = 0\n"
                        "php_admin_flag[zlib.output_compression] = off\n")
                    php = subprocess.Popen([fpm, "-F", "-y", str(root / "fpm.conf")],
                                           stdout=php_log, stderr=subprocess.STDOUT)
                    wait_ready(php, lambda: (root / "fpm.sock").exists())
                    location = (
                        f'\n[[site.location]]\npath = "/{script}"\nmatch = "exact"\n'
                        'handler = "fastcgi"\n'
                        f'fastcgi = {{ socket = "unix:{root}/fpm.sock", buffering = false, '
                        'read_timeout = 20 }\n')
                idle = 30 if row == "h2-window-flood" else 15 if health_row or row in ("cached-tls", "h2-idle", "h2-header-block") else 3
                protocols = '"h1", "h2", "h2c"' if row in ("h2-idle", "h2-header-block", "h2-window-flood", "health-h2-dribble") else '"h1", "h2"'
                ceiling = 'max_connections = 3\n' if health_row else ""
                control = (f'[control]\nsocket = "{root}/control.sock"\naudit = "{root}/audit.log"\n'
                           'host_protection = "off"\n') if health_row else ""
                level = "info" if row == "h2-goaway-stalled" else "error"
                (root / "agensio.toml").write_text(
                    f'[server]\nworkers = 1\nidle_timeout = {idle}\nprotocols = [{protocols}]\n'
                    f'pid_file = "{root}/agensio.pid"\n' + ceiling + control +
                    '[cache]\nmax_file_size = "4MB"\nsendfile_min_size = "48KB"\n'
                    f'[log]\naccess = "off"\nlevel = "{level}"\n'
                    f'[[site]]\nserver_name = ["localhost"]\nlisten = ["127.0.0.1:{plain}"]\n'
                    f'root = "{root}"\n' + (location if health_row else "") +
                    f'[[site]]\nserver_name = ["localhost"]\nlisten = ["127.0.0.1:{tls}"]\n'
                    f'root = "{root}"\ntls = {{ cert = "{root}/cert.pem", key = "{root}/key.pem" }}\n'
                    + location)
                process = subprocess.Popen([binary, "-c", str(root / "agensio.toml")],
                                           stdout=log, stderr=subprocess.STDOUT)
                wait_ready(process, lambda: listening(plain) and listening(tls))
                yield process, plain, tls
            finally:
                if process is not None:
                    stop(process)
                if php is not None:
                    stop(php)
                log.seek(0)
                output = log.read()
                php_log.seek(0)
                php_output = php_log.read()
                print(output[:4096], end="", flush=True)
                if len(output) > 4096:
                    print("\n... server log truncated ...\n" + output[-4096:], end="", flush=True)
                if php_output:
                    print(php_output, end="", flush=True)
                assert "Sanitizer" not in output and "runtime error:" not in output, "sanitizer report"
                if process is not None:
                    assert process.returncode in (0, -15, -9), f"server exited with {process.returncode}"


def connect(port, protocol=None):
    sock = socket.socket()
    sock.settimeout(3)
    # Set before connect: the TCP window scale is negotiated in the SYN.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    # Keep segments below the receive window, rather than loopback's jumbo MSS:
    # its large send queue can mask the old timeout or delay a fixed writer's wakeup.
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1024)
    try:
        sock.connect(("127.0.0.1", port))
        if protocol:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols([protocol])
            sock = ctx.wrap_socket(sock, server_hostname="localhost")
            assert sock.selected_alpn_protocol() == protocol, "wrong ALPN"
        return sock
    except (OSError, AssertionError):
        sock.close()
        raise


def h1_head(sock, path):
    sock.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
    head = bytearray()
    deadline = time.monotonic() + 3
    while not head.endswith(b"\r\n\r\n"):
        assert len(head) < 16384 and time.monotonic() < deadline, "response head exceeded bounds"
        data = sock.recv(1)
        assert data, "EOF before response head"
        head.extend(data)
    assert head.startswith(b"HTTP/1.1 200 "), f"unexpected status: {head!r}"
    return dict(line.lower().split(b":", 1) for line in bytes(head).split(b"\r\n")[1:] if b":" in line)


def cpu_seconds(process):
    fields = Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def worker_available(process, port):
    before = cpu_seconds(process)
    time.sleep(1)
    cpu = cpu_seconds(process) - before
    started = time.monotonic()
    print(f"  idle sample: {cpu:.3f} CPU s / 1 s", flush=True)
    with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
        h1_head(sock, "/")
        body = bytearray()
        while len(body) < 256:
            data = sock.recv(256 - len(body))
            assert data, "probe body truncated"
            body.extend(data)
    elapsed = time.monotonic() - started
    assert body == BLOCK[:256], "wrong probe body"
    assert elapsed < 1, f"plain probe took {elapsed:.3f} s (limit 1 s)"
    assert cpu < 0.2, f"worker spinning: {cpu:.3f} CPU s / 1 s (limit 0.2)"
    print(f"  plain probe: {elapsed:.3f} s", flush=True)


def h2_start(sock, path):
    conn = h2.connection.H2Connection(config=h2.config.H2Configuration(header_encoding="utf-8"))
    conn.initiate_connection()
    conn.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 2**31 - 1})
    conn.increment_flow_control_window(2**31 - 1 - 65535)
    conn.send_headers(1, [(":method", "GET"), (":scheme", "https"),
                          (":authority", "localhost"), (":path", path)], end_stream=True)
    sock.sendall(conn.data_to_send())
    return conn


def h2_read(sock, conn, body):
    data = sock.recv(16384)
    assert data, f"HTTP/2 EOF after {len(body)} bytes"
    ended = False
    for event in conn.receive_data(data):
        if isinstance(event, h2.events.ResponseReceived):
            assert dict(event.headers)[":status"] == "200", str(event.headers)
        elif isinstance(event, h2.events.DataReceived):
            body.extend(event.data)
        elif isinstance(event, h2.events.StreamEnded):
            ended = True
        elif isinstance(event, (h2.events.StreamReset, h2.events.ConnectionTerminated)):
            raise AssertionError(f"HTTP/2 cut after {len(body)} bytes: {event}")
    pending = conn.data_to_send()
    if pending:
        sock.sendall(pending)
    return ended


def h2_stalled(process, plain, tls):
    with connect(tls, "h2") as sock:
        conn = h2_start(sock, "/large.bin")
        body = bytearray()
        deadline = time.monotonic() + 3
        while not body:
            assert time.monotonic() < deadline, "no initial HTTP/2 DATA"
            assert not h2_read(sock, conn, body), "large response already ended"
        print(f"  stopping reads after {len(body)} bytes; both h2 windows = 2^31-1", flush=True)
        time.sleep(4)
        worker_available(process, plain)
        worker_available(process, plain)
        worker_available(process, plain)


def server_socket(process, sock):
    local = f"0100007F:{sock.getpeername()[1]:04X}"
    remote = f"0100007F:{sock.getsockname()[1]:04X}"
    for line in Path(f"/proc/{process.pid}/net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        if fields[1:3] == [local, remote] and fields[9] != "0":
            return fields[9], int(fields[4].split(":")[0], 16)
    return None, 0


def owns_socket(process, inode):
    # FIN/EOF may sit behind unread TLS records. Observe close without draining them.
    for fd in Path(f"/proc/{process.pid}/fd").iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue  # the probe's socket can close between listing and readlink
        if target == f"socket:[{inode}]":
            return True
    return False


def h2_stalled_deadline(process, plain, tls, *, chatty=False, error=False):
    with connect(tls, "h2") as sock:
        conn = h2_start(sock, "/large.bin")
        body = bytearray()
        deadline = time.monotonic() + 3
        while not body:
            assert time.monotonic() < deadline, "no initial DATA"
            assert not h2_read(sock, conn, body), "response already finished"
        started = time.monotonic()
        inode, _ = server_socket(process, sock)
        assert inode and owns_socket(process, inode), "accepted server socket not found"
        print(f"  last read: {len(body)} body bytes, socket inode={inode}, idle_timeout=3", flush=True)
        worker_available(process, plain)
        _, queued = server_socket(process, sock)
        assert queued > sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF), (
            f"fixture did not fill the small receive window: tx_queue={queued}")
        print(f"  unread server TCP send queue: {queued} bytes", flush=True)
        if error:
            # RFC 9113 6.9: zero increment on stream 0 is a connection PROTOCOL_ERROR.
            sock.sendall(WindowUpdateFrame(0, window_increment=0).serialize())
        closed = None
        sent = []
        while time.monotonic() < started + 20.2:
            if not owns_socket(process, inode):
                closed = time.monotonic() - started
                break
            if chatty and time.monotonic() >= started + 5 * (len(sent) + 1):
                conn.ping(b"stalled!")
                try:
                    sock.sendall(conn.data_to_send())
                except OSError:
                    if owns_socket(process, inode):
                        raise
                    closed = time.monotonic() - started
                    break
                sent.append(round(time.monotonic() - started, 3))
            worker_available(process, plain)
        age = time.monotonic() - started
        still_owned = owns_socket(process, inode)
        if closed is None and not still_owned:
            closed = age
        print(f"  deadline: closed={closed}, observed_age={age:.3f}, "
              f"server_socket_owned={still_owned}, PING ages={sent}", flush=True)
        if error:
            output = (Path(process.args[-1]).parent / "server.log").read_text()
            reason = "closing, PROTOCOL_ERROR: WINDOW_UPDATE of zero on the connection"
            assert reason in output, "missing info log for the intended connection error"
            print("  info log: " + reason, flush=True)
            # Only after checking the deadline may the client drain its queued records.
            goaway = None
            finish = "read deadline"
            end = time.monotonic() + 3
            drained = 0
            sock.settimeout(0.2)
            while not still_owned and time.monotonic() < end and drained < 10 * MIB:
                try:
                    data = sock.recv(65536)
                except socket.timeout:
                    continue
                except (ConnectionResetError, ssl.SSLError) as exc:
                    finish = type(exc).__name__ + ": " + str(exc)
                    break
                if not data:
                    finish = "EOF"
                    break
                drained += len(data)
                for ev in conn.receive_data(data):
                    if isinstance(ev, h2.events.ConnectionTerminated):
                        goaway = int(ev.error_code)
            print(f"  post-deadline drain: {drained} bytes, GOAWAY={goaway}, {finish}", flush=True)
            assert goaway in (None, 1), f"wrong GOAWAY error: {goaway}"
        assert closed is not None and closed <= 15, "writer not closed within 4 * idle_timeout + 3 s"


def h2_stalled_silent(process, plain, tls):
    h2_stalled_deadline(process, plain, tls)


def h2_stalled_chatty(process, plain, tls):
    h2_stalled_deadline(process, plain, tls, chatty=True)


def h2_goaway_stalled(process, plain, tls):
    h2_stalled_deadline(process, plain, tls, chatty=True, error=True)


def control_json(process, command):
    result = subprocess.run([process.args[0], "ctl", command, "--socket",
                             str(Path(process.args[-1]).parent / "control.sock")],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, f"ctl {command}: {result.stderr}\n{result.stdout}"
    return json.loads(result.stdout)


def read_h1_response(sock):
    head = bytearray()
    end = time.monotonic() + 3
    while not head.endswith(b"\r\n\r\n"):
        assert len(head) < 16384 and time.monotonic() < end, "response head exceeded bounds"
        data = sock.recv(1)
        assert data, "EOF in response head"
        head.extend(data)
    if head.startswith(b"HTTP/1.1 100 "):
        return 100, b""
    assert head.startswith(b"HTTP/1.1 200 "), f"unexpected response: {head!r}"
    headers = dict(line.lower().split(b":", 1) for line in bytes(head).split(b"\r\n")[1:] if b":" in line)
    assert b"content-length" in headers, f"expected a sized fixture response: {head!r}"
    size = int(headers[b"content-length"])
    assert size <= 4096, f"unexpected body length {size}"
    body = bytearray()
    while len(body) < size:
        assert time.monotonic() < end, "response body exceeded deadline"
        data = sock.recv(size - len(body))
        assert data, "truncated response body"
        body.extend(data)
    return 200, bytes(body)


def health_shape(process, plain, tls, shape):
    deadline = time.monotonic() + 5
    while True:
        baseline = control_json(process, "status")
        if baseline["connections"] == 1:
            break
        assert time.monotonic() < deadline, "readiness connections did not retire"
        time.sleep(0.05)
    assert baseline["connections_refused"] == 0, "refusals before the fixture"
    with ExitStack() as stack:
        clients = [stack.enter_context(socket.create_connection(("127.0.0.1", plain), timeout=3))
                   for _ in range(3)]
        h2_clients = []
        for sock in clients:
            if shape == "idle":
                sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                assert read_h1_response(sock) == (200, BLOCK[:256])
            elif shape == "body":
                sock.sendall(b"POST /body.php HTTP/1.1\r\nHost: localhost\r\n"
                             b"Content-Length: 1000000\r\nContent-Type: application/octet-stream\r\n"
                             b"Expect: 100-continue\r\n\r\n")
                assert read_h1_response(sock) == (100, b""), "handler did not start reading the body"
            elif shape == "h2":
                conn = h2_ready(sock)
                conn.send_headers(1, [(":method", "POST"), (":scheme", "http"),
                                     (":authority", "localhost"), (":path", "/body.php"),
                                     ("content-length", "1000000"), ("content-type", "application/octet-stream")])
                sock.sendall(conn.data_to_send())
                h2_clients.append(conn)
        started = time.monotonic()
        if shape == "idle":
            time.sleep(3)
        else:
            for tick in range(4):
                time.sleep(max(0, started + tick * 2 - time.monotonic()))
                for i, sock in enumerate(clients):
                    if shape == "h2":
                        h2_clients[i].send_data(1, b"x")
                        sock.sendall(h2_clients[i].data_to_send())
                    else:
                        sock.sendall(b"GET "[tick:tick + 1] if shape == "head" else b"x")
            print(f"  {shape}: four one-byte drips per client at 0/2/4/6 s", flush=True)
        for last in range(2, 6):
            address = f"127.0.0.{last}"
            with socket.socket() as refused:
                refused.settimeout(2)
                refused.bind((address, 0))
                refused.connect(("127.0.0.1", plain))
                reply = bytearray()
                while len(reply) < 4096:
                    part = refused.recv(4096 - len(reply))
                    if not part:
                        break
                    reply.extend(part)
                assert reply.startswith(b"HTTP/1.1 503 ") and b"retry-after:" in reply.lower(), repr(reply)
                assert len(reply) < 4096, "refusal did not close within response bound"
                print(f"  refusal from {address}: 503, Retry-After, EOF", flush=True)
        status = control_json(process, "status")
        print("  status: " + json.dumps({k: status[k] for k in
              ("connections", "connections_idle", "connections_refused")}, sort_keys=True), flush=True)
        assert status["connections"] - baseline["connections"] == 3, "fixture lost a held connection"
        assert status["connections_refused"] == 4, "wrong refusal count"
        health = control_json(process, "health")
        findings = [f for f in health["findings"] if f["code"] == "connections_refused"]
        assert len(findings) == 1, "missing or duplicate refusal finding"
        print("  health: " + json.dumps(findings[0], sort_keys=True), flush=True)
        if shape == "idle":
            assert status["connections_idle"] == 3, "silent completed requests not counted idle"
            assert "full of idle connections" in findings[0]["fix"], "wrong idle control diagnosis"
        # Finish one body after observing health: prove the configured handler actually
        # consumes the declared body, rather than answering early and discarding DATA.
        if shape == "body":
            clients[0].sendall(b"x" * (1000000 - 4))
            assert read_h1_response(clients[0]) == (200, b"1000000")
            print("  body reader verified: PHP received 1000000 bytes", flush=True)
        elif shape == "h2":
            sock, conn = clients[0], h2_clients[0]
            remaining = 1000000 - 4
            body = bytearray()
            ended = False
            end = time.monotonic() + 5
            while not ended:
                assert time.monotonic() < end, "body completion exceeded 5 s"
                while remaining and conn.local_flow_control_window(1) > 0:
                    size = min(remaining, conn.local_flow_control_window(1), conn.max_outbound_frame_size)
                    remaining -= size
                    conn.send_data(1, b"x" * size, end_stream=remaining == 0)
                sock.sendall(conn.data_to_send())
                data = sock.recv(65536)
                assert data, "EOF before body reader completed"
                for ev in conn.receive_data(data):
                    if isinstance(ev, h2.events.ResponseReceived):
                        assert dict(ev.headers)[b":status"] == b"200", str(ev)
                    elif isinstance(ev, h2.events.DataReceived):
                        body.extend(ev.data)
                    elif isinstance(ev, h2.events.StreamEnded):
                        ended = True
                    assert not isinstance(ev, (h2.events.StreamReset, h2.events.ConnectionTerminated)), str(ev)
            assert body == b"1000000" and remaining == 0, repr(body)
            print("  DATA reader verified: PHP received 1000000 bytes", flush=True)


def health_head_dribble(process, plain, tls):
    health_shape(process, plain, tls, "head")


def health_body_dribble(process, plain, tls):
    health_shape(process, plain, tls, "body")


def health_h2_dribble(process, plain, tls):
    health_shape(process, plain, tls, "h2")


def health_idle(process, plain, tls):
    health_shape(process, plain, tls, "idle")


def fastcgi(process, plain, tls):
    with connect(tls, "h2") as sock:
        conn = h2_start(sock, "/pause.php")
        body = bytearray()
        started = time.monotonic()
        deadline = started + 3
        while len(body) < 65536:
            assert time.monotonic() < deadline, "FastCGI first print was buffered"
            assert not h2_read(sock, conn, body), "FastCGI ended before its pause"
        assert body == b"a" * 65536, "wrong FastCGI first print"
        time.sleep(4)
        worker_available(process, plain)
        worker_available(process, plain)
        deadline = started + 15
        while True:
            assert time.monotonic() < deadline, "FastCGI did not finish within 15 s"
            if h2_read(sock, conn, body):
                break
        assert body == b"a" * 65536 + b"b" * 65536, f"FastCGI truncated: {len(body)} bytes"
        elapsed = time.monotonic() - started
        assert elapsed >= 8, f"FastCGI pause missing: {elapsed:.3f} s"
        print(f"  FastCGI complete: {len(body)} bytes in {elapsed:.3f} s", flush=True)


def h1_sendfile(process, plain, tls):
    with connect(plain) as sock:
        head = h1_head(sock, "/large.bin")
        assert int(head[b"content-length"]) == 10 * MIB, "wrong sendfile size"
        assert sock.recv(1) == BLOCK[:1], "no initial sendfile body"
        time.sleep(4)
        worker_available(process, plain)
        worker_available(process, plain)
        worker_available(process, plain)


def cached_tls(process, plain, tls):
    with connect(tls, "http/1.1") as sock:
        head = h1_head(sock, "/cached.bin")
        assert int(head[b"content-length"]) == 2 * MIB, "wrong Content-Length"
        assert b"no-store" not in head.get(b"cache-control", b""), "file is not cacheable"
        body = bytearray()
        started = time.monotonic()
        while len(body) < 2 * MIB:
            delay = started + (len(body) + 4096) / RATE - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            assert time.monotonic() - started < 30, "slow reader exceeded 30 s"
            data = sock.recv(min(4096, 2 * MIB - len(body)))
            assert data, f"cached TLS truncated: {len(body)}/{2 * MIB} bytes after {time.monotonic() - started:.3f} s"
            body.extend(data)
        elapsed = time.monotonic() - started
        assert elapsed >= 2 * MIB / RATE, f"reader exceeded 100 KiB/s: {elapsed:.3f} s"
        assert body == BLOCK * 32, "cached TLS body differs from file"
        print(f"  cached TLS complete: {len(body)} bytes in {elapsed:.3f} s at 100 KiB/s", flush=True)


def h2_idle(process, plain, tls):
    with ExitStack() as stack:
        clients = []
        for name in ("settings-dribble", "preface-dribble", "preface-silent"):
            sock = stack.enter_context(connect(plain))
            conn = h2.connection.H2Connection()
            conn.initiate_connection()
            preface = conn.data_to_send()
            # RFC 9113 3.4: the 24-byte magic alone deliberately omits SETTINGS.
            sock.sendall(preface if name == "settings-dribble" else preface[:24])
            if name == "settings-dribble":
                settings = ack = False
                deadline = time.monotonic() + 3
                while not (settings and ack):
                    assert time.monotonic() < deadline, "HTTP/2 SETTINGS exchange exceeded 3 s"
                    data = sock.recv(65536)
                    assert data, "EOF during HTTP/2 SETTINGS exchange"
                    for event in conn.receive_data(data):
                        settings |= isinstance(event, h2.events.RemoteSettingsChanged)
                        ack |= isinstance(event, h2.events.SettingsAcknowledged)
                        assert not isinstance(event, h2.events.ConnectionTerminated), str(event)
                    pending = conn.data_to_send()
                    if pending:
                        sock.sendall(pending)
                assert conn.open_outbound_streams == 0 and conn.open_inbound_streams == 0
                conn.ping(b"idleping")
                fragment = conn.data_to_send()
            else:
                fragment = preface[24:]  # dribble the required first SETTINGS, not an invalid frame
            sock.setblocking(False)
            clients.append({"name": name, "sock": sock, "started": time.monotonic(),
                            "fragment": fragment, "sent": 0, "closed": None})

        end = max(c["started"] for c in clients) + 17
        while time.monotonic() < end and any(c["closed"] is None for c in clients):
            for c in clients:
                if c["closed"] is None and c["name"] != "preface-silent":
                    if time.monotonic() >= c["started"] + 14 * (c["sent"] + 1):
                        try:
                            c["sock"].sendall(c["fragment"][c["sent"]:c["sent"] + 1])
                        except (BrokenPipeError, ConnectionResetError):
                            c["closed"] = time.monotonic() - c["started"]
                        else:
                            c["sent"] += 1
            pending = [c["sock"] for c in clients if c["closed"] is None]
            if not pending:
                break
            ready, _, _ = select.select(pending, [], [], min(0.05, max(0, end - time.monotonic())))
            for c in clients:
                if c["sock"] in ready:
                    try:
                        data = c["sock"].recv(65536)
                    except ConnectionResetError:
                        data = b""
                    if not data:
                        c["closed"] = time.monotonic() - c["started"]

        failures = []
        for c in clients:
            age = c["closed"]
            good = age is not None and 14.5 <= age <= 16
            state = "still open at 17 s" if age is None else f"closed at {age:.3f} s"
            if c["name"] != "preface-silent" and c["sent"] != 1:
                good = False
            print(f"  {'PASS' if good else 'FAIL'} {c['name']}: {state}; "
                  f"{c['sent']} frame bytes sent, expected close at 15 s (1 s tolerance)", flush=True)
            if not good:
                failures.append(c["name"])
        worker_available(process, plain)
        assert not failures, "HTTP/2 idle deadline: " + ", ".join(failures)


def h2_ready(sock, streams=0):
    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    if streams:
        conn.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 0})
    sock.sendall(conn.data_to_send())
    settings = ack = False
    deadline = time.monotonic() + 3
    while not (settings and ack):
        assert time.monotonic() < deadline, "SETTINGS exchange exceeded 3 s"
        data = sock.recv(65536)
        assert data, "EOF during SETTINGS"
        for ev in conn.receive_data(data):
            settings |= isinstance(ev, h2.events.RemoteSettingsChanged)
            ack |= isinstance(ev, h2.events.SettingsAcknowledged)
            assert not isinstance(ev, h2.events.ConnectionTerminated), str(ev)
        sock.sendall(conn.data_to_send())
    for i in range(streams):
        conn.send_headers(2 * i + 1, [(":method", "GET"), (":scheme", "http"),
                                     (":authority", "localhost"), (":path", "/large.bin")], end_stream=True)
    sock.sendall(conn.data_to_send())
    answered = set()
    while len(answered) < streams:
        assert time.monotonic() < deadline, "stream setup exceeded 3 s"
        data = sock.recv(65536)
        assert data, "EOF during stream setup"
        for ev in conn.receive_data(data):
            if isinstance(ev, h2.events.ResponseReceived):
                assert dict(ev.headers)[b":status"] == b"200", str(ev.headers)
                answered.add(ev.stream_id)
            assert not isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset,
                                       h2.events.ConnectionTerminated, h2.events.DataReceived)), str(ev)
        sock.sendall(conn.data_to_send())
    assert conn.open_outbound_streams == streams
    return conn


def h2_header_block(process, plain, tls):
    with connect(plain) as sock:
        conn = h2_ready(sock)
        block = conn.encoder.encode([(":method", "GET"), (":scheme", "http"), (":authority", "localhost"),
                                     (":path", "/"), ("x-padding", "a" * 64)], huffman=False)
        head = HeadersFrame(1)
        head.flags.add("END_STREAM")
        head.data = block[:1]
        started = time.monotonic()
        sock.sendall(head.serialize())  # no END_HEADERS: agensio has not allocated a stream yet
        sock.setblocking(False)
        sent = 0
        goaway = closed = None
        while time.monotonic() < started + 18:
            now = time.monotonic()
            if goaway is None and now >= started + 4 * (sent + 1):
                # RFC 9113 6.10: only CONTINUATION may follow. Stay below the eight-frame
                # and compressed-size budgets, and refresh frame progress, not just reads.
                frame = ContinuationFrame(1)
                frame.data = block[sent + 1:sent + 2]
                sock.sendall(frame.serialize())
                sent += 1
            ready, _, _ = select.select([sock], [], [], 0.05)
            if ready:
                data = sock.recv(65536)
                if not data:
                    closed = time.monotonic() - started
                    break
                for ev in conn.receive_data(data):
                    if isinstance(ev, h2.events.ConnectionTerminated):
                        goaway = (ev, time.monotonic() - started)
                    assert not isinstance(ev, (h2.events.ResponseReceived, h2.events.StreamReset)), str(ev)
        print(f"  header block: {sent} nonempty CONTINUATION frames; GOAWAY={goaway}; EOF={closed}", flush=True)
        assert goaway is not None, "no GOAWAY by 18 s despite an unfinished header block"
        event, age = goaway
        assert event.error_code == 11 and event.additional_data == b"header block not completed in time", str(event)
        assert 14.5 <= age <= 17 and closed is not None and closed <= 18, "wrong block deadline or missing EOF"
        assert sent >= 3, "fixture did not maintain frame-level progress"
    worker_available(process, plain)


def h2_window_flood(process, plain, tls):
    def barrier(sock, conn, expect_cut=False):
        conn.ping(b"progress")
        sock.sendall(conn.data_to_send())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            data = sock.recv(65536)
            assert data, "EOF before flood barrier"
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.ConnectionTerminated):
                    assert expect_cut and ev.error_code == 11, str(ev)
                    return
                assert not isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset, h2.events.DataReceived)), str(ev)
                if isinstance(ev, h2.events.PingAckReceived) and ev.ping_data == b"progress":
                    assert not expect_cut, "1023-byte WINDOW_UPDATE bypassed the glitch budget"
                    return
        raise AssertionError("flood barrier exceeded 5 s")

    with socket.create_connection(("127.0.0.1", plain), timeout=5) as sock:
        conn = h2_ready(sock, 128)
        small = WindowUpdateFrame(0, window_increment=1023).serialize()
        sock.sendall(small * 256)
        barrier(sock, conn, expect_cut=True)
        print("  control: 1023-byte updates get GOAWAY(ENHANCE_YOUR_CALM)", flush=True)

    frame = WindowUpdateFrame(0, window_increment=1024).serialize()
    batch = frame * 4096
    for streams in (0, 128, 128, 0):
        started = time.monotonic()
        cpu = cpu_seconds(process)
        count = rotations = 0
        while time.monotonic() - started < 3:
            with socket.create_connection(("127.0.0.1", plain), timeout=5) as sock:
                conn = h2_ready(sock, streams)
                # RFC 9113 6.9.1: rotate below 2^31-1, rather than measuring the
                # overflow close. The PING ACK proves every preceding update ran.
                for _ in range(244):
                    sock.sendall(batch)
                barrier(sock, conn)
                assert conn.open_outbound_streams == streams, "streams disappeared during the sample"
                count += 244 * 4096
                rotations += 1
        elapsed = time.monotonic() - started
        used = cpu_seconds(process) - cpu
        print(f"  WINDOW_UPDATE streams={streams} frames={count} connections={rotations} "
              f"wall_s={elapsed:.3f} cpu_s={used:.3f} cpu_s_per_s={used / elapsed:.3f} "
              f"cpu_ns_per_frame={used * 1e9 / count:.1f} frames_per_s={count / elapsed:.0f}", flush=True)
    worker_available(process, plain)


ROWS = {"h2-stalled": h2_stalled, "fastcgi": fastcgi, "h1-sendfile": h1_sendfile,
        "cached-tls": cached_tls, "h2-idle": h2_idle, "h2-header-block": h2_header_block,
        "h2-window-flood": h2_window_flood, "h2-stalled-silent": h2_stalled_silent,
        "h2-stalled-chatty": h2_stalled_chatty, "h2-goaway-stalled": h2_goaway_stalled,
        "health-head-dribble": health_head_dribble, "health-body-dribble": health_body_dribble,
        "health-h2-dribble": health_h2_dribble, "health-idle": health_idle}
OPT_IN = {"h2-window-flood", "health-head-dribble", "health-body-dribble",
          "health-h2-dribble", "health-idle"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--rows", default=",".join(row for row in ROWS if row not in OPT_IN),
                        help="comma-separated rows; opt-in: " + ",".join(sorted(OPT_IN)))
    args = parser.parse_args()
    rows = args.rows.split(",")
    if any(row not in ROWS for row in rows):
        parser.error(f"rows must be chosen from {','.join(ROWS)}")
    if not Path("/proc/self/stat").exists():
        parser.error("run inside the Linux devbox (CPU assertions require /proc)")
    binary = str(Path(args.binary).resolve())
    failed = []
    for row in rows:
        print(f"RUN {row}", flush=True)
        try:
            with server(binary, row) as instance:
                ROWS[row](*instance)
        except (AssertionError, OSError, subprocess.SubprocessError) as error:
            print(f"FAIL {row}: {error}", flush=True)
            failed.append(row)
        else:
            print(f"PASS {row}", flush=True)
    print(f"timeout regressions: {len(rows) - len(failed)}/{len(rows)} passed", flush=True)
    return bool(failed)


if __name__ == "__main__":
    raise SystemExit(main())
