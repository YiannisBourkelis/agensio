#!/usr/bin/env python3
"""Security audit 2026-10-07, section 5 items 1 and 2.

Run inside the Linux devbox: python3 tests/timeout-regressions.py BINARY [--rows a,b]
Rows: h2-stalled,fastcgi,h1-sendfile,cached-tls. Each owns a single-worker server.
Requires python3-h2, openssl and (for fastcgi) php-fpm. Exit 1 on any failed row.
"""
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
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
                if row == "fastcgi":
                    fpm = next((p for name in ("php-fpm8.4", "php-fpm8.3", "php-fpm")
                                if (p := shutil.which(name))), None)
                    assert fpm, "FastCGI regression requires php-fpm"
                    (root / "pause.php").write_text(
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
                        '\n[[site.location]]\npath = "/pause.php"\nmatch = "exact"\n'
                        'handler = "fastcgi"\n'
                        f'fastcgi = {{ socket = "unix:{root}/fpm.sock", buffering = false, '
                        'read_timeout = 20 }\n')
                idle = 15 if row == "cached-tls" else 3
                (root / "agensio.toml").write_text(
                    f'[server]\nworkers = 1\nidle_timeout = {idle}\nprotocols = ["h1", "h2"]\n'
                    f'pid_file = "{root}/agensio.pid"\n'
                    '[cache]\nmax_file_size = "4MB"\nsendfile_min_size = "48KB"\n'
                    '[log]\naccess = "off"\nlevel = "error"\n'
                    f'[[site]]\nserver_name = ["localhost"]\nlisten = ["127.0.0.1:{plain}"]\n'
                    f'root = "{root}"\n'
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


ROWS = {"h2-stalled": h2_stalled, "fastcgi": fastcgi, "h1-sendfile": h1_sendfile, "cached-tls": cached_tls}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--rows", default=",".join(ROWS))
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
