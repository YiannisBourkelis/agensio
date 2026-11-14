#!/usr/bin/env python3
"""Opens N client connections to 127.0.0.1:PORT, makes one GET on each, and holds them open: the
idle-memory rows of bench/pingora/run.sh. HTTP/1.1 by default, --tls over TLS, --h2 HTTP/2 (with
--tls through ALPN). Prints "opened N" once every connection has been answered, then, --settle
seconds later, "alive K": how many the server still holds open. Then waits until killed.
usage: hold.py N PORT [--tls] [--h2] [--path /json] [--settle 6]
"""
import selectors
import socket
import ssl
import sys
import time


def arg(name, default):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default


def main():
    n, port = int(sys.argv[1]), int(sys.argv[2])
    tls, h2 = "--tls" in sys.argv, "--h2" in sys.argv
    path, settle = arg("--path", "/json"), float(arg("--settle", "6"))
    ctx = None
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"] if h2 else ["http/1.1"])
    if h2:
        import h2.config
        import h2.connection
        import h2.events
    conns = []
    for _ in range(n):
        s = socket.create_connection(("127.0.0.1", port))
        if ctx:
            s = ctx.wrap_socket(s, server_hostname="localhost")
        c = None
        if h2:
            c = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
            c.initiate_connection()
            c.send_headers(c.get_next_available_stream_id(),
                           [(":method", "GET"), (":path", path), (":authority", "127.0.0.1:%d" % port),
                            (":scheme", "https" if tls else "http")], end_stream=True)
            s.sendall(c.data_to_send())
        else:
            s.sendall(("GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % (path, port)).encode())
        conns.append([s, c, b""])
    pending = set(range(n))
    sel = selectors.DefaultSelector()
    for i, (s, _, _) in enumerate(conns):
        sel.register(s, selectors.EVENT_READ, i)
    deadline = time.time() + 120
    while pending and time.time() < deadline:
        for key, _ in sel.select(timeout=1):
            i = key.data
            if i not in pending:
                continue
            s, c, seen = conns[i]
            try:
                data = s.recv(65536)
            except ssl.SSLWantReadError:
                continue
            if not data:
                pending.discard(i)
                continue
            if c:
                for ev in c.receive_data(data):
                    if isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset)):
                        pending.discard(i)
                out = c.data_to_send()
                if out:
                    s.sendall(out)
            else:
                seen += data
                conns[i][2] = seen
                head_end = seen.find(b"\r\n\r\n")
                if head_end < 0:
                    continue
                length = 0
                for line in seen[:head_end].split(b"\r\n")[1:]:
                    k, _, v = line.partition(b":")
                    if k.strip().lower() == b"content-length":
                        length = int(v)
                if len(seen) >= head_end + 4 + length:
                    pending.discard(i)
                    conns[i][2] = b""
    print("opened", n - len(pending), flush=True)
    time.sleep(settle)
    alive = 0
    for s, _, _ in conns:
        s.setblocking(False)
        try:
            data = s.recv(1) if not tls else s.recv(1)
            if data:  # a server's own bytes (an HTTP/2 PING, a TLS ticket) still mean an open connection
                alive += 1
        except (BlockingIOError, ssl.SSLWantReadError):
            alive += 1
        except OSError:
            pass
    print("alive", alive, flush=True)
    time.sleep(3600)


if __name__ == "__main__":
    main()
