#!/usr/bin/env python3
"""Opens N HTTP/2 connections (prior knowledge, or --tls) to 127.0.0.1:PORT, makes one GET
on each, then holds them all open for --seconds (default an hour) or until killed. For memory-per-
connection measurements (bench/h2/memory.sh): the server's RSS with N idle connections.
usage: hold.py N PORT [--tls] [--seconds S]
prints "opened N" once every connection has been answered, then waits.
"""
import selectors
import socket
import ssl
import sys
import time

import h2.config
import h2.connection
import h2.events


def main():
    n, port = int(sys.argv[1]), int(sys.argv[2])
    tls = "--tls" in sys.argv
    seconds = float(sys.argv[sys.argv.index("--seconds") + 1]) if "--seconds" in sys.argv else 3600
    ctx = None
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
    conns = []
    for _ in range(n):
        s = socket.create_connection(("127.0.0.1", port))
        if ctx:
            s = ctx.wrap_socket(s, server_hostname="localhost")
        c = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
        c.initiate_connection()
        sid = c.get_next_available_stream_id()
        c.send_headers(sid, [(":method", "GET"), (":path", "/"), (":authority", "localhost"),
                             (":scheme", "https" if tls else "http")], end_stream=True)
        s.sendall(c.data_to_send())
        conns.append((s, c))
    # Wait for every answer (the request makes the connection real on the server: a stream
    # was opened and released), so the sample measures connections that have served once.
    pending = set(range(len(conns)))
    sel = selectors.DefaultSelector()  # epoll: select() stops at 1024 descriptors
    for i, (s, _) in enumerate(conns):
        sel.register(s, selectors.EVENT_READ, i)
    deadline = time.time() + 60
    while pending and time.time() < deadline:
        for key, _ in sel.select(timeout=1):
            i = key.data
            if i not in pending:
                continue
            s = conns[i][0]
            data = s.recv(65536)
            if not data:
                pending.discard(i)
                continue
            for ev in conns[i][1].receive_data(data):
                if isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset)):
                    pending.discard(i)
            out = conns[i][1].data_to_send()
            if out:
                s.sendall(out)
    print("opened", len(conns) - len(pending), flush=True)
    time.sleep(seconds)  # held until the caller kills us or the time is up
    for s, _ in conns:
        s.close()


if __name__ == "__main__":
    main()
