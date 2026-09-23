#!/usr/bin/env python3
"""A small HTTP/2 client on the h2 library, for the integration suite and the attack
scripts: one connection, any number of requests, raw frames where a test needs them.

usage: h2client.py [--tls] [--sni NAME] HOST PORT PATH [AUTHORITY] ...
       prints one line per request: "<status> <bytes> <error-or-->"
       h2client.py --goaway-code ... prints the GOAWAY error code the server sent
Each PATH may be followed by an AUTHORITY (the :authority of that request); the default
is HOST. Requests are sent on one connection, all at once, and answered in any order.
"""
import socket
import ssl
import sys

import h2.config
import h2.connection
import h2.events

CODES = {0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR", 4: "SETTINGS_TIMEOUT",
         5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL", 9: "COMPRESSION_ERROR",
         10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM", 12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED"}


def connect(host, port, tls, sni):
    sock = socket.create_connection((host, port), timeout=10)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        sock = ctx.wrap_socket(sock, server_hostname=sni or host)
        if sock.selected_alpn_protocol() != "h2":
            print("no h2 through ALPN")
            sys.exit(2)
    return sock


def main():
    args = sys.argv[1:]
    tls = goaway = False
    sni = None
    while args and args[0].startswith("--"):
        opt = args.pop(0)
        if opt == "--tls":
            tls = True
        elif opt == "--sni":
            sni = args.pop(0)
        elif opt == "--goaway-code":
            goaway = True
    host, port = args[0], int(args[1])
    rest = args[2:]
    requests = []
    i = 0
    while i < len(rest):
        path = rest[i]
        authority = rest[i + 1] if i + 1 < len(rest) and not rest[i + 1].startswith("/") else host
        i += 2 if authority is not host or (i + 1 < len(rest) and rest[i + 1] == host) else 1
        requests.append((path, authority))
    sock = connect(host, port, tls, sni)
    conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
    conn.initiate_connection()
    streams = {}
    for path, authority in requests:
        sid = conn.get_next_available_stream_id()
        conn.send_headers(sid, [(":method", "GET"), (":path", path), (":authority", authority),
                               (":scheme", "https" if tls else "http")], end_stream=True)
        streams[sid] = {"status": None, "bytes": 0, "error": "-", "done": False}
    sock.sendall(conn.data_to_send())
    goaway_code = None
    while not all(s["done"] for s in streams.values()):
        try:
            data = sock.recv(65536)
        except (ConnectionResetError, socket.timeout, ssl.SSLError):
            break
        if not data:
            break
        for ev in conn.receive_data(data):
            if isinstance(ev, h2.events.ResponseReceived):
                streams[ev.stream_id]["status"] = dict(ev.headers).get(":status")
            elif isinstance(ev, h2.events.DataReceived):
                streams[ev.stream_id]["bytes"] += len(ev.data)
                conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
            elif isinstance(ev, h2.events.StreamEnded):
                streams[ev.stream_id]["done"] = True
            elif isinstance(ev, h2.events.StreamReset):
                streams[ev.stream_id]["error"] = CODES.get(ev.error_code, str(ev.error_code))
                streams[ev.stream_id]["done"] = True
            elif isinstance(ev, h2.events.ConnectionTerminated):
                goaway_code = CODES.get(ev.error_code, str(ev.error_code))
                for s in streams.values():
                    s["done"] = True
        out = conn.data_to_send()
        if out:
            sock.sendall(out)
    if goaway:
        print(goaway_code or "-")
        return
    for sid in sorted(streams):
        s = streams[sid]
        print(s["status"] or "-", s["bytes"], s["error"])


if __name__ == "__main__":
    main()
