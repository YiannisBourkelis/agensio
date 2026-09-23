#!/usr/bin/env python3
"""For tests/reload.sh: one prior-knowledge HTTP/2 connection to 127.0.0.1:PORT, a GET,
then the reload command given after "--", then a GET on the same connection, then a
short wait for a GOAWAY and a close. Prints
    body1 | body2 | goaway or none | closed or open | reload exit code
usage: reload_client.py PORT PATH -- command args...
"""
import socket
import subprocess
import sys
import time

import h2.config
import h2.connection
import h2.events


def main():
    port, path = int(sys.argv[1]), sys.argv[2]
    cmd = sys.argv[sys.argv.index("--") + 1:]
    sock = socket.create_connection(("127.0.0.1", port))
    sock.settimeout(5)
    conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    state = {"goaway": False, "closed": False}

    def pump(data):
        for ev in conn.receive_data(data):
            if isinstance(ev, h2.events.ConnectionTerminated):
                state["goaway"] = True
            yield ev
        out = conn.data_to_send()
        if out:
            sock.sendall(out)

    def get():
        sid = conn.get_next_available_stream_id()
        conn.send_headers(sid, [(":method", "GET"), (":path", path), (":authority", "k"), (":scheme", "http")],
                          end_stream=True)
        sock.sendall(conn.data_to_send())
        body = b""
        while True:
            try:
                data = sock.recv(65536)
            except socket.timeout:
                return "timeout"
            if not data:
                state["closed"] = True
                return body.decode().strip() or "closed"
            done = False
            for ev in pump(data):
                if isinstance(ev, h2.events.DataReceived):
                    body += ev.data
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, h2.events.StreamEnded):
                    done = True
                elif isinstance(ev, h2.events.StreamReset):
                    return "reset"
            if done:
                return body.decode().strip()

    first = get()
    rc = subprocess.run(cmd, capture_output=True).returncode
    time.sleep(0.5)
    second = get()
    # A GOAWAY and a close may follow the answer; wait a little for them.
    sock.settimeout(2)
    for _ in range(2):
        try:
            data = sock.recv(65536)
        except socket.timeout:
            break
        if not data:
            state["closed"] = True
            break
        for _ev in pump(data):
            pass
    print(first, "|", second, "|", "goaway" if state["goaway"] else "none", "|", "closed" if state["closed"] else "open", "|", rc)


if __name__ == "__main__":
    main()
