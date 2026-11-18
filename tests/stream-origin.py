#!/usr/bin/env python3
"""An origin for tests/proxy-streaming.sh: answers of any size in every framing an HTTP/1.1
origin has, written the way the test asks, so the proxy's paths for an answer (whole with its
head, read into the writer's buffer, decoded, read ahead) each meet bodies around their sizes.

  /len/N        Content-Length N; the head, then the body in a write of its own
  /whole/N      the same, head and body in one write
  /chunked/N    chunked, 7,000 bytes a chunk
  /wchunked/N   the same, the head and every chunk in one write
  /close/N      no length: the body ends with the connection
  /slow/N       Content-Length N in ten pieces, 30 ms apart
  /cut/N        declares N, sends half and closes
  /badlen/V     Content-Length V as written (not a number agensio can hold), 10 bytes, closes
  /twolen       two Content-Length fields that disagree (10 and 5), 10 bytes
  /upgrade      a 101 the request did not ask for
  /sha/N        the sha256 of the N-byte body, as text
  /stats        connections accepted so far, as text
usage: stream-origin.py PORT
"""
import hashlib, socket, sys, threading, time

accepted = 0

def body(n):
    block = bytes((i * 7 + i // 251) % 251 for i in range(65536))
    return (block * (n // 65536 + 1))[:n]

def serve(conn):
    buf = b""
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                more = conn.recv(65536)
                if not more:
                    return
                buf += more
            head, buf = buf.split(b"\r\n\r\n", 1)
            line = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ")
            method, target = line[0], line[1]
            parts = target.strip("/").split("/")
            kind = parts[0]
            n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            data = body(n) if method != "HEAD" else b""
            ok = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            if kind == "sha":
                text = hashlib.sha256(body(n)).hexdigest().encode()
                conn.sendall(ok + b"Content-Length: %d\r\n\r\n" % len(text) + text)
            elif kind == "stats":
                text = str(accepted).encode()
                conn.sendall(ok + b"Content-Length: %d\r\n\r\n" % len(text) + text)
            elif kind == "whole":
                conn.sendall(ok + b"Content-Length: %d\r\n\r\n" % n + data)
            elif kind == "len":
                conn.sendall(ok + b"Content-Length: %d\r\n\r\n" % n)
                time.sleep(0.01)
                conn.sendall(data)
            elif kind == "wchunked":
                wire = ok + b"Transfer-Encoding: chunked\r\n\r\n"
                for at in range(0, len(data), 7000):
                    piece = data[at:at + 7000]
                    wire += b"%x\r\n" % len(piece) + piece + b"\r\n"
                conn.sendall(wire + b"0\r\n\r\n")
            elif kind == "chunked":
                conn.sendall(ok + b"Transfer-Encoding: chunked\r\n\r\n")
                time.sleep(0.01)
                for at in range(0, len(data), 7000):
                    piece = data[at:at + 7000]
                    conn.sendall(b"%x\r\n" % len(piece) + piece + b"\r\n")
                conn.sendall(b"0\r\n\r\n")
            elif kind == "close":
                conn.sendall(ok + b"Connection: close\r\n\r\n")
                time.sleep(0.01)
                conn.sendall(data)
                return
            elif kind == "slow":
                conn.sendall(ok + b"Content-Length: %d\r\n\r\n" % n)
                step = max(1, len(data) // 10)
                for at in range(0, len(data), step):
                    time.sleep(0.03)
                    conn.sendall(data[at:at + step])
            elif kind == "cut":
                conn.sendall(ok + b"Content-Length: %d\r\n\r\n" % n)
                time.sleep(0.01)
                conn.sendall(data[:n // 2])
                return
            elif kind == "badlen":
                conn.sendall(ok + b"Content-Length: " + parts[1].encode() + b"\r\n\r\n0123456789")
                return
            elif kind == "twolen":
                conn.sendall(ok + b"Content-Length: 10\r\nContent-Length: 5\r\n\r\n0123456789")
            elif kind == "upgrade":
                conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
                time.sleep(0.2)
                return
            else:
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
    except OSError:
        pass
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()

def main():
    global accepted
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", int(sys.argv[1])))
    srv.listen(512)
    while True:
        conn, _ = srv.accept()
        accepted += 1
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=serve, args=(conn,), daemon=True).start()

main()
