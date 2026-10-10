#!/usr/bin/env python3
"""A small HTTPS origin for the reverse proxy's TLS checks in tests/integration.sh: every answer
carries the Host it received (X-Seen-Host), and .../go/... answers with an absolute redirect to its
own address, the kind the proxy rewrites to the site: to <what came before /go/>/landing, as an
application builds its redirects from the path it was asked.

usage: tests/tls-origin.py PORT CERT KEY
"""
import http.server
import ssl
import sys

port, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        go = self.path.find("/go/")
        if go >= 0:
            self.send_response(302)
            self.send_header("Location", f"https://127.0.0.1:{port}{self.path[:go]}/landing")
            body = b""
        else:
            self.send_response(200)
            body = b"tls origin\n"
        self.send_header("X-Seen-Host", self.headers.get("Host", ""))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
