#!/usr/bin/env python3
"""A lossy UDP relay between a QUIC client and the server (docs/design-http3.md 9.2): every
datagram, in either direction, is dropped, delayed or reordered at the given rates, so a
transfer that completes through it proves loss detection, probes and retransmission on
both sides with a real client. One upstream socket per client address keeps the server's
view of the client stable.

Usage: tests/quic-lossy.py LISTEN_PORT TARGET_PORT [--loss 0.03] [--reorder 0.05]
       [--delay-ms 3] [--seed 1]
"""
import argparse
import heapq
import random
import select
import socket
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("listen_port", type=int)
    ap.add_argument("target_port", type=int)
    ap.add_argument("--loss", type=float, default=0.03)
    ap.add_argument("--reorder", type=float, default=0.05)
    ap.add_argument("--delay-ms", type=float, default=3.0)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    rnd = random.Random(args.seed)
    target = ("127.0.0.1", args.target_port)
    front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    front.bind(("127.0.0.1", args.listen_port))
    front.setblocking(False)
    up = {}        # client address -> upstream socket
    back = {}      # upstream socket -> client address
    held = []      # (release time, sequence, socket, data, address)
    seq = 0
    stats = {"in": 0, "dropped": 0, "delayed": 0}

    def relay(sock, data, addr):
        nonlocal seq
        stats["in"] += 1
        r = rnd.random()
        if r < args.loss:
            stats["dropped"] += 1
            return
        if r < args.loss + args.reorder:
            stats["delayed"] += 1
            seq += 1
            heapq.heappush(held, (time.monotonic() + rnd.uniform(0, args.delay_ms) / 1000.0, seq, sock, data, addr))
            return
        sock.sendto(data, addr)

    while True:
        timeout = None
        if held:
            timeout = max(0.0, held[0][0] - time.monotonic())
        readable, _, _ = select.select([front] + list(back.keys()), [], [], timeout)
        now = time.monotonic()
        while held and held[0][0] <= now:
            _, _, sock, data, addr = heapq.heappop(held)
            sock.sendto(data, addr)
        for s in readable:
            for _ in range(64):
                try:
                    data, addr = s.recvfrom(65536)
                except BlockingIOError:
                    break
                if s is front:
                    u = up.get(addr)
                    if u is None:
                        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        u.bind(("127.0.0.1", 0))
                        u.setblocking(False)
                        up[addr] = u
                        back[u] = addr
                    relay(u, data, target)
                else:
                    relay(front, data, back[s])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
