#!/usr/bin/env python3
"""WebSocket-shaped echo load through a proxy: N tunnels to the D0 upstream's /tunnel
(Upgrade: echo), each sending a message and waiting for its echo, for D seconds.
Prints: tunnels messages seconds messages_per_second. The proxy's CPU per message is what
the caller measures around this. usage: ws_load.py PORT CONNS SECONDS [MESSAGE_BYTES]"""
import asyncio, sys, time

port, conns, seconds = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
size = int(sys.argv[4]) if len(sys.argv) > 4 else 1024
payload = b"x" * size
total = 0
failures = 0

async def one():
    global total, failures
    try:
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"GET /tunnel HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
        await w.drain()
        head = await r.readuntil(b"\r\n\r\n")
        if not head.startswith(b"HTTP/1.1 101"):
            failures += 1
            return
        end = time.monotonic() + seconds
        n = 0
        while time.monotonic() < end:
            w.write(payload)
            await w.drain()
            await r.readexactly(size)
            n += 1
        total += n
        w.close()
    except Exception:
        failures += 1

async def main():
    t0 = time.monotonic()
    await asyncio.gather(*[one() for _ in range(conns)])
    dt = time.monotonic() - t0
    print(f"{conns} {total} {dt:.2f} {total / dt:.0f} failures={failures}")

asyncio.run(main())
