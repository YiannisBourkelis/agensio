# The protocol specifications, as text

The RFCs the protocol layers implement, fetched from https://www.rfc-editor.org/rfc/ as
plain text so that a section number in a comment, a design document or a commit message
can be read here without a browser. Cite them by number and section (`RFC 9000 8.1`).
Keep this list in step with the code: a new protocol feature adds its RFC here first.

| File | Title | Implemented by |
|---|---|---|
| `rfc9110.txt` | HTTP Semantics | every protocol layer: methods, status codes, fields, conditionals, ranges (`src/core/`, `src/handlers/`) |
| `rfc9112.txt` | HTTP/1.1 | `src/http1/` (parser, connection, chunked coding) |
| `rfc9113.txt` | HTTP/2 | `src/http2/` (`docs/design-http2.md`) |
| `rfc7541.txt` | HPACK: Header Compression for HTTP/2 | `src/http2/hpack.*`, the Huffman and integer codec shared with QPACK (`src/http/field_codec.*`) |
| `rfc8999.txt` | Version-Independent Properties of QUIC | `src/quic/packet.hpp` (the invariants every version keeps) |
| `rfc9000.txt` | QUIC: A UDP-Based Multiplexed and Secure Transport | `src/quic/` (`docs/design-http3.md` section 6) |
| `rfc9001.txt` | Using TLS to Secure QUIC | `src/quic/crypto.*`, `src/quic/tls.*` |
| `rfc9002.txt` | QUIC Loss Detection and Congestion Control | `src/quic/recovery.*`, `src/quic/ack.hpp` |
| `rfc9114.txt` | HTTP/3 | `src/http3/` (`docs/design-http3.md` section 7) |
| `rfc9204.txt` | QPACK: Field Compression for HTTP/3 | `src/http3/qpack.*` |
| `rfc9438.txt` | CUBIC for Fast and Long-Distance Networks | `src/quic/recovery.*` (phase I3) |
| `rfc8899.txt` | Packetization Layer Path MTU Discovery for Datagram Transports | `src/quic/connection.*` (the MTU probe, phase I1b) |
