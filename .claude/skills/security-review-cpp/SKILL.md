---
name: security-review-cpp
description: Review C++ network-facing code in agensio (parsers, path handling, TLS, control interface) against CERT C++ rules and the project's threat model, and add fuzz targets.
---

# Security review for C++ network code

References: SEI CERT C++ Coding Standard (https://wiki.sei.cmu.edu/confluence/x/Wnw-BQ),
C++ Core Guidelines safety profiles (type, bounds, lifetime), `docs/ROADMAP.md` phase F0
threat model, `docs/legacy-analysis.md` section 6 (bugs of the old server, never repeat).

## Checklist
1. **Bounds**: every index and length derived from network data is checked against the
   actual buffer size before use (ARR30-C, STR50-CPP). Look for `buf[pos + n]` without a
   size check, `memcpy` with attacker-controlled length, `substr` with unchecked offsets.
2. **Integers**: no signed/unsigned mix in size arithmetic, no overflow in
   `offset + length` (INT30-C, INT32-C); Content-Length and chunk sizes are parsed with
   explicit maximums.
3. **Lifetime**: buffers referenced by `string_view`s or `const_buffer`s must outlive the
   async operation; check what holds the connection, the cache entry, the plan pieces
   (EXP54-CPP). No use after `close()`.
4. **Resource limits**: header size, header count, body size, idle/read/write timeouts,
   per-connection request cap, upstream concurrency; slowloris and amplification
   resistance.
5. **Paths**: decode, normalise, canonicalise, then containment under the root; symlinks;
   Windows case-insensitivity, reserved names, `::$DATA`; deny-lists compare after
   normalisation.
6. **Protocol ambiguity**: Content-Length vs Transfer-Encoding conflicts, duplicate
   headers, obs-fold, absolute-form targets, Host mismatch (request smuggling).
7. **TLS**: minimum TLS 1.2, no compression, error queue cleared after errors, no secrets
   in logs, certificate/key file permissions checked at load.
8. **Control interface**: peer credentials verified, loopback only, token constant-time
   compared, Origin refused, mutations validated and audited (phase F0 rules).
9. **Error paths**: every early return releases what it took; no silent close where a
   log line would help troubleshooting.
10. **Fuzzing**: each parser has a libFuzzer target under `tests/fuzz/`; run it for at
    least an hour after parser changes; add crashing inputs as regression tests.

## Output
List findings by severity with the CERT/Core Guidelines ID, the file and line, a concrete
attacker input, and the fix. Confirm each finding by reading the code path end to end.
