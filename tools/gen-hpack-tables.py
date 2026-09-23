#!/usr/bin/env python3
"""Generates the HPACK tables from the text of RFC 7541 (https://www.rfc-editor.org/rfc/rfc7541.txt):

  src/http2/hpack_tables.hpp   the 61-entry static table, the Huffman codes of the 257
                               symbols, and a nibble-driven Huffman decoding automaton
  tests/hpack_vectors.hpp      the request and response examples of appendix C as test
                               vectors (encoded bytes, expected fields, table size after)
  tests/h2/hpack_huffman.py    the Huffman codes for the Python test client

usage: tools/gen-hpack-tables.py rfc7541.txt
The outputs are checked in; a unit test regenerates nothing but checks the automaton's
invariants. Re-run only when this script changes.
"""
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read().splitlines()


def section(start_pat, end_pat):
    out, on = [], False
    for line in text:
        if re.match(start_pat, line):
            on = True
            continue
        if on and re.match(end_pat, line):
            break
        if on:
            out.append(line)
    return out


# ---- static table (appendix A) ----
static = []
for line in section(r"^Appendix A\.", r"^Appendix B\."):
    m = re.match(r"^\s*\|\s*(\d+)\s*\|\s*(\S+)\s*\|\s*(.*?)\s*\|\s*$", line)
    if m:
        idx, name, value = int(m.group(1)), m.group(2), m.group(3)
        assert idx == len(static) + 1, (idx, name)
        static.append((name, value))
assert len(static) == 61, len(static)

# ---- Huffman code (appendix B) ----
codes = {}
for line in section(r"^Appendix B\.", r"^Appendix C\."):
    m = re.match(r"^(?:.*?\s)?\(\s*(\d+)\)\s+\|([01|]+)\s+([0-9a-f]+)\s+\[\s*(\d+)\]\s*$", line)
    if m:
        sym, bits, hexcode, length = int(m.group(1)), m.group(2).replace("|", ""), int(m.group(3), 16), int(m.group(4))
        assert len(bits) == length and int(bits, 2) == hexcode, line
        codes[sym] = (hexcode, length)
assert len(codes) == 257 and all(s in codes for s in range(257)), len(codes)

# The decoding automaton: states are the internal nodes of the code tree (256 of them
# for 257 leaves), transitions consume one nibble. Each transition records the next
# state, the symbol emitted (at most one: no code is shorter than 5 bits) and whether the
# position after it is a valid end of input (only 1-bits consumed since the last symbol,
# fewer than 8 of them: RFC 7541 5.2 padding). Reaching EOS is an error.
class Node:
    def __init__(self):
        self.child = [None, None]
        self.sym = None

root = Node()
for sym, (code, length) in codes.items():
    n = root
    for i in range(length - 1, -1, -1):
        b = (code >> i) & 1
        if n.child[b] is None:
            n.child[b] = Node()
        n = n.child[b]
    assert n.sym is None and n.child == [None, None]
    n.sym = sym

internal = []
def number(n):
    if n.sym is not None:
        return
    n.id = len(internal)
    internal.append(n)
    number(n.child[0])
    number(n.child[1])
number(root)
assert len(internal) == 256, len(internal)

# Nodes on the all-ones path from the root at depth 0..7 are accepting end positions.
accepting = set()
n = root
for depth in range(8):
    accepting.add(id(n))
    n = n.child[1]
    if n is None or n.sym is not None:
        break

FLAG_ACCEPTED, FLAG_SYMBOL, FLAG_FAIL = 1, 2, 4
transitions = []  # [state][nibble] = (next, flags, symbol)
for state in internal:
    row = []
    for nibble in range(16):
        n, sym, fail = state, 0, False
        flags = 0
        for i in (3, 2, 1, 0):
            b = (nibble >> i) & 1
            n = n.child[b]
            if n.sym is not None:
                if n.sym == 256:
                    fail = True
                    break
                assert not (flags & FLAG_SYMBOL)
                flags |= FLAG_SYMBOL
                sym = n.sym
                n = root
        if fail:
            row.append((0, FLAG_FAIL, 0))
            continue
        if id(n) in accepting:
            flags |= FLAG_ACCEPTED
        row.append((n.id, flags, sym))
    transitions.append(row)

# ---- examples (appendix C) ----
vectors = []  # (name, group, hex, [(name, value)], table_size_after, max_table)
cur = None
mode = None
lines = section(r"^Appendix C\.", r"^Appendix D\.|^Authors' Addresses")
for line in lines:
    m = re.match(r"^C\.(\d)\.(\d)\.\s+(.*)$", line)
    if m:
        if cur:
            vectors.append(cur)
        group = int(m.group(1))
        if group == 1:
            cur = None
            mode = None
            continue
        cur = {"name": "C.%s.%s %s" % (m.group(1), m.group(2), m.group(3).strip()), "group": group,
               "hex": "", "fields": [], "size": 0, "max_table": 256 if group in (5, 6) else 4096}
        mode = None
        continue
    if cur is None:
        continue
    if re.match(r"^\s+Header list to encode:", line):
        mode = "fields"
        continue
    if re.match(r"^\s+Hex dump of encoded data:", line):
        mode = "hex"
        continue
    if re.match(r"^\s+Decoding process:", line) or re.match(r"^\s+Decoded header list:", line):
        mode = None
        continue
    if re.match(r"^\s+Dynamic Table \(after decoding\):", line):
        mode = "table"
        continue
    if mode == "fields":
        f = re.match(r"^\s+(\S+?):\s(.*)$", line)
        if f:
            cur["fields"].append((f.group(1), f.group(2).rstrip()))
        elif line.strip() == "" and cur["fields"]:
            mode = None
    elif mode == "hex":
        h = re.match(r"^\s+((?:[0-9a-f]{2,4}\s?)+)\s*\|", line)
        if h:
            cur["hex"] += h.group(1).replace(" ", "")
    elif mode == "table":
        t = re.match(r"^\s+Table size:\s+(\d+)", line)
        if t:
            cur["size"] = int(t.group(1))
            mode = None
        elif re.match(r"^\s+empty\.", line):
            cur["size"] = 0
            mode = None
if cur:
    vectors.append(cur)
assert len(vectors) == 16, [v["name"] for v in vectors]
for v in vectors:
    assert v["hex"] and v["fields"], v["name"]


def cstr(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


with open("src/http2/hpack_tables.hpp", "w", encoding="utf-8") as out:
    out.write("// Generated by tools/gen-hpack-tables.py from RFC 7541 (appendices A and B). Do not edit.\n")
    out.write("#pragma once\n\n#include <array>\n#include <cstdint>\n#include <string_view>\n\nnamespace agensio::hpack {\n\n")
    out.write("struct StaticEntry {\n    std::string_view name;\n    std::string_view value;\n};\n\n")
    out.write("// Index 1 is kStaticTable[0] (RFC 7541 appendix A).\ninline constexpr std::array<StaticEntry, 61> kStaticTable = {{\n")
    for name, value in static:
        out.write("    {%s, %s},\n" % (cstr(name), cstr(value)))
    out.write("}};\n\n")
    out.write("struct HuffmanCode {\n    std::uint32_t code;\n    std::uint8_t bits;\n};\n\n")
    out.write("// Symbol 256 is EOS (RFC 7541 appendix B).\ninline constexpr std::array<HuffmanCode, 257> kHuffmanCodes = {{\n")
    for sym in range(257):
        code, length = codes[sym]
        out.write("    {0x%x, %d},%s\n" % (code, length, "" if sym % 4 != 3 else ""))
    out.write("}};\n\n")
    out.write("// Decoding automaton: 256 states (the internal nodes of the code tree), one transition\n"
              "// per input nibble. flags: 1 = accepted (a valid end of input after this nibble),\n"
              "// 2 = a symbol was emitted, 4 = invalid (EOS or a code that does not exist).\n")
    out.write("struct HuffmanStep {\n    std::uint8_t next;\n    std::uint8_t flags;\n    std::uint8_t symbol;\n};\n")
    out.write("inline constexpr std::uint8_t kHuffmanAccepted = 1, kHuffmanSymbol = 2, kHuffmanFail = 4;\n\n")
    out.write("inline constexpr std::array<std::array<HuffmanStep, 16>, 256> kHuffmanSteps = {{\n")
    for row in transitions:
        out.write("    {{" + ", ".join("{%d, %d, %d}" % t for t in row) + "}},\n")
    out.write("}};\n\n}  // namespace agensio::hpack\n")

with open("tests/hpack_vectors.hpp", "w", encoding="utf-8") as out:
    out.write("// Generated by tools/gen-hpack-tables.py from RFC 7541 appendix C. Do not edit.\n")
    out.write("#pragma once\n\n#include <string_view>\n#include <vector>\n\nnamespace agensio::hpack_vectors {\n\n")
    out.write("struct Field {\n    std::string_view name;\n    std::string_view value;\n};\n")
    out.write("struct Vector {\n    std::string_view name;\n    int group;               // examples of one group share a connection (dynamic table)\n"
              "    std::string_view hex;    // the encoded block\n    std::vector<Field> fields;\n    unsigned table_size_after;\n    unsigned max_table;\n};\n\n")
    out.write("inline const std::vector<Vector>& all() {\n    static const std::vector<Vector> v = {\n")
    for v in vectors:
        out.write("        {%s, %d, %s, {%s}, %d, %d},\n" % (
            cstr(v["name"]), v["group"], cstr(v["hex"]),
            ", ".join("{%s, %s}" % (cstr(n), cstr(val)) for n, val in v["fields"]), v["size"], v["max_table"]))
    out.write("    };\n    return v;\n}\n\n}  // namespace agensio::hpack_vectors\n")

import os
os.makedirs("tests/h2", exist_ok=True)
with open("tests/h2/hpack_huffman.py", "w", encoding="utf-8") as out:
    out.write("# Generated by tools/gen-hpack-tables.py from RFC 7541 appendix B. Do not edit.\n")
    out.write("# symbol -> (code, bits); symbol 256 is EOS.\nCODES = {\n")
    for sym in range(257):
        code, length = codes[sym]
        out.write("    %d: (0x%x, %d),\n" % (sym, code, length))
    out.write("}\nSTATIC_TABLE = [\n")
    for name, value in static:
        out.write("    (%r, %r),\n" % (name, value))
    out.write("]\n")
print("static %d, codes %d, states %d, vectors %d" % (len(static), len(codes), len(internal), len(vectors)))
