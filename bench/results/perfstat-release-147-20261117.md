# perf stat on the release A/B's rows above 1.03: base v0.1.0-alpha.146 (f5a55b49) vs new 0c824ed1

- machine: x86_64, AMD Ryzen 9 9900X 12-Core Processor, Linux 6.12.116+deb13-amd64 (Debian 13), 2026-11-17
- why: the release check's two A/Bs (ab-20261117-211846.md, `-3 -r 4`; ab-20261117-212559.md, `-2 -P -C -r 3`,
  both in the devbox with `--network none`, load average 2.4 to 2.6 at their start) put these rows above
  1.03: https /style.css (1.039 in the first, 1.020 in the second), h3 / at 64 streams (1.032), comp / (1.030).
  https / was 1.004 and 1.027; it is measured too.
- both binaries built with build/CMakeCache.txt's options (the base by ab.sh, bench/tmp/ab/f5a55b49); the
  bisection's binaries the same way (bench/tmp/ab/<commit>, `-DAGENSIO_TESTS=OFF` plus those options)
- agensio workers = 1, one configuration for all rows: bench/tmp/ab-agensio-h3.toml followed by
  bench/tmp/ab-comp.toml (the A/B's static, HTTP/3 and compression sites); in agensio-devbox-perf
  (`--network none --cap-add SYS_ADMIN --cap-add PERFMON --user root`)
- command, per side, the sides alternated three times: the server started, 2 s of warm-up, then
  `perf stat -e instructions,cycles,L1-icache-load-misses -p <server> -- sleep 5` during
  `wrk -t4 -c64 -d5s https://127.0.0.1:8443/style.css`, `... https://127.0.0.1:8443/`,
  `wrk -t4 -c64 -d5s -H "Accept-Encoding: gzip, deflate, br, zstd" http://127.0.0.1:8087/` and
  `/opt/nghttp2/bin/h2load --alpn-list=h3 -D 5 -c64 -m64 -t4 https://127.0.0.1:8443/`

## The four rows

```
https_css  base reqs 254545   instr/req 201851   cycles/req 106649   L1i-miss/req 2295.8
https_css  new  reqs 255684   instr/req 202578   cycles/req 106219   L1i-miss/req 2362.9
https_css  base reqs 254932   instr/req 201825   cycles/req 106493   L1i-miss/req 2392.8
https_css  new  reqs 252526   instr/req 202575   cycles/req 107583   L1i-miss/req 2329.8
https_css  base reqs 252136   instr/req 202016   cycles/req 107689   L1i-miss/req 2351.9
https_css  new  reqs 253159   instr/req 201842   cycles/req 107166   L1i-miss/req 2355.8
https_1k   base reqs 1745854  instr/req 29306    cycles/req 15507    L1i-miss/req 480.3
https_1k   new  reqs 1754434  instr/req 29725    cycles/req 15447    L1i-miss/req 487.3
https_1k   base reqs 1753030  instr/req 29323    cycles/req 15428    L1i-miss/req 485.7
https_1k   new  reqs 1671865  instr/req 30142    cycles/req 16099    L1i-miss/req 493.9
https_1k   base reqs 1697646  instr/req 29337    cycles/req 15963    L1i-miss/req 491.2
https_1k   new  reqs 1683211  instr/req 29762    cycles/req 16091    L1i-miss/req 481.8
comp_1k    base reqs 2484350  instr/req 19974    cycles/req 10912    L1i-miss/req 286.5
comp_1k    new  reqs 2410194  instr/req 20030    cycles/req 11236    L1i-miss/req 346.2
comp_1k    base reqs 2468379  instr/req 19962    cycles/req 10985    L1i-miss/req 276.4
comp_1k    new  reqs 2406261  instr/req 19998    cycles/req 11267    L1i-miss/req 334.6
comp_1k    base reqs 2507174  instr/req 19976    cycles/req 10811    L1i-miss/req 280.4
comp_1k    new  reqs 2444101  instr/req 20004    cycles/req 11085    L1i-miss/req 336.6
h3_m64     base reqs 5247848  instr/req 8096     cycles/req 3997     L1i-miss/req 33.7
h3_m64     new  reqs 5282048  instr/req 8117     cycles/req 3927     L1i-miss/req 41.6
h3_m64     base reqs 5238026  instr/req 8114     cycles/req 3985     L1i-miss/req 34.3
h3_m64     new  reqs 5206738  instr/req 8125     cycles/req 4045     L1i-miss/req 40.4
h3_m64     base reqs 5149662  instr/req 8130     cycles/req 4131     L1i-miss/req 35.2
h3_m64     new  reqs 5233792  instr/req 8135     cycles/req 4056     L1i-miss/req 42.6
```

The same instructions a request on both sides for https /style.css (201.8 to 202.0 k against 201.8 to
202.6 k), comp / (19.96 to 19.98 k against 20.00 to 20.03 k) and h3 at 64 streams (8.10 to 8.13 k against
8.12 to 8.14 k); on the last two about 20 % more L1 instruction-cache misses on the new side (layout, as
the alpha.144 check found for proxy /json), cycles overlapping on h3 and 2.5 to 3 % higher on comp /.
https / runs 400 to 800 more instructions a request on the new side, every round.

## https / split: user and kernel (`perf stat -e instructions:u,instructions:k,page-faults,context-switches`)

```
base  ins:u 15258.17  ins:k 14011.03  page-faults 0.00  context-switches 0.00
new   ins:u 15718.42  ins:k 13995.77  page-faults 0.00  context-switches 0.00
base  ins:u 15381.60  ins:k 14052.67  page-faults 0.00  context-switches 0.00
new   ins:u 15694.19  ins:k 14051.10  page-faults 0.00  context-switches 0.00
base  ins:u 15264.51  ins:k 14015.32  page-faults 0.00  context-switches 0.00
new   ins:u 15700.02  ins:k 14001.99  page-faults 0.00  context-switches 0.00
```

The kernel's share is the same; the difference is in user space, 330 to 460 instructions a request
(2 to 3 % of user space, 1.2 to 1.6 % of the whole).

## Bisection: user instructions a request on https / along the series (`perf stat -e instructions:u`)

First pass (two rounds, the binaries in rotation):

```
f5a55b49  15307 15298   v0.1.0-alpha.146
4dc6d338  15313 15269   Upstream: a kept connection to an origin no longer holds its read buffer
b33385d9  15313 15257   TLS: an idle connection gives back its buffers
eca09dbd  15296 15283   Proxy: pool = "shared"
37f6e94d  15472 15474   (after 0058a9ba, 64419def, 8b12bf19)
0293f67a  15481 15480   Control: a proxying site's own settings and streamed paths
0e9afda4  15692 15660   (after 800e3356, 8cc944e2, b609b1dc)
HEAD      15707 15723   0c824ed1 (the field values of HTTP/2 and HTTP/3)
```

Second pass (three rounds, two commits built to split the steps):

```
eca09dbd  15334 15287 15271
64419def  15279 15337 15266   Proxy: a buffered body of known length is read into its place
37f6e94d  15495 15528 15521   (8b12bf19 between them; 37f6e94d changes bench files only)
0293f67a  15446 15446 15517
800e3356  15670 15722 15645   TLS: HTTP/1.1 holds a request to its connection's certificate from the first request
0e9afda4  15696 15648 16061
```

Two steps of about 200 instructions each:
- 8b12bf19 (A busy connection holds less: an answer's buffers go with the answer): the HTTP/1 writer's
  TLS coalescing buffer lent per answer from the worker's spares and given back after the first write
  (`core/spare_buffers.hpp`), the price of 45 KB less a busy TLS connection; its own A/B read it as free.
- 800e3356 (F2 of the alpha.146 report): every HTTP/1.1 request over TLS now runs the certificate-name
  check (`CertNames::covers`: the Host copied lower case into a 256-byte stack buffer, which the hardened
  build zero-fills, then the comparisons), which HTTP/2 and HTTP/3 always ran; before, it ran on HTTP/1.1
  only once something had filled the connection's details.
