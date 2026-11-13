# perf stat on four A/B rows: base v0.1.0-alpha.143 (1a8843f0) vs new 754d2a5b + the quic_buffers_note move

- machine: x86_64, AMD Ryzen 9 9900X 12-Core Processor, Linux 6.12.116+deb13-amd64 (Debian 13), 2026-11-13
- why: the release check's two A/Bs (ab-20261113-031901.md, `-3 -r 4`; ab-20261113-032613.md, `-2 -P -r 3`)
  ran on a machine that was not quiet (load average 4 to 9 at their start: the editor's C++ indexer on a
  full core, a VM, other containers) and put these rows above 1.03: http /big.bin (1.065 and 1.048),
  https / (1.046 in the second run, 0.973 in the first), https /style.css (1.047, 0.977 in the first),
  proxy /json (1.047).
- both binaries built with build/CMakeCache.txt's options (the base by ab.sh, bench/tmp/ab/1a8843f0)
- agensio workers = 1, the A/B's configurations (ab-agensio.toml, ab-agensio-proxy.toml with
  build/agensio_upstream on 9100); in agensio-devbox-perf
  (`--network none --cap-add SYS_ADMIN --cap-add PERFMON --user root`)
- command, per side, the sides alternated three times: the server started, 2 s of warm-up, then
  `perf stat -e instructions,cycles,L1-icache-load-misses -p <server> -- sleep 5` during `wrk -t4 -d5s`
  with `-c16 http://127.0.0.1:8080/big.bin`, `-c64 http://127.0.0.1:8093/json`,
  `-c64 https://127.0.0.1:8443/` and `-c64 https://127.0.0.1:8443/style.css`

```
http big.bin base reqs 12427  instr/req 3402164  cycles/req 2157822  L1i-miss/req 35131.1
http big.bin new  reqs 13633  instr/req 3353896  cycles/req 1949336  L1i-miss/req 33310.9
http big.bin base reqs 14110  instr/req 3366510  cycles/req 1881818  L1i-miss/req 32980.3
http big.bin new  reqs 14525  instr/req 3360614  cycles/req 1830014  L1i-miss/req 34117.8
http big.bin base reqs 14413  instr/req 3363732  cycles/req 1843974  L1i-miss/req 33117.4
http big.bin new  reqs 13563  instr/req 3362665  cycles/req 1960024  L1i-miss/req 33440.6
proxy json   base reqs 1059089  instr/req 47294  cycles/req 25383  L1i-miss/req 672.8
proxy json   new  reqs 1021318  instr/req 47494  cycles/req 26398  L1i-miss/req 729.9
proxy json   base reqs 948173  instr/req 47079  cycles/req 28361  L1i-miss/req 677.6
proxy json   new  reqs 924698  instr/req 47198  cycles/req 29085  L1i-miss/req 720.8
proxy json   base reqs 965916  instr/req 47169  cycles/req 27788  L1i-miss/req 668.1
proxy json   new  reqs 1009893  instr/req 47642  cycles/req 26486  L1i-miss/req 723.5
https 1 KB   base reqs 1570875  instr/req 29004  cycles/req 17058  L1i-miss/req 485.1
https 1 KB   new  reqs 1619837  instr/req 29057  cycles/req 16552  L1i-miss/req 495.1
https 1 KB   base reqs 1624581  instr/req 29073  cycles/req 16481  L1i-miss/req 485.8
https 1 KB   new  reqs 1457898  instr/req 29068  cycles/req 18444  L1i-miss/req 498.2
https 1 KB   base reqs 1597538  instr/req 29032  cycles/req 16786  L1i-miss/req 491.6
https 1 KB   new  reqs 1646305  instr/req 29019  cycles/req 16308  L1i-miss/req 498.2
https 100 KB base reqs 233292  instr/req 198570  cycles/req 115089  L1i-miss/req 2322.3
https 100 KB new  reqs 232639  instr/req 199059  cycles/req 115578  L1i-miss/req 2355.3
https 100 KB base reqs 226753  instr/req 199258  cycles/req 118306  L1i-miss/req 2329.5
https 100 KB new  reqs 219646  instr/req 198798  cycles/req 122300  L1i-miss/req 2365.6
https 100 KB base reqs 218495  instr/req 199792  cycles/req 123041  L1i-miss/req 2371.7
https 100 KB new  reqs 228846  instr/req 199126  cycles/req 117156  L1i-miss/req 2344.1
```

Reading, row by row:
- http /big.bin: 3.35 to 3.40 M instructions a response on both sides, the new side never above the base;
  one binary's cycles swing 8 % between runs.
- https / and https /style.css: 29.0 to 29.1 k and 198.6 to 199.8 k instructions on both sides, the ranges
  the same; cycles higher on either side by turns.
- proxy /json: 47.1 to 47.3 k instructions on the base, 47.2 to 47.6 k on the new side (0.3 to 1.0 % more
  in each pair, the ranges overlapping), about 50 more L1 instruction-cache misses a request, cycles
  higher on either side by turns. Nothing a proxied request runs changed between the two (the diff of
  src/upstream and src/handlers/proxy.cpp since alpha.143 is in UpstreamRequest::fail() alone), so this
  is layout, not work.
