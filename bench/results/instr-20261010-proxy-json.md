# Instructions per proxied request, 2026-10-10: base 928ac42 vs new 928ac42+dirty (alpha.61 report, finding 1)

- machine: x86_64, AMD Ryzen 9 9900X 12-Core Processor, Linux 6.12.111+deb13-amd64 (Debian 13), devbox image agensio-devbox-perf
- why: bench/ab.sh -P put proxy /json at 1.032 with the fix (ab-20261010-194344, 3 rounds) while the
  same code on both sides gave 1.005 and 1.028 (ab-20261010-194855, ab-20261010-192221): timing
  noise or cost? Instructions retired per request do not depend on timing.
- setup: the A/B's own proxy site (bench/tmp/ab-agensio-proxy.toml, one worker, 127.0.0.1:8093)
  in front of build/agensio_upstream -p 9100 -w 1; wrk -t4 -c64 -d5s http://127.0.0.1:8093/json
  after a 1 s warm-up; perf stat -e instructions,cycles -p <agensio pid> for the 5 s; base and new
  alternated, three rounds. Script: raw/instr-20261010-proxy-json/instr.sh
- command: docker run --rm --init --ulimit nofile=65536:65536 -v $PWD:$PWD -w $PWD --cap-add SYS_ADMIN
  --cap-add PERFMON --user root agensio-devbox-perf:latest instr.sh bench/tmp/ab/928ac42/build/agensio build/agensio 3

```
base round 1 requests=1102061 instructions/req=46214 cycles/req=24668
new  round 1 requests=1081433 instructions/req=46224 cycles/req=25148
base round 2 requests=1094689 instructions/req=46127 cycles/req=24838
new  round 2 requests=1116058 instructions/req=46200 cycles/req=24332
base round 3 requests=1124860 instructions/req=46195 cycles/req=24178
new  round 3 requests=1115124 instructions/req=46283 cycles/req=24351
```

Means: instructions 46,179 (base) vs 46,236 (new), +0.12 %, inside the base rounds' own spread
(46,127 to 46,214); cycles 24,561 vs 24,610, +0.2 %. The changed function (rewrite_location) runs
only for a Location field, which /json answers do not carry. No cost.
