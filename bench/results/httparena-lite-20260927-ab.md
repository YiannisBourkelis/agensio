# HttpArena lite, alpha.26 against the working tree (2026-09-27)

- machine: AMD Ryzen 9 9900X (12 cores, 24 threads), Debian 13, kernel 6.12.107+deb13-amd64,
  the arena's harness inside Docker-in-Docker (`bench/httparena/local.sh`, engine 29.8.1)
- base: 26b4801 (v0.1.0-alpha.26), built from the A/B worktree `bench/tmp/ab/26b4801`;
  new: 26b4801 plus the uncommitted alpha.27 changes (the site environment, the Writebook
  report's fixes, the HTTP/2 and HTTP/3 cookie join); both with `Dockerfile.local`
  (`-DAGENSIO_NATIVE=ON -DAGENSIO_HTTPARENA=ON`)
- server pinned to cores 0-5,12-17, load generators to 6-11,18-23; 5 s per run, best of 3
- raw output: `bench/results/raw/httparena-20260927/`

Commands:

```
LOCAL=1 bench/httparena/local.sh validate agensio                       # new: 72 passed, 0 failed
export LOCAL=1 SERVER_CPUS=0-5,12-17 LOAD_CPUS=6-11,18-23 ARENA=$PWD/bench/tmp/httparena
bench/tmp/ab/26b4801/bench/httparena/local.sh bench agensio             # base, every profile
bench/httparena/local.sh bench agensio                                  # new, every profile
bench/httparena/local.sh bench agensio static-tls                       # rerun, new first
bench/tmp/ab/26b4801/bench/httparena/local.sh bench agensio static-tls  # then base
```

| profile | alpha.26 req/s | new req/s | new/base | CPU base / new | Mem base / new |
|---|---|---|---|---|---|
| baseline 512c | 2,472,287 | 2,488,824 | 1.007 | 1122% / 1129% | 56 / 58 MiB |
| pipelined 512c | 3,508,357 | 3,496,300 | 0.997 | 1231% / 1229% | 46 / 46 MiB |
| limited-conn 512c | 1,985,320 | 1,978,705 | 0.997 | 1186% / 1100% | 45 / 51 MiB |
| baseline-h2 512c | 11,584,961 | 11,567,265 | 0.998 | 420% / 437% | 83 / 82 MiB |
| static-h2 512c | 751,677 | 750,034 | 0.998 | 1111% / 1221% | 271 / 270 MiB |
| static-tls 512c | 638,238 | 624,401 | 0.978 | 1088% / 1057% | 91 / 88 MiB |
| static-tls 512c, rerun (new first) | 622,091 | 630,505 | 1.014 | 1174% / 1053% | 100 / 107 MiB |
| json-tls 512c | 1,172,754 | 1,166,266 | 0.994 | 999% / 930% | 83 / 85 MiB |
| baseline-h2c 512c | 12,662,124 | 12,572,393 | 0.993 | 448% / 420% | 53 / 54 MiB |
| json-h2c 512c | 3,017,933 | 3,013,927 | 0.999 | 1132% / 1212% | 281 / 291 MiB |
| baseline-h3 64c | 3,992,187 | 4,002,243 | 1.003 | 224% / 227% | 80 / 80 MiB |
| static-h3 64c | 607,362 | 618,495 | 1.018 | 849% / 839% | 76 / 76 MiB |

Every row within the harness's run-to-run spread; static-tls's 0.978 reversed to 1.014
when the order was swapped. The CPU-per-request gate for the same change is the A/B:
`ab-20260927-125724.md` (static, proxy, h2), `ab-20260927-130438.md` (h3, three rounds),
`ab-20260927-130731.md` (h2, five rounds), `ab-20260927-131148.md` (proxy, five rounds).
