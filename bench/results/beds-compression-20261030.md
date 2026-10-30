# Response compression on the PHP beds, 2026-10-30 (design-compression.md 10, "PHP pages")

- machine: x86_64, AMD Ryzen 9 9900X 12-Core Processor, Linux 6.12.113+deb13-amd64, 24 threads, Debian 13
- commit: 9589cc58+dirty (the step-4 tree: zstd and brotli per request, the padding), zlib 1.3.1, libzstd 1.5.7, libbrotli 1.1.0
- one web-server worker; wrk 4 threads, 64 connections, 10 s, one round per row; wrk asks for one coding (`Accept-Encoding: <coding>`)
- Laravel: `bench/laravel/bench.sh -p unix -u / -e <coding>` (the ddev bed's pool over the bind-mounted unix socket, 8 static children; nginx 1.26.3 from the devbox image, `gzip on; gzip_comp_level 5` for the gzip row, no brotli or zstd module in its stock build), results `laravel-20261030-0855*.md` and, for the 256 KB rows, `laravel-20261030-0859*.md` (raw wrk output beside each)
- WordPress: `bench/wordpress/.ddev/bench.sh build/agensio <coding> 10s 64` (the same measurement as the Laravel script: `build/agensio` on the bed's pool on 127.0.0.1:9002 through docker-proxy, `app = "wordpress"`, `Host: wp.agensio.ddev.site:8072`, access log off), raw wrk output of the 256 KB rows in `raw/wordpress-compression-20261030/`
- web us/req = CPU of the web server's process / requests; php us/req = CPU of the web container's cgroup / requests; bytes/ans = bytes on the wire per answer, headers included (wrk's total read / requests)

## As committed: the whole-answer limit of 64 KB

Both pages are above the limit (Laravel's welcome page 82,458 bytes, WordPress's home page 70,286), so
agensio sends them identity with `Vary: Accept-Encoding` (the decision's reason `large`: compressed in
pieces from step 6 on) and pays the decision alone; nginx gzips Laravel's page.

| server | bed | coding asked | sent | req/s | p50 | p99 | web us/req | php us/req | bytes/ans |
|---|---|---|---|---|---|---|---|---|---|
| agensio | laravel / | none | identity | 3605 | 17.1 ms | 23.3 ms | 49.3 | 2196 | 82458 |
| nginx | laravel / | none | identity | 3361 | 18.4 ms | 25.1 ms | 80.6 | 2325 | 82686 |
| agensio | laravel / | gzip | identity (large) | 3610 | 17.2 ms | 21.9 ms | 51.0 | 2191 | 82669 |
| nginx | laravel / | gzip | gzip 5 | 1518 | 41.6 ms | 50.0 ms | 657.8 | 2370 | 18104 |
| agensio | laravel / | zstd | identity (large) | 3653 | 17.1 ms | 21.0 ms | 48.4 | 2165 | 82537 |
| agensio | laravel / | br | identity (large) | 3625 | 17.2 ms | 21.5 ms | 52.9 | 2187 | 82600 |
| agensio | wordpress / | none | identity | 351 | 181 ms | 196 ms | 162.2 | 20853 | 70402 |
| agensio | wordpress / | zstd | identity (large) | 346 | 182 ms | 215 ms | 167.5 | 21164 | 70551 |
| agensio | wordpress / | br | identity (large) | 340 | 186 ms | 219 ms | 167.5 | 21632 | 70542 |
| agensio | wordpress / | gzip | identity (large) | 322 | 199 ms | 222 ms | 167.5 | 22876 | 70252 |

The nginx gzip row is wrk-bound on the server's CPU in the same way the agensio rows are PHP-bound:
both servers wait on the same 8 children; nginx's 658 us per answer is zlib's deflate at level 5 on 82 KB.

## Experiment: the limit raised to 256 KB (`kWholeMax`, not committed)

The same pages compressed whole on the worker, so the encoders' cost on real pages is known
before step 6 compresses them in pieces:

| server | bed | coding | req/s | p50 | p99 | web us/req | encoder us (web minus the identity row) | php us/req | bytes/ans | ratio |
|---|---|---|---|---|---|---|---|---|---|---|
| agensio | laravel / | zstd 3 | 3315 | 18.5 ms | 25.3 ms | 166.1 | 117 | 2337 | 18397 | 4.5:1 |
| agensio | laravel / | br 4 | 1686 | 37.0 ms | 46.4 ms | 592.2 | 543 | 2393 | 17226 | 4.8:1 |
| agensio | laravel / | gzip 5 | 1501 | 41.8 ms | 49.7 ms | 664.4 | 615 | 2409 | 18107 | 4.6:1 |
| nginx | laravel / | gzip 5 | 1518 | 41.6 ms | 50.0 ms | 657.8 | 577 | 2370 | 18104 | 4.6:1 |
| agensio | wordpress / | zstd 3 | 351 | 181 ms | 200 ms | 347.5 | 185 | 20860 | 13663 | 5.2:1 |
| agensio | wordpress / | br 4 | 338 | 188 ms | 217 ms | 805.0 | 643 | 21573 | 12788 | 5.5:1 |
| agensio | wordpress / | gzip 5 | 343 | 182 ms | 226 ms | 696.6 | 535 | 21289 | 12622 | 5.6:1 |

Read: on an 82 KB Laravel page zstd 3 costs the worker 117 us for 4.5:1, a fifth of gzip 5 (615 us,
the same zlib as nginx's 577 us) and of brotli 4 (543 us) for 2 to 7 % more bytes; the PHP side is
2.2 ms per request on Laravel and 21 ms on WordPress, so even gzip 5 is under a quarter of a Laravel
request's CPU and 3 % of a WordPress one's. The req/s and latency columns are the pool's (the same
eight children for every row); the brotli and gzip rows of Laravel sit lower because the web worker
spends 0.6 ms per answer on the critical path of one worker.

## brotli per answer on the upstream's 32 KB page (`bench/compression/brotli-time.cpp`, 300 calls each, in the devbox)

| call | us | bytes |
|---|---|---|
| one-shot quality 4, window 2^22 (the library's default) | 290.2 | 10638 |
| one-shot quality 4, window 2^16 (sized to the page) | 281.5 | 10637 |
| stream quality 4, window 2^16, an encoder made per answer (compress.cpp's way) | 279.8 | 10637 |
| stream quality 4, window 2^16, the encoder's memory from a reused arena | 230.8 | 10637 |
| one-shot quality 3, window 2^22 | 103.4 | 10677 |
| stream quality 3, window 2^16, encoder per answer | 102.6 | 10676 |
| stream quality 3, reused arena | 103.7 | 10676 |
| stream quality 2, window 2^16, encoder per answer | 95.3 | 10603 |
| stream quality 1, window 2^16, encoder per answer | 63.7 | 11594 |

Read: on a whole answer quality 4 costs 2.7 times quality 3 for 0.4 % fewer bytes (quality 4's
hasher is the larger one; 50 us of its 280 is the memory of a fresh encoder, which a reused arena
would save, and nothing at quality 3). The design's reason for 4 is the loss below it when a stream is
flushed every 16 KB (design 6), which does not apply to an answer compressed whole.
