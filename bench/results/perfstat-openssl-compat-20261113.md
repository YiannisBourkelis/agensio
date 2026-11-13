# perf stat: the OpenSSL compatibility helpers, inlined against ordinary functions

- machine: x86_64, AMD Ryzen 9 9900X 12-Core Processor, Linux 6.12.116+deb13-amd64 (Debian 13), 2026-11-13,
  load average 3 to 5 during the runs (not quiet)
- base: 0feefb69 (built by bench/ab.sh with build/CMakeCache.txt's options, bench/tmp/ab/0feefb69);
  new: the working tree that replaces SSL_set1_host, X509_NAME_get_text_by_NID and ASN1_STRING_length
- why: none of the three calls runs per request, so the change adds no work to one; but the first form
  of it (the helpers `inline` in core/openssl_compat.hpp) made five functions 48 to 176 bytes larger,
  among them UpstreamRequest::handshake() and Server::build_listeners(), and moved the code around
  them. Its A/B (`bench/ab.sh 0feefb69 -2 -P -r 3`, not kept) ran 0.940 to 1.080 with h2 over TLS at
  ten streams at 1.043, and perf stat, in two separate runs, showed the same instructions per request
  and more L1 instruction-cache misses on every TLS row in every round. The second form (ordinary
  functions in core/openssl_compat.cpp, linked last) shows no such difference: its A/B is
  ab-20261113-143633.md, 0.964 to 1.055 with the TLS rows at 0.987 to 1.009. That form is the one
  committed.
- a caution on the miss counts: within one run they repeat to a few per request, but between runs the
  same binary moves by a tenth (the base's http / 271 to 272 in one run and 294 to 300 in another), so
  only a difference that holds across runs is read as the binary's.
- agensio workers = 1, the A/B's configuration (bench/tmp/ab-agensio-proxy.toml with
  build/agensio_upstream on 9100); in agensio-devbox-perf
  (`--network none --cap-add SYS_ADMIN --cap-add PERFMON --user root`)
- command, per side, the sides alternated: the server started, 2 s of warm-up, then
  `perf stat -e instructions,cycles,L1-icache-load-misses -p <server> -- sleep 5` during
  `wrk -t4 -c64 -d5s <url>` or `h2load -D 5 -c64 -m<streams> -t4 <url>`
  (http on 8080, https and h2 on 8443, proxy on 8093)

## First form: helpers inline (not committed)

The three rows the A/B put above 1.03:

```
http /       base reqs 1990768  instr/req 18505  cycles/req 13309  L1i-miss/req 271.2
http /       new  reqs 1338513  instr/req 18899  cycles/req 19400  L1i-miss/req 239.1
http /       base reqs 1402950  instr/req 18458  cycles/req 18557  L1i-miss/req 314.6
http /       new  reqs 1949351  instr/req 18421  cycles/req 13662  L1i-miss/req 283.4
http /       base reqs 2279488  instr/req 18514  cycles/req 11836  L1i-miss/req 352.0
http /       new  reqs 2048807  instr/req 18562  cycles/req 12812  L1i-miss/req 276.1
proxy /big   base reqs 90508  instr/req 132622  cycles/req 287584  L1i-miss/req 1649.6
proxy /big   new  reqs 108301  instr/req 133275  cycles/req 239848  L1i-miss/req 1721.0
proxy /big   base reqs 186289  instr/req 132224  cycles/req 143231  L1i-miss/req 1788.7
proxy /big   new  reqs 276561  instr/req 131874  cycles/req 97434  L1i-miss/req 1701.7
proxy /big   base reqs 193183  instr/req 131789  cycles/req 138023  L1i-miss/req 1757.2
proxy /big   new  reqs 270829  instr/req 131970  cycles/req 99496  L1i-miss/req 1720.4
h2 / m=10    base reqs 8686130  instr/req 7758  cycles/req 3042  L1i-miss/req 67.2
h2 / m=10    new  reqs 8249460  instr/req 7746  cycles/req 3217  L1i-miss/req 81.8
h2 / m=10    base reqs 8406480  instr/req 7733  cycles/req 3124  L1i-miss/req 66.2
h2 / m=10    new  reqs 7824780  instr/req 7721  cycles/req 3384  L1i-miss/req 79.9
h2 / m=10    base reqs 8109430  instr/req 7731  cycles/req 3253  L1i-miss/req 66.7
h2 / m=10    new  reqs 7666560  instr/req 7763  cycles/req 3439  L1i-miss/req 81.1
```

The HTTP/2 and TLS rows again, more rounds:

```
h2 m=10      base reqs 8560100  instr/req 7752  cycles/req 3092  L1i-miss/req 66.7
h2 m=10      new  reqs 8251050  instr/req 7754  cycles/req 3223  L1i-miss/req 80.9
h2 m=10      base reqs 7447490  instr/req 7782  cycles/req 3541  L1i-miss/req 67.3
h2 m=10      new  reqs 7913260  instr/req 7794  cycles/req 3340  L1i-miss/req 80.9
h2 m=10      base reqs 8143250  instr/req 7740  cycles/req 3258  L1i-miss/req 66.2
h2 m=10      new  reqs 6632670  instr/req 7758  cycles/req 3945  L1i-miss/req 81.3
h2 m=10      base reqs 8649610  instr/req 7735  cycles/req 3053  L1i-miss/req 65.7
h2 m=10      new  reqs 8072320  instr/req 7723  cycles/req 3276  L1i-miss/req 79.8
h2c m=10     base reqs 11613490  instr/req 5880  cycles/req 2271  L1i-miss/req 53.1
h2c m=10     new  reqs 11445650  instr/req 5875  cycles/req 2306  L1i-miss/req 46.6
h2c m=10     base reqs 10971050  instr/req 5860  cycles/req 2385  L1i-miss/req 49.8
h2c m=10     new  reqs 7186400  instr/req 5908  cycles/req 3592  L1i-miss/req 50.6
h2c m=10     base reqs 6215970  instr/req 5880  cycles/req 4079  L1i-miss/req 46.3
h2c m=10     new  reqs 8752990  instr/req 5883  cycles/req 2983  L1i-miss/req 49.1
h2c m=10     base reqs 11117020  instr/req 5863  cycles/req 2375  L1i-miss/req 47.1
h2c m=10     new  reqs 11869740  instr/req 5862  cycles/req 2214  L1i-miss/req 46.3
h2 m=1       base reqs 1530332  instr/req 31192  cycles/req 17413  L1i-miss/req 509.5
h2 m=1       new  reqs 1504417  instr/req 31301  cycles/req 17841  L1i-miss/req 571.2
h2 m=1       base reqs 1411871  instr/req 31333  cycles/req 19042  L1i-miss/req 514.4
h2 m=1       new  reqs 1587651  instr/req 31207  cycles/req 16786  L1i-miss/req 558.7
h2 m=1       base reqs 1275843  instr/req 31291  cycles/req 20680  L1i-miss/req 493.9
h2 m=1       new  reqs 1511027  instr/req 31239  cycles/req 17694  L1i-miss/req 556.4
https /      base reqs 1619492  instr/req 29028  cycles/req 16511  L1i-miss/req 482.4
https /      new  reqs 1685572  instr/req 29030  cycles/req 15917  L1i-miss/req 582.2
https /      base reqs 1449718  instr/req 28981  cycles/req 18370  L1i-miss/req 476.9
https /      new  reqs 1422788  instr/req 28932  cycles/req 18843  L1i-miss/req 585.2
https /      base reqs 1680138  instr/req 29051  cycles/req 16043  L1i-miss/req 485.0
https /      new  reqs 1659974  instr/req 29007  cycles/req 16162  L1i-miss/req 584.8
```

Reading: instructions per request equal on every row. L1 instruction-cache misses per request higher
on the new side on every TLS row and in every round (https / 477 to 485 against 582 to 585, h2 at one
stream 494 to 514 against 556 to 571, h2 at ten streams 66 to 67 against 80 to 82), equal on the plain
rows (h2c at ten streams 46 to 53 both). Cycles on h2 at ten streams higher in six of the seven pairs
of the two runs (4 to 8 %, once 21 %); on the other rows inside the machine's noise.

## Second form: ordinary functions in their own file (committed)

```
https /      base reqs 1400737  instr/req 28983  cycles/req 19047  L1i-miss/req 516.2
https /      new  reqs 1475234  instr/req 28924  cycles/req 18167  L1i-miss/req 535.6
https /      base reqs 1476523  instr/req 29103  cycles/req 18056  L1i-miss/req 502.6
https /      new  reqs 1494395  instr/req 28997  cycles/req 17914  L1i-miss/req 502.9
https /      base reqs 1588447  instr/req 28960  cycles/req 16847  L1i-miss/req 511.1
https /      new  reqs 1546732  instr/req 29013  cycles/req 17286  L1i-miss/req 504.3
h2 m=10      base reqs 8022570  instr/req 7744  cycles/req 3302  L1i-miss/req 70.8
h2 m=10      new  reqs 8255530  instr/req 7744  cycles/req 3203  L1i-miss/req 66.0
h2 m=10      base reqs 8113980  instr/req 7774  cycles/req 3262  L1i-miss/req 70.6
h2 m=10      new  reqs 8183410  instr/req 7736  cycles/req 3206  L1i-miss/req 67.0
h2 m=10      base reqs 7888330  instr/req 7780  cycles/req 3351  L1i-miss/req 71.3
h2 m=10      new  reqs 7664500  instr/req 7729  cycles/req 3448  L1i-miss/req 66.2
h2 m=1       base reqs 1149712  instr/req 31295  cycles/req 22232  L1i-miss/req 489.3
h2 m=1       new  reqs 1247678  instr/req 31164  cycles/req 20945  L1i-miss/req 493.6
h2 m=1       base reqs 1200152  instr/req 31165  cycles/req 21636  L1i-miss/req 517.8
h2 m=1       new  reqs 1231508  instr/req 31310  cycles/req 21496  L1i-miss/req 516.6
http /       base reqs 1943697  instr/req 18404  cycles/req 13557  L1i-miss/req 272.1
http /       new  reqs 2225912  instr/req 18458  cycles/req 11895  L1i-miss/req 282.5
http /       base reqs 2030414  instr/req 18417  cycles/req 12851  L1i-miss/req 270.8
http /       new  reqs 2288272  instr/req 18442  cycles/req 11659  L1i-miss/req 275.8
h2c m=10     base reqs 8678600  instr/req 5885  cycles/req 2998  L1i-miss/req 49.3
h2c m=10     new  reqs 5934150  instr/req 5897  cycles/req 4261  L1i-miss/req 48.4
h2c m=10     base reqs 6384700  instr/req 5884  cycles/req 4008  L1i-miss/req 46.4
h2c m=10     new  reqs 9415910  instr/req 5870  cycles/req 2775  L1i-miss/req 44.8
```

Reading (base against new): instructions per request equal; L1 instruction-cache misses per request
within the rounds' spread on every row (https / 503 to 516 against 503 to 536, h2 at one stream 489 to
518 against 494 to 517, h2 at ten streams 71 against 66 to 67, http / 271 to 272 against 276 to 283,
h2c at ten streams 46 to 49 against 45 to 48); cycles higher on either side by turns.

The two rows the second form's A/B (ab-20261113-143633.md) put above 1.03, http / at 1.055 (one round
of three at 2.32 us, the others 1.96 and 2.08 against the base's 2.00 to 2.02) and h2c at one stream
at 1.049:

```
http /       base reqs 2417769  instr/req 18536  cycles/req 11185  L1i-miss/req 299.5
http /       new  reqs 2422498  instr/req 18535  cycles/req 11172  L1i-miss/req 270.8
http /       base reqs 2542077  instr/req 18509  cycles/req 10629  L1i-miss/req 293.7
http /       new  reqs 2580085  instr/req 18550  cycles/req 10466  L1i-miss/req 271.2
http /       base reqs 2326583  instr/req 18465  cycles/req 11637  L1i-miss/req 296.1
http /       new  reqs 2557999  instr/req 18517  cycles/req 10563  L1i-miss/req 269.9
http /       base reqs 2582495  instr/req 18511  cycles/req 10467  L1i-miss/req 297.3
http /       new  reqs 2560016  instr/req 18531  cycles/req 10543  L1i-miss/req 273.7
h2c m=1      base reqs 2421803  instr/req 19979  cycles/req 11062  L1i-miss/req 311.8
h2c m=1      new  reqs 2387105  instr/req 19969  cycles/req 11256  L1i-miss/req 287.1
h2c m=1      base reqs 2433118  instr/req 19890  cycles/req 11010  L1i-miss/req 318.5
h2c m=1      new  reqs 2313632  instr/req 19991  cycles/req 11637  L1i-miss/req 287.3
h2c m=1      base reqs 2490150  instr/req 19981  cycles/req 10766  L1i-miss/req 313.9
h2c m=1      new  reqs 2277127  instr/req 19939  cycles/req 11798  L1i-miss/req 284.5
h2c m=1      base reqs 2217955  instr/req 19926  cycles/req 12145  L1i-miss/req 307.7
h2c m=1      new  reqs 2377172  instr/req 19966  cycles/req 11323  L1i-miss/req 283.2
```

Reading: instructions per request equal on both rows; L1 instruction-cache misses lower on the new
side in this run (http / 294 to 300 against 270 to 274, where the run above had 271 to 272 against 276
to 283); cycles on http / equal (the new side lower in three pairs of four), on h2c at one stream
higher on the new side in three pairs and lower in the fourth, 2 to 10 % either way. No work added;
what the A/B showed on these two rows is the machine.

## The replaced calls themselves

Old call against the new function, 2,000,000 calls each, three rounds, one pinned core, OpenSSL 3.5.7
(a scratch program, not in the tree), the committed form:

```
round 1  peer name (DNS): old 48.0 ns, new 50.4 ns | peer name (IP): old 35.3, new 36.0 | common name: old 15.1, new 17.1
round 2  peer name (DNS): old 46.9 ns, new 47.1 ns | peer name (IP): old 33.3, new 34.4 | common name: old 14.7, new 15.3
round 3  peer name (DNS): old 46.1 ns, new 46.6 ns | peer name (IP): old 35.2, new 34.2 | common name: old 15.0, new 15.3
```

Each of them runs once per TLS connection agensio opens (the peer's name) or once per certificate
loaded (the common name), never per request.
