# Setting up agensio on a Debian development machine

Written for a coding agent (or a person) on the Linux box after `git pull`. Everything
below is scripted; the numbers it produces are the first native-Linux benchmarks of the
project and should be saved in `bench/results/` and committed.

## 1. Packages

```sh
sudo apt update
sudo apt install -y build-essential g++ cmake ninja-build git ca-certificates libssl-dev \
  curl netcat-openbsd openssl python3 procps wrk nginx
# Debian 12 ships GCC 12 (the C++20 floor) and Asio 1.22, which is too old; CMake fetches
# Asio 1.38 from GitHub automatically, so do not install libasio-dev.
# wrk is in Debian 12 (bookworm) main. Caddy: https://caddyserver.com/docs/install#debian-ubuntu-raspbian
# OpenLiteSpeed native: https://openlitespeed.org/kb/install-from-binary/ (or use the container run).
```

CMake must be 3.24 or newer (`cmake --version`); Debian 12 has 3.25.

## 2. Build and test

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/agensio_tests                 # unit + security regression tests
tests/integration.sh build/agensio    # live checks over HTTP and HTTPS (generates docroot and cert)
cd build && ctest --output-on-failure && cd ..
```

Optional, worth doing once on Linux:

```sh
# sanitizers
cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DAGENSIO_SANITIZE=address,undefined
cmake --build build-asan && ./build-asan/agensio_tests && tests/integration.sh build-asan/agensio
# fuzzers (needs clang with libFuzzer: sudo apt install clang)
cmake -S . -B build-fuzz -G Ninja -DAGENSIO_FUZZ=ON -DAGENSIO_TESTS=OFF -DAGENSIO_TLS=OFF -DCMAKE_CXX_COMPILER=clang++
cmake --build build-fuzz && build-fuzz/fuzz_parser tests/fuzz/regressions/parser -max_len=4096 -max_total_time=120
build-fuzz/fuzz_path tests/fuzz/regressions/path -max_len=2048 -max_total_time=120
# lint / format (clang-tidy, clang-format from apt)
scripts/lint.sh && scripts/format.sh
```

Things to verify on Linux specifically and report back: the startup line says
"SO_REUSEPORT per worker"; `agensio_tests` and `integration.sh` pass; `-w 2` and `-w 4`
benchmark runs work (multi-worker with SO_REUSEPORT is untested on Linux so far).

## 3. Benchmarks

Native (preferred on Linux, no VM in the way). Stop any system nginx first
(`sudo systemctl stop nginx`); the harness starts its own on ports 8081/8444.

```sh
bench/run.sh                                  # agensio, nginx, caddy; one worker each; wrk 4 threads
bench/run.sh -s "agensio nginx"               # subset
bench/run.sh -d 15s                           # publishable numbers
AGENSIO_WORKERS=1 NGINX_WORKERS=auto CADDY_WORKERS=0 bench/run.sh -t 4   # one worker vs all cores
```

Container run, adds OpenLiteSpeed (needs Docker with the compose plugin or `docker-compose`):

```sh
bench/docker/run.sh                           # builds agensio for Linux, runs all four servers
```

`bench/docker/docker-compose.yml` pins servers to CPU 0 and wrk to CPUs 1-3; on a machine
with more cores, widen the wrk cpuset. The docroot is a bind mount; for the 10 MB stream
row use a docroot on a local filesystem (see CLAUDE.md, virtiofs note); since A1b the
descriptor is cached, so only the first request pays the open.

## 3b. Laravel test bed (ddev)

```sh
bench/laravel/.ddev/setup.sh    # once: ddev project + composer create-project + test routes
tests/laravel.sh build/agensio  # live checks through agensio -> published php-fpm port
bench/laravel/bench.sh -d 10s -c 64 -r 2   # C5: agensio vs nginx in front of the bed's php-fpm pool (TCP)
bench/laravel/bench.sh -p unix             # the same over the bind-mounted unix socket (.ddev/run/php-fpm.sock)
bench/statamic/.ddev/setup.sh   # same for Statamic: control panel http://127.0.0.1:8071/cp, admin@admin.com / 4444
bench/wordpress/.ddev/setup.sh  # same for WordPress: http://wp.agensio.ddev.site:8072, wp-admin admin / 4444
```

## 4. What to send back

Commit `bench/results/<stamp>.md` (native) and `bench/results/docker-<stamp>.md`, and
add a short note to CLAUDE.md "Performance notes" with the machine (CPU, kernel, Debian
version), the agensio-vs-nginx CPU us/req per case, and anything that behaved differently
from macOS (SO_REUSEPORT, timeouts, sanitizer or fuzzer findings).
