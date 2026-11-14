# The build image of the Pingora proxy the comparison runs (bench/pingora/run.sh): the Rust toolchain
# on Debian 13, the system the devbox runs, so the binary links the same glibc and the same OpenSSL
# as agensio does there. cmake: Pingora's zlib-ng and brotli dependencies build with it.
FROM rust:1-trixie
RUN apt-get update && apt-get install -y --no-install-recommends cmake && rm -rf /var/lib/apt/lists/*
