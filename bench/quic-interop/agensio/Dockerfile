# agensio as a server implementation of the QUIC interop runner
# (https://github.com/quic-interop/quic-interop-runner, docs/design-http3.md 9.2).
# The runner's endpoint base image is Ubuntu 24.04 with OpenSSL 3.0, which has no QUIC
# TLS API, so this image is Debian trixie (OpenSSL 3.5) with the endpoint's /setup.sh
# copied in: the runner needs the routes, the checksum offload switched off and the
# environment contract, not the base image itself.
FROM debian:trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build libasio-dev libssl-dev zlib1g-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . /src
# CMAKE_EXTRA: -DAGENSIO_QUIC_TRACE=ON gives a server that logs every packet to stderr, which
# the runner keeps in each test's output.txt (bench/quic-interop/run.sh with TRACE=1).
ARG CMAKE_EXTRA=""
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DAGENSIO_TESTS=OFF -DAGENSIO_INTEROP=ON $CMAKE_EXTRA \
    && cmake --build build --target agensio

FROM debian:trixie
RUN apt-get update && apt-get install -y --no-install-recommends \
      libssl3t64 zlib1g ethtool net-tools iproute2 iputils-ping ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=martenseemann/quic-network-simulator-endpoint:latest /setup.sh /setup.sh
COPY --from=build /src/build/agensio /usr/local/bin/agensio
COPY bench/quic-interop/agensio/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh /setup.sh
ENTRYPOINT ["/run_endpoint.sh"]
