# agensio in the QUIC interop runner

The [QUIC interop runner](https://github.com/quic-interop/quic-interop-runner) is the
harness every QUIC stack is measured with: a network simulator (ns-3) between a client
and a server container, test cases that drop, delay, reorder and corrupt packets or
rebind the client's address, and checks on the decrypted traces. This directory is
agensio's server entry (`docs/design-http3.md` 9.2).

- `agensio/Dockerfile` builds agensio from the working tree with `-DAGENSIO_INTEROP=ON`
  on Debian trixie (the runner's endpoint base image is Ubuntu 24.04 with OpenSSL 3.0,
  which has no QUIC TLS API; the endpoint's `/setup.sh` is copied in, which is what the
  simulator needs: the routes and the checksum offload switched off).
- `agensio/run_endpoint.sh` is the entry point: `/setup.sh`, then agensio on `[::]:443`
  serving `/www` with the runner's certificate, `protocols = ["h3", "hq-interop"]`,
  `http3.retry = "always"` for the `retry` case, `SSLKEYLOGFILE` honoured so the runner
  can decrypt its traces. Test cases the server does not do exit 127, as required:
  `zerortt` (early data is refused in phase I), `ecn`, `v2` and `connectionmigration`
  (a client migrating actively; a client whose address changes is handled, which is
  what `rebind-addr` and `rebind-port` test).
- `hq-interop` is the runner's own application protocol for the transport cases: the
  client writes `GET /path\r\n` on a bidirectional stream and the file's bytes come back
  raw, then the stream ends. It exists only in interop builds (`Http3Connection::pump_hq`,
  the ALPN offer in `select_protocol`); a release build refuses it in `protocols`.
- `Dockerfile.runner` is the runner itself (Python, tshark for the trace checks, the
  docker client and compose plugin).
- `run.sh [-c clients] [-t tests]` runs everything inside a Docker-in-Docker daemon
  (`agensio-interop-dind`, started on first use): the runner's compose file names the
  simulator's interfaces (`interface_name`), which needs Docker Engine 28.1 where the
  host has 26.1, and the runner creates its temporary directories under `/tmp` and hands
  them to compose as bind mounts, so the runner and the daemon must share one
  filesystem view. In that daemon the bridge netfilter hook is switched off
  (`bridge-nf-call-iptables=0`): with it on, the daemon's own iptables rules drop a
  bridged frame whose IP destination lies on another bridge, which is every packet the
  client sends to the server through the simulator. It copies the tree into
  `bench/tmp/interop/src` as the build context,
  builds both images in that daemon, adds agensio to the runner's implementation list
  and runs the matrix; the summary goes to `bench/results/interop-<stamp>.md`, the
  runner's logs and traces to `bench/tmp/interop/logs-<stamp>`.

```
bench/quic-interop/run.sh -c quic-go,ngtcp2 -t handshake,transfer,retry,http3,multiplexing
bench/quic-interop/run.sh                      # every case against quic-go and ngtcp2
```

The first run pulls the simulator and client images (about 1 GB).
