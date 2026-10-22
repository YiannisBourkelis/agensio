# HTTP/3 on older distributions: OpenSSL versions, nginx's compatibility layer, how others ship

Research notes, 2026-10-22. Every fact has its source URL. Anything marked **(inference)** is my
reading of the sources, not something a source says. Package versions are as published on the day
of checking (2026-10-22) and will move.

Context: agensio's HTTP/3 calls OpenSSL's third-party QUIC TLS API: `SSL_set_quic_tls_cbs` and
`SSL_set_quic_tls_transport_params` in `src/quic/tls.cpp`, detected by `check_symbol_exists` in
`CMakeLists.txt`. The man page says "These functions were added in OpenSSL 3.5."
(https://raw.githubusercontent.com/openssl/openssl/openssl-3.5/doc/man3/SSL_set_quic_tls_cbs.pod,
HISTORY). OpenSSL 3.5.0's changelog: "Added new API calls to enable 3rd party QUIC stacks to use the
OpenSSL TLS implementation." and "Added new API to enable 0-RTT for 3rd party QUIC stacks."
(https://raw.githubusercontent.com/openssl/openssl/openssl-3.5/CHANGES.md, "Changes between 3.4 and
3.5.0 [8 Apr 2025]").

---

## 1. OpenSSL per distribution

### Summary table

| Distribution | OpenSSL now (updates/security) | 3.5 QUIC TLS API? | Library binary package |
|---|---|---|---|
| Debian 12 bookworm | 3.0.22-1~deb12u1 (security; amd64, arm64, armhf, i386, ppc64el) | no | `libssl3` |
| Debian 12 bookworm-backports | no OpenSSL binaries (source 3.0.14-1~deb12u1 kept as `Extra-Source-Only`) | no | none |
| Debian 13 trixie | 3.5.7-1~deb13u3 (security) | yes | `libssl3t64` (Provides `libssl3`) |
| Ubuntu 22.04 jammy | 3.0.2-0ubuntu1.30 | no | `libssl3` |
| Ubuntu 24.04 noble | 3.0.13-0ubuntu3.16 | no | `libssl3t64` (Provides `libssl3`) |
| Ubuntu 25.04 plucky (obsolete) | 3.4.1-1ubuntu4 | no | |
| Ubuntu 25.10 questing (obsolete) | 3.5.3-1ubuntu3.4 | yes | |
| Ubuntu 26.04 LTS resolute (released 2026-04-23) | 3.5.5-1ubuntu3.7 | yes | `libssl3t64` (Provides `libssl3`) |
| Ubuntu 26.10 stonking (released 2026-10-15) | 4.0.3-1ubuntu1 | yes (inference: 4.0 keeps the API) | |
| RHEL 9.0 / 9.1 | 3.0.1 | no | `openssl-libs` |
| RHEL 9.2 / 9.3 / 9.4 | 3.0.7 | no | |
| RHEL 9.5 / 9.6 | 3.2.2 | no | |
| RHEL 9.7 | 3.5.1 | yes | |
| RHEL 9.8 (current 9) | 3.5.5, then 3.5.8 | yes | |
| RHEL 10.0 | 3.2.2 | no | |
| RHEL 10.1 | 3.5.1 | yes | |
| RHEL 10.2 (current 10) | 3.5.5, then 3.5.8 | yes | |
| Fedora 42 (archived 2026-05-27) | 3.2.6-4.fc42 | no | |
| Fedora 43 | 3.5.9-1.fc43 | yes | |
| Fedora 44 | 3.5.9-1.fc44 | yes | |
| Arch Linux | 3.6.5-1 | yes | `openssl` |

### Debian

- All suites, one page (https://packages.debian.org/search?keywords=openssl&searchon=names&exact=1&suite=all&section=all):
  bookworm (oldstable) 3.0.22-1~deb12u1 [security] on amd64, arm64, armhf, i386, ppc64el (3.0.20-1~deb12u2 on the
  other architectures); bookworm-updates 3.0.17-1~deb12u2; trixie (stable) 3.5.7-1~deb13u3 [security]; forky
  (testing) and sid 3.6.5-1; experimental 4.0.3-1. The page lists no openssl for bookworm-backports, trixie-updates
  or trixie-backports.
- bookworm-backports: the suite's source index has one `openssl` stanza, version 3.0.14-1~deb12u1, marked
  `Extra-Source-Only: yes`, and the amd64 binary index has no `openssl`, `libssl3` or `libssl-dev`
  (https://deb.debian.org/debian/dists/bookworm-backports/main/source/Sources.xz,
  https://deb.debian.org/debian/dists/bookworm-backports/main/binary-amd64/Packages.xz; InRelease dated
  2026-10-22). `packages.debian.org/source/bookworm-backports/openssl` answers "Package not available in this suite."
  (https://packages.debian.org/source/bookworm-backports/openssl). **There is no OpenSSL 3.5 for bookworm from Debian.**
  (inference: the source-only entry is kept for some backport's Built-Using, not something you can install.)
- The rename, confirmed. trixie's library package is `libssl3t64`, 3.5.7-1~deb13u3, source openssl
  (https://packages.debian.org/trixie/libssl3t64). Its control stanza: `Provides: ${t64:Provides}`,
  `Replaces: libssl3`, `Breaks: libssl3 (<< ${source:Version}), ...`
  (https://sources.debian.org/data/main/o/openssl/3.5.7-1~deb13u3/debian/control). In the amd64 archive index
  that becomes `Provides: libssl3 (= 3.5.7-1~deb13u3)`, `Replaces: libssl3`,
  `Depends: libc6 (>= 2.38), libzstd1 (>= 1.5.5), zlib1g (>= 1:1.1.4), openssl-provider-legacy`
  (https://security.debian.org/debian-security/dists/trixie-security/main/binary-amd64/Packages.xz).
  Why the rename happened: Debian 13 release notes, 2.2.6 "64-bit time_t ABI transition": "All architectures other
  than i386 now use a 64-bit time_t ABI ... On 32-bit architectures (armel and armhf) the ABI of many libraries
  changed without changing the library 'soname'." (https://www.debian.org/releases/trixie/release-notes/whats-new.en.html).
- trixie's OpenSSL is built without `no-quic`: its `CONFARGS` are `... no-idea no-mdc2 no-rc5 no-ssl3 enable-unit-test
  no-ssl3-method enable-rfc3779 enable-cms no-capieng no-rdrand enable-tfo enable-zstd enable-zlib enable-fips`
  (https://sources.debian.org/data/main/o/openssl/3.5.7-1~deb13u3/debian/rules). The symbols file maps every symbol
  versioned `@OPENSSL_3.5.0` to `libssl3t64 (>= 3.5.0)`
  (https://sources.debian.org/data/main/o/openssl/3.5.7-1~deb13u3/debian/libssl3t64.symbols).
- What it means for a .deb built on trixie and installed on bookworm (**inference** from the facts below):
  - A binary that calls `SSL_set_quic_tls_cbs` gets `Depends: libssl3t64 (>= 3.5.0)` from that symbols file (nginx.org's
    trixie package shows exactly this: `libssl3t64 (>= 3.5.0)`, see section 4). bookworm has no `libssl3t64` at all,
    and its `libssl3` is 3.0.x, so the package is uninstallable there, and even forced the binary would fail to load
    for want of `OPENSSL_3.5.0` symbols.
  - The C and C++ runtimes block it as well: trixie has libc6 2.41-12+deb13u4 (https://packages.debian.org/trixie/libc6)
    and libstdc++6 14.2.0-19 from gcc-14 (https://packages.debian.org/trixie/libstdc++6); bookworm has libc6
    2.36-9+deb12u14 (https://packages.debian.org/bookworm/libc6) and libstdc++6 12.2.0-14+deb12u1 from gcc-12
    (https://packages.debian.org/bookworm/libstdc++6). A C++23 binary built with GCC 14 on trixie will normally need
    symbol versions bookworm's libraries do not have.
  - The other direction works: a .deb built on jammy or bookworm declares `libssl3 (>= 3.0.x)`, which trixie, noble and
    resolute satisfy through `Provides: libssl3 (= ...)` on 64-bit architectures (trixie above; noble
    `Provides: libssl3 (= 3.0.13-0ubuntu3.16)`, http://archive.ubuntu.com/ubuntu/dists/noble-updates/main/binary-amd64/Packages.xz;
    resolute `Provides: libssl3 (= 3.5.5-1ubuntu3.7)`, http://archive.ubuntu.com/ubuntu/dists/resolute-updates/main/binary-amd64/Packages.xz).
    That is why agensio's jammy-built package installs on trixie today, without HTTP/3.

### Ubuntu

- Launchpad overview (https://launchpad.net/ubuntu/+source/openssl): resolute 3.5.5-1ubuntu3 at release,
  3.5.5-1ubuntu3.7 in security and updates; noble 3.0.13-0ubuntu3 at release, 3.0.13-0ubuntu3.16 now; jammy
  3.0.2-0ubuntu1 at release, 3.0.2-0ubuntu1.30 now; "Stonking Stingray" (current stable) and "Tenacious T-Rex"
  (pre-release freeze) 4.0.3-1ubuntu1.
- 25.04 plucky: release 3.4.1-1ubuntu3, security/updates 3.4.1-1ubuntu4 (https://launchpad.net/ubuntu/plucky/+source/openssl).
- 25.10 questing: release 3.5.3-1ubuntu2, security/updates 3.5.3-1ubuntu3.4 (https://launchpad.net/ubuntu/questing/+source/openssl).
- 26.04 resolute: release 3.5.5-1ubuntu3, security/updates 3.5.5-1ubuntu3.7 (https://launchpad.net/ubuntu/resolute/+source/openssl).
- Series states (https://launchpad.net/ubuntu/+series): 25.04 Plucky Obsolete, 25.10 Questing Obsolete, 26.04 Resolute
  Supported, 26.10 Stonking Current Stable Release, 27.04 Tenacious Pre-release Freeze. Release dates from the
  Launchpad API: resolute 26.04 `datereleased` 2026-04-23 (https://api.launchpad.net/devel/ubuntu/resolute), stonking
  26.10 2026-10-15 (https://api.launchpad.net/devel/ubuntu/stonking).
- Package names: jammy `libssl3`, 3.0.2-0ubuntu1.30 (https://launchpad.net/ubuntu/jammy/amd64/libssl3); noble
  `libssl3t64`, 3.0.13-0ubuntu3.16, published 2026-09-29 (https://launchpad.net/ubuntu/noble/amd64/libssl3t64);
  resolute `libssl3t64` 3.5.5-1ubuntu3.7 (resolute-updates index above).
- No OpenSSL in jammy-backports or noble-backports (main and universe source indexes have no `openssl` package:
  http://archive.ubuntu.com/ubuntu/dists/noble-backports/main/source/Sources.xz,
  http://archive.ubuntu.com/ubuntu/dists/jammy-backports/universe/source/Sources.xz and siblings). **No official
  OpenSSL 3.5 for 22.04 or 24.04.** I did not look at PPAs or Ubuntu Pro.

### RHEL 9 and 10 (Red Hat release notes, with Rocky and Alma package listings for the per-minor versions)

- 9.5: "The OpenSSL TLS toolkit is upgraded to version 3.2.2."
  (https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/9.5_release_notes/overview).
- 9.7: "OpenSSL is rebased to upstream version 3.5." with "Added support for the QUIC transport protocol according to
  the IETF RFC 9000 draft." (https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/9.7_release_notes/new-features).
- 10.1: section 6.2 "OpenSSL is rebased to upstream version 3.5." (same QUIC line)
  (https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/10.1_release_notes/index).
  The 10.0 overview names no OpenSSL version (https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/10.0_release_notes/overview).
- Rocky Linux BaseOS listings (rebuilds of RHEL, so a proxy for RHEL's own builds):
  - 9.0 `openssl-3.0.1-43.el9_0`, 9.1 `3.0.1-47.el9_1`, 9.2 `3.0.7-17.el9_2`, 9.3 `3.0.7-24/25`, 9.4 `3.0.7-27/28.el9_4`,
    9.5 `3.2.2-6.el9_5(.1)`, 9.6 `3.2.2-6.el9_5.1` (no rebase in 9.6), 9.7 `3.5.1-4/5/7.el9_7`
    (https://dl.rockylinux.org/vault/rocky/9.0/BaseOS/x86_64/os/Packages/o/ and the same path for 9.1 to 9.7).
  - 9 current (9.8): `3.5.5-2..6.el9_8`, `3.5.8-1/2.el9_8` (https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/Packages/o/).
  - 10.0 `3.2.2-16.el10(_0.4)`, 10.1 `3.5.1-3.el10` to `3.5.1-7.el10_1`
    (https://dl.rockylinux.org/vault/rocky/10.0/BaseOS/x86_64/os/Packages/o/, .../10.1/...), 10 current (10.2)
    `3.5.5-*.el10_2`, `3.5.8-1/2.el10_2` (https://dl.rockylinux.org/pub/rocky/10/BaseOS/x86_64/os/Packages/o/).
  - AlmaLinux agrees: 9 current `openssl-libs-3.5.8-2.el9_8` (https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/Packages/),
    9.6 vault `3.2.2-6.el9_5.1` (https://vault.almalinux.org/9.6/BaseOS/x86_64/os/Packages/), 10 current
    `3.5.8-2.el10_2.alma.1` (https://repo.almalinux.org/almalinux/10/BaseOS/x86_64/os/Packages/).
- Red Hat's build keeps QUIC: CentOS Stream 9's spec is 3.5.9 and configures with `enable-sslkeylog ... enable-ktls
  enable-fips ... no-mdc2 no-ec2m no-sm2 no-sm4`, no `no-quic`
  (https://gitlab.com/redhat/centos-stream/rpms/openssl/-/raw/c9s/openssl.spec). (inference: so 9.7+ has
  `SSL_set_quic_tls_cbs`; nginx.org's RHEL 9 package requiring `libssl.so.3(OPENSSL_3.5.0)` in section 4 agrees.)
- **(inference)** A binary built on RHEL 9.7+ against 3.5 requires `libssl.so.3(OPENSSL_3.5.0)` and installs on 9.7
  and later only; RHEL 9.4 and 9.6 EUS hosts stay on 3.0.7 and 3.2.2.

### Fedora

- Bodhi: F42 state `archived`, EOL 2026-05-27, last stable `openssl-3.2.6-4.fc42`
  (https://bodhi.fedoraproject.org/releases/F42, https://bodhi.fedoraproject.org/updates/FEDORA-2026-7af660d639);
  F43 `current`, EOL 2026-12-02, `openssl-3.5.9-1.fc43` (https://bodhi.fedoraproject.org/updates/FEDORA-2026-93eed17997);
  F44 `current`, `openssl-3.5.9-1.fc44` (https://bodhi.fedoraproject.org/updates/FEDORA-2026-12f3f3d569).
- dist-git specs: f42 `Version: 3.2.6` (https://src.fedoraproject.org/rpms/openssl/raw/f42/f/openssl.spec), f43 and f44
  `Version: 3.5.9` (https://src.fedoraproject.org/rpms/openssl/raw/f43/f/openssl.spec), rawhide `Version: 4.0.3`
  (https://src.fedoraproject.org/rpms/openssl/raw/rawhide/f/openssl.spec); none configures `no-quic`.

### Arch

- `openssl 3.6.5-1` in core, updated 2026-09-30 (https://archlinux.org/packages/core/x86_64/openssl/).

---

## 2. OpenSSL 3.5's support status

From the release strategy (https://openssl-library.org/policies/releasestrat/; www.openssl.org redirects there):

- "Every two years we designate a release as a Long Term Support (LTS) release that will be supported for at least
  5 years. During the final year of support, we do not commit to anything other than security fixes."
- "Starting with 3.5, there will be a Long Term Support (LTS) every two years. Starting with 5.0 (October 2027),
  there will be major release every two years."
- "Non-LTS releases after 3.5 will be full supported for 13 months."
- Dates: "Version 4.0 will be supported until 2027-05-14", "Version 3.6 will be supported until 2026-11-01",
  "Version 3.5 will be supported until 2030-04-08 (LTS)", "Version 3.4 will be supported until 2026-10-22",
  "Versions 3.0, 1.1.1 and 1.0.2 are no longer supported." (paid extended support exists for them).
- So **3.5 is the current LTS, supported to 2030-04-08**, and upstream 3.0 (what bookworm, jammy, noble and RHEL 9.0
  to 9.4 carry) has ended; those distributions patch their 3.0 themselves.
- 3.5.x point releases so far: 3.5.1 (1 Jul 2025) to 3.5.9 (29 Sep 2026)
  (https://raw.githubusercontent.com/openssl/openssl/openssl-3.5/CHANGES.md). The 3.5.8 to 3.5.9 section lists a
  run of QUIC fixes (amplification credit, O(n^2) reassembly, unbounded queues); from their wording these are in
  OpenSSL's own QUIC server stack, not in the third-party TLS callbacks (inference).
- One 3.5.0 bug matters to any server with SNI: in 3.5.0 the `quic_transport_parameters` extension set through the
  QUIC TLS API was cleared when `SSL_set_SSL_CTX()` switched contexts on SNI, so a server stopped sending its
  transport parameters (nginx commit cedb855d75, https://github.com/nginx/nginx/commit/cedb855d75ceefd7fe513f9c27c9364678582786;
  report https://github.com/nginx/nginx/issues/711; OpenSSL fix
  https://github.com/openssl/openssl/commit/45bd3c3798ab2f1f143f26c27b6d080c72b70eea, PR
  https://github.com/openssl/openssl/pull/27706). nginx says it "is now fixed in the OpenSSL 3.5.1 release"
  (https://github.com/nginx/nginx/commit/0bb7489cb2fcc60ce24fae2d5581c7441bfa0931). Every distribution above with 3.5
  ships 3.5.1 or later.
- HAProxy draws its line at 3.5.2: "QUIC is not fully supported when haproxy is built with OpenSSL < 3.5.2 version"
  (https://raw.githubusercontent.com/haproxy/haproxy/master/INSTALL). I did not find which 3.5.2 change that refers to;
  the 3.5.1 to 3.5.2 changelog section lists only a FIPS PCT change.

---

## 3. nginx's OpenSSL compatibility layer for QUIC

### When and what for

- Added by commit a36ebf7e95 "QUIC: OpenSSL compatibility layer." (2023-02-22): "The change allows to compile QUIC with
  OpenSSL which lacks BoringSSL QUIC API. This implementation does not support 0-RTT." It added 646 lines in
  `ngx_event_quic_openssl_compat.c` and 60 in the header
  (https://github.com/nginx/nginx/commit/a36ebf7e95baebf445b0973bd270bc009b0b0e9a).
- First release: 1.25.0 (the GitHub compare shows the commit inside `release-1.25.0` and not in `release-1.24.0`,
  https://api.github.com/repos/nginx/nginx/compare/release-1.25.0...a36ebf7e95). 1.25.0's CHANGES entry is
  "Feature: experimental HTTP/3 support." (https://nginx.org/en/CHANGES). Today's docs: "Support for QUIC and HTTP/3
  protocols is available since 1.25.0, it is included in Linux binary packages." (https://nginx.org/en/docs/quic.html).
- Which OpenSSL versions: the selection is in `src/event/quic/ngx_event_quic.h` (master, 1.31.8):
  `OPENSSL_VERSION_NUMBER >= 0x30500010L` (3.5.1) uses the native API (`NGX_QUIC_OPENSSL_API`); else
  `SSL_R_MISSING_QUIC_TRANSPORT_PARAMETERS_EXTENSION` defined means QuicTLS; else BoringSSL, AWS-LC or LibreSSL use the
  BoringSSL API; else (plain OpenSSL) `NGX_QUIC_BORINGSSL_API` plus `NGX_QUIC_OPENSSL_COMPAT`
  (https://raw.githubusercontent.com/nginx/nginx/master/src/event/quic/ngx_event_quic.h). configure tries
  `SSL_set_quic_tls_cbs`, then `SSL_set_quic_method`, then for the compat layer only `SSL_CTX_add_custom_ext`
  (https://raw.githubusercontent.com/nginx/nginx/master/auto/lib/openssl/conf). **(inference)** So the layer serves
  OpenSSL 1.1.1 (the first with TLS 1.3, the keylog callback and custom extensions for TLS 1.3 messages) through 3.5.0.
- Docs today: "The OpenSSL library version 3.5.1 or higher is recommended to build nginx with QUIC support. Otherwise,
  the OpenSSL compatibility layer will be used that does not support early data. Alternatively, BoringSSL, LibreSSL,
  or QuicTLS prebuilt libraries can be used." (https://nginx.org/en/docs/quic.html). The page does not mention AWS-LC,
  although CHANGES 1.29.2 says "Feature: now nginx can be built with AWS-LC." (https://nginx.org/en/CHANGES).

### How it works (`src/event/quic/ngx_event_quic_openssl_compat.c`, master)

Size: 657 lines in the .c, 52 in the .h on master at 1.31.8
(https://raw.githubusercontent.com/nginx/nginx/master/src/event/quic/ngx_event_quic_openssl_compat.c,
https://raw.githubusercontent.com/nginx/nginx/master/src/event/quic/ngx_event_quic_openssl_compat.h). It implements the
BoringSSL-style API itself (`SSL_set_quic_method`, `SSL_provide_quic_data`, `SSL_set_quic_transport_params`,
`SSL_get_peer_quic_transport_params`, the `SSL_QUIC_METHOD` struct) over OpenSSL's ordinary TLS 1.3 stack:

1. **Secrets from the keylog callback.** `ngx_quic_compat_keylog_init` installs `SSL_CTX_set_keylog_callback`; the
   callback parses the NSS key log lines `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`,
   `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0` from hex text and hands each to the QUIC method's
   `set_read_secret` / `set_write_secret`. Yes, it uses the keylog callback for the secrets.
2. **Transport parameters as a custom extension.** `SSL_CTX_add_custom_ext(ctx, 0x39, SSL_EXT_CLIENT_HELLO |
   SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS, add_cb, ..., parse_cb, ...)`: extension 57, quic_transport_parameters, added
   to EncryptedExtensions and parsed from ClientHello. Yes, a custom extension.
3. **Outgoing handshake bytes from the message callback.** `SSL_set_quic_method` gives the SSL a memory read BIO and a
   *null* write BIO, and `SSL_set_msg_callback` catches each handshake message and alert OpenSSL "writes", passing them
   to `add_handshake_data` / `send_alert` at the current level. The TLS records OpenSSL produces go to the null BIO.
4. **Incoming CRYPTO data re-wrapped as TLS records, re-encrypted.** `SSL_provide_quic_data` turns the CRYPTO bytes into
   TLS records and writes them into the read BIO: at the Initial level as plaintext handshake records (up to 65,535
   bytes each); at the Handshake level it derives the record key and IV itself from the client handshake secret
   (HKDF "tls13 key" / "tls13 iv") and **seals TLS 1.3 records** with AEAD (`ngx_quic_crypto_seal`, inner content type
   appended, 1,024-byte records, nonce from a record counter), so OpenSSL can decrypt them again as if they came from a
   TLS peer. Yes, its own TLS 1.3 record encryption of the handshake messages (inbound only; outbound needs none,
   because the message callback sees plaintext).
5. Early data: `SSL_set_max_early_data(ssl, 0); /* early data is not supported */`.

HAProxy's compat layer is the same design ("Highly inspired from nginx QUIC TLS compatibility code"), 530 lines, and
also registers the keylog callback and the custom extension
(https://raw.githubusercontent.com/haproxy/haproxy/master/src/quic_openssl_compat.c).

**What it does not support, and what it costs** (sources above; costs are inference):
- 0-RTT / early data (commit message, docs, the code).
- It occupies the keylog callback (HAProxy's copy notes it shares the callback with its own TLS key logging).
- Its extension and callbacks live on the `SSL_CTX`, which TCP TLS connections share; three of the bugs below come
  from that.
- Every inbound Handshake-level CRYPTO byte is encrypted once by nginx and decrypted once by OpenSSL (inference: extra
  AEAD work per handshake, small next to the certificate signature).

### Native OpenSSL 3.5 API in nginx

- Commit 6a134dfd48 "QUIC: using QUIC API introduced in OpenSSL 3.5." (committed 2025-05-23; PR
  https://github.com/nginx/nginx/pull/646): "Similarly to the QUIC API originated in BoringSSL, this API allows to
  register custom TLS callbacks for an external QUIC implementation." (https://github.com/nginx/nginx/commit/6a134dfd4888fc3850d22294687cfb3940994c69).
- Commit cedb855d75 (2025-06-23), "QUIC: disabled OpenSSL 3.5 QUIC API support by default.", because of the 3.5.0 SNI
  bug: "When building with OpenSSL 3.5, OpenSSL compat layer is now used by default. The OpenSSL 3.5 QUIC API support
  can be switched back using --with-cc-opt='-DNGX_QUIC_OPENSSL_API=1'."
  (https://github.com/nginx/nginx/commit/cedb855d75ceefd7fe513f9c27c9364678582786).
- Commit 0bb7489cb2 (2025-07-03), "QUIC: adjusted OpenSSL 3.5 QUIC API feature test.": native API from 3.5.1
  (https://github.com/nginx/nginx/commit/0bb7489cb2fcc60ce24fae2d5581c7441bfa0931).
- Releases (GitHub compare): 6a134dfd48 and cedb855d75 are in `release-1.29.0`, 0bb7489cb2 is not, and it is in
  `release-1.29.1` (https://api.github.com/repos/nginx/nginx/compare/release-1.29.0...0bb7489cb2,
  .../release-1.29.1...0bb7489cb2). 1.27.5 does not contain the native API
  (https://api.github.com/repos/nginx/nginx/compare/release-1.27.5...6a134dfd48), and the 1.28 stable branch has no
  `SSL_set_quic_tls_cbs` at `release-1.28.3`, while 1.30.0 has it
  (https://raw.githubusercontent.com/nginx/nginx/release-1.28.3/src/event/quic/ngx_event_quic_ssl.c,
  https://raw.githubusercontent.com/nginx/nginx/release-1.30.0/src/event/quic/ngx_event_quic_ssl.c).
- So: **nginx 1.29.1+ (mainline) and 1.30.x (stable) prefer the native API when built against OpenSSL >= 3.5.1**; 1.29.0
  used the compat layer by default even with 3.5; 1.27.x and 1.28.x only have the compat layer for OpenSSL. CHANGES
  1.29.1: "Feature: support for 0-RTT in QUIC when using OpenSSL 3.5.1 or newer." (https://nginx.org/en/CHANGES).
  Current mainline is 1.31.8 of 21 Oct 2026 (same file).
- freenginx (the Dounin fork) has not taken it: its tip (1.31.4) `ngx_event_quic_ssl.c` has no `SSL_set_quic_tls_cbs`
  and selects the BoringSSL API for BoringSSL, LibreSSL or the compat layer
  (https://freenginx.org/hg/nginx/raw-file/tip/src/event/quic/ngx_event_quic_ssl.c); its docs recommend "BoringSSL,
  LibreSSL, or QuicTLS" and say the fallback "does not support early data" (https://freenginx.org/en/docs/quic.html).
  (inference: freenginx with OpenSSL 3.5 still runs through the compat layer.)

### Known problems with the compatibility layer

- Ticket #2500, fixed 2023-05-28 (1.25.1): the compat layer used AES-128 whatever cipher was negotiated, because a
  record's level was left uninitialised (https://github.com/nginx/nginx/commit/cb70d5954c65b5683bc1c104bbf2466b73f4aa2b;
  CHANGES 1.25.1 "Bugfix: in HTTP/3 when using OpenSSL.", https://nginx.org/en/CHANGES).
- c67bf9415f (2026-02-24): NULL dereference in `ngx_quic_compat_create_record()` when key setup in the keylog callback
  failed under memory pressure (https://github.com/nginx/nginx/commit/c67bf9415fca91434f047d6113435e4cc699c859).
- **CVE-2026-90439**, "Buffer overflow when using ngx_http_v3_module", medium, vulnerable 1.29.2-1.31.5, fixed in 1.31.6+
  and 1.30.5+ (https://nginx.org/en/security_advisories.html). CHANGES 1.31.6 (15 Sep 2026): "a heap memory buffer
  overflow might occur in a worker process under certain configurations when using HTTP/3 with OpenSSL 3.5.0 and
  earlier" (https://nginx.org/en/CHANGES). The fix, 7c7363266d: the compat layer registered its custom extension only
  in the SSL contexts of QUIC-reachable virtual servers, and the ClientHello callback added in 1.29.2 lets OpenSSL switch
  contexts between collecting and parsing extensions, so "the custom extensions may not match the expected number";
  now the extension is registered in all SSL contexts (https://github.com/nginx/nginx/commit/7c7363266d54bc3836c1d13d1ed1e1d93ee9ed98;
  in `release-1.31.6`, not in 1.31.5: https://api.github.com/repos/nginx/nginx/compare/release-1.31.6...7c7363266d).
  Follow-up 22ba566244: the QUIC extension received in an ordinary TCP TLS handshake is now ignored instead of failing
  the handshake (https://github.com/nginx/nginx/commit/22ba5662440d2865153ac1ff7de5f2b171414346; CHANGES 1.31.6
  "Change: now the QUIC transport parameters extension received in an SSL connection is always ignored.").
- GitHub #1490 (closed 2026-06-23): workers SIGSEGV in `SSL_do_handshake` (`BUF_MEM_grow_clean` -> `memset`) on the
  official nginx.org noble package 1.30.3 "built with OpenSSL 3.0.13", only with `listen ... quic` enabled, on ordinary
  TCP handshakes from scanners; the maintainer's advice was "building against OpenSSL 3.5+ which uses the native QUIC
  API and doesn't compile in the compat layer at all"; a later comment (2026-08-23) gives a sufficient condition, more
  custom extension methods in the SNI-selected context than in the default server's, which is the CVE-2026-90439
  mechanism (https://github.com/nginx/nginx/issues/1490). (inference: that link is the commenter's analysis and the
  dates line up; the issue thread itself does not confirm the original crash was this bug.)
- GitHub #1415 (closed 2026-07-14): "Active connections" climbing on 1.30.x with HTTP/3, nginx.org noble package with
  OpenSSL 3.0.13; a maintainer's conclusion: "same crash as #1490 ... reached through the OpenSSL 3.0-3.4 QUIC
  compatibility layer", each crashed worker leaving its counts in the shared zone; also: "the nginx.org Noble package
  doesn't ship its own OpenSSL -- it links the system one, which on Ubuntu 24.04 LTS is 3.0.13"
  (https://github.com/nginx/nginx/issues/1415). Another maintainer comment in the same thread says an audit of the
  compat framing found no nginx-side overflow, so the root cause was open there as of 2026-07-20.
- GitHub #1371 (open): worker segfaults in `ngx_http_v3_parse_field_ri` with 1.31.0-1~bookworm (nginx.org package on
  Debian 12, so OpenSSL 3.0 and the compat layer); the crash is in HTTP/3 field parsing, not in the layer itself
  (https://github.com/nginx/nginx/issues/1371).

---

## 4. How other servers ship HTTP/3 on older distributions

### nginx.org packages

- Built per codename: `nginx.org/packages/mainline/ubuntu/dists/` has jammy, noble, resolute, plucky, questing and older
  ones (https://nginx.org/packages/mainline/ubuntu/dists/); Debian has bookworm and trixie among others
  (https://nginx.org/packages/mainline/debian/dists/). Supported today: RHEL 8.x, 9.x, 10.x; Debian 12, 13; Ubuntu
  22.04, 24.04, 26.04; SLES 15 SP6+, 16; Alpine 3.21-3.24; Amazon Linux 2023 (https://nginx.org/en/linux_packages.html).
- They link the **system OpenSSL**, dynamically. `Depends` of nginx 1.31.8 in each repository:
  - jammy `libssl3 (>= 3.0.0~~alpha1)` (https://nginx.org/packages/mainline/ubuntu/dists/jammy/nginx/binary-amd64/Packages.gz)
  - noble `libssl3t64 (>= 3.0.0)` (https://nginx.org/packages/mainline/ubuntu/dists/noble/nginx/binary-amd64/Packages.gz)
  - resolute `libssl3t64 (>= 3.5.0)` (https://nginx.org/packages/mainline/ubuntu/dists/resolute/nginx/binary-amd64/Packages.gz)
  - bookworm `libssl3 (>= 3.0.0)` (https://nginx.org/packages/mainline/debian/dists/bookworm/nginx/binary-amd64/Packages.gz;
    stable 1.30.6 the same: https://nginx.org/packages/debian/dists/bookworm/nginx/binary-amd64/Packages.gz)
  - trixie `libssl3t64 (>= 3.5.0)` (https://nginx.org/packages/mainline/debian/dists/trixie/nginx/binary-amd64/Packages.gz)
  - RHEL 9: the 1.31.8-1.el9.ngx RPM requires `libssl.so.3(OPENSSL_3.5.0)(64bit)` among others
    (https://nginx.org/packages/mainline/rhel/9/x86_64/repodata/ primary.xml)
- **(inference)** So nginx.org's HTTP/3 runs on the native API on trixie, resolute and RHEL 9 (built on 9.7+, so that
  package needs a 9.7+ host), and on the compat layer (no 0-RTT, the bugs above) on bookworm, jammy and noble. The
  `(>= 3.5.0)` dependencies are what dpkg-shlibdeps derives from the `@OPENSSL_3.5.0` symbols the binary uses.

### Angie

- Packages per codename from its own repository, linked to the system OpenSSL. Angie 1.12.4 `Depends`: bookworm
  `libssl3 (>= 3.0.0)`, trixie `libssl3t64 (>= 3.5.0)`, jammy `libssl3 (>= 3.0.0~~alpha1)`, noble
  `libssl3t64 (>= 3.0.0)` (https://download.angie.software/angie/debian/12/dists/bookworm/main/binary-amd64/Packages.gz,
  .../debian/13/dists/trixie/..., .../ubuntu/22.04/dists/jammy/..., .../ubuntu/24.04/dists/noble/...).
- Its HTTP/3 module page: in official packages "the module is included in the build"; "0-RTT support requires OpenSSL
  3.5.1 or higher"; BoringSSL, LibreSSL or QuicTLS "can be used to build and run this module"
  (https://en.angie.software/angie/docs/configuration/modules/http/http_v3/). The page does not name a compatibility
  layer. (inference: Angie, an nginx fork, carries the same compat layer on 3.0 systems; not verified in its source.)

### freenginx

- Source tarballs and a Windows zip only, no Linux packages (https://freenginx.org/en/download.html). See section 3 for
  its QUIC library handling.

### HAProxy

- Upstream ships no Linux packages itself; its site points to distribution packages, haproxy.debian.net, Docker images,
  and HAProxy Technologies' "Performance Packages" (https://www.haproxy.org/). It also says: "OpenSSL 3.5's QUIC API is
  supported" (3.2 release notes on the same page).
- Build options (https://raw.githubusercontent.com/haproxy/haproxy/master/INSTALL): native `USE_OPENSSL=1 USE_QUIC=1`
  "from 3.5 version with 0-RTT support", or `USE_QUIC_OPENSSL_COMPAT=1` "for all OpenSSL versions but without O-RTT
  support"; QuicTLS, AWS-LC and wolfSSL as alternatives. The compat layer must also be switched on at run time with the
  `limited-quic` global keyword: "This feature is primarily targeted for OpenSSL prior to version 3.5.2"
  (https://raw.githubusercontent.com/haproxy/haproxy/master/doc/configuration.txt).
- Debian's own package (sid/forky, salsa master, 3.2.26-1): `USE_OPENSSL=1 USE_QUIC=1` against the system OpenSSL
  (https://salsa.debian.org/haproxy-team/haproxy/-/raw/master/debian/rules). Versions: bookworm 2.6.12, trixie 3.0.11,
  forky/sid 3.2.26, experimental 3.4.7
  (https://packages.debian.org/search?keywords=haproxy&searchon=names&exact=1&suite=all&section=all).
- haproxy.debian.net (run by "The Debian HAProxy packaging team", https://haproxy.debian.net/): the bookworm 3.2
  backport depends on the system `libssl3 (>= 3.0.0)` (https://haproxy.debian.net/dists/bookworm-backports-3.2/main/binary-amd64/Packages.gz)
  and its binary's build string reads `USE_OPENSSL=1 ... USE_QUIC=1 ... USE_QUIC_OPENSSL_COMPAT=1` (read with `strings`
  from `pool/main/h/haproxy/haproxy_3.2.26-1~bpo12+1_amd64.deb` on the same host): system OpenSSL 3.0 plus the compat layer.
- HAProxy Technologies' Performance Packages: "containing the latest HAProxy stable version built against the latest
  AWS-LC stable version" (https://www.haproxy.org/, news of Dec 3rd, 2025); Debian 13 and 12, Ubuntu 26.04, 24.04,
  22.04, RHEL 9 and 10, package `haproxy-awslc` (https://www.haproxy.com/downloads). AWS-LC is **not static**: it is a
  separate package `libssl-awslc` installing `/opt/aws-lc/lib/x86_64-linux-gnu/libssl.so` and `libcrypto.so`, which
  `haproxy-awslc` depends on at an exact version (`libssl-awslc (= 3.3.0-0+ha32+ubuntu22.04u2)`), and the haproxy
  binary has `NEEDED libssl.so`, `libcrypto.so` and `RUNPATH /opt/aws-lc/lib/x86_64-linux-gnu`; its build string has
  `USE_OPENSSL_AWSLC=1 ... USE_QUIC=1` (https://www.haproxy.com/download/haproxy/performance/ubuntu/ha32/dists/jammy/main/binary-amd64/Packages.gz
  and the two .debs in its pool, inspected with `dpkg-deb -c`, `readelf -d`, `strings`; nothing was executed). The same
  repository layout exists for bookworm (https://www.haproxy.com/download/haproxy/performance/debian/ha32/dists/bookworm/main/binary-amd64/Packages.gz).

### Caddy

- Go, HTTP/3 through quic-go and Go's own TLS: `github.com/quic-go/quic-go v0.63.0` in go.mod
  (https://raw.githubusercontent.com/caddyserver/caddy/master/go.mod). `protocols` default "h1 h2 h3"; 0-RTT "enabled
  for QUIC listeners (i.e. HTTP/3)" by default (https://caddyserver.com/docs/caddyfile/options).
- The release .deb (v2.11.7, 2026-10-03, https://github.com/caddyserver/caddy/releases/tag/v2.11.7) has no `Depends`
  field and its `/usr/bin/caddy` is "ELF 64-bit LSB executable, x86-64 ... statically linked, Go BuildID=..."
  (`file` on the extracted binary): one binary for every distribution, no system TLS library.

---

## 5. Debian and Ubuntu on embedding a static OpenSSL in a third-party .deb

- I found **no official Debian or Ubuntu statement about third-party .debs** (packages outside their archives) bundling or
  statically linking OpenSSL.
- Debian Policy covers the Debian archive only: "This manual describes the policy requirements for the Debian
  distribution." (https://www.debian.org/doc/debian-policy/ch-scope.html, 1.1). For archive packages, 4.13 "Embedded
  code copies": Debian packages should not use bundled convenience copies "unless the included package is explicitly
  intended to be used in this way", and "the Debian packaging should ensure that binary packages reference the
  libraries already in Debian" (https://www.debian.org/doc/debian-policy/ch-source.html).
- Ubuntu's Main Inclusion Review applies the same to packages promoted to main: for static builds and vendored code "the
  security team will track CVEs for all vendored/embedded sources in main" and "the owning team must state their
  commitment to provide updates to the security team for any affected vendored code"
  (https://ubuntu.com/project/docs/MIR/mir-reporters-template/).
- (inference) Neither binds a vendor's own repository; the practical cost of bundling is the same one these rules guard
  against: whoever bundles OpenSSL owns its security updates (HAProxy Technologies takes that on with `libssl-awslc`).
