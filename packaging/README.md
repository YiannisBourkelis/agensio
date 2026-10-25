# Packaging

- `agensio.service`, `agensio.logrotate`: installed by every package (`/lib/systemd/system`, `/etc/logrotate.d`).
- `etc/`: the packaged `/etc/agensio/agensio.toml` and `sites.d/default.toml` (serves `/var/www/html`).
- `www/index.html`: the placeholder page, copied into an empty `/var/www/html` at install.
- `firewall/agensio.nft`, `fail2ban/jail.d/agensio.conf`, `fail2ban/filter.d/agensio-*.conf`,
  `agensio-firewall.service`: the host protection of `docs/configuration.md` 18, installed
  inactive under `/usr/share/agensio/` (the unit under `/usr/lib/systemd/system/`); root
  applies them by hand, trial first. All but the filters are `build/agensio protection
  --defaults --nft | --jail | --unit` (ports 80 and 443), the filters `--filter NAME`; the
  unit test holds the files to the renderers, so regenerate them after a change there.
- `deb/`: maintainer scripts for the `.deb` that CPack builds (`cpack -G DEB` in the build directory).
- `rpm/agensio.spec`: for COPR (builds from the tag's tarball); CPack also builds an `.rpm` with the same scripts.
  It lists its files itself, so a file CMake installs that it does not name, or a directory it names
  that nothing makes, fails the build: it packs the documentation directory CMake fills, makes the
  `/var` directories it owns, and installs `agensio.sysusers` as `/usr/lib/sysusers.d/agensio.conf`,
  which provides the `user(agensio)` and `group(agensio)` Fedora's rpm requires for the owners in
  `%files`. `tests/rpm.sh` builds it from the working tree in a Fedora container, installs it and
  checks the guides, the owners and `agensio -t`; run it after any change to the spec or to what
  CMake installs.
- `arch/`: `PKGBUILD` and install hooks; the release workflow's `arch` job builds the binary
  `.pkg.tar.zst` from it in an Arch container and attaches it to the release
  (`sudo pacman -U ./agensio-*.pkg.tar.zst`); the same file is what the AUR will publish.
- `.github/workflows/release.yml` builds the `.deb` and `.rpm` on every `v*` tag, attaches them to the GitHub release, and publishes the APT repository to GitHub Pages when the `APT_GPG_PRIVATE_KEY` secret exists (`docs/install.md`). Two `.deb` files, built by two jobs that run in parallel, neither waiting for the other:
  - `packages`, on Ubuntu 22.04: `agensio_<version>_amd64.deb` (and the `.rpm`) for Debian 12, Ubuntu 22.04 and later, without HTTP/3 (OpenSSL 3.0 has no QUIC TLS API). It feeds the APT repository and the `fedora` smoke test.
  - `debian13`, in a `debian:trixie` container: `agensio_<version>+deb13_amd64.deb` (`-DAGENSIO_DEB_SUFFIX=deb13`), against Debian 13's OpenSSL 3.5, with HTTP/3, which the job proves by loading a configuration with `"h3"`; Debian 13 and later only.
  - Whichever finishes first creates the release (`release-upload.sh`, which also takes the version's section of `CHANGELOG.md` as the notes), and the other attaches its files to it.

Version strings: the tag is `v0.1.0-alpha.1`; Debian gets `0.1.0~alpha.1` (a tilde sorts
before the release), RPM `0.1.0-0.1.alpha.1`, Arch `0.1.0alpha1-1`.

## Publishing the APT repository (one-time setup)

The release workflow's `apt` job signs and publishes the repository to GitHub Pages
(`packaging/apt-repo.sh`: suites `stable` and `trixie`) only when the repository secret
`APT_GPG_PRIVATE_KEY` exists; `tests/apt-repo.sh` builds and installs from it locally.

1. A signing key without a passphrase (the workflow cannot type one), kept only in the
   GitHub secret and in a backup you control:

   ```sh
   gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "agensio packages <yiannis@grbytes.com>" ed25519 sign never
   gpg --armor --export-secret-keys "agensio packages" > agensio-apt-signing.key   # the secret; keep it safe
   ```

2. GitHub, repository *Settings*: *Secrets and variables* / *Actions* / *New repository
   secret*: name `APT_GPG_PRIVATE_KEY`, value: the whole content of the file above.
3. *Settings* / *Pages*: *Build and deployment*: source *Deploy from a branch*, branch
   `gh-pages`, folder `/ (root)`. The branch appears after the first publishing run.
4. Run a release (or delete and re-push the current tag). The workflow writes
   `https://yiannisbourkelis.github.io/agensio/agensio.gpg` and `.../apt/`.

Each release publishes the whole site anew: each suite lists that release and the one before it,
whose files stay so that a host meeting an index GitHub Pages' CDN still caches (up to ten
minutes) finds what it names; the indexes are also served by hash (`Acquire-By-Hash`). Anything
older is dropped, and the branch is one commit each time, so neither the site nor the repository's
history grows with the releases. Debian sorts `0.1.0~alpha.2` before `0.1.0~alpha.3` and before
`0.1.0`, so `apt upgrade` follows the tags in order.
