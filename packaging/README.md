# Packaging

- `agensio.service`, `agensio.logrotate`: installed by every package (`/lib/systemd/system`, `/etc/logrotate.d`).
- `etc/`: the packaged `/etc/agensio/agensio.toml` and `sites.d/default.toml` (serves `/var/www/html`).
- `www/index.html`: the placeholder page, copied into an empty `/var/www/html` at install.
- `deb/`: maintainer scripts for the `.deb` that CPack builds (`cpack -G DEB` in the build directory).
- `rpm/agensio.spec`: for COPR (builds from the tag's tarball); CPack also builds an `.rpm` with the same scripts.
- `arch/`: `PKGBUILD` and install hooks for the AUR.
- `.github/workflows/release.yml` builds the `.deb` and `.rpm` on every `v*` tag, attaches them to the GitHub release, and publishes the APT repository to GitHub Pages when the `APT_GPG_PRIVATE_KEY` secret exists (`docs/install.md`).

Version strings: the tag is `v0.1.0-alpha.1`; Debian gets `0.1.0~alpha.1` (a tilde sorts
before the release), RPM `0.1.0-0.1.alpha.1`, Arch `0.1.0alpha1-1`.
