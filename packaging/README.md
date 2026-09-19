# Packaging

- `agensio.service`, `agensio.logrotate`: installed by every package (`/lib/systemd/system`, `/etc/logrotate.d`).
- `etc/`: the packaged `/etc/agensio/agensio.toml` and `sites.d/default.toml` (serves `/var/www/html`).
- `www/index.html`: the placeholder page, copied into an empty `/var/www/html` at install.
- `deb/`: maintainer scripts for the `.deb` that CPack builds (`cpack -G DEB` in the build directory).
- `rpm/agensio.spec`: for COPR (builds from the tag's tarball); CPack also builds an `.rpm` with the same scripts.
- `arch/`: `PKGBUILD` and install hooks; the release workflow's `arch` job builds the binary
  `.pkg.tar.zst` from it in an Arch container and attaches it to the release
  (`sudo pacman -U ./agensio-*.pkg.tar.zst`); the same file is what the AUR will publish.
- `.github/workflows/release.yml` builds the `.deb` and `.rpm` on every `v*` tag, attaches them to the GitHub release, and publishes the APT repository to GitHub Pages when the `APT_GPG_PRIVATE_KEY` secret exists (`docs/install.md`).

Version strings: the tag is `v0.1.0-alpha.1`; Debian gets `0.1.0~alpha.1` (a tilde sorts
before the release), RPM `0.1.0-0.1.alpha.1`, Arch `0.1.0alpha1-1`.

## Publishing the APT repository (one-time setup)

The release workflow signs and publishes `dists/stable` to GitHub Pages only when the
repository secret `APT_GPG_PRIVATE_KEY` exists.

1. A signing key without a passphrase (the workflow cannot type one), kept only in the
   GitHub secret and in a backup you control:

   ```sh
   gpg --batch --quick-gen-key --passphrase '' "agensio packages <yiannis@grbytes.com>" ed25519 sign never
   gpg --armor --export-secret-keys "agensio packages" > agensio-apt-signing.key   # the secret; keep it safe
   ```

2. GitHub, repository *Settings*: *Secrets and variables* / *Actions* / *New repository
   secret*: name `APT_GPG_PRIVATE_KEY`, value: the whole content of the file above.
3. *Settings* / *Pages*: *Build and deployment*: source *Deploy from a branch*, branch
   `gh-pages`, folder `/ (root)`. The branch appears after the first publishing run.
4. Run a release (or delete and re-push the current tag). The workflow writes
   `https://yiannisbourkelis.github.io/agensio/agensio.gpg` and `.../apt/`.

Every later release replaces the index with its own packages (older files stay on the
branch, unindexed). Debian sorts `0.1.0~alpha.2` before `0.1.0~alpha.3` and before
`0.1.0`, so `apt upgrade` follows the tags in order.
