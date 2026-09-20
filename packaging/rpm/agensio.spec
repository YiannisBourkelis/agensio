# Fedora / EPEL spec for COPR (builds from the release tarball of the tag).
%global upstream_version 0.1.0-alpha.12

Name:           agensio
Version:        0.1.0
Release:        0.1.alpha.12%{?dist}
Summary:        Fast web server with PHP, reverse proxy, automatic TLS and an MCP control plane
License:        MIT
URL:            https://github.com/YiannisBourkelis/agensio
Source0:        %{url}/archive/refs/tags/v%{upstream_version}.tar.gz
BuildRequires:  cmake >= 3.24, ninja-build, gcc-c++ >= 12, asio-devel, openssl-devel, zlib-devel, systemd-rpm-macros
Requires:       openssl-libs, zlib
Requires(pre):  shadow-utils
%{?systemd_requires}

%description
agensio serves static sites, PHP applications through FastCGI (Laravel, WordPress
presets), and anything else through its reverse proxy, obtains its own TLS
certificates, reloads without dropping a connection, and can be managed by an AI agent
through its Model Context Protocol server over SSH.

%prep
%autosetup -n agensio-%{upstream_version}

%build
%cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DAGENSIO_TESTS=OFF
%cmake_build

%install
%cmake_install

%pre
getent group agensio >/dev/null || groupadd -r agensio
getent group agensio-admin >/dev/null || groupadd -r agensio-admin
getent passwd agensio >/dev/null || useradd -r -g agensio -d /var/lib/agensio -s /sbin/nologin agensio
exit 0

%post
%systemd_post agensio.service
[ -e /var/www/html/index.html ] || [ -n "$(ls -A /var/www/html 2>/dev/null)" ] || install -m 0644 /usr/share/agensio/www/index.html /var/www/html/index.html

%preun
%systemd_preun agensio.service

%postun
%systemd_postun_with_restart agensio.service

%files
%license LICENSE
%doc README.md CHANGELOG.md docs/configuration.md docs/install.md docs/mcp.md
%{_sbindir}/agensio
%config(noreplace) %attr(0640,root,agensio) %{_sysconfdir}/agensio/agensio.toml
%config(noreplace) %{_sysconfdir}/agensio/sites.d/default.toml
%config(noreplace) %{_sysconfdir}/logrotate.d/agensio
%{_unitdir}/agensio.service
%{_datadir}/agensio/www/index.html
%dir %attr(0750,root,agensio) %{_sysconfdir}/agensio
%dir %attr(0750,agensio,agensio) %{_sysconfdir}/agensio/sites.d
%dir %attr(0750,agensio,agensio) /var/log/agensio
%dir %attr(0751,agensio,agensio) /var/lib/agensio
%dir /var/www/html

%changelog
* Sun Sep 20 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.12
- Release 0.1.0-alpha.12, see CHANGELOG.md.

* Sun Sep 20 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.11
- Release 0.1.0-alpha.11, see CHANGELOG.md.

* Sun Sep 20 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.10
- Release 0.1.0-alpha.10, see CHANGELOG.md.

* Sun Sep 20 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.9
- Release 0.1.0-alpha.9, see CHANGELOG.md.

* Sun Sep 20 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.8
- Release 0.1.0-alpha.8, see CHANGELOG.md.

* Sat Sep 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.7
- Release 0.1.0-alpha.7, see CHANGELOG.md.

* Sat Sep 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.6
- Release 0.1.0-alpha.6, see CHANGELOG.md.

* Sat Sep 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.5
- Release 0.1.0-alpha.5, see CHANGELOG.md.

* Sat Sep 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.4
- Release 0.1.0-alpha.4, see CHANGELOG.md.

* Sat Sep 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.3
- Release 0.1.0-alpha.3, see CHANGELOG.md.

* Sat Sep 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.3
- Release 0.1.0-alpha.3, see CHANGELOG.md.

* Sat Sep 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.2
- Release 0.1.0-alpha.2, see CHANGELOG.md.

* Sat Sep 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.2
- Release 0.1.0-alpha.2, see CHANGELOG.md.

* Sat Sep 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.3
- Release 0.1.0-alpha.3, see CHANGELOG.md.

* Sat Sep 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.2
- Release 0.1.0-alpha.2, see CHANGELOG.md.

* Sat Sep 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.3
- Release 0.1.0-alpha.3, see CHANGELOG.md.

* Sat Sep 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.2
- Release 0.1.0-alpha.2, see CHANGELOG.md.

* Sat Sep 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.1
- First pre-alpha.
