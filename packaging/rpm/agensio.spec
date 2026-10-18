# Fedora / EPEL spec for COPR (builds from the release tarball of the tag).
%global upstream_version 0.1.0-alpha.102

Name:           agensio
Version:        0.1.0
Release:        0.1.alpha.102%{?dist}
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
# The directories %files owns with their modes; the .deb makes them in postinst.
install -d %{buildroot}/var/log/agensio %{buildroot}/var/lib/agensio %{buildroot}/var/www/html
# The account and groups for rpm (user(agensio), group(agensio) from the owners in %files);
# %pre still makes them where rpm does not read sysusers.d (EPEL 9).
install -Dm0644 packaging/agensio.sysusers %{buildroot}%{_sysusersdir}/agensio.conf

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
%{_docdir}/%{name}/
%{_sbindir}/agensio
%config(noreplace) %attr(0640,root,agensio) %{_sysconfdir}/agensio/agensio.toml
%config(noreplace) %{_sysconfdir}/agensio/sites.d/default.toml
%config(noreplace) %{_sysconfdir}/logrotate.d/agensio
%{_unitdir}/agensio.service
%{_sysusersdir}/agensio.conf
%{_unitdir}/agensio-firewall.service
%{_datadir}/agensio/www/index.html
%{_datadir}/agensio/firewall/agensio.nft
%{_datadir}/agensio/fail2ban/jail.d/agensio.conf
%{_datadir}/agensio/fail2ban/filter.d/agensio-login.conf
%{_datadir}/agensio/fail2ban/filter.d/agensio-auth.conf
%{_datadir}/agensio/fail2ban/filter.d/agensio-scan.conf
%{_datadir}/agensio/fail2ban/filter.d/agensio-post.conf
%{_datadir}/agensio/fail2ban/filter.d/agensio-denied.conf
%dir %attr(0750,root,agensio) %{_sysconfdir}/agensio
%dir %attr(0750,agensio,agensio) %{_sysconfdir}/agensio/sites.d
%dir %attr(0750,agensio,agensio) /var/log/agensio
%dir %attr(0751,agensio,agensio) /var/lib/agensio
%dir /var/www/html

%changelog
* Mon Oct 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.102
- Release 0.1.0-alpha.102, see CHANGELOG.md.

* Mon Oct 19 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.101
- Release 0.1.0-alpha.101, see CHANGELOG.md.

* Sun Oct 18 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.100
- Release 0.1.0-alpha.100, see CHANGELOG.md.

* Sun Oct 18 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.99
- Release 0.1.0-alpha.99, see CHANGELOG.md.

* Sat Oct 17 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.98
- Release 0.1.0-alpha.98, see CHANGELOG.md.

* Sat Oct 17 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.97
- Release 0.1.0-alpha.97, see CHANGELOG.md.

* Fri Oct 16 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.96
- Release 0.1.0-alpha.96, see CHANGELOG.md.

* Fri Oct 16 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.95
- Release 0.1.0-alpha.95, see CHANGELOG.md.

* Wed Oct 14 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.94
- Release 0.1.0-alpha.94, see CHANGELOG.md.

* Wed Oct 14 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.93
- Release 0.1.0-alpha.93, see CHANGELOG.md.

* Wed Oct 14 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.92
- Release 0.1.0-alpha.92, see CHANGELOG.md.

* Wed Oct 14 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.91
- Release 0.1.0-alpha.91, see CHANGELOG.md.

* Wed Oct 14 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.90
- Release 0.1.0-alpha.90, see CHANGELOG.md.

* Wed Oct 14 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.89
- Release 0.1.0-alpha.89, see CHANGELOG.md.

* Wed Oct 14 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.88
- Release 0.1.0-alpha.88, see CHANGELOG.md.

* Wed Oct 14 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.87
- Release 0.1.0-alpha.87, see CHANGELOG.md.

* Wed Oct 14 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.86
- Release 0.1.0-alpha.86, see CHANGELOG.md.

* Tue Oct 13 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.85
- Release 0.1.0-alpha.85, see CHANGELOG.md.

* Tue Oct 13 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.84
- Release 0.1.0-alpha.84, see CHANGELOG.md.

* Tue Oct 13 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.83
- Release 0.1.0-alpha.83, see CHANGELOG.md.

* Tue Oct 13 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.82
- Release 0.1.0-alpha.82, see CHANGELOG.md.

* Tue Oct 13 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.81
- Release 0.1.0-alpha.81, see CHANGELOG.md.

* Tue Oct 13 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.80
- Release 0.1.0-alpha.80, see CHANGELOG.md.

* Tue Oct 13 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.79
- Release 0.1.0-alpha.79, see CHANGELOG.md.

* Tue Oct 13 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.78
- Release 0.1.0-alpha.78, see CHANGELOG.md.

* Tue Oct 13 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.77
- Release 0.1.0-alpha.77, see CHANGELOG.md.

* Tue Oct 13 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.76
- Release 0.1.0-alpha.76, see CHANGELOG.md.

* Tue Oct 13 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.75
- Release 0.1.0-alpha.75, see CHANGELOG.md.

* Tue Oct 13 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.74
- Release 0.1.0-alpha.74, see CHANGELOG.md.

* Tue Oct 13 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.73
- Release 0.1.0-alpha.73, see CHANGELOG.md.

* Mon Oct 12 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.72
- Release 0.1.0-alpha.72, see CHANGELOG.md.

* Sun Oct 11 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.71
- Release 0.1.0-alpha.71, see CHANGELOG.md.

* Sun Oct 11 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.70
- Release 0.1.0-alpha.70, see CHANGELOG.md.

* Sun Oct 11 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.69
- Release 0.1.0-alpha.69, see CHANGELOG.md.

* Sun Oct 11 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.68
- Release 0.1.0-alpha.68, see CHANGELOG.md.

* Sun Oct 11 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.66
- Release 0.1.0-alpha.66, see CHANGELOG.md.

* Sun Oct 11 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.65
- Release 0.1.0-alpha.65, see CHANGELOG.md.

* Sun Oct 11 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.64
- Release 0.1.0-alpha.64, see CHANGELOG.md.

* Sun Oct 11 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.63
- Release 0.1.0-alpha.63, see CHANGELOG.md.

* Sat Oct 10 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.62
- Release 0.1.0-alpha.62, see CHANGELOG.md.

* Sat Oct 10 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.61
- Release 0.1.0-alpha.61, see CHANGELOG.md.

* Fri Oct 09 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.60
- Release 0.1.0-alpha.60, see CHANGELOG.md.

* Fri Oct 09 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.59
- Release 0.1.0-alpha.59, see CHANGELOG.md.

* Fri Oct 09 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.58
- Release 0.1.0-alpha.58, see CHANGELOG.md.

* Thu Oct 08 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.57
- Release 0.1.0-alpha.57, see CHANGELOG.md.

* Thu Oct 08 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.56
- Release 0.1.0-alpha.56, see CHANGELOG.md.

* Thu Oct 08 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.55
- Release 0.1.0-alpha.55, see CHANGELOG.md.

* Thu Oct 08 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.54
- Release 0.1.0-alpha.54, see CHANGELOG.md.

* Wed Oct 07 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.53
- Release 0.1.0-alpha.53, see CHANGELOG.md.

* Wed Oct 07 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.52
- Release 0.1.0-alpha.52, see CHANGELOG.md.

* Wed Oct 07 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.51
- Release 0.1.0-alpha.51, see CHANGELOG.md.

* Mon Oct 05 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.50
- Release 0.1.0-alpha.50, see CHANGELOG.md.

* Sun Oct 04 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.49
- Release 0.1.0-alpha.49, see CHANGELOG.md.

* Sun Oct 04 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.48
- Release 0.1.0-alpha.48, see CHANGELOG.md.

* Sat Oct 03 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.47
- Release 0.1.0-alpha.47, see CHANGELOG.md.

* Fri Oct 02 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.46
- Release 0.1.0-alpha.46, see CHANGELOG.md.

* Fri Oct 02 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.45
- Release 0.1.0-alpha.45, see CHANGELOG.md.

* Fri Oct 02 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.44
- Release 0.1.0-alpha.44, see CHANGELOG.md.

* Fri Oct 02 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.43
- Release 0.1.0-alpha.43, see CHANGELOG.md.

* Fri Oct 02 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.42
- Release 0.1.0-alpha.42, see CHANGELOG.md.

* Fri Oct 02 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.41
- Release 0.1.0-alpha.41, see CHANGELOG.md.

* Fri Oct 02 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.40
- Release 0.1.0-alpha.40, see CHANGELOG.md.

* Thu Oct 01 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.39
- Release 0.1.0-alpha.39, see CHANGELOG.md.

* Mon Sep 28 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.38
- Release 0.1.0-alpha.38, see CHANGELOG.md.

* Mon Sep 28 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.37
- Release 0.1.0-alpha.37, see CHANGELOG.md.

* Mon Sep 28 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.36
- Release 0.1.0-alpha.36, see CHANGELOG.md.

* Mon Sep 28 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.35
- Release 0.1.0-alpha.35, see CHANGELOG.md.

* Sun Sep 27 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.34
- Release 0.1.0-alpha.34, see CHANGELOG.md.

* Sun Sep 27 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.33
- Release 0.1.0-alpha.33, see CHANGELOG.md.

* Sun Sep 27 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.32
- Release 0.1.0-alpha.32, see CHANGELOG.md.

* Sun Sep 27 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.31
- Release 0.1.0-alpha.31, see CHANGELOG.md.

* Sun Sep 27 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.30
- Release 0.1.0-alpha.30, see CHANGELOG.md.

* Sun Sep 27 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.29
- Release 0.1.0-alpha.29, see CHANGELOG.md.

* Sun Sep 27 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.28
- Release 0.1.0-alpha.28, see CHANGELOG.md.

* Sun Sep 27 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.27
- Release 0.1.0-alpha.27, see CHANGELOG.md.

* Sun Sep 27 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.26
- Release 0.1.0-alpha.26, see CHANGELOG.md.

* Sun Sep 27 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.25
- Release 0.1.0-alpha.25, see CHANGELOG.md.

* Sun Sep 27 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.24
- Release 0.1.0-alpha.24, see CHANGELOG.md.

* Fri Sep 25 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.23
- Release 0.1.0-alpha.23, see CHANGELOG.md.

* Fri Sep 25 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.22
- Release 0.1.0-alpha.22, see CHANGELOG.md.

* Thu Sep 24 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.21
- Release 0.1.0-alpha.21, see CHANGELOG.md.

* Thu Sep 24 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.20
- Release 0.1.0-alpha.20, see CHANGELOG.md.

* Wed Sep 23 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.19
- Release 0.1.0-alpha.19, see CHANGELOG.md.

* Sun Sep 20 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.18
- Release 0.1.0-alpha.18, see CHANGELOG.md.

* Sun Sep 20 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.17
- Release 0.1.0-alpha.17, see CHANGELOG.md.

* Sun Sep 20 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.16
- Release 0.1.0-alpha.16, see CHANGELOG.md.

* Sun Sep 20 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.15
- Release 0.1.0-alpha.15, see CHANGELOG.md.

* Sun Sep 20 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.14
- Release 0.1.0-alpha.14, see CHANGELOG.md.

* Sun Sep 20 2026 Yiannis Bourkelis - 0.1.0-0.1.alpha.13
- Release 0.1.0-alpha.13, see CHANGELOG.md.

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
