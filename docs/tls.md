# TLS certificates in agensio

How a site gets its certificate, how a renewed one reaches the clients, what health tells you
about it and what to do when something goes wrong. Written for the administrator of a host:
what to configure, what the server does on its own, and what it needs from you.

The reference for each key is `docs/configuration.md` section 14 (TLS) and `docs/keys.md`; the
recipes are in the cookbook, [HTTPS with a certificate agensio obtains
itself](examples/basics.md#https-with-a-certificate-agensio-obtains-itself), [HTTPS with
certificate files you manage](examples/basics.md#https-with-certificate-files-you-manage) and
[Certificates from certbot](examples/basics.md#certificates-from-certbot). The decisions behind
section 4 are in `docs/design-site-operations.md` section 26. This document describes what the
code does as of 0.1.0-alpha.64.

## 1. Two ways to get a certificate

| | Automatic: `tls = "auto"` | Your own files: `tls = { cert, key }` |
|---|---|---|
| Who obtains it | agensio, from Let's Encrypt or any ACME CA | you: certbot, another ACME client, a company or commercial CA |
| What you install | nothing | the client that obtains them |
| Validation | HTTP-01 over port 80, answered by agensio | whatever your client uses (DNS-01 for a wildcard) |
| Renewal | by agensio, at a third of the lifetime left | by your client; agensio picks the new files up (section 3.3) |
| Wildcards (`*.example.com`) | no (they need DNS-01) | yes |
| Fits | a site whose names resolve here, port 80 open | wildcards, no port 80, a CA without ACME, an existing certbot |

Both kinds can share one listener: each site's certificate is chosen by the name the client asks
for (SNI). A listen address is either plain or TLS for every site on it.

## 2. Automatic certificates

### 2.1 What you need

```toml
# /etc/agensio/agensio.toml: once per host
[server]
acme = { email = "admin@example.com" }
```

```toml
# /etc/agensio/sites.d/example.com.toml
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https"

[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = "auto"
```

- Every name in `server_name` resolves to this host, and port 80 reaches it from the internet:
  the CA fetches `http://<name>/.well-known/acme-challenge/<token>`. A plain site on port 80
  for the same names must exist (here the redirect); agensio answers the challenge itself,
  before any site, location, redirect or access rule, so nothing in your configuration can get
  in its way. Health warns (`acme_needs_port_80`) when no plain site covers the names.
- Real host names: no `*` and no wildcard (they need DNS-01, which agensio does not do yet).
- An email for the account: the CA sends expiry warnings there; it never appears in a
  certificate.

### 2.2 What happens

1. **Start.** A site without a certificate yet gets a self-signed placeholder (issuer `agensio
   placeholder`, valid seven days), so its listener comes up at once, and an order is placed.
   Browsers warn about the placeholder; health says `certificate_not_issued` until the order
   succeeds.
2. **Validation.** The CA fetches the token over port 80 for every name; agensio answers it.
3. **Issue.** A new P-256 key is made for each certificate, the CA signs it for all the site's
   names, and the key and the chain are written to the storage (2.3).
4. **Switch.** The server loads the new certificate through the certificate refresh (section 4):
   `certificates refreshed: site example.com: loaded the certificate valid until ...` in the
   error log. New connections get it; connections in flight finish on the old one.
5. **Renewal.** Once an hour the manager looks at every automatic certificate and orders again
   when a third of its lifetime is left: day 60 of a 90-day certificate, day 4 of a 6-day one,
   so shorter certificates need nothing changed. A name added to `server_name` orders a new
   certificate at once.
6. **Failure.** A failed order is logged with the CA's reason (`acme: example.com: ... (retry in
   an hour)`) and retried an hour later; the current certificate keeps serving. Health shows the
   last failure (`acme_renewal_failed`) and, a day past the renewal point, raises it to an error
   (`acme_renewal_overdue`) with the CA's message, weeks before the certificate expires.

`agensio ctl cert-renew example.com` (MCP `cert_renew`) orders again at once, for example after
fixing DNS.

### 2.3 Where the files are, and backups

Everything lives under `[server] acme.storage`, `<state_dir>/acme` by default
(`/var/lib/agensio/acme`): `account.key`, then per certificate a directory named after the
site's first name with `key.pem` (0600) and `fullchain.pem`. Started as root with
`server.user`, the tree is given to that account, so renewals work after the privilege drop.
The storage is all there is to back up: restored on another host, renewals continue without a
new account or order. Deleting a site's directory orders a new certificate at the next start.

### 2.4 Other authorities, and testing

`acme = { email, directory }` names any RFC 8555 CA: ZeroSSL, Buypass, Google, a private
step-ca. While testing a new host, Let's Encrypt's staging directory
(`https://acme-staging-v02.api.letsencrypt.org/directory`) avoids its production rate limits;
its certificates are not trusted by browsers. `ca = "..."` trusts a private CA's own TLS for the
directory; only for private CAs and tests.

### 2.5 Not in this release

DNS-01 (and so wildcards), TLS-ALPN-01 (a host without port 80), external account binding,
OCSP stapling. For a wildcard today, use certbot with a DNS plugin (section 3.4).

### 2.6 On a managed site

`agensio ctl site-create --domain example.com --alias www.example.com --https auto ...` (MCP
`site_create` with `https: "auto"`) writes both sites; the server's main file needs `[server]
acme` once, which only root edits.

## 3. Your own certificate files

### 3.1 The files

`cert` is the certificate followed by the intermediates (`fullchain.pem`), `key` its private
key, both PEM. The certificate must cover every name in `server_name`: a request for a name it
does not cover is answered `421`, and a TLS client asking for a name no site lists is refused
during the handshake (`unrecognized_name`), so another site's certificate is never shown.

A site whose files are missing, or exist but do not load (not PEM, a key that is not the
certificate's, unreadable), is set aside with its file and the other sites load (section 4); in
the main file it stops the start. `agensio -t` loads each pair as the start does, so it says the
same ahead of time: a warning per file set aside, and `-t --strict` fails. Run it as the account
that starts the server (root, with `server.user`): run as another account, it cannot read a key
only root reads and says it did not check it (`note: ... not checked`).

### 3.2 Who must be able to read them

With `server.user` (the normal setup: started as root, then running as `agensio`), the start
reads the certificates as root, and **every later load reads them as `agensio`**, its group and
its supplementary groups included. A key only root can read works at boot and is never read
again: every renewal waits for a restart, and the certificate served runs out. agensio checks
this ahead of time: `agensio -t`, the start and health (`tls_key_unreadable`) name the file and
every directory on the way that the account cannot read, with root's lines, for example:

```sh
chgrp agensio /etc/ssl/example.com && chmod g+x /etc/ssl/example.com
chgrp agensio /etc/ssl/example.com/privkey.pem && chmod 640 /etc/ssl/example.com/privkey.pem
```

Layouts that work:

- a directory of its own, `root:agensio 0750`, the key `root:agensio 0640`, the chain `0644`;
- Debian's `/etc/ssl/private` (`root:ssl-cert 0710`, keys `root:ssl-cert 0640`) with the server's
  account in `ssl-cert` (`usermod -aG ssl-cert agensio`, then a restart);
- certbot's tree with its directories opened and the key given the group (the cookbook's certbot
  recipe); certbot keeps the key's group and group read bit on every renewal.

### 3.3 Renewal: picked up by itself

The server stats every certificate and key file once an hour and loads the pairs whose files
changed: a `cp` over the file, a new file moved into place, certbot pointing its `live/` link at
a new version. Nothing else is needed: no reload, no restart, no hook. For a renewal to be served
at once, the client's hook runs

```sh
agensio ctl cert-renew example.com --yes --reason renewal
```

which loads that site's files now and answers what happened: `loaded the certificate valid until
...`, `unchanged` (the files are the certificate served), or why they could not be loaded, the
certificate served staying (exit status 1). Run as root (certbot's hooks are) it needs no other
permission. `agensio reload` loads them too, but reads every configuration file as well; the
refresh reads none (section 4).

### 3.4 certbot

The cookbook's [Certificates from certbot](examples/basics.md#certificates-from-certbot) recipe
covers the two common cases: a wildcard over DNS-01 with a certbot DNS plugin (nothing of
agensio's is involved in the validation), and an existing certbot that renews with
`--webroot` through agensio. Use `tls = "auto"` instead when agensio can validate over port 80
itself: one program less.

### 3.5 On a managed site

The files must exist first; `agensio ctl site-create --domain example.com --cert
/etc/ssl/example.com/fullchain.pem --key /etc/ssl/example.com/privkey.pem ...` (MCP
`site_create` or `site_update` with `https: {"cert": "...", "key": "..."}`).

## 4. How a new certificate reaches the clients

A new certificate is loaded through the **certificate refresh**: the running configuration's
certificates are read again from their files, and no configuration file is read. So a mistake
in the main file or in any site's file, which refuses a reload, never keeps a renewal waiting.
The ACME manager uses it after every order, the hourly check for the files that changed, and
`cert-renew` for one site. New connections get the new certificate; connections already open
finish on the old one; nothing is dropped.

When a certificate's files cannot be loaded, the server keeps serving the certificate it loaded
before, with the reason in the error log (`the certificate loaded before keeps serving`) and in
health (`certificate_not_loaded`), until the files load. The cases:

- **on reload or refresh, a site that was serving**: it keeps its certificate; nothing else
  changes for it, and every other site's change applies;
- **at start, or a site that is new**: there is no certificate to keep, so that site's file is
  set aside and not served, and every other site starts (health `site_file_held_back`); a site
  in the main file stops the start instead;
- **a key only root can read** (3.2): read at start, then kept, with the lines to fix it.

Before 0.1.0-alpha.64 a certificate that did not load refused the whole reload (every other
site's change and every renewal with it), at start kept the server from starting, and nothing
watched the files.

## 5. What health tells you

Health (`agensio ctl health`, MCP `health_check`) judges the certificate each site **serves**,
read from the server's memory, not the file on disk: a renewal written but not loaded is not
mistaken for one in service.

| Finding | Severity | Means | Do |
|---|---|---|---|
| `certificate_expired` | error | the certificate served has expired | automatic: see `acme_renewal_*`; your own: install a renewed one, `cert-renew` |
| `certificate_expiring` | warn | your own certificate served expires within 14 days | renew it; the hourly check or `cert-renew` loads it |
| `certificate_not_issued` | error | an automatic site still serves its placeholder | names resolving here, port 80 reachable; the acme lines of the error log |
| `certificate_not_loaded` | warn, error under 7 days left | the file on disk is newer than the certificate served; the message says why: loaded at the next hourly check (or now with `cert-renew`), or the server could not load it, with the error | `cert-renew NAME`; if it could not be loaded, the fix of `tls_key_unreadable` or the file corrected |
| `acme_renewal_failed` | warn | the last automatic order failed, with the CA's message; retried every hour | correct what the CA says (DNS, port 80, a firewall, a CDN in front), then `cert-renew NAME` |
| `acme_renewal_overdue` | error | a day past the renewal point (a third of the lifetime left), with the last failure | the same, now |
| `acme_needs_port_80` | warn | `tls = "auto"` but no plain site on port 80 covers the names | add the port-80 site (2.1) |
| `tls_key_unreadable` | warn | the server's account cannot read a certificate or key after the start | root runs the lines given (3.2) |
| `site_file_held_back` | error | a site's file is set aside; a certificate that did not load is one reason, named in the message | the message's error |
| `no_http_redirect` | info | no plain site redirects these names to https | add `redirect = "https"` on port 80 |

`agensio ctl site NAME` (MCP `site_show`) shows both: `tls` describes the file on disk and
`tls.served` the certificate in memory, `same_as_disk` false while a newer file waits.

## 6. Troubleshooting

**Browsers say the certificate has expired.** `agensio ctl health`. On an automatic site,
`acme_renewal_overdue` carries the CA's last error; the usual causes are a name that no longer
resolves here, port 80 closed by a firewall or a cloud security group, a CDN or proxy in front
answering `/.well-known/acme-challenge/` itself, or the CA's rate limits (its message says
which). On your own certificate, `certificate_not_loaded` says whether a renewed file is waiting
and why.

**certbot renewed, but the old certificate is still served.** The server loads it within the
hour; `agensio ctl cert-renew NAME` loads it now and says what happened. If it answers that the
key could not be loaded, run the lines `tls_key_unreadable` gives (3.2).

**An automatic site stays on the placeholder.** As above: `certificate_not_issued`, the acme
lines of the error log (`agensio ctl logs --level info`), DNS and port 80. While trying things,
use the staging directory (2.4) so as not to reach the CA's limits.

**A name answers 421.** It is not in the site's `server_name`, or the certificate does not cover
it. `openssl s_client -connect HOST:443 -servername NAME </dev/null | openssl x509 -noout
-subject -ext subjectAltName` shows the names of the certificate served.

**After changing a site's certificate paths, the site is not served (or serves the old one).**
Its file was set aside because the new files did not load: on a reload it keeps serving its
previous version, at start it is not served. Health's `site_file_held_back` gives the error.

**What exactly is served?** `agensio ctl site NAME` (`tls.served`: issuer, expiry, whether it is
the file on disk), or `openssl s_client -connect HOST:443 -servername NAME </dev/null | openssl
x509 -noout -issuer -enddate -fingerprint -sha256`.

## 7. Commands at a glance

```sh
agensio -t -c /etc/agensio/agensio.toml         # loads every pair as the start does; names files the server's account cannot read
agensio ctl health                              # every finding of section 5
agensio ctl site example.com                    # tls (the file) and tls.served (the certificate in memory)
agensio ctl cert-renew example.com --yes        # automatic: order now; your own files: load them now
agensio ctl logs --level info --since 1d        # the acme lines and the refreshes
```

MCP: `health_check`, `site_show`, `sites_list`, `cert_renew`, `logs_query`.
