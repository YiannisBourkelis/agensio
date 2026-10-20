# Checking a site from outside

agensio's own tools see a site from the inside: `agensio -t` and `health_check` judge the
configuration and the files, `path_check` says what the server would do with one request. The
services below see what a visitor's browser sees, from the internet: the certificate it gets,
the headers, the redirects, the protocols. Use both: a setting that `-t` accepts can still look
wrong from outside (a firewall in the way, a CDN in front, DNS pointing elsewhere).

They are run by third parties and free for occasional use. What they read is public anyway
(any visitor sees a site's certificate and headers), but some list the names they tested on a
public page, which draws attention to a site still being set up: each entry says how to keep a
result off those lists. Services change; this list was checked on 2026-10-12.

## Which check for which question

| question | service | the agensio side |
|---|---|---|
| Is HTTPS set up well (certificate chain, protocol versions, HSTS)? | [SSL Labs](#ssl-labs-ssl-server-test) | `tls`, `hsts`, `docs/tls.md` |
| Why will my certificate not issue or renew? | [Let's Debug](#lets-debug) | `tls = "auto"`, health's `acme_renewal_failed` |
| Which certificates were issued for my names? | [crt.sh](#crtsh) | `tls`, `server_name` |
| Which security headers does the site send? | [securityheaders.com](#securityheaderscom), [MDN HTTP Observatory](#mdn-http-observatory) | `[[site.response_headers]]` and `response_headers_baseline`; `hsts` (a lifetime, or `"application"` when the application sends its own, `"none"` for none); `[server] server_header`; health's `response_headers_suggested` |
| Is my Content-Security-Policy any good? | [CSP Evaluator](#csp-evaluator) | the application's own, or the site's `[[site.response_headers]]` |
| Is my domain on the HSTS preload list? | [hstspreload.org](#hstspreloadorg) | `hsts` (agensio sends no `preload`, so a domain does not qualify through it) |
| Where do my redirects go, hop by hop? | [httpstatus.io](#httpstatusio) | `[[site.redirect]]`, `canonical`, `http`, `path_check` |
| Does HTTP/3 work? | [http3check.net](#http3checknet) | `[server] protocols = [..., "h3"]` |
| IPv6, DNSSEC, HTTPS and headers together? | [internet.nl](#internetnl) | `listen`, `tls`, `hsts` |
| Is DNSSEC set up right? | [DNSViz](#dnsviz) | (your DNS provider) |
| How fast is the page, and does it follow browser best practices? | [PageSpeed Insights](#pagespeed-insights) | a managed site's `rules.cache`, `Cache-Control` in `[[site.response_headers]]`, `protocols` |

## TLS and certificates

### SSL Labs SSL Server Test

<https://www.ssllabs.com/ssltest/> grades a site's TLS from A to F: the certificate and its chain,
the protocol versions and ciphers offered, and whether HSTS is sent. Run it after the first
certificate is in place and after any change to `tls`. Tick **"Do not show the results on the
boards"** to keep the name off its list of recent tests; a link to a hidden result needs
`hiddenResults=on` in it.

### Let's Debug

<https://letsdebug.net/> explains why a Let's Encrypt certificate cannot be issued: DNS records
that point elsewhere, port 80 closed, a redirect that breaks the challenge, a CAA record, a rate
limit. For a site with `tls = "auto"` it is the first look when health reports
`acme_renewal_failed`. Choose HTTP-01, and open "Show verbose information": the summary can say
OK while the details show the problem.

### crt.sh

<https://crt.sh/> searches the public Certificate Transparency logs, where every publicly trusted
certificate is recorded. Search a name to see what agensio's ACME manager obtained and when, or
`%.example.com` for every subdomain; a certificate you did not ask for is worth investigating.
The logs are public by design.

On the server itself, `testssl.sh` (<https://github.com/testssl/testssl.sh>) runs the same kind
of TLS checks from the command line and publishes nothing.

## Headers

### securityheaders.com

<https://securityheaders.com/> grades the security headers of an address (HSTS,
Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy) and says which are missing. Tick **"Hide results"** to keep the grade off its
public dashboards; the report you get is unchanged.

### MDN HTTP Observatory

<https://developer.mozilla.org/en-US/observatory> is Mozilla's assessment of a site's headers and
related security settings (the redirect to HTTPS, cookies' flags, and more), with advice per
finding.

### CSP Evaluator

<https://csp-evaluator.withgoogle.com/> takes a Content-Security-Policy and points out ways around
it (an allowed host that serves scripts anyone can upload, `unsafe-inline`). Its project says it
is not an official Google product.

### hstspreload.org

<https://hstspreload.org/> shows whether a domain is on the browsers' HSTS preload list, pending,
or being removed, and whether it would qualify. agensio does not offer preload (it binds every
subdomain and takes months to undo), but the check is worth running for a domain you take over:
if it is preloaded, every subdomain must keep HTTPS.

## Redirects

### httpstatus.io

<https://httpstatus.io/> follows the redirects of one address or of a list, and shows every hop
with its status code and target. Use it after setting up HTTPS (`http://` should take one hop to
`https://`), and after a migration with the list of old addresses: each should end on a `200`
in as few hops as possible, and none should end on a `404`.

From a shell, `curl -sI http://example.com/page` shows one hop; agensio's `path_check` shows what
the server would answer without sending a request.

## Protocols

### http3check.net

<https://http3check.net/> reads the `alt-svc` header a site sends over HTTPS, then tries an
HTTP/3 request over QUIC. It runs LiteSpeed's QUIC library; its version-negotiation probe can
fail against other servers while HTTP/3 itself works, so trust the HTTP/3 request's result. In a
browser, the developer tools' Network tab shows the protocol of each request (`h2`, `h3`).

## Everything at once

### internet.nl

<https://internet.nl/> (the website test) checks a domain against current internet standards in
one report: IPv6 for the web and name servers, DNSSEC, HTTPS against the Dutch NCSC's TLS
guidelines (including that plain HTTP redirects to HTTPS on the same domain first), security
headers and RPKI. The report has a permanent link you can send to whoever runs the DNS or the
server.

### DNSViz

<https://dnsviz.net/> draws a domain's DNSSEC chain of trust and marks where it breaks. DNSSEC is
your DNS provider's, not agensio's, but a broken chain makes the site unreachable for every
visitor whose resolver validates.

## Speed and best practices

### PageSpeed Insights

<https://pagespeed.web.dev/> runs Google's Lighthouse on a page and adds what real Chrome users
measured. Its Best Practices part checks HTTPS and the redirect to it; its Performance part shows
what caching and compression would save.
