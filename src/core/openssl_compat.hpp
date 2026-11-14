// The OpenSSL calls whose spelling changed between the versions agensio builds against
// (3.0 to 4.1), each behind one function, so no caller names a function a version deprecates:
// SSL_set1_host() and X509_NAME_get_text_by_NID() since 4.0, ASN1_STRING_length() since 4.1.
// Each does what the call it replaces did, on every version; the unit tests hold them to that.
//
// Nothing here runs per request: names are read when a certificate is loaded, and a peer's
// name is set once per TLS connection agensio opens (to an origin, a CA, a download). They are
// ordinary functions of their own file on purpose: inlined into their callers they made those
// larger and moved the TLS code of the request path (measured 2026-11-13: the same instructions
// per HTTPS request and a fifth more L1 instruction-cache misses).
#pragma once
#ifdef AGENSIO_HAS_TLS

#include <openssl/types.h>

#include <cstddef>
#include <string_view>

namespace agensio::tls {

// The bytes an ASN.1 string holds: their count, and the bytes as a view into the string.
std::size_t asn1_length(const ASN1_STRING* s) noexcept;
std::string_view asn1_text(const ASN1_STRING* s) noexcept;

// The first commonName of `name` as X509_NAME_get_text_by_NID() gave it into a buffer of
// `limit + 1` bytes read as a C string: the entry's bytes as they are, at most `limit` of
// them, ending before a NUL byte. Empty when the name has none. The view points into `name`.
std::string_view first_common_name(const X509_NAME* name, std::size_t limit) noexcept;

// The certificate `ssl`'s peer shows must name `host`, and nothing else is expected of it:
// an IP literal is looked for among the certificate's IP addresses, any other name among
// its DNS names (what SSL_set1_host() did). Call before the handshake.
bool expect_peer_name(SSL* ssl, const char* host) noexcept;

// The name a client handshake asks for (the server_name extension, SNI): `host` when it is a
// host name, and nothing when it is an IP literal, which RFC 6066 3 does not permit there. An
// address is still what the certificate is checked for (expect_peer_name); what tells the two
// apart is that function's own test. False only when a name could not be set. Until
// 0.1.0-alpha.146 every client of agensio's (to an origin, a CA, a download, its own listener)
// sent an address as it was given. Call before the handshake.
bool send_server_name(SSL* ssl, const char* host) noexcept;

// SSL_free_buffers() may be called on this library: it carries the fix of CVE-2024-4741 (the call
// freed a read buffer still in use when a record's header had been processed and its body had not
// arrived, a use after free; OpenSSL's advisory of 2024-05-28), by its release: 3.0.14, 3.1.6, 3.2.2,
// 3.3.1 and everything after. A distribution that patched an older release without renumbering it
// (Ubuntu 22.04's 3.0.2, 24.04's 3.0.13) is read as unfixed: there an idle TLS connection keeps
// OpenSSL's two buffers. `free_buffers_fixed` is the rule, unit tested; `free_buffers_safe` asks the
// library loaded, once.
bool free_buffers_fixed(unsigned major, unsigned minor, unsigned patch) noexcept;
bool free_buffers_safe() noexcept;

} // namespace agensio::tls

#endif // AGENSIO_HAS_TLS
