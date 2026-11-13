#include "core/openssl_compat.hpp"

#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <algorithm>

namespace agensio::tls {

// ASN1_STRING_get_length() came with OpenSSL 4.1, which deprecates ASN1_STRING_length().
std::size_t asn1_length(const ASN1_STRING* s) noexcept {
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    return ASN1_STRING_get_length(s);
#else
    const int n = ASN1_STRING_length(s);
    return n > 0 ? static_cast<std::size_t>(n) : 0;
#endif
}

std::string_view asn1_text(const ASN1_STRING* s) noexcept {
    return {reinterpret_cast<const char*>(ASN1_STRING_get0_data(s)), asn1_length(s)};
}

// The way OpenSSL names in place of X509_NAME_get_text_by_NID(): the entry by its index,
// then its data. The cuts are that call's (its buffer's size) and its callers' (a C string).
std::string_view first_common_name(const X509_NAME* name, std::size_t limit) noexcept {
    const int at = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if (at < 0) return {};
    const X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, at);
    const ASN1_STRING* data = entry ? X509_NAME_ENTRY_get_data(entry) : nullptr;
    if (!data) return {};
    std::string_view text = asn1_text(data);
    text = text.substr(0, std::min(text.size(), limit));
    return text.substr(0, text.find('\0'));
}

// The body of SSL_set1_host() in OpenSSL 3.5 and 4.1, made of the calls it is made of, which
// every version has and none deprecates (4.0's own replacements, SSL_set1_ipaddr() and
// SSL_set1_dnsname(), are one of them each): one code path, no version test.
bool expect_peer_name(SSL* ssl, const char* host) noexcept {
    X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
    (void)X509_VERIFY_PARAM_set1_host(param, nullptr, 0);
    (void)X509_VERIFY_PARAM_set1_ip(param, nullptr, 0);
    return X509_VERIFY_PARAM_set1_ip_asc(param, host) == 1 || X509_VERIFY_PARAM_set1_host(param, host, 0) == 1;
}

} // namespace agensio::tls
