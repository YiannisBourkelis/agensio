#include "core/openssl_compat.hpp"

#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

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

std::string asn1_utf8(const ASN1_STRING* s) {
    if (!s) return {};
    unsigned char* utf8 = nullptr;
    const int n = ASN1_STRING_to_UTF8(&utf8, s);
    if (n < 0 || !utf8) return {};
    std::string text(reinterpret_cast<const char*>(utf8), static_cast<std::size_t>(n));
    OPENSSL_free(utf8);
    return text;
}

std::string common_name_text(const X509_NAME* name, std::size_t limit) {
    const int at = name ? X509_NAME_get_index_by_NID(name, NID_commonName, -1) : -1;
    if (at < 0) return {};
    const X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, at);
    std::string text = asn1_utf8(entry ? X509_NAME_ENTRY_get_data(entry) : nullptr);
    if (const std::size_t nul = text.find('\0'); nul != std::string::npos) text.resize(nul);
    if (text.size() > limit) {
        std::size_t cut = limit;
        while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xC0) == 0x80) --cut;  // not inside a character
        text.resize(cut);
    }
    return text;
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

bool free_buffers_fixed(unsigned major, unsigned minor, unsigned patch) noexcept {
    if (major != 3) return major > 3;
    switch (minor) {
        case 0: return patch >= 14;
        case 1: return patch >= 6;
        case 2: return patch >= 2;
        case 3: return patch >= 1;
        default: return true;
    }
}

bool free_buffers_safe() noexcept {
    static const bool safe = free_buffers_fixed(OPENSSL_version_major(), OPENSSL_version_minor(), OPENSSL_version_patch());
    return safe;
}

bool send_server_name(SSL* ssl, const char* host) noexcept {
    // a2i_IPADDRESS is what X509_VERIFY_PARAM_set1_ip_asc reads an address with, so a host the
    // certificate is checked for as an address is exactly a host that is not sent as a name.
    if (ASN1_OCTET_STRING* address = a2i_IPADDRESS(host)) {
        ASN1_OCTET_STRING_free(address);
        return true;
    }
    return SSL_set_tlsext_host_name(ssl, host) == 1;
}

} // namespace agensio::tls
