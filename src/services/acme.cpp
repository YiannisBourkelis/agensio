// ACME v2 client (RFC 8555), HTTP-01. See acme.hpp.
#include "services/acme.hpp"

#ifdef AGENSIO_HAS_TLS

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>

#include <asio/ssl.hpp>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "services/json.hpp"

namespace agensio {

namespace fs = std::filesystem;
using Clock = std::chrono::system_clock;

namespace acme {

namespace {

constexpr const char* kPlaceholderName = "agensio placeholder";

std::string ssl_error() {
    char buf[256];
    const unsigned long e = ERR_get_error();
    if (!e) return "unknown OpenSSL error";
    ERR_error_string_n(e, buf, sizeof buf);
    ERR_clear_error();
    return buf;
}

struct PkeyDeleter { void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); } };
struct BioDeleter { void operator()(BIO* b) const noexcept { BIO_free(b); } };
struct X509Deleter { void operator()(X509* x) const noexcept { X509_free(x); } };
struct ReqDeleter { void operator()(X509_REQ* r) const noexcept { X509_REQ_free(r); } };
struct MdCtxDeleter { void operator()(EVP_MD_CTX* c) const noexcept { EVP_MD_CTX_free(c); } };
struct BnDeleter { void operator()(BIGNUM* b) const noexcept { BN_free(b); } };
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using Bio = std::unique_ptr<BIO, BioDeleter>;
using Cert = std::unique_ptr<X509, X509Deleter>;

Pkey generate_key() { return Pkey(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256")); }

std::string key_to_pem(EVP_PKEY* key) {
    Bio bio(BIO_new(BIO_s_mem()));
    if (!bio || !PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr)) return {};
    char* data = nullptr;
    const long n = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, static_cast<std::size_t>(n));
}

Pkey key_from_pem(const std::string& pem) {
    Bio bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) return nullptr;
    return Pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
}

bool read_file(const fs::path& p, std::string& out) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return false;
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

// Writes `data` to a sibling temp file with `mode` and renames it over `p`.
bool write_file(const fs::path& p, const std::string& data, mode_t mode, std::string& error) {
    const fs::path tmp = p.string() + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) {
        error = "cannot write " + tmp.string() + ": " + std::strerror(errno);
        return false;
    }
    std::size_t done = 0;
    while (done < data.size()) {
        const ssize_t n = ::write(fd, data.data() + done, data.size() - done);
        if (n < 0) {
            error = "cannot write " + tmp.string() + ": " + std::strerror(errno);
            ::close(fd);
            return false;
        }
        done += static_cast<std::size_t>(n);
    }
    ::fchmod(fd, mode);
    ::close(fd);
    std::error_code ec;
    fs::rename(tmp, p, ec);
    if (ec) {
        error = "cannot rename " + tmp.string() + ": " + ec.message();
        return false;
    }
    return true;
}

std::string sha256(std::string_view data) {
    unsigned char out[32];
    unsigned n = 0;
    EVP_Digest(data.data(), data.size(), out, &n, EVP_sha256(), nullptr);
    return std::string(reinterpret_cast<const char*>(out), n);
}

// EC public coordinates as 32-byte big-endian strings.
bool ec_point(EVP_PKEY* key, std::string& x, std::string& y) {
    BIGNUM* bx = nullptr;
    BIGNUM* by = nullptr;
    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &bx) ||
        !EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &by)) {
        BN_free(bx);
        BN_free(by);
        return false;
    }
    unsigned char buf[32];
    BN_bn2binpad(bx, buf, 32);
    x.assign(reinterpret_cast<const char*>(buf), 32);
    BN_bn2binpad(by, buf, 32);
    y.assign(reinterpret_cast<const char*>(buf), 32);
    BN_free(bx);
    BN_free(by);
    return true;
}

std::string jwk_json(EVP_PKEY* key) {
    std::string x, y;
    if (!ec_point(key, x, y)) return {};
    // Lexicographic member order: what the RFC 7638 thumbprint hashes.
    return "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + base64url(x) + "\",\"y\":\"" + base64url(y) + "\"}";
}

// ES256: raw r||s (64 bytes) of the ECDSA signature over SHA-256.
bool es256_sign(EVP_PKEY* key, std::string_view data, std::string& out) {
    std::unique_ptr<EVP_MD_CTX, MdCtxDeleter> ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key) != 1) return false;
    std::size_t len = 0;
    if (EVP_DigestSign(ctx.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(data.data()), data.size()) != 1)
        return false;
    std::string der(len, '\0');
    if (EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(der.data()), &len,
                       reinterpret_cast<const unsigned char*>(data.data()), data.size()) != 1)
        return false;
    const unsigned char* p = reinterpret_cast<const unsigned char*>(der.data());
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(len));
    if (!sig) return false;
    unsigned char raw[64];
    BN_bn2binpad(ECDSA_SIG_get0_r(sig), raw, 32);
    BN_bn2binpad(ECDSA_SIG_get0_s(sig), raw + 32, 32);
    ECDSA_SIG_free(sig);
    out.assign(reinterpret_cast<const char*>(raw), 64);
    return true;
}

bool es256_verify(EVP_PKEY* key, std::string_view data, std::string_view raw) {
    if (raw.size() != 64) return false;
    ECDSA_SIG* sig = ECDSA_SIG_new();
    BIGNUM* r = BN_bin2bn(reinterpret_cast<const unsigned char*>(raw.data()), 32, nullptr);
    BIGNUM* s = BN_bin2bn(reinterpret_cast<const unsigned char*>(raw.data()) + 32, 32, nullptr);
    ECDSA_SIG_set0(sig, r, s);
    unsigned char* der = nullptr;
    const int len = i2d_ECDSA_SIG(sig, &der);
    ECDSA_SIG_free(sig);
    if (len <= 0) return false;
    std::unique_ptr<EVP_MD_CTX, MdCtxDeleter> ctx(EVP_MD_CTX_new());
    bool ok = ctx && EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key) == 1 &&
              EVP_DigestVerify(ctx.get(), der, static_cast<std::size_t>(len),
                               reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1;
    OPENSSL_free(der);
    return ok;
}

std::string base64url_decode(std::string_view in) {
    auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-') return 62;
        if (c == '_') return 63;
        return -1;
    };
    std::string out;
    unsigned acc = 0;
    int bits = 0;
    for (char c : in) {
        const int v = value(c);
        if (v < 0) break;
        acc = (acc << 6) | static_cast<unsigned>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

// DER CSR for `names` signed by `key`, base64url encoded.
std::string make_csr(EVP_PKEY* key, const std::vector<std::string>& names, std::string& error) {
    std::unique_ptr<X509_REQ, ReqDeleter> req(X509_REQ_new());
    if (!req || !X509_REQ_set_version(req.get(), 0) || !X509_REQ_set_pubkey(req.get(), key)) {
        error = "CSR: " + ssl_error();
        return {};
    }
    X509_NAME* subject = X509_REQ_get_subject_name(req.get());
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(names.front().c_str()),
                               -1, -1, 0);
    std::string san;
    for (const auto& n : names) san += (san.empty() ? "DNS:" : ",DNS:") + n;
    STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san.c_str());
    if (!ext) {
        sk_X509_EXTENSION_free(exts);
        error = "CSR subjectAltName: " + ssl_error();
        return {};
    }
    sk_X509_EXTENSION_push(exts, ext);
    X509_REQ_add_extensions(req.get(), exts);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    if (X509_REQ_sign(req.get(), key, EVP_sha256()) <= 0) {
        error = "CSR sign: " + ssl_error();
        return {};
    }
    unsigned char* der = nullptr;
    const int len = i2d_X509_REQ(req.get(), &der);
    if (len <= 0) {
        error = "CSR encode: " + ssl_error();
        return {};
    }
    std::string out = base64url(std::string_view(reinterpret_cast<const char*>(der), static_cast<std::size_t>(len)));
    OPENSSL_free(der);
    return out;
}

// A self-signed certificate for `names`, valid a week, marked as ours so it is always renewed.
std::string placeholder_pem(EVP_PKEY* key, const std::vector<std::string>& names) {
    Cert x(X509_new());
    X509_set_version(x.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(x.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(x.get()), 7 * 24 * 3600);
    X509_set_pubkey(x.get(), key);
    X509_NAME* name = X509_get_subject_name(x.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(kPlaceholderName), -1,
                               -1, 0);
    X509_set_issuer_name(x.get(), name);
    std::string san;
    for (const auto& n : names) san += (san.empty() ? "DNS:" : ",DNS:") + n;
    if (X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san.c_str())) {
        X509_add_ext(x.get(), ext, -1);
        X509_EXTENSION_free(ext);
    }
    if (X509_sign(x.get(), key, EVP_sha256()) <= 0) return {};
    Bio bio(BIO_new(BIO_s_mem()));
    if (!PEM_write_bio_X509(bio.get(), x.get())) return {};
    char* data = nullptr;
    const long n = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, static_cast<std::size_t>(n));
}

bool asn1_time(const ASN1_TIME* t, Clock::time_point& out) {
    std::tm tm{};
    if (!ASN1_TIME_to_tm(t, &tm)) return false;
    out = Clock::from_time_t(timegm(&tm));
    return true;
}

// ---- the HTTPS client: one request per connection, blocking, on the manager's thread ----

struct HttpReply {
    int status = 0;
    std::string body;
    std::string nonce;     // Replay-Nonce
    std::string location;  // Location
    std::string retry_after;
};

bool split_url(const std::string& url, std::string& host, std::string& port, std::string& path) {
    if (!url.starts_with("https://")) return false;
    std::string rest = url.substr(8);
    const std::size_t slash = rest.find('/');
    std::string authority = rest.substr(0, slash);
    path = slash == std::string::npos ? "/" : rest.substr(slash);
    const std::size_t colon = authority.rfind(':');
    if (colon != std::string::npos && authority.find(']') == std::string::npos) {
        host = authority.substr(0, colon);
        port = authority.substr(colon + 1);
    } else {
        host = authority;
        port = "443";
    }
    return !host.empty();
}

std::string dechunk(std::string_view in) {
    std::string out;
    std::size_t pos = 0;
    for (;;) {
        const std::size_t eol = in.find("\r\n", pos);
        if (eol == std::string_view::npos) return out;
        const std::size_t size = std::strtoul(std::string(in.substr(pos, eol - pos)).c_str(), nullptr, 16);
        if (size == 0) return out;
        pos = eol + 2;
        if (pos + size > in.size()) return out;
        out.append(in.data() + pos, size);
        pos += size + 2;
    }
}

bool https_request(const AcmeConfig& cfg, const std::string& method, const std::string& url, const std::string& body,
                   HttpReply& reply, std::string& error) {
    std::string host, port, path;
    if (!split_url(url, host, port, path)) {
        error = "ACME directory URLs must be https://: " + url;
        return false;
    }
    try {
        asio::io_context io;
        asio::ssl::context tls(asio::ssl::context::tls_client);
        tls.set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
                        asio::ssl::context::no_sslv3 | asio::ssl::context::no_tlsv1 | asio::ssl::context::no_tlsv1_1);
        if (!cfg.ca_file.empty()) tls.load_verify_file(cfg.ca_file);
        else tls.set_default_verify_paths();
        tls.set_verify_mode(asio::ssl::verify_peer);
        asio::ip::tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(host, port);
        asio::ssl::stream<asio::ip::tcp::socket> stream(io, tls);
        asio::connect(stream.lowest_layer(), endpoints);
        stream.lowest_layer().set_option(asio::ip::tcp::no_delay(true));
        const timeval timeout{30, 0};
        ::setsockopt(stream.lowest_layer().native_handle(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
        ::setsockopt(stream.lowest_layer().native_handle(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
        SSL_set_tlsext_host_name(stream.native_handle(), host.c_str());
        SSL_set1_host(stream.native_handle(), host.c_str());
        stream.handshake(asio::ssl::stream_base::client);

        std::string req = method + " " + path + " HTTP/1.1\r\nHost: " + host + (port == "443" ? "" : ":" + port) +
                          "\r\nUser-Agent: agensio/" AGENSIO_VERSION "\r\nConnection: close\r\nAccept: */*\r\n";
        if (!body.empty())
            req += "Content-Type: application/jose+json\r\nContent-Length: " + std::to_string(body.size()) + "\r\n";
        req += "\r\n" + body;
        asio::write(stream, asio::buffer(req));

        std::string raw;
        asio::error_code ec;
        char buf[8192];
        for (;;) {
            const std::size_t n = stream.read_some(asio::buffer(buf), ec);
            if (n) raw.append(buf, n);
            if (ec) break;
            if (raw.size() > (1u << 20)) break;
        }
        // eof, ssl short read and a peer that closes without close_notify are all the end.
        const std::size_t head_end = raw.find("\r\n\r\n");
        if (head_end == std::string::npos) {
            error = "no HTTP response from " + host + " (" + ec.message() + ")";
            return false;
        }
        std::string_view head(raw.data(), head_end);
        reply.status = std::atoi(std::string(head.substr(head.find(' ') + 1, 3)).c_str());
        bool chunked = false;
        std::size_t line = head.find("\r\n");
        while (line != std::string_view::npos) {
            std::string_view l = head.substr(line + 2);
            const std::size_t next = l.find("\r\n");
            if (next != std::string_view::npos) l = l.substr(0, next);
            const std::size_t colon = l.find(':');
            if (colon != std::string_view::npos) {
                std::string name(l.substr(0, colon));
                std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return std::tolower(c); });
                std::string_view value = l.substr(colon + 1);
                while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
                if (name == "replay-nonce") reply.nonce = value;
                else if (name == "location") reply.location = value;
                else if (name == "retry-after") reply.retry_after = value;
                else if (name == "transfer-encoding" && value.find("chunked") != std::string_view::npos) chunked = true;
            }
            line = next == std::string_view::npos ? next : line + 2 + next;
        }
        std::string_view rest(raw.data() + head_end + 4, raw.size() - head_end - 4);
        reply.body = chunked ? dechunk(rest) : std::string(rest);
        return true;
    } catch (const std::exception& e) {
        error = std::string(method) + " " + url + ": " + e.what();
        return false;
    }
}

// The account and the signed requests of one session.
class Session {
public:
    Session(const AcmeConfig& cfg, ErrorLog& log) : cfg_(cfg), log_(log) {}

    bool open(const fs::path& account_key, std::string& error) {
        std::string pem;
        if (!read_file(account_key, pem)) {
            Pkey key = generate_key();
            pem = key ? key_to_pem(key.get()) : std::string();
            if (pem.empty() || !write_file(account_key, pem, 0600, error)) {
                if (error.empty()) error = "cannot create the account key: " + ssl_error();
                return false;
            }
            log_.info("acme: created account key " + account_key.string());
        }
        key_ = key_from_pem(pem);
        if (!key_) {
            error = "cannot read " + account_key.string() + ": " + ssl_error();
            return false;
        }
        jwk_ = jwk_json(key_.get());
        thumbprint_ = base64url(sha256(jwk_));
        HttpReply dir;
        if (!https_request(cfg_, "GET", cfg_.directory, "", dir, error)) return false;
        json::Value d;
        if (dir.status != 200 || !json::parse(dir.body, d, error)) {
            error = "directory " + cfg_.directory + ": HTTP " + std::to_string(dir.status) + " " + error;
            return false;
        }
        new_nonce_ = d.get("newNonce");
        new_account_ = d.get("newAccount");
        new_order_ = d.get("newOrder");
        if (new_nonce_.empty() || new_account_.empty() || new_order_.empty()) {
            error = "directory " + cfg_.directory + " lacks newNonce/newAccount/newOrder";
            return false;
        }
        // The account: created or found by key (RFC 8555 section 7.3).
        json::Value acct = json::Value::object();
        acct.set("termsOfServiceAgreed", true);
        if (!cfg_.email.empty()) acct.set("contact", json::Value::array().push("mailto:" + cfg_.email));
        HttpReply r;
        if (!post(new_account_, acct.dump(), r, error)) return false;
        if (r.status != 200 && r.status != 201) {
            error = "newAccount: " + problem(r);
            return false;
        }
        kid_ = r.location;
        if (kid_.empty()) {
            error = "newAccount: no account URL in the reply";
            return false;
        }
        return true;
    }

    const std::string& thumbprint() const noexcept { return thumbprint_; }
    const std::string& new_order() const noexcept { return new_order_; }

    // A signed POST (payload "" is POST-as-GET). Retries once on a bad nonce.
    bool post(const std::string& url, const std::string& payload, HttpReply& reply, std::string& error) {
        for (int attempt = 0; attempt < 2; ++attempt) {
            if (nonce_.empty() && !fetch_nonce(error)) return false;
            json::Value header = json::Value::object();
            header.set("alg", "ES256").set("nonce", nonce_).set("url", url);
            std::string header_text;
            if (kid_.empty()) {
                header_text = "{\"alg\":\"ES256\",\"jwk\":" + jwk_ + ",\"nonce\":" + json::Value(nonce_).dump() +
                              ",\"url\":" + json::Value(url).dump() + "}";
            } else {
                header.set("kid", kid_);
                header_text = header.dump();
            }
            nonce_.clear();
            const std::string body = jws_sign(key_pem_cache(), header_text, payload, error);
            if (body.empty()) return false;
            reply = HttpReply{};
            if (!https_request(cfg_, "POST", url, body, reply, error)) return false;
            nonce_ = reply.nonce;
            if (reply.status == 400 && reply.body.find("badNonce") != std::string::npos) continue;
            return true;
        }
        error = "badNonce twice from " + url;
        return false;
    }

    static std::string problem(const HttpReply& r) {
        json::Value p;
        std::string ignored;
        if (json::parse(r.body, p, ignored) && p.is_object())
            return "HTTP " + std::to_string(r.status) + " " + std::string(p.get("type")) + ": " +
                   std::string(p.get("detail"));
        return "HTTP " + std::to_string(r.status) + " " + r.body.substr(0, 200);
    }

private:
    bool fetch_nonce(std::string& error) {
        HttpReply r;
        if (!https_request(cfg_, "HEAD", new_nonce_, "", r, error)) return false;
        nonce_ = r.nonce;
        if (nonce_.empty()) {
            error = "newNonce gave no Replay-Nonce";
            return false;
        }
        return true;
    }
    const std::string& key_pem_cache() {
        if (pem_.empty()) pem_ = key_to_pem(key_.get());
        return pem_;
    }

    const AcmeConfig& cfg_;
    ErrorLog& log_;
    Pkey key_;
    std::string pem_, jwk_, thumbprint_, kid_, nonce_;
    std::string new_nonce_, new_account_, new_order_;
};

// Polls `url` (POST-as-GET) until its "status" leaves `waiting`; at most a minute.
bool poll(Session& s, const std::string& url, std::string_view waiting1, std::string_view waiting2, json::Value& out,
          std::string& error) {
    for (int i = 0; i < 60; ++i) {
        HttpReply r;
        if (!s.post(url, "", r, error)) return false;
        if (r.status != 200) {
            error = Session::problem(r);
            return false;
        }
        if (!json::parse(r.body, out, error)) return false;
        const std::string_view status = out.get("status");
        if (status != waiting1 && status != waiting2) return true;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    error = "timed out waiting for " + url;
    return false;
}

}  // namespace

// ---- public helpers ----

std::string base64url(std::string_view bytes) {
    static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((bytes.size() + 2) / 3 * 4);
    std::size_t i = 0;
    while (i + 3 <= bytes.size()) {
        const unsigned v = (static_cast<unsigned char>(bytes[i]) << 16) | (static_cast<unsigned char>(bytes[i + 1]) << 8) |
                           static_cast<unsigned char>(bytes[i + 2]);
        out.push_back(alphabet[(v >> 18) & 63]);
        out.push_back(alphabet[(v >> 12) & 63]);
        out.push_back(alphabet[(v >> 6) & 63]);
        out.push_back(alphabet[v & 63]);
        i += 3;
    }
    if (bytes.size() - i == 1) {
        const unsigned v = static_cast<unsigned char>(bytes[i]) << 16;
        out.push_back(alphabet[(v >> 18) & 63]);
        out.push_back(alphabet[(v >> 12) & 63]);
    } else if (bytes.size() - i == 2) {
        const unsigned v = (static_cast<unsigned char>(bytes[i]) << 16) | (static_cast<unsigned char>(bytes[i + 1]) << 8);
        out.push_back(alphabet[(v >> 18) & 63]);
        out.push_back(alphabet[(v >> 12) & 63]);
        out.push_back(alphabet[(v >> 6) & 63]);
    }
    return out;
}

std::string jws_sign(const std::string& pem_key, std::string_view protected_header, std::string_view payload,
                     std::string& error) {
    Pkey key = key_from_pem(pem_key);
    if (!key) {
        error = "JWS: bad key: " + ssl_error();
        return {};
    }
    const std::string p = base64url(protected_header);
    const std::string b = base64url(payload);
    std::string sig;
    if (!es256_sign(key.get(), p + "." + b, sig)) {
        error = "JWS: sign: " + ssl_error();
        return {};
    }
    return "{\"protected\":\"" + p + "\",\"payload\":\"" + b + "\",\"signature\":\"" + base64url(sig) + "\"}";
}

bool jws_verify(const std::string& pem_key, std::string_view jws_json, std::string& error) {
    Pkey key = key_from_pem(pem_key);
    json::Value v;
    if (!key || !json::parse(jws_json, v, error)) return false;
    const std::string signing_input = std::string(v.get("protected")) + "." + std::string(v.get("payload"));
    if (!es256_verify(key.get(), signing_input, base64url_decode(v.get("signature")))) {
        error = "signature does not verify";
        return false;
    }
    return true;
}

bool jwk_of(const std::string& pem_key, std::string& jwk, std::string& thumbprint, std::string& error) {
    Pkey key = key_from_pem(pem_key);
    if (!key) {
        error = ssl_error();
        return false;
    }
    jwk = jwk_json(key.get());
    thumbprint = base64url(sha256(jwk));
    return !jwk.empty();
}

std::vector<AcmeSite> sites_of(const Config& cfg) {
    std::vector<AcmeSite> out;
    for (const auto& site : cfg.sites) {
        if (!site.tls || !site.tls->automatic) continue;
        if (std::any_of(out.begin(), out.end(), [&](const AcmeSite& s) { return s.cert == site.tls->cert; })) continue;
        AcmeSite s;
        s.names = site.server_names;
        s.cert = site.tls->cert;
        s.key = site.tls->key;
        s.dir = s.cert.parent_path();
        out.push_back(std::move(s));
    }
    return out;
}

void prepare_storage(const Config& cfg, const std::vector<AcmeSite>& sites, int uid, int gid) {
    if (sites.empty()) return;
    auto own = [&](const fs::path& p) {
        if (uid >= 0 && ::chown(p.c_str(), static_cast<uid_t>(uid), static_cast<gid_t>(gid)) != 0)
            throw std::runtime_error("acme: cannot chown " + p.string() + ": " + std::strerror(errno));
    };
    std::error_code ec;
    const fs::path storage = cfg.acme.storage;
    fs::create_directories(storage, ec);
    if (ec) throw std::runtime_error("acme: cannot create " + storage.string() + ": " + ec.message());
    ::chmod(storage.c_str(), 0700);
    own(storage);
    for (const auto& site : sites) {
        fs::create_directories(site.dir, ec);
        if (ec) throw std::runtime_error("acme: cannot create " + site.dir.string() + ": " + ec.message());
        ::chmod(site.dir.c_str(), 0700);
        if (!fs::is_regular_file(site.cert) || !fs::is_regular_file(site.key)) {
            Pkey key = generate_key();
            const std::string pem = key ? key_to_pem(key.get()) : std::string();
            const std::string cert = key ? placeholder_pem(key.get(), site.names) : std::string();
            std::string error;
            if (pem.empty() || cert.empty() || !write_file(site.key, pem, 0600, error) ||
                !write_file(site.cert, cert, 0644, error))
                throw std::runtime_error("acme: placeholder certificate for " + site.names.front() + ": " +
                                         (error.empty() ? ssl_error() : error));
        }
        own(site.dir);
        own(site.key);
        own(site.cert);
    }
    const fs::path account = storage / "account.key";
    if (fs::is_regular_file(account)) own(account);
}

bool renewal_due(Clock::time_point not_before, Clock::time_point not_after, Clock::time_point now) noexcept {
    if (now >= not_after) return true;
    const auto lifetime = not_after - not_before;
    return (not_after - now) * 3 < lifetime;
}

bool needs_renewal(const fs::path& cert_path, const std::vector<std::string>& names, Clock::time_point now,
                   std::string& why) {
    std::string pem;
    if (!read_file(cert_path, pem)) {
        why = "no certificate yet";
        return true;
    }
    Bio bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    Cert x(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!x) {
        why = "unreadable certificate";
        return true;
    }
    char cn[128] = {};
    X509_NAME_get_text_by_NID(X509_get_issuer_name(x.get()), NID_commonName, cn, sizeof cn);
    if (std::string_view(cn) == kPlaceholderName) {
        why = "placeholder certificate";
        return true;
    }
    std::vector<std::string> covered;
    if (auto* sans = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(x.get(), NID_subject_alt_name, nullptr, nullptr))) {
        for (int i = 0; i < sk_GENERAL_NAME_num(sans); ++i) {
            const GENERAL_NAME* g = sk_GENERAL_NAME_value(sans, i);
            if (g->type == GEN_DNS)
                covered.emplace_back(reinterpret_cast<const char*>(ASN1_STRING_get0_data(g->d.dNSName)),
                                     static_cast<std::size_t>(ASN1_STRING_length(g->d.dNSName)));
        }
        GENERAL_NAMES_free(sans);
    }
    for (const auto& n : names)
        if (std::find(covered.begin(), covered.end(), n) == covered.end()) {
            why = "certificate does not cover " + n;
            return true;
        }
    Clock::time_point nb, na;
    if (!asn1_time(X509_get0_notBefore(x.get()), nb) || !asn1_time(X509_get0_notAfter(x.get()), na)) {
        why = "unreadable validity";
        return true;
    }
    if (renewal_due(nb, na, now)) {
        why = "less than a third of the lifetime left";
        return true;
    }
    return false;
}

bool issue(const AcmeConfig& cfg, const AcmeSite& site, AcmeChallenges& challenges, ErrorLog& log,
           std::string& error) {
    Session s(cfg, log);
    if (!s.open(fs::path(cfg.storage) / "account.key", error)) return false;

    json::Value order = json::Value::object();
    json::Value ids = json::Value::array();
    for (const auto& n : site.names) ids.push(json::Value::object().set("type", "dns").set("value", n));
    order.set("identifiers", std::move(ids));
    HttpReply r;
    if (!s.post(s.new_order(), order.dump(), r, error)) return false;
    if (r.status != 201) {
        error = "newOrder: " + Session::problem(r);
        return false;
    }
    const std::string order_url = r.location;
    json::Value o;
    if (!json::parse(r.body, o, error)) return false;
    const std::string finalize_url(o.get("finalize"));

    // One HTTP-01 challenge per authorization; tokens are published for the whole order.
    std::vector<std::string> tokens;
    auto cleanup = [&] {
        for (const auto& t : tokens) challenges.remove(t);
    };
    bool ok = true;
    for (const auto& auth_url : o["authorizations"].items()) {
        if (!auth_url.is_string()) continue;
        HttpReply ar;
        json::Value a;
        if (!s.post(auth_url.str(), "", ar, error) || ar.status != 200 || !json::parse(ar.body, a, error)) {
            if (error.empty()) error = "authorization: " + Session::problem(ar);
            ok = false;
            break;
        }
        const std::string name(a["identifier"].get("value"));
        if (a.get("status") == "valid") continue;
        std::string challenge_url, token;
        for (const auto& c : a["challenges"].items())
            if (c.get("type") == "http-01") {
                challenge_url = c.get("url");
                token = c.get("token");
            }
        if (token.empty()) {
            error = name + ": the CA offers no http-01 challenge";
            ok = false;
            break;
        }
        challenges.add(token, token + "." + s.thumbprint());
        tokens.push_back(token);
        HttpReply cr;
        if (!s.post(challenge_url, "{}", cr, error)) {
            ok = false;
            break;
        }
        if (cr.status != 200) {
            error = name + ": challenge: " + Session::problem(cr);
            ok = false;
            break;
        }
        json::Value result;
        if (!poll(s, auth_url.str(), "pending", "processing", result, error)) {
            ok = false;
            break;
        }
        if (result.get("status") != "valid") {
            std::string detail;
            for (const auto& c : result["challenges"].items())
                if (c.get("type") == "http-01") detail = c["error"].get("detail");
            error = name + ": validation " + std::string(result.get("status")) + (detail.empty() ? "" : ": " + detail);
            ok = false;
            break;
        }
        log.info("acme: " + name + " validated (http-01)");
    }
    if (!ok) {
        cleanup();
        return false;
    }

    // Finalize with a CSR for a fresh key, wait for the certificate, download the chain.
    Pkey key = generate_key();
    const std::string csr = key ? make_csr(key.get(), site.names, error) : std::string();
    if (csr.empty()) {
        cleanup();
        return false;
    }
    HttpReply fr;
    if (!s.post(finalize_url, json::Value::object().set("csr", csr).dump(), fr, error) ||
        (fr.status != 200 && (error = "finalize: " + Session::problem(fr), true))) {
        cleanup();
        return false;
    }
    json::Value done;
    if (!poll(s, order_url, "processing", "ready", done, error)) {
        cleanup();
        return false;
    }
    cleanup();
    if (done.get("status") != "valid" || done.get("certificate").empty()) {
        error = "order ended " + std::string(done.get("status"));
        return false;
    }
    HttpReply cert;
    if (!s.post(std::string(done.get("certificate")), "", cert, error)) return false;
    if (cert.status != 200 || cert.body.find("-----BEGIN CERTIFICATE-----") == std::string::npos) {
        error = "certificate download: " + Session::problem(cert);
        return false;
    }
    return write_file(site.key, key_to_pem(key.get()), 0600, error) && write_file(site.cert, cert.body, 0644, error);
}

}  // namespace acme

// ---- AcmeManager ----

AcmeManager::~AcmeManager() { stop(); }

void AcmeManager::start(asio::io_context& ctx, const AcmeConfig& cfg, std::vector<AcmeSite> sites,
                        std::function<void()> on_renewed) {
    ctx_ = &ctx;
    timer_ = std::make_unique<asio::steady_timer>(ctx);
    on_renewed_ = std::move(on_renewed);
    update(cfg, std::move(sites));
}

void AcmeManager::update(const AcmeConfig& cfg, std::vector<AcmeSite> sites) {
    cfg_ = cfg;
    sites_ = std::move(sites);
    if (!sites_.empty()) check();
}

void AcmeManager::stop() {
    stopped_ = true;
    if (timer_) timer_->cancel();
    if (worker_.joinable()) worker_.join();  // an order in flight finishes (bounded by its polls)
}

void AcmeManager::arm(std::chrono::seconds delay) {
    timer_->expires_after(delay);
    timer_->async_wait([this](const asio::error_code& ec) {
        if (!ec && !stopped_) check();
    });
}

void AcmeManager::check() {
    if (busy_ || stopped_ || !ctx_) return;
    const auto now = std::chrono::steady_clock::now();
    std::vector<AcmeSite> due;
    for (const auto& site : sites_) {
        auto failed = failed_at_.find(site.cert.string());
        if (failed != failed_at_.end() && now - failed->second < std::chrono::hours(1)) continue;
        std::string why;
        if (acme::needs_renewal(site.cert, site.names, Clock::now(), why)) {
            log_.info("acme: ordering a certificate for " + site.names.front() + " (" + why + ")");
            due.push_back(site);
        }
    }
    if (due.empty()) {
        arm(std::chrono::hours(1));
        return;
    }
    busy_ = true;
    if (worker_.joinable()) worker_.join();
    worker_ = std::jthread([this, due = std::move(due), cfg = cfg_] {
        std::vector<std::pair<std::string, bool>> results;  // cert path, success
        for (const auto& site : due) {
            std::string error;
            const bool ok = acme::issue(cfg, site, challenges_, log_, error);
            if (ok) log_.warn("acme: certificate issued for " + site.names.front() + " -> " + site.cert.string());
            else log_.error("acme: " + site.names.front() + ": " + error + " (retry in an hour)");
            results.emplace_back(site.cert.string(), ok);
        }
        asio::post(*ctx_, [this, results = std::move(results)] {
            busy_ = false;
            bool renewed = false;
            for (const auto& [path, ok] : results) {
                if (ok) {
                    failed_at_.erase(path);
                    renewed = true;
                } else {
                    failed_at_[path] = std::chrono::steady_clock::now();
                }
            }
            if (stopped_) return;
            if (renewed && on_renewed_) on_renewed_();
            check();  // sites added meanwhile; failures wait their hour, so this cannot spin
        });
    });
}

}  // namespace agensio

#else  // without OpenSSL there is nothing to order; the manager only has to exist

namespace agensio {
AcmeManager::~AcmeManager() = default;
void AcmeManager::stop() {}
}  // namespace agensio

#endif  // AGENSIO_HAS_TLS
