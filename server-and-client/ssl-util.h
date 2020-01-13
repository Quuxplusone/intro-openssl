#pragma once

#include <memory>
#include <stdarg.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

#include "ssl-backport.h"  // BIO_meth_new in OpenSSL 1.0.2

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace my {

template<class T> struct DeleterOf;
template<> struct DeleterOf<SSL_CTX> { void operator()(SSL_CTX *p) const { SSL_CTX_free(p); } };
template<> struct DeleterOf<SSL> { void operator()(SSL *p) const { SSL_free(p); } };
template<> struct DeleterOf<BIO> { void operator()(BIO *p) const { BIO_free_all(p); } };
template<> struct DeleterOf<BIO_METHOD> { void operator()(BIO_METHOD *p) const { BIO_meth_free(p); } };

template<class OpenSSLType>
using UniquePtr = std::unique_ptr<OpenSSLType, DeleterOf<OpenSSLType>>;

class StringBIO {
    std::string str_;
    my::UniquePtr<BIO_METHOD> methods_;
    my::UniquePtr<BIO> bio_;
public:
    StringBIO(StringBIO&&) = delete;
    StringBIO& operator=(StringBIO&&) = delete;

    explicit StringBIO() {
        methods_.reset(BIO_meth_new(BIO_TYPE_SOURCE_SINK, "StringBIO"));
        if (methods_ == nullptr) {
            throw std::runtime_error("StringBIO: error in BIO_meth_new");
        }
        BIO_meth_set_write(methods_.get(), [](BIO *bio, const char *data, int len) -> int {
            std::string *str = reinterpret_cast<std::string*>(BIO_get_data(bio));
            str->append(data, len);
            return len;
        });
        bio_.reset(BIO_new(methods_.get()));
        if (bio_ == nullptr) {
            throw std::runtime_error("StringBIO: error in BIO_new");
        }
        BIO_set_data(bio_.get(), &str_);
        BIO_set_init(bio_.get(), 1);
    }
    BIO *bio() { return bio_.get(); }
    std::string str() && { return std::move(str_); }
};

[[noreturn]] inline void __attribute__((format(printf,1,2)))
print_errors_and_exit(const char *message, ...)
{
    va_list ap;
    va_start(ap, message);
    vfprintf(stderr, message, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    ERR_print_errors_fp(stderr);
    exit(1);
}

[[noreturn]] inline void
print_errors_and_throw(const char *message)
{
    my::StringBIO bio;
    ERR_print_errors(bio.bio());
    throw std::runtime_error(std::string(message) + "\n" + std::move(bio).str());
}

inline SSL *get_ssl(BIO *bio)
{
    SSL *ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (ssl == nullptr) {
        my::print_errors_and_exit("Error in BIO_get_ssl");
    }
    return ssl;
}

inline std::string receive_some_data(BIO *bio)
{
    std::string result = "";
    do {
        char buffer[1024];
        int len = BIO_read(bio, buffer, sizeof(buffer));
        if (len < 0) {
            my::print_errors_and_throw("error in BIO_read");
        } else if (len == 0) {
            if (BIO_should_retry(bio)) {
                continue;
            }
            if (result.empty()) {
                my::print_errors_and_throw("empty BIO_read");
            }
        } else {
            result.append(buffer, len);
            if (BIO_pending(bio)) {
                continue;
            }
        }
    } while (false);
    return result;
}

inline std::vector<std::string> split_headers(const std::string& text)
{
    std::vector<std::string> lines;
    const char *start = text.c_str();
    while (const char *end = strstr(start, "\r\n")) {
        lines.push_back(std::string(start, end));
        start = end + 2;
    }
    return lines;
}

} // namespace my