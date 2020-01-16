#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string>

#include "ssl-defines.h"
#include "ssl-util.h"

namespace my {

void send_http_request(BIO *bio, const std::string& line, const std::string& host)
{
    std::string request = line + "\r\n";
    request += "Host: " + host + "\r\n";
    request += "\r\n";

    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);
}

void verify_the_certificate(SSL *ssl, const std::string& expected_hostname)
{
    int err = SSL_get_verify_result(ssl);
    if (err != X509_V_OK) {
        const char *message = X509_verify_cert_error_string(err);
        fprintf(stderr, "Certificate verification error: %s (%d)\n", message, err);
        exit(1);
    }
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr) {
        fprintf(stderr, "No certificate was presented by the server\n");
        exit(1);
    }
    if (X509_check_host(cert, expected_hostname.data(), expected_hostname.size(), 0, nullptr) != 1) {
        fprintf(stderr, "Certificate verification error: X509_check_host\n");
        exit(1);
    }
}

} // namespace my

int main()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
#endif

    /* Set up the SSL context */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_client_method()));
#else
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_client_method()));
#endif

    /* Load the trust store */

    if (!SSL_CTX_load_verify_locations(ctx.get(), "client-trust-store.pem", nullptr)) {
        my::print_errors_and_exit("Error loading trust store");
    }

    /* Set up the underlying TCP connection */

    std::string server_ip_address_and_port = std::string(MY_SERVER_IP_ADDRESS) + ":" + std::to_string(MY_SERVER_PORT);
    auto underlying_bio = my::UniquePtr<BIO>(BIO_new_connect(server_ip_address_and_port.c_str()));
    if (underlying_bio == nullptr) {
        my::print_errors_and_exit("Error in BIO_new_connect");
    }
    if (BIO_do_connect(underlying_bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_connect on connect BIO");
    }

    /* Set up the TLS filter and create the TLS connection */

    auto bio = std::move(underlying_bio)
        | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 1))
        ;
    if (BIO_do_connect(bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_connect on SSL BIO");
    }
    my::verify_the_certificate(my::get_ssl(bio.get()), MY_SERVER_HOSTNAME);

    /* Perform the HTTPS transaction */

    my::send_http_request(bio.get(), "GET / HTTP/1.1", MY_SERVER_HOSTNAME);
    std::string response = my::receive_http_message(bio.get());
    printf("%s", response.c_str());
}
