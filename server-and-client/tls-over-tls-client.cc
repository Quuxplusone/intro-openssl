#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string>

#include "ssl-defines.h"
#include "ssl-util.h"


namespace my {

void send_connect_request(BIO *bio, const std::string& host)
{
    std::string request = "CONNECT " + host + " HTTP/1.1\r\n";
    request += "Host: " + host + "\r\n";
    request += "\r\n";

    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);
}

void send_http_request(BIO *bio, const std::string& path, const std::string& host)
{
    std::string request = "GET " + path + " HTTP/1.1\r\n";
    request += "Host: " + host + "\r\n";
    request += "Connection: Close\r\n";
    request += "\r\n";

    BIO_write(bio, request.data(), request.size());
    BIO_flush(bio);
}

std::string receive_http_response(BIO *bio)
{
    std::string headers = my::receive_some_data(bio);
    const char *end_of_headers = strstr(headers.c_str(), "\r\n\r\n");
    while (end_of_headers == nullptr) {
        headers += my::receive_some_data(bio);
        end_of_headers = strstr(headers.c_str(), "\r\n\r\n");
    }
    std::string body = std::string(end_of_headers+4, (const char *)&headers[headers.size()]);
    headers.resize(end_of_headers+2 - &headers[0]);
    size_t content_length = 0;
    for (const std::string& line : my::split_headers(headers)) {
        if (const char *colon = strchr(line.c_str(), ':')) {
            std::string header_name = std::string(&line[0], colon);
            if (header_name == "Content-Length") {
                do { ++colon; } while (isspace(*colon));
                content_length = std::stoul(colon);
            }
        }
    }
    while (body.size() < content_length) {
        body += my::receive_some_data(bio);
    }
    return headers + "\r\n" + body;
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

    /* Set up the TLS filter */

    auto bio = my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 1));
    BIO_push(bio.get(), underlying_bio.release());

    /* Create and set up the connection */

    if (BIO_do_connect(bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_connect on SSL BIO");
    }

    my::verify_the_certificate(my::get_ssl(bio.get()), MY_SERVER_HOSTNAME);

    my::send_connect_request(bio.get(), MY_SERVER_HOSTNAME);

    std::string response = my::receive_http_response(bio.get());

    printf("Got first response: %s\n", response.c_str());

    /* Set up a second TLS filter */
    auto inner_bio = my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 1));
    BIO_push(inner_bio.get(), bio.release());
    if (BIO_do_connect(inner_bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_connect on inner SSL BIO");
    }

    my::verify_the_certificate(my::get_ssl(inner_bio.get()), MY_INNER_SERVER_HOSTNAME);

    my::send_http_request(inner_bio.get(), "/foo.html", MY_INNER_SERVER_HOSTNAME);

    response = my::receive_http_response(inner_bio.get());

    printf("%s", response.c_str());
}
