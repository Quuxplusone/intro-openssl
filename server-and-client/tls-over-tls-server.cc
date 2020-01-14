#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <signal.h>
#include <unistd.h>

#include <stdexcept>
#include <stdio.h>
#include <string>
#include <thread>
#include <vector>

#include "ssl-defines.h"
#include "ssl-util.h"


namespace my {

std::string receive_http_request(BIO *bio)
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

void send_http_response(BIO *bio, const std::string& body)
{
    std::string response = "HTTP/1.1 200 OK\r\n";
    response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    response += "\r\n";

    BIO_write(bio, response.data(), response.size());
    BIO_write(bio, body.data(), body.size());
    BIO_flush(bio);
}

void worker_thread(my::UniquePtr<BIO> bio, SSL_CTX *inner_ctx)
{
    std::string request = my::receive_http_request(bio.get());
    printf("Got outer request:\n");
    printf("%s\n", request.c_str());
    my::send_http_response(bio.get(), "");

    auto inner_bio = my::UniquePtr<BIO>(BIO_new_ssl(inner_ctx, 0));
    BIO_push(inner_bio.get(), bio.release());

    request = my::receive_http_request(inner_bio.get());
    printf("Got inner request:\n");
    printf("%s\n", request.c_str());
    my::send_http_response(inner_bio.get(), "okay cool");
}

my::UniquePtr<BIO> accept_new_tcp_connection(BIO *accept_bio, bool *quit)
{
    if (BIO_do_accept(accept_bio) <= 0) {
        if (*quit) {
            return nullptr;
        }
        my::print_errors_and_exit("Error in BIO_do_accept (accepting a connection from the client)");
    }
    return my::UniquePtr<BIO>(BIO_pop(accept_bio));
}

} // namespace my

int main()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_method()));
    std::shared_ptr<SSL_CTX> inner_ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(SSLv23_method()));
#else
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_method()));
    std::shared_ptr<SSL_CTX> inner_ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_method()));
#endif

    if (!SSL_CTX_load_verify_locations(ctx.get(), "server-trust-store.pem", nullptr)) {
        my::print_errors_and_exit("Error loading trust store");
    }
    if (SSL_CTX_use_certificate_file(ctx.get(), "server-certificate.pem", SSL_FILETYPE_PEM) <= 0) {
        my::print_errors_and_exit("Error loading server certificate");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), "server-private-key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        my::print_errors_and_exit("Error loading server private key");
    }

    if (!SSL_CTX_load_verify_locations(inner_ctx.get(), "server-trust-store.pem", nullptr)) {
        my::print_errors_and_exit("Error loading trust store");
    }
    if (SSL_CTX_use_certificate_file(inner_ctx.get(), "inner-server-certificate.pem", SSL_FILETYPE_PEM) <= 0) {
        my::print_errors_and_exit("Error loading inner server certificate");
    }
    if (SSL_CTX_use_PrivateKey_file(inner_ctx.get(), "inner-server-private-key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        my::print_errors_and_exit("Error loading inner server private key");
    }

    /* Set up the underlying TCP acceptor */

    std::string server_port_as_string = std::to_string(MY_SERVER_PORT);
    auto accept_bio = my::UniquePtr<BIO>(BIO_new_accept(server_port_as_string.c_str()));
    if (accept_bio == nullptr) {
        my::print_errors_and_exit("Error in BIO_new_accept");
    }

    BIO_set_close(accept_bio.get(), 1);

    if (BIO_do_accept(accept_bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_accept (binding to port %d)", MY_SERVER_PORT);
    }

    /* Set up a signal handler so that when you Ctrl-C the server program,
     * it will quickly relinquish the socket it was using.
     */
    bool quit = false;
    static auto shutdown_the_socket = [&]() {
        int fd = BIO_get_fd(accept_bio.get(), nullptr);
        BIO_set_close(accept_bio.get(), 0);
        close(fd);
        quit = true;
    };
    signal(SIGINT, +[](int) { shutdown_the_socket(); });

    while (auto client_bio = my::accept_new_tcp_connection(accept_bio.get(), &quit)) {
        auto ssl_bio = my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 0));
        BIO_push(ssl_bio.get(), client_bio.release());

        std::thread([ssl_bio = std::move(ssl_bio), inner_ctx]() mutable {
            try {
                my::worker_thread(std::move(ssl_bio), inner_ctx.get());
            } catch (const std::exception& ex) {
                printf("Worker thread exited with exception:\n%s\n", ex.what());
            }
        }).detach();
    }

    printf("\nClean exit!\n");
}
