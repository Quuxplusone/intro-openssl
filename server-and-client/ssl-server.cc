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

void send_http_response(BIO *bio, const std::string& body)
{
    std::string response = "HTTP/1.1 200 OK\r\n";
    response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    response += "\r\n";

    BIO_write(bio, response.data(), response.size());
    BIO_write(bio, body.data(), body.size());
    BIO_flush(bio);
}

void worker_thread(my::UniquePtr<BIO> bio)
{
    /* Perform the HTTPS transaction */

    std::string request = my::receive_http_message(bio.get());
    printf("Got request:\n");
    printf("%s\n", request.c_str());
    my::send_http_response(bio.get(), "okay cool\n");
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
#else
    auto ctx = my::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_method()));
#endif

    if (SSL_CTX_use_certificate_file(ctx.get(), "server-certificate.pem", SSL_FILETYPE_PEM) <= 0) {
        my::print_errors_and_exit("Error loading server certificate");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), "server-private-key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        my::print_errors_and_exit("Error loading server private key");
    }

    /* Set up the underlying TCP acceptor */

    std::string server_port_as_string = std::to_string(MY_SERVER_PORT);
    auto accept_bio = my::UniquePtr<BIO>(BIO_new_accept(server_port_as_string.c_str()));
    if (accept_bio == nullptr) {
        my::print_errors_and_exit("Error in BIO_new_accept");
    }
    if (BIO_do_accept(accept_bio.get()) <= 0) {
        my::print_errors_and_exit("Error in BIO_do_accept (binding to port %d)", MY_SERVER_PORT);
    }

    /* Set up a Ctrl-C signal handler for clean shutdowns */

    bool quit = false;
    static auto shutdown_the_socket = [&]() {
        int fd = BIO_get_fd(accept_bio.get(), nullptr);
        quit = true;
        close(fd);
    };
    signal(SIGINT, +[](int) { shutdown_the_socket(); });

    /* The main server loop */

    while (auto client_bio = my::accept_new_tcp_connection(accept_bio.get(), &quit)) {
        auto ssl_bio = std::move(client_bio)
            | my::UniquePtr<BIO>(BIO_new_ssl(ctx.get(), 0))
            ;

        std::thread([ssl_bio = std::move(ssl_bio)]() mutable {
            try {
                my::worker_thread(std::move(ssl_bio));
            } catch (const std::exception& ex) {
                printf("Worker thread exited with exception:\n%s\n", ex.what());
            }
        }).detach();
    }

    printf("\nClean exit!\n");
}
