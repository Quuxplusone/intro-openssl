// This source file is not part of Kenneth Ballard's tutorial.
// It builds on Ballard's "withssl.c" and shows how to create a
// TLS connection that takes ownership of an existing TCP connection.

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string.h>

int main()
{
    BIO * bio;
    SSL * ssl;
    SSL_CTX * ctx;

    int p;

    const char * request = "GET / HTTP/1.1\x0D\x0AHost: www.verisign.com\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A";
    char r[1024];

    /* Set up the library */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
#else
    OPENSSL_init_ssl(0, NULL);
#endif
    SSL_load_error_strings();

    /* Set up the SSL context */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ctx = SSL_CTX_new(SSLv23_client_method());
#else
    ctx = SSL_CTX_new(TLS_client_method());
#endif

    /* Load the trust store */

    if(! SSL_CTX_load_verify_locations(ctx, "TrustStore.pem", NULL))
    {
        fprintf(stderr, "Error loading trust store\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    /* Setup the underlying connection */

    BIO *underlying_bio = BIO_new_connect("www.verisign.com:443");
    if (underlying_bio == NULL) {
        printf("underlying BIO is null\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    if (BIO_do_connect(underlying_bio) <= 0)
    {
        fprintf(stderr, "Error attempting to connect on underlying BIO\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(underlying_bio);
        SSL_CTX_free(ctx);
        return 1;
    }

    /* Setup the buffering filter */

    BIO *buffer_bio = BIO_new(BIO_f_buffer());
    BIO_push(buffer_bio, underlying_bio);

    bio = BIO_new_ssl(ctx, 1);
    BIO_push(bio, buffer_bio);

    /* Set the SSL_MODE_AUTO_RETRY flag */

    BIO_get_ssl(bio, & ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    /* Create and setup the connection */

    BIO_set_conn_hostname(bio, "www.verisign.com:https");

    if(BIO_do_connect(bio) <= 0)
    {
        fprintf(stderr, "Error attempting to connect\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 1;
    }

    /* Check the certificate */

    if(SSL_get_verify_result(ssl) != X509_V_OK)
    {
        fprintf(stderr, "Certificate verification error: %d\n", (int)SSL_get_verify_result(ssl));
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 1;
    }

    /* Send the request */

    BIO_write(bio, request, strlen(request));
    BIO_flush(bio);

    /* Read in the response */

    for(;;)
    {
        p = BIO_read(bio, r, 1023);
        if(p <= 0) break;
        r[p] = 0;
        printf("%s", r);
    }

    /* Close the connection and free the context */

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 0;
}
