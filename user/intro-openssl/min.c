#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <stdio.h>
#include <string.h>

#define MAX_LENGTH 1024

int main()
{
    BIO * bio;
    SSL * ssl;
    SSL_CTX * ctx;

    int p;

    /* Set up the library */
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    /* Set up the SSL context */
    const SSL_METHOD *meth = SSLv23_client_method();
    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return -1;
    }

    
    char* store_path = "./root";
    if(!SSL_CTX_load_verify_locations(ctx, NULL, store_path))
    {
        fprintf(stderr, "Can't load trusted CA from %s\n", store_path);
        return -1;
    }

    /* Setup the connection */
    bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, & ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    // Set 
    SSL_CTX_set_verify_depth(ctx, 50);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* Create and setup the connection */

    BIO_set_conn_hostname(bio, "www.google.com:https");
    if(BIO_do_connect(bio) <= 0)
    {
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }

    if(SSL_get_verify_result(ssl) != X509_V_OK)
    {
        fprintf(stderr, "Verification Error: %ld\n", SSL_get_verify_result(ssl));
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }

    /* Close the connection and free the context */
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 0;
}
