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


int verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];
    
    /*
     * succeeds if ok <> 0
     * Only intervene if failed
     */
    if (!ok) {
        // ok = 0
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int depth = X509_STORE_CTX_get_error_depth(store);
        int err = X509_STORE_CTX_get_error(store);

        fprintf(stderr, "-Error with certificate at depth: %d\n", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr, "  issuer = %s\n", data);
        
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr, "  subject = %s\n", data);

        fprintf(stderr, "  err %i:%s\n", err, X509_verify_cert_error_string(err));
    }

    return ok;
}

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

    /* Create a CTX
     * Application should set up SSL_CTX completely before creating
     * SSL objects from it.
     * In general, an application will create just one SSL_CTX object
     * for all of the connections it makes.
     */
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "Error creating ctx\n");
        SSL_CTX_free(ctx);
        return -1;
    }

    SSL_CTX_set_verify_depth(ctx, 50);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    
    char* CApath = "CAfiles";
    char* CAfile = "CAfile.pem";
    if(!SSL_CTX_load_verify_locations(ctx, CAfile, NULL))
    {
        fprintf(stderr, "Can't load trusted CA from %s\n", CApath);
        return -1;
    }

    /* Setup the connection */
    bio = BIO_new_connect("www.google.com:https");
    if (!bio)
    {
        fprintf(stderr, "Error creating connection BIO\n");
    }

    if(BIO_do_connect(bio) <= 0)
    {
        fprintf(stderr, "Error connecting BIO\n");
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }

    if (!(ssl = SSL_new(ctx))) {
        fprintf(stderr, "Error creating an SSL object\n");
        return -1;
    }

    SSL_set_bio(ssl, bio, bio);
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "Error connecting SSL object\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if(SSL_get_verify_result(ssl) != X509_V_OK)
    {
        fprintf(stderr, "Verification Error: %ld\n", SSL_get_verify_result(ssl));
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }
    
    fprintf(stderr, "Peer verification passed\n");
    char buf[80] = "GET /\n\r";

    int nwritten, rc;
    printf("Bytes to write: %ld\n", strlen(buf));
    for (nwritten = 0; nwritten < sizeof buf; nwritten += rc)
    {
        rc = SSL_write(ssl, buf + nwritten, strlen(buf) - nwritten);
        if (rc <= 0)
        {
            ERR_print_errors_fp(stderr);
            break;
        }
        else
            printf("Bytes written: %d return: %d\n", nwritten, rc);
    }

    char content[1024*1024];
    for (nwritten = 0; nwritten < sizeof content; nwritten += rc)
    {
        rc = SSL_read(ssl, content + nwritten, sizeof content - nwritten);
        if (rc <= 0)
        {
            ERR_print_errors_fp(stderr);
            break;
        }
        else
            printf("Bytes written: %d return: %d\n", nwritten, rc);
    }

    FILE* fp = fopen("page.html", "w");
    if (!fp) {
        fprintf(stderr, "Error creating download file\n");
        return -1;
    }

    // write to a file
    fwrite(content, sizeof(char), nwritten, fp);
    fclose(fp);

    /* Close the connection and free the context */
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 0;
}
