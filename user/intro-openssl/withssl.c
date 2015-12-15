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

int verify_cert_chain(X509_STORE *store, X509 *cert, STACK_OF(X509) *st)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "unable to create STORE CTX\n");
        return -1;
    }
    if (X509_STORE_CTX_init(ctx, store, cert, st) != 1) {
        fprintf(stderr, "unable to initialize STORE CTX.\n");
        X509_STORE_CTX_free(ctx);
        return -1;
    }
    int rc = X509_verify_cert(ctx);
    if (!rc)
        rc = X509_STORE_CTX_get_error(ctx);
    X509_STORE_CTX_free(ctx);
    return rc;
}

const char* get_validation_errstr(long e) {
    switch ((int) e) {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            return "ERR_UNABLE_TO_GET_ISSUER_CERT";
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            return "ERR_UNABLE_TO_GET_CRL";
        case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
            return "ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE";
        case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
            return "ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE";
        case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
            return "ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";
        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
            return "ERR_CERT_SIGNATURE_FAILURE";
        case X509_V_ERR_CRL_SIGNATURE_FAILURE:
            return "ERR_CRL_SIGNATURE_FAILURE";
        case X509_V_ERR_CERT_NOT_YET_VALID:
            return "ERR_CERT_NOT_YET_VALID";
        case X509_V_ERR_CERT_HAS_EXPIRED:
            return "ERR_CERT_HAS_EXPIRED";
        case X509_V_ERR_CRL_NOT_YET_VALID:
            return "ERR_CRL_NOT_YET_VALID";
        case X509_V_ERR_CRL_HAS_EXPIRED:
            return "ERR_CRL_HAS_EXPIRED";
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            return "ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD";
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            return "ERR_ERROR_IN_CERT_NOT_AFTER_FIELD";
        case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
            return "ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD";
        case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
            return "ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD";
        case X509_V_ERR_OUT_OF_MEM:
            return "ERR_OUT_OF_MEM";
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            return "ERR_DEPTH_ZERO_SELF_SIGNED_CERT";
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            return "ERR_SELF_SIGNED_CERT_IN_CHAIN";
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            return "ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
            return "ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE";
        case X509_V_ERR_CERT_CHAIN_TOO_LONG:
            return "ERR_CERT_CHAIN_TOO_LONG";
        case X509_V_ERR_CERT_REVOKED:
            return "ERR_CERT_REVOKED";
        case X509_V_ERR_INVALID_CA:
            return "ERR_INVALID_CA";
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
            return "ERR_PATH_LENGTH_EXCEEDED";
        case X509_V_ERR_INVALID_PURPOSE:
            return "ERR_INVALID_PURPOSE";
        case X509_V_ERR_CERT_UNTRUSTED:
            return "ERR_CERT_UNTRUSTED";
        case X509_V_ERR_CERT_REJECTED:
            return "ERR_CERT_REJECTED";
        case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
            return "ERR_SUBJECT_ISSUER_MISMATCH";
        case X509_V_ERR_AKID_SKID_MISMATCH:
            return "ERR_AKID_SKID_MISMATCH";
        case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
            return "ERR_AKID_ISSUER_SERIAL_MISMATCH";
        case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
            return "ERR_KEYUSAGE_NO_CERTSIGN";
        case X509_V_ERR_INVALID_EXTENSION:
            return "ERR_INVALID_EXTENSION";
        case X509_V_ERR_INVALID_POLICY_EXTENSION:
            return "ERR_INVALID_POLICY_EXTENSION";
        case X509_V_ERR_NO_EXPLICIT_POLICY:
            return "ERR_NO_EXPLICIT_POLICY";
        case X509_V_ERR_APPLICATION_VERIFICATION:
            return "ERR_APPLICATION_VERIFICATION";
        default:
            return "ERR_UNKNOWN";
    }
}

int main()
{
    BIO * bio;
    SSL * ssl;
    SSL_CTX * ctx;

    int p;

    char * request = "GET / HTTP/1.1\n\r";
    char r[1024];
    char* store_path = "./root";

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

    /* set depth */
    SSL_CTX_set_verify_depth(ctx, 50);
    
    if(!SSL_CTX_load_verify_locations(ctx, NULL, store_path))
    {
        fprintf(stderr, "Can't load trusted CA from %s\n", store_path);
        return -1;
    }


    /* Load the trust store */
    X509_STORE *s = X509_STORE_new();
    if (s == NULL) {
        fprintf(stderr, "Unable to create new X509 store.\n");
        return -1;
    }

    int rc = X509_STORE_load_locations(s, NULL, store_path); 
    if (rc != 1) {
        fprintf(stderr, "Unable to load certificates at %s to store\n", store_path);
        X509_STORE_free(s);
        return -1;
    }

    /* Setup the connection */
    bio = BIO_new_ssl_connect(ctx);

    /* Set the SSL_MODE_AUTO_RETRY flag */

    BIO_get_ssl(bio, & ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    /* Create and setup the connection */

    BIO_set_conn_hostname(bio, "www.google.com:https");

    if(BIO_do_connect(bio) <= 0)
    {
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }

    /*
     * Check Client_CA_list send from the server, if any
     */

    STACK_OF(X509_NAME) *ca_list = SSL_CTX_get_client_CA_list(ctx);
    if (sk_X509_NAME_num(ca_list) > 0) {
        for (int i = 0; i < sk_X509_NAME_num(ca_list); i++) {
            printf("%d: %s\n", i, X509_NAME_oneline(sk_X509_NAME_value(ca_list, i), NULL, 0));
        }
    }
    else {
        fprintf(stderr, "No CA sent from the server!\n");
    }

    /* Check the certificate */
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL)
    {
        fprintf(stderr, "Certs return NULL\n"); 
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // print out certs
    // PEM_write_X509(stdout, cert);

    STACK_OF(X509) *sk = SSL_get_peer_cert_chain(ssl);

    char subject[MAX_LENGTH+1];
    char issuer[MAX_LENGTH+1];


    STACK_OF(X509) *r_sk = sk_X509_new_null();
    sk_X509_push(r_sk, sk_X509_value(sk, 0));
    
    for (int i=1; i < sk_X509_num(sk); i++) {
        X509 *prev = sk_X509_value(r_sk, i-1);
        X509 *next = NULL;
        for (int j=1; j < sk_X509_num(sk); j++) {
            X509 *cand = sk_X509_value(sk, j);
            if (!X509_NAME_cmp(cand->cert_info->subject, prev->cert_info->issuer)
                    || j == sk_X509_num(sk) - 1) {
                next = cand;
                break;
            }
        }
        if (next) {
            sk_X509_push(r_sk, next);
        } else {
            // we're unable to figure out the correct stack so just use the original one provided.
            sk_X509_free(r_sk);
            r_sk = sk_X509_dup(sk);
            break;
        }
    }

    if (sk != NULL) {
        for (int i = 0; i < sk_X509_num(sk); i++) {
            X509_NAME_oneline(X509_get_subject_name(sk_X509_value(sk, i)), subject, MAX_LENGTH);
            printf("Subject: %s\n", subject);
            X509_NAME_oneline(X509_get_issuer_name(sk_X509_value(sk, i)), issuer, MAX_LENGTH);
            printf("Issuer: %s\n", issuer);
        }
    }

    int vcode = verify_cert_chain(s, cert, sk);
    fprintf(stderr, "Verification Error: %d (%s)\n", vcode, get_validation_errstr(vcode));

    if(SSL_get_verify_result(ssl) != X509_V_OK)
    {
        fprintf(stderr, "Verification Error: %ld\n", SSL_get_verify_result(ssl));
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 0;
    }

    /* Send the request */

    BIO_write(bio, request, strlen(request));

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
