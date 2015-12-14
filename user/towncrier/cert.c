/*
 *  Copyright (C) 2015, OpenSGX team, Georgia Tech & KAIST, All Rights Reserved
 *
 *  This file is part of OpenSGX (https://github.com/sslab-gatech/opensgx).
 *
 *  OpenSGX is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  OpenSGX is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSGX.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <fcntl.h>
#include <err.h>
#include <assert.h>

#include <sys/stat.h>

#include <sgx.h>
#include <sgx-user.h>
#include <sgx-kern.h>
#include <sgx-lib.h>

#define is_aligned(addr, bytes) \
    ((((uintptr_t)(const void *)(addr)) & (bytes - 1)) == 0)

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <errno.h>

 
void enclave_main()
{
    struct sockaddr_in sa;
    SSL*     ssl;
    X509*    server_cert;
 
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    SSL_CTX* ctx = SSL_CTX_new (SSLv23_method());

    char* filename = "output.pem";
 
    int sd = socket (AF_INET, SOCK_STREAM, 0);//create socket
    if (sd!=-1 && ctx!=NULL)
    {
        memset (&sa, '\0', sizeof(sa));
        sa.sin_family      = AF_INET;
        sa.sin_addr.s_addr = inet_addr ("216.58.219.206");   /* Server IP */
        sa.sin_port        = htons     (443);           /* Server Port number */
 
        
        if (connect(sd, (struct sockaddr*) &sa, sizeof(sa)) != -1)
        {
            ssl = SSL_new (ctx);
            if (ssl!=NULL)
            {
                SSL_set_fd(ssl, sd);
                int err = SSL_connect(ssl);
                if (err!=-1)
                {
                    server_cert = SSL_get_peer_certificate(ssl);
                    if (server_cert!=NULL)
                    {
                        BIO * bio_out = BIO_new_file(filename, "w");
                        if (bio_out)
                        {
                            X509_print(bio_out, server_cert); //parsed
                            PEM_write_bio_X509(bio_out, server_cert);
                            BIO_free(bio_out);
                            printf("Done writing to %s\n", filename);
                        }
                        X509_free (server_cert);
                    }
                    else {
                        printf("No cert found!\n");
                    }
                }
                SSL_free (ssl);
            }
            close(sd);//close socket
        }
        else {
            printf("Connection error %s\n", strerror(errno));
        }
    }
    else{
        printf("Can't open socket");
    }
    SSL_CTX_free (ctx);
    sgx_exit(NULL);
}
