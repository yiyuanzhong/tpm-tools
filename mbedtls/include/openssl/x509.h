#ifndef OPENSSL_X509_H
#define OPENSSL_X509_H

#include <mbedtls/x509_crt.h>

#include "evp.h"
#include "rsa.h"

typedef mbedtls_x509_crt X509;

extern RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
extern EVP_PKEY *X509_get_pubkey(X509 *x);
extern void X509_free(X509 *x509);
extern X509 *d2i_X509(X509 *x509, const unsigned char **buf, int len);

#endif /* OPENSSL_X509_H */
