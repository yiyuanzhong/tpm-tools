#ifndef OPENSSL_PEM_H
#define OPENSSL_PEM_H

#include <stdlib.h>

#include <openssl/evp.h>

extern int PEM_write_PUBKEY(FILE *fp, EVP_PKEY *pkey);

#endif /* OPENSSL_PEM_H */
