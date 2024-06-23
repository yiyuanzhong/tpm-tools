#ifndef OPENSSL_BN_H
#define OPENSSL_BN_H

#include <mbedtls/bignum.h>

typedef mbedtls_mpi BIGNUM;

extern BIGNUM *BN_new(void);

extern BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);

extern void BN_free(BIGNUM *a);

#endif /* OPENSSL_BN_H */
