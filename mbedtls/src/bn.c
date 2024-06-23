#include <openssl/bn.h>

#include <stdlib.h>

#include <openssl/err.h>

BIGNUM *BN_new(void)
{
    mbedtls_mpi *n;

    n = (mbedtls_mpi *)malloc(sizeof(*n));
    if (!n) { /* BIGNUM - Memory allocation failed */
        mbedtls_error(0x0010);
        return NULL;
    }

    mbedtls_mpi_init(n);
    return n;
}

BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    mbedtls_mpi *obj;

    if (!s || len < 0) { /* BIGNUM - Bad input parameters to function */
        mbedtls_error(0x0004);
        return NULL;
    }

    obj = NULL;
    if (!ret) {
        if (!(ret = obj = BN_new())) {
            return NULL;
        }
    }

    if (mbedtls_error(mbedtls_mpi_read_binary(ret, s, (size_t)len))) {
        if (obj) {
            BN_free(obj);
        }
        return NULL;
    }

    return ret;
}

void BN_free(BIGNUM *a)
{
    mbedtls_mpi_free(a);
}
