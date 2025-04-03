#include <openssl/rsa.h>

#include <stdlib.h>
#include <string.h>

#include <mbedtls/rsa.h>
#include <mbedtls/version.h>

#include <openssl/err.h>

int RSA_size(const RSA *rsa)
{
    return (int)mbedtls_rsa_get_len(rsa);
}

RSA *RSA_new(void)
{
    mbedtls_rsa_context *rsa;

    rsa = (mbedtls_rsa_context *)malloc(sizeof(*rsa));
    if (!rsa) { /* MD - Failed to allocate memory */
        mbedtls_error(0x5180);
        return NULL;
    }

#if MBEDTLS_VERSION_MAJOR >= 3
    mbedtls_rsa_init(rsa);
#else
    mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
#endif

    return rsa;
}

void RSA_free(RSA *rsa)
{
    mbedtls_rsa_free(rsa);
    free(rsa);
}

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    if (mbedtls_error(mbedtls_rsa_import(r, n, NULL, NULL, d, e))) {
        return 0;
    }

    if (mbedtls_error(mbedtls_rsa_complete(r))) {
        return 0;
    }

    return 1;
}

static int rsa_public_raw(
        int flen,
        const unsigned char *from,
        unsigned char *to,
        RSA *rsa)
{
    size_t len;
    len = mbedtls_rsa_get_len(rsa);
    if ((int)len != flen) { /* RSA - Bad input parameters to function */
        mbedtls_error(0x4080);
        return 0;
    }

    if (mbedtls_error(mbedtls_rsa_public(rsa, from, to))) {
        return 0;
    }

    return 1;
}

int RSA_public_encrypt(
        int flen,
        const unsigned char *from,
        unsigned char *to,
        RSA *rsa,
        int padding)
{
    switch (padding) {
    case RSA_NO_PADDING:
        return rsa_public_raw(flen, from, to, rsa);
    default: /* RSA - Input data contains invalid padding and is rejected */
        mbedtls_error(0x4100);
        return 0;
    }
}
