#include <openssl/pem.h>

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

#include <openssl/err.h>

int PEM_write_PUBKEY(FILE *fp, EVP_PKEY *pkey)
{
    unsigned char buf[8192];

    if (!fp || !pkey) {
        mbedtls_error(0x4080); /* RSA - Bad input parameters to function */
        return 0;
    }

    if (mbedtls_error(mbedtls_pk_write_pubkey_pem(pkey, buf, sizeof(buf)))) {
        return 0;
    }

    if (fputs((char *)buf, fp) == EOF) { /* PK - Read/write of file failed */
        mbedtls_error(0x3E00);
        return 0;
    }

    return 1;
}
