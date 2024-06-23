#ifndef OPENSSL_AES_H
#define OPENSSL_AES_H

#include <mbedtls/aes.h>

typedef mbedtls_aes_context AES_KEY;

extern int AES_set_encrypt_key(
        const unsigned char *userKey,
        const int bits,
        AES_KEY *key);

extern void AES_encrypt(
        const unsigned char *in,
        unsigned char *out,
        /*const*/ AES_KEY *key); /* API incompatibility */

extern void AES_ofb128_encrypt(
        const unsigned char *in,
        unsigned char *out,
        size_t length,
        /*const*/ AES_KEY *key, /* API incompatibility */
        unsigned char *ivec,
        int *num);

#endif /* OPENSSL_AES_H */
