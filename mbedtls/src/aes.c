#include <openssl/aes.h>

#include <stdlib.h>

#include <openssl/err.h>

int AES_set_encrypt_key(
        const unsigned char *userKey,
        const int bits,
        AES_KEY *key)
{
    mbedtls_aes_init(key);
    if (mbedtls_error(mbedtls_aes_setkey_enc(key, userKey, bits))) {
        return 0;
    }

    return 1;
}

void AES_encrypt(
        const unsigned char *in,
        unsigned char *out,
        AES_KEY *key)
{
    if (mbedtls_aes_crypt_ecb(key, MBEDTLS_AES_ENCRYPT, in, out)) {
        abort(); /* I don't have a way to report error */
    }
}

void AES_ofb128_encrypt(
        const unsigned char *in,
        unsigned char *out,
        size_t length,
        AES_KEY *key,
        unsigned char *ivec,
        int *num)
{
    size_t iv_off;

    if (!num) {
        abort(); /* I don't have a way to report error */
    }

    iv_off = *num;
    if (mbedtls_aes_crypt_ofb(key, length, &iv_off, ivec, in, out)) {
        abort(); /* I don't have a way to report error */
    }

    *num = (int)iv_off;
}
