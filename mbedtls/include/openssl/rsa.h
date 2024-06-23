#ifndef OPENSSL_RSA_H
#define OPENSSL_RSA_H

#include <mbedtls/rsa.h>

#include "bn.h"
#include "evp.h"

typedef mbedtls_rsa_context RSA;

enum RSA_PADDING {
    RSA_PKCS1_OAEP_PADDING = 1,
    RSA_NO_PADDING         = 2
};

enum NID {
    NID_sha1
};

extern int RSA_size(const RSA *rsa);

extern RSA *RSA_new(void);
extern void RSA_free(RSA *rsa);

extern int RSA_public_encrypt(
        int flen,
        const unsigned char *from,
        unsigned char *to,
        RSA *rsa,
        int padding);

extern int RSA_public_decrypt(
        int flen,
        unsigned char *from,
        unsigned char *to,
        RSA *rsa,
        int padding);

extern int RSA_verify(
        int type,
        const unsigned char *m,
        unsigned int m_len,
        unsigned char *sigbuf,
        unsigned int siglen,
        RSA *rsa);

extern int RSA_padding_add_PKCS1_type_1(
        unsigned char *to, int tlen,
        const unsigned char *f, int fl);

extern int RSA_padding_add_PKCS1_type_2(
        unsigned char *to, int tlen,
        const unsigned char *f, int fl);

extern int RSA_padding_add_PKCS1_OAEP(
        unsigned char *to, int tlen,
        const unsigned char *f, int fl,
        const unsigned char *p, int pl);

extern int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);

extern int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key);

extern int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad);

extern int EVP_PKEY_CTX_set0_rsa_oaep_label(
        EVP_PKEY_CTX *ctx,
        void *label,
        int len);

#endif /* OPENSSL_RSA_H */
