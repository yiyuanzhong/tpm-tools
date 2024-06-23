#ifndef OPENSSL_EVP_H
#define OPENSSL_EVP_H

#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

#include "engine.h"

typedef mbedtls_pk_context EVP_PKEY;

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

typedef mbedtls_md_context_t EVP_MD_CTX;
typedef mbedtls_md_info_t EVP_MD;
typedef void OSSL_LIB_CTX;

extern const EVP_MD *EVP_sha1();
extern EVP_MD_CTX *EVP_MD_CTX_new(void);
extern void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

extern int EVP_DigestInit_ex(
        EVP_MD_CTX *ctx,
        const EVP_MD *type,
        ENGINE *impl);

extern int EVP_DigestUpdate(
        EVP_MD_CTX *ctx,
        const void *d,
        size_t cnt);

extern int EVP_DigestFinal_ex(
        EVP_MD_CTX *ctx,
        unsigned char *md,
        unsigned int *s);

extern EVP_PKEY *EVP_PKEY_new(void);
extern void EVP_PKEY_free(EVP_PKEY *key);

extern int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);

extern int EVP_PKEY_encrypt(
        EVP_PKEY_CTX *ctx,
        unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen);

extern EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_pkey(
        OSSL_LIB_CTX *libctx,
        EVP_PKEY *pkey,
        const char *propquery);

extern void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);

#endif /* OPENSSL_EVP_H */
