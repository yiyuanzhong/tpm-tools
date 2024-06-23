#ifndef OPENSSL_HMAC_H
#define OPENSSL_HMAC_H

#include <stdarg.h>

#include <mbedtls/md.h>

#include "engine.h"
#include "evp.h"

typedef mbedtls_md_context_t HMAC_CTX;

extern HMAC_CTX *HMAC_CTX_new(void);

extern int HMAC_Init_ex(
        HMAC_CTX *ctx,
        const void *key,
        int key_len,
        const EVP_MD *md,
        ENGINE *impl);

extern int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len);

extern int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);

extern void HMAC_CTX_free(HMAC_CTX *ctx);

#endif /* OPENSSL_HMAC_H */
