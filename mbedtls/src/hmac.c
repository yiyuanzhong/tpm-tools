#include <openssl/hmac.h>

#include <stdlib.h>

#include <openssl/err.h>

HMAC_CTX *HMAC_CTX_new(void)
{
    mbedtls_md_context_t *ctx;

    ctx = (mbedtls_md_context_t *)malloc(sizeof(*ctx));
    if (!ctx) { /* MD - Failed to allocate memory */
        mbedtls_error(0x5180);
        return NULL;
    }

    mbedtls_md_init(ctx);
    return ctx;
}

int HMAC_Init_ex(
        HMAC_CTX *ctx,
        const void *key,
        int key_len,
        const EVP_MD *md,
        ENGINE *impl)
{
    if (key_len < 0 || impl) { /* MD - Bad input parameters to function */
        mbedtls_error(0x5100);
        return 0;
    }

    if (mbedtls_error(mbedtls_md_setup(ctx, md, 1))) {
        return 0;
    }

    if (mbedtls_error(mbedtls_md_hmac_starts(ctx, key, (size_t)key_len))) {
        return 0;
    }

    return 1;
}

int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len)
{
    if (mbedtls_error(mbedtls_md_hmac_update(ctx, data, len))) {
        return 0;
    }

    return 1;
}

int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len)
{
    if (mbedtls_error(mbedtls_md_hmac_finish(ctx, md))) {
        return 0;
    }

    if (len) {
        *len = mbedtls_md_get_size(ctx->private_md_info);
    }

    return 1;
}

void HMAC_CTX_free(HMAC_CTX *ctx)
{
    mbedtls_md_free(ctx);
    free(ctx);
}
