#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>

#include <mbedtls/md.h>
#include <mbedtls/version.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#if MBEDTLS_VERSION_MAJOR < 3
static const mbedtls_md_info_t *mbedtls_md_info_from_ctx(
        const mbedtls_md_context_t *ctx)
{
    return ctx->md_info;
}

static int mbedtls_rsa_get_padding_mode(const mbedtls_rsa_context *ctx)
{
    return ctx->padding;
}
#endif

struct evp_pkey_ctx_st {
    mbedtls_rsa_context *rsa;
    size_t oaep_label_length;
    void *oaep_label;
};

const EVP_MD *EVP_sha1()
{
    return mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
}

EVP_MD_CTX *EVP_MD_CTX_new(void)
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

int EVP_DigestInit_ex(
        EVP_MD_CTX *ctx,
        const EVP_MD *type,
        ENGINE *impl)
{
    if (impl) { /* MD - Bad input parameters to function */
        mbedtls_error(0x5100);
        return 0;
    }

    if (mbedtls_error(mbedtls_md_setup(ctx, type, 0))) {
        return 0;
    }

    if (mbedtls_error(mbedtls_md_starts(ctx))) {
        return 0;
    }

    return 1;
}

int EVP_DigestUpdate(
        EVP_MD_CTX *ctx,
        const void *d,
        size_t cnt)
{
    if (mbedtls_error(mbedtls_md_update(ctx, d, cnt))) {
        return 0;
    }

    return 1;
}

int EVP_DigestFinal_ex(
        EVP_MD_CTX *ctx,
        unsigned char *md,
        unsigned int *s)
{
    if (mbedtls_error(mbedtls_md_finish(ctx, md))) {
        return 0;
    }

    if (s) {
        *s = mbedtls_md_get_size(mbedtls_md_info_from_ctx(ctx));
    }

    return 1;
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    mbedtls_md_free(ctx);
    free(ctx);
}

EVP_PKEY *EVP_PKEY_new(void)
{
    EVP_PKEY *pkey;

    pkey = (EVP_PKEY *)malloc(sizeof(*pkey));
    if (!pkey) { /* MD - Failed to allocate memory */
        mbedtls_error(0x5180);
        return NULL;
    }

    mbedtls_pk_init(pkey);
    return pkey;
}

void EVP_PKEY_free(EVP_PKEY *key)
{
    mbedtls_pk_free(key);
    free(key);
}

int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx)
{
    if (!ctx) { /* RSA - Bad input parameters to function */
        mbedtls_error(0x4080);
        return 0;
    }

    return 1;
}

static int mbedtls_rand(void *param, unsigned char *out, size_t len)
{
    (void)param;

    if (RAND_bytes(out, len) != 1) {
        return 0;
    }

    return 0;
}

int EVP_PKEY_encrypt(
        EVP_PKEY_CTX *ctx,
        unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen)
{
    if (!ctx || !ctx->rsa || !out || !outlen || !in || !inlen) {
        /* RSA - Bad input parameters to function */
        mbedtls_error(0x4080);
        return 0;
    }

    if (*outlen < mbedtls_rsa_get_len(ctx->rsa)) {
        /* RSA - Bad input parameters to function */
        mbedtls_error(0x4080);
        return 0;
    }

    switch (mbedtls_rsa_get_padding_mode(ctx->rsa)) {
    case MBEDTLS_RSA_PKCS_V21:
        if (!ctx->oaep_label) {
            /* RSA - Bad input parameters to function */
            mbedtls_error(0x4080);
            return 0;
        }

        if (mbedtls_error(mbedtls_rsa_rsaes_oaep_encrypt(
                ctx->rsa, mbedtls_rand, NULL,
#if MBEDTLS_VERSION_MAJOR < 3
                MBEDTLS_RSA_PUBLIC,
#endif
                ctx->oaep_label, ctx->oaep_label_length,
                inlen, in, out))) {

            return 0;
        }
        break;

    default:
        /* RSA - Input data contains invalid padding and is rejected */
        mbedtls_error(0x4100);
        return 0;
    }

    return 1;
}

EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_pkey(
        OSSL_LIB_CTX *libctx,
        EVP_PKEY *pkey,
        const char *propquery)
{
    EVP_PKEY_CTX *ctx;

    if (libctx || !pkey || propquery                ||
        mbedtls_pk_get_type(pkey) != MBEDTLS_PK_RSA ){

        /* RSA - Bad input parameters to function */
        mbedtls_error(0x4080);
        return NULL;
    }

    ctx = (EVP_PKEY_CTX *)malloc(sizeof(*ctx));
    if (!ctx) { /* MD - Failed to allocate memory */
        mbedtls_error(0x5180);
        return NULL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->rsa = mbedtls_pk_rsa(*pkey);
    if (!ctx->rsa) { /* MD - Failed to allocate memory */
        mbedtls_error(0x5180);
        free(ctx);
        return NULL;
    }

    return ctx;
}

void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx)
{
    free(ctx->oaep_label);
    free(ctx);
}

int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key)
{
    mbedtls_rsa_context *rsa;

    if (!pkey || !key) { /* MD - Bad input parameters to function */
        mbedtls_error(0x5100);
        return 0;
    }

    if (mbedtls_error(mbedtls_pk_setup(
            pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)))) {

        return 0;
    }

    rsa = mbedtls_pk_rsa(*pkey);
    if (!rsa) { /* MD - Failed to allocate memory */
        mbedtls_error(0x5100);
        return 0;
    }

    if (mbedtls_error(mbedtls_rsa_copy(rsa, key))) {
        return 0;
    }

    return 1;
}

int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad)
{
    int padding;
    int hash;

    if (!ctx || !ctx->rsa) { /* MD - Bad input parameters to function */
        mbedtls_error(0x5100);
        return 0;
    }

    switch (pad) {
    case RSA_PKCS1_OAEP_PADDING:
        padding = MBEDTLS_RSA_PKCS_V21;
        hash = MBEDTLS_MD_SHA1;
        break;
    case RSA_NO_PADDING:
        padding = MBEDTLS_RSA_PKCS_V15;
        hash = MBEDTLS_MD_NONE;
        break;
    default: /* RSA - Input data contains invalid padding and is rejected */
        mbedtls_error(0x4100);
        return 0;
    }

#if MBEDTLS_VERSION_MAJOR < 3
    mbedtls_rsa_set_padding(ctx->rsa, padding, hash);
#else
    if (mbedtls_error(mbedtls_rsa_set_padding(ctx->rsa, padding, hash))) {
        return 0;
    }
#endif

    return 1;
}

int EVP_PKEY_CTX_set0_rsa_oaep_label(
        EVP_PKEY_CTX *ctx,
        void *label,
        int len)
{
    if (!ctx || !ctx->rsa || !label || len < 0) {
        /* MD - Bad input parameters to function */
        mbedtls_error(0x5100);
        return 0;
    }

    if (mbedtls_rsa_get_padding_mode(ctx->rsa) != MBEDTLS_RSA_PKCS_V21) {
        /* RSA - Input data contains invalid padding and is rejected */
        mbedtls_error(0x4100);
        return 0;
    }

    free(ctx->oaep_label);
    ctx->oaep_label = NULL;
    ctx->oaep_label_length = 0;

    if (len) {
        ctx->oaep_label = malloc((size_t)len);
        if (!ctx->oaep_label) { /* MD - Failed to allocate memory */
            mbedtls_error(0x5100);
            return 0;
        }

        memcpy(ctx->oaep_label, label, (size_t)len);
        ctx->oaep_label_length = (size_t)len;
    }

    return 1;
}
