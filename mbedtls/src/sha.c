#include <openssl/sha.h>

#include <openssl/err.h>

int SHA1_Init(SHA_CTX *c)
{
    mbedtls_sha1_init(c);
    if (mbedtls_error(mbedtls_sha1_starts(c))) {
        return 0;
    }

    return 1;
}

int SHA1_Update(SHA_CTX *c, const void *data, size_t len)
{
    if (mbedtls_error(mbedtls_sha1_update(c, data, len))) {
        return 0;
    }

    return 1;
}

int SHA1_Final(unsigned char *md, SHA_CTX *c)
{
    int ret;

    ret = mbedtls_error(mbedtls_sha1_finish(c, md));
    mbedtls_sha1_free(c);
    return ret ? 0 : 1;
}
