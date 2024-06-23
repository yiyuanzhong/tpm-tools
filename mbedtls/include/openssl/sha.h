#ifndef OPENSSL_SHA_H
#define OPENSSL_SHA_H

#include <mbedtls/sha1.h>

typedef mbedtls_sha1_context SHA_CTX;

extern int SHA1_Init(SHA_CTX *c);
extern int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
extern int SHA1_Final(unsigned char *md, SHA_CTX *c);

#endif /* OPENSSL_SHA_H */
