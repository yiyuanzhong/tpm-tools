#include <openssl/err.h>

#include <mbedtls/error.h>

/* Single thread support only */
static int g_mbedtls_error = 0;

unsigned long ERR_get_error(void)
{
    unsigned long e = (unsigned long)g_mbedtls_error;
    g_mbedtls_error = 0;
    return e;
}

char *ERR_error_string(unsigned long e, char *buf)
{
    static char buffer[256];

    if (!buf) {
        buf = buffer;
    }

    mbedtls_strerror((int)e, buf, 256);
    return buf;
}

int mbedtls_error(int e)
{
    if (!g_mbedtls_error) {
        g_mbedtls_error = e;
    }

    return e;
}
