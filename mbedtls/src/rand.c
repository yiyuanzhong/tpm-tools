#include <openssl/rand.h>

#include <fcntl.h>
#include <unistd.h>

#include <openssl/err.h>

int RAND_bytes(unsigned char *buf, int num)
{
    /* It's difficult to initialize mbedtls entropy so I just ask the kernel */
    ssize_t ret;
    int fd;

    if (!buf || num <= 0) { /* BIGNUM - Bad input parameters to function */
        mbedtls_error(0x0004);
    }

    fd = open("/dev/random", O_RDONLY);
    if (fd < 0) { /* ENTROPY - Read/write error in file */
        mbedtls_error(0x003F);
        return 0;
    }

    while (num) {
        ret = read(fd, buf, num);
        if (ret <= 0) { /* ENTROPY - Critical entropy source failure */
            mbedtls_error(0x003C);
            close(fd);
            return 0;
        }

        num -= (int)ret;
        buf += ret;
    }

    close(fd);
    return 1;
}
