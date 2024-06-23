#ifndef OPENSSL_ERR_H
#define OPENSSL_ERR_H

extern unsigned long ERR_get_error(void);
extern char *ERR_error_string(unsigned long e, char *buf);

extern int mbedtls_error(int e); /* Private */

#endif /* OPENSSL_ERR_H */
