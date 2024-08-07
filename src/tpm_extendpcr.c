#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <getopt.h>

#include <openssl/sha.h>

#include <tpmfunc.h>
#include <tpm_error.h>

static int help(const char *argv0)
{
    fprintf(stderr, "%s <-p index> <-i filename>\n", argv0);
    return EXIT_FAILURE;
}

static int hash_file(const char *filename, unsigned char *hash)
{
    unsigned char buffer[8192];
    SHA_CTX ctx;
    size_t ret;
    FILE *fp;

    fp = fopen(filename, "rb");
    if (!fp) {
        return -1;
    }

    SHA1_Init(&ctx);
    for (;;) {
        ret = fread(buffer, 1, sizeof(buffer), fp);
        if (ret == 0) {
            if (ferror(fp)) {
                fclose(fp);
                return -1;
            } else {
                break;
            }
        }

        SHA1_Update(&ctx, buffer, ret);
    }

    SHA1_Final(hash, &ctx);
    fclose(fp);
    return 0;
}

int tpm_extendpcr(int argc, char *argv[])
{
    unsigned char hash[TPM_HASH_SIZE];
    uint32_t ret;
    int c;

    char *end;
    int has_index = 0;
    char *filename = NULL;
    unsigned long index = 0;
    while ((c = getopt(argc, argv, "p:i:")) != -1) {
        switch (c) {
        case 'p':
            errno = 0;
            has_index = 1;
            index = strtoul(optarg, &end, 0);
            if (index > UINT32_MAX || *end || errno) {
                return help(argv[0]);
            }
            break;
        case 'i':
            filename = optarg;
            break;
        default:
            return help(argv[0]);
        }
    }

    if (optind != argc) {
        return help(argv[0]);
    } else if (!has_index || !filename) {
        return help(argv[0]);
    }

    TPM_setlog(0);

    if (hash_file(filename, hash)) {
        fprintf(stderr, "Failed: %d: %s\n", errno, strerror(errno));
        return EXIT_FAILURE;
    }

    ret = TPM_Extend((uint32_t)index, hash, NULL);
    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
