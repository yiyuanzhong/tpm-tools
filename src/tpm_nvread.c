#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <getopt.h>

#include <tpmfunc.h>
#include <tpm_error.h>

static int help(const char *argv0)
{
    fprintf(stderr, "%s <-i index> [-s bytes] [-n offset] "
                    "[-f filename] [-z]\n", argv0);
    return EXIT_FAILURE;
}

static long tpm_get_nv_size(uint32_t index)
{
    STACK_TPM_BUFFER(response);
    STACK_TPM_BUFFER(subcap);
    TPM_NV_DATA_PUBLIC ndp;
    uint32_t ret;

    *(uint32_t *)subcap.buffer = htonl(index);
    subcap.used = sizeof(uint32_t);

    ret = TPM_GetCapability(TPM_CAP_NV_INDEX, &subcap, &response);
    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return -1;
    }

    ret = TPM_ReadNVDataPublic(&response, 0, &ndp);
    if ((ret & ERR_MASK)) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return -1;
    }

    return (long)ndp.dataSize;
}

int tpm_nvread(int argc, char *argv[])
{
    unsigned char ownerhash[TPM_HASH_SIZE];
    uint32_t buflen;
    uint32_t ret;
    void *buffer;
    int c;

    char *end;
    long size = -1;
    long offset = 0;
    int has_index = 0;
    int ownerpass = 0;
    char *filename = NULL;
    unsigned long index = 0;
    while ((c = getopt(argc, argv, "i:s:n:f:o:z")) != -1) {
        switch (c) {
        case 'i':
            errno = 0;
            has_index = 1;
            index = strtoul(optarg, &end, 0);
            if (index > UINT32_MAX || *end || errno) {
                return help(argv[0]);
            }
            break;
        case 's':
            errno = 0;
            size = strtol(optarg, &end, 0);
            if (size < 0 || size > INT32_MAX || *end || errno) {
                return help(argv[0]);
            }
            break;
        case 'n':
            errno = 0;
            offset = strtol(optarg, &end, 0);
            if (offset < 0 || offset > INT32_MAX || *end || errno) {
                return help(argv[0]);
            }
            break;
        case 'f':
            filename = optarg;
            break;
        case 'o':
            TSS_sha1(optarg, strlen(optarg), ownerhash);
            ownerpass = 1;
            break;
        case 'z':
            memset(ownerhash, 0, sizeof(ownerhash));
            ownerpass = 1;
            break;
        default:
            return help(argv[0]);
        }
    }

    if (optind != argc) {
        return help(argv[0]);
    } else if (!has_index) {
        return help(argv[0]);
    }

    TPM_setlog(0);

    if (size < 0) {
        size = tpm_get_nv_size((uint32_t)index);
        if (size < 0) {
            return EXIT_FAILURE;
        }
    }

    if (size > 0 && !filename) {
        fprintf(stderr, "not implemented\n");
        return EXIT_FAILURE;
    }

    buflen = (uint32_t)size > sizeof(void *) ? (uint32_t)size : sizeof(void *);
    buffer = malloc(buflen);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate memory\n");
        return EXIT_FAILURE;
    }

    ret = TPM_NV_ReadValue(
            (uint32_t)index,
            (uint32_t)offset,
            (uint32_t)size,
            (unsigned char *)buffer, &buflen,
            ownerpass ? ownerhash : NULL);

    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        free(buffer);
        return EXIT_FAILURE;
    }

    if (filename) {
        ret = TPM_WriteFile(filename, buffer, buflen);
        if (ret != TPM_SUCCESS) {
            fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
            free(buffer);
            return EXIT_FAILURE;
        }
    }

    free(buffer);
    return EXIT_SUCCESS;
}
