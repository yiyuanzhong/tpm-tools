#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <getopt.h>

#include <tpmfunc.h>
#include <tpm_error.h>

static int help(const char *argv0)
{
    fprintf(stderr, "%s <-i index> [-s bytes] [-n offset] "
                    "[-f filename] [-d data] [-z]\n", argv0);
    return EXIT_FAILURE;
}

static unsigned char *read_file(const char *filename, uint32_t *filesize)
{
    unsigned char *file;
    unsigned char *old;
    size_t capacity;
    size_t size;
    size_t ret;
    FILE *fp;

    fp = fopen(filename, "rb");
    if (!fp) {
        return NULL;
    }

    size = 0;
    capacity = 256;
    file = (unsigned char *)malloc(capacity);
    if (!file) {
        fclose(fp);
        return NULL;
    }

    *filesize = 0;
    for (;;) {
        ret = fread(file + size, 1, capacity - size, fp);
        if (ret == 0) {
            if (ferror(fp)) {
                free(file);
                fclose(fp);
                return NULL;
            } else {
                break;
            }
        }

        size += ret;
        if (size == capacity) {
            old = file;
            capacity = capacity * 2;
            if (capacity > INT32_MAX) {
                free(file);
                fclose(fp);
                return NULL;
            }

            file = realloc(file, capacity);
            if (!file) {
                free(old);
                fclose(fp);
                return NULL;
            }
        }
    }

    fclose(fp);

    *filesize = (uint32_t)size;
    return file;
}

int tpm_nvwrite(int argc, char *argv[])
{
    unsigned char ownerhash[TPM_HASH_SIZE];
    unsigned char *buffer;
    unsigned char *file;
    uint32_t filesize;
    uint32_t buflen;
    uint32_t ret;
    int c;

    char *end;
    long size = -1;
    long offset = 0;
    char *data = NULL;
    int ownerpass = 0;
    int has_index = 0;
    char *filename = NULL;
    unsigned long index = 0;
    while ((c = getopt(argc, argv, "i:s:n:f:d:o:z")) != -1) {
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
        case 'd':
            data = optarg;
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

    if (size < 0) {
        if (!!data == !!filename) {
            return help(argv[0]);
        }
    } else if (size > 0) {
        if (data || !filename) {
            return help(argv[0]);
        }
    } else if (filename || data) {
        return help(argv[0]);
    }

    TPM_setlog(0);

    buflen = 0;
    file = NULL;
    buffer = NULL;
    if (filename) {
        if (!(file = read_file(filename, &filesize))) {
            fprintf(stderr, "Failed: %d: %s\n", errno, strerror(errno));
            return EXIT_FAILURE;
        }

        buffer = file;
        if (size < 0) {
            buflen = filesize;

        } else if (size > 0) {
            if ((uint32_t)size > filesize) {
                fprintf(stderr, "File has only %u bytes but requested %ld\n",
                        filesize, size);
                free(file);
                return EXIT_FAILURE;
            }

            buflen = (uint32_t)size;
        }

    } else if (data) {
        buffer = (unsigned char *)data;
        buflen = (uint32_t)strlen(data);
    }

    ret = TPM_NV_WriteValue(
            (uint32_t)index,
            (uint32_t)offset,
            (unsigned char *)buffer, buflen,
            ownerpass ? ownerhash : NULL);

    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        free(file);
        return EXIT_FAILURE;
    }

    free(file);

    return EXIT_SUCCESS;
}
