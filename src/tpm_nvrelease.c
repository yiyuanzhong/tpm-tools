#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>

#include <pcrs.h>
#include <tpmfunc.h>
#include <tpm_error.h>

static int help(const char *argv0)
{
    fprintf(stderr, "%s <-i index> [-o ownerpass] [-y]\n", argv0);
    return EXIT_FAILURE;
}

int tpm_nvrelease(int argc, char *argv[])
{
    unsigned char ownerhash[TPM_HASH_SIZE];
    uint32_t ret;
    int c;

    char *end;
    long index = -1;
    int ownerpass = 0;
    while ((c = getopt(argc, argv, "i:o:y")) != -1) {
        switch (c) {
        case 'i':
            index = strtol(optarg, &end, 0);
            if (index < 0 || index > UINT32_MAX || *end) {
                return help(argv[0]);
            }
            break;
        case 'o':
            TSS_sha1(optarg, strlen(optarg), ownerhash);
            ownerpass = 1;
            break;
        case 'y':
            memset(ownerhash, 0, sizeof(ownerhash));
            ownerpass = 1;
            break;
        default:
            return help(argv[0]);
        }
    }

    if (optind != argc) {
        return help(argv[0]);
    } else if (index < 0) {
        return help(argv[0]);
    }

    if (!ownerpass) {
        fprintf(stderr, "not implemented\n");
        return EXIT_FAILURE;
    }

    TPM_setlog(0);

    ret = TPM_NV_DefineSpace2(
            ownerhash,
            (uint32_t)index,
            0,
            0,
            NULL, NULL, NULL);

    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
