#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>

#include <tpmfunc.h>
#include <tpm_error.h>

static int help(const char *argv0)
{
    fprintf(stderr, "%s [-f (force clear)] [-z]\n", argv0);
    return EXIT_FAILURE;
}

int tpm_clear(int argc, char *argv[])
{
    unsigned char ownerhash[TPM_HASH_SIZE];
    uint32_t ret;
    int c;

    int force = 0;
    int ownerpass = 0;
    while ((c = getopt(argc, argv, "fz")) != -1) {
        switch (c) {
        case 'f':
            force = 1;
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
    }

    TPM_setlog(0);

    if (force) {
        ret = TPM_ForceClear();

    } else {
        if (!ownerpass) {
            fprintf(stderr, "not implemented\n");
            return EXIT_FAILURE;
        }

        ret = TPM_OwnerClear12(ownerhash);
    }

    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
