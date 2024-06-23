#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>

#include <tpmfunc.h>
#include <tpm_error.h>

static int help(const char *argv0)
{
    fprintf(stderr, "%s <-s|-o [-z]|-f>\n", argv0);
    return EXIT_FAILURE;
}

int tpm_setclearable(int argc, char *argv[])
{
    unsigned char ownerhash[TPM_HASH_SIZE];
    uint32_t ret;
    int c;

    int ownerpass = 0;
    int forceclear = 0;
    int ownerclear = 0;
    while ((c = getopt(argc, argv, "sfoz")) != -1) {
        switch (c) {
        case 'f':
            forceclear = 1;
            ownerclear = 0;
            break;
        case 'o':
            forceclear = 0;
            ownerclear = 1;
            break;
        case 's':
            forceclear = 0;
            ownerclear = 0;
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

    if (ownerclear) {
        if (!ownerpass) {
            fprintf(stderr, "not implemented\n");
            return EXIT_FAILURE;
        }

        ret = TPM_DisableOwnerClear(ownerhash);

    } else if (forceclear) {
        ret = TPM_DisableForceClear();

    } else {
        fprintf(stderr, "not implemented\n");
        return EXIT_FAILURE;
    }

    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
