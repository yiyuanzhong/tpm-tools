#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>

#include <tpmfunc.h>
#include <tpm_error.h>

static int help(const char *argv0)
{
    fprintf(stderr, "%s [-y (owner well known)] "
                       "[-z (srk well known)]\n", argv0);
    return EXIT_FAILURE;
}

int tpm_takeownership(int argc, char *argv[])
{
    unsigned char ownerhash[TPM_HASH_SIZE];
    unsigned char srkhash[TPM_HASH_SIZE];
    uint32_t ret;
    keydata srk;
    int c;

    int srkpass = 0;
    int ownerpass = 0;
    while ((c = getopt(argc, argv, "yz")) != -1) {
        switch (c) {
        case 'y':
            memset(ownerhash, 0, sizeof(ownerhash));
            ownerpass = 1;
            break;
        case 'z':
            memset(srkhash, 0, sizeof(srkhash));
            srkpass = 1;
            break;
        default:
            return help(argv[0]);
        }
    }

    if (optind != argc) {
        return help(argv[0]);
    }

    if (!ownerpass) {
        fprintf(stderr, "not implemented\n");
        return EXIT_FAILURE;
    }

    TPM_setlog(0);

    ret = TPM_TakeOwnership12(ownerhash, srkpass ? srkhash : NULL, &srk);
    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
