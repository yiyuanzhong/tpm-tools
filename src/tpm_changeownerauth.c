#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>

#include <tpmfunc.h>
#include <tpm_error.h>

static int help(const char *argv0)
{
    fprintf(stderr, "%s <-o|-s> [-z] [-r] [-f oldpass] [-t newpass]\n", argv0);
    return EXIT_FAILURE;
}

int tpm_changeownerauth(int argc, char *argv[])
{
    unsigned char oldhash[TPM_HASH_SIZE];
    unsigned char newhash[TPM_HASH_SIZE];
    uint32_t ret;
    int c;

    int oldpass = 0;
    int newpass = 0;
    int changesrk = 0;
    int changeowner = 0;
    while ((c = getopt(argc, argv, "oszrf:t:")) != -1) {
        switch (c) {
        case 'o':
            changeowner = 1;
            changesrk = 0;
            break;
        case 's':
            changeowner = 0;
            changesrk = 1;
            break;
        case 'z':
            memset(oldhash, 0, sizeof(oldhash));
            oldpass = 1;
            break;
        case 'r':
            memset(newhash, 0, sizeof(newhash));
            newpass = 1;
            break;
        case 'f':
            TSS_sha1(optarg, strlen(optarg), oldhash);
            oldpass = 1;
            break;
        case 't':
            TSS_sha1(optarg, strlen(optarg), newhash);
            newpass = 1;
            break;
        default:
            return help(argv[0]);
        }
    }

    if (optind != argc) {
        return help(argv[0]);
    } else if (!changeowner && !changesrk) {
        return help(argv[0]);
    }

    if (!oldpass || !newpass) {
        fprintf(stderr, "not implemented\n");
        return EXIT_FAILURE;
    }

    TPM_setlog(0);

    if (changeowner) {
        ret = TPM_ChangeOwnAuth(oldhash, newhash);
    } else {
        ret = TPM_ChangeSRKAuth(oldhash, newhash);
    }

    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
