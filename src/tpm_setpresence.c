#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>

#include <tpmfunc.h>
#include <tpm_error.h>

static int help(const char *argv0)
{
    fprintf(stderr, "%s <-a|-c> [--lock]\n", argv0);
    return EXIT_FAILURE;
}

int tpm_setpresence(int argc, char *argv[])
{
    static const struct option kOptions[] = {
        { "lock", no_argument, NULL, 'L' },
        { 0, 0, 0, 0 }
    };

    uint16_t presence;
    uint32_t ret;
    int c;

    int lock = 0;
    int action = -1;
    while ((c = getopt_long(argc, argv, "ac", kOptions, NULL)) != -1) {
        switch (c) {
        case 'a':
            action = 0;
            break;
        case 'c':
            action = 1;
            break;
        case 'L':
            lock = 1;
            break;
        default:
            return help(argv[0]);
        }
    }

    if (optind != argc) {
        return help(argv[0]);
    }

    switch (action) {
    case 1: presence = TPM_PHYSICAL_PRESENCE_NOTPRESENT; break;
    case 0: presence = TPM_PHYSICAL_PRESENCE_PRESENT; break;
	default: return help(argv[0]);
    }

    if (lock) {
        presence |= TPM_PHYSICAL_PRESENCE_LOCK;
    }

    TPM_setlog(0);

    ret = TSC_PhysicalPresence(presence);
    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
