#include <stdio.h>
#include <stdlib.h>

#include <tpmfunc.h>
#include <tpm_error.h>

static void hexdump(const void *buffer, size_t length)
{
    const unsigned char *p = (const unsigned char *)buffer;
    size_t i;

    for (i = 0; i < length; ++i) {
        if ((i % 32) == 0) {
            if (length > 32) {
                printf("\n");
            } else if ((i % 4) == 0) {
                printf(" ");
            }
        }
        printf("%02X", p[i]);
    }

    printf("\n");
}

int tpm_version(int argc, char *argv[])
{
    TPM_CAP_VERSION_INFO version;
    STACK_TPM_BUFFER(response);
    uint32_t ret;

    (void)argc;
    (void)argv;

    TPM_setlog(0);

    ret = TPM_GetCapability(TPM_CAP_VERSION_VAL, NULL, &response);
    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return EXIT_FAILURE;
    }

    ret = TPM_ReadCapVersionInfo(&response, 0, &version);
    if ((ret & ERR_MASK)) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return EXIT_FAILURE;
    }

    printf("  TPM 1.2 Version Info:\n");
    printf("  Chip Version:        %u.%u.%u.%u\n",
            version.version.major,
            version.version.minor,
            version.version.revMajor,
            version.version.revMinor);

    printf("  Spec Level:          %u\n", version.specLevel);
    printf("  Errata Revision:     %u\n", version.errataRev);
    printf("  TPM Vendor ID:       %c%c%c%c\n",
            version.tpmVendorID[0],
            version.tpmVendorID[1],
            version.tpmVendorID[2],
            version.tpmVendorID[3]);

    if (version.vendorSpecificSize) {
        printf("  Vendor Specific Data: ");
        hexdump(version.vendorSpecific, version.vendorSpecificSize);
    }

    return EXIT_SUCCESS;
}
