#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <getopt.h>

#include <tpmfunc.h>
#include <tpm_error.h>

static int help(const char *argv0)
{
    fprintf(stderr, "%s [-i index] [-n]\n", argv0);
    return EXIT_FAILURE;
}

static void tpm_nvinfo_pcr(const TPM_PCR_INFO_SHORT *index)
{
    uint32_t pcr;
    uint8_t bit;
    uint8_t i;
    uint8_t c;

    printf(":");

    c = 0;
    for (i = 0, pcr = 0; i < index->pcrSelection.sizeOfSelect; ++i) {
        for (bit = 1; bit; bit <<= 1, ++pcr) {
            if ((bit & index->pcrSelection.pcrSelect[i])) {
                if (c++) {
                    printf(",");
                }
                printf("%u", pcr);
            }
        }
    }

    printf(":");
    if (index->localityAtRelease == TPM_LOC_ALL) {
        printf("ALL");
    } else {
        printf("%u", index->localityAtRelease);
    }

    printf(":");
    if (c) {
        for (i = 0; i < sizeof(index->digestAtRelease); ++i) {
            printf("%02x", index->digestAtRelease[i]);
        }
    }
}

static int tpm_nvinfo_detail(uint32_t index)
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

    printf("0x%08x", ndp.nvIndex);
    tpm_nvinfo_pcr(&ndp.pcrInfoRead);
    tpm_nvinfo_pcr(&ndp.pcrInfoWrite);
    printf(":%08x", ndp.permission.attributes);
    printf(":%c", ndp.bReadSTClear + '0');
    printf(":%c", ndp.bWriteSTClear + '0');
    printf(":%c", ndp.bWriteDefine + '0');
    printf(":%u\n", ndp.dataSize);
    return 0;
}

int tpm_nvinfo(int argc, char *argv[])
{
    STACK_TPM_BUFFER(response);
    uint32_t *list;
    uint32_t ret;
    size_t count;
    size_t i;
    int c;

    char *end;
    int parsable = 0;
    int list_only = 0;
    int has_index = 0;
    unsigned long index = 0;
    while ((c = getopt(argc, argv, "i:np")) != -1) {
        switch (c) {
        case 'i':
            errno = 0;
            list_only = 0;
            has_index = 1;
            index = strtoul(optarg, &end, 0);
            if (index > UINT32_MAX || *end || errno) {
                return help(argv[0]);
            }
            break;
        case 'n':
            list_only = 1;
            break;
        case 'p':
            parsable = 1;
            break;
        default:
            return help(argv[0]);
        }
    }

    if (optind != argc) {
        return help(argv[0]);
    }

    if (!parsable) {
        fprintf(stderr, "not implemented\n");
        return EXIT_FAILURE;
    }

    TPM_setlog(0);

    if (has_index) {
        return tpm_nvinfo_detail((uint32_t)index) ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    ret = TPM_GetCapability(TPM_CAP_NV_LIST, NULL, &response);
    if (ret != TPM_SUCCESS || (response.used % sizeof(uint32_t))) {
        return EXIT_FAILURE;
    }

    list = (uint32_t *)response.buffer;
    count = response.used / sizeof(uint32_t);
    for (i = 0; i < count; ++i) {
        if (list_only) {
            printf("0x%08x (%u)\n", ntohl(list[i]), ntohl(list[i]));
        } else if (tpm_nvinfo_detail(ntohl(list[i]))) {
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
