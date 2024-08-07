#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <getopt.h>

#include <pcrs.h>
#include <tpmfunc.h>
#include <tpm_error.h>

static int help(const char *argv0)
{
    fprintf(stderr, "%s <-i index> <-p protection> <-s bytes> "
                    "[-r pcr] [-w pcr] [-y]\n", argv0);
    return EXIT_FAILURE;
}

static int parse_permission(char *input, uint32_t *permission)
{
    static const struct {
        const char *name;
        uint32_t permission;
    } kPermissions[] = {
        { "AUTHREAD",      TPM_NV_PER_AUTHREAD      },
        { "AUTHWRITE",     TPM_NV_PER_AUTHWRITE     },
        { "OWNERREAD",     TPM_NV_PER_OWNERREAD     },
        { "OWNERWRITE",    TPM_NV_PER_OWNERWRITE    },
        { "PPREAD",        TPM_NV_PER_PPREAD        },
        { "PPWRITE",       TPM_NV_PER_PPWRITE       },
        { "GLOBALLOCK",    TPM_NV_PER_GLOBALLOCK    },
        { "READ_STCLEAR",  TPM_NV_PER_READ_STCLEAR  },
        { "WRITE_STCLEAR", TPM_NV_PER_WRITE_STCLEAR },
        { "WRITEDEFINE",   TPM_NV_PER_WRITEDEFINE   },
        { "WRITEALL",      TPM_NV_PER_WRITEALL      }
    };

    uint32_t found;
    size_t i;
    char *s;

    *permission = 0;
    s = strtok(input, "|");
    do {
        found = 0;
        for (i = 0; i < sizeof(kPermissions) / sizeof(*kPermissions); ++i) {
            if (strcmp(s, kPermissions[i].name) == 0) {
                found = kPermissions[i].permission;
                break;
            }
        }

        if (!found) {
            return -1;
        }

        *permission |= found;
    } while ((s = strtok(NULL, "|")));

    return 0;
}

static int read_current_pcr_value(uint32_t index, unsigned char *digest)
{
    uint32_t ret;

    ret = TPM_PcrRead(index, digest);
    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return -1;
    }

    return 0;
}

static int read_current_pcr_values(TPM_PCR_COMPOSITE *comp)
{
    TPM_DIGEST digests[TPM_PCR_NUM];
    uint32_t ret;
    uint32_t pcr;
    uint8_t bit;
    uint8_t i;
    int any;

    any = 0;
    memset(digests, 0, sizeof(digests));
    for (i = 0, pcr = 0; i < comp->select.sizeOfSelect; ++i) {
        for (bit = 1; bit; bit <<= 1, ++pcr) {
            if ((bit & comp->select.pcrSelect[i])) {
                any = 1;
                if (read_current_pcr_value(pcr, digests[pcr])) {
                    return -1;
                }
            }
        }
    }

    if (!any) {
        return 0;
    }

    ret = TSS_PCRComposite_Set(comp, digests);
    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return -1;
    }

    return 0;
}

int tpm_nvdefine(int argc, char *argv[])
{
    TPM_PCR_INFO_SHORT rpcr;
    TPM_PCR_INFO_SHORT wpcr;
    TPM_PCR_COMPOSITE rcomp;
    TPM_PCR_COMPOSITE wcomp;
    uint32_t ret;
    int c;

    long pcr;
    char *end;
    long size = -1;
    int has_index = 0;
    int ownerpass = 0;
    uint32_t rset = 0;
    uint32_t wset = 0;
    unsigned long index = 0;
    uint32_t permissions = 0;
    unsigned char ownerhash[TPM_HASH_SIZE];

    while ((c = getopt(argc, argv, "i:r:w:s:p:o:y")) != -1) {
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
        case 'p':
            if (parse_permission(optarg, &permissions)) {
                return EXIT_FAILURE;
            }
            break;
        case 'r':
            pcr = strtol(optarg, &end, 0);
            if (pcr < 0 || pcr >= TPM_PCR_NUM) {
                return EXIT_FAILURE;
            }
            rset |= 1 << pcr;
            break;
        case 'w':
            pcr = strtol(optarg, &end, 0);
            if (pcr < 0 || pcr >= TPM_PCR_NUM) {
                return EXIT_FAILURE;
            }
            wset |= 1 << pcr;
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
    } else if (!has_index || size <= 0) {
        return help(argv[0]);
    }

    if (!ownerpass) {
        fprintf(stderr, "not implemented\n");
        return EXIT_FAILURE;
    }

    TPM_setlog(0);
    TSS_PCRComposite_Init(&rcomp);
    TSS_PCRComposite_Init(&wcomp);
    TSS_PCRSelection_Set(&rcomp.select, rset);
    TSS_PCRSelection_Set(&wcomp.select, wset);
    if (read_current_pcr_values(&rcomp) || read_current_pcr_values(&wcomp) ){
        TSS_PCRComposite_Delete(&wcomp);
        TSS_PCRComposite_Delete(&rcomp);
        return EXIT_FAILURE;
    }

    ret = TSS_PCRComposite_ToPCRInfoShort(&rcomp, &rpcr, TPM_LOC_ALL);
    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        TSS_PCRComposite_Delete(&wcomp);
        TSS_PCRComposite_Delete(&rcomp);
        return EXIT_FAILURE;
    }

    ret = TSS_PCRComposite_ToPCRInfoShort(&wcomp, &wpcr, TPM_LOC_ALL);
    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        TSS_PCRComposite_Delete(&wcomp);
        TSS_PCRComposite_Delete(&rcomp);
        return EXIT_FAILURE;
    }

    TSS_PCRComposite_Delete(&wcomp);
    TSS_PCRComposite_Delete(&rcomp);
    ret = TPM_NV_DefineSpace2(
            ownerhash,
            (uint32_t)index,
            (uint32_t)size,
            permissions,
            NULL, &rpcr, &wpcr);

    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
