#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <tpmfunc.h>
#include <tpm_error.h>

static int help(const char *argv0)
{
    fprintf(stderr, "%s [-f filename] [-z]\n", argv0);
    return EXIT_FAILURE;
}

int tpm_getpubek(int argc, char *argv[])
{
    unsigned char ownerhash[TPM_HASH_SIZE];
    EVP_PKEY *pkey;
    pubkeydata ek;
    uint32_t ret;
    FILE *fp;
    RSA *rsa;
    int c;

    int ownerpass = 0;
    char *filename = NULL;
    while ((c = getopt(argc, argv, "f:o:z")) != -1) {
        switch (c) {
        case 'f':
            filename = optarg;
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
    }

    TPM_setlog(0);

    if (!filename) {
        fprintf(stderr, "not implemented\n");
        return EXIT_FAILURE;
    }

    if (ownerpass) {
        ret = TPM_OwnerReadPubek(ownerhash, &ek);
    } else {
        ret = TPM_ReadPubek(&ek);
    }

    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return EXIT_FAILURE;
    }

    rsa = TSS_convpubkey(&ek);
    if (!rsa) {
        fprintf(stderr, "Failed to convert public key\n");
        return EXIT_FAILURE;
    }

    pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "Failed to allocate public key\n");
        RSA_free(rsa);
        return EXIT_FAILURE;
    }

    if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
        fprintf(stderr, "Failed to initialize public key\n");
        RSA_free(rsa);
        return EXIT_FAILURE;
    }

    RSA_free(rsa);

    fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open %s for writing\n", filename);
        EVP_PKEY_free(pkey);
        return EXIT_FAILURE;
    }

    if (PEM_write_PUBKEY(fp, pkey) != 1) {
        fprintf(stderr, "Failed to write to %s\n", filename);
        fclose(fp);
        EVP_PKEY_free(pkey);
        return EXIT_FAILURE;
    }

    fclose(fp);
    EVP_PKEY_free(pkey);
    return EXIT_SUCCESS;
}
