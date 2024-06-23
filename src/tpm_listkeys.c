#include <stdio.h>
#include <stdlib.h>

#include <tpmfunc.h>
#include <tpm_error.h>

int tpm_listkeys(int argc, char *argv[])
{
    STACK_TPM_BUFFER(response);
    uint32_t handle;
    uint16_t count;
    uint32_t ret;
    uint16_t i;
    int offset;

    (void)argc;
    (void)argv;

    TPM_setlog(0);

    ret = TPM_GetCapability(TPM_CAP_KEY_HANDLE, NULL, &response);
    if (ret != TPM_SUCCESS) {
        fprintf(stderr, "Failed: %u: %s\n", ret, TPM_GetErrMsg(ret));
        return EXIT_FAILURE;
    }

    count = LOAD16(response.buffer, 0);
    for (i = 0, offset = 2; i < count; ++i, offset += 4) {
        handle = LOAD32(response.buffer, offset);
        printf("%08X\n", handle);
    }

    return EXIT_SUCCESS;
}
