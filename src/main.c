#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libgen.h>
#include <limits.h>
#include <unistd.h>

#define HANDLER(f)     \
    f(clear)           \
    f(changeownerauth) \
    f(extendpcr)       \
    f(getpubek)        \
    f(listkeys)        \
    f(nvdefine)        \
    f(nvinfo)          \
    f(nvread)          \
    f(nvrelease)       \
    f(nvwrite)         \
    f(setclearable)    \
    f(setpresence)     \
    f(takeownership)   \
    f(version)

#define DECLARE(x) extern int tpm_##x(int argc,char *argv[]);
HANDLER(DECLARE)

struct command {
    const char *name;
    int (*function)(int, char **);
};

#define COMMAND(x) {"tpm_"#x,tpm_##x},
static const struct command kCommands[] = {
    HANDLER(COMMAND)
};

int main(int argc, char *argv[])
{
    char target[PATH_MAX];
    char bnbuf[PATH_MAX];
    char dnbuf[PATH_MAX];
    size_t length;
    size_t dnlen;
    size_t i;
    char *bn;
    char *dn;

    if (argc < 1 || strlen(argv[0]) >= PATH_MAX) {
        return EXIT_FAILURE;
    }

    strcpy(bnbuf, argv[0]);
    bn = basename(bnbuf);

    for (i = 0; i < sizeof(kCommands) / sizeof(*kCommands); ++i) {
        if (strcmp(bn, kCommands[i].name) == 0) {
            return kCommands[i].function(argc, argv);
        }
    }

    strcpy(dnbuf, argv[0]);
    dn = dirname(dnbuf);
    dnlen = strlen(dn);

    if (!dnlen || dnlen + 1 >= sizeof(target)) {
        return EXIT_FAILURE;
    }

    memcpy(target, dn, dnlen);
    if (target[dnlen - 1] != '/') {
        target[dnlen++] = '/';
    }

    if (argc == 2 && strcmp(argv[1], "--install") == 0) {
        for (i = 0; i < sizeof(kCommands) / sizeof(*kCommands); ++i) {
            length = strlen(kCommands[i].name);
            if (dnlen + length >= sizeof(target)) {
                continue;
            }

            memcpy(target + dnlen, kCommands[i].name, length);
            target[dnlen + length] = '\0';
            symlink(bn, target);
        }

        return EXIT_SUCCESS;
    }

    fprintf(stderr, "To create symlinks:\n");
    fprintf(stderr, "%s --install\n", argv[0]);
    fprintf(stderr, "\n");
    fprintf(stderr, "Supported commands:\n");
    for (i = 0; i < sizeof(kCommands) / sizeof(*kCommands); ++i) {
        fprintf(stderr, "  %s\n", kCommands[i].name);
    }

    return EXIT_FAILURE;
}
