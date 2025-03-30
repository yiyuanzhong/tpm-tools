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

#define COMMAND(x) {#x,tpm_##x},
static const struct command kCommands[] = {
    HANDLER(COMMAND)
};

static int help(char *argv0)
{
    size_t i;

    fprintf(stderr, "To run an applet:\n");
    fprintf(stderr, "%s <applet> (for example \"tpm version\")\n", argv0);
    fprintf(stderr, "\n");
    fprintf(stderr, "To create symlinks:\n");
    fprintf(stderr, "%s --install\n", argv0);
    fprintf(stderr, "\n");
    fprintf(stderr, "Supported commands:\n");
    for (i = 0; i < sizeof(kCommands) / sizeof(*kCommands); ++i) {
        fprintf(stderr, "  tpm_%s\n", kCommands[i].name);
    }

    return EXIT_FAILURE;
}

static int install(int argc, char *argv[], char *bn)
{
    char target[PATH_MAX];
    char dnbuf[PATH_MAX];
    size_t length;
    size_t dnlen;
    size_t i;
    char *dn;
    int ret;

    if (argc != 2) {
        return help(bn);
    }

    strcpy(dnbuf, argv[0]);
    dn = dirname(dnbuf);
    dnlen = strlen(dn);

    if (!dnlen || dnlen + 5 >= sizeof(target)) {
        return EXIT_FAILURE;
    }

    memcpy(target, dn, dnlen);
    if (target[dnlen - 1] != '/') {
        target[dnlen++] = '/';
    }

    memcpy(target + dnlen, "tpm_", 4);
    dnlen += 4;

    ret = EXIT_SUCCESS;
    for (i = 0; i < sizeof(kCommands) / sizeof(*kCommands); ++i) {
        length = strlen(kCommands[i].name);
        if (dnlen + length >= sizeof(target)) {
            ret = EXIT_FAILURE;
            continue;
        }

        memcpy(target + dnlen, kCommands[i].name, length);
        target[dnlen + length] = '\0';
        if (symlink(bn, target)) {
            ret = EXIT_FAILURE;
        }
    }

    return ret;
}

static int invoke_applet(int argc, char *argv[], char *bn)
{
    size_t i;

    for (i = 0; i < sizeof(kCommands) / sizeof(*kCommands); ++i) {
        if (strcmp(bn + 4, kCommands[i].name) == 0) {
            argv[0] = bn;
            return kCommands[i].function(argc, argv);
        }
    }

    return help(bn);
}

static int run_applet(int argc, char *argv[], char *bn)
{
    char fullbuf[PATH_MAX];
    size_t length;
    size_t i;

    length = strlen(argv[1]);
    if (length + 5 > sizeof(fullbuf)) {
        return EXIT_FAILURE;
    }

    memcpy(fullbuf, "tpm_", 4);
    memcpy(fullbuf + 4, argv[1], length + 1);
    for (i = 0; i < sizeof(kCommands) / sizeof(*kCommands); ++i) {
        if (strcmp(argv[1], kCommands[i].name) == 0) {
            argv[1] = fullbuf;
            return kCommands[i].function(argc - 1, argv + 1);
        }
    }

    return help(bn);
}

int main(int argc, char *argv[])
{
    char bnbuf[PATH_MAX];
    char *bn;

    if (argc < 1 || !*argv[0] || strlen(argv[0]) >= PATH_MAX) {
        return EXIT_FAILURE;
    }

    strcpy(bnbuf, argv[0]);
    bn = basename(bnbuf);

    if (strncmp(bn, "tpm_", 4) == 0) {
        return invoke_applet(argc, argv, bn);

    } else if (argc >= 2) {
        if (strcmp(argv[1], "--install") == 0) {
            return install(argc, argv, bn);
        } else {
            return run_applet(argc, argv, bn);
        }

    } else {
        return help(bn);
    }
}
