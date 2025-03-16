.PHONY: all clean

BACKEND ?= openssl
ifneq ($(BACKEND),openssl)
ifneq ($(BACKEND),mbedtls)
$(error BACKEND shall be set to either openssl or mbedtls)
endif
endif

MKDIR := mkdir -p
PATCH := patch -b
TOUCH := touch
RM := rm -f
TAR := tar

CPPFLAGS ?=
ifeq ($(BACKEND),mbedtls)
CPPFLAGS += -isystemmbedtls/include
endif
CPPFLAGS += -isystemlibtpm/lib
CPPFLAGS += -DTPM_POSIX=1 -DTPM_NV_DISK=1 -DTPM_AES=1 -DTPM_V12=1
CPPFLAGS += -DTPM_USE_TAG_IN_STRUCTURE=1 -DTPM_USE_CHARDEV=1

CFLAGS ?= -g -Os
CFLAGS += -Wall -Wextra -Wformat
CFLAGS += -Wno-deprecated-declarations
CFLAGS += -flto=auto
CFLAGS += -fPIE -pie
CFLAGS += -Wl,-z,nodlopen
CFLAGS += -Wl,-z,noexecstack
CFLAGS += -Wl,-z,relro -Wl,-z,now

LDFLAGS ?=
LDFLAGS += $(CFLAGS)
ifeq ($(BACKEND),openssl)
LDFLAGS += -lcrypto
else
LDFLAGS += -lmbedcrypto
endif

SRC := main.c tpm_changeownerauth.c tpm_clear.c tpm_extendpcr.c      \
       tpm_getpubek.c tpm_listkeys.c tpm_nvdefine.c tpm_nvinfo.c     \
       tpm_nvread.c tpm_nvrelease.c tpm_nvwrite.c tpm_setclearable.c \
       tpm_setpresence.c tpm_takeownership.c tpm_version.c
OBJ := $(foreach i,$(SRC),src/$(i).o)

LIBTPM_SRC := auditing.c bind.c chgauth.c delegation.c eviction.c \
              hmac.c keys.c keyswap.c miscfunc.c nv.c oiaposap.c  \
              owner.c ownertpmdiag.c pcrs.c serialize.c session.c \
              tpmutil.c tpmutil_tty.c transport.c

LIBTPM_OBJ := $(foreach i,$(LIBTPM_SRC),libtpm/lib/$i.o)
OBJ += $(LIBTPM_OBJ)

MBEDTLS_SRC := aes.c bn.c err.c evp.c hmac.c pem.c rand.c rsa.c sha.c
MBEDTLS_OBJ := $(foreach i,$(MBEDTLS_SRC),mbedtls/src/$i.o)
ifeq ($(BACKEND),mbedtls)
OBJ += $(MBEDTLS_OBJ)
endif

all: bin/tpm

clean:
	$(RM) -r bin libtpm src/*.o mbedtls/src/*.o

libtpm/.done: tpm4769tar.gz
	$(RM) -r libtpm
	$(TAR) -xzf $< ./libtpm/lib
	$(TAR) -xzf $< ./libtpm/utils
	for i in patches/*.patch; do $(PATCH) -p1 -i $$i; done
	$(TOUCH) $@

%.c.o: %.c libtpm/.done
	$(CC) -c -o $@ $< $(CPPFLAGS) $(CFLAGS)

libtpm/utils/%.c: libtpm/.done

libtpm/utils/%: libtpm/utils/%.c.o libtpm/.done
	$(CC) -o $@ $< $(LDFLAGS) $(LIBTPM_OBJ)

bin/tpm: $(OBJ)
	$(MKDIR) bin
	$(CC) -o $@ $^ $(LDFLAGS)
