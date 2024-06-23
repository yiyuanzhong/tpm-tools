# tpm-tools
## TPM 1.2 is dead
TPM 1.2 specification was released in 2003, but never got actual application support until TCG released the reference stack TrouSerS in 2006. Unfortunately the only hash algorithm adopted in TPM 1.2, SHA1, has been considered insecure in 2005 and deemed to cease operation since 2006. The production continued as the industry didn't have better alternatives until TPM 2.0 specification was finalized in 2014, which provided modern cryptography and more features after the industry feedbacks. Industry decided to provide TPM 1.2 and 2.0 simultaneously starting CPUs providing easy way to switch between the two versions using Firmware TPM feature, but the release of Windows 11 simply killed the interests in TPM 1.2 despite the support had come to an end even earlier. Computers manufactured with irreplaceable discrete TPM 1.2 chips might still be active in the field, some of them in pretty good conditions. Also surprisingly there're still ongoing manufacturing of TPM 1.2 equipped computers due to special interests. Unfortunately the mainstream operating systems are dropping support for TPM 1.2 and you might find it difficult to utilize TPM 1.2 for LUKS FDE or just sealing a secret.

## The remaining choices
Due to lack of modern OS support TPM 1.2 is more for industrial and embedded systems which can only work with what they have, where best efforts are made into making they as secure as they can. However TrouSerS, the only TSS which actually work with TPM 1.2, is no longer being maintained and too complicated to be used in an embedded environment. To some, libtpm, the experimental testing software stack before production grade TrouSerS is a better choice due to its simplicity and straightforward approaches (no daemon, direct communication with TPM device).

libtpm is a testing software package with such disclaimer:
>The important disclaimer is that this is demo quality code. It is not sample code or in any way a recommended way of interfacing to a TPM.

The demo codes are not only quality limited, also they do not provide TSS equivalent functions and calling conventions. Still due to its simplicity projects like tpmtotp still made their ways with libtpm and they worked well.

## The challenge
libtpm was developed with OpenSSL 0.9.6, many of its APIs are now deprecated in OpenSSL 3.0 and some being removed at all. Getting to build with OpenSSL 3.0 is not difficult as long as legacy APIs are not disabled at compile time, but the size of OpenSSL itself is already a challenge for resource limited environments. It helps greatly if we can port libtpm to another embedded cryptography libraries like wolfSSL or mbedTLS. However after some attempts I decided that the "demo quality codes" really have difficulties being ported to another cryptography backend, but it might easier that I emulate OpenSSL with mbedTLS instead.

## The outcome
This project provides a few TSS utilities for Linux which can be used to perform operations on TPM 1.2, the scope is limited since I only implemented what I need for another project based on LinuxBOOT. Size is first to come, so all the utilities are combined in a multi-call binary similar to busybox, and mbedtls is statically linked in to minimize the space used.

To start with, make symlinks with:
>./tpm --install

It will create symlinks for all the supported commands:
>tpm_clear
>tpm_changeownerauth
>tpm_extendpcr
>tpm_nvdefine
>tpm_nvinfo
>tpm_nvread
>tpm_nvrelease
>tpm_nvwrite
>tpm_setclearable
>tpm_takeownership

These commands take similar arguments like their TSS counterparts, with some interactive features removed and some batch features added. You can refer to the original commands for more detailed descriptions on the command line switches.
