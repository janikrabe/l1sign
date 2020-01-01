bin_PROGRAMS = l1sign

AM_CFLAGS = $(warn_CFLAGS) $(LIBGCRYPT_CFLAGS)

l1sign_LDADD = $(LIBGCRYPT_LIBS)

l1sign_SOURCES = \
	l1sign.c \
	l1sign_cmd_genkey.c \
	l1sign_cmd_pubkey.c \
	l1sign_cmd_sign.c \
	l1sign_cmd_verify.c \
	l1sign_util.c \
	l1sign_gcrypt.c

noinst_HEADERS = \
	l1sign.h \
	l1sign_cmd_genkey.h \
	l1sign_cmd_pubkey.h \
	l1sign_cmd_sign.h \
	l1sign_cmd_verify.h \
	l1sign_util.h \
	l1sign_gcrypt.h
