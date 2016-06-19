noinst_LTLIBRARIES = libdcrypt.la
pkglib_LTLIBRARIES =

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

libdcrypt_la_SOURCES = \
	dcrypt.c \
	istream-decrypt.c \
	ostream-encrypt.c

libdcrypt_la_CFLAGS = $(AM_CPPFLAGS) \
	-DDCRYPT_MODULE_DIR=\"$(pkglibdir)\"

if BUILD_OPENSSL
pkglib_LTLIBRARIES += libdcrypt_openssl.la
libdcrypt_openssl_la_SOURCES = dcrypt-openssl.c dcrypt.c
libdcrypt_openssl_la_LDFLAGS = -module -avoid-version -shared $(SSL_LIBS) ../lib/liblib.la
libdcrypt_openssl_la_CFLAGS = $(AM_CPPFLAGS) \
	-DDCRYPT_MODULE_DIR=\"$(pkglibdir)\"
	$(SSL_CFLAGS)
endif

headers = \
	dcrypt.h \
	dcrypt-iostream-private.h \
	dcrypt-private.h \
	ostream-encrypt.h \
	istream-decrypt.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

EXTRA_DIST = \
	sample-v1.asc \
	sample-v2.asc

test_programs = test-crypto test-stream
noinst_PROGRAMS = $(test_programs)

check: check-am check-test

check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

LIBDOVECOT_TEST = \
	../lib-test/libtest.la \
	../lib/liblib.la \
	$(MODULE_LIBS)

test_crypto_LDADD = $(LIBDOVECOT_TEST)
test_crypto_CFLAGS = $(AM_CPPFLAGS) -DDCRYPT_MODULE_DIR=\".libs\" -DDCRYPT_SRC_DIR=\"$(top_srcdir)/src/lib-dcrypt\"
test_crypto_SOURCES = $(libdcrypt_la_SOURCES) test-crypto.c

test_stream_LDADD = $(LIBDOVECOT_TEST)
test_stream_CFLAGS = $(AM_CPPFLAGS) -DDCRYPT_MODULE_DIR=\".libs\" -DDCRYPT_SRC_DIR=\"$(top_srcdir)/src/lib-dcrypt\"
test_stream_SOURCES = $(libdcrypt_la_SOURCES) test-stream.c
