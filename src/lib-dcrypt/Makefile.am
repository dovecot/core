noinst_LTLIBRARIES = libdcrypt.la libdcrypt_openssl_static.la
module_LTLIBRARIES =

NOPLUGIN_LDFLAGS=

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-json \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-DDCRYPT_MODULE_DIR=\"$(moduledir)\"

libdcrypt_la_SOURCES = \
	dcrypt.c \
	istream-decrypt.c \
	ostream-encrypt.c

libdcrypt_la_CFLAGS = $(AM_CPPFLAGS)

libdcrypt_openssl_static_la_SOURCES = dcrypt-openssl1.c dcrypt-openssl3.c
libdcrypt_openssl_static_la_LDFLAGS = ../lib-ssl-iostream/libssl_iostream_openssl.la
libdcrypt_openssl_static_la_LIBADD = $(SSL_LIBS)
libdcrypt_openssl_static_la_DEPENDENCIES = ../lib-ssl-iostream/libssl_iostream_openssl.la
libdcrypt_openssl_static_la_CFLAGS = $(AM_CPPFLAGS) \
	$(SSL_CFLAGS)

module_LTLIBRARIES += libdcrypt_openssl.la

libdcrypt_openssl_la_SOURCES = dcrypt-openssl1.c dcrypt-openssl3.c
libdcrypt_openssl_la_LDFLAGS = -module -avoid-version ../lib-ssl-iostream/libssl_iostream_openssl.la
libdcrypt_openssl_la_LIBADD = $(SSL_LIBS)
libdcrypt_openssl_la_DEPENDENCIES = ../lib-ssl-iostream/libssl_iostream_openssl.la
libdcrypt_openssl_la_CFLAGS = $(AM_CPPFLAGS) \
	$(SSL_CFLAGS)

headers = \
	dcrypt.h \
	dcrypt-iostream.h \
	dcrypt-private.h \
	ostream-encrypt.h \
	istream-decrypt.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

EXTRA_DIST = \
	sample-v1.asc \
	sample-v1_short.asc \
	sample-v2.asc

test_programs = test-crypto test-stream
noinst_PROGRAMS = $(test_programs)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

LIBDOVECOT_TEST_DEPS = \
	../lib-var-expand/libvar_expand.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-json/libjson.la \
	../lib-settings/libsettings.la \
	../lib-dns/libdns.la \
	../lib-test/libtest.la \
	../lib/liblib.la
LIBDOVECOT_TEST = \
	$(LIBDOVECOT_TEST_DEPS) \
	$(MODULE_LIBS)

test_crypto_LDADD = $(LIBDOVECOT_TEST)
test_crypto_DEPENDENCIES = $(LIBDOVECOT_TEST_DEPS)
if HAVE_WHOLE_ARCHIVE
test_crypto_LDFLAGS = -export-dynamic -Wl,$(LD_WHOLE_ARCHIVE),../lib-var-expand/.libs/libvar_expand.a,../lib/.libs/liblib.a,../lib-json/.libs/libjson.a,../lib-ssl-iostream/.libs/libssl_iostream.a,$(LD_NO_WHOLE_ARCHIVE)
endif
test_crypto_CFLAGS = $(AM_CPPFLAGS) -DDCRYPT_SRC_DIR=\"$(top_srcdir)/src/lib-dcrypt\"
test_crypto_SOURCES = $(libdcrypt_la_SOURCES) test-crypto.c

test_stream_LDADD = $(LIBDOVECOT_TEST)
test_stream_DEPENDENCIES = $(LIBDOVECOT_TEST_DEPS)
if HAVE_WHOLE_ARCHIVE
test_stream_LDFLAGS = -export-dynamic -Wl,$(LD_WHOLE_ARCHIVE),../lib-var-expand/.libs/libvar_expand.a,../lib/.libs/liblib.a,../lib-json/.libs/libjson.a,../lib-ssl-iostream/.libs/libssl_iostream.a,$(LD_NO_WHOLE_ARCHIVE)
endif
test_stream_CFLAGS = $(AM_CPPFLAGS) -DDCRYPT_SRC_DIR=\"$(top_srcdir)/src/lib-dcrypt\"
test_stream_SOURCES = $(libdcrypt_la_SOURCES) test-stream.c
