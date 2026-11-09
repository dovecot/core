include $(top_srcdir)/Makefile.test.include

noinst_LTLIBRARIES = \
	libssl_iostream.la \
	libssl_iostream_openssl_common.la \
	libssl_iostream_openssl_static.la

NOPLUGIN_LDFLAGS =

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-var-expand \
	-DMODULE_DIR=\""$(moduledir)"\" \
	$(SSL_CFLAGS)

module_LTLIBRARIES = libssl_iostream_openssl.la

# OpenSSL backend as convenience libraries, reused both by the loadable
# module and by unit tests that link the backend statically. Linking
# executables against the loadable module itself isn't portable.
libssl_iostream_openssl_common_la_SOURCES = \
	dovecot-openssl-common.c \
	iostream-openssl-common.c

libssl_iostream_openssl_static_la_LIBADD = \
	libssl_iostream_openssl_common.la \
	$(SSL_LIBS)
libssl_iostream_openssl_static_la_SOURCES = \
	iostream-openssl.c \
	iostream-openssl-context.c \
	istream-openssl.c \
	ostream-openssl.c

libssl_iostream_openssl_la_LDFLAGS = -module -avoid-version
libssl_iostream_openssl_la_LIBADD = \
	libssl_iostream_openssl_static.la \
	$(SSL_LIBS)
libssl_iostream_openssl_la_SOURCES =

libssl_iostream_la_SOURCES = \
	iostream-ssl.c \
	iostream-ssl-context-cache.c \
	iostream-ssl-test.c \
	ssl-settings.c

noinst_HEADERS = \
	dovecot-openssl-common.h

headers = \
	iostream-openssl.h \
	iostream-ssl.h \
	iostream-ssl-private.h \
	iostream-ssl-test.h \
	ssl-settings.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_libs = \
	libssl_iostream_openssl_static.la \
	libssl_iostream.la \
	../lib-settings/libsettings.la \
	../lib-dns/libdns.la \
	../lib-var-expand/libvar_expand.la \
	../lib-regex/libdregex.la \
	../lib-url/liburl.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_iostream_ssl_SOURCES = test-iostream-ssl.c
test_iostream_ssl_LDADD = $(test_libs) $(SSL_LIBS) $(LIBDOVECOT_TEST_LIBS)
test_iostream_ssl_DEPENDENCIES = $(test_libs)

test_programs = \
	test-iostream-ssl
