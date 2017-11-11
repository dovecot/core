noinst_LTLIBRARIES = libssl_iostream.la

NOPLUGIN_LDFLAGS =

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-DMODULE_DIR=\""$(moduledir)"\"

if BUILD_OPENSSL
module_LTLIBRARIES = libssl_iostream_openssl.la

libssl_iostream_openssl_la_LDFLAGS = -module -avoid-version
libssl_iostream_openssl_la_LIBADD = $(SSL_LIBS)
libssl_iostream_openssl_la_SOURCES = \
	dovecot-openssl-common.c \
	iostream-openssl.c \
	iostream-openssl-common.c \
	iostream-openssl-context.c \
	iostream-openssl-params.c \
	istream-openssl.c \
	ostream-openssl.c

test_programs = test-ssl-iostream
noinst_PROGRAMS = $(test_programs)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

LIBDOVECOT_TEST_DEPS = \
	libssl_iostream_openssl.la \
	libssl_iostream.la \
	../lib-test/libtest.la \
	../lib/liblib.la
LIBDOVECOT_TEST = \
	$(LIBDOVECOT_TEST_DEPS) \
	$(MODULE_LIBS)

test_ssl_iostream_LDADD = $(LIBDOVECOT_TEST)
test_ssl_iostream_DEPENDENCIES = $(LIBDOVECOT_TEST_DEPS)
test_ssl_iostream_CFLAGS = $(AM_CPPFLAGS)
test_ssl_iostream_SOURCES = test-ssl-iostream.c
endif

libssl_iostream_la_SOURCES = \
	iostream-ssl.c

noinst_HEADERS = \
	dovecot-openssl-common.h

headers = \
	iostream-openssl.h \
	iostream-ssl.h \
	iostream-ssl-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
