include $(top_srcdir)/Makefile.test.include

noinst_LTLIBRARIES = libpop3_client.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-dns-client \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-sasl \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-pop3 \
	-I$(top_srcdir)/src/lib-var-expand

libpop3_client_la_SOURCES = \
	pop3c-client.c \
	pop3c-client-settings.c

headers = \
	pop3c-client.h \
	pop3c-client-settings.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-pop3c-client

test_deps = \
	$(noinst_LTLIBRARIES) \
	../lib-dovecot/libdovecot.la

test_libs = \
	$(test_deps) \
	$(LIBDOVECOT_TEST_LIBS)

test_pop3c_client_SOURCES = test-pop3c-client.c
test_pop3c_client_LDADD = $(test_libs)
test_pop3c_client_DEPENDENCIES = $(test_deps)
