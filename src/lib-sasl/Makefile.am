noinst_LTLIBRARIES = libsasl.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-json \
	-I$(top_srcdir)/src/lib-ssl-iostream

client_mechanisms = \
	dsasl-client-mech-anonymous.c \
	dsasl-client-mech-external.c \
	dsasl-client-mech-login.c \
	dsasl-client-mech-oauthbearer.c \
	dsasl-client-mech-plain.c \
	dsasl-client-mech-scram.c

libsasl_la_SOURCES = \
	$(client_mechanisms) \
	dsasl-client.c
libsasl_la_DEPENDENCIES = \
	../lib-auth/libauth.la \
	../lib-json/libjson.la

headers = \
	sasl-common.h \
	dsasl-client.h \
	dsasl-client-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-sasl-client

noinst_PROGRAMS = $(test_programs)

test_libs = \
	$(noinst_LTLIBRARIES) \
	../lib-auth/libauth.la \
	../lib-json/libjson.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_deps = $(test_libs)

test_sasl_client_SOURCES = test-sasl-client.c
test_sasl_client_LDADD = $(test_libs)
test_sasl_client_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
