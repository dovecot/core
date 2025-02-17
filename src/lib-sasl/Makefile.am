noinst_LTLIBRARIES = libsasl.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-json \
	-I$(top_srcdir)/src/lib-ssl-iostream

libsasl_la_SOURCES = \
	mech-anonymous.c \
	mech-external.c \
	mech-login.c \
	mech-plain.c \
	mech-oauthbearer.c \
	mech-scram.c \
	dsasl-client.c
libsasl_la_DEPENDENCIES = \
	../lib-auth/libauth.la \
	../lib-json/libjson.la

headers = \
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
