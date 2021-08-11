noinst_LTLIBRARIES = libsasl.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

libsasl_la_SOURCES = \
	mech-external.c \
	mech-login.c \
	mech-plain.c \
	mech-oauthbearer.c \
	dsasl-client.c 

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
