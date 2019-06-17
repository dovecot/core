noinst_LTLIBRARIES = libauth.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-test

libauth_la_SOURCES = \
	auth-client.c \
	auth-client-request.c \
	auth-client-connection.c \
	auth-master.c

headers = \
	auth-client.h \
	auth-client-interface.h \
	auth-client-private.h \
	auth-master.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-auth-master

noinst_PROGRAMS = $(test_programs)

test_libs = \
	$(noinst_LTLIBRARIES) \
	../lib-test/libtest.la \
	../lib/liblib.la \
	$(MODULE_LIBS)

test_deps = \
	$(noinst_LTLIBRARIES) \
	../lib-test/libtest.la \
	../lib/liblib.la

test_auth_master_SOURCES = test-auth-master.c
test_auth_master_LDADD = $(test_libs)
test_auth_master_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
