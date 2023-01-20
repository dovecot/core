noinst_LTLIBRARIES = libauth-client.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-test

libauth_client_la_SOURCES = \
	auth-client.c \
	auth-client-request.c \
	auth-client-connection.c \
	auth-master.c \
	auth-proxy.c

headers = \
	auth-client.h \
	auth-client-interface.h \
	auth-client-private.h \
	auth-master.h \
	auth-proxy.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-auth-client \
	test-auth-master

noinst_PROGRAMS = $(test_programs)

test_libs = \
	$(noinst_LTLIBRARIES) \
	../lib-settings/libsettings.la \
	../lib-test/libtest.la \
	../lib/liblib.la \
	$(MODULE_LIBS)

test_deps = \
	$(noinst_LTLIBRARIES) \
	../lib-settings/libsettings.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_auth_master_SOURCES = test-auth-master.c
test_auth_master_LDADD = $(test_libs)
test_auth_master_DEPENDENCIES = $(test_deps)

test_auth_client_SOURCES = test-auth-client.c
test_auth_client_LDADD = $(test_libs)
test_auth_client_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
