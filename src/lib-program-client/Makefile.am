noinst_LTLIBRARIES = libprogram_client.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dns

libprogram_client_la_SOURCES = \
	program-client.c \
	program-client-local.c \
	program-client-remote.c

headers = \
	program-client.h

noinst_HEADERS = \
	program-client-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-program-client-local \
	test-program-client-unix \
	test-program-client-net

noinst_PROGRAMS = $(test_programs)

test_libs = \
	libprogram_client.la \
	../lib-dns/libdns.la  \
	../lib-test/libtest.la \
	../lib/liblib.la \
	$(MODULE_LIBS)

test_program_client_local_SOURCE = test-program-client-local.c
test_program_client_local_LDADD = $(test_libs)

test_program_client_unix_SOURCE = test-program-client-unix.c
test_program_client_unix_LDADD = $(test_libs)

test_program_client_net_SOURCE = test-program-client-net.c
test_program_client_net_LDADD = $(test_libs)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
