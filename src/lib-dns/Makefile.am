noinst_LTLIBRARIES = libdns.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libdns_la_SOURCES = \
	dns-lookup.c \
	dns-util.c

headers = \
	dns-lookup.h \
	dns-util.h

test_programs = \
	test-dns-util

noinst_PROGRAMS = $(test_programs)

test_libs = \
	libdns.la  \
	../lib-test/libtest.la \
	../lib/liblib.la

test_dns_util_SOURCE = test-dns-util.c
test_dns_util_LDADD = $(test_libs)
test_dns_util_CFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/lib-test

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if test "$$bin" = "test-program-client-local"; then \
	    if ! env NOVALGRIND=yes $(RUN_TEST) ./$$bin; then exit 1; fi; \
	  else \
	    if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	  fi \
	done


pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
