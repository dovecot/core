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

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done


pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
