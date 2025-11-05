include $(top_srcdir)/Makefile.test.include

noinst_LTLIBRARIES = libdns.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

libdns_la_SOURCES = \
	dns-util.c

headers = \
	dns-util.h

test_programs = \
	test-dns-util

test_libs = \
	libdns.la  \
	../lib-test/libtest.la \
	../lib/liblib.la

test_dns_util_SOURCES = test-dns-util.c
test_dns_util_LDADD = $(test_libs)

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
