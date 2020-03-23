noinst_LTLIBRARIES = libtest.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-charset

libtest_la_SOURCES = \
	test-common.c \
	test-istream.c \
	test-ostream.c \
	test-subprocess.c

headers = \
	fuzzer.h \
	test-common.h \
	test-subprocess.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
