noinst_LTLIBRARIES = libtest.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-charset

libtest_la_SOURCES = \
	fuzzer.c \
	ostream-final-trickle.c \
	test-common.c \
	test-dir.c \
	test-istream.c \
	test-ostream.c \
	test-subprocess.c

headers = \
	fuzzer.h \
	ostream-final-trickle.h \
	test-common.h \
	test-private.h \
	test-dir.h \
	test-subprocess.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
