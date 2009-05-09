noinst_LTLIBRARIES = libtest.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-charset

libtest_la_SOURCES = \
	test-common.c

headers = \
	test-common.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
