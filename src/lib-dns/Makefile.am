noinst_LTLIBRARIES = libdns.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libdns_la_SOURCES = \
	dns-lookup.c

headers = \
	dns-lookup.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
