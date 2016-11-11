noinst_LTLIBRARIES = libdns.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libdns_la_SOURCES = \
	dns-lookup.c \
	dns-util.c

headers = \
	dns-lookup.h \
	dns-util.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
