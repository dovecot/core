noinst_LTLIBRARIES = libcharset.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libcharset_la_SOURCES = \
	charset-iconv.c \
	charset-utf8.c

headers = \
	charset-utf8.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
