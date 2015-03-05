noinst_LTLIBRARIES = libstats.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libstats_la_SOURCES = \
	stats.c \
	stats-parser.c

headers = \
	stats.h \
	stats-parser.h

pkginc_libdir = $(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
