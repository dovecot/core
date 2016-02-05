noinst_LTLIBRARIES = libstats.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-master

libstats_la_SOURCES = \
	stats.c \
	stats-connection.c \
	stats-parser.c

headers = \
	stats.h \
	stats-connection.h \
	stats-parser.h

pkginc_libdir = $(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
