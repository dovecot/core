noinst_LTLIBRARIES = libsettings.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libsettings_la_SOURCES = \
	settings.c \
	settings-parser.c

headers = \
	settings.h \
	settings-parser.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
