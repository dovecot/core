noinst_LTLIBRARIES = libprogram_client.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libprogram_client_la_SOURCES = \
	program-client.c \
	program-client-local.c \
	program-client-remote.c

headers = \
	program-client.h

noinst_HEADERS = \
	program-client-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
