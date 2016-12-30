noinst_LTLIBRARIES = libsmtp.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dns

libsmtp_la_SOURCES = \
	lmtp-client.c

headers = \
	lmtp-client.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
