noinst_LTLIBRARIES = libimap_client.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap

libimap_client_la_SOURCES = \
	imapc-client.c \
	imapc-connection.c \
	imapc-msgmap.c

headers = \
	imapc-client.h \
	imapc-client-private.h \
	imapc-connection.h \
	imapc-msgmap.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
