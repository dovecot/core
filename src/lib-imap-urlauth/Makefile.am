noinst_LTLIBRARIES = libimap-urlauth.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-charset \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-imap-storage

libimap_urlauth_la_SOURCES = \
	imap-urlauth.c \
	imap-urlauth-fetch.c \
	imap-urlauth-backend.c \
	imap-urlauth-connection.c

headers = \
	imap-urlauth.h \
	imap-urlauth-private.h \
	imap-urlauth-fetch.h \
	imap-urlauth-backend.h \
	imap-urlauth-connection.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

