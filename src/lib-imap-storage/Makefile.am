noinst_LTLIBRARIES = libimap-storage.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-charset \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-imap

libimap_storage_la_SOURCES = \
	imap-msgpart.c \
	imap-msgpart-url.c

headers = \
	imap-msgpart.h \
	imap-msgpart-url.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

