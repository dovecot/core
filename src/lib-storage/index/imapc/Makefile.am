noinst_LTLIBRARIES = libstorage_imapc.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_imapc_la_SOURCES = \
	imapc-client.c \
	imapc-connection.c \
	imapc-mail.c \
	imapc-save.c \
	imapc-search.c \
	imapc-seqmap.c \
	imapc-sync.c \
	imapc-storage.c

headers = \
	imapc-connection.h \
	imapc-seqmap.h \
	imapc-storage.h \
	imapc-sync.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
