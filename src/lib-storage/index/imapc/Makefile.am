noinst_LTLIBRARIES = libstorage_imapc.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/list \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_imapc_la_SOURCES = \
	imapc-client.c \
	imapc-connection.c \
	imapc-list.c \
	imapc-mail.c \
	imapc-mail-fetch.c \
	imapc-mailbox.c \
	imapc-msgmap.c \
	imapc-save.c \
	imapc-settings.c \
	imapc-sync.c \
	imapc-storage.c

headers = \
	imapc-client.h \
	imapc-client-private.h \
	imapc-connection.h \
	imapc-list.h \
	imapc-mail.h \
	imapc-msgmap.h \
	imapc-settings.h \
	imapc-storage.h \
	imapc-sync.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
