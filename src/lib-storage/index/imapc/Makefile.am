noinst_LTLIBRARIES = libstorage_imapc.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-imap-client \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/list \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-ssl-iostream

libstorage_imapc_la_SOURCES = \
	imapc-list.c \
	imapc-mail.c \
	imapc-mail-fetch.c \
	imapc-mailbox.c \
	imapc-save.c \
	imapc-search.c \
	imapc-settings.c \
	imapc-sync.c \
	imapc-storage.c

headers = \
	imapc-list.h \
	imapc-mail.h \
	imapc-search.h \
	imapc-settings.h \
	imapc-storage.h \
	imapc-sync.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
