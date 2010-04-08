noinst_LTLIBRARIES = libstorage_mbox.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_mbox_la_SOURCES = \
	istream-raw-mbox.c \
	mbox-file.c \
	mbox-lock.c \
	mbox-mail.c \
	mbox-md5.c \
	mbox-save.c \
	mbox-settings.c \
	mbox-sync-parse.c \
	mbox-sync-rewrite.c \
	mbox-sync-update.c \
	mbox-sync.c \
	mbox-storage.c

headers = \
	istream-raw-mbox.h \
	mbox-file.h \
	mbox-lock.h \
	mbox-md5.h \
	mbox-settings.h \
	mbox-storage.h \
	mbox-sync-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
