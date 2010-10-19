noinst_LTLIBRARIES = libstorage_dbox_single.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-fs \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/dbox-common

libstorage_dbox_single_la_SOURCES = \
	sdbox-copy.c \
	sdbox-file.c \
	sdbox-mail.c \
	sdbox-save.c \
	sdbox-sync.c \
	sdbox-sync-rebuild.c \
	sdbox-storage.c

headers = \
	sdbox-file.h \
	sdbox-storage.h \
	sdbox-sync.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
