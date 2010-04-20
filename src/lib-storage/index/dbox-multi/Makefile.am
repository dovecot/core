noinst_LTLIBRARIES = libstorage_dbox_multi.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/dbox-common

libstorage_dbox_multi_la_SOURCES = \
	mdbox-file.c \
	mdbox-mail.c \
	mdbox-map.c \
	mdbox-purge.c \
	mdbox-save.c \
	mdbox-settings.c \
	mdbox-sync.c \
	mdbox-storage.c \
	mdbox-storage-rebuild.c

headers = \
	mdbox-file.h \
	mdbox-map.h \
	mdbox-map-private.h \
	mdbox-settings.h \
	mdbox-storage.h \
	mdbox-storage-rebuild.h \
	mdbox-sync.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
