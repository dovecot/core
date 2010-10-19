noinst_LTLIBRARIES = libstorage_dbox_common.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-fs \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_dbox_common_la_SOURCES = \
	dbox-attachment.c \
	dbox-file.c \
	dbox-file-fix.c \
	dbox-mail.c \
	dbox-save.c \
	dbox-storage.c \
	dbox-sync-rebuild.c

headers = \
	dbox-attachment.h \
	dbox-file.h \
	dbox-mail.h \
	dbox-save.h \
	dbox-storage.h \
	dbox-sync-rebuild.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
