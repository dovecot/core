noinst_LTLIBRARIES = libstorage_dbox.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_dbox_la_SOURCES = \
	dbox-file.c \
	dbox-file-fix.c \
	dbox-file-maildir.c \
	dbox-mail.c \
	dbox-map.c \
	dbox-save.c \
	dbox-settings.c \
	dbox-sync.c \
	dbox-sync-file.c \
	dbox-sync-rebuild.c \
	dbox-storage.c \
	dbox-storage-rebuild.c

headers = \
	dbox-file.h \
	dbox-file-maildir.h \
	dbox-map.h \
	dbox-map-private.h \
	dbox-settings.h \
	dbox-storage.h \
	dbox-storage-rebuild.h \
	dbox-sync.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
