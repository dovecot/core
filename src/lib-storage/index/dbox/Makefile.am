noinst_LIBRARIES = libstorage_dbox.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_dbox_a_SOURCES = \
	dbox-file.c \
	dbox-file-maildir.c \
	dbox-index.c \
	dbox-mail.c \
	dbox-save.c \
	dbox-sync.c \
	dbox-sync-file.c \
	dbox-sync-rebuild.c \
	dbox-storage.c \
	dbox-transaction.c

headers = \
	dbox-file.h \
	dbox-index.h \
	dbox-storage.h \
	dbox-sync.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-storage/index/dbox
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
