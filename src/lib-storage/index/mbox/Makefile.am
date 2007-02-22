noinst_LIBRARIES = libstorage_mbox.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_mbox_a_SOURCES = \
	istream-raw-mbox.c \
	mbox-file.c \
	mbox-from.c \
	mbox-lock.c \
	mbox-mail.c \
	mbox-md5.c \
	mbox-save.c \
	mbox-sync-parse.c \
	mbox-sync-rewrite.c \
	mbox-sync-update.c \
	mbox-sync.c \
	mbox-storage.c \
	mbox-transaction.c

headers = \
	istream-raw-mbox.h \
	mbox-file.h \
	mbox-from.h \
	mbox-lock.h \
	mbox-md5.h \
	mbox-storage.h \
	mbox-sync-private.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-storage/index/mbox
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
