noinst_LIBRARIES = libstorage_mbox.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-index/mbox \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_mbox_a_SOURCES = \
	istream-raw-mbox.c \
	mbox-expunge.c \
	mbox-from.c \
	mbox-list.c \
	mbox-save.c \
	mbox-sync-parse.c \
	mbox-sync-rewrite.c \
	mbox-sync-update.c \
	mbox-sync.c
	mbox-storage.c

noinst_HEADERS = \
	istream-raw-mbox.h \
	mbox-from.h \
	mbox-storage.h \
	mbox-sync-private.h
