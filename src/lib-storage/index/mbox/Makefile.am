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
	mbox-expunge.c \
	mbox-list.c \
	mbox-save.c \
	mbox-storage.c

noinst_HEADERS = \
	mbox-storage.h
