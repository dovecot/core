noinst_LIBRARIES = libstorage_index_mbox.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index

libstorage_index_mbox_a_SOURCES = \
	mbox-append.c \
	mbox-fsck.c \
	mbox-index.c \
	mbox-lock.c \
	mbox-open.c \
	mbox-rebuild.c \
	mbox-sync.c

noinst_HEADERS = \
	mbox-index.h \
	mbox-lock.h
