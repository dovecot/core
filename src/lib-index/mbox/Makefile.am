noinst_LIBRARIES = libindex_mbox.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index

libindex_mbox_a_SOURCES = \
	mbox-append.c \
	mbox-from.c \
	mbox-index.c \
	mbox-lock.c \
	mbox-open.c \
	mbox-rewrite.c \
	mbox-sync.c \
	mbox-sync-full.c

noinst_HEADERS = \
	mbox-index.h \
	mbox-lock.h
