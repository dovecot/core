SUBDIRS = maildir mbox

noinst_LIBRARIES = libstorage_index.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

libstorage_index_a_SOURCES = \
	index-fetch.c \
	index-mail.c \
	index-mail-headers.c \
	index-mailbox-check.c \
	index-search.c \
	index-status.c \
	index-storage.c \
	index-sync.c \
	index-transaction.c

noinst_HEADERS = \
	index-mail.h \
	index-storage.h
