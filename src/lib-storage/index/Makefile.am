SUBDIRS = maildir mbox

noinst_LIBRARIES = libstorage_index.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

libstorage_index_a_SOURCES = \
	index-copy.c \
	index-expunge.c \
	index-fetch.c \
	index-fetch-section.c \
	index-mailbox-check.c \
	index-messageset.c \
	index-msgcache.c \
	index-save.c \
	index-search.c \
	index-status.c \
	index-storage.c \
	index-sync.c \
	index-update-flags.c

noinst_HEADERS = \
	index-fetch.h \
	index-messageset.h \
	index-storage.h
