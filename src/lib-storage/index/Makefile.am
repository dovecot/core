SUBDIRS = maildir mbox dbox cydir raw shared

noinst_LTLIBRARIES = libstorage_index.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

libstorage_index_la_SOURCES = \
	istream-mail-stats.c \
	index-fetch.c \
	index-mail.c \
	index-mail-headers.c \
	index-mailbox-check.c \
	index-search.c \
	index-search-result.c \
	index-sort.c \
	index-sort-string.c \
	index-status.c \
	index-storage.c \
	index-sync.c \
	index-sync-changes.c \
	index-sync-search.c \
	index-thread.c \
	index-thread-finish.c \
	index-thread-links.c \
	index-transaction.c

libstorage_index_la_LIBADD = @LINKED_STORAGE_LIBS@
libstorage_index_la_DEPENDENCIES = @LINKED_STORAGE_LIBS@

headers = \
	istream-mail-stats.h \
	index-mail.h \
	index-search-result.h \
	index-sort.h \
	index-sort-private.h \
	index-storage.h \
	index-sync-changes.h \
	index-sync-private.h \
	index-thread-private.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
