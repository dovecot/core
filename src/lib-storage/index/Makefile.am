SUBDIRS = maildir mbox dbox cydir raw

noinst_LIBRARIES = libstorage_index.a

AM_CPPFLAGS = \
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
	index-sort.c \
	index-status.c \
	index-storage.c \
	index-sync.c \
	index-sync-changes.c \
	index-transaction.c

headers = \
	index-mail.h \
	index-sort.h \
	index-storage.h \
	index-sync-changes.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-storage/index
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
