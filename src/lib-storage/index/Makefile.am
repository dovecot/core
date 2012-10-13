SUBDIRS = maildir mbox dbox-common dbox-multi dbox-single cydir imapc pop3c raw shared

noinst_LTLIBRARIES = libstorage_index.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-fs \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

libstorage_index_la_SOURCES = \
	istream-mail.c \
	index-attachment.c \
	index-attribute.c \
	index-mail.c \
	index-mail-binary.c \
	index-mail-headers.c \
	index-mailbox-check.c \
	index-rebuild.c \
	index-search.c \
	index-search-result.c \
	index-sort.c \
	index-sort-string.c \
	index-status.c \
	index-storage.c \
	index-sync.c \
	index-sync-changes.c \
	index-sync-pvt.c \
	index-sync-search.c \
	index-thread.c \
	index-thread-finish.c \
	index-thread-links.c \
	index-transaction.c

headers = \
	istream-mail.h \
	index-attachment.h \
	index-mail.h \
	index-rebuild.h \
	index-search-private.h \
	index-search-result.h \
	index-sort.h \
	index-sort-private.h \
	index-storage.h \
	index-sync-changes.h \
	index-sync-private.h \
	index-thread-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
