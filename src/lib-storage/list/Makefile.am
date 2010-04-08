noinst_LTLIBRARIES = libstorage_list.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_list_la_SOURCES = \
	index-mailbox-list.c \
	index-mailbox-list-sync.c \
	mailbox-list-delete.c \
	mailbox-list-fs.c \
	mailbox-list-fs-flags.c \
	mailbox-list-fs-iter.c \
	mailbox-list-maildir.c \
	mailbox-list-maildir-iter.c \
	mailbox-list-none.c \
	mailbox-list-subscriptions.c \
	subscription-file.c

headers = \
	index-mailbox-list.h \
	mailbox-list-delete.h \
	mailbox-list-fs.h \
	mailbox-list-maildir.h \
	mailbox-list-subscriptions.h \
	subscription-file.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
