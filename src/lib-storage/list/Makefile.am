noinst_LTLIBRARIES = libstorage_list.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-fs \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-var-expand

libstorage_list_la_SOURCES = \
	mail-storage-list-index-rebuild.c \
	mailbox-list-delete.c \
	mailbox-list-fs.c \
	mailbox-list-fs-flags.c \
	mailbox-list-fs-iter.c \
	mailbox-list-index.c \
	mailbox-list-index-backend.c \
	mailbox-list-index-iter.c \
	mailbox-list-index-notify.c \
	mailbox-list-index-status.c \
	mailbox-list-index-sync.c \
	mailbox-list-iter.c \
	mailbox-list-maildir.c \
	mailbox-list-maildir-iter.c \
	mailbox-list-none.c \
	mailbox-list-notify-tree.c \
	mailbox-list-subscriptions.c \
	subscription-file.c

headers = \
	mailbox-list-delete.h \
	mailbox-list-fs.h \
	mailbox-list-index.h \
	mailbox-list-index-storage.h \
	mailbox-list-index-sync.h \
	mailbox-list-iter-private.h \
	mailbox-list-maildir.h \
	mailbox-list-notify-tree.h \
	mailbox-list-subscriptions.h \
	subscription-file.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
