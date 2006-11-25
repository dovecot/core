noinst_LIBRARIES = libstorage_list.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_list_a_SOURCES = \
	index-mailbox-list.c \
	index-mailbox-list-sync.c \
	mailbox-list-fs.c \
	mailbox-list-fs-iter.c \
	mailbox-list-maildir.c \
	mailbox-list-maildir-iter.c \
	subscription-file.c

noinst_HEADERS = \
	index-mailbox-list.h \
	mailbox-list-fs.h \
	mailbox-list-maildir.h \
	subscription-file.h
