noinst_LIBRARIES = libstorage_list.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-storage

libstorage_list_a_SOURCES = \
	mailbox-list-fs.c \
	mailbox-list-fs-iter.c \
	mailbox-list-maildir.c \
	mailbox-list-maildir-iter.c \
	subscription-file.c

noinst_HEADERS = \
	mailbox-list-fs.h \
	mailbox-list-maildir.h \
	subscription-file.h
