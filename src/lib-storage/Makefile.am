SUBDIRS = index subscription-file register

noinst_LIBRARIES = libstorage.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap

libstorage_a_SOURCES = \
	mail-copy.c \
	mail-search.c \
	mail-storage.c \
	mailbox-tree.c \
	proxy-mail.c \
	proxy-mail-storage.c \
	proxy-mailbox.c

noinst_HEADERS = \
	mail-copy.h \
	mail-search.h \
	mail-storage.h \
	mail-storage-private.h \
	mailbox-tree.h \
	proxy-mail.h \
	proxy-mail-storage.h \
	proxy-mailbox.h
