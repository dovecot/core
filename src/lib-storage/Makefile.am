SUBDIRS = index subscription-file register

noinst_LIBRARIES = libstorage.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap

libstorage_a_SOURCES = \
	mail-save.c \
	mail-search.c \
	mail-storage.c \
	proxy-mail.c \
	proxy-mail-storage.c \
	proxy-mailbox.c

noinst_HEADERS = \
	mail-save.h \
	mail-search.h \
	mail-storage.h \
	proxy-mail.h \
	proxy-mail-storage.h \
	proxy-mailbox.h
