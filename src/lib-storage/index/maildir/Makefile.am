noinst_LIBRARIES = libstorage_maildir.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-index/maildir \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_maildir_a_SOURCES = \
	maildir-copy.c \
	maildir-expunge.c \
	maildir-list.c \
	maildir-save.c \
	maildir-storage.c

noinst_HEADERS = \
	maildir-storage.h
