noinst_LIBRARIES = libstorage_index_maildir.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index

libstorage_index_maildir_a_SOURCES = \
	maildir-index.c \
	maildir-build.c \
	maildir-open.c \
	maildir-rebuild.c \
	maildir-sync.c \
	maildir-update.c

noinst_HEADERS = \
	maildir-index.h
