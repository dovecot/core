noinst_LIBRARIES = libindex_maildir.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index

libindex_maildir_a_SOURCES = \
	maildir-index.c \
	maildir-build.c \
	maildir-clean.c \
	maildir-expunge.c \
	maildir-open.c \
	maildir-rebuild.c \
	maildir-sync.c \
	maildir-uidlist.c \
	maildir-update-flags.c

noinst_HEADERS = \
	maildir-index.h \
	maildir-uidlist.h
