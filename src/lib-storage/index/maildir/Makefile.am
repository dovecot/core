noinst_LIBRARIES = libstorage_maildir.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_maildir_a_SOURCES = \
	maildir-copy.c \
	maildir-keywords.c \
	maildir-mail.c \
	maildir-save.c \
	maildir-storage.c \
	maildir-sync.c \
	maildir-transaction.c \
	maildir-uidlist.c \
	maildir-util.c

headers = \
	maildir-keywords.h \
	maildir-storage.h \
	maildir-sync.h \
	maildir-uidlist.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-storage/index/maildir
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
