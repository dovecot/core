SUBDIRS = list index register

noinst_LIBRARIES = libstorage.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-DPKG_RUNDIR=\""$(rundir)"\"

libstorage_a_SOURCES = \
	mail.c \
	mail-copy.c \
	mail-error.c \
	mail-namespace.c \
	mail-search.c \
	mail-search-build.c \
	mail-storage.c \
	mail-storage-settings.c \
	mail-user.c \
	mailbox-list.c \
	mailbox-search-result.c \
	mailbox-tree.c \
	mailbox-uidvalidity.c

headers = \
	mail-copy.h \
	mail-error.h \
	mail-namespace.h \
	mail-search.h \
	mail-search-build.h \
	mail-thread.h \
	mail-storage.h \
	mail-storage-private.h \
	mail-storage-settings.h \
	mail-user.h \
	mailbox-list.h \
	mailbox-list-private.h \
	mailbox-search-result-private.h \
	mailbox-tree.h \
	mailbox-uidvalidity.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-storage
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
