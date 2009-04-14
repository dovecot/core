SUBDIRS = list index register

noinst_LTLIBRARIES = libstorage.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DMODULEDIR=\""$(moduledir)"\"

libstorage_la_SOURCES = \
	mail.c \
	mail-copy.c \
	mail-error.c \
	mail-namespace.c \
	mail-search.c \
	mail-search-build.c \
	mail-storage.c \
	mail-storage-service.c \
	mail-storage-settings.c \
	mail-user.c \
	mailbox-list.c \
	mailbox-search-result.c \
	mailbox-tree.c \
	mailbox-uidvalidity.c

libs = \
	../lib-index/libindex.la \
	list/libstorage_list.la \
	index/libstorage_index.la \
	register/libstorage_register.la	

libstorage_la_LIBADD = $(libs)
libstorage_la_DEPENDENCIES = $(libs)

headers = \
	mail-copy.h \
	mail-error.h \
	mail-namespace.h \
	mail-search.h \
	mail-search-build.h \
	mail-thread.h \
	mail-storage.h \
	mail-storage-private.h \
	mail-storage-service.h \
	mail-storage-settings.h \
	mail-user.h \
	mailbox-list.h \
	mailbox-list-private.h \
	mailbox-search-result-private.h \
	mailbox-tree.h \
	mailbox-uidvalidity.h

pkglib_LTLIBRARIES = libdovecot-storage.la
libdovecot_storage_la_SOURCES = 
libdovecot_storage_la_LIBADD = libstorage.la
libdovecot_storage_la_DEPENDENCIES = libstorage.la
libdovecot_storage_la_LDFLAGS = -export-dynamic

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-storage
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
