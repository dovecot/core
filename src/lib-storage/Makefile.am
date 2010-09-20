SUBDIRS = list index register

noinst_LTLIBRARIES = libstorage.la libstorage_service.la
noinst_LIBRARIES = libstorage_test.a

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
	mail-search-parser.c \
	mail-search-parser-imap.c \
	mail-search-parser-cmdline.c \
	mail-search-register.c \
	mail-search-register-human.c \
	mail-search-register-imap.c \
	mail-storage.c \
	mail-storage-hooks.c \
	mail-storage-settings.c \
	mail-thread.c \
	mail-user.c \
	mailbox-list.c \
	mailbox-search-result.c \
	mailbox-tree.c \
	mailbox-uidvalidity.c

libstorage_service_la_SOURCES = \
	mail-storage-service.c

headers = \
	mail-copy.h \
	mail-error.h \
	mail-namespace.h \
	mail-search.h \
	mail-search-build.h \
	mail-search-register.h \
	mail-thread.h \
	mail-storage.h \
	mail-search-parser.h \
	mail-search-parser-private.h \
	mail-storage-private.h \
	mail-storage-hooks.h \
	mail-storage-service.h \
	mail-storage-settings.h \
	mail-user.h \
	mailbox-list.h \
	mailbox-list-private.h \
	mailbox-search-result-private.h \
	mailbox-tree.h \
	mailbox-uidvalidity.h

shlibs = \
	libstorage.la \
	libstorage_service.la \
	list/libstorage_list.la \
	index/libstorage_index.la \
	register/libstorage_register.la \
	../lib-index/libindex.la \
	../lib-dovecot/libdovecot.la

pkglib_LTLIBRARIES = libdovecot-storage.la
libdovecot_storage_la_SOURCES = 
libdovecot_storage_la_LIBADD = $(shlibs) $(MODULE_LIBS)
libdovecot_storage_la_DEPENDENCIES = $(shlibs)
libdovecot_storage_la_LDFLAGS = -export-dynamic

libstorage_test_a_SOURCES = \
	test-mail-storage.c \
	test-mailbox.c \
	test-mail.c

test_headers = \
	test-mail-storage.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
noinst_HEADERS = $(test_headers)
