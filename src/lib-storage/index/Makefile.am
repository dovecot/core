SUBDIRS = maildir mbox dbox-common dbox-multi dbox-single cydir raw shared

noinst_LTLIBRARIES = libstorage_index.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-fs \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

libstorage_index_la_SOURCES = \
	istream-attachment.c \
	istream-mail-stats.c \
	index-attachment.c \
	index-fetch.c \
	index-mail.c \
	index-mail-headers.c \
	index-mailbox-check.c \
	index-search.c \
	index-search-result.c \
	index-sort.c \
	index-sort-string.c \
	index-status.c \
	index-storage.c \
	index-sync.c \
	index-sync-changes.c \
	index-sync-search.c \
	index-thread.c \
	index-thread-finish.c \
	index-thread-links.c \
	index-transaction.c

libstorage_index_la_LIBADD = @LINKED_STORAGE_LIBS@
libstorage_index_la_DEPENDENCIES = @LINKED_STORAGE_LIBS@

headers = \
	istream-attachment.h \
	istream-mail-stats.h \
	index-attachment.h \
	index-mail.h \
	index-search-result.h \
	index-sort.h \
	index-sort-private.h \
	index-storage.h \
	index-sync-changes.h \
	index-sync-private.h \
	index-thread-private.h

test_programs = \
	test-index-fetch

noinst_PROGRAMS = $(test_programs)

test_libs = \
	$(top_builddir)/src/lib-test/libtest.la \
	$(top_builddir)/src/lib/liblib.la

test_index_fetch_SOURCES = test-index-fetch.c
test_index_fetch_LDADD = index-fetch.lo $(test_libs)
test_index_fetch_DEPENDENCIES = index-fetch.lo $(test_libs)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
