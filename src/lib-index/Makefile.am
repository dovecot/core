noinst_LTLIBRARIES = libindex.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-mail

libindex_la_SOURCES = \
	mail-cache.c \
	mail-cache-compress.c \
	mail-cache-decisions.c \
	mail-cache-fields.c \
	mail-cache-lookup.c \
	mail-cache-transaction.c \
	mail-cache-sync-update.c \
        mail-index.c \
        mail-index-dummy-view.c \
        mail-index-fsck.c \
        mail-index-lock.c \
        mail-index-map.c \
        mail-index-modseq.c \
        mail-index-transaction.c \
        mail-index-transaction-export.c \
        mail-index-transaction-finish.c \
        mail-index-transaction-sort-appends.c \
        mail-index-transaction-view.c \
        mail-index-strmap.c \
        mail-index-sync.c \
        mail-index-sync-ext.c \
        mail-index-sync-keywords.c \
        mail-index-sync-update.c \
        mail-index-view.c \
        mail-index-view-sync.c \
        mail-index-write.c \
        mail-transaction-log.c \
        mail-transaction-log-append.c \
        mail-transaction-log-file.c \
        mail-transaction-log-view.c \
        mailbox-list-index.c \
        mailbox-list-index-sync.c

headers = \
	mail-cache.h \
	mail-cache-private.h \
	mail-index.h \
        mail-index-modseq.h \
	mail-index-private.h \
        mail-index-strmap.h \
	mail-index-sync-private.h \
	mail-index-transaction-private.h \
	mail-index-view-private.h \
        mail-transaction-log.h \
	mail-transaction-log-private.h \
	mail-transaction-log-view-private.h \
        mailbox-list-index.h \
        mailbox-list-index-private.h

test_programs = test-index
noinst_PROGRAMS = $(test_programs)

test_libs = \
	libindex.la \
	../lib-test/libtest.la \
	../lib-mail/libmail.la \
	../lib/liblib.la

test_index_SOURCES = \
	test-index.c \
	test-transaction-log-view.c

test_headers = \
	test-index.h

test_index_LDADD = $(test_libs)
test_index_DEPENDENCIES = $(test_libs)

check: check-am check-test
check-test: $(test_programs)
	for bin in $(test_programs); do \
	  if ! ./$$bin; then exit 1; fi \
	done

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)
  pkginc_lib_HEADERS = $(headers) $(test_headers)
else
  noinst_HEADERS = $(headers) $(test_headers)
endif
