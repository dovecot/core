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
        mail-index-alloc-cache.c \
        mail-index-dummy-view.c \
        mail-index-fsck.c \
        mail-index-lock.c \
        mail-index-map.c \
        mail-index-map-hdr.c \
        mail-index-map-read.c \
        mail-index-modseq.c \
        mail-index-transaction.c \
        mail-index-transaction-export.c \
        mail-index-transaction-finish.c \
        mail-index-transaction-sort-appends.c \
        mail-index-transaction-update.c \
        mail-index-transaction-view.c \
        mail-index-strmap.c \
        mail-index-sync.c \
        mail-index-sync-ext.c \
        mail-index-sync-keywords.c \
        mail-index-sync-update.c \
        mail-index-util.c \
        mail-index-view.c \
        mail-index-view-sync.c \
        mail-index-write.c \
        mail-transaction-log.c \
        mail-transaction-log-append.c \
        mail-transaction-log-file.c \
        mail-transaction-log-view.c \
        mailbox-list-index.c \
        mailbox-list-index-sync.c \
        mailbox-log.c

headers = \
	mail-cache.h \
	mail-cache-private.h \
	mail-index.h \
        mail-index-alloc-cache.h \
        mail-index-modseq.h \
	mail-index-private.h \
        mail-index-strmap.h \
	mail-index-sync-private.h \
	mail-index-transaction-private.h \
	mail-index-util.h \
	mail-index-view-private.h \
        mail-transaction-log.h \
	mail-transaction-log-private.h \
	mail-transaction-log-view-private.h \
        mailbox-list-index.h \
        mailbox-list-index-private.h \
        mailbox-log.h

test_programs = \
	test-mail-index-sync-ext \
	test-mail-index-transaction-finish \
	test-mail-index-transaction-update \
	test-mail-transaction-log-append \
	test-mail-transaction-log-view

noinst_PROGRAMS = $(test_programs)

test_libs = \
	mail-index-util.lo \
	../lib-test/libtest.la \
	../lib/liblib.la

test_mail_index_sync_ext_SOURCES = test-mail-index-sync-ext.c
test_mail_index_sync_ext_LDADD = mail-index-sync-ext.lo $(test_libs)
test_mail_index_sync_ext_DEPENDENCIES = mail-index-sync-ext.lo $(test_libs)

test_mail_index_transaction_finish_SOURCES = test-mail-index-transaction-finish.c
test_mail_index_transaction_finish_LDADD = mail-index-transaction-finish.lo $(test_libs)
test_mail_index_transaction_finish_DEPENDENCIES = mail-index-transaction-finish.lo $(test_libs)

test_mail_index_transaction_update_SOURCES = test-mail-index-transaction-update.c
test_mail_index_transaction_update_LDADD = mail-index-transaction-update.lo $(test_libs)
test_mail_index_transaction_update_DEPENDENCIES = mail-index-transaction-update.lo $(test_libs)

test_mail_transaction_log_append_SOURCES = test-mail-transaction-log-append.c
test_mail_transaction_log_append_LDADD = mail-transaction-log-append.lo $(test_libs)
test_mail_transaction_log_append_DEPENDENCIES = mail-transaction-log-append.lo $(test_libs)

test_mail_transaction_log_view_SOURCES = test-mail-transaction-log-view.c
test_mail_transaction_log_view_LDADD = mail-transaction-log-view.lo $(test_libs)
test_mail_transaction_log_view_DEPENDENCIES = mail-transaction-log-view.lo $(test_libs)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
