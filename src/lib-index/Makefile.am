noinst_LTLIBRARIES = libindex.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-mail

libindex_la_SOURCES = \
	mail-cache.c \
	mail-cache-decisions.c \
	mail-cache-fields.c \
	mail-cache-lookup.c \
	mail-cache-purge.c \
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
        mailbox-log.h

test_programs = \
	test-mail-cache \
	test-mail-cache-purge \
	test-mail-index \
	test-mail-index-map \
	test-mail-index-modseq \
	test-mail-index-sync-ext \
	test-mail-index-transaction-finish \
	test-mail-index-transaction-update \
	test-mail-transaction-log-append \
	test-mail-transaction-log-file \
	test-mail-transaction-log-view

noinst_PROGRAMS = $(test_programs)

test_libs = \
	mail-index-util.lo \
	../lib-test/libtest.la \
	../lib/liblib.la

test_deps = $(noinst_LTLIBRARIES) $(test_libs)

test_mail_cache_SOURCES = test-mail-cache-common.c test-mail-cache.c
test_mail_cache_LDADD = $(noinst_LTLIBRARIES) $(test_libs)
test_mail_cache_DEPENDENCIES = $(test_deps)

test_mail_cache_purge_SOURCES = test-mail-cache-common.c test-mail-cache-purge.c
test_mail_cache_purge_LDADD = $(noinst_LTLIBRARIES) $(test_libs)
test_mail_cache_purge_DEPENDENCIES = $(test_deps)

test_mail_index_SOURCES = test-mail-index.c
test_mail_index_LDADD = $(noinst_LTLIBRARIES) $(test_libs)
test_mail_index_DEPENDENCIES = $(test_deps)

test_mail_index_map_SOURCES = test-mail-index-map.c
test_mail_index_map_LDADD = $(noinst_LTLIBRARIES) $(test_libs)
test_mail_index_map_DEPENDENCIES = $(test_deps)

test_mail_index_modseq_SOURCES = test-mail-index-modseq.c
test_mail_index_modseq_LDADD = $(noinst_LTLIBRARIES) $(test_libs)
test_mail_index_modseq_DEPENDENCIES = $(test_deps)

test_mail_index_sync_ext_SOURCES = test-mail-index-sync-ext.c
test_mail_index_sync_ext_LDADD = mail-index-sync-ext.lo $(test_libs)
test_mail_index_sync_ext_DEPENDENCIES = $(test_deps)

test_mail_index_transaction_finish_SOURCES = test-mail-index-transaction-finish.c
test_mail_index_transaction_finish_LDADD = mail-index-transaction-finish.lo $(test_libs)
test_mail_index_transaction_finish_DEPENDENCIES = $(test_deps)

test_mail_index_transaction_update_SOURCES = test-mail-index-transaction-update.c
test_mail_index_transaction_update_LDADD = mail-index-transaction-update.lo $(test_libs)
test_mail_index_transaction_update_DEPENDENCIES = $(test_deps)

test_mail_transaction_log_append_SOURCES = test-mail-transaction-log-append.c
test_mail_transaction_log_append_LDADD = mail-transaction-log-append.lo $(test_libs)
test_mail_transaction_log_append_DEPENDENCIES = $(test_deps)

test_mail_transaction_log_file_SOURCES = test-mail-transaction-log-file.c
test_mail_transaction_log_file_LDADD = $(noinst_LTLIBRARIES) $(test_libs)
test_mail_transaction_log_file_DEPENDENCIES = $(test_deps)

test_mail_transaction_log_view_SOURCES = test-mail-transaction-log-view.c
test_mail_transaction_log_view_LDADD = mail-transaction-log-view.lo $(test_libs)
test_mail_transaction_log_view_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

noinst_HEADERS = \
	test-mail-cache.h \
	test-mail-index.h
