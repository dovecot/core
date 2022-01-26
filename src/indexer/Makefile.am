pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = indexer indexer-worker

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	$(BINARY_CFLAGS)

indexer_LDADD = $(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

indexer_DEPENDENCIES = $(LIBDOVECOT_DEPS)
indexer_SOURCES = \
	indexer.c \
	indexer-client.c \
	indexer-queue.c \
	indexer-settings.c \
	worker-connection.c

indexer_worker_LDADD = \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

indexer_worker_DEPENDENCIES = \
	$(LIBDOVECOT_STORAGE_DEPS) \
	$(LIBDOVECOT_DEPS)
indexer_worker_SOURCES = \
	indexer-worker.c \
	indexer-worker-settings.c \
	master-connection.c

noinst_HEADERS = \
	indexer.h \
	indexer-client.h \
	indexer-queue.h \
	master-connection.h \
	worker-connection.h

test_programs = \
	test-indexer-queue

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../lib-test/libtest.la \
	../lib/liblib.la

test_indexer_queue_SOURCES = test-indexer-queue.c indexer-queue.c
test_indexer_queue_LDADD = $(test_libs)
test_indexer_queue_DEPENDENCIES = $(pkglibexec_PROGRAMS) $(test_libs)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
