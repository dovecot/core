pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = replicator

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth-client \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/replication \
	-DPKG_STATEDIR=\""$(statedir)"\" \
	$(BINARY_CFLAGS)

replicator_LDFLAGS = -export-dynamic \
	$(BINARY_LDFLAGS)

replicator_LDADD = $(LIBDOVECOT)
replicator_DEPENDENCIES = $(LIBDOVECOT_DEPS)

replicator_SOURCES = \
	doveadm-connection.c \
	dsync-client.c \
	replicator.c \
	replicator-brain.c \
	replicator-queue.c \
	replicator-queue-auth.c \
	replicator-settings.c \
	notify-connection.c

noinst_HEADERS = \
	doveadm-connection.h \
	dsync-client.h \
	replicator-brain.h \
	replicator-queue.h \
	replicator-queue-private.h \
	replicator-settings.h \
	notify-connection.h

test_programs = \
	test-replicator-queue

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../../lib-test/libtest.la \
	../../lib/liblib.la

test_deps = $(test_libs)

test_replicator_queue_SOURCES = \
	replicator-queue.c \
	replicator-settings.c \
	test-replicator-queue.c
test_replicator_queue_LDADD = $(test_libs)
test_replicator_queue_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
