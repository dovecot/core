pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = dsync

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

dsync_LDADD = $(LIBDOVECOT_STORAGE) $(LIBDOVECOT) $(MODULE_LIBS)
dsync_DEPENDENCIES = $(LIBDOVECOT_STORAGE) $(LIBDOVECOT)
dsync_SOURCES = \
	dsync.c \
	dsync-brain.c \
	dsync-data.c \
	dsync-proxy.c \
	dsync-proxy-client.c \
	dsync-proxy-server.c \
	dsync-proxy-server-cmd.c \
	dsync-worker.c \
	dsync-worker-local.c

noinst_HEADERS = \
	dsync-brain.h \
	dsync-brain-private.h \
	dsync-data.h \
	dsync-proxy.h \
	dsync-proxy-server.h \
	dsync-worker.h \
	dsync-worker-private.h \
	test-dsync-common.h \
	test-dsync-worker.h

test_programs = \
	test-dsync-brain \
	test-dsync-proxy \
	test-dsync-proxy-server-cmd

noinst_PROGRAMS = $(test_programs)

test_libs = \
	test-dsync-common.o \
	../lib-test/libtest.la \
	../lib-mail/libmail.la \
	../lib-imap/libimap.la \
	../lib/liblib.la

test_dsync_brain_SOURCES = test-dsync-brain.c
test_dsync_brain_LDADD = test-dsync-worker.o dsync-data.o dsync-brain.o dsync-worker.o $(test_libs)
test_dsync_brain_DEPENDENCIES = test-dsync-worker.o dsync-data.o dsync-brain.o dsync-worker.o $(test_libs)

test_dsync_proxy_SOURCES = test-dsync-proxy.c
test_dsync_proxy_LDADD = dsync-proxy.o $(test_libs)
test_dsync_proxy_DEPENDENCIES = dsync-proxy.o $(test_libs)

test_dsync_proxy_server_cmd_SOURCES = test-dsync-proxy-server-cmd.c
test_dsync_proxy_server_cmd_LDADD = test-dsync-worker.o dsync-worker.o dsync-proxy.o dsync-proxy-server-cmd.o $(test_libs)
test_dsync_proxy_server_cmd_DEPENDENCIES = test-dsync-worker.o dsync-worker.o dsync-proxy.o dsync-proxy-server-cmd.o $(test_libs)

check: check-am check-test
check-test: $(test_programs)
	for bin in $(test_programs); do \
	  if ! ./$$bin; then exit 1; fi; \
	done
