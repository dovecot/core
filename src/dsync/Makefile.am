bin_PROGRAMS = dsync

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

if !BUILD_SHARED_LIBS
unused_objects = \
	../lib/mountpoint.o \
	../lib-storage/mail-search-parser-imap.o
endif

libs = \
	$(LIBDOVECOT_STORAGE) \
	$(unused_objects)

dsync_LDADD = $(libs) $(LIBDOVECOT) $(MODULE_LIBS)
dsync_DEPENDENCIES = $(libs) $(LIBDOVECOT_DEPS)
dsync_SOURCES = \
	dsync.c \
	dsync-brain.c \
	dsync-brain-msgs.c \
	dsync-brain-msgs-new.c \
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
	test-dsync-brain-msgs \
	test-dsync-proxy \
	test-dsync-proxy-server-cmd

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../lib-test/libtest.la \
	../lib-mail/libmail.la \
	../lib-imap/libimap.la \
	../lib-charset/libcharset.la \
	../lib/liblib.la

test_ldadd = \
	$(test_libs) \
	$(LIBICONV)

test_dsync_brain_SOURCES = test-dsync-brain.c test-dsync-worker.c test-dsync-common.c
test_dsync_brain_LDADD = dsync-data.o dsync-brain.o dsync-worker.o $(test_ldadd)
test_dsync_brain_DEPENDENCIES = dsync-data.o dsync-brain.o dsync-worker.o $(test_libs)

test_dsync_brain_msgs_SOURCES = test-dsync-brain-msgs.c test-dsync-worker.c test-dsync-common.c
test_dsync_brain_msgs_LDADD = dsync-data.o dsync-brain-msgs.o dsync-worker.o $(test_ldadd)
test_dsync_brain_msgs_DEPENDENCIES = dsync-data.o dsync-brain-msgs.o dsync-worker.o $(test_libs)

test_dsync_proxy_SOURCES = test-dsync-proxy.c test-dsync-common.c
test_dsync_proxy_LDADD = dsync-proxy.o dsync-data.o $(test_ldadd)
test_dsync_proxy_DEPENDENCIES = dsync-proxy.o dsync-data.o $(test_libs)

test_dsync_proxy_server_cmd_SOURCES = test-dsync-proxy-server-cmd.c test-dsync-worker.c test-dsync-common.c
test_dsync_proxy_server_cmd_LDADD = dsync-worker.o dsync-proxy.o dsync-proxy-server-cmd.o dsync-data.o $(test_ldadd)
test_dsync_proxy_server_cmd_DEPENDENCIES = dsync-worker.o dsync-proxy.o dsync-proxy-server-cmd.o dsync-data.o $(test_libs)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
