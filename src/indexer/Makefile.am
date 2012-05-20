pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = indexer indexer-worker

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage \
	-DPKG_RUNDIR=\""$(rundir)"\"

indexer_LDADD = $(LIBDOVECOT) $(MODULE_LIBS)
indexer_DEPENDENCIES = $(LIBDOVECOT_DEPS)
indexer_SOURCES = \
	indexer.c \
	indexer-client.c \
	indexer-queue.c \
	indexer-settings.c \
	worker-connection.c \
	worker-pool.c

if !BUILD_SHARED_LIBS
unused_objects = \
	../lib/mountpoint.o \
	../lib-imap/imap-util.o \
	../lib-storage/mail-search-parser-imap.o
endif

indexer_worker_LDADD = \
	$(unused_objects) \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT) \
	$(MODULE_LIBS)
indexer_worker_DEPENDENCIES = \
	$(unused_objects) \
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
	worker-connection.h \
	worker-pool.h

