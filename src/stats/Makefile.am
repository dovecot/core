pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = stats

noinst_LTLIBRARIES = libstats_local.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-http \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-test \
	$(BINARY_CFLAGS)

stats_LDADD = \
	$(noinst_LTLIBRARIES) \
	$(LIBDOVECOT) \
	$(DOVECOT_SSL_LIBS) \
	$(BINARY_LDFLAGS) \
	-lm

stats_DEPENDENCIES = \
	$(noinst_LTLIBRARIES) \
	$(DOVECOT_SSL_LIBS) \
	$(LIBDOVECOT_DEPS)

stats_services = \
	stats-service-openmetrics.c

stats_SOURCES = \
	main.c

libstats_local_la_SOURCES = \
	client-reader.c \
	client-writer.c \
	client-http.c \
	event-exporter-fmt.c \
	event-exporter-fmt-json.c \
	event-exporter-fmt-none.c \
	event-exporter-fmt-tab-text.c \
	event-exporter-transport-drop.c \
	event-exporter-transport-http-post.c \
	event-exporter-transport-log.c \
	$(stats_services) \
	stats-service.c \
	stats-event-category.c \
	stats-metrics.c \
	stats-settings.c

noinst_HEADERS = \
	stats-common.h \
	client-reader.h \
	client-writer.h \
	client-http.h\
	event-exporter.h \
	stats-service.h \
	stats-service-private.h \
	stats-event-category.h \
	stats-metrics.h \
	stats-settings.h \
	test-stats-common.h

test_libs = \
	$(noinst_LTLIBRARIES) \
	$(DOVECOT_SSL_LIBS) \
	$(LIBDOVECOT) \
	$(BINARY_LDFLAGS) \
	-lm

test_deps = \
	$(noinst_LTLIBRARIES) \
	$(DOVECOT_SSL_LIBS) \
	$(LIBDOVECOT_DEPS)

test_stats_metrics_SOURCES = test-stats-metrics.c test-stats-common.c
test_stats_metrics_LDADD = $(test_libs)
test_stats_metrics_DEPENDENCIES = $(test_deps)

test_client_writer_SOURCES = test-client-writer.c test-stats-common.c
test_client_writer_LDADD = $(test_libs)
test_client_writer_DEPENDENCIES = $(test_deps)

test_client_reader_SOURCES = test-client-reader.c test-stats-common.c
test_client_reader_LDADD = $(test_libs)
test_client_reader_DEPENDENCIES = $(test_deps)

test_programs = test-stats-metrics test-client-writer test-client-reader
noinst_PROGRAMS = $(test_programs)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

LIBDOVECOT_TEST_DEPS = \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-test/libtest.la \
	../lib/liblib.la
LIBDOVECOT_TEST = \
	$(LIBDOVECOT_TEST_DEPS) \
	$(MODULE_LIBS)
