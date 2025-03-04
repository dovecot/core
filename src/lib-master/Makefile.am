pkgsysconfdir = $(sysconfdir)/dovecot

noinst_LTLIBRARIES = libmaster.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-dns-client \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-var-expand \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DPKG_STATEDIR=\""$(statedir)"\" \
	-DSYSCONFDIR=\""$(pkgsysconfdir)"\" \
	-DBINDIR=\""$(bindir)"\"

libmaster_la_SOURCES = \
	anvil-client.c \
	log-error-buffer.c \
	master-admin-client.c \
	master-instance.c \
	master-service.c \
	master-service-haproxy.c \
	master-service-settings.c \
	master-service-ssl.c \
	stats-client.c \
	syslog-util.c

headers = \
	anvil-client.h \
	log-error-buffer.h \
	master-admin-client.h \
	master-instance.h \
	master-interface.h \
	master-service.h \
	master-service-private.h \
	master-service-settings.h \
	master-service-ssl.h \
	service-settings.h \
	stats-client.h \
	syslog-util.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-event-stats \
	test-master-service \
	test-master-service-settings

noinst_PROGRAMS = $(test_programs)

test_deps = \
	libmaster.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-settings/libsettings.la \
	../lib-dns/libdns.la \
	../lib-var-expand/libvar_expand.la \
	../lib-test/libtest.la \
	../lib-dns-client/libdns-client.la  \
	../lib-dns/libdns.la \
	../lib/liblib.la

test_libs = \
	$(test_deps) \
	$(MODULE_LIBS)

test_event_stats_SOURCES = test-event-stats.c
test_event_stats_LDADD = $(test_libs)
test_event_stats_DEPENDENCIES = $(test_deps)

test_master_service_SOURCES = test-master-service.c
test_master_service_LDADD = $(test_libs)
test_master_service_DEPENDENCIES = $(test_deps)

test_master_service_settings_SOURCES = test-master-service-settings.c
test_master_service_settings_LDADD = $(test_libs)
test_master_service_settings_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
