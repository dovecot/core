pkgsysconfdir = $(sysconfdir)/dovecot

noinst_LTLIBRARIES = libmaster.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-ssl-iostream \
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
	master-service-ssl-settings.c \
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
	master-service-ssl-settings.h \
	service-settings.h \
	stats-client.h \
	syslog-util.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-event-stats

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../lib-test/libtest.la \
	../lib-dns/libdns.la \
	../lib/liblib.la

test_event_stats_libs = \
	libmaster.la

test_deps = $(noinst_LTLIBRARIES) $(test_libs)

test_event_stats_SOURCES = test-event-stats.c
test_event_stats_LDADD = $(test_event_stats_libs) $(test_libs)
test_event_stats_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
