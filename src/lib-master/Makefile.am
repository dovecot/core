pkgsysconfdir = $(sysconfdir)/dovecot

noinst_LTLIBRARIES = libmaster.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
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
	ipc-client.c \
	ipc-server.c \
	master-auth.c \
	master-instance.c \
	master-login.c \
	master-login-auth.c \
	master-service.c \
	master-service-haproxy.c \
	master-service-settings.c \
	master-service-settings-cache.c \
	master-service-ssl.c \
	master-service-ssl-settings.c \
	stats-client.c \
	syslog-util.c

headers = \
	anvil-client.h \
	ipc-client.h \
	ipc-server.h \
	master-auth.h \
	master-instance.h \
	master-interface.h \
	master-login.h \
	master-login-auth.h \
	master-service.h \
	master-service-private.h \
	master-service-settings.h \
	master-service-settings-cache.h \
	master-service-ssl.h \
	master-service-ssl-settings.h \
	service-settings.h \
	stats-client.h \
	syslog-util.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-master-service-settings-cache \
	test-event-stats

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../lib-test/libtest.la \
	../lib-dns/libdns.la \
	../lib/liblib.la

test_event_stats_libs = \
	libmaster.la

test_deps = $(noinst_LTLIBRARIES) $(test_libs)

test_master_service_settings_cache_SOURCES = test-master-service-settings-cache.c
test_master_service_settings_cache_LDADD = master-service-settings-cache.lo ../lib-settings/libsettings.la $(test_libs)
test_master_service_settings_cache_DEPENDENCIES = $(test_deps) ../lib-settings/libsettings.la

test_event_stats_SOURCES = test-event-stats.c
test_event_stats_LDADD = $(test_event_stats_libs) $(test_libs)
test_event_stats_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
