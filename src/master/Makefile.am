pkglibexecdir = $(libexecdir)/dovecot

sbin_PROGRAMS = dovecot

if HAVE_SYSTEMD
SYSTEMD_SOURCES = sd-daemon.c
endif


AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DPKG_STATEDIR=\""$(statedir)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DBINDIR=\""$(bindir)"\" \
	$(BINARY_CFLAGS)

dovecot_LDADD = \
	$(LIBCAP) \
	$(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

dovecot_DEPENDENCIES = $(LIBDOVECOT_DEPS)

dovecot_SOURCES = \
	capabilities-posix.c \
	dup2-array.c \
	main.c \
	master-client.c \
	master-settings.c \
	service-anvil.c \
	service-listen.c \
	service-log.c \
	service-monitor.c \
	service-process.c \
	service-process-notify.c \
	service.c \
	$(SYSTEMD_SOURCES)

noinst_HEADERS = \
	capabilities.h \
	common.h \
	dup2-array.h \
	master-client.h \
	master-settings.h \
	sd-daemon.h \
	service-anvil.h \
	service-listen.h \
	service-log.h \
	service-monitor.h \
	service-process.h \
	service-process-notify.h \
	service.h

test_programs = \
	test-auth-client \
	test-auth-master \
	test-master-login-auth

test_nocheck_programs =

noinst_PROGRAMS = $(test_programs) $(test_nocheck_programs)

test_libs = \
	../lib-auth/libauth.la \
	../lib-master/libmaster.la \
	../lib-dns/libdns.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-settings/libsettings.la \
	../lib-test/libtest.la \
	../lib/liblib.la \
	$(MODULE_LIBS)

test_deps = \
	../lib-auth/libauth.la \
	../lib-master/libmaster.la \
	../lib-dns/libdns.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-settings/libsettings.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_auth_client_SOURCES = test-auth-client.c
test_auth_client_LDADD = $(test_libs)
test_auth_client_DEPENDENCIES = $(test_deps)

test_auth_master_SOURCES = test-auth-master.c
test_auth_master_LDADD = $(test_libs)
test_auth_master_DEPENDENCIES = $(test_deps)

test_master_login_auth_SOURCES = test-master-login-auth.c
test_master_login_auth_LDADD = $(test_libs)
test_master_login_auth_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
