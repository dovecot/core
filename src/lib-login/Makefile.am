pkgsysconfdir = $(sysconfdir)/dovecot

noinst_LTLIBRARIES = liblogin.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-auth-client \
	-I$(top_srcdir)/src/lib-master

liblogin_la_SOURCES = \
	login-client.c \
	login-server.c \
	login-server-auth.c

headers = \
	login-client.h \
	login-interface.h \
	login-server.h \
	login-server-auth.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-login-server-auth

noinst_PROGRAMS = $(test_programs)

test_libs = \
	liblogin.la \
	../lib-master/libmaster.la \
	../lib-auth-client/libauth-client.la \
	../lib-dns/libdns.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-settings/libsettings.la \
	../lib-test/libtest.la \
	../lib/liblib.la \
	$(MODULE_LIBS)

test_deps = \
	liblogin.la \
	../lib-master/libmaster.la \
	../lib-auth-client/libauth-client.la \
	../lib-dns/libdns.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-settings/libsettings.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_login_server_auth_SOURCES = test-login-server-auth.c
test_login_server_auth_LDADD = $(test_libs)
test_login_server_auth_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
