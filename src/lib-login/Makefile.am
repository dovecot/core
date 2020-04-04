pkgsysconfdir = $(sysconfdir)/dovecot

noinst_LTLIBRARIES = liblogin.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-master

liblogin_la_SOURCES = \
	master-auth.c \
	master-login.c \
	master-login-auth.c

headers = \
	master-auth.h \
	master-login.h \
	master-login-auth.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-master-login-auth

noinst_PROGRAMS = $(test_programs)

test_libs = \
	liblogin.la \
	../lib-master/libmaster.la \
	../lib-auth/libauth.la \
	../lib-dns/libdns.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-settings/libsettings.la \
	../lib-test/libtest.la \
	../lib/liblib.la \
	$(MODULE_LIBS)

test_deps = \
	liblogin.la \
	../lib-master/libmaster.la \
	../lib-auth/libauth.la \
	../lib-dns/libdns.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-settings/libsettings.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_master_login_auth_SOURCES = test-master-login-auth.c
test_master_login_auth_LDADD = $(test_libs)
test_master_login_auth_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
