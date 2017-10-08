pkglib_LTLIBRARIES = libdovecot-ldap.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	$(LDAP_CFLAGS)

libdovecot_ldap_la_SOURCES = \
	ldap-client.c \
	ldap-connection.c \
	ldap-connection-pool.c \
	ldap-iterator.c \
	ldap-search.c \
	ldap-compare.c \
	ldap-entry.c

libdovecot_ldap_la_DEPENDENCIES = ../lib-dovecot/libdovecot.la
libdovecot_ldap_la_LDFLAGS = -export-dynamic
libdovecot_ldap_la_LIBADD = ../lib-dovecot/libdovecot.la $(LDAP_LIBS)

headers = \
	ldap-client.h

noinst_HEADERS = \
	ldap-connection-pool.h \
	ldap-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_libs = \
	../lib-test/libtest.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib/liblib.la

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
