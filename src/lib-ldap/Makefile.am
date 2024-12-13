noinst_LTLIBRARIES = libdldap.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-var-expand \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	$(LDAP_CFLAGS)

libdldap_la_SOURCES = \
	ldap-client.c \
	ldap-connection.c \
	ldap-connection-pool.c \
	ldap-iterator.c \
	ldap-search.c \
	ldap-settings.c \
	ldap-utils.c \
	ldap-compare.c \
	ldap-entry.c

libdldap_la_DEPENDENCIES = $(LIBDOVECOT_DEPS)
libdldap_la_LIBADD = $(LDAP_LIBS)

pkglib_LTLIBRARIES = libdovecot-ldap.la
libdovecot_ldap_la_SOURCES =
libdovecot_ldap_la_LIBADD = libdldap.la $(LIBDOVECOT)
libdovecot_ldap_la_DEPENDENCIES = libdldap.la $(LIBDOVECOT_DEPS)
libdovecot_ldap_la_LDFLAGS = -export-dynamic

headers = \
	ldap-client.h \
	ldap-utils.h

noinst_HEADERS = \
	ldap-connection-pool.h \
	ldap-private.h \
	ldap-settings.h \
	ldap-settings-parse.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_libs = \
	../lib-test/libtest.la \
	../lib-var-expand/libvar_expand.la \
	../lib/liblib.la

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
