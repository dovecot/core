noinst_LIBRARIES = libpassword.a
auth_moduledir = $(moduledir)/auth

if GSSAPI_PLUGIN
GSSAPI_LIB = libmech_gssapi.la
endif

if LDAP_PLUGIN
LDAP_LIB = libauthdb_ldap.la
endif

auth_module_LTLIBRARIES = \
	$(GSSAPI_LIB) \
	$(LDAP_LIB)

pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = dovecot-auth checkpassword-reply

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-sql \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-ntlm \
	-I$(top_srcdir)/src/lib-otp \
	-I$(top_srcdir)/src/lib-master \
	-DAUTH_MODULE_DIR=\""$(auth_moduledir)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	$(AUTH_CFLAGS)

dovecot_auth_LDFLAGS = -export-dynamic

libpassword_a_SOURCES = \
	mycrypt.c \
	password-scheme.c \
	password-scheme-md5crypt.c \
	password-scheme-otp.c \
	password-scheme-rpa.c

dovecot_auth_libs = \
	libpassword.a \
	../lib-ntlm/libntlm.a \
	../lib-otp/libotp.a \
	$(LIBDOVECOT_SQL)

dovecot_auth_LDADD = $(dovecot_auth_libs) $(LIBDOVECOT) $(AUTH_LIBS) $(MODULE_LIBS)
dovecot_auth_DEPENDENCIES = $(dovecot_auth_libs) $(LIBDOVECOT_DEPS)

ldap_sources = db-ldap.c passdb-ldap.c userdb-ldap.c

dovecot_auth_SOURCES = \
	auth.c \
	auth-cache.c \
	auth-client-connection.c \
	auth-master-connection.c \
	mech-otp-skey-common.c \
	mech-plain-common.c \
	auth-request.c \
	auth-request-handler.c \
	auth-settings.c \
	auth-stream.c \
	auth-worker-client.c \
	auth-worker-server.c \
	db-checkpassword.c \
	db-sql.c \
	db-passwd-file.c \
	main.c \
	mech.c \
	mech-anonymous.c \
	mech-plain.c \
	mech-login.c \
	mech-cram-md5.c \
	mech-digest-md5.c \
	mech-external.c \
	mech-gssapi.c \
	mech-ntlm.c \
	mech-otp.c \
	mech-skey.c \
	mech-rpa.c \
	mech-apop.c \
	mech-winbind.c \
	passdb.c \
	passdb-blocking.c \
	passdb-bsdauth.c \
	passdb-cache.c \
	passdb-checkpassword.c \
	passdb-passwd.c \
	passdb-passwd-file.c \
	passdb-pam.c \
	passdb-shadow.c \
	passdb-sia.c \
	passdb-vpopmail.c \
	passdb-sql.c \
	userdb.c \
	userdb-blocking.c \
	userdb-checkpassword.c \
	userdb-nss.c \
	userdb-passwd.c \
	userdb-passwd-file.c \
	userdb-prefetch.c \
	userdb-static.c \
	userdb-vpopmail.c \
	userdb-sql.c \
	$(ldap_sources)

headers = \
	auth.h \
	auth-cache.h \
	auth-client-connection.h \
	auth-common.h \
	auth-master-connection.h \
	mech-otp-skey-common.h \
	mech-plain-common.h \
	auth-request.h \
	auth-request-handler.h \
	auth-settings.h \
	auth-stream.h \
	auth-worker-client.h \
	auth-worker-server.h \
	db-ldap.h \
	db-sql.h \
	db-passwd-file.h \
	db-checkpassword.h \
	mech.h \
	mycrypt.h \
	passdb.h \
	passdb-blocking.h \
	passdb-cache.h \
	password-scheme.h \
	userdb.h \
	userdb-blocking.h \
	userdb-static.h \
	userdb-vpopmail.h

if GSSAPI_PLUGIN
libmech_gssapi_la_LDFLAGS = -module -avoid-version
libmech_gssapi_la_LIBADD = $(KRB5_LIBS)
libmech_gssapi_la_CPPFLAGS = $(AM_CPPFLAGS) $(KRB5_CFLAGS) -DPLUGIN_BUILD
libmech_gssapi_la_SOURCES = mech-gssapi.c
endif

if LDAP_PLUGIN
libauthdb_ldap_la_LDFLAGS = -module -avoid-version
libauthdb_ldap_la_LIBADD = $(LDAP_LIBS)
libauthdb_ldap_la_CPPFLAGS = $(AM_CPPFLAGS) -DPLUGIN_BUILD
libauthdb_ldap_la_SOURCES = $(ldap_sources)
endif

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif

checkpassword_reply_LDADD = $(LIBDOVECOT)
checkpassword_reply_DEPENDENCIES = $(LIBDOVECOT_DEPS)

checkpassword_reply_sources = \
	checkpassword-reply.c
