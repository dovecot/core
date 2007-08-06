noinst_LIBRARIES = libpassword.a

pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = dovecot-auth checkpassword-reply

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-sql \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-ntlm \
	-I$(top_srcdir)/src/lib-otp \
	-DAUTH_MODULE_DIR=\""$(moduledir)/auth"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	$(AUTH_CFLAGS)

dovecot_auth_LDFLAGS = -export-dynamic

libpassword_a_SOURCES = \
	mycrypt.c \
	password-scheme.c \
	password-scheme-md5crypt.c \
	password-scheme-otp.c \
	password-scheme-rpa.c

dovecot_auth_LDADD = \
	libpassword.a \
	../lib-settings/libsettings.a \
	../lib-ntlm/libntlm.a \
	../lib-otp/libotp.a \
	../lib-sql/libsql.a \
	../lib/liblib.a \
	$(AUTH_LIBS) \
	$(RAND_LIBS) \
	$(MODULE_LIBS)

dovecot_auth_SOURCES = \
	auth.c \
	auth-cache.c \
	auth-client-connection.c \
	auth-master-connection.c \
	auth-master-listener.c \
	auth-module.c \
	auth-request.c \
	auth-request-handler.c \
	auth-stream.c \
	auth-worker-client.c \
	auth-worker-server.c \
	db-ldap.c \
	db-sql.c \
	db-passwd-file.c \
	main.c \
	mech.c \
	mech-anonymous.c \
	mech-plain.c \
	mech-login.c \
	mech-cram-md5.c \
	mech-digest-md5.c \
	mech-ntlm.c \
	mech-otp.c \
	mech-skey.c \
	mech-gssapi.c \
	mech-rpa.c \
	mech-apop.c \
	mech-winbind.c \
	otp-skey-common.c \
	plain-common.c \
	passdb.c \
	passdb-blocking.c \
	passdb-bsdauth.c \
	passdb-cache.c \
	passdb-checkpassword.c \
	passdb-ldap.c \
	passdb-passwd.c \
	passdb-passwd-file.c \
	passdb-pam.c \
	passdb-shadow.c \
	passdb-sia.c \
	passdb-vpopmail.c \
	passdb-sql.c \
	userdb.c \
	userdb-blocking.c \
	userdb-ldap.c \
	userdb-nss.c \
	userdb-passwd.c \
	userdb-passwd-file.c \
	userdb-prefetch.c \
	userdb-static.c \
	userdb-vpopmail.c \
	userdb-sql.c

headers = \
	auth.h \
	auth-cache.h \
	auth-client-connection.h \
	auth-client-interface.h \
	auth-master-interface.h \
	auth-master-connection.h \
	auth-master-listener.h \
	auth-module.h \
	auth-request.h \
	auth-request-handler.h \
	auth-stream.h \
	auth-worker-client.h \
	auth-worker-server.h \
	db-ldap.h \
	db-sql.h \
	db-passwd-file.h \
	common.h \
	mech.h \
	mycrypt.h \
	otp-skey-common.h \
	plain-common.h \
	passdb.h \
	passdb-blocking.h \
	passdb-cache.h \
	password-scheme.h \
	userdb.h \
	userdb-blocking.h \
	userdb-vpopmail.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/auth
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif

checkpassword_reply_LDADD = \
	../lib/liblib.a

checkpassword_reply_sources = \
	checkpassword-reply.c
