noinst_LIBRARIES = libpassword.a

pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = dovecot-auth checkpassword-reply

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-sql \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-ntlm \
	-DAUTH_MODULE_DIR=\""$(moduledir)/auth"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	$(AUTH_CFLAGS)

libpassword_a_SOURCES = \
	mycrypt.c \
	password-scheme.c \
	password-scheme-md5crypt.c \
	password-scheme-cram-md5.c \
	password-scheme-ntlm.c \
	password-scheme-rpa.c

dovecot_auth_LDADD = \
	libpassword.a \
	../lib-settings/libsettings.a \
	../lib-ntlm/libntlm.a \
	../lib-sql/libsql.a \
	../lib/liblib.a \
	$(AUTH_LIBS) \
	$(RAND_LIBS) \
	$(MODULE_LIBS)

dovecot_auth_SOURCES = \
	auth-client-connection.c \
	auth-master-connection.c \
	auth-module.c \
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
	mech-rpa.c \
	mech-apop.c \
	passdb.c \
	passdb-bsdauth.c \
	passdb-ldap.c \
	passdb-passwd.c \
	passdb-passwd-file.c \
	passdb-pam.c \
	passdb-checkpassword.c \
	passdb-shadow.c \
	passdb-vpopmail.c \
	passdb-sql.c \
	userdb.c \
	userdb-ldap.c \
	userdb-passwd.c \
	userdb-passwd-file.c \
	userdb-static.c \
	userdb-vpopmail.c \
	userdb-sql.c

noinst_HEADERS = \
	auth-client-connection.h \
	auth-client-interface.h \
	auth-master-interface.h \
	auth-master-connection.h \
	auth-module.h \
	db-ldap.h \
	db-sql.h \
	db-passwd-file.h \
	common.h \
	mech.h \
	mycrypt.h \
	passdb.h \
	password-scheme.h \
	userdb.h \
	userdb-vpopmail.h

checkpassword_reply_LDADD = \
	../lib/liblib.a

checkpassword_reply_sources = \
	checkpassword-reply.c
