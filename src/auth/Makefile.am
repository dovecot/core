pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = dovecot-auth

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-DAUTH_MODULE_DIR=\""$(libdir)/dovecot/auth"\" \
	$(AUTH_CFLAGS)

dovecot_auth_LDADD = \
	../lib-settings/libsettings.a \
	../lib/liblib.a \
	$(AUTH_LIBS) \
	$(RAND_LIBS) \
	$(MODULE_LIBS)

dovecot_auth_SOURCES = \
	auth-client-connection.c \
	auth-master-connection.c \
	auth-module.c \
	db-ldap.c \
	db-pgsql.c \
	db-passwd-file.c \
	main.c \
	md5crypt.c \
	mech.c \
	mech-anonymous.c \
	mech-cyrus-sasl2.c \
	mech-plain.c \
	mech-digest-md5.c \
	mycrypt.c \
	passdb.c \
	passdb-bsdauth.c \
	passdb-ldap.c \
	passdb-passwd.c \
	passdb-passwd-file.c \
	passdb-pam.c \
	passdb-shadow.c \
	passdb-vpopmail.c \
	passdb-pgsql.c \
	password-scheme.c \
	userdb.c \
	userdb-ldap.c \
	userdb-passwd.c \
	userdb-passwd-file.c \
	userdb-static.c \
	userdb-vpopmail.c \
	userdb-pgsql.c

noinst_HEADERS = \
	auth-client-connection.h \
	auth-client-interface.h \
	auth-master-connection.h \
	auth-master-interface.h \
	auth-mech-desc.h \
	auth-module.h \
	db-ldap.h \
	db-pgsql.h \
	db-passwd-file.h \
	common.h \
	md5crypt.h \
	mech.h \
	mycrypt.h \
	passdb.h \
	password-scheme.h \
	userdb.h \
	userdb-vpopmail.h
