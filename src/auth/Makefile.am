pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = dovecot-auth

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-DAUTH_MODULE_DIR=\""$(libdir)/dovecot/auth"\" \
	$(VPOPMAIL_CFLAGS)

dovecot_auth_LDADD = \
	../lib-settings/libsettings.a \
	../lib/liblib.a \
	$(PASSDB_LIBS) \
	$(SASL_LIBS) \
	$(VPOPMAIL_LIBS)

if AUTH_MODULES
dovecot_auth_LDFLAGS = -export-dynamic
endif

dovecot_auth_SOURCES = \
	auth-module.c \
	db-ldap.c \
	db-passwd-file.c \
	login-connection.c \
	main.c \
	master-connection.c \
	mech.c \
	mech-cyrus-sasl2.c \
	mech-plain.c \
	mech-digest-md5.c \
	mycrypt.c \
	passdb.c \
	passdb-ldap.c \
	passdb-passwd.c \
	passdb-passwd-file.c \
	passdb-pam.c \
	passdb-shadow.c \
	passdb-vpopmail.c \
	userdb.c \
	userdb-ldap.c \
	userdb-passwd.c \
	userdb-passwd-file.c \
	userdb-static.c \
	userdb-vpopmail.c

noinst_HEADERS = \
	auth-login-interface.h \
	auth-master-interface.h \
	auth-mech-desc.h \
	auth-module.h \
	db-ldap.h \
	db-passwd-file.h \
	common.h \
	login-connection.h \
	master-connection.h \
	mech.h \
	mycrypt.h \
	passdb.h \
	userdb.h \
	userdb-vpopmail.h
