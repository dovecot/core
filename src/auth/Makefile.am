pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = imap-auth

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	$(VPOPMAIL_CFLAGS)

imap_auth_LDADD = \
	../lib/liblib.a \
	$(PASSDB_LIBS) \
	$(SASL_LIBS) \
	$(VPOPMAIL_LIBS)

imap_auth_SOURCES = \
	login-connection.c \
	main.c \
	master-connection.c \
	mech.c \
	mech-cyrus-sasl2.c \
	mech-plain.c \
	mech-digest-md5.c \
	mycrypt.c \
	passdb.c \
	passdb-passwd.c \
	passdb-passwd-file.c \
	passdb-pam.c \
	passdb-shadow.c \
	passdb-vpopmail.c \
	passwd-file.c \
	userdb.c \
	userdb-passwd.c \
	userdb-passwd-file.c \
	userdb-static.c \
	userdb-vpopmail.c

noinst_HEADERS = \
	auth-login-interface.h \
	auth-master-interface.h \
	auth-mech-desc.h \
	common.h \
	login-connection.h \
	master-connection.h \
	mech.h \
	mycrypt.h \
	passdb.h \
	passwd-file.h \
	userdb.h \
	userdb-vpopmail.h
