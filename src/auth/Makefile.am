pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = imap-auth

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	$(VPOPMAIL_CFLAGS)

imap_auth_LDADD = \
	../lib/liblib.a \
	$(USERINFO_LIBS) \
	$(VPOPMAIL_LIBS)

imap_auth_SOURCES = \
	auth.c \
	auth-plain.c \
	auth-digest-md5.c \
	cookie.c \
	login-connection.c \
	main.c \
	master.c \
	userinfo.c \
	userinfo-passwd.c \
	userinfo-shadow.c \
	userinfo-pam.c \
	userinfo-passwd-file.c \
	userinfo-vpopmail.c

noinst_HEADERS = \
	auth.h \
	auth-interface.h \
	common.h \
	cookie.h \
	login-connection.h \
	userinfo.h \
	userinfo-passwd.h
