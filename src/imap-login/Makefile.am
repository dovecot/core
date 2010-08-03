pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = imap-login

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/login-common

imap_login_LDADD = \
	$(LIBDOVECOT_LOGIN) \
	$(LIBDOVECOT) \
	$(SSL_LIBS)
imap_login_DEPENDENCIES = \
	$(LIBDOVECOT_LOGIN) \
	$(LIBDOVECOT_DEPS)

imap_login_SOURCES = \
	client.c \
	client-authenticate.c \
	imap-login-settings.c \
	imap-proxy.c

noinst_HEADERS = \
	client.h \
	client-authenticate.h \
	imap-login-settings.h \
	imap-proxy.h
