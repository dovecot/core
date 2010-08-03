pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = pop3-login

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/login-common

pop3_login_LDADD = \
	$(LIBDOVECOT_LOGIN) \
	$(LIBDOVECOT) \
	$(SSL_LIBS)
pop3_login_DEPENDENCIES = \
	$(LIBDOVECOT_LOGIN) \
	$(LIBDOVECOT_DEPS)

pop3_login_SOURCES = \
	client.c \
	client-authenticate.c \
	pop3-login-settings.c \
	pop3-proxy.c

noinst_HEADERS = \
	client.h \
	client-authenticate.h \
	pop3-login-settings.h \
	pop3-proxy.h
