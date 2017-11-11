pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = submission-login

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-sasl \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-smtp \
	-I$(top_srcdir)/src/login-common

submission_login_LDADD = \
	$(LIBDOVECOT_LOGIN) \
	$(LIBDOVECOT) \
	$(SSL_LIBS)
submission_login_DEPENDENCIES = \
	$(LIBDOVECOT_LOGIN) \
	$(LIBDOVECOT_DEPS)

submission_login_SOURCES = \
	client.c \
	client-authenticate.c \
	submission-login-settings.c \
	submission-proxy.c

noinst_HEADERS = \
	client.h \
	client-authenticate.h \
	submission-login-settings.h \
	submission-proxy.h
