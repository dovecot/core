pkglibexecdir = $(libexecdir)/dovecot

# Refer to comment in imap-urlauth.c for info on what these binaries are for.
pkglibexec_PROGRAMS = imap-urlauth-login

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth-client \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-login \
	$(BINARY_CFLAGS)

imap_urlauth_login_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/login-common

imap_urlauth_login_LDADD = \
	$(LIBDOVECOT_LOGIN) \
	$(LIBDOVECOT) \
	$(SSL_LIBS) \
	$(BINARY_LDFLAGS)

imap_urlauth_login_DEPENDENCIES = \
	$(LIBDOVECOT_LOGIN_DEPS) \
	$(LIBDOVECOT_DEPS)

imap_urlauth_login_SOURCES = \
	imap-urlauth-login.c \
	imap-urlauth-login-settings.c

noinst_HEADERS = \
	imap-urlauth-login-settings.h
