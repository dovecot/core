pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = imap-login

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-sasl \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/login-common \
	$(BINARY_CFLAGS)

imap_login_LDADD = \
	$(LIBDOVECOT_LOGIN) \
	$(LIBDOVECOT) \
	$(SSL_LIBS) \
	$(BINARY_LDFLAGS)

imap_login_DEPENDENCIES = \
	$(LIBDOVECOT_LOGIN) \
	$(LIBDOVECOT_DEPS)

imap_login_SOURCES = \
	imap-login-client.c \
	client-authenticate.c \
	imap-login-commands.c \
	imap-login-settings.c \
	imap-proxy.c

noinst_HEADERS = \
	client-authenticate.h \
	imap-proxy.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = \
	imap-login-client.h \
	imap-login-commands.h \
	imap-login-settings.h
