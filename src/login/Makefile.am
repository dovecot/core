pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = imap-login

INCLUDES = \
	-I$(top_srcdir)/src/lib

imap_login_LDADD = \
	../lib/liblib.a \
	$(SSL_LIBS)

imap_login_SOURCES = \
	auth-connection.c \
	client.c \
	client-authenticate.c \
	main.c \
	master.c \
	ssl-proxy.c \
	ssl-proxy-gnutls.c \
	ssl-proxy-openssl.c

noinst_HEADERS = \
	auth-connection.h \
	common.h \
	client.h \
	client-authenticate.h \
	master.h \
	ssl-proxy.h
