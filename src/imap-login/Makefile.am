pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = imap-login

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/login-common

imap_login_LDADD = \
	../login-common/liblogin-common.a \
	../lib-imap/imap-parser.o \
	../lib-auth/libauth.a \
	../lib/liblib.a \
	$(SSL_LIBS)

imap_login_SOURCES = \
	client.c \
	client-authenticate.c

noinst_HEADERS = \
	client.h \
	client-authenticate.h
