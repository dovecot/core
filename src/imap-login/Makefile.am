pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = imap-login

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/login-common

imap_login_LDADD = \
	../login-common/libdovecot-login.la \
	../lib-dovecot/libdovecot.la

imap_login_SOURCES = \
	client.c \
	client-authenticate.c \
	imap-proxy.c

noinst_HEADERS = \
	client.h \
	client-authenticate.h \
	imap-proxy.h
