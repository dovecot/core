pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = pop3-login

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/login-common

pop3_login_LDADD = \
	../login-common/liblogin-common.a \
	../lib/liblib.a \
	$(SSL_LIBS)

pop3_login_SOURCES = \
	client.c \
	client-authenticate.c

noinst_HEADERS = \
	common.h \
	client.h
