pkglibexecdir = $(libexecdir)/dovecot

sbin_PROGRAMS = imap-master

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DPKG_RUNDIR=\""$(localstatedir)/run/$(PACKAGE)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DSSLDIR=\""$(ssldir)\""

imap_master_LDADD = \
	../lib/liblib.a \
	$(SSL_LIBS)

imap_master_SOURCES = \
	auth-process.c \
	imap-process.c \
	login-process.c \
	main.c \
	settings.c \
	ssl-init.c \
	ssl-init-gnutls.c \
	ssl-init-openssl.c

noinst_HEADERS = \
	auth-process.h \
	common.h \
	imap-process.h \
	login-process.h \
	master-login-interface.h \
	settings.h \
	ssl-init.h
