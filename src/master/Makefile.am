pkglibexecdir = $(libexecdir)/dovecot

sbin_PROGRAMS = dovecot

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DPKG_RUNDIR=\""$(localstatedir)/run/$(PACKAGE)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DSSLDIR=\""$(ssldir)\""

dovecot_LDADD = \
	../lib/liblib.a \
	$(SSL_LIBS)

dovecot_SOURCES = \
	auth-process.c \
	login-process.c \
	mail-process.c \
	main.c \
	settings.c \
	ssl-init.c \
	ssl-init-gnutls.c \
	ssl-init-openssl.c

noinst_HEADERS = \
	auth-process.h \
	common.h \
	login-process.h \
	mail-process.h \
	master-login-interface.h \
	settings.h \
	ssl-init.h
