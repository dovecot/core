pkglibexecdir = $(libexecdir)/dovecot

sbin_PROGRAMS = dovecot

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DPKG_RUNDIR=\""$(localstatedir)/run/$(PACKAGE)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DPKG_LIBDIR=\""$(libdir)/$(PACKAGE)"\" \
	-DSSLDIR=\""$(ssldir)\""

dovecot_LDADD = \
	../lib-settings/libsettings.a \
	../lib/liblib.a \
	$(SSL_LIBS)

dovecot_SOURCES = \
	auth-process.c \
	login-process.c \
	mail-process.c \
	main.c \
	master-settings.c \
	ssl-init.c \
	ssl-init-gnutls.c \
	ssl-init-openssl.c

noinst_HEADERS = \
	auth-process.h \
	common.h \
	login-process.h \
	mail-process.h \
	master-login-interface.h \
	master-settings.h \
	ssl-init.h
