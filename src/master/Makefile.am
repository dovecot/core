pkglibexecdir = $(libexecdir)/dovecot

sbin_PROGRAMS = dovecot

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DMODULEDIR=\""$(moduledir)"\" \
	-DSSLDIR=\""$(ssldir)\""

dovecot_LDADD = \
	../lib-settings/libsettings.a \
	../lib/liblib.a \
	$(SSL_LIBS)

dovecot_SOURCES = \
	auth-process.c \
	askpass.c \
	dict-process.c \
	log.c \
	login-process.c \
	mail-process.c \
	main.c \
	master-settings.c \
	syslog-util.c \
	ssl-init.c \
	ssl-init-gnutls.c \
	ssl-init-openssl.c

noinst_HEADERS = \
	auth-process.h \
	askpass.h \
	dict-process.h \
	common.h \
	log.h \
	login-process.h \
	mail-process.h \
	master-login-interface.h \
	master-settings.h \
	syslog-util.h \
	ssl-init.h
