pkglibexecdir = $(libexecdir)/dovecot

sbin_PROGRAMS = dovecot
pkglibexec_PROGRAMS = ssl-build-param

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DPKG_STATEDIR=\""$(statedir)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DSSLDIR=\""$(ssldir)\""

dovecot_LDADD = \
	$(LIBCAP) \
	$(LIBDOVECOT)

dovecot_SOURCES = \
	auth-process.c \
	askpass.c \
	capabilities-posix.c \
	child-process.c \
	dict-process.c \
	dup2-array.c \
	listener.c \
	log.c \
	login-process.c \
	mail-process.c \
	master-settings.c \
	main.c \
	ssl-init.c \
	sysinfo-get.c

noinst_HEADERS = \
	auth-process.h \
	askpass.h \
	capabilities.h \
	child-process.h \
	dict-process.h \
	dup2-array.h \
	listener.h \
	common.h \
	log.h \
	login-process.h \
	mail-process.h \
	master-login-interface.h \
	master-settings.h \
	ssl-init.h \
	sysinfo-get.h

ssl_build_param_SOURCES = \
	ssl-init-main.c \
	ssl-init-openssl.c \
	ssl-init-gnutls.c

ssl_build_param_LDADD = \
	$(LIBDOVECOT) \
	$(SSL_LIBS)

