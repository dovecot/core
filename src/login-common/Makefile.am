noinst_LTLIBRARIES = liblogin.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DPKG_STATEDIR=\""$(statedir)"\" \
	-DSBINDIR=\""$(sbindir)"\" \
	-DSSLDIR=\""$(ssldir)\""

liblogin_la_SOURCES = \
	client-common.c \
	login-proxy.c \
	login-settings.c \
	main.c \
	master.c \
	sasl-server.c \
	ssl-proxy.c \
	ssl-proxy-gnutls.c \
	ssl-proxy-openssl.c

liblogin_la_LIBADD = \
	$(SSL_LIBS)

noinst_HEADERS = \
	client-common.h \
	login-proxy.h \
	login-settings.h \
	common.h \
	master.h \
	sasl-server.h \
	ssl-proxy.h

pkglib_LTLIBRARIES = libdovecot-login.la
libdovecot_login_la_SOURCES = 
libdovecot_login_la_LIBADD = liblogin.la
libdovecot_login_la_DEPENDENCIES = liblogin.la
libdovecot_login_la_LDFLAGS = -export-dynamic
