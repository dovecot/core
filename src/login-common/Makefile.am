noinst_LTLIBRARIES = liblogin.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth-client \
	-I$(top_srcdir)/src/lib-sasl \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-login \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-var-expand \
	-DPKG_STATEDIR=\""$(statedir)"\" \
	-DMODULEDIR=\""$(moduledir)"\"

liblogin_la_SOURCES = \
	client-common.c \
	client-common-auth.c \
	login-proxy.c \
	login-proxy-state.c \
	login-settings.c \
	main.c \
	sasl-server.c

headers = \
	client-common.h \
	login-common.h \
	login-proxy.h \
	login-proxy-state.h \
	login-settings.h \
	sasl-server.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

pkglib_LTLIBRARIES = libdovecot-login.la
libdovecot_login_la_SOURCES =
libdovecot_login_la_LIBADD = liblogin.la $(LIBDOVECOT) $(SSL_LIBS)
libdovecot_login_la_DEPENDENCIES = liblogin.la $(LIBDOVECOT_DEPS)
libdovecot_login_la_LDFLAGS = -export-dynamic
