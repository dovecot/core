noinst_LTLIBRARIES = liblogin.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-master \
	-DPKG_STATEDIR=\""$(statedir)"\"

liblogin_la_SOURCES = \
	access-lookup.c \
	client-common.c \
	client-common-auth.c \
	login-proxy.c \
	login-proxy-state.c \
	login-settings.c \
	main.c \
	sasl-server.c \
	ssl-proxy.c \
	ssl-proxy-gnutls.c \
	ssl-proxy-openssl.c

liblogin_la_LIBADD = \
	$(SSL_LIBS)

headers = \
	access-lookup.h \
	client-common.h \
	login-common.h \
	login-proxy.h \
	login-proxy-state.h \
	login-settings.h \
	sasl-server.h \
	ssl-proxy.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

pkglib_LTLIBRARIES = libdovecot-login.la
libdovecot_login_la_SOURCES = 
libdovecot_login_la_LIBADD = liblogin.la
libdovecot_login_la_DEPENDENCIES = liblogin.la
libdovecot_login_la_LDFLAGS = -export-dynamic
