noinst_LIBRARIES = liblogin-common.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DPKG_STATEDIR=\""$(statedir)"\" \
	-DSBINDIR=\""$(sbindir)"\"

liblogin_common_a_SOURCES = \
	client-common.c \
	login-proxy.c \
	main.c \
	master.c \
	sasl-server.c \
	ssl-proxy.c \
	ssl-proxy-gnutls.c \
	ssl-proxy-openssl.c

noinst_HEADERS = \
	client-common.h \
	login-proxy.h \
	common.h \
	master.h \
	sasl-server.h \
	ssl-proxy.h
