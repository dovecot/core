noinst_LIBRARIES = liblogin-common.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-DPKG_RUNDIR=\""$(localstatedir)/run/$(PACKAGE)"\" \
	-DSBINDIR=\""$(sbindir)"\"

liblogin_common_a_SOURCES = \
	client-common.c \
	main.c \
	master.c \
	sasl-server.c \
	ssl-proxy.c \
	ssl-proxy-gnutls.c \
	ssl-proxy-openssl.c

noinst_HEADERS = \
	client-common.h \
	common.h \
	master.h \
	ssl-proxy.h
