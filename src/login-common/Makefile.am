noinst_LIBRARIES = liblogin-common.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-DPKG_RUNDIR=\""$(localstatedir)/run/$(PACKAGE)"\" \
	-DSBINDIR=\""$(sbindir)"\"

liblogin_common_a_SOURCES = \
	auth-common.c \
	auth-connection.c \
	main.c \
	master.c \
	ssl-proxy.c \
	ssl-proxy-gnutls.c \
	ssl-proxy-openssl.c

noinst_HEADERS = \
	auth-common.h \
	auth-connection.h \
	client-common.h \
	common.h \
	master.h \
	ssl-proxy.h
