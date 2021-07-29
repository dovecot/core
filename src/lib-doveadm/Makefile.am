noinst_LTLIBRARIES = libdoveadm.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-ssl-iostream

libdoveadm_la_SOURCES = \
	doveadm-client.c \
	doveadm-protocol.c

headers = \
	doveadm-client.h \
	doveadm-protocol.h

pkginc_libdir = $(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
