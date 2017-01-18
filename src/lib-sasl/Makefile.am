noinst_LTLIBRARIES = libsasl.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libsasl_la_SOURCES = \
	mech-external.c \
	mech-login.c \
	mech-plain.c \
	mech-oauthbearer.c \
	dsasl-client.c 

headers = \
	dsasl-client.h \
	dsasl-client-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
