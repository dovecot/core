noinst_LTLIBRARIES = libsasl.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libsasl_la_SOURCES = \
	mech-login.c \
	mech-plain.c \
	sasl-client.c 

headers = \
	sasl-client.h \
	sasl-client-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
