pkgsysconfdir = $(sysconfdir)/dovecot

noinst_LTLIBRARIES = liblogin.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-master

liblogin_la_SOURCES = \
	master-auth.c \
	master-login.c \
	master-login-auth.c

headers = \
	master-auth.h \
	master-login.h \
	master-login-auth.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
