AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-http \
	-I$(top_srcdir)/src/lib-settings

noinst_LTLIBRARIES=liboauth2.la

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = \
	oauth2.h

noinst_HEADERS = \
	oauth2-private.h

liboauth2_la_SOURCES = \
	oauth2.c \
	oauth2-token-validate.c \
	oauth2-passwd-grant.c \
	oauth2-introspect.c \
	oauth2-refresh.c

check_programs = \
	oauth2-server \
	test-oauth2
