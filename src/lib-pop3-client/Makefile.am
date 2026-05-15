include $(top_srcdir)/Makefile.test.include

noinst_LTLIBRARIES = libpop3_client.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-dns-client \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-sasl \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-pop3 \
	-I$(top_srcdir)/src/lib-var-expand

libpop3_client_la_SOURCES = \
	pop3c-client.c \
	pop3c-settings.c

headers = \
	pop3c-client.h \
	pop3c-settings.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
