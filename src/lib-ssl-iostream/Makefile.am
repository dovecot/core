noinst_LTLIBRARIES = libssl_iostream.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

libssl_iostream_la_SOURCES = \
	iostream-openssl.c \
	iostream-openssl-context.c \
	iostream-openssl-params.c \
	istream-openssl.c \
	ostream-openssl.c

libssl_iostream_la_LIBADD = \
	$(SSL_LIBS)

headers = \
	iostream-openssl.h \
	iostream-ssl.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

pkglib_LTLIBRARIES = libdovecot-ssl.la
libdovecot_ssl_la_SOURCES = 
libdovecot_ssl_la_LIBADD = libssl_iostream.la ../lib-dovecot/libdovecot.la
libdovecot_ssl_la_DEPENDENCIES = libssl_iostream.la
libdovecot_ssl_la_LDFLAGS = -export-dynamic
