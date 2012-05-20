noinst_LTLIBRARIES = libssl_iostream.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

if BUILD_OPENSSL
ssl_sources = \
	iostream-openssl.c \
	iostream-openssl-context.c \
	iostream-openssl-params.c \
	istream-openssl.c \
	ostream-openssl.c
else
ssl_sources = \
	iostream-ssl-none.c
endif

libssl_iostream_la_SOURCES = \
	$(ssl_sources)
libssl_iostream_la_LIBADD = \
	$(SSL_LIBS)

headers = \
	iostream-openssl.h \
	iostream-ssl.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

pkglib_LTLIBRARIES = libdovecot-ssl.la
libdovecot_ssl_la_SOURCES = 
libdovecot_ssl_la_LIBADD = libssl_iostream.la ../lib/liblib.la $(MODULE_LIBS) $(SSL_LIBS)
libdovecot_ssl_la_DEPENDENCIES = libssl_iostream.la
libdovecot_ssl_la_LDFLAGS = -export-dynamic
