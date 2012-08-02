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

noinst_HEADERS = \
	iostream-openssl.h \
	iostream-ssl.h
