noinst_LTLIBRARIES = libauth.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libauth_la_SOURCES = \
	auth-client.c \
	auth-master.c \
	auth-server-connection.c \
	auth-server-request.c

headers = \
	auth-client.h \
	auth-client-interface.h \
	auth-master.h \
	auth-server-connection.h \
	auth-server-request.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
