noinst_LIBRARIES = libauth.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libauth_a_SOURCES = \
	auth-client.c \
	auth-server-connection.c \
	auth-server-request.c

headers = \
	auth-client.h \
	auth-server-connection.h \
	auth-server-request.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-auth
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
