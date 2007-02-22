noinst_LIBRARIES = libcharset.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libcharset_a_SOURCES = \
	charset-iconv.c \
	charset-utf8.c

headers = \
	charset-utf8.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-charset
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
