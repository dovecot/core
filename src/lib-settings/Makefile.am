noinst_LIBRARIES = libsettings.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libsettings_a_SOURCES = \
	settings.c

headers = \
	settings.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-settings
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
