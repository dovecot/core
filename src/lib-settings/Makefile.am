noinst_LIBRARIES = libsettings.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libsettings_a_SOURCES = \
	settings.c \
	settings-parser.c

headers = \
	settings.h \
	settings-parser.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-settings
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
