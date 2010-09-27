AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/dbox-common

lib20_zlib_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_zlib_plugin.la

if BUILD_ZLIB
ZLIB_LIB = -lz
endif
if BUILD_BZLIB
BZLIB_LIB = -lbz2
endif

lib20_zlib_plugin_la_LIBADD = \
	$(ZLIB_LIB) $(BZLIB_LIB)

lib20_zlib_plugin_la_SOURCES = \
	istream-bzlib.c \
	istream-zlib.c \
	ostream-zlib.c \
	ostream-bzlib.c \
	zlib-plugin.c

noinst_HEADERS = \
	istream-zlib.h \
	ostream-zlib.h \
	zlib-plugin.h
