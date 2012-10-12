AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-compression \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/dbox-common

NOPLUGIN_LDFLAGS =
lib20_zlib_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_zlib_plugin.la

lib20_zlib_plugin_la_LIBADD = \
	../../lib-compression/libcompression.la

lib20_zlib_plugin_la_SOURCES = \
	zlib-plugin.c

noinst_HEADERS = \
	zlib-plugin.h
