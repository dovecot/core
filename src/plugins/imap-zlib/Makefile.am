AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-compression \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/imap

imap_moduledir = $(moduledir)

NOPLUGIN_LDFLAGS =
lib30_imap_zlib_plugin_la_LDFLAGS = -module -avoid-version

imap_module_LTLIBRARIES = \
	lib30_imap_zlib_plugin.la

lib30_imap_zlib_plugin_la_LIBADD = \
	../../lib-compression/libcompression.la

lib30_imap_zlib_plugin_la_SOURCES = \
	imap-zlib-plugin.c

noinst_HEADERS = \
	imap-zlib-plugin.h
