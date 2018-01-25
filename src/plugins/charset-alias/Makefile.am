AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-charset \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage 

NOPLUGIN_LDFLAGS =
lib20_charset_alias_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_charset_alias_plugin.la

lib20_charset_alias_plugin_la_SOURCES = \
	charset-alias-plugin.c

noinst_HEADERS = \
	charset-alias-plugin.h
