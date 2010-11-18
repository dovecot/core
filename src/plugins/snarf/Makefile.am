AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

lib05_snarf_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib05_snarf_plugin.la

lib05_snarf_plugin_la_SOURCES = \
	snarf-plugin.c

noinst_HEADERS = \
	snarf-plugin.h
