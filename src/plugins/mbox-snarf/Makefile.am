AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

lib20_mbox_snarf_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_mbox_snarf_plugin.la

lib20_mbox_snarf_plugin_la_SOURCES = \
	mbox-snarf-plugin.c

noinst_HEADERS = \
	mbox-snarf-plugin.h
