AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

lib20_listescape_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_listescape_plugin.la

lib20_listescape_plugin_la_SOURCES = \
	listescape-plugin.c

noinst_HEADERS = \
	listescape-plugin.h
