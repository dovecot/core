AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-storage

lib20_autocreate_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_autocreate_plugin.la

lib20_autocreate_plugin_la_SOURCES = \
	autocreate-plugin.c

noinst_HEADERS = \
	autocreate-plugin.h
