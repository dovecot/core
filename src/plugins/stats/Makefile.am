AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

NOPLUGIN_LDFLAGS =
lib90_stats_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib90_stats_plugin.la

lib90_stats_plugin_la_SOURCES = \
	stats-connection.c \
	stats-plugin.c

noinst_HEADERS = \
	stats-connection.h \
	stats-plugin.h
