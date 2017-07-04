AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/plugins/notify

NOPLUGIN_LDFLAGS =
lib20_notify_status_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_notify_status_plugin.la

lib20_notify_status_plugin_la_SOURCES = \
	notify-status-plugin.c
