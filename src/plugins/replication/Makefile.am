AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/replication \
	-I$(top_srcdir)/src/plugins/notify

NOPLUGIN_LDFLAGS =
lib20_replication_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_replication_plugin.la

if DOVECOT_PLUGIN_DEPS
lib20_replication_plugin_la_LIBADD = \
	../notify/lib15_notify_plugin.la
endif

lib20_replication_plugin_la_SOURCES = \
	replication-plugin.c

noinst_HEADERS = \
	replication-plugin.h
