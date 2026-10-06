AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-var-expand \
	-I$(top_srcdir)/src/plugins/notify

NOPLUGIN_LDFLAGS =
lib20_mail_log_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_mail_log_plugin.la

lib20_mail_log_plugin_la_SOURCES = \
	mail-log-plugin.c

noinst_HEADERS = \
	mail-log-plugin.h
