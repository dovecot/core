AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/maildir \
	-I$(top_srcdir)/src/plugins/notify

lib20_mail_log_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_mail_log_plugin.la

if DOVECOT_PLUGIN_DEPS
lib20_mail_log_plugin_la_LIBADD = \
	../notify/lib15_notify_plugin.la
endif

lib20_mail_log_plugin_la_SOURCES = \
	mail-log-plugin.c

noinst_HEADERS = \
	mail-log-plugin.h
