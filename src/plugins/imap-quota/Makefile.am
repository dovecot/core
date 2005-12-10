AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/imap \
	-I$(top_srcdir)/src/plugins/quota

imap_moduledir = $(moduledir)/imap

libimap_quota_plugin_la_LDFLAGS = -module -avoid-version

imap_module_LTLIBRARIES = \
	libimap_quota_plugin.la

libimap_quota_plugin_la_SOURCES = \
	imap-quota-plugin.c
