AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

NOPLUGIN_LDFLAGS =
lib20_mailbox_alias_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_mailbox_alias_plugin.la

lib20_mailbox_alias_plugin_la_SOURCES = \
	mailbox-alias-plugin.c

noinst_HEADERS = \
	mailbox-alias-plugin.h
