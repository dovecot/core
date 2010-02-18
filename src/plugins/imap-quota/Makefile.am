AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/imap \
	-I$(top_srcdir)/src/plugins/quota

imap_moduledir = $(moduledir)

lib11_imap_quota_plugin_la_LDFLAGS = -module -avoid-version

imap_module_LTLIBRARIES = \
	lib11_imap_quota_plugin.la

if DOVECOT_PLUGIN_DEPS
lib11_imap_quota_plugin_la_LIBADD = \
	../quota/lib10_quota_plugin.la
endif

lib11_imap_quota_plugin_la_SOURCES = \
	imap-quota-plugin.c

noinst_HEADERS = \
	imap-quota-plugin.h
