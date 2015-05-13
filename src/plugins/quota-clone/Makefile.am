AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/plugins/quota

NOPLUGIN_LDFLAGS =
lib20_quota_clone_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_quota_clone_plugin.la

lib20_quota_clone_plugin_la_SOURCES = \
	quota-clone-plugin.c

noinst_HEADERS = \
	quota-clone-plugin.h
