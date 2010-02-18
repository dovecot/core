AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/plugins/quota

lib11_trash_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib11_trash_plugin.la

if DOVECOT_PLUGIN_DEPS
lib11_trash_plugin_la_LIBADD = \
	../quota/lib10_quota_plugin.la
endif

lib11_trash_plugin_la_SOURCES = \
	trash-plugin.c

noinst_HEADERS = \
	trash-plugin.h
