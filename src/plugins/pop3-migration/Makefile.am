AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

NOPLUGIN_LDFLAGS =
lib05_pop3_migration_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib05_pop3_migration_plugin.la

lib05_pop3_migration_plugin_la_SOURCES = \
	pop3-migration-plugin.c

noinst_HEADERS = \
	pop3-migration-plugin.h
