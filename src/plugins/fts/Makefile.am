AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

lib20_fts_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_fts_plugin.la

lib20_fts_plugin_la_SOURCES = \
	fts-api.c \
	fts-mailbox.c \
	fts-plugin.c \
	fts-search.c \
	fts-storage.c

noinst_HEADERS = \
	fts-api.h \
	fts-api-private.h \
	fts-mailbox.h \
	fts-plugin.h \
	fts-storage.h
