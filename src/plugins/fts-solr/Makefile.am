AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-http \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/plugins/fts

NOPLUGIN_LDFLAGS =
lib21_fts_solr_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib21_fts_solr_plugin.la

if DOVECOT_PLUGIN_DEPS
fts_plugin_dep = ../fts/lib20_fts_plugin.la
endif

lib21_fts_solr_plugin_la_LIBADD = \
	$(fts_plugin_dep) \
	-lexpat

lib21_fts_solr_plugin_la_SOURCES = \
	fts-backend-solr.c \
	fts-backend-solr-old.c \
	fts-solr-plugin.c \
	solr-connection.c

EXTRA_DIST = \
	solr-response.c

noinst_HEADERS = \
	fts-solr-plugin.h \
	solr-response.h \
	solr-connection.h
