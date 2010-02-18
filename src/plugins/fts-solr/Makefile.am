AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/plugins/fts \
	$(CURL_CFLAGS)

lib21_fts_solr_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib21_fts_solr_plugin.la

if DOVECOT_PLUGIN_DEPS
fts_plugin_dep = ../fts/lib20_fts_plugin.la
endif

lib21_fts_solr_plugin_la_LIBADD = \
	$(fts_plugin_dep) \
	$(CURL_LIBS) -lexpat

lib21_fts_solr_plugin_la_SOURCES = \
	fts-backend-solr.c \
	fts-solr-plugin.c \
	solr-connection.c

noinst_HEADERS = \
	fts-solr-plugin.h \
	solr-connection.h
