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

lib21_fts_solr_plugin_la_LIBADD = \
	$(CURL_LIBS) -lexpat

lib21_fts_solr_plugin_la_SOURCES = \
	fts-backend-solr.c \
	fts-solr-plugin.c \
	solr-connection.c

noinst_HEADERS = \
	fts-solr-plugin.h \
	solr-connection.h

EXTRA_DIST = schema.xml

install-exec-local:
	for d in imap lda; do \
	  $(mkdir_p) $(DESTDIR)$(moduledir)/$$d; \
	  rm -f $(DESTDIR)$(moduledir)/$$d/lib21_fts_solr_plugin$(MODULE_SUFFIX); \
	  $(LN_S) ../lib21_fts_solr_plugin$(MODULE_SUFFIX) $(DESTDIR)$(moduledir)/$$d; \
	done
