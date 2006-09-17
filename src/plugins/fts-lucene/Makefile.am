AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/plugins/fts \
	-I/usr/lib

lib02_fts_lucene_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib02_fts_lucene_plugin.la

lib02_fts_lucene_plugin_la_LIBADD = \
	-lclucene

lib02_fts_lucene_plugin_la_SOURCES = \
	fts-lucene-plugin.c \
	fts-backend-lucene.c \
	lucene-wrapper.cc

noinst_HEADERS = \
	fts-lucene-plugin.h

install-exec-local:
	for d in imap lda; do \
	  $(mkdir_p) $(DESTDIR)$(moduledir)/$$d; \
	  rm -f $(DESTDIR)$(moduledir)/$$d/lib02_fts_lucene_plugin.so; \
	  $(LN_S) ../lib02_fts_lucene_plugin.so $(DESTDIR)$(moduledir)/$$d; \
	done
