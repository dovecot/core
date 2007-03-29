AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

lib20_fts_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_fts_plugin.la

lib20_fts_plugin_la_SOURCES = \
	fts-api.c \
	fts-plugin.c \
	fts-storage.c

noinst_HEADERS = \
	fts-api.h \
	fts-api-private.h \
	fts-plugin.h

install-exec-local:
	for d in imap lda; do \
	  $(mkdir_p) $(DESTDIR)$(moduledir)/$$d; \
	  rm -f $(DESTDIR)$(moduledir)/$$d/lib20_fts_plugin.so; \
	  $(LN_S) ../lib20_fts_plugin.so $(DESTDIR)$(moduledir)/$$d; \
	done
