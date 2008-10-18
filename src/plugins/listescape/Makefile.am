AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

lib20_listescape_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_listescape_plugin.la

lib20_listescape_plugin_la_SOURCES = \
	listescape-plugin.c

noinst_HEADERS = \
	listescape-plugin.h

install-exec-local:
	for d in imap pop3 lda; do \
	  $(mkdir_p) $(DESTDIR)$(moduledir)/$$d; \
	  rm -f $(DESTDIR)$(moduledir)/$$d/lib20_listescape_plugin$(MODULE_SUFFIX); \
	  $(LN_S) ../lib20_listescape_plugin$(MODULE_SUFFIX) $(DESTDIR)$(moduledir)/$$d; \
	done

