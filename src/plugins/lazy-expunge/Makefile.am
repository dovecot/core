AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/maildir \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/plugins/quota

lib02_lazy_expunge_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib02_lazy_expunge_plugin.la

lib02_lazy_expunge_plugin_la_SOURCES = \
	lazy-expunge-plugin.c

noinst_HEADERS = \
	lazy-expunge-plugin.h

install-exec-local:
	for d in imap pop3; do \
	  $(mkdir_p) $(DESTDIR)$(moduledir)/$$d; \
	  rm -f $(DESTDIR)$(moduledir)/$$d/lib02_lazy_expunge_plugin$(MODULE_SUFFIX); \
	  $(LN_S) ../lib02_lazy_expunge_plugin$(MODULE_SUFFIX) $(DESTDIR)$(moduledir)/$$d; \
	done

