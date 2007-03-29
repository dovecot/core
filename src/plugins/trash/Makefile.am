AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/plugins/quota

lib11_trash_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib11_trash_plugin.la

lib11_trash_plugin_la_SOURCES = \
	trash-plugin.c

noinst_HEADERS = \
	trash-plugin.h

install-exec-local:
	for d in imap lda; do \
	  $(mkdir_p) $(DESTDIR)$(moduledir)/$$d; \
	  rm -f $(DESTDIR)$(moduledir)/$$d/lib11_trash_plugin.so; \
	  $(LN_S) ../lib11_trash_plugin.so $(DESTDIR)$(moduledir)/$$d; \
	done

