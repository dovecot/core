AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/maildir

lib15_notify_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib15_notify_plugin.la

lib15_notify_plugin_la_SOURCES = \
	notify-plugin.c \
	notify-noop.c \
	notify-storage.c

noinst_HEADERS = \
	notify-plugin.h \
	notify-plugin-private.h

install-exec-local:
	for d in imap pop3 lda; do \
	  $(mkdir_p) $(DESTDIR)$(moduledir)/$$d; \
	  rm -f $(DESTDIR)$(moduledir)/$$d/lib15_notify_plugin$(MODULE_SUFFIX); \
	  $(LN_S) ../lib15_notify_plugin$(MODULE_SUFFIX) $(DESTDIR)$(moduledir)/$$d; \
	done
