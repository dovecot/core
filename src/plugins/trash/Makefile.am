AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/plugins/quota

libtrash_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	libtrash_plugin.la

libtrash_plugin_la_SOURCES = \
	trash-plugin.c

noinst_HEADERS = \
	trash-plugin.h

install-exec-local:
	$(mkdir_p) $(DESTDIR)$(moduledir)/imap $(DESTDIR)$(moduledir)/lda
	for d in imap lda; do \
	  rm -f $(DESTDIR)$(moduledir)/$$d/libtrash_plugin.so; \
	  $(LN_S) ../libtrash_plugin.so $(DESTDIR)$(moduledir)/$$d; \
	done

