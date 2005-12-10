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

install-exec-local:
	$(mkdir_p) $(moduledir)/imap $(moduledir)/lda
	for d in imap lda; do \
	  rm -f $(moduledir)/$$d/libtrash_plugin.so; \
	  $(LN_S) ../libtrash_plugin.so $(moduledir)/$$d; \
	done

