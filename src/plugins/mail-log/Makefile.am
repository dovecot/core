AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/maildir

lib20_mail_log_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_mail_log_plugin.la

lib20_mail_log_plugin_la_SOURCES = \
	mail-log-plugin.c

noinst_HEADERS = \
	mail-log-plugin.h

install-exec-local:
	for d in imap pop3 lda; do \
	  $(mkdir_p) $(DESTDIR)$(moduledir)/$$d; \
	  rm -f $(DESTDIR)$(moduledir)/$$d/lib20_mail_log_plugin.so; \
	  $(LN_S) ../lib20_mail_log_plugin.so $(DESTDIR)$(moduledir)/$$d; \
	done

