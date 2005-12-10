AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage

libquota_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	libquota_plugin.la

libquota_plugin_la_SOURCES = \
	quota.c \
	quota-dict.c \
	quota-dirsize.c \
        quota-plugin.c \
	quota-storage.c

install-exec-local:
	$(mkdir_p) $(moduledir)/imap $(moduledir)/lda
	for d in imap lda; do \
	  rm -f $(moduledir)/$$d/libquota_plugin.so; \
	  $(LN_S) ../libquota_plugin.so $(moduledir)/$$d; \
	done
