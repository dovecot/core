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
	quota-fs.c \
	quota-dict.c \
	quota-dirsize.c \
        quota-plugin.c \
	quota-storage.c

noinst_HEADERS = \
	quota.h \
	quota-fs.h \
	quota-plugin.h \
	quota-private.h

install-exec-local:
	$(mkdir_p) $(DESTDIR)$(moduledir)/imap $(DESTDIR)$(moduledir)/lda
	for d in imap lda; do \
	  rm -f $(DESTDIR)$(moduledir)/$$d/libquota_plugin.so; \
	  $(LN_S) ../libquota_plugin.so $(DESTDIR)$(moduledir)/$$d; \
	done
