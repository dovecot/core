AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

lib20_virtual_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_virtual_plugin.la

lib20_virtual_plugin_la_SOURCES = \
	virtual-config.c \
	virtual-mail.c \
	virtual-plugin.c \
	virtual-search.c \
	virtual-storage.c \
	virtual-save.c \
	virtual-sync.c \
	virtual-transaction.c

noinst_HEADERS = \
	virtual-plugin.h \
	virtual-storage.h \
	virtual-transaction.h

install-exec-local:
	for d in imap pop3 lda; do \
	  $(mkdir_p) $(DESTDIR)$(moduledir)/$$d; \
	  rm -f $(DESTDIR)$(moduledir)/$$d/lib20_virtual_plugin.so; \
	  $(LN_S) ../lib20_virtual_plugin.so $(DESTDIR)$(moduledir)/$$d; \
	done
