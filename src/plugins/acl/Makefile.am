AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

lib01_acl_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib01_acl_plugin.la

lib01_acl_plugin_la_SOURCES = \
	acl-api.c \
	acl-backend.c \
	acl-backend-vfile.c \
	acl-backend-vfile-acllist.c \
	acl-cache.c \
	acl-mailbox.c \
	acl-mailbox-list.c \
	acl-plugin.c \
	acl-storage.c

noinst_HEADERS = \
	acl-api.h \
	acl-api-private.h \
	acl-backend-vfile.h \
	acl-cache.h \
	acl-plugin.h

install-exec-local:
	for d in imap lda; do \
	  $(mkdir_p) $(DESTDIR)$(moduledir)/$$d; \
	  rm -f $(DESTDIR)$(moduledir)/$$d/lib01_acl_plugin$MODULE_SUFFIX; \
	  $(LN_S) ../lib01_acl_plugin$MODULE_SUFFIX $(DESTDIR)$(moduledir)/$$d; \
	done
