pkglibexecdir = $(libexecdir)/dovecot

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

lib20_convert_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_convert_plugin.la

lib20_convert_plugin_la_SOURCES = \
	convert-storage.c \
	convert-plugin.c

noinst_HEADERS = \
	convert-storage.h \
	convert-plugin.h

pkglibexec_PROGRAMS = convert-tool

convert_tool_SOURCES = \
	convert-tool.c

common_objects = \
	convert-storage.lo

libs = \
	$(top_builddir)/src/lib-storage/register/libstorage-register.a \
	$(top_builddir)/src/lib-storage/list/libstorage_list.a \
	$(STORAGE_LIBS) \
	$(top_builddir)/src/lib-imap/libimap.a \
	$(top_builddir)/src/lib-mail/libmail.a \
	$(top_builddir)/src/lib-charset/libcharset.a \
	$(top_builddir)/src/lib/liblib.a

convert_tool_LDADD = \
	$(common_objects) \
	$(libs) \
	$(LIBICONV) \
	$(RAND_LIBS)

convert_tool_DEPENDENCIES = $(libs) $(common_objects)

install-exec-local:
	for d in imap pop3 lda; do \
	  $(mkdir_p) $(DESTDIR)$(moduledir)/$$d; \
	  rm -f $(DESTDIR)$(moduledir)/$$d/lib20_convert_plugin$MODULE_SUFFIX; \
	  $(LN_S) ../lib20_convert_plugin$MODULE_SUFFIX $(DESTDIR)$(moduledir)/$$d; \
	done
