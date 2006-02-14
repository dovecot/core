AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

lib01_convert_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib01_convert_plugin.la

lib01_convert_plugin_la_SOURCES = \
	convert-storage.c \
	convert-plugin.c

noinst_HEADERS = \
	convert-storage.h \
	convert-plugin.h

noinst_PROGRAMS = convert-tool

convert_tool_SOURCES = \
	convert-tool.c

libs = \
	$(top_builddir)/src/lib-storage/register/libstorage-register.a \
	$(STORAGE_LIBS) \
	$(top_builddir)/src/lib-storage/libstorage.a \
	$(top_builddir)/src/lib-storage/subscription-file/libstorage_subscription_file.a \
	$(top_builddir)/src/lib-imap/libimap.a \
	$(top_builddir)/src/lib-mail/libmail.a \
	$(top_builddir)/src/lib-charset/libcharset.a \
	$(top_builddir)/src/lib/liblib.a

convert_tool_LDADD = \
	$(libs) \
	$(LIBICONV) \
	$(RAND_LIBS)

install-exec-local:
	$(mkdir_p) $(DESTDIR)$(moduledir)/imap $(DESTDIR)$(moduledir)/pop3 $(DESTDIR)$(moduledir)/lda
	for d in imap pop3 lda; do \
	  rm -f $(DESTDIR)$(moduledir)/$$d/lib01_convert_plugin.so; \
	  $(LN_S) ../lib01_convert_plugin.so $(DESTDIR)$(moduledir)/$$d; \
	done
