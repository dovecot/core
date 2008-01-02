AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/plugins/fts

lib21_fts_squat_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib21_fts_squat_plugin.la

lib21_fts_squat_plugin_la_SOURCES = \
	fts-squat-plugin.c \
	fts-backend-squat.c \
	squat-trie.c \
	squat-uidlist.c

noinst_HEADERS = \
	fts-squat-plugin.h \
	squat-trie.h \
	squat-trie-private.h \
	squat-uidlist.h

noinst_PROGRAMS = squat-test

squat_test_SOURCES = \
	squat-test.c

common_objects = \
	squat-trie.lo \
	squat-uidlist.lo

libs = \
	$(top_builddir)/src/lib-storage/register/libstorage-register.a \
	$(STORAGE_LIBS) \
	$(top_builddir)/src/lib-storage/list/libstorage_list.a \
	$(top_builddir)/src/lib-imap/libimap.a \
	$(top_builddir)/src/lib-mail/libmail.a \
	$(top_builddir)/src/lib-charset/libcharset.a \
	$(top_builddir)/src/lib/liblib.a

squat_test_LDADD = \
	$(common_objects) \
	$(libs) \
	$(LIBICONV) \
	$(RAND_LIBS)

squat_test_DEPENDENCIES = $(libs) $(common_objects)

install-exec-local:
	for d in imap lda; do \
	  $(mkdir_p) $(DESTDIR)$(moduledir)/$$d; \
	  rm -f $(DESTDIR)$(moduledir)/$$d/lib21_fts_squat_plugin.so; \
	  $(LN_S) ../lib21_fts_squat_plugin.so $(DESTDIR)$(moduledir)/$$d; \
	done
