AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/plugins/fts

lib21_fts_squat_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib21_fts_squat_plugin.la

if DOVECOT_PLUGIN_DEPS
lib21_fts_squat_plugin_la_LIBADD = \
	../fts/lib20_fts_plugin.la
endif

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
	$(LIBDOVECOT_STORAGE) \
	$(common_objects)

squat_test_LDADD = $(libs) $(LIBDOVECOT)
squat_test_DEPENDENCIES = $(libs) $(LIBDOVECOT_DEPS)
