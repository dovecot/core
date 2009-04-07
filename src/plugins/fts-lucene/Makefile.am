AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/plugins/fts \
	-I/usr/lib

lib21_fts_lucene_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib21_fts_lucene_plugin.la

lib21_fts_lucene_plugin_la_LIBADD = \
	-lclucene

lib21_fts_lucene_plugin_la_SOURCES = \
	fts-lucene-plugin.c \
	fts-backend-lucene.c \
	lucene-wrapper.cc

noinst_HEADERS = \
	fts-lucene-plugin.h \
	lucene-wrapper.h
