AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/plugins/fts \
	-I/usr/lib

NOPLUGIN_LDFLAGS =
lib21_fts_lucene_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib21_fts_lucene_plugin.la

if BUILD_LUCENE_TEXTCAT
TEXTCAT_LIBS = -lstemmer -ltextcat
SHOWBALL_SOURCES = Snowball.cc
endif

lib21_fts_lucene_plugin_la_LIBADD = \
	-lclucene-shared -lclucene-core $(TEXTCAT_LIBS)

lib21_fts_lucene_plugin_la_SOURCES = \
	fts-lucene-plugin.c \
	fts-backend-lucene.c \
	lucene-wrapper.cc \
	$(SHOWBALL_SOURCES)

noinst_HEADERS = \
	fts-lucene-plugin.h \
	lucene-wrapper.h
	SnowballAnalyzer.h \
	SnowballFilter.h

if BUILD_LUCENE_TEXTCAT
exampledir = $(docdir)/example-config
example_DATA = \
	textcat.conf
else
EXTRA_DIST = textcat.conf
endif
