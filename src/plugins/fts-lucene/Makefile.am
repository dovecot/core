doveadm_moduledir = $(moduledir)/doveadm

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/plugins/fts \
	-I$(top_srcdir)/src/doveadm

AM_CXXFLAGS = \
	$(CLUCENE_CFLAGS)

NOPLUGIN_LDFLAGS =
lib21_fts_lucene_plugin_la_LDFLAGS = -module -avoid-version
lib20_doveadm_fts_lucene_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib21_fts_lucene_plugin.la

if BUILD_LUCENE_STEMMER
STEMMER_LIBS = -lstemmer
SHOWBALL_SOURCES = Snowball.cc
endif
if BUILD_LUCENE_TEXTCAT
TEXTCAT_LIBS = -ltextcat
else
if BUILD_LUCENE_EXTTEXTCAT
TEXTCAT_LIBS = -lexttextcat
endif
endif

lib21_fts_lucene_plugin_la_LIBADD = \
	$(CLUCENE_LIBS) $(TEXTCAT_LIBS) $(STEMMER_LIBS)

lib21_fts_lucene_plugin_la_SOURCES = \
	fts-lucene-plugin.c \
	fts-backend-lucene.c \
	lucene-wrapper.cc \
	$(SHOWBALL_SOURCES)

noinst_HEADERS = \
	fts-lucene-plugin.h \
	lucene-wrapper.h \
	SnowballAnalyzer.h \
	SnowballFilter.h

if BUILD_LUCENE_TEXTCAT
exampledir = $(docdir)/example-config
example_DATA = \
	textcat.conf
endif
EXTRA_DIST = textcat.conf

doveadm_module_LTLIBRARIES = \
	lib20_doveadm_fts_lucene_plugin.la

lib20_doveadm_fts_lucene_plugin_la_SOURCES = \
	doveadm-fts-lucene.c
