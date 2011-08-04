AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

NOPLUGIN_LDFLAGS =
lib20_fts_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_fts_plugin.la

lib20_fts_plugin_la_SOURCES = \
	fts-api.c \
	fts-build.c \
	fts-build-indexer.c \
	fts-build-mailbox.c \
	fts-build-virtual.c \
	fts-parser.c \
	fts-parser-html.c \
	fts-parser-script.c \
	fts-plugin.c \
	fts-search.c \
	fts-search-serialize.c \
	fts-storage.c

noinst_HEADERS = \
	html-entities.h \
	fts-api.h \
	fts-api-private.h \
	fts-build.h \
	fts-build-private.h \
	fts-parser.h \
	fts-plugin.h \
	fts-search-serialize.h \
	fts-storage.h

pkglibexec_PROGRAMS = xml2text

xml2text_SOURCES = xml2text.c

xml2text_LDADD = fts-parser-html.lo $(LIBDOVECOT)
xml2text_DEPENDENCIES = fts-parser-html.lo $(LIBDOVECOT_DEPS)

EXTRA_DIST = decode2text.sh
