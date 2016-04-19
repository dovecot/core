pkglibexecdir = $(libexecdir)/dovecot
doveadm_moduledir = $(moduledir)/doveadm

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-fts \
	-I$(top_srcdir)/src/lib-http \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/doveadm

NOPLUGIN_LDFLAGS =
lib20_doveadm_fts_plugin_la_LDFLAGS = -module -avoid-version
lib20_fts_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_fts_plugin.la

lib20_fts_plugin_la_LIBADD = ../../lib-fts/libfts.la

lib20_fts_plugin_la_SOURCES = \
	fts-api.c \
	fts-build-mail.c \
	fts-expunge-log.c \
	fts-indexer.c \
	fts-parser.c \
	fts-parser-html.c \
	fts-parser-script.c \
	fts-parser-tika.c \
	fts-plugin.c \
	fts-search.c \
	fts-search-args.c \
	fts-search-serialize.c \
	fts-storage.c \
	fts-user.c

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = \
	fts-api.h \
	fts-api-private.h \
	fts-expunge-log.h \
	fts-indexer.h \
	fts-parser.h \
	fts-storage.h \
	fts-user.h

noinst_HEADERS = \
	doveadm-fts.h \
	fts-build-mail.h \
	fts-plugin.h \
	fts-search-args.h \
	fts-search-serialize.h

pkglibexec_PROGRAMS = xml2text

xml2text_SOURCES = xml2text.c fts-parser-html.c
xml2text_CPPFLAGS = $(AM_CPPFLAGS) $(BINARY_CFLAGS)
xml2text_LDADD = $(LIBDOVECOT) $(BINARY_LDFLAGS)
xml2text_DEPENDENCIES = $(module_LTLIBRARIES) $(LIBDOVECOT_DEPS)

pkglibexec_SCRIPTS = decode2text.sh
EXTRA_DIST = $(pkglibexec_SCRIPTS)

doveadm_module_LTLIBRARIES = \
	lib20_doveadm_fts_plugin.la

lib20_doveadm_fts_plugin_la_SOURCES = \
	doveadm-fts.c \
	doveadm-dump-fts-expunge-log.c
