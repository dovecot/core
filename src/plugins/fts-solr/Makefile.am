AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-http \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/plugins/fts

NOPLUGIN_LDFLAGS =
lib21_fts_solr_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib21_fts_solr_plugin.la

if DOVECOT_PLUGIN_DEPS
fts_plugin_dep = ../fts/lib20_fts_plugin.la
endif

lib21_fts_solr_plugin_la_LIBADD = \
	$(fts_plugin_dep) \
	-lexpat

lib21_fts_solr_plugin_la_SOURCES = \
	fts-backend-solr.c \
	fts-backend-solr-old.c \
	fts-solr-plugin.c \
	solr-response.c \
	solr-connection.c

noinst_HEADERS = \
	fts-solr-plugin.h \
	solr-response.h \
	solr-connection.h

test_programs = \
	test-solr-response

test_libs = \
	../../lib-test/libtest.la \
	../../lib-charset/libcharset.la \
	../../lib/liblib.la \
	$(MODULE_LIBS)

noinst_PROGRAMS = test-solr-response

test_solr_response_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/lib-test
test_solr_response_SOURCES = \
	solr-response.c \
	test-solr-response.c
test_solr_response_LDADD = \
	$(test_libs) -lexpat

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
