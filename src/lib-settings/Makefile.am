noinst_LTLIBRARIES = libsettings.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-var-expand

libsettings_la_SOURCES = \
	settings.c \
	settings-history.c \
	settings-parser.c

headers = \
	settings.h \
	settings-history.h \
	settings-parser.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

BUILT_SOURCES = settings-history-core.c

settings-history.c: settings-history-core.c

settings-history-core.c: $(top_srcdir)/src/lib-settings/settings-history.pl $(top_srcdir)/src/lib-settings/settings-history-core.txt
	$(AM_V_GEN)$(top_srcdir)/src/lib-settings/settings-history.pl $(top_srcdir)/src/lib-settings/settings-history-core.txt $(DOVECOT_PRO_BUILD) > settings-history-core.c || rm -f settings-history-core.c

EXTRA_DIST = \
	settings-history-core.txt \
	settings-history.pl

test_programs = \
	test-settings-parser \
	test-settings

noinst_PROGRAMS = $(test_programs)

test_libs = \
	libsettings.la \
	../lib-var-expand/libvar_expand.la \
	../lib-dns/libdns.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_settings_parser_SOURCES = test-settings-parser.c
test_settings_parser_LDADD = $(test_libs) $(DLLIB)
test_settings_parser_DEPENDENCIES = $(test_libs)

test_settings_SOURCES = test-settings.c
test_settings_LDADD = $(test_libs) $(DLLIB)
test_settings_DEPENDENCIES = $(test_libs)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
