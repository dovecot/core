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

BUILT_SOURCES = settings-history-core.h

settings-history.c: settings-history-core.h

settings-history-core.h: $(srcdir)/settings-history-core.txt $(srcdir)/settings-history.py
	$(AM_V_GEN)$(PYTHON) $(srcdir)/settings-history.py --pro $(DOVECOT_PRO_BUILD) $< $@

EXTRA_DIST = \
	settings-history-core.h \
	settings-history-core.txt \
	settings-history.py

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
