noinst_LTLIBRARIES = libsettings.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

libsettings_la_SOURCES = \
	settings.c \
	settings-legacy.c \
	settings-parser.c

headers = \
	settings.h \
	settings-legacy.h \
	settings-parser.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-settings-parser \
	test-settings

noinst_PROGRAMS = $(test_programs)

test_libs = \
	libsettings.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_settings_parser_SOURCES = test-settings-parser.c
test_settings_parser_LDADD = $(test_libs)
test_settings_parser_DEPENDENCIES = $(test_libs)

test_settings_SOURCES = test-settings.c
test_settings_LDADD = $(test_libs)
test_settings_DEPENDENCIES = $(test_libs)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
