noinst_LTLIBRARIES = libsettings.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

libsettings_la_SOURCES = \
	settings.c \
	settings-parser.c

headers = \
	settings.h \
	settings-parser.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-settings-parser

noinst_PROGRAMS = $(test_programs)

test_libs = \
	libsettings.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_settings_parser_SOURCES = test-settings-parser.c
test_settings_parser_LDADD = $(test_libs)
test_settings_parser_DEPENDENCIES = $(test_libs)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
