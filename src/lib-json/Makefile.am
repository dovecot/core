noinst_LTLIBRARIES = libjson.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

libjson_la_SOURCES = \
	json-syntax.c \
	json-types.c \
	json-parser.new.c
libjson_la_LIBADD = -lm

headers = \
	json-syntax.h \
	json-types.h \
	json-parser.new.h

test_programs = \
	test-json-parser

noinst_PROGRAMS = $(test_programs)

test_libs = \
	libjson.la \
	../lib-test/libtest.la \
	../lib-charset/libcharset.la \
	../lib/liblib.la \
	$(MODULE_LIBS)
test_deps = \
	libjson.la \
	../lib-test/libtest.la \
	../lib-charset/libcharset.la \
	../lib/liblib.la

test_json_parser_SOURCE = \
	test-json-parser.c
test_json_parser_LDADD = \
	$(test_libs)
test_json_parser_DEPENDENCIES = \
	$(test_deps)

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
