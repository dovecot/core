noinst_LTLIBRARIES = libjson.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

libjson_la_SOURCES = \
	json-syntax.c \
	json-types.c \
	json-tree.new.c \
	json-parser.new.c \
	json-generator.c \
	json-istream.c \
	json-ostream.c
libjson_la_LIBADD = -lm

headers = \
	json-syntax.h \
	json-types.h \
	json-tree.new.h \
	json-parser.new.h \
	json-generator.h \
	json-istream.h \
	json-ostream.h

test_programs = \
	test-json-parser \
	test-json-generator \
	test-json-io \
	test-json-istream \
	test-json-ostream

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

test_json_generator_SOURCE = \
	test-json-generator.c
test_json_generator_LDADD = \
	$(test_libs)
test_json_generator_DEPENDENCIES = \
	$(test_deps)

test_json_io_SOURCE = \
	test-json-io.c
test_json_io_LDADD = \
	$(test_libs)
test_json_io_DEPENDENCIES = \
	$(test_deps)

test_json_istream_SOURCE = \
	test-json-istream.c
test_json_istream_LDADD = \
	$(test_libs)
test_json_istream_DEPENDENCIES = \
	$(test_deps)

test_json_ostream_SOURCE = \
	test-json-ostream.c
test_json_ostream_LDADD = \
	$(test_libs)
test_json_ostream_DEPENDENCIES = \
	$(test_deps)

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
