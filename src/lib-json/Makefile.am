noinst_LTLIBRARIES = libjson.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

libjson_la_SOURCES = \
	json-syntax.c \
	json-types.c \
	json-tree.c \
	json-tree-io.c \
	json-parser.c \
	json-generator.c \
	json-istream.c \
	json-ostream.c \
	json-text.c
libjson_la_LIBADD = -lm

headers = \
	json-syntax.h \
	json-types.h \
	json-tree.h \
	json-tree-io.h \
	json-parser.h \
	json-generator.h \
	json-istream.h \
	json-ostream.h \
	json-text.h

test_programs = \
	test-json-parser \
	test-json-generator \
	test-json-io \
	test-json-istream \
	test-json-ostream \
	test-json-tree \
	test-json-tree-io

fuzz_programs =

if USE_FUZZER
fuzz_programs += \
        fuzz-json-istream
endif

noinst_PROGRAMS = json-format $(test_programs) $(fuzz_programs)

json_format_SOURCE = \
	json-format.c
json_format_LDADD = \
	libjson.la \
	../lib-charset/libcharset.la \
	../lib/liblib.la \
	$(MODULE_LIBS)

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

test_json_tree_SOURCE = \
	test-json-tree.c
test_json_tree_LDADD = \
	$(test_libs)
test_json_tree_DEPENDENCIES = \
	$(test_deps)

test_json_tree_io_SOURCE = \
	test-json-tree-io.c
test_json_tree_io_LDADD = \
	$(test_libs)
test_json_tree_io_DEPENDENCIES = \
	$(test_deps)

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

nodist_EXTRA_fuzz_json_istream_SOURCES = force-cxx-linking.cxx
fuzz_json_istream_CPPFLAGS = \
	$(FUZZER_CPPFLAGS)
fuzz_json_istream_LDFLAGS = \
	$(FUZZER_LDFLAGS)
fuzz_json_istream_SOURCES = \
	fuzz-json-istream.c
fuzz_json_istream_LDADD = \
	$(test_libs)
fuzz_json_istream_DEPENDENCIES = \
	$(test_deps)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
