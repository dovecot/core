include $(top_srcdir)/Makefile.test.include

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
	json-text.c \
	istream-json-string.c
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
	json-text.h \
	istream-json-string.h

test_programs = \
	test-json-parser \
	test-json-generator \
	test-json-io \
	test-json-istream \
	test-istream-json-string \
	test-json-ostream \
	test-json-tree \
	test-json-tree-io

fuzz_programs =

if USE_FUZZER
fuzz_programs += \
	fuzz-json-istream \
	fuzz-istream-json-string
endif

noinst_PROGRAMS += json-format $(fuzz_programs)

EXTRA_DIST = \
	fuzz-json-istream.dict

json_format_SOURCES = \
	json-format.c
json_format_LDADD = \
	libjson.la \
	../lib-charset/libcharset.la \
	../lib/liblib.la \
	$(LIBDOVECOT_TEST_LIBS)

test_libs = \
	libjson.la \
	../lib-test/libtest.la \
	../lib-charset/libcharset.la \
	../lib/liblib.la \
	$(LIBDOVECOT_TEST_LIBS)
test_deps = \
	libjson.la \
	../lib-test/libtest.la \
	../lib-charset/libcharset.la \
	../lib/liblib.la

test_json_parser_SOURCES = \
	test-json-parser.c
test_json_parser_LDADD = \
	$(test_libs)
test_json_parser_DEPENDENCIES = \
	$(test_deps)

test_json_generator_SOURCES = \
	test-json-generator.c
test_json_generator_LDADD = \
	$(test_libs)
test_json_generator_DEPENDENCIES = \
	$(test_deps)

test_json_io_SOURCES = \
	test-json-io.c
test_json_io_LDADD = \
	$(test_libs)
test_json_io_DEPENDENCIES = \
	$(test_deps)

test_json_istream_SOURCES = \
	test-json-istream.c
test_json_istream_LDADD = \
	$(test_libs)
test_json_istream_DEPENDENCIES = \
	$(test_deps)

test_json_ostream_SOURCES = \
	test-json-ostream.c
test_json_ostream_LDADD = \
	$(test_libs)
test_json_ostream_DEPENDENCIES = \
	$(test_deps)

test_json_tree_SOURCES = \
	test-json-tree.c
test_json_tree_LDADD = \
	$(test_libs)
test_json_tree_DEPENDENCIES = \
	$(test_deps)

test_json_tree_io_SOURCES = \
	test-json-tree-io.c
test_json_tree_io_LDADD = \
	$(test_libs)
test_json_tree_io_DEPENDENCIES = \
	$(test_deps)

test_istream_json_string_SOURCES = \
	test-istream-json-string.c
test_istream_json_string_LDADD = \
	$(test_libs)
test_istream_json_string_DEPENDENCIES = \
	$(test_deps)

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

nodist_EXTRA_fuzz_istream_json_string_SOURCES = force-cxx-linking.cxx
fuzz_istream_json_string_CPPFLAGS = \
	$(FUZZER_CPPFLAGS)
fuzz_istream_json_string_LDFLAGS = \
	$(FUZZER_LDFLAGS)
fuzz_istream_json_string_SOURCES = \
	fuzz-istream-json-string.c
fuzz_istream_json_string_LDADD = \
	$(test_libs)
fuzz_istream_json_string_DEPENDENCIES = \
	$(test_deps)

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
