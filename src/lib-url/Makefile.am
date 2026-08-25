include $(top_srcdir)/Makefile.test.include

noinst_LTLIBRARIES = liburl.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

liburl_la_SOURCES = \
	uri-util.c \
	http-url.c

headers = \
	uri-util.h \
	http-url.h

noinst_HEADERS = \
	http-url-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-uri-util \
	test-http-url

test_libs = \
	liburl.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_uri_util_SOURCES = test-uri-util.c
test_uri_util_LDADD = $(test_libs) $(LIBDOVECOT_TEST_LIBS)
test_uri_util_DEPENDENCIES = $(test_libs)

test_http_url_SOURCES = test-http-url.c
test_http_url_LDADD = $(test_libs) $(LIBDOVECOT_TEST_LIBS)
test_http_url_DEPENDENCIES = $(test_libs)

if USE_FUZZER
noinst_PROGRAMS += fuzz-uri-util
nodist_EXTRA_fuzz_uri_util_SOURCES = force-cxx-linking.cxx
fuzz_uri_util_SOURCES = fuzz-uri-util.c
fuzz_uri_util_CPPFLAGS = $(FUZZER_CPPFLAGS)
fuzz_uri_util_LDFLAGS = $(FUZZER_LDFLAGS)
fuzz_uri_util_LDADD = $(test_libs)
fuzz_uri_util_DEPENDENCIES = $(test_libs)

noinst_PROGRAMS += fuzz-http-url
nodist_EXTRA_fuzz_http_url_SOURCES = force-cxx-linking.cxx
fuzz_http_url_SOURCES = fuzz-http-url.c
fuzz_http_url_CPPFLAGS = $(FUZZER_CPPFLAGS)
fuzz_http_url_LDFLAGS = $(FUZZER_LDFLAGS)
fuzz_http_url_LDADD = $(test_libs)
fuzz_http_url_DEPENDENCIES = $(test_libs)

EXTRA_DIST = \
	fuzz-uri-util.dict \
	fuzz-http-url.dict
endif
