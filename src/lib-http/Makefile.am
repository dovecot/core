noinst_LTLIBRARIES = libhttp.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-ssl-iostream

libhttp_la_SOURCES = \
	http-url.c

headers = \
	http-url.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-http-url

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../lib-test/libtest.la \
	../lib/liblib.la

test_deps = $(noinst_LTLIBRARIES) $(test_libs)

test_http_url_SOURCES = test-http-url.c
test_http_url_LDADD = http-url.lo  $(test_libs)
test_http_url_DEPENDENCIES = $(test_deps)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
