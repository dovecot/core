noinst_LTLIBRARIES = libcharset.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

libcharset_la_LIBADD = $(LTLIBICONV)
libcharset_la_SOURCES = \
	charset-iconv.c \
	charset-utf8.c

headers = \
	charset-utf8.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-charset

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../lib-test/libtest.la \
	../lib/liblib.la
test_deps = $(noinst_LTLIBRARIES) $(test_libs)

test_charset_SOURCES = test-charset.c
test_charset_LDADD = libcharset.la $(test_libs)
test_charset_DEPENDENCIES = libcharset.la $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
