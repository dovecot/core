noinst_LTLIBRARIES = libjson.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

libjson_la_SOURCES = \
	json-syntax.c
libjson_la_LIBADD = -lm

headers = \
	json-syntax.h

test_programs =

noinst_PROGRAMS = $(test_programs)

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
