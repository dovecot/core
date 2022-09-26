noinst_LTLIBRARIES = libauth-common.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

libauth_common_la_SOURCES = \
	auth-scram.c \
	auth-scram-server.c

headers = \
	auth-scram.h \
	auth-scram-server.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs =

noinst_PROGRAMS = $(test_programs)

test_libs = \
	$(noinst_LTLIBRARIES) \
	../lib-test/libtest.la \
	../lib/liblib.la \
	$(MODULE_LIBS)

test_deps = \
	$(noinst_LTLIBRARIES) \
	../lib-test/libtest.la \
	../lib/liblib.la

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
