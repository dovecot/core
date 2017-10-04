noinst_LTLIBRARIES = libdict.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings

base_sources = \
	dict.c \
	dict-client.c \
	dict-file.c \
	dict-memcached.c \
	dict-memcached-ascii.c \
	dict-redis.c \
	dict-fail.c \
	dict-transaction-memory.c

libdict_la_SOURCES = \
	$(base_sources)

headers = \
	dict.h \
	dict-client.h \
	dict-private.h \
	dict-transaction-memory.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-dict

noinst_PROGRAMS = $(test_programs) test-dict-client

test_libs = \
	../lib-test/libtest.la \
	../lib/liblib.la

test_dict_SOURCES = test-dict.c
test_dict_LDADD = libdict.la $(test_libs)
test_dict_DEPENDENCIES = $(noinst_LTLIBRARIES) $(test_libs)

test_dict_client_SOURCES = test-dict-client.c
test_dict_client_LDADD = $(noinst_LTLIBRARIES) ../lib/liblib.la
test_dict_client_DEPENDENCIES = $(noinst_LTLIBRARIES) $(test_libs)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
