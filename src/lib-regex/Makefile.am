AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-doveadm \
	-I$(top_srcdir)/src/lib-dns-client \
	-I$(top_srcdir)/src/lib-http \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-var-expand \
	$(LIBPCRE_CFLAGS)

headers = \
	dregex.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

noinst_LTLIBRARIES=libdregex.la

if BUILD_LIBREGEX
libdregex_la_SOURCES = regex.c
libdregex_la_LIBADD = $(LIBPCRE_LIBS)

EXTRA_DIST =

test_programs = test-regex

noinst_PROGRAMS = $(test_programs)

test_regex_SOURCES = test-regex.c
test_regex_LDADD = libdregex.la \
		   ../lib-test/libtest.la \
		   ../lib/liblib.la \
		   $(LIBPCRE_LIBS)
test_regex_DEPENDENCIES = libdregex.la $(LIBPCRE_LIBS)

else
libdregex_la_SOURCES = empty.c
endif
