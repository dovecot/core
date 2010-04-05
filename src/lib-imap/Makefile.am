noinst_LTLIBRARIES = libimap.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-charset \
	-I$(top_srcdir)/src/lib-mail

libimap_la_SOURCES = \
	imap-arg.c \
	imap-base-subject.c \
	imap-bodystructure.c \
	imap-date.c \
	imap-envelope.c \
	imap-id.c \
	imap-match.c \
	imap-parser.c \
	imap-quote.c \
	imap-seqset.c \
	imap-utf7.c \
	imap-util.c

headers = \
	imap-arg.h \
	imap-base-subject.h \
	imap-bodystructure.h \
	imap-date.h \
	imap-envelope.h \
	imap-id.h \
	imap-match.h \
	imap-parser.h \
	imap-resp-code.h \
	imap-quote.h \
	imap-seqset.h \
	imap-utf7.h \
	imap-util.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif

test_programs = \
	test-imap-match \
	test-imap-parser \
	test-imap-utf7 \
	test-imap-util

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../lib-test/libtest.la \
	../lib/liblib.la

test_imap_match_SOURCES = test-imap-match.c
test_imap_match_LDADD = imap-match.lo $(test_libs)
test_imap_match_DEPENDENCIES = imap-match.lo $(test_libs)

test_imap_parser_SOURCES = test-imap-parser.c
test_imap_parser_LDADD = imap-parser.lo imap-arg.lo $(test_libs)
test_imap_parser_DEPENDENCIES = imap-parser.lo imap-arg.lo $(test_libs)

test_imap_utf7_SOURCES = test-imap-utf7.c
test_imap_utf7_LDADD = imap-utf7.lo $(test_libs)
test_imap_utf7_DEPENDENCIES = imap-utf7.lo $(test_libs)

test_imap_util_SOURCES = test-imap-util.c
test_imap_util_LDADD = imap-util.lo imap-arg.lo $(test_libs)
test_imap_util_DEPENDENCIES = imap-util.lo imap-arg.lo $(test_libs)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
