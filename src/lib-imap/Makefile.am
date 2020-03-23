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
	imap-keepalive.c \
	imap-match.c \
	imap-parser.c \
	imap-quote.c \
	imap-url.c \
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
	imap-keepalive.h \
	imap-match.h \
	imap-parser.h \
	imap-resp-code.h \
	imap-quote.h \
	imap-url.h \
	imap-seqset.h \
	imap-utf7.h \
	imap-util.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-imap-bodystructure \
	test-imap-envelope \
	test-imap-match \
	test-imap-parser \
	test-imap-quote \
	test-imap-url \
	test-imap-utf7 \
	test-imap-util

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../lib-test/libtest.la \
	../lib/liblib.la

test_deps = $(noinst_LTLIBRARIES) $(test_libs)

test_imap_bodystructure_SOURCES = test-imap-bodystructure.c
test_imap_bodystructure_LDADD = imap-bodystructure.lo imap-envelope.lo imap-quote.lo imap-parser.lo imap-arg.lo ../lib-mail/libmail.la $(test_libs)
test_imap_bodystructure_DEPENDENCIES = $(test_deps) ../lib-mail/libmail.la

test_imap_envelope_SOURCES = test-imap-envelope.c
test_imap_envelope_LDADD = imap-envelope.lo imap-quote.lo imap-parser.lo imap-arg.lo ../lib-mail/libmail.la $(test_libs)
test_imap_envelope_DEPENDENCIES = $(test_deps) ../lib-mail/libmail.la

test_imap_match_SOURCES = test-imap-match.c
test_imap_match_LDADD = imap-match.lo $(test_libs)
test_imap_match_DEPENDENCIES = $(test_deps)

test_imap_parser_SOURCES = test-imap-parser.c
test_imap_parser_LDADD = imap-parser.lo imap-arg.lo $(test_libs)
test_imap_parser_DEPENDENCIES = $(test_deps)

test_imap_quote_SOURCES = test-imap-quote.c
test_imap_quote_LDADD = imap-quote.lo $(test_libs)
test_imap_quote_DEPENDENCIES = $(test_deps)

test_imap_url_SOURCES = test-imap-url.c
test_imap_url_LDADD = imap-url.lo  $(test_libs)
test_imap_url_DEPENDENCIES = $(test_deps)

test_imap_utf7_SOURCES = test-imap-utf7.c
test_imap_utf7_LDADD = imap-utf7.lo $(test_libs)
test_imap_utf7_DEPENDENCIES = $(test_deps)

test_imap_util_SOURCES = test-imap-util.c
test_imap_util_LDADD = imap-util.lo imap-arg.lo $(test_libs)
test_imap_util_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

if USE_FUZZER
noinst_PROGRAMS += \
	fuzz-imap-utf7

nodist_EXTRA_fuzz_imap_utf7_SOURCES = force-cxx-linking.cxx
fuzz_imap_utf7_SOURCES = fuzz-imap-utf7.c
fuzz_imap_utf7_CPPFLAGS = $(FUZZER_CPPFLAGS)
fuzz_imap_utf7_LDFLAGS = $(FUZZER_LDFLAGS)
fuzz_imap_utf7_LDADD = libimap.la $(test_libs)
fuzz_imap_utf7_DEPENDENCIES = libimap.la $(test_deps)

endif
