noinst_LTLIBRARIES = libfts.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	$(LIBEXTTEXTCAT_CFLAGS) \
	$(LIBFTS_NORMALIZER_CFLAGS) \
	-DUDHRDIR=\""$(top_srcdir)/src/lib-fts"\" \
	-DDATADIR=\"$(pkgdatadir)\" \
	-DTEST_STOPWORDS_DIR=\""$(top_srcdir)/src/lib-fts"\"

stopwordsdir = $(datadir)/${PACKAGE_TARNAME}/stopwords
dist_stopwords_DATA = stopwords_en.txt stopwords_fr.txt

BUILT_SOURCES = word-boundary-data.c word-break-data.c

EXTRA_DIST = \
	WordBreakProperty.txt \
	word-boundary-data.sh \
	word-boundary-data.c \
	word-break-data.sh \
	word-break-data.c

WordBreakProperty.txt:
	test -f WordBreakProperty.txt || wget http://www.unicode.org/Public/UNIDATA/auxiliary/WordBreakProperty.txt
$(srcdir)/word-boundary-data.c: word-boundary-data.sh WordBreakProperty.txt
	$(srcdir)/word-boundary-data.sh < WordBreakProperty.txt > $@

PropList.txt:
	test -f PropList.txt || wget http://www.unicode.org/Public/UNIDATA/PropList.txt
$(srcdir)/word-break-data.c: word-break-data.sh PropList.txt
	$(srcdir)/word-break-data.sh < PropList.txt > $@


if BUILD_FTS_STEMMER
STEMMER_LIBS = -lstemmer
endif

if BUILD_FTS_EXTTEXTCAT
TEXTCAT_LIBS = $(LIBEXTTEXTCAT_LIBS)
else
if BUILD_FTS_TEXTCAT
TEXTCAT_LIBS = -ltextcat
endif
endif

if BUILD_FTS_NORMALIZER
NORMALIZER_LIBS = $(LIBFTS_NORMALIZER_LIBS)
endif

libfts_la_LIBADD = \
	$(STEMMER_LIBS) \
	$(TEXTCAT_LIBS) \
	$(NORMALIZER_LIBS)

libfts_la_SOURCES = \
	fts-filter.c \
	fts-filter-normalizer.c \
	fts-filter-stopwords.c \
	fts-filter-stemmer-snowball.c \
	fts-language.c \
	fts-tokenizer.c \
	fts-tokenizer-address.c \
	fts-tokenizer-generic.c

noinst_HEADERS = \
	fts-filter.h \
	fts-filter-private.h \
	fts-language.h \
	fts-tokenizer.h \
	fts-tokenizer-private.h \
	fts-tokenizer-generic-private.h

test_programs = \
	test-fts-filter \
	$(TEST_FTS_LANGUAGE) \
	$(TEST_FTS_NORMALIZER) \
	test-fts-tokenizer

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../lib-test/libtest.la \
	../lib/liblib.la
test_deps = $(noinst_LTLIBRARIES) $(test_libs)

filter_deps = \
	fts-filter.lo fts-filter-stopwords.lo \
	fts-filter-stemmer-snowball.lo fts-filter-normalizer.lo

test_fts_filter_SOURCES = test-fts-filter.c
test_fts_filter_LDADD = $(filter_deps) $(test_libs) $(STEMMER_LIBS) $(TEXTCAT_LIBS) $(NORMALIZER_LIBS)
test_fts_filter_DEPENDENCIES = $(test_deps) $(filter_deps)

if BUILD_FTS_EXTTEXTCAT
TEST_FTS_LANGUAGE = test-fts-language
test_fts_language_SOURCES = test-fts-language.c
test_fts_language_LDADD = fts-language.lo $(test_libs) $(TEXTCAT_LIBS)
test_fts_language_DEPENDENCIES = $(test_deps)
endif

test_fts_tokenizer_SOURCES = test-fts-tokenizer.c
test_fts_tokenizer_LDADD = fts-tokenizer.lo fts-tokenizer-generic.lo fts-tokenizer-address.lo $(test_libs)
test_fts_tokenizer_DEPENDENCIES = $(test_deps)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
