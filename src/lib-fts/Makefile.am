noinst_LTLIBRARIES = libfts.la

# I$(top_srcdir)/src/lib-fts needed to include
# word-break-data.c and word-boundary-data.c
# in fts-tokenizer-generic.c
AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-fts \
	$(LIBEXTTEXTCAT_CFLAGS) \
	$(LIBICU_CFLAGS) \
	-DUDHRDIR=\""$(top_srcdir)/src/lib-fts"\" \
	-DDATADIR=\"$(pkgdatadir)\" \
	-DTEST_STOPWORDS_DIR=\""$(top_srcdir)/src/lib-fts/stopwords"\"

stopwordsdir = $(datadir)/${PACKAGE_TARNAME}/stopwords
dist_stopwords_DATA = \
	stopwords/stopwords_da.txt \
	stopwords/stopwords_de.txt \
	stopwords/stopwords_en.txt \
	stopwords/stopwords_es.txt \
	stopwords/stopwords_fi.txt \
	stopwords/stopwords_fr.txt \
	stopwords/stopwords_it.txt \
	stopwords/stopwords_nl.txt \
	stopwords/stopwords_no.txt \
	stopwords/stopwords_pt.txt \
	stopwords/stopwords_ro.txt \
	stopwords/stopwords_ru.txt \
	stopwords/stopwords_sv.txt \
	stopwords/stopwords_tr.txt

BUILT_SOURCES = $(srcdir)/word-boundary-data.c \
		$(srcdir)/word-break-data.c

EXTRA_DIST = \
	udhr_fra.txt \
	PropList.txt \
	word-properties.pl \
	WordBreakProperty.txt \
	word-boundary-data.c \
	word-break-data.c \
	stopwords/stopwords_malformed.txt

$(srcdir)/WordBreakProperty.txt:
	test -f $@ || wget -O $@ https://dovecot.org/res/WordBreakProperty.txt
$(srcdir)/word-boundary-data.c: $(srcdir)/word-properties.pl $(srcdir)/WordBreakProperty.txt
	perl $(srcdir)/word-properties.pl boundaries $(srcdir)/WordBreakProperty.txt > $@

$(srcdir)/PropList.txt:
	test -f $@ || wget -O $@ https://dovecot.org/res/PropList.txt
$(srcdir)/word-break-data.c: $(srcdir)/word-properties.pl $(srcdir)/PropList.txt
	perl $(srcdir)/word-properties.pl breaks $(srcdir)/PropList.txt > $@


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

if BUILD_LIBICU
ICU_SOURCES = fts-icu.c
NORMALIZER_LIBS = $(LIBICU_LIBS)
ICU_TESTS = test-fts-icu
endif

libfts_la_LIBADD = \
	$(STEMMER_LIBS) \
	$(TEXTCAT_LIBS) \
	$(NORMALIZER_LIBS)

libfts_la_SOURCES = \
	fts-filter.c \
	fts-filter-contractions.c \
	fts-filter-common.c \
	fts-filter-english-possessive.c \
	fts-filter-lowercase.c \
	fts-filter-normalizer-icu.c \
	fts-filter-stopwords.c \
	fts-filter-stemmer-snowball.c \
	fts-language.c \
	fts-library.c \
	fts-tokenizer.c \
	fts-tokenizer-address.c \
	fts-tokenizer-common.c \
	fts-tokenizer-generic.c \
	$(ICU_SOURCES)

headers = \
	fts-common.h \
	fts-filter.h \
	fts-filter-common.h \
	fts-filter-private.h \
	fts-icu.h \
	fts-language.h \
	fts-library.h \
	fts-tokenizer.h \
	fts-tokenizer-common.h \
	fts-tokenizer-private.h \
	fts-tokenizer-generic-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

deps=../lib-dovecot/libdovecot.la

pkglib_LTLIBRARIES = libdovecot-fts.la
libdovecot_fts_la_SOURCES = 
libdovecot_fts_la_LIBADD = libfts.la $(deps)
libdovecot_fts_la_DEPENDENCIES = libfts.la $(deps)
libdovecot_fts_la_LDFLAGS = -export-dynamic

test_programs = \
	$(ICU_TESTS) \
	$(TEST_FTS_LANGUAGE) \
	test-fts-filter \
	test-fts-tokenizer

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../lib-test/libtest.la \
	../lib/liblib.la
test_deps = $(noinst_LTLIBRARIES) $(test_libs)

test_fts_icu_SOURCES = test-fts-icu.c
test_fts_icu_LDADD = fts-icu.lo $(LIBICU_LIBS) $(test_libs)
test_fts_icu_DEPENDENCIES = fts-icu.lo $(test_deps)

test_fts_filter_SOURCES = test-fts-filter.c
test_fts_filter_LDADD = libfts.la $(test_libs)
test_fts_filter_DEPENDENCIES = libfts.la $(test_deps)

if BUILD_FTS_EXTTEXTCAT
TEST_FTS_LANGUAGE = test-fts-language
test_fts_language_SOURCES = test-fts-language.c
test_fts_language_LDADD = fts-language.lo $(test_libs) $(TEXTCAT_LIBS)
test_fts_language_DEPENDENCIES = $(test_deps)
endif

test_fts_tokenizer_SOURCES = test-fts-tokenizer.c
test_fts_tokenizer_LDADD = fts-tokenizer.lo fts-tokenizer-generic.lo fts-tokenizer-address.lo fts-tokenizer-common.lo ../lib-mail/libmail.la $(test_libs)
test_fts_tokenizer_DEPENDENCIES = ../lib-mail/libmail.la $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
