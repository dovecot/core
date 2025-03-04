noinst_LTLIBRARIES = liblanguage.la

# I$(top_srcdir)/src/lib-language needed to include
# word-break-data.c and word-boundary-data.c
# in lang-tokenizer-generic.c
AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-language \
	-I$(top_srcdir)/src/lib-var-expand \
	$(LIBEXTTEXTCAT_CFLAGS) \
	$(LIBICU_CFLAGS) \
	-DUDHRDIR=\""$(top_srcdir)/src/lib-language"\" \
	-DDATADIR=\"$(pkgdatadir)\" \
	-DTEST_STOPWORDS_DIR=\""$(top_srcdir)/src/lib-language/stopwords"\"

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
	$(AM_V_at)test -f $@ || $(WGET) -nv -O $@ https://dovecot.org/res/WordBreakProperty.txt
$(srcdir)/word-boundary-data.c: $(srcdir)/word-properties.pl $(srcdir)/WordBreakProperty.txt
	$(AM_V_at)perl $(srcdir)/word-properties.pl boundaries $(srcdir)/WordBreakProperty.txt > $@

$(srcdir)/PropList.txt:
	$(AM_V_at)test -f $@ || $(WGET) -nv -O $@ https://dovecot.org/res/PropList.txt
$(srcdir)/word-break-data.c: $(srcdir)/word-properties.pl $(srcdir)/PropList.txt
	$(AM_V_at)perl $(srcdir)/word-properties.pl breaks $(srcdir)/PropList.txt > $@


if BUILD_LANG_STEMMER
STEMMER_LIBS = -lstemmer
endif

if BUILD_LANG_EXTTEXTCAT
TEXTCAT_LIBS = $(LIBEXTTEXTCAT_LIBS)
else
if BUILD_LANG_TEXTCAT
TEXTCAT_LIBS = -ltextcat
endif
endif

if BUILD_LIBICU
ICU_SOURCES = lang-icu.c
NORMALIZER_LIBS = $(LIBICU_LIBS)
ICU_TESTS = test-lang-icu
endif

liblanguage_la_LIBADD = \
	$(STEMMER_LIBS) \
	$(TEXTCAT_LIBS) \
	$(NORMALIZER_LIBS)

liblanguage_la_SOURCES = \
	lang-filter.c \
	lang-filter-contractions.c \
	lang-filter-english-possessive.c \
	lang-filter-lowercase.c \
	lang-filter-normalizer-icu.c \
	lang-filter-stopwords.c \
	lang-filter-stemmer-snowball.c \
	language.c \
	lang-library.c \
	lang-tokenizer.c \
	lang-tokenizer-address.c \
	lang-tokenizer-common.c \
	lang-tokenizer-generic.c \
	lang-settings.c \
	$(ICU_SOURCES)

headers = \
	lang-common.h \
	lang-filter.h \
	lang-filter-private.h \
	lang-icu.h \
	language.h \
	lang-library.h \
	lang-tokenizer.h \
	lang-tokenizer-common.h \
	lang-tokenizer-private.h \
	lang-tokenizer-generic-private.h \
	lang-indexer-status.h \
	lang-settings.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

pkglib_LTLIBRARIES = libdovecot-language.la
libdovecot_language_la_SOURCES =
libdovecot_language_la_LIBADD = liblanguage.la $(LIBDOVECOT)
libdovecot_language_la_DEPENDENCIES = liblanguage.la $(LIBDOVECOT_DEPS)
libdovecot_language_la_LDFLAGS = -export-dynamic

test_programs = \
	$(ICU_TESTS) \
	$(TEST_LANGUAGE) \
	test-lang-filter \
	test-lang-tokenizer

noinst_PROGRAMS = $(test_programs)

test_libs = ../lib-dovecot/libdovecot.la
test_deps = $(noinst_LTLIBRARIES) $(test_libs)

test_lang_icu_SOURCES = test-lang-icu.c
test_lang_icu_LDADD = lang-icu.lo $(LIBICU_LIBS) $(test_libs)
test_lang_icu_DEPENDENCIES = lang-icu.lo $(test_deps)

test_lang_filter_SOURCES = test-lang-filter.c
test_lang_filter_LDADD = liblanguage.la $(test_libs)
test_lang_filter_DEPENDENCIES = liblanguage.la $(test_deps)

if BUILD_LANG_EXTTEXTCAT
TEST_LANGUAGE = test-language
test_language_SOURCES = test-language.c
test_language_LDADD = language.lo $(test_libs) $(TEXTCAT_LIBS)
test_language_DEPENDENCIES = $(test_deps)
endif

test_lang_tokenizer_SOURCES = test-lang-tokenizer.c
test_lang_tokenizer_LDADD = liblanguage.la $(test_libs)
test_lang_tokenizer_DEPENDENCIES = liblanguage.la $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
