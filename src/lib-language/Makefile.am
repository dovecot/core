include $(top_srcdir)/Makefile.test.include

noinst_LTLIBRARIES = liblanguage.la

# automake seems to force making this unconditional..
NOPLUGIN_LDFLAGS =

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-var-expand \
	$(LIBEXTTEXTCAT_CFLAGS) \
	$(LIBICU_CFLAGS) \
	-DUDHRDIR=\""$(top_srcdir)/src/lib-language"\" \
	-DDATADIR=\"$(pkgdatadir)\" \
	-DMODULE_DIR=\""$(moduledir)"\" \
	-DTEST_STOPWORDS_DIR=\""$(top_srcdir)/src/lib-language/stopwords"\" \
	-DTEST_MODULE_DIR=\""$(abs_builddir)/.libs"\"

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

EXTRA_DIST = \
	udhr_fra.txt \
	stopwords/stopwords_malformed.txt

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
module_LTLIBRARIES = liblang_filter_normalizer_icu.la
ICU_TESTS = test-lang-icu
endif

liblang_filter_normalizer_icu_la_LDFLAGS = -module -avoid-version
liblang_filter_normalizer_icu_la_LIBADD = libdovecot-language-icu.la
liblang_filter_normalizer_icu_la_SOURCES = \
	lang-filter-normalizer-icu.c

liblanguage_la_LIBADD = \
	$(STEMMER_LIBS) \
	$(TEXTCAT_LIBS)

liblanguage_la_SOURCES = \
	lang-filter.c \
	lang-filter-contractions.c \
	lang-filter-english-possessive.c \
	lang-filter-lowercase.c \
	lang-filter-normalizer.c \
	lang-filter-stopwords.c \
	lang-filter-stemmer-snowball.c \
	language.c \
	lang-library.c \
	lang-tokenizer.c \
	lang-tokenizer-address.c \
	lang-tokenizer-common.c \
	lang-tokenizer-generic.c \
	lang-settings.c

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

noinst_HEADERS = \
	lang-filter-normalizer-icu.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

pkglib_LTLIBRARIES = libdovecot-language.la
libdovecot_language_la_SOURCES =
libdovecot_language_la_LIBADD = liblanguage.la $(LIBDOVECOT)
libdovecot_language_la_DEPENDENCIES = liblanguage.la $(LIBDOVECOT_DEPS)
libdovecot_language_la_LDFLAGS = -export-dynamic

# libicu helper functions. These are in a separate library, so that linking
# libdovecot-language doesn't load libicu.
if BUILD_LIBICU
pkglib_LTLIBRARIES += libdovecot-language-icu.la
endif
libdovecot_language_icu_la_SOURCES = lang-icu.c
libdovecot_language_icu_la_LIBADD = $(LIBICU_LIBS) $(LIBDOVECOT)
libdovecot_language_icu_la_DEPENDENCIES = $(LIBDOVECOT_DEPS)
libdovecot_language_icu_la_LDFLAGS = -export-dynamic

test_programs = \
	$(ICU_TESTS) \
	$(TEST_LANGUAGE) \
	test-lang-filter \
	test-lang-tokenizer

test_libs = ../lib-dovecot/libdovecot.la
test_deps = $(noinst_LTLIBRARIES) $(test_libs)

test_lang_icu_SOURCES = test-lang-icu.c
test_lang_icu_LDADD = lang-filter-normalizer-icu.lo libdovecot-language-icu.la liblanguage.la $(LIBICU_LIBS) $(test_libs) $(LIBDOVECOT_TEST_LIBS)
test_lang_icu_DEPENDENCIES = lang-filter-normalizer-icu.lo libdovecot-language-icu.la liblanguage.la $(test_deps)

test_lang_filter_SOURCES = test-lang-filter.c
test_lang_filter_LDADD = liblanguage.la $(test_libs) $(LIBDOVECOT_TEST_LIBS)
test_lang_filter_DEPENDENCIES = liblanguage.la $(module_LTLIBRARIES) $(test_deps)

if BUILD_LANG_EXTTEXTCAT
TEST_LANGUAGE = test-language
test_language_SOURCES = test-language.c
test_language_LDADD = language.lo $(test_libs) $(LIBDOVECOT_TEST_LIBS) $(TEXTCAT_LIBS)
test_language_DEPENDENCIES = $(test_deps)
endif

test_lang_tokenizer_SOURCES = test-lang-tokenizer.c
test_lang_tokenizer_LDADD = liblanguage.la $(test_libs) $(LIBDOVECOT_TEST_LIBS)
test_lang_tokenizer_DEPENDENCIES = liblanguage.la $(test_deps)
