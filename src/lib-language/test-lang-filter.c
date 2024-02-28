/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "sha2.h"
#include "str.h"
#include "unichar.h"
#include "test-common.h"
#include "language.h"
#include "lang-filter.h"
#include "settings.h"
#include "lang-settings.h"

#include <stdio.h>

#define MALFORMED "malformed"
#define UNKNOWN "bebobidoop"
#define LANG_EN "en"
#define LANG_FI "fi"
#define LANG_FR "fr"
#define LANG_NO "no"
#define LANG_SV "sv"

/* core filters don't use the event in lang_filter_create() */
static struct event *const event = NULL;

static struct lang_settings stopword_settings;
static void init_lang_settings(void)
{
	stopword_settings = lang_default_settings;
	stopword_settings.filter_stopwords_dir = TEST_STOPWORDS_DIR;
}

static struct lang_settings *make_settings(const char *lang,
					   const struct lang_settings *template)
{
	struct lang_settings *set = t_new(struct lang_settings, 1);
	*set = template != NULL ? *template : lang_default_settings;
	set->name = lang;
	return set;
}

static void test_lang_filter_find(void)
{
	test_begin("lang filter find");
	test_assert(lang_filter_find("stopwords") == lang_filter_stopwords);
	test_assert(lang_filter_find("snowball") == lang_filter_stemmer_snowball);
	test_assert(lang_filter_find("normalizer-icu") == lang_filter_normalizer_icu);
	test_assert(lang_filter_find("lowercase") == lang_filter_lowercase);
	test_assert(lang_filter_find("contractions") == lang_filter_contractions);
	test_end();
}

static void test_lang_filter_contractions_fail(void)
{

	struct lang_filter *filter;
	const char *error;

	test_begin("lang filter contractions, unsupported language");
	test_assert(lang_filter_create(lang_filter_contractions, NULL, make_settings(LANG_EN, NULL), event, &filter, &error) != 0);
	test_assert(error != NULL);
	test_end();
}

static void test_lang_filter_contractions_fr(void)
{
	static const struct {
		const char *input;
		const char *output;
	} tests[] = {
		{ "foo", "foo" },
		{ "you're", "you're" },
		{ "l'homme", "homme" },
		{ "l\xE2\x80\x99homme", "homme" },
		{ "aujourd'hui", "aujourd'hui" },
		{ "qu\xE2\x80\x99il", "il" },
		{ "qu'il", "il" },
		{ "du'il", "du'il" },
		{ "que", "que" },
		{ "'foobar'", "'foobar'" },
		{ "foo'bar", "foo'bar" },
		{ "a'foo", "a'foo" },
		{ "cu'", "cu'" },
		{ "qu", "qu" },
		{ "d", "d" },
		{ "qu'", NULL },
		{ "j'adore", "adore" },
		{ "quelqu'un", "quelqu'un" },
		{ "l'esprit", "esprit" }
	};
	struct lang_filter *filter;
	const char *error;
	const char *token;
	unsigned int i;
	int ret;

	test_begin("lang filter contractions, French");
	test_assert(lang_filter_create(lang_filter_contractions, NULL, make_settings(LANG_FR, NULL), event, &filter, &error) == 0);

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		token = tests[i].input;
		ret = lang_filter(filter, &token, &error);
		test_assert(ret >= 0);
		if (ret > 0)
			test_assert_idx(strcmp(token, tests[i].output) == 0, i);
		else if (ret == 0)
			test_assert_idx(token == NULL && tests[i].output == NULL, i);
	}
	lang_filter_unref(&filter);
	test_end();
}

static void test_lang_filter_lowercase(void)
{
	static const struct {
		const char *input;
		const char *output;
	} tests[] = {
		{ "foo", "foo" },
		{ "FOO", "foo" },
		{ "fOo", "foo" }
	};
	struct lang_filter *filter;
	const char *error;
	const char *token;
	unsigned int i;

	test_begin("lang filter lowercase");
	test_assert(lang_filter_create(lang_filter_lowercase, NULL, make_settings(LANG_EN, NULL), event, &filter, &error) == 0);

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		token = tests[i].input;
		test_assert_idx(lang_filter(filter, &token, &error) > 0 &&
				strcmp(token, tests[i].output) == 0, 0);
	}
	lang_filter_unref(&filter);
	test_end();
}

#ifdef HAVE_LIBICU
static void test_lang_filter_lowercase_utf8(void)
{
	static const struct {
		const char *input;
		const char *output;
	} tests[] = {
		{ "f\xC3\x85\xC3\x85", "f\xC3\xA5\xC3\xA5" },
		{ "F\xC3\x85\xC3\x85", "f\xC3\xA5\xC3\xA5" },
		{ "F\xC3\x85\xC3\xA5", "f\xC3\xA5\xC3\xA5" }
	};
	struct lang_filter *filter;
	const char *error;
	const char *token;
	unsigned int i;

	test_begin("lang filter lowercase, UTF8");
	test_assert(lang_filter_create(lang_filter_lowercase, NULL, make_settings(LANG_EN, NULL), event, &filter, &error) == 0);

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		token = tests[i].input;
		test_assert_idx(lang_filter(filter, &token, &error) > 0 &&
		                strcmp(token, tests[i].output) == 0, 0);
	}
	lang_filter_unref(&filter);
	test_end();
}

#endif

static void test_lang_filter_stopwords_eng(void)
{
	struct lang_filter *filter;
	const char *error;
	int ret;
	const char *input[] = {"an", "elephant", "and", "a", "bear",
	                       "drive", "by", "for", "no", "reason",
	                       "they", "will", "not",  "sing", NULL};
	const char *output[] = {NULL, "elephant", NULL, NULL, "bear",
	                       "drive", NULL, NULL, NULL, "reason",
	                       NULL, NULL, NULL,  "sing"};
	const char **ip, **op;
	const char *token;

	test_begin("lang filter stopwords, English");
	test_assert(lang_filter_create(lang_filter_stopwords, NULL, make_settings(LANG_EN, &stopword_settings), event, &filter, &error) == 0);

	ip = input;
	op = output;
	while (*ip != NULL) {
		token = *ip;
		ret = lang_filter(filter, &token, &error);
		if (ret <= 0) {
			test_assert(ret == 0);
			test_assert(*op == NULL);
		} else {
			test_assert(*op != NULL);
			test_assert(strcmp(*ip, token)  == 0);
		}
		op++;
		ip++;
	}

	lang_filter_unref(&filter);
	test_assert(filter == NULL);
	test_end();
}

static void test_lang_filter_stopwords_fin(void)
{
	struct lang_filter *filter;
	const char *error;
	int ret;
	const char *input[] = {"olla", "vaiko", "eik\xC3\xB6", "olla",
	                       "kenest\xC3\xA4", "ja", "joista", "jonka",
	                       "testi", NULL};
	const char *output[] = {NULL, "vaiko", "eik\xC3\xB6", NULL, NULL,
	                        NULL, NULL, NULL, "testi"};
	const char *input2[] =
		{"kuka", "kenet", "keneen", "testi", "eiv\xC3\xA4t", NULL};
	const char *output2[] = {NULL, NULL, NULL, "testi", NULL};
	const char **ip, **op;
	const char *token;

	test_begin("lang filter stopwords, Finnish");
	test_assert(lang_filter_create(lang_filter_stopwords, NULL, make_settings(LANG_FI, &stopword_settings), event, &filter, &error) == 0);

	ip = input;
	op = output;
	while (*ip != NULL) {
		token = *ip;
		ret = lang_filter(filter, &token, &error);
		if (ret <= 0) {
			test_assert(ret == 0);
			test_assert(*op == NULL);
		} else {
			test_assert(*op != NULL);
			test_assert(strcmp(*ip, token)  == 0);
		}
		op++;
		ip++;
	}

	lang_filter_unref(&filter);
	test_assert(filter == NULL);

	test_assert(lang_filter_create(lang_filter_stopwords, NULL, make_settings(LANG_FI, &stopword_settings), event, &filter, &error) == 0);
	ip = input2;
	op = output2;
	while (*ip != NULL) {
		token = *ip;
		ret = lang_filter(filter, &token, &error);
		if (ret <= 0) {
			test_assert(ret == 0);
			test_assert(*op == NULL);
		} else {
			test_assert(*op != NULL);
			test_assert(strcmp(*ip, token)  == 0);
		}
		op++;
		ip++;
	}

	lang_filter_unref(&filter);
	test_assert(filter == NULL);
	test_end();
}

static void test_lang_filter_stopwords_fra(void)
{
	struct lang_filter *filter;
	const char *error;
	int ret;

	const char *input[] = {"e\xC3\xBBt", "soyez", "soi", "peut", "que",
	                       "quelconque", "\xC3\xA9t\xC3\xA9",
	                       "l\xE2\x80\x99""av\xC3\xA8nement",
	                       NULL};
	const char *output[] = {NULL, NULL, NULL, "peut", NULL,
	                        "quelconque", NULL,
	                        "l\xE2\x80\x99""av\xC3\xA8nement",};
	const char **ip, **op;
	const char *token;

	test_begin("lang filter stopwords, French");
	test_assert(lang_filter_create(lang_filter_stopwords, NULL, make_settings(LANG_FR, &stopword_settings), event, &filter, &error) == 0);

	ip = input;
	op = output;
	while (*ip != NULL) {
		token = *ip;
		ret = lang_filter(filter, &token, &error);
		if (ret <= 0) {
			test_assert(ret == 0);
			test_assert(*op == NULL);
		} else {
			test_assert(*op != NULL);
			test_assert(strcmp(*ip, token)  == 0);
		}
		op++;
		ip++;
	}

	lang_filter_unref(&filter);
	test_assert(filter == NULL);
	test_end();
}

static void test_lang_filter_stopwords_no(void)
{
	struct lang_filter *filter;
	const char *error;
	int ret;

	const char *input[] = {"og", "d\xC3\xA5", "medlemsstatane", "har",
	                       "bunde", "seg", "til", "\xC3\xA5", "fremje",
	                       "allmenn", "v\xC3\xB8rdnad", "for", "pakta",
	                       "og", "halde", "seg", "etter", "menneskerettane",
	                       "og", "den", "grunnleggjande", "fridomen", "i",
	                       "samarbeid", "med", "Dei", "Sameinte",
	                       "Nasjonane", NULL};

	const char *output[] = {NULL, NULL, "medlemsstatane", NULL,
	                       "bunde", NULL, NULL, NULL, "fremje",
	                       "allmenn", "v\xC3\xB8rdnad", NULL, "pakta",
	                       NULL, "halde", NULL, NULL, "menneskerettane",
	                       NULL, NULL, "grunnleggjande", "fridomen", NULL,
	                       "samarbeid", NULL, "Dei", "Sameinte",
	                       "Nasjonane"};
	const char **ip, **op;
	const char *token;

	test_begin("lang filter stopwords, Norwegian");
	test_assert(lang_filter_create(lang_filter_stopwords, NULL, make_settings(LANG_NO, &stopword_settings), event, &filter, &error) == 0);

	ip = input;
	op = output;
	while (*ip != NULL) {
		token = *ip;
		ret = lang_filter(filter, &token, &error);
		if (ret <= 0) {
			test_assert(ret == 0);
			test_assert(*op == NULL);
		} else {
			test_assert(*op != NULL);
			test_assert(strcmp(*ip, token)  == 0);
		}
		op++;
		ip++;
	}

	lang_filter_unref(&filter);
	test_assert(filter == NULL);
	test_end();
}

static void test_lang_filter_stopwords_fail_lazy_init(void)
{
	struct lang_filter *filter = NULL;
	const char *error = NULL, *token = "foobar";

	test_begin("lang filter stopwords, fail filter() (lazy init)");
	test_assert(lang_filter_create(lang_filter_stopwords, NULL, make_settings(UNKNOWN, &stopword_settings), event, &filter, &error) == 0);
	test_assert(filter != NULL && error == NULL);
	test_assert(lang_filter(filter, &token, &error) < 0 && error != NULL);
	lang_filter_unref(&filter);
	test_end();

}

static void test_lang_filter_stopwords_malformed(void)
{
	struct lang_filter *filter = NULL;
	const char *error = NULL, *token = "foobar";

	test_begin("lang filter stopwords, malformed list");
	test_assert(lang_filter_create(lang_filter_stopwords, NULL, make_settings(MALFORMED, &stopword_settings), event, &filter, &error) == 0);
	test_assert(lang_filter(filter, &token, &error) < 0);
	test_assert(strstr(error, "seems empty. Is the file correctly formatted?") != NULL);
	test_expect_no_more_errors();
	lang_filter_unref(&filter);
	test_end();

}

#ifdef HAVE_LANG_STEMMER
static void test_lang_filter_stemmer_snowball_stem_english(void)
{
	struct lang_filter *stemmer;
	const char *error;
	const char *token = NULL;
	const char * const tokens[] = {
		"dries" ,"friendlies", "All", "human", "beings", "are",
		 "born", "free", "and", "equal", "in", "dignity", "and",
		 "rights", "They", "are", "endowed", "with", "reason", "and",
		 "conscience", "and", "should", "act", "towards", "one",
		 "another", "in", "a", "spirit", "of", "brotherhood", NULL};
	const char * const bases[] = {
		"dri" ,"friend", "All", "human", "be", "are", "born", "free",
		"and", "equal", "in", "digniti", "and", "right", "They", "are",
		"endow", "with", "reason", "and", "conscienc", "and", "should",
		"act", "toward", "one", "anoth", "in", "a", "spirit", "of",
		"brotherhood", NULL};
	const char * const *tpp;
	const char * const *bpp;

	test_begin("lang filter stem English");
	test_assert(lang_filter_create(lang_filter_stemmer_snowball, NULL, make_settings(LANG_EN, NULL), event, &stemmer, &error) == 0);
	bpp = bases;
	for (tpp=tokens; *tpp != NULL; tpp++) {
		token = *tpp;
		test_assert(lang_filter(stemmer, &token, &error) > 0);
		test_assert(token != NULL);
		test_assert(null_strcmp(token, *bpp) == 0);
		bpp++;
	}
	lang_filter_unref(&stemmer);
	test_assert(stemmer == NULL);
	test_end();
}

static void test_lang_filter_stemmer_snowball_stem_french(void)
{
	struct lang_filter *stemmer;
	const char *error;
	const char *token = NULL;
	const char * const tokens[] = {
		"Tous", "les", "\xC3\xAAtres", "humains", "naissent",
		"libres", "et",	"\xC3\xA9gaux", "en", "dignit\xC3\xA9",
		"et", "en", "droits", NULL};
	const char * const bases[] = {
		"Tous" ,"le", "\xC3\xAAtre", "humain", "naissent", "libr", "et",
		"\xC3\xA9gal", "en", "dignit", "et", "en", "droit", NULL};
	const char * const *tpp;
	const char * const *bpp;

	test_begin("lang filter stem French");
	test_assert(lang_filter_create(lang_filter_stemmer_snowball, NULL, make_settings(LANG_FR, NULL), event, &stemmer, &error) == 0);
	bpp = bases;
	for (tpp=tokens; *tpp != NULL; tpp++) {
		token = *tpp;
		test_assert(lang_filter(stemmer, &token, &error) > 0);
		test_assert(token != NULL);
		test_assert(null_strcmp(token, *bpp) == 0);
		bpp++;
	}
	lang_filter_unref(&stemmer);
	test_assert(stemmer == NULL);
	test_end();
}

static void test_lang_filter_stopwords_stemmer_eng(void)
{
	int ret;
	struct lang_filter *stemmer;
	struct lang_filter *filter;
	const char *error;
	const char *token = NULL;
	const char * const tokens[] = {
		"dries" ,"friendlies", "All", "human", "beings", "are",
		 "born", "free", "and", "equal", "in", "dignity", "and",
		 "rights", "They", "are", "endowed", "with", "reason", "and",
		 "conscience", "and", "should", "act", "towards", "one",
		 "another", "in", "a", "spirit", "of", "brotherhood", NULL};
	const char * const bases[] = {
		"dri" ,"friend", "All", "human", "be", NULL, "born", "free",
		NULL, "equal", NULL, "digniti", NULL, "right", "They", NULL,
		"endow", NULL, "reason", NULL, "conscienc", NULL, "should",
		"act", "toward", "one", "anoth", NULL, NULL, "spirit", NULL,
		"brotherhood", NULL};
	const char * const *tpp;
	const char * const *bpp;

	test_begin("lang filters stopwords and stemming chained, English");

	test_assert(lang_filter_create(lang_filter_stopwords, NULL, make_settings(LANG_EN, &stopword_settings), event, &filter, &error) == 0);
	test_assert(lang_filter_create(lang_filter_stemmer_snowball, filter, make_settings(LANG_EN, NULL), event, &stemmer, &error) == 0);

	bpp = bases;
	for (tpp=tokens; *tpp != NULL; tpp++) {
		token = *tpp;
		ret = lang_filter(stemmer, &token, &error);
		test_assert(ret >= 0);
		if (ret == 0)
			test_assert(*bpp == NULL);
		else {
			test_assert(*bpp != NULL);
			test_assert(null_strcmp(*bpp, token)  == 0);
		}
		bpp++;
	}
	lang_filter_unref(&stemmer);
	lang_filter_unref(&filter);
	test_assert(stemmer == NULL);
	test_assert(filter == NULL);
	test_end();
}
#endif

#ifdef HAVE_LIBICU
static void test_lang_filter_normalizer_swedish_short(void)
{
	struct lang_filter *norm = NULL;
	const char *input[] = {
		"Vem",
		"\xC3\x85",
		"\xC3\x85\xC3\x84\xC3\x96",
		("Vem kan segla f\xC3\xB6rutan vind?\n"
		 "\xC3\x85\xC3\x84\xC3\x96\xC3\xB6\xC3\xA4\xC3\xA5")
	};
	const char *expected_output[] = {
		"vem",
		"a",
		"aao",
		"vem kan segla forutan vind?\naaooaa"
	};
	struct lang_settings set = lang_default_settings;
	set.filter_normalizer_icu_id = "Any-Lower; NFKD; [: Nonspacing Mark :] Remove; NFC";
	const char *error = NULL;
	const char *token = NULL;
	unsigned int i;

	test_begin("lang filter normalizer Swedish short text");

	test_assert(lang_filter_create(lang_filter_normalizer_icu, NULL, make_settings(NULL, &set), event, &norm, &error) == 0);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		token = input[i];
		test_assert_idx(lang_filter(norm, &token, &error) == 1, i);
		test_assert_idx(null_strcmp(token, expected_output[i]) == 0, i);
	}
	lang_filter_unref(&norm);
	test_assert(norm == NULL);
	test_end();
}

static void test_lang_filter_normalizer_swedish_short_default_id(void)
{
	struct lang_filter *norm = NULL;
	const char *input[] = {
		"Vem",
		"\xC3\x85",
		"\xC3\x85\xC3\x84\xC3\x96",
		("Vem kan segla f\xC3\xB6rutan vind?\n"
		 "\xC3\x85\xC3\x84\xC3\x96\xC3\xB6\xC3\xA4\xC3\xA5")
	};
	const char *expected_output[] = {
		"vem",
		"a",
		"aao",
		"vemkanseglaforutanvind?\naaooaa"
	};
	const char *error = NULL;
	const char *token = NULL;
	unsigned int i;

	test_begin("lang filter normalizer Swedish short text using default ID");

	test_assert(lang_filter_create(lang_filter_normalizer_icu, NULL, make_settings(NULL, NULL), event, &norm, &error) == 0);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		token = input[i];
		test_assert_idx(lang_filter(norm, &token, &error) == 1, i);
		test_assert_idx(null_strcmp(token, expected_output[i]) == 0, i);
	}
	lang_filter_unref(&norm);
	test_assert(norm == NULL);
	test_end();
}

/* UDHRDIR comes from Automake AM_CPPFLAGS */
#define UDHR_FRA_NAME "/udhr_fra.txt"
static void test_lang_filter_normalizer_french(void)
{
	struct lang_filter *norm = NULL;
	FILE *input;
	struct lang_settings set = lang_default_settings;
	set.filter_normalizer_icu_id = "Any-Lower; NFKD; [: Nonspacing Mark :] Remove";
	char buf[250] = {0};
	const char *error = NULL;
	const char *tokens;
	unsigned char sha512_digest[SHA512_RESULTLEN];
	struct sha512_ctx ctx;
	const unsigned char correct_digest[] = {
		0x06, 0x80, 0xf1, 0x81, 0xf2, 0xed, 0xfb, 0x6d,
		0xcd, 0x7d, 0xcb, 0xbd, 0xc4, 0x87, 0xc3, 0xf6,
		0xb8, 0x6a, 0x01, 0x82, 0xdf, 0x0a, 0xb5, 0x92,
		0x6b, 0x9b, 0x7b, 0x21, 0x5e, 0x62, 0x40, 0xbd,
		0xbf, 0x15, 0xb9, 0x7b, 0x75, 0x9c, 0x4e, 0xc9,
		0xe8, 0x48, 0xaa, 0x08, 0x63, 0xf2, 0xa0, 0x6c,
		0x20, 0x4c, 0x01, 0xe3, 0xb3, 0x4f, 0x15, 0xc6,
		0x8c, 0xd6, 0x7a, 0xb7, 0xc5, 0xc6, 0x85, 0x00};
	const char *udhr_path;

	test_begin("lang filter normalizer French UDHR");

	udhr_path = t_strconcat(UDHRDIR, UDHR_FRA_NAME, NULL);
	test_assert(lang_filter_create(lang_filter_normalizer_icu, NULL, make_settings(NULL, &set), event, &norm, &error) == 0);
	input = fopen(udhr_path, "r");
	test_assert(input != NULL);
	sha512_init(&ctx);
	while (NULL != fgets(buf, sizeof(buf), input)) {
		tokens = buf;
		if (lang_filter(norm, &tokens, &error) != 1){
			break;
		}
		sha512_loop(&ctx, tokens, strlen(tokens));
	}
	fclose(input);
	sha512_result(&ctx, sha512_digest);
	test_assert(memcmp(sha512_digest, correct_digest,
			   sizeof(sha512_digest)) == 0);
	lang_filter_unref(&norm);
	test_assert(norm == NULL);
	test_end();
}

static void test_lang_filter_normalizer_empty(void)
{
	/* test just a couple of these */
	static const char *empty_tokens[] = {
		"\xC2\xAF", /* U+00AF */
		"\xCC\x80", /* U+0300 */
		"\xF3\xA0\x87\xAF", /* U+E01EF */
		"\xCC\x80\xF3\xA0\x87\xAF" /* U+0300 U+E01EF */
	};
	struct lang_settings set = lang_default_settings;
	set.filter_normalizer_icu_id = "Any-Lower; NFKD; [: Nonspacing Mark :] Remove; [\\x20] Remove";
	struct lang_filter *norm;
	const char *error;
	unsigned int i;

	test_begin("lang filter normalizer empty tokens");
	test_assert(lang_filter_create(lang_filter_normalizer_icu, NULL, make_settings(NULL, &set), event, &norm, &error) == 0);
	for (i = 0; i < N_ELEMENTS(empty_tokens); i++) {
		const char *token = empty_tokens[i];
		test_assert_idx(lang_filter(norm, &token, &error) == 0, i);
	}
	lang_filter_unref(&norm);
	test_end();
}

static void test_lang_filter_normalizer_baddata(void)
{
	struct lang_settings set = lang_default_settings;
	set.filter_normalizer_icu_id = "Any-Lower; NFKD; [: Nonspacing Mark :] Remove";
	struct lang_filter *norm;
	const char *token, *error;
	string_t *str;
	unichar_t i;

	test_begin("lang filter normalizer bad data");

	test_assert(lang_filter_create(lang_filter_normalizer_icu, NULL, make_settings(NULL, &set), event, &norm, &error) == 0);
	str = t_str_new(128);
	for (i = 1; i < 0x1ffff; i++) {
		if (!uni_is_valid_ucs4(i)) continue;
		str_truncate(str, 0);
		uni_ucs4_to_utf8_c(i, str);
		token = str_c(str);
		T_BEGIN {
			test_assert_idx(lang_filter(norm, &token, &error) >= 0, i);
		} T_END;
	}

	str_truncate(str, 0);
	uni_ucs4_to_utf8_c(UNICHAR_T_MAX, str);
	token = str_c(str);
	test_assert(lang_filter(norm, &token, &error) >= 0);

	lang_filter_unref(&norm);
	test_end();
}

static void test_lang_filter_normalizer_invalid_id(void)
{
	struct lang_filter *norm = NULL;
	struct lang_settings set = lang_default_settings;
	set.filter_normalizer_icu_id = "Any-One-Out-There; DKFN; [: Nonspacing Mark :] Remove";
	const char *error = NULL, *token = "foo";

	test_begin("lang filter normalizer invalid id");
	test_assert(lang_filter_create(lang_filter_normalizer_icu, NULL, make_settings(NULL, &set), event, &norm, &error) == 0);
	test_assert(error == NULL);
	test_assert(lang_filter(norm, &token, &error) < 0 && error != NULL);
	lang_filter_unref(&norm);
	test_end();
}

#ifdef HAVE_LANG_STEMMER
static void test_lang_filter_normalizer_stopwords_stemmer_eng(void)
{
	int ret;
	struct lang_filter *normalizer;
	struct lang_filter *stemmer;
	struct lang_filter *filter;
	const char *error;
	struct lang_settings set = lang_default_settings;
	// set.filter_normalizer_icu_id = "Any-Lower; NFKD; [: Nonspacing Mark :] Remove; NFC"
	set.filter_normalizer_icu_id = "Lower";
	const char *token = NULL;
	const char * const tokens[] = {
		"dries" ,"friendlies", "All", "human", "beings", "are",
		"born", "free", "and", "equal", "in", "dignity", "and",
		"rights", "They", "are", "endowed", "with", "reason", "and",
		"conscience", "and", "should", "act", "towards", "one",
		"another", "in", "a", "spirit", "of", "brotherhood", "ABCFoo",
		NULL};
	const char * const bases[] = {
		"dri" ,"friend", "all", "human", "be", NULL, "born", "free",
		NULL, "equal", NULL, "digniti", NULL, "right", NULL, NULL,
		"endow", NULL, "reason", NULL, "conscienc", NULL, "should",
		"act", "toward", "one", "anoth", NULL, NULL, "spirit", NULL,
		"brotherhood", "abcfoo", NULL};
	const char * const *tpp;
	const char * const *bpp;

	test_begin("lang filters normalizer, stopwords and stemming chained, English");

	test_assert(lang_filter_create(lang_filter_normalizer_icu, NULL, make_settings(NULL, &set), event, &normalizer, &error) == 0);
	test_assert(lang_filter_create(lang_filter_stopwords, normalizer, make_settings(LANG_EN, &stopword_settings), event, &filter, &error) == 0);
	test_assert(lang_filter_create(lang_filter_stemmer_snowball, filter, make_settings(LANG_EN, NULL), event, &stemmer, &error) == 0);

	bpp = bases;
	for (tpp = tokens; *tpp != NULL; tpp++) {
		token = *tpp;
		ret = lang_filter(stemmer, &token, &error);
		if (ret <= 0) {
			test_assert(ret == 0);
			test_assert(*bpp == NULL);
		} else {
			test_assert(*bpp != NULL);
			test_assert(strcmp(*bpp, token)  == 0);
		}
		bpp++;
	}
	lang_filter_unref(&stemmer);
	lang_filter_unref(&filter);
	lang_filter_unref(&normalizer);
	test_assert(stemmer == NULL);
	test_assert(filter == NULL);
	test_assert(normalizer == NULL);
	test_end();
}

static void test_lang_filter_stopwords_normalizer_stemmer_no(void)
{
	int ret;
	struct lang_filter *normalizer;
	struct lang_filter *stemmer;
	struct lang_filter *filter;
	const char *error;
	const char *token = NULL;
	const char * const tokens[] = {
		/* Nynorsk*/
		"Alle", "har", "plikter", "andsynes", "samfunnet", "d\xC3\xA5",
		"personlegdomen", "til", "den", "einskilde", "einast", "der",
		"kan", "f\xC3\xA5", "frie", "og", "fullgode",
		"voksterk\xC3\xA5r",
		/* Bokmal */
		"Alle", "mennesker", "er", "f\xC3\xB8""dt", "frie", "og", "med",
		"samme", "menneskeverd", "og", "menneskerettigheter", "De",
		"er", "utstyrt", "med", "fornuft", "og", "samvittighet",
		"og", "b\xC3\xB8r", "handle", "mot", "hverandre", "i",
		"brorskapets", "\xC3\xA5nd", NULL};

	const char * const bases[] = {
		/* Nynorsk*/
		"all", NULL, "plikt", "andsyn", "samfunn", NULL,
		"personlegdom", NULL, NULL, "einskild", "ein", NULL, NULL,
		"fa", "frie", NULL, "fullgod", "voksterk",
		/* Bokmal */
		"all", "mennesk", NULL, "f\xC3\xB8""dt", "frie", NULL, NULL,
		NULL, "menneskeverd", NULL, "menneskerett", "de", NULL,
		"utstyrt", NULL, "fornuft", NULL, "samvitt", NULL, "b\xC3\xB8r",
		"handl", NULL, "hverandr", NULL, "brorskap", "and", NULL};
	const char * const *tpp;
	const char * const *bpp;

	test_begin("lang filters with stopwords, default normalizer and stemming chained, Norwegian");

	test_assert(lang_filter_create(lang_filter_stopwords, NULL, make_settings(LANG_NO, &stopword_settings), event, &filter, &error) == 0);
	test_assert(lang_filter_create(lang_filter_normalizer_icu, filter, make_settings(NULL, NULL), event, &normalizer, &error) == 0);
	test_assert(lang_filter_create(lang_filter_stemmer_snowball, normalizer, make_settings(LANG_NO, NULL), event, &stemmer, &error) == 0);

	bpp = bases;
	for (tpp = tokens; *tpp != NULL; tpp++) {
		token = *tpp;
		ret = lang_filter(stemmer, &token, &error);
		if (ret <= 0) {
			test_assert(ret == 0);
			test_assert(*bpp == NULL);
		} else {
			test_assert(*bpp != NULL);
			test_assert(null_strcmp(*bpp, token) == 0);
		}
		bpp++;
	}
	lang_filter_unref(&stemmer);
	lang_filter_unref(&normalizer);
	lang_filter_unref(&filter);
	test_assert(stemmer == NULL);
	test_assert(filter == NULL);
	test_assert(normalizer == NULL);
	test_end();
}

static void test_lang_filter_stopwords_normalizer_stemmer_sv(void)
{
	int ret;
	struct lang_filter *normalizer;
	struct lang_filter *stemmer;
	struct lang_filter *filter;
	const char *error;
	const char *token = NULL;
	const char * const tokens[] = {
		"Enär", "erkännandet", "av", "det", "inneboende", "värdet",
		"hos", "alla", "medlemmar", "av", "människosläktet", "och",
		"av", "deras", "lika", "och", "oförytterliga", "rättigheter",
		"är", "grundvalen", "för", "frihet", "rättvisa", "och", "fred",
		"i", "världen",	NULL};
	const char * const bases[] = {
		"enar", "erkan", NULL, NULL, "inneboend", "vardet", "hos", NULL,
		"medlemm", NULL, "manniskoslaktet", NULL, NULL, NULL, "lik",
		NULL, "oforytter", "ratt", NULL, "grundval", NULL, "frihet",
		"rattvis", NULL, "fred", NULL, "varld", NULL};
	const char * const *tpp;
	const char * const *bpp;

	test_begin("lang filters with stopwords, default normalizer and stemming chained, Swedish");


	test_assert(lang_filter_create(lang_filter_stopwords, NULL, make_settings(LANG_SV, &stopword_settings), event, &filter, &error) == 0);
	test_assert(lang_filter_create(lang_filter_normalizer_icu, filter, make_settings(NULL, NULL), event, &normalizer, &error) == 0);
	test_assert(lang_filter_create(lang_filter_stemmer_snowball, normalizer, make_settings(LANG_SV, NULL), event, &stemmer, &error) == 0);

	bpp = bases;
	for (tpp = tokens; *tpp != NULL; tpp++) {
		token = *tpp;
		ret = lang_filter(stemmer, &token, &error);
		if (ret <= 0) {
			test_assert(ret == 0);
			test_assert(*bpp == NULL);
		} else {
			test_assert(*bpp != NULL);
			test_assert(null_strcmp(*bpp, token) == 0);
		}
		bpp++;
	}
	lang_filter_unref(&stemmer);
	lang_filter_unref(&normalizer);
	lang_filter_unref(&filter);
	test_assert(stemmer == NULL);
	test_assert(filter == NULL);
	test_assert(normalizer == NULL);
	test_end();
}
#endif
#endif

static void test_lang_filter_english_possessive(void)
{
	struct lang_filter *norm = NULL;
	const char *input[] = {
		"foo'",

		"foo's",
		"foo\xC3\xA4's",
		"foo'S",
		"foos'S",
		"foo's's",
		"foo'ss",

		"foo\xE2\x80\x99s",
		"foo\xC3\xA4\xE2\x80\x99s",
		"foo\xE2\x80\x99S",
		"foos\xE2\x80\x99S",
		"foo\xE2\x80\x99s\xE2\x80\x99s",
		"foo\xE2\x80\x99ss"
	};
	const char *expected_output[] = {
		"foo'",

		"foo",
		"foo\xC3\xA4",
		"foo",
		"foos",
		"foo's",
		"foo'ss",

		"foo",
		"foo\xC3\xA4",
		"foo",
		"foos",
		"foo\xE2\x80\x99s",
		"foo\xE2\x80\x99ss"
	};
	const char *error = NULL;
	const char *token = NULL;
	unsigned int i;

	test_begin("lang filter english possessive");

	test_assert(lang_filter_create(lang_filter_english_possessive, NULL, make_settings(NULL, NULL), event, &norm, &error) == 0);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		token = input[i];
		test_assert_idx(lang_filter(norm, &token, &error) == 1, i);
		test_assert_idx(null_strcmp(token, expected_output[i]) == 0, i);
	}
	lang_filter_unref(&norm);
	test_assert(norm == NULL);
	test_end();
}

/* TODO: Functions to test 1. ref-unref pairs 2. multiple registers +
  an unregister + find */

int main(void)
{
	init_lang_settings();
	static void (*const test_functions[])(void) = {
		test_lang_filter_find,
		test_lang_filter_contractions_fail,
		test_lang_filter_contractions_fr,
		test_lang_filter_lowercase,
#ifdef HAVE_LIBICU
		test_lang_filter_lowercase_utf8,
#endif
		test_lang_filter_stopwords_eng,
		test_lang_filter_stopwords_fin,
		test_lang_filter_stopwords_fra,
		test_lang_filter_stopwords_no,
		test_lang_filter_stopwords_fail_lazy_init,
		test_lang_filter_stopwords_malformed,
#ifdef HAVE_LANG_STEMMER
		test_lang_filter_stemmer_snowball_stem_english,
		test_lang_filter_stemmer_snowball_stem_french,
		test_lang_filter_stopwords_stemmer_eng,
#endif
#ifdef HAVE_LIBICU
		test_lang_filter_normalizer_swedish_short,
		test_lang_filter_normalizer_swedish_short_default_id,
		test_lang_filter_normalizer_french,
		test_lang_filter_normalizer_empty,
		test_lang_filter_normalizer_baddata,
		test_lang_filter_normalizer_invalid_id,
#ifdef HAVE_LANG_STEMMER
		test_lang_filter_normalizer_stopwords_stemmer_eng,
		test_lang_filter_stopwords_normalizer_stemmer_no,
		test_lang_filter_stopwords_normalizer_stemmer_sv,
#endif
#endif
		test_lang_filter_english_possessive,
		NULL
	};
	int ret;

	lang_filters_init();
	ret = test_run(test_functions);
	lang_filters_deinit();
	return ret;
}
