/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "unichar.h"
#include "str.h"
#include "test-common.h"
#include "lang-tokenizer.h"
#include "lang-tokenizer-common.h"
#include "lang-tokenizer-private.h"
#include "lang-tokenizer-generic-private.h"
#include "lang-settings.h"

/* core filters don't use the event in lang_filter_create() */
static struct event *const event = NULL;

static struct lang_settings simple_settings;
static struct lang_settings tr29_settings;
static struct lang_settings tr29_wb5a_settings;

static void init_lang_settings(void)
{
	simple_settings = lang_default_settings;
	simple_settings.tokenizer_generic_algorithm = "simple";

	tr29_settings = lang_default_settings;
	tr29_settings.tokenizer_generic_algorithm = "tr29";

	tr29_wb5a_settings = lang_default_settings;
	tr29_wb5a_settings.tokenizer_generic_algorithm = "tr29";
	tr29_wb5a_settings.tokenizer_generic_wb5a = TRUE;
}

/*there should be a trailing space ' ' at the end of each string except the last one*/
#define TEST_INPUT_ADDRESS \
	"@invalid invalid@ Abc Dfg <abc.dfg@example.com>, " \
	"Bar Baz <bar@example.org>" \
	"Foo Bar (comment)foo.bar@host.example.org " \
	"foo, foo@domain " \
	"abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyzabcdefghijklmnopqrstuvxyz@1bcdefghijklmnopqrstuvxy1.2bcdefghijklmnopqrstuvxy2.3bcdefghijklmnopqrstuvxy3.4bcdefghijklmnopqrstuvxy4.5bcdefghijklmnopqrstuvxy5.6bcdefghijklmnopqrstuvxy6.7bcdefghijklmnopqrstuvxy7.8bcdefghijklmnopqrstuvxy8.9bcdefghijklmnopqrstuvxy9.0bcdefghijklmnopqrstuvxy0.tld " \
	"trailing, period@blue.com. " \
	"multi-trialing, mul@trail.com..... " \
	"m@s " \
	"hypen@hypen-hypen.com " \
	"hypen@hypen-hypen-sick.com.-"

static const char *test_inputs[] = {
	/* generic things and word truncation: */
	"hello world\r\n\nAnd there\twas: text galor\xC3\xA9\xE2\x80\xA7 "
	"abc@example.com, "
	"Bar Baz <bar@example.org>, "
	"foo@domain "
	"1234567890123456789012345678\xC3\xA4,"
	"12345678901234567890123456789\xC3\xA4,"
	"123456789012345678901234567890\xC3\xA4,"
	"and longlonglongabcdefghijklmnopqrstuvwxyz more.\n\n "
	"(\"Hello world\")3.14 3,14 last",

	"1.",

	"' ' '' ''' 'quoted text' 'word' 'hlo words' you're bad'''word '''pre post'''",

	"'1234567890123456789012345678\xC3\xA4,"
	"123456789012345678901234567x'\xC3\xA4,"
	"1234567890123456789012345678x're,"
	"1234567890123456789012345678x',"
	"1234567890123456789012345678x'',"
	"12345678901234567890123456789x',"
	"12345678901234567890123456789x'',"
	"123456789012345678901234567890x',"
	"123456789012345678901234567890x'',"

	/* \xe28099 = U+2019 is a smart quote, sometimes used as an apostrophe */
#define SQ "\xE2\x80\x99"
	SQ " " SQ " " SQ SQ " " SQ SQ SQ " " SQ "quoted text" SQ SQ "word" SQ " " SQ "hlo words" SQ " you" SQ "re78901234567890123456789012 bad" SQ SQ SQ "word" SQ SQ SQ "pre post" SQ SQ SQ,

	"you" SQ "re" SQ "xyz",

	/* whitespace: with Unicode(utf8) U+FF01(ef bc 81)(U+2000(e2 80 80) and
	   U+205A(e2 81 9a) and U+205F(e2 81 9f) */
	"hello\xEF\xBC\x81world\r\nAnd\xE2\x80\x80there\twas: text "
	"galore\xE2\x81\x9F""and\xE2\x81\x9Amore.\n\n",

	/* TR29 MinNumLet U+FF0E at end: u+FF0E is EF BC 8E  */
	"hello world\xEF\xBC\x8E",

	/* TR29 WB5a */
	"l" SQ "homme l" SQ "humanit\xC3\xA9 d" SQ "immixtions qu" SQ "il aujourd'hui que'euq"
};

static void test_lang_tokenizer_find(void)
{
	test_begin("lang tokenizer find");
	test_assert(lang_tokenizer_find("email-address") == lang_tokenizer_email_address);
	test_assert(lang_tokenizer_find("generic") == lang_tokenizer_generic);
	test_end();
}

static unsigned int
test_tokenizer_inputoutput(struct lang_tokenizer *tok, const char *_input,
			   const char *const *expected_output,
			   unsigned int first_outi)
{
	const unsigned char *input = (const unsigned char *)_input;
	const char *token, *error;
	unsigned int i, outi, max, char_len;
	size_t input_len = strlen(_input);

	/* test all input at once */
	outi = first_outi;
	while (lang_tokenizer_next(tok, input, input_len, &token, &error) > 0) {
		test_assert_strcmp(token, expected_output[outi]);
		outi++;
	}
	while (lang_tokenizer_next(tok, NULL, 0, &token, &error) > 0) {
		test_assert_strcmp(token, expected_output[outi]);
		outi++;
	}
	test_assert_idx(expected_output[outi] == NULL, outi);

	/* test input one byte at a time */
	outi = first_outi;
	for (i = 0; i < input_len; i += char_len) {
		char_len = uni_utf8_char_bytes(input[i]);
		while (lang_tokenizer_next(tok, input+i, char_len, &token, &error) > 0) {
			test_assert_strcmp(token, expected_output[outi]);
			outi++;
		}
	}
	while (lang_tokenizer_final(tok, &token, &error) > 0) {
		test_assert_strcmp(token, expected_output[outi]);
		outi++;
	}
	test_assert_idx(expected_output[outi] == NULL, outi);

	/* test input in random chunks */
	outi = first_outi;
	for (i = 0; i < input_len; i += char_len) {
		max = i_rand_minmax(1, input_len - i);
		for (char_len = 0; char_len < max; )
			char_len += uni_utf8_char_bytes(input[i+char_len]);
		while (lang_tokenizer_next(tok, input+i, char_len, &token, &error) > 0) {
			test_assert_strcmp(token, expected_output[outi]);
			outi++;
		}
	}
	while (lang_tokenizer_final(tok, &token, &error) > 0) {
		test_assert_strcmp(token, expected_output[outi]);
		outi++;
	}
	test_assert_idx(expected_output[outi] == NULL, outi);

	return outi+1;
}

static void
test_tokenizer_inputs(struct lang_tokenizer *tok,
		      const char *const *inputs, unsigned int count,
		      const char *const *expected_output)
{
	unsigned int i, outi = 0;

	for (i = 0; i < count; i++) {
		outi = test_tokenizer_inputoutput(tok, inputs[i],
						  expected_output, outi);
	}
	test_assert_idx(expected_output[outi] == NULL, outi);
}

static void test_lang_tokenizer_generic_only(void)
{
	static const char *const expected_output[] = {
		"hello", "world", "And",
		"there", "was", "text", "galor\xC3\xA9",
		"abc", "example", "com", "Bar", "Baz",
		"bar", "example", "org", "foo", "domain",
		"1234567890123456789012345678\xC3\xA4",
		"12345678901234567890123456789",
		"123456789012345678901234567890",
		"and", "longlonglongabcdefghijklmnopqr",
		"more", "Hello", "world", "3", "14", "3", "14", "last", NULL,

		"1", NULL,

		"quoted", "text", "word", "hlo", "words", "you're", "bad",
		"word", "pre", "post", NULL,

		"1234567890123456789012345678\xC3\xA4",
		"123456789012345678901234567x'",
		"1234567890123456789012345678x'",
		"1234567890123456789012345678x",
		"1234567890123456789012345678x",
		"12345678901234567890123456789x",
		"12345678901234567890123456789x",
		"123456789012345678901234567890",
		"123456789012345678901234567890",

		"quoted", "text", "word", "hlo", "words", "you're789012345678901234567890", "bad",
		"word", "pre", "post", NULL,

		"you're'xyz", NULL,

		"hello", "world", "And",
		"there", "was", "text", "galore",
		"and", "more", NULL,

		"hello", "world", NULL,

		"l'homme", "l'humanit\xC3\xA9", "d'immixtions", "qu'il", "aujourd'hui", "que'euq", NULL,

		NULL
	};
	struct lang_tokenizer *tok;
	const char *error;

	test_begin("lang tokenizer generic simple");
	test_assert(lang_tokenizer_create(lang_tokenizer_generic, NULL, &lang_default_settings, event, 0, &tok, &error) == 0);
	test_assert(((struct generic_lang_tokenizer *) tok)->algorithm == BOUNDARY_ALGORITHM_SIMPLE);

	test_tokenizer_inputs(tok, test_inputs, N_ELEMENTS(test_inputs), expected_output);
	lang_tokenizer_unref(&tok);
	test_end();
}

/* TODO: U+206F is in "Format" and therefore currently not word break.
   This definitely needs to be remapped. */
static void test_lang_tokenizer_generic_tr29_only(void)
{
	static const char *const expected_output[] = {
		"hello", "world", "And",
		"there", "was", "text", "galor\xC3\xA9",
		"abc", "example", "com", "Bar", "Baz",
		"bar", "example", "org", "foo", "domain",
		"1234567890123456789012345678\xC3\xA4",
		"12345678901234567890123456789",
		"123456789012345678901234567890",
		"and", "longlonglongabcdefghijklmnopqr",
		"more", "Hello", "world", "3", "14", "3,14", "last", NULL,

		"1", NULL,

		"quoted", "text", "word", "hlo", "words", "you're", "bad",
		"word", "pre", "post", NULL,

		"1234567890123456789012345678\xC3\xA4",
		"123456789012345678901234567x'",
		"1234567890123456789012345678x'",
		"1234567890123456789012345678x",
		"1234567890123456789012345678x",
		"12345678901234567890123456789x",
		"12345678901234567890123456789x",
		"123456789012345678901234567890",
		"123456789012345678901234567890",

		"quoted", "text", "word", "hlo", "words", "you're789012345678901234567890", "bad",
		"word", "pre", "post", NULL,

		"you're'xyz", NULL,

		"hello", "world", "And",
		"there", "was", "text", "galore",
		"and", "more", NULL,

		"hello", "world", NULL,

		"l'homme", "l'humanit\xC3\xA9", "d'immixtions", "qu'il", "aujourd'hui", "que'euq", NULL,
		NULL
	};
	struct lang_tokenizer *tok;
	const char *error;

	test_begin("lang tokenizer generic TR29");
	test_assert(lang_tokenizer_create(lang_tokenizer_generic, NULL, &tr29_settings, event, 0, &tok, &error) == 0);
	test_tokenizer_inputs(tok, test_inputs, N_ELEMENTS(test_inputs), expected_output);
	lang_tokenizer_unref(&tok);
	test_end();
}

/* TODO: U+206F is in "Format" and therefore currently not word break.
   This definitely needs to be remapped. */
static void test_lang_tokenizer_generic_tr29_wb5a(void)
{
	static const char *const expected_output[] = {
		"hello", "world", "And",
		"there", "was", "text", "galor\xC3\xA9",
		"abc", "example", "com", "Bar", "Baz",
		"bar", "example", "org", "foo", "domain",
		"1234567890123456789012345678\xC3\xA4",
		"12345678901234567890123456789",
		"123456789012345678901234567890",
		"and", "longlonglongabcdefghijklmnopqr",
		"more", "Hello", "world", "3", "14", "3,14", "last", NULL,

		"1", NULL,

		"quoted", "text", "word", "hlo", "words", "you're", "bad",
		"word", "pre", "post", NULL,

		"1234567890123456789012345678\xC3\xA4",
		"123456789012345678901234567x'",
		"1234567890123456789012345678x'",
		"1234567890123456789012345678x",
		"1234567890123456789012345678x",
		"12345678901234567890123456789x",
		"12345678901234567890123456789x",
		"123456789012345678901234567890",
		"123456789012345678901234567890",

		"quoted", "text", "word", "hlo", "words", "you're789012345678901234567890", "bad",
		"word", "pre", "post", NULL,

		"you're'xyz", NULL,

		"hello", "world", "And",
		"there", "was", "text", "galore",
		"and", "more", NULL,

		"hello", "world", NULL,

		"l", "homme", "l", "humanit\xC3\xA9", "d", "immixtions", "qu", "il", "aujourd'hui", "que'euq", NULL,

		NULL
	};
	struct lang_tokenizer *tok;
	const char *error;

	test_begin("lang tokenizer generic TR29 with WB5a");
	test_assert(lang_tokenizer_create(lang_tokenizer_generic, NULL, &tr29_wb5a_settings, event, 0, &tok, &error) == 0);
	test_tokenizer_inputs(tok, test_inputs, N_ELEMENTS(test_inputs), expected_output);
	lang_tokenizer_unref(&tok);
	test_end();
}

static void test_lang_tokenizer_address_only(void)
{
	static const char input[] = TEST_INPUT_ADDRESS;
	static const char *const expected_output[] = {
		"abc.dfg@example.com", "bar@example.org",
		"foo.bar@host.example.org", "foo@domain",
		"period@blue.com", /*trailing period '.' in email */
		"mul@trail.com",
		"m@s", /*one letter local-part and domain name */
		"hypen@hypen-hypen.com",
		"hypen@hypen-hypen-sick.com",
		NULL
	};
	struct lang_tokenizer *tok;
	const char *error;

	test_begin("lang tokenizer email address only");
	test_assert(lang_tokenizer_create(lang_tokenizer_email_address, NULL, &lang_default_settings, event, 0, &tok, &error) == 0);
	test_tokenizer_inputoutput(tok, input, expected_output, 0);
	lang_tokenizer_unref(&tok);
	test_end();
}

static void test_lang_tokenizer_address_parent(const char *name, struct lang_settings *set, enum lang_tokenizer_flags flags)
{
	static const char input[] = TEST_INPUT_ADDRESS;
	static const char *const expected_output[] = {
		"invalid", "invalid", "Abc", "Dfg", "abc", "dfg", "example", "abc.dfg@example.com", "com",
		"Bar", "Baz", "bar", "example", "bar@example.org", "org",
		"Foo", "Bar", "comment", "foo", "bar", "host", "example", "foo.bar@host.example.org", "org",
		"foo", "foo", "foo@domain", "domain",
		"abcdefghijklmnopqrstuvxyz", "abcdefghijklmnopqrstuvxyzabcde",
		"1bcdefghijklmnopqrstuvxy1",
		"2bcdefghijklmnopqrstuvxy2",
		"3bcdefghijklmnopqrstuvxy3",
		"4bcdefghijklmnopqrstuvxy4",
		"5bcdefghijklmnopqrstuvxy5",
		"6bcdefghijklmnopqrstuvxy6",
		"7bcdefghijklmnopqrstuvxy7",
		"8bcdefghijklmnopqrstuvxy8",
		"9bcdefghijklmnopqrstuvxy9",
		"0bcdefghijklmnopqrstuvxy0", "tld",
		"trailing", "period", "blue", "com", "period@blue.com",
		"multi", "trialing", "mul", "trail", "com", "mul@trail.com",
		"m", "m@s", "s",
		"hypen", "hypen", "hypen", "hypen@hypen-hypen.com", "com",
		"hypen", "hypen", "hypen", "sick", "com", "hypen@hypen-hypen-sick.com",
		NULL
	};
	struct lang_tokenizer *tok, *gen_tok;
	const char *error;

	test_begin(t_strdup_printf("lang tokenizer email address + parent %s", name));
	test_assert(lang_tokenizer_create(lang_tokenizer_generic, NULL, set, event, flags, &gen_tok, &error) == 0);
	test_assert(lang_tokenizer_create(lang_tokenizer_email_address, gen_tok, &lang_default_settings, event, 0, &tok, &error) == 0);
	test_tokenizer_inputoutput(tok, input, expected_output, 0);
	lang_tokenizer_unref(&tok);
	lang_tokenizer_unref(&gen_tok);
	test_end();
}

static void test_lang_tokenizer_address_parent_simple(void)
{
	test_lang_tokenizer_address_parent("simple", &simple_settings, 0);
}

static void test_lang_tokenizer_address_parent_tr29(void)
{
	test_lang_tokenizer_address_parent("tr29", &tr29_settings, 0);
}

static void test_lang_tokenizer_address_search(void)
{
	static const char input[] = TEST_INPUT_ADDRESS;
	static const char *const expected_output[] = {
		"invalid", "invalid", "Abc", "Dfg", "abc.dfg@example.com",
		"Bar", "Baz", "bar@example.org",
		"Foo", "Bar", "comment", "foo.bar@host.example.org",
		"foo", "foo@domain",
		"abcdefghijklmnopqrstuvxyz", "abcdefghijklmnopqrstuvxyzabcde",
		"1bcdefghijklmnopqrstuvxy1",
		"2bcdefghijklmnopqrstuvxy2",
		"3bcdefghijklmnopqrstuvxy3",
		"4bcdefghijklmnopqrstuvxy4",
		"5bcdefghijklmnopqrstuvxy5",
		"6bcdefghijklmnopqrstuvxy6",
		"7bcdefghijklmnopqrstuvxy7",
		"8bcdefghijklmnopqrstuvxy8",
		"9bcdefghijklmnopqrstuvxy9",
		"0bcdefghijklmnopqrstuvxy0", "tld",
		"trailing", "period@blue.com",
		"multi", "trialing", "mul@trail.com",
		"m@s",
		"hypen@hypen-hypen.com",
		"hypen@hypen-hypen-sick.com",
		NULL
	};
	struct lang_tokenizer *tok, *gen_tok;
	const char *token, *error;

	test_begin("lang tokenizer search email address + parent");
	test_assert(lang_tokenizer_create(lang_tokenizer_generic, NULL, &lang_default_settings, event, 0, &gen_tok, &error) == 0);
	test_assert(lang_tokenizer_create(lang_tokenizer_email_address, gen_tok, &lang_default_settings, event, LANG_TOKENIZER_FLAG_SEARCH, &tok, &error) == 0);
	test_tokenizer_inputoutput(tok, input, expected_output, 0);

	/* make sure state is forgotten at EOF */
	test_assert(lang_tokenizer_next(tok, (const void *)"foo", 3, &token, &error) == 0);
	test_assert(lang_tokenizer_final(tok, &token, &error) > 0 &&
		    strcmp(token, "foo") == 0);
	test_assert(lang_tokenizer_final(tok, &token, &error) == 0);

	test_assert(lang_tokenizer_next(tok, (const void *)"bar@baz", 7, &token, &error) == 0);
	test_assert(lang_tokenizer_final(tok, &token, &error) > 0 &&
		    strcmp(token, "bar@baz") == 0);
	test_assert(lang_tokenizer_final(tok, &token, &error) == 0);

	test_assert(lang_tokenizer_next(tok, (const void *)"foo@", 4, &token, &error) == 0);
	test_assert(lang_tokenizer_final(tok, &token, &error) > 0 &&
		    strcmp(token, "foo") == 0);
	test_assert(lang_tokenizer_final(tok, &token, &error) == 0);

	/* test reset explicitly */
	test_assert(lang_tokenizer_next(tok, (const void *)"a", 1, &token, &error) == 0);
	lang_tokenizer_reset(tok);
	test_assert(lang_tokenizer_next(tok, (const void *)"b@c", 3, &token, &error) == 0);
	test_assert(lang_tokenizer_final(tok, &token, &error) > 0 &&
		    strcmp(token, "b@c") == 0);
	test_assert(lang_tokenizer_final(tok, &token, &error) == 0);

	lang_tokenizer_unref(&tok);
	lang_tokenizer_unref(&gen_tok);
	test_end();
}

static void test_lang_tokenizer_delete_trailing_partial_char(void)
{
	static const struct {
		const char *str;
		unsigned int truncated_len;
	} tests[] = {
		/* non-truncated */
		{ "\x7f", 1 },
		{ "\xC2\x80", 2 },
		{ "\xE0\x80\x80", 3 },
		{ "\xF0\x80\x80\x80", 4 },

		/* truncated */
		{ "\xF0\x80\x80", 0 },
		{ "x\xF0\x80\x80", 1 },
	};
	unsigned int i;
	size_t size;

	test_begin("lang tokenizer delete trailing partial char");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		size = strlen(tests[i].str);
		lang_tokenizer_delete_trailing_partial_char((const unsigned char *)tests[i].str, &size);
		test_assert(size == tests[i].truncated_len);
	}
	test_end();
}

static void test_lang_tokenizer_address_maxlen(void)
{
	struct lang_settings set = lang_default_settings;
	set.tokenizer_address_token_maxlen = 5;

	const char *input = "...\357\277\275@a";
	struct lang_tokenizer *tok;
	const char *token, *error;

	test_begin("lang tokenizer address maxlen");
	test_assert(lang_tokenizer_create(lang_tokenizer_email_address, NULL, &set, event, 0, &tok, &error) == 0);

	while (lang_tokenizer_next(tok, (const unsigned char *)input,
				  strlen(input), &token, &error) > 0) ;
	while (lang_tokenizer_final(tok, &token, &error) > 0) ;
	lang_tokenizer_unref(&tok);
	test_end();
}

static void test_lang_tokenizer_random(void)
{
	const unsigned char test_chars[] = { 0, ' ', '.', 'a', 'b', 'c', '-', '@', '\xC3', '\xA4' };

	struct lang_settings set = lang_default_settings;
	set.tokenizer_generic_algorithm = "simple";

	struct lang_settings email_set = lang_default_settings;
	email_set.tokenizer_address_token_maxlen = 9;

	unsigned int i;
	unsigned char addr[10] = { 0 };
	string_t *str = t_str_new(20);
	struct lang_tokenizer *tok, *gen_tok;
	const char *token, *error;

	test_begin("lang tokenizer random");
	test_assert(lang_tokenizer_create(lang_tokenizer_generic, NULL, &set, event, 0, &gen_tok, &error) == 0);
	test_assert(lang_tokenizer_create(lang_tokenizer_email_address, gen_tok, &email_set, event, 0, &tok, &error) == 0);

	for (i = 0; i < 10000; i++) T_BEGIN {
		for (unsigned int j = 0; j < sizeof(addr); j++)
			addr[j] = test_chars[i_rand_limit(N_ELEMENTS(test_chars))];
		str_truncate(str, 0);
		if (uni_utf8_get_valid_data(addr, sizeof(addr), str))
			str_append_data(str, addr, sizeof(addr));
		while (lang_tokenizer_next(tok, str_data(str), str_len(str),
					  &token, &error) > 0) ;
		while (lang_tokenizer_final(tok, &token, &error) > 0) ;
	} T_END;
	lang_tokenizer_unref(&tok);
	lang_tokenizer_unref(&gen_tok);
	test_end();
}

static void
test_lang_tokenizer_explicit_prefix(void)
{
	const char *input = "* ** "
		"*pre *both* post* "
		"mid*dle *mid*dle* "
		"**twopre **twoboth** twopost**";
	const char *const expected_star[] = { "pre", "both*", "post*",
					      "mid*", "dle", "mid*", "dle*",
					      "twopre", "twoboth*", "twopost*",
					      NULL, NULL };
	const char *const expected_nostar[] = { "pre", "both", "post",
						"mid", "dle", "mid", "dle",
						"twopre", "twoboth", "twopost",
						NULL, NULL };

	const struct algo {
		const char *name;
		bool wb5a;
	} algos[] = {
		{ ALGORITHM_SIMPLE_NAME, FALSE },
		{ ALGORITHM_TR29_NAME,   FALSE },
		{ ALGORITHM_TR29_NAME,   TRUE  },
	};

	struct lang_settings set = lang_default_settings;
	for (unsigned int algo_index = 0; algo_index < N_ELEMENTS(algos); algo_index++) {
		const struct algo *algo = &algos[algo_index];
		set.tokenizer_generic_wb5a = algo->wb5a;
		set.tokenizer_generic_algorithm = algo->name;
		const char *algo_str = t_strdup_printf("%s%s", algo->name, algo->wb5a ? "+wb5a" : "");

		for (int search = 0; search < 2; search++) {
			enum lang_tokenizer_flags flags = search > 0 ? LANG_TOKENIZER_FLAG_SEARCH : 0;
			const char *search_str = search > 0 ? "searching" : "indexing";

			for (int explicitprefix = 0; explicitprefix < 2; explicitprefix++) {
				set.tokenizer_generic_explicit_prefix = explicitprefix > 0;
				const char *prefix_str = explicitprefix > 0 ? "prefix" : "fixed";

				test_begin(t_strdup_printf("prefix search %s:%s:%s",
							   algo_str, search_str, prefix_str));
				struct lang_tokenizer *tok;
				const char *error;

				test_assert(lang_tokenizer_create(lang_tokenizer_generic, NULL,
								  &set, event, flags, &tok, &error) == 0);
				test_tokenizer_inputs(
					tok, &input, 1,
					(search!=0) && (explicitprefix!=0)
					? expected_star : expected_nostar);

				lang_tokenizer_unref(&tok);
				test_end();
			}
		}
	}
}

static void test_lang_tokenizer_skip_base64(void)
{
	/* The skip_base64 works on the data already available in the buffer
	   of the tokenizer, it does not pull more data to see if a base64
	   sequence long enough would match or not. This is why it does not
	   use test_tokenizer_inputoutput that also tests with one-byte-at-once
	   or random chunking, as those are known to fail with the current
	   implementation */
	struct lang_tokenizer *tok;
	const char *error;
	const char *token;

	static const char *input =
		",/dirtyleader/456789012345678901234567890123456789/\r\n"

		" /cleanleader/456789012345678901234567890123456789/\r\n"
		"\t/cleanleader/456789012345678901234567890123456789/\r\n"
		"\r/cleanleader/456789012345678901234567890123456789/\r\n"
		"\n/cleanleader/456789012345678901234567890123456789/\r\n"
		"=/cleanleader/456789012345678901234567890123456789/\r\n"
		";/cleanleader/456789012345678901234567890123456789/\r\n"
		":/cleanleader/456789012345678901234567890123456789/\r\n"
		";/cleanleader/456789012345678901234567890123456789/\r\n"

		"/23456789012345678901234567890123456/dirtytrailer/,\r\n"

		"/23456789012345678901234567890123456/cleantrailer/ \r\n"
		"/23456789012345678901234567890123456/cleantrailer/\t\r\n"
		"/23456789012345678901234567890123456/cleantrailer/\r\r\n"
		"/23456789012345678901234567890123456/cleantrailer/\n\r\n"
		"/23456789012345678901234567890123456/cleantrailer/=\r\n"
		"/23456789012345678901234567890123456/cleantrailer/;\r\n"
		"/23456789012345678901234567890123456/cleantrailer/:\r\n"
		"/23456789012345678901234567890123456/cleantrailer/?\r\n"

		"J1RrDrZSWxIAphKpYckeKNs10iTeiGMY0hNI32SMoSqCTgH96\r\n" // 49
		"MziUaLMK6FAOQws3OIuX0tgvQcyhu06ILAWWB1nGPy/bSEAEYg\r\n" // 50
		"ljWSJo8kxsm4/CiZBpwFfWkd64y+5ZytnKqgkQD87UbQ7FcpZgj\r\n" // 51
		"pTXUOBszCfdAgfZpWpPiOEQSthPxN9XMaS7HnOTyXtRBPVt96vw=\r\n" // 51=
		"MJmsWlDKXo7NCSt1wvazf9Xad18qOzpLJkVs/sxKsvLYyPD/zv=\r\n" // 50=
		"CBLsZ5dUybAEWcDkQwytSL348U/2lvadma7lF4wdNOc8sjUL8=\r\n" // 49=

		"4HWw7lJ15ZW3G1GtH9/NQbylcThN2IJo1kr83Fa2c9z2GFK1/NF+DpAkjbhDA3Al\r\n"

		"alpha bravo charlie delta echo foxtrot golf hotel india\r\n"
		"=juliet=kilo=lima=mike=november=oscar=papa=qebec=romeo=\r\n";

	static const char *const expected_output[] = {
		"dirtyleader", "456789012345678901234567890123",
		"234567890123456789012345678901", "dirtytrailer",
		"J1RrDrZSWxIAphKpYckeKNs10iTeiG", // 49
		"CBLsZ5dUybAEWcDkQwytSL348U", "2lvadma7lF4wdNOc8sjUL8", // 49=
		"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
		"juliet", "kilo", "lima", "mike", "november", "oscar", "papa", "qebec", "romeo",
		NULL
	};

	test_begin("lang tokenizer skip base64");
	test_assert(lang_tokenizer_create(lang_tokenizer_generic, NULL, &tr29_settings, event, 0, &tok, &error) == 0);

	size_t index = 0;
	while (lang_tokenizer_next(tok, (const unsigned char *) input, strlen(input), &token, &error) > 0) {
		i_assert(index < N_ELEMENTS(expected_output));
		test_assert_strcmp(token, expected_output[index]);
		++index;
	}
	while (lang_tokenizer_next(tok, NULL, 0, &token, &error) > 0) {
		i_assert(index < N_ELEMENTS(expected_output));
		test_assert_strcmp(token, expected_output[index]);
		++index;
	}
	i_assert(index < N_ELEMENTS(expected_output));
	test_assert_idx(expected_output[index] == NULL, index);

	lang_tokenizer_unref(&tok);
	test_end();
}

int main(void)
{
	init_lang_settings();
	static void (*const test_functions[])(void) = {
		test_lang_tokenizer_skip_base64,
		test_lang_tokenizer_find,
		test_lang_tokenizer_generic_only,
		test_lang_tokenizer_generic_tr29_only,
		test_lang_tokenizer_generic_tr29_wb5a,
		test_lang_tokenizer_address_only,
		test_lang_tokenizer_address_parent_simple,
		test_lang_tokenizer_address_parent_tr29,
		test_lang_tokenizer_address_maxlen,
		test_lang_tokenizer_address_search,
		test_lang_tokenizer_delete_trailing_partial_char,
		test_lang_tokenizer_random,
		test_lang_tokenizer_explicit_prefix,
		NULL
	};
	int ret;

	lang_tokenizers_init();
	ret = test_run(test_functions);
	lang_tokenizers_deinit();

	return ret;
}
