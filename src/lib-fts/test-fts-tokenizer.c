/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "unichar.h"
#include "str.h"
#include "test-common.h"
#include "fts-tokenizer.h"
#include "fts-tokenizer-common.h"
#include "fts-tokenizer-private.h"
#include "fts-tokenizer-generic-private.h"

/*there should be a trailing space ' ' at the end of each string except the last one*/
#define TEST_INPUT_ADDRESS \
	"@invalid invalid@ Abc Dfg <abc.dfg@example.com>, " \
	"Bar Baz <bar@example.org>" \
	"Foo Bar (comment)foo.bar@host.example.org " \
	"foo, foo@domain " \
	"abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyzabcdefghijklmnopqrstuvxyz@abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.tld " \
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
	"\xE2\x80\x99 \xE2\x80\x99 \xE2\x80\x99\xE2\x80\x99 \xE2\x80\x99\xE2\x80\x99\xE2\x80\x99 \xE2\x80\x99quoted text\xE2\x80\x99\xE2\x80\x99word\xE2\x80\x99 \xE2\x80\x99hlo words\xE2\x80\x99 you\xE2\x80\x99re78901234567890123456789012 bad\xE2\x80\x99\xE2\x80\x99\xE2\x80\x99word\xE2\x80\x99\xE2\x80\x99\xE2\x80\x99pre post\xE2\x80\x99\xE2\x80\x99\xE2\x80\x99",

	"you\xE2\x80\x99re\xE2\x80\x99xyz",

	/* whitespace: with Unicode(utf8) U+FF01(ef bc 81)(U+2000(e2 80 80) and
	   U+205A(e2 81 9a) and U+205F(e2 81 9f) */
	"hello\xEF\xBC\x81world\r\nAnd\xE2\x80\x80there\twas: text "
	"galore\xE2\x81\x9F""and\xE2\x81\x9Amore.\n\n",

	/* TR29 MinNumLet U+FF0E at end: u+FF0E is EF BC 8E  */
	"hello world\xEF\xBC\x8E",

	/* TR29 WB5a */
	"l\xE2\x80\x99homme l\xE2\x80\x99humanit\xC3\xA9 d\xE2\x80\x99immixtions qu\xE2\x80\x99il aujourd'hui que'euq"
};

static void test_fts_tokenizer_find(void)
{
	test_begin("fts tokenizer find");
	test_assert(fts_tokenizer_find("email-address") == fts_tokenizer_email_address);
	test_assert(fts_tokenizer_find("generic") == fts_tokenizer_generic);
	test_end();
}

static unsigned int
test_tokenizer_inputoutput(struct fts_tokenizer *tok, const char *_input,
			   const char *const *expected_output,
			   unsigned int first_outi)
{
	const unsigned char *input = (const unsigned char *)_input;
	const char *token, *error;
	unsigned int i, outi, max, char_len;
	size_t input_len = strlen(_input);

	/* test all input at once */
	outi = first_outi;
	while (fts_tokenizer_next(tok, input, input_len, &token, &error) > 0) {
		test_assert_strcmp(token, expected_output[outi]);
		outi++;
	}
	while (fts_tokenizer_next(tok, NULL, 0, &token, &error) > 0) {
		test_assert_strcmp(token, expected_output[outi]);
		outi++;
	}
	test_assert_idx(expected_output[outi] == NULL, outi);

	/* test input one byte at a time */
	outi = first_outi;
	for (i = 0; i < input_len; i += char_len) {
		char_len = uni_utf8_char_bytes(input[i]);
		while (fts_tokenizer_next(tok, input+i, char_len, &token, &error) > 0) {
			test_assert_strcmp(token, expected_output[outi]);
			outi++;
		}
	}
	while (fts_tokenizer_final(tok, &token, &error) > 0) {
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
		while (fts_tokenizer_next(tok, input+i, char_len, &token, &error) > 0) {
			test_assert_strcmp(token, expected_output[outi]);
			outi++;
		}
	}
	while (fts_tokenizer_final(tok, &token, &error) > 0) {
		test_assert_strcmp(token, expected_output[outi]);
		outi++;
	}
	test_assert_idx(expected_output[outi] == NULL, outi);

	return outi+1;
}

static void
test_tokenizer_inputs(struct fts_tokenizer *tok,
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

static void test_fts_tokenizer_generic_only(void)
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
	struct fts_tokenizer *tok;
	const char *error;

	test_begin("fts tokenizer generic simple");
	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, NULL, &tok, &error) == 0);
	test_assert(((struct generic_fts_tokenizer *) tok)->algorithm == BOUNDARY_ALGORITHM_SIMPLE);

	test_tokenizer_inputs(tok, test_inputs, N_ELEMENTS(test_inputs), expected_output);
	fts_tokenizer_unref(&tok);
	test_end();
}

const char *const tr29_settings[] = {"algorithm", "tr29", NULL};

/* TODO: U+206F is in "Format" and therefore currently not word break.
   This definitely needs to be remapped. */
static void test_fts_tokenizer_generic_tr29_only(void)
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
	struct fts_tokenizer *tok;
	const char *error;

	test_begin("fts tokenizer generic TR29");
	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, tr29_settings, &tok, &error) == 0);
	test_tokenizer_inputs(tok, test_inputs, N_ELEMENTS(test_inputs), expected_output);
	fts_tokenizer_unref(&tok);
	test_end();
}

const char *const tr29_settings_wb5a[] = {"algorithm", "tr29", "wb5a", "yes", NULL};

/* TODO: U+206F is in "Format" and therefore currently not word break.
   This definitely needs to be remapped. */
static void test_fts_tokenizer_generic_tr29_wb5a(void)
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
	struct fts_tokenizer *tok;
	const char *error;

	test_begin("fts tokenizer generic TR29 with WB5a");
	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, tr29_settings_wb5a, &tok, &error) == 0);
	test_tokenizer_inputs(tok, test_inputs, N_ELEMENTS(test_inputs), expected_output);
	fts_tokenizer_unref(&tok);
	test_end();
}

static void test_fts_tokenizer_address_only(void)
{
	static const char input[] = TEST_INPUT_ADDRESS;
	static const char *const expected_output[] = {
		"abc.dfg@example.com", "bar@example.org",
		"foo.bar@host.example.org", "foo@domain",
		"abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyzabcdefghijklmnopqrstuvxyz@abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstu",
		"period@blue.com", /*trailing period '.' in email */
		"mul@trail.com",
		"m@s", /*one letter local-part and domain name */
		"hypen@hypen-hypen.com",
		"hypen@hypen-hypen-sick.com",
		NULL
	};
	struct fts_tokenizer *tok;
	const char *error;

	test_begin("fts tokenizer email address only");
	test_assert(fts_tokenizer_create(fts_tokenizer_email_address, NULL, NULL, &tok, &error) == 0);
	test_tokenizer_inputoutput(tok, input, expected_output, 0);
	fts_tokenizer_unref(&tok);
	test_end();
}

static void test_fts_tokenizer_address_parent(const char *name, const char * const *settings)
{
	static const char input[] = TEST_INPUT_ADDRESS;
	static const char *const expected_output[] = {
		"invalid", "invalid", "Abc", "Dfg", "abc", "dfg", "example", "com", "abc.dfg@example.com",
		"Bar", "Baz", "bar", "example", "org", "bar@example.org",
		"Foo", "Bar", "comment", "foo", "bar", "host", "example", "org", "foo.bar@host.example.org",
		"foo", "foo", "domain", "foo@domain", "abcdefghijklmnopqrstuvxyz", "abcdefghijklmnopqrstuvxyzabcde",  "abcdefghijklmnopqrstuvxyz", "abcdefghijklmnopqrstuvxyz", "abcdefghijklmnopqrstuvxyz", "abcdefghijklmnopqrstuvxyz", "abcdefghijklmnopqrstuvxyz", "abcdefghijklmnopqrstuvxyz", "abcdefghijklmnopqrstuvxyz", "abcdefghijklmnopqrstuvxyz", "abcdefghijklmnopqrstuvxyz", "abcdefghijklmnopqrstuvxyz","tld", "abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyzabcdefghijklmnopqrstuvxyz@abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstu",
		"trailing", "period", "blue", "com", "period@blue.com",
		"multi", "trialing", "mul", "trail", "com", "mul@trail.com",
		"m", "s", "m@s",
		"hypen", "hypen", "hypen", "com", "hypen@hypen-hypen.com",
		"hypen", "hypen", "hypen", "sick", "com", "hypen@hypen-hypen-sick.com",
		NULL
	};
	struct fts_tokenizer *tok, *gen_tok;
	const char *error;

	test_begin(t_strdup_printf("fts tokenizer email address + parent %s", name));
	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, settings, &gen_tok, &error) == 0);
	test_assert(fts_tokenizer_create(fts_tokenizer_email_address, gen_tok, NULL, &tok, &error) == 0);
	test_tokenizer_inputoutput(tok, input, expected_output, 0);
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unref(&gen_tok);
	test_end();
}

const char *const simple_settings[] = {"algorithm", "simple", NULL};
static void test_fts_tokenizer_address_parent_simple(void)
{
	test_fts_tokenizer_address_parent("simple", simple_settings);
}

static void test_fts_tokenizer_address_parent_tr29(void)
{
	test_fts_tokenizer_address_parent("tr29", tr29_settings);
}

static void test_fts_tokenizer_address_search(void)
{
	static const char input[] = TEST_INPUT_ADDRESS;
	static const char *const expected_output[] = {
		"invalid", "invalid", "Abc", "Dfg", "abc.dfg@example.com",
		"Bar", "Baz", "bar@example.org",
		"Foo", "Bar", "comment", "foo.bar@host.example.org",
		"foo", "foo@domain", "abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyzabcdefghijklmnopqrstuvxyz@abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstuvxyz.abcdefghijklmnopqrstu",
		"trailing", "period@blue.com",
		"multi", "trialing", "mul@trail.com",
		"m@s",
		"hypen@hypen-hypen.com",
		"hypen@hypen-hypen-sick.com",
		NULL
	};
	static const char *const settings[] = { "search", "", NULL };
	struct fts_tokenizer *tok, *gen_tok;
	const char *token, *error;

	test_begin("fts tokenizer search email address + parent");
	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, NULL, &gen_tok, &error) == 0);
	test_assert(fts_tokenizer_create(fts_tokenizer_email_address, gen_tok, settings, &tok, &error) == 0);
	test_tokenizer_inputoutput(tok, input, expected_output, 0);

	/* make sure state is forgotten at EOF */
	test_assert(fts_tokenizer_next(tok, (const void *)"foo", 3, &token, &error) == 0);
	test_assert(fts_tokenizer_final(tok, &token, &error) > 0 &&
		    strcmp(token, "foo") == 0);
	test_assert(fts_tokenizer_final(tok, &token, &error) == 0);

	test_assert(fts_tokenizer_next(tok, (const void *)"bar@baz", 7, &token, &error) == 0);
	test_assert(fts_tokenizer_final(tok, &token, &error) > 0 &&
		    strcmp(token, "bar@baz") == 0);
	test_assert(fts_tokenizer_final(tok, &token, &error) == 0);

	test_assert(fts_tokenizer_next(tok, (const void *)"foo@", 4, &token, &error) == 0);
	test_assert(fts_tokenizer_final(tok, &token, &error) > 0 &&
		    strcmp(token, "foo") == 0);
	test_assert(fts_tokenizer_final(tok, &token, &error) == 0);

	/* test reset explicitly */
	test_assert(fts_tokenizer_next(tok, (const void *)"a", 1, &token, &error) == 0);
	fts_tokenizer_reset(tok);
	test_assert(fts_tokenizer_next(tok, (const void *)"b@c", 3, &token, &error) == 0);
	test_assert(fts_tokenizer_final(tok, &token, &error) > 0 &&
		    strcmp(token, "b@c") == 0);
	test_assert(fts_tokenizer_final(tok, &token, &error) == 0);

	fts_tokenizer_unref(&tok);
	fts_tokenizer_unref(&gen_tok);
	test_end();
}

static void test_fts_tokenizer_delete_trailing_partial_char(void)
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

	test_begin("fts tokenizer delete trailing partial char");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		size = strlen(tests[i].str);
		fts_tokenizer_delete_trailing_partial_char((const unsigned char *)tests[i].str, &size);
		test_assert(size == tests[i].truncated_len);
	}
	test_end();
}

static void test_fts_tokenizer_address_maxlen(void)
{
	const char *const settings[] = {"maxlen", "5", NULL};
	const char *input = "...\357\277\275@a";
	struct fts_tokenizer *tok;
	const char *token, *error;

	test_begin("fts tokenizer address maxlen");
	test_assert(fts_tokenizer_create(fts_tokenizer_email_address, NULL, settings, &tok, &error) == 0);

	while (fts_tokenizer_next(tok, (const unsigned char *)input,
				  strlen(input), &token, &error) > 0) ;
	while (fts_tokenizer_final(tok, &token, &error) > 0) ;
	fts_tokenizer_unref(&tok);
	test_end();
}

static void test_fts_tokenizer_random(void)
{
	const char test_chars[] = { 0, ' ', '.', 'a', 'b', 'c', '-', '@', '\xC3', '\xA4' };
	const char *const settings[] = {"algorithm", "simple", NULL};
	const char *const email_settings[] = {"maxlen", "9", NULL};
	unsigned int i;
	unsigned char addr[10] = { 0 };
	string_t *str = t_str_new(20);
	struct fts_tokenizer *tok, *gen_tok;
	const char *token, *error;

	test_begin("fts tokenizer random");
	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, settings, &gen_tok, &error) == 0);
	test_assert(fts_tokenizer_create(fts_tokenizer_email_address, gen_tok, email_settings, &tok, &error) == 0);

	for (i = 0; i < 10000; i++) T_BEGIN {
		for (unsigned int j = 0; j < sizeof(addr); j++)
			addr[j] = test_chars[i_rand() % N_ELEMENTS(test_chars)];
		str_truncate(str, 0);
		if (uni_utf8_get_valid_data(addr, sizeof(addr), str))
			str_append_data(str, addr, sizeof(addr));
		while (fts_tokenizer_next(tok, str_data(str), str_len(str),
					  &token, &error) > 0) ;
		while (fts_tokenizer_final(tok, &token, &error) > 0) ;
	} T_END;
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unref(&gen_tok);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_fts_tokenizer_find,
		test_fts_tokenizer_generic_only,
		test_fts_tokenizer_generic_tr29_only,
		test_fts_tokenizer_generic_tr29_wb5a,
		test_fts_tokenizer_address_only,
		test_fts_tokenizer_address_parent_simple,
		test_fts_tokenizer_address_parent_tr29,
		test_fts_tokenizer_address_maxlen,
		test_fts_tokenizer_address_search,
		test_fts_tokenizer_delete_trailing_partial_char,
		test_fts_tokenizer_random,
		NULL
	};
	int ret;

	fts_tokenizers_init();
	ret = test_run(test_functions);
	fts_tokenizers_deinit();

	return ret;
}
