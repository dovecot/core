/* Copyright (c) 2014-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "unichar.h"
#include "test-common.h"
#include "fts-tokenizer.h"
#include "fts-tokenizer-private.h"
#include "fts-tokenizer-generic-private.h"

#include <stdlib.h>

#define TEST_INPUT_TEXT \
	"hello world\r\n\nAnd there\twas: text galore, " \
	"abc@example.com, " \
	"Bar Baz <bar@example.org>, " \
	"foo@domain " \
	"1234567890123456789012345678ä," \
	"12345678901234567890123456789ä," \
	"123456789012345678901234567890ä," \
	"and longlonglongabcdefghijklmnopqrstuvwxyz more.\n\n " \
	"(\"Hello world\")3.14 3,14 last"
#define TEST_INPUT_ADDRESS \
	"@invalid invalid@ Abc Dfg <abc.dfg@example.com>, " \
	"Bar Baz <bar@example.org>" \
	"Foo Bar (comment)foo.bar@host.example.org " \
	"foo, foo@domain"

static void test_fts_tokenizer_find(void)
{
	test_begin("fts tokenizer find");
	test_assert(fts_tokenizer_find("email-address") == fts_tokenizer_email_address);
	test_assert(fts_tokenizer_find("generic") == fts_tokenizer_generic);
	test_end();
}

static void
test_tokenizer_inputoutput(struct fts_tokenizer *tok, const char *_input,
			   const char *const *expected_output)
{
	const unsigned char *input = (const unsigned char *)_input;
	const char *token, *error;
	unsigned int i, max, outi, char_len, input_len = strlen(_input);

	/* test all input at once */
	outi = 0;
	while (fts_tokenizer_next(tok, input, input_len, &token, &error) > 0) {
		test_assert_idx(strcmp(token, expected_output[outi]) == 0, outi);
		outi++;
	}
	while (fts_tokenizer_next(tok, NULL, 0, &token, &error) > 0) {
		test_assert_idx(strcmp(token, expected_output[outi]) == 0, outi);
		outi++;
	}
	test_assert(expected_output[outi] == NULL);

	/* test input one byte at a time */
	for (i = outi = 0; i < input_len; i += char_len) {
		char_len = uni_utf8_char_bytes(input[i]);
		while (fts_tokenizer_next(tok, input+i, char_len, &token, &error) > 0) {
			test_assert_idx(strcmp(token, expected_output[outi]) == 0, outi);
			outi++;
		}
	}
	while (fts_tokenizer_final(tok, &token, &error) > 0) {
		test_assert_idx(strcmp(token, expected_output[outi]) == 0, outi);
		outi++;
	}
	test_assert(expected_output[outi] == NULL);

	/* test input in random chunks */
	for (i = outi = 0; i < input_len; i += char_len) {
		max = rand() % (input_len - i) + 1;
		for (char_len = 0; char_len < max; )
			char_len += uni_utf8_char_bytes(input[i+char_len]);
		while (fts_tokenizer_next(tok, input+i, char_len, &token, &error) > 0) {
			test_assert_idx(strcmp(token, expected_output[outi]) == 0, outi);
			outi++;
		}
	}
	while (fts_tokenizer_final(tok, &token, &error) > 0) {
		test_assert_idx(strcmp(token, expected_output[outi]) == 0, outi);
		outi++;
	}
	test_assert(expected_output[outi] == NULL);
}

static void test_fts_tokenizer_generic_only(void)
{
	static const char input[] = TEST_INPUT_TEXT;
	static const char *const expected_output[] = {
		"hello", "world", "And",
		"there", "was", "text", "galore",
		"abc", "example", "com", "Bar", "Baz",
		"bar", "example", "org", "foo", "domain",
		"1234567890123456789012345678ä",
		"12345678901234567890123456789",
		"123456789012345678901234567890",
		"and", "longlonglongabcdefghijklmnopqr",
		"more", "Hello", "world", "3", "14", "3", "14", "last", NULL
	};
	struct fts_tokenizer *tok;
	const char *error;

	test_begin("fts tokenizer generic simple");
	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, NULL, &tok, &error) == 0);
	test_assert(((struct generic_fts_tokenizer *) tok)->algorithm == BOUNDARY_ALGORITHM_SIMPLE);

	test_tokenizer_inputoutput(tok, input, expected_output);
	fts_tokenizer_unref(&tok);
	test_end();
}

static void test_fts_tokenizer_generic_unicode_whitespace(void)
{
	/* with Unicode(utf8) U+FF01(ef bc 81)(U+2000(e2 80 80) and
	   U+205A(e2 81 9a) and U+205F(e2 81 9f )*/
	static const char input[] =
		"hello\xEF\xBC\x81world\r\nAnd\xE2\x80\x80there\twas: text "
		"galore\xE2\x81\x9F""and\xE2\x81\x9Amore.\n\n";
	static const char *const expected_output[] = {
		"hello", "world", "And",
		"there", "was", "text", "galore",
		"and", "more", NULL
	};
	struct fts_tokenizer *tok;
	const char *error;

	test_begin("fts tokenizer generic simple with Unicode whitespace");
	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, NULL, &tok, &error) == 0);
	test_tokenizer_inputoutput(tok, input, expected_output);
	fts_tokenizer_unref(&tok);
	test_end();
}

const char *const tr29_settings[] = {"algorithm", "tr29", NULL};

static void test_fts_tokenizer_generic_tr29_only(void)
{
	static const char input[] = TEST_INPUT_TEXT;
	static const char *const expected_output[] = {
		"hello", "world", "And",
		"there", "was", "text", "galore",
		"abc", "example.com", "Bar", "Baz",
		"bar", "example.org", "foo", "domain",
		"1234567890123456789012345678ä",
		"12345678901234567890123456789",
		"123456789012345678901234567890",
		"and", "longlonglongabcdefghijklmnopqr",
		"more", "Hello", "world", "3.14", "3,14", "last", NULL
	};
	struct fts_tokenizer *tok;
	const char *error;

	test_begin("fts tokenizer generic TR29");
	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, tr29_settings, &tok, &error) == 0);
	test_tokenizer_inputoutput(tok, input, expected_output);
	fts_tokenizer_unref(&tok);
	test_end();
}

/* TODO: U+206F is in "Format" and therefore currently not word break.
   This definitely needs to be remapped. */
static void test_fts_tokenizer_generic_tr29_unicode_whitespace(void)
{
	/* with Unicode(utf8) U+2000(e2 80 80) and U+205A(e2 81 9a) and U+205F(e2
	   81 9f)*/
	static const char input[] =
		"hello world\r\nAnd\xE2\x80\x80there\twas: text "
		"galore\xE2\x81\x9F""and\xE2\x81\x9Amore.\n\n";
	static const char *const expected_output[] = {
		"hello", "world", "And",
		"there", "was", "text", "galore",
		"and", "more", NULL
	};
	struct fts_tokenizer *tok;
	const char *error;

	test_begin("fts tokenizer generic TR29 with Unicode whitespace");
	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, tr29_settings, &tok, &error) == 0);
	test_tokenizer_inputoutput(tok, input, expected_output);
	fts_tokenizer_unref(&tok);
	test_end();
}

static void test_fts_tokenizer_generic_tr29_midnumlet_end(void)
{
	/* u+FF0E is EF BC 8E  */
	static const char input[] =
		"hello world\xEF\xBC\x8E";
	static const char *const expected_output[] = {
		"hello", "world", NULL
	};
	struct fts_tokenizer *tok;
	const char *error;

	test_begin("fts tokenizer generic TR29 with MinNumLet U+FF0E at end");
	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, tr29_settings, &tok, &error) == 0);
	test_tokenizer_inputoutput(tok, input, expected_output);
	fts_tokenizer_unref(&tok);
	test_end();
}

static void test_fts_tokenizer_address_only(void)
{
	static const char input[] = TEST_INPUT_ADDRESS;
	static const char *const expected_output[] = {
		"abc.dfg@example.com", "bar@example.org",
		"foo.bar@host.example.org", "foo@domain", NULL
	};
	struct fts_tokenizer *tok;
	const char *error;

	test_begin("fts tokenizer email address only");
	test_assert(fts_tokenizer_create(fts_tokenizer_email_address, NULL, NULL, &tok, &error) == 0);
	test_tokenizer_inputoutput(tok, input, expected_output);
	fts_tokenizer_unref(&tok);
	test_end();
}

static void test_fts_tokenizer_address_parent(void)
{
	static const char input[] = TEST_INPUT_ADDRESS;
	static const char *const expected_output[] = {
		"invalid", "invalid", "Abc", "Dfg", "abc", "dfg", "example", "com", "abc.dfg@example.com",
		"Bar", "Baz", "bar", "example", "org", "bar@example.org",
		"Foo", "Bar", "comment", "foo", "bar", "host", "example", "org", "foo.bar@host.example.org",
		"foo", "foo", "domain", "foo@domain", NULL
	};
	struct fts_tokenizer *tok, *gen_tok;
	const char *error;

	test_begin("fts tokenizer email address + parent");
	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, NULL, &gen_tok, &error) == 0);
	test_assert(fts_tokenizer_create(fts_tokenizer_email_address, gen_tok, NULL, &tok, &error) == 0);
	test_tokenizer_inputoutput(tok, input, expected_output);
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unref(&gen_tok);
	test_end();
}

static void test_fts_tokenizer_address_search(void)
{
	static const char input[] = TEST_INPUT_ADDRESS;
	static const char *const expected_output[] = {
		"invalid", "invalid", "Abc", "Dfg", "abc.dfg@example.com",
		"Bar", "Baz", "bar@example.org",
		"Foo", "Bar", "comment", "foo.bar@host.example.org",
		"foo", "foo@domain", NULL
	};
	static const char *const settings[] = { "search", "", NULL };
	struct fts_tokenizer *tok, *gen_tok;
	const char *token, *error;

	test_begin("fts tokenizer search email address + parent");
	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, NULL, &gen_tok, &error) == 0);
	test_assert(fts_tokenizer_create(fts_tokenizer_email_address, gen_tok, settings, &tok, &error) == 0);
	test_tokenizer_inputoutput(tok, input, expected_output);

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

int main(void)
{
	static void (*test_functions[])(void) = {
		test_fts_tokenizer_find,
		test_fts_tokenizer_generic_only,
		test_fts_tokenizer_generic_unicode_whitespace,
		test_fts_tokenizer_generic_tr29_only,
		test_fts_tokenizer_generic_tr29_unicode_whitespace,
		test_fts_tokenizer_generic_tr29_midnumlet_end,
		test_fts_tokenizer_address_only,
		test_fts_tokenizer_address_parent,
		test_fts_tokenizer_address_search,
		NULL
	};
	int ret;

	fts_tokenizers_init();
	ret = test_run(test_functions);
	fts_tokenizers_deinit();
	return ret;
}
