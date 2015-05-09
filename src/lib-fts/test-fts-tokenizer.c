/* Copyright (c) 2014-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "sha2.h"
#include "hex-binary.h"
#include "test-common.h"
#include "fts-tokenizer.h"
#include "fts-tokenizer-private.h"
/* TODO: fix including and linking of this. */
/* #include "fts-tokenizer-generic-private.h" */

#include <stdlib.h>

static void test_fts_tokenizer_generic_only(void)
{
	static const unsigned char input[] =
		"hello world\r\nAnd there\twas: text "
		"galore, and longlonglongabcdefghijklmnopqrstuvwxyz more.\n\n (\"Hello world\")last ";
	static const char *const expected_output[] = {
		"hello", "world", "And",
		"there", "was", "text", "galore",
		"and", "longlonglongabcdefghijklmnopqr",
		"more", "Hello", "world", "last", NULL
	};
	const struct fts_tokenizer *tok_class;
	struct fts_tokenizer *tok;
	const char * const *eopp = expected_output;
	const char *token, *error;

	test_begin("fts tokenizer generic simple");
	fts_tokenizers_init();
	tok_class = fts_tokenizer_find(FTS_TOKENIZER_GENERIC_NAME);
	test_assert(fts_tokenizer_create(tok_class, NULL, NULL, &tok, &error) == 0);
/*TODO: Uncomment when fts-tokenizer-generic-private.h inclusion is fixed */
/*test_assert(((struct generic_fts_tokenizer *) tok)->algorithm ==  BOUNDARY_ALGORITHM_SIMPLE);*/
	while (fts_tokenizer_next(tok, input, sizeof(input)-1, &token) > 0) {
		test_assert(strcmp(token, *eopp) == 0);
		eopp++;
	}
	while (fts_tokenizer_next(tok, NULL, 0, &token) > 0) {
		test_assert(strcmp(token, *eopp) == 0);
		eopp++;
	}
	test_assert(*eopp == NULL);
	fts_tokenizer_unref(&tok);
	fts_tokenizers_deinit();
	test_end();
}

static void test_fts_tokenizer_generic_unicode_whitespace(void)
{
	/* with Unicode(utf8) U+FF01(ef bc 81)(U+2000(e2 80 80) and
	   U+205A(e2 81 9a) and U+205F(e2 81 9f )*/
	static const unsigned char input[] =
		"hello\xEF\xBC\x81world\r\nAnd\xE2\x80\x80there\twas: text "
		"galore\xE2\x81\x9F""and\xE2\x81\x9Amore.\n\n";
	static const char *const expected_output[] = {
		"hello", "world", "And",
		"there", "was", "text", "galore",
		"and", "more", NULL
	};
	const struct fts_tokenizer *tok_class;
	struct fts_tokenizer *tok;
	const char * const *eopp = expected_output;
	const char *token, *error;

	test_begin("fts tokenizer generic simple with Unicode whitespace");
	fts_tokenizer_register(fts_tokenizer_generic);
	tok_class = fts_tokenizer_find(FTS_TOKENIZER_GENERIC_NAME);
	test_assert(fts_tokenizer_create(tok_class, NULL, NULL, &tok, &error) == 0);
	while (fts_tokenizer_next(tok, input, sizeof(input)-1, &token) > 0) {
		test_assert(strcmp(token, *eopp) == 0);
		eopp++;
	}
	while (fts_tokenizer_next(tok, NULL, 0, &token) > 0) {
		test_assert(strcmp(token, *eopp) == 0);
		eopp++;
	}
	test_assert(*eopp == NULL);
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unregister(fts_tokenizer_generic);
	test_end();
}

static void test_fts_tokenizer_char_generic_only(void)
{
	static const unsigned char input[] =
		"abc@example.com, "
		"Bar Baz <bar@example.org>, "
		"foo@domain";
	static const char *const expected_output[] = {
		"abc", "example", "com", "Bar", "Baz",
		"bar", "example", "org", "foo", "domain", NULL
	};
	struct fts_tokenizer *tok;
	const char * const *eopp = expected_output;
	const char *token, *error;
	unsigned int i;
	int ret;

	test_begin("fts tokenizer generic simple input one character at a time");
	fts_tokenizer_register(fts_tokenizer_generic);

	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, NULL, &tok, &error) == 0);

	for (i = 0; i <= sizeof(input)-1; ) {
		ret = i < sizeof(input)-1 ?
			fts_tokenizer_next(tok, &input[i], 1, &token) :
			fts_tokenizer_next(tok, NULL, 0, &token);
		if (ret == 0) {
			i++;
			continue;
		}
		test_assert(null_strcmp(token, *eopp) == 0);
		eopp++;
	}
	test_assert(*eopp == NULL);
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unregister(fts_tokenizer_generic);
	test_end();
}

const char *const tr29_settings[] = {"algorithm", "tr29", NULL};

static void test_fts_tokenizer_generic_tr29_only(void)
{
	static const unsigned char input[] =
		"hello world\r\n\nAnd there\twas: text "
		"galore, and more.\n\n (\"Hello world\")3.14 3,14 last"
		" longlonglongabcdefghijklmnopqrstuvwxyz 1.";
	static const char *const expected_output[] = {
		"hello", "world", "And",
		"there", "was", "text", "galore",
		"and", "more", "Hello", "world", "3.14",
		"3,14", "last", "longlonglongabcdefghijklmnopqr", "1", NULL
	};
	const struct fts_tokenizer *tok_class;
	struct fts_tokenizer *tok;
	const char * const *eopp = expected_output;
	const char *token, *error;

	test_begin("fts tokenizer generic TR29");
	fts_tokenizer_register(fts_tokenizer_generic);
	tok_class = fts_tokenizer_find(FTS_TOKENIZER_GENERIC_NAME);
	test_assert(fts_tokenizer_create(tok_class, NULL, tr29_settings, &tok, &error) == 0);
	while (fts_tokenizer_next(tok, input, sizeof(input)-1, &token) > 0) {
		test_assert(strcmp(token, *eopp) == 0);
		eopp++;
	}
	while (fts_tokenizer_next(tok, NULL, 0, &token) > 0) {
		test_assert(strcmp(token, *eopp) == 0);
		eopp++;
	}
	test_assert(*eopp == NULL);
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unregister(fts_tokenizer_generic);
	test_end();
}

/* TODO: U+206F is in "Format" and therefore currently not word break.
   This definitely needs to be remapped. */
static void test_fts_tokenizer_generic_tr29_unicode_whitespace(void)
{
	/* with Unicode(utf8) U+2000(e2 80 80) and U+205A(e2 81 9a) and U+205F(e2
	   81 9f)*/
	static const unsigned char input[] =
		"hello world\r\nAnd\xE2\x80\x80there\twas: text "
		"galore\xE2\x81\x9F""and\xE2\x81\x9Amore.\n\n";
	static const char *const expected_output[] = {
		"hello", "world", "And",
		"there", "was", "text", "galore",
		"and", "more", NULL
	};
	const struct fts_tokenizer *tok_class;
	struct fts_tokenizer *tok;
	const char * const *eopp = expected_output;
	const char *token, *error;

	test_begin("fts tokenizer generic TR29 with Unicode whitespace");
	fts_tokenizer_register(fts_tokenizer_generic);
	tok_class = fts_tokenizer_find(FTS_TOKENIZER_GENERIC_NAME);
	test_assert(fts_tokenizer_create(tok_class, NULL, tr29_settings, &tok, &error) == 0);
	while (fts_tokenizer_next(tok, input, sizeof(input)-1, &token) > 0) {
		test_assert(strcmp(token, *eopp) == 0);
		eopp++;
	}
	while (fts_tokenizer_next(tok, NULL, 0, &token) > 0) {
		test_assert(strcmp(token, *eopp) == 0);
		eopp++;
	}
	test_assert(*eopp == NULL);
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unregister(fts_tokenizer_generic);
	test_end();
}

static void test_fts_tokenizer_generic_tr29_midnumlet_end(void)
{
	/* u+FF0E is EF BC 8E  */
	static const unsigned char input[] =
		"hello world\xEF\xBC\x8E";
	static const char *const expected_output[] = {
		"hello", "world", NULL
	};
	const struct fts_tokenizer *tok_class;
	struct fts_tokenizer *tok;
	const char * const *eopp = expected_output;
	const char *token, *error;

	test_begin("fts tokenizer generic TR29 with MinNumLet U+FF0E at end");
	fts_tokenizer_register(fts_tokenizer_generic);
	tok_class = fts_tokenizer_find(FTS_TOKENIZER_GENERIC_NAME);
	test_assert(fts_tokenizer_create(tok_class, NULL, tr29_settings, &tok, &error) == 0);
	while (fts_tokenizer_next(tok, input, sizeof(input)-1, &token) > 0) {
		test_assert(null_strcmp(token, *eopp) == 0);
		eopp++;
	}
	while (fts_tokenizer_next(tok, NULL, 0, &token) > 0) {
		test_assert(null_strcmp(token, *eopp) == 0);
		eopp++;
	}
	test_assert(*eopp == NULL);
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unregister(fts_tokenizer_generic);
	test_end();
}

static void test_fts_tokenizer_char_generic_tr29_only(void)
{
	static const unsigned char input[] =
		"abc@example.com, "
		"Bar Baz <bar@example.org>, "
		"foo@domain";
	static const char *const expected_output[] = {
		"abc", "example.com", "Bar", "Baz",
		"bar", "example.org", "foo", "domain", NULL
	};
	struct fts_tokenizer *tok;
	const char * const *eopp = expected_output;
	const char *token, *error;
	unsigned int i;
	int ret;

	test_begin("fts tokenizer generic TR29 input one character at a time");
	fts_tokenizer_register(fts_tokenizer_generic);

	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, tr29_settings, &tok, &error) == 0);

	for (i = 0; i <= sizeof(input)-1; ) {
		ret = i < sizeof(input)-1 ?
			fts_tokenizer_next(tok, &input[i], 1, &token) :
			fts_tokenizer_next(tok, NULL, 0, &token);
		if (ret == 0) {
			i++;
			continue;
		}
		test_assert(null_strcmp(token, *eopp) == 0);
		eopp++;
	}
	test_assert(*eopp == NULL);
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unregister(fts_tokenizer_generic);
	test_end();
}

static void test_fts_tokenizer_line_address_only(void)
{
	static const char *const input[] = {
		"abc@example.com",
		" Bar Baz <bar@example.org>",
		"foo@domain",
		" moro foo@domain Bar Baz <bar@example.org>"
	};
	static const char *const expected_output[] = {
		"abc@example.com", "bar@example.org",
		"foo@domain", "foo@domain", "bar@example.org", NULL
	};
	const char *const settings[] = {"no_parent", "foo", NULL};
	struct fts_tokenizer *tok;
	const char * const *eopp = expected_output;
	const char *token, *error;
	unsigned int i;
	int ret;

	test_begin("fts tokenizer email address only, input one line at a time");
	fts_tokenizer_register(fts_tokenizer_email_address);

	test_assert(fts_tokenizer_create(fts_tokenizer_email_address, NULL, settings, &tok, &error) == 0);

	for (i = 0; i <= N_ELEMENTS(input);) {
		ret = i < N_ELEMENTS(input) ?
			fts_tokenizer_next(tok, (unsigned char *)input[i],
			                   strlen(input[i]), &token) :
			fts_tokenizer_next(tok, NULL, 0, &token);
		if (ret == 0) {
			i++;
			continue;
		}
		test_assert(null_strcmp(token, *eopp) == 0);
		eopp++;
	}
	test_assert(*eopp == NULL);
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unregister(fts_tokenizer_email_address);
	test_end();

}
static void test_fts_tokenizer_char_address_only(void)
{
	static const unsigned char input[] =
		"@invalid invalid@ abc@example.com, "
		"Bar Baz <bar@example.org>, "
		"foo@domain";
	static const char *const expected_output[] = {
		"abc@example.com", "bar@example.org",
		"foo@domain", NULL
	};
	const char *const settings[] = {"no_parent", "0", NULL};
	struct fts_tokenizer *tok;
	const char * const *eopp = expected_output;
	const char *token, *error;
	unsigned int i;
	int ret;

	test_begin("fts tokenizer email address only, input one character at a time");
	fts_tokenizer_register(fts_tokenizer_email_address);
	test_assert(fts_tokenizer_create(fts_tokenizer_email_address, NULL, settings, &tok, &error) == 0);

	for (i = 0; i <= sizeof(input)-1; ) {
		ret = i < sizeof(input)-1 ?
			fts_tokenizer_next(tok, &input[i], 1, &token) :
			fts_tokenizer_next(tok, NULL, 0, &token);
		if (ret == 0) {
			i++;
			continue;
		}
		test_assert(null_strcmp(token, *eopp) == 0);
		eopp++;
	}
	test_assert(*eopp == NULL);
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unregister(fts_tokenizer_email_address);
	test_end();
}

static void test_fts_tokenizer_rand_address_only(void)
{
	static const unsigned char input[] =
		"@invalid invalid@ Abc Dfg <abc.dfg@example.com>, "
		"Foo Bar (comment)foo.bar@host.example.org foo ";

	static const char *const expected_output[] = {
		"abc.dfg@example.com",
		"foo.bar@host.example.org",
		 NULL
	};
	struct fts_tokenizer *tok;
	const char * const *eopp = expected_output;
	const char *token, *error;
	const char *const settings[] = {"no_parent", "abc", NULL};
	unsigned int i, step, step_max = 10;
	int ret;

	test_begin("fts tokenizer email address, input random length");
	fts_tokenizer_register(fts_tokenizer_email_address);
	test_assert(fts_tokenizer_create(fts_tokenizer_email_address, NULL,
	                                 settings, &tok, &error) == 0);
	step = rand() % step_max + 1;
	for (i = 0; i <= sizeof(input)-1; ) {
		ret = i < sizeof(input)-1 ?
			fts_tokenizer_next(tok, &input[i], step, &token) :
			fts_tokenizer_next(tok, NULL, 0, &token);
		if (ret == 0) {
			i += step;
			step = rand() % step_max + 1;
			step = I_MIN(step, sizeof(input) - i);
			continue;
		}
		test_assert(null_strcmp(token, *eopp) == 0);
		eopp++;
	}
	test_assert(*eopp == NULL);
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unregister(fts_tokenizer_email_address);
	test_end();
}

static void test_fts_tokenizer_address_char(void)
{
	static const unsigned char input[] =
		"@invalid invalid@ abc@example.com, "
		"Bar Baz <bar@example.org>, "
		"foo@domain";
	static const char *const expected_output[] = {
		"invalid", "invalid", "abc", "example", "com", "abc@example.com", "Bar", "Baz",
		"bar", "example", "org", "bar@example.org",
		"foo", "domain", "foo@domain", NULL
	};
	struct fts_tokenizer *tok, *gen_tok;
	const char * const *eopp = expected_output;
	const char *token, *error;
	unsigned int i;
	int ret;

	test_begin("fts tokenizer email address + parent, input one character at a time");
	fts_tokenizers_init();

	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, NULL, &gen_tok, &error) == 0);
	test_assert(fts_tokenizer_create(fts_tokenizer_email_address, gen_tok, NULL, &tok, &error) == 0);

	for (i = 0; i <= sizeof(input)-1; ) {
		ret = i < sizeof(input)-1 ?
			fts_tokenizer_next(tok, &input[i], 1, &token) :
			fts_tokenizer_next(tok, NULL, 0, &token);
		if (ret == 0) {
			i++;
			continue;
		}
		test_assert(*eopp != NULL);
		test_assert(null_strcmp(token, *eopp) == 0);
		eopp++;
	}
	test_assert(*eopp == NULL);
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unref(&gen_tok);
	fts_tokenizers_deinit();
	test_end();
}

static void test_fts_tokenizer_address_line(void)
{
	static const char *const input[] = {
		"@invalid invalid@ abc@example.com, ",
		"Bar Baz <bar@example.org>, ",
		"foo@domain, ",
		"foo@domain Bar Baz <bar@example.org>, "
	};
	static const char *const expected_output[] = {
		"invalid", "invalid", "abc", "example", "com", "abc@example.com", "Bar", "Baz",
		"bar", "example", "org", "bar@example.org",
		"foo", "domain", "foo@domain",
		"foo", "domain", "foo@domain", "Bar", "Baz",
		"bar", "example", "org", "bar@example.org", NULL
	};
	struct fts_tokenizer *tok, *gen_tok;
	const char * const *eopp = expected_output;
	const char *token, *error;
	unsigned int i;
	int ret;

	test_begin("fts tokenizer email address + parent, input one line at a time");
	fts_tokenizers_init();

	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, NULL, &gen_tok, &error) == 0);
	test_assert(fts_tokenizer_create(fts_tokenizer_email_address, gen_tok, NULL, &tok, &error) == 0);

	for (i = 0; i <= N_ELEMENTS(input);) {
		ret = i < N_ELEMENTS(input) ?
			fts_tokenizer_next(tok, (unsigned char *)input[i],
			                   strlen(input[i]), &token) :
			fts_tokenizer_next(tok, NULL, 0, &token);
		if (ret == 0) {
			i++;
			continue;
		}
		test_assert(null_strcmp(token, *eopp) == 0);
		eopp++;
	}
	test_assert(*eopp == NULL);
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unref(&gen_tok);
	fts_tokenizers_deinit();
	test_end();

}

static void test_fts_tokenizer_address_rand(void)
{
	static const unsigned char input[] =
		"@invalid invalid@ abc@example.com, "
		"Bar Baz <bar@example.org>, "
		"foo@domain";
	static const char *const expected_output[] = {
		"invalid", "invalid", "abc", "example", "com", "abc@example.com", "Bar", "Baz",
		"bar", "example", "org", "bar@example.org",
		"foo", "domain", "foo@domain", NULL
	};
	struct fts_tokenizer *tok, *gen_tok;
	const char * const *eopp = expected_output;
	const char *token, *error;
	unsigned int i, step, step_max = 10;
	int ret;

	test_begin("fts tokenizer email address + parent, input random length");
	fts_tokenizer_register(fts_tokenizer_generic);
	fts_tokenizer_register(fts_tokenizer_email_address);

	test_assert(fts_tokenizer_create(fts_tokenizer_generic, NULL, NULL, &gen_tok, &error) == 0);
	test_assert(fts_tokenizer_create(fts_tokenizer_email_address, gen_tok, NULL, &tok, &error) == 0);

	//srand(1424142100); /* had a bug */
	step = rand() % step_max + 1;
	for (i = 0; i <= sizeof(input)-1; ) {
		ret = i < sizeof(input)-1 ?
		      fts_tokenizer_next(tok, &input[i], step, &token) :
		      fts_tokenizer_next(tok, NULL, 0, &token);
		if (ret == 0) {
			i += step;
			step = rand() % step_max + 1;
			step = I_MIN(step, sizeof(input) - i);
			continue;
		}
		test_assert(null_strcmp(token, *eopp) == 0);
		eopp++;
	}
	test_assert(*eopp == NULL);
	fts_tokenizer_unref(&tok);
	fts_tokenizer_unref(&gen_tok);
	fts_tokenizer_unregister(fts_tokenizer_generic);
	fts_tokenizer_unregister(fts_tokenizer_email_address);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_fts_tokenizer_generic_only,
		test_fts_tokenizer_generic_unicode_whitespace,
		test_fts_tokenizer_char_generic_only,
		test_fts_tokenizer_generic_tr29_only,
		test_fts_tokenizer_generic_tr29_unicode_whitespace,
		test_fts_tokenizer_char_generic_tr29_only,
		test_fts_tokenizer_generic_tr29_midnumlet_end,
		test_fts_tokenizer_char_address_only,
		test_fts_tokenizer_line_address_only,
		test_fts_tokenizer_rand_address_only,
		test_fts_tokenizer_address_char,
		test_fts_tokenizer_address_line,
		test_fts_tokenizer_address_rand,
		NULL
	};

	return test_run(test_functions);
}
