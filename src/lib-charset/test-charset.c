/* Copyright (c) 2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "test-common.h"
#include "charset-utf8.h"

static void test_charset_is_utf8(void)
{
	test_begin("charset_is_utf8");
	test_assert(charset_is_utf8("AScII"));
	test_assert(charset_is_utf8("us-AScII"));
	test_assert(charset_is_utf8("uTF8"));
	test_assert(charset_is_utf8("uTF-8"));
	test_end();
}

static void test_charset_utf8_common(const char *input_charset)
{
	struct {
		const char *input;
		const char *output;
		enum charset_result result;
	} tests[] = {
		{ "p\xC3\xA4\xC3", "p\xC3\xA4", CHARSET_RET_INCOMPLETE_INPUT },
		{ "p\xC3\xA4\xC3""a", "p\xC3\xA4"UNICODE_REPLACEMENT_CHAR_UTF8"a", CHARSET_RET_INVALID_INPUT }
	};
	string_t *str = t_str_new(128);
	enum charset_result result;
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		test_assert_idx(charset_to_utf8_str(input_charset, NULL,
						    tests[i].input, str, &result) == 0, i);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
		test_assert_idx(result == tests[i].result, i);
	}
}

static void test_charset_utf8(void)
{
	test_begin("charset utf8");
	test_charset_utf8_common("UTF-8");
	test_end();
}

#ifdef HAVE_ICONV
static void test_charset_iconv(void)
{
	struct {
		const char *charset;
		const char *input;
		const char *output;
		enum charset_result result;
	} tests[] = {
		{ "ISO-8859-1", "p\xE4\xE4", "pää", CHARSET_RET_OK }
	};
	string_t *str = t_str_new(128);
	enum charset_result result;
	unsigned int i;

	test_begin("charset iconv");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		test_assert_idx(charset_to_utf8_str(tests[i].charset, NULL,
						    tests[i].input, str, &result) == 0, i);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
		test_assert_idx(result == tests[i].result, i);
	}
	/* Use //IGNORE just to force handling to be done by iconv
	   instead of our own UTF-8 routines. */
	test_charset_utf8_common("UTF-8//IGNORE");
	test_end();
}
#endif

int main(void)
{
	static void (*test_functions[])(void) = {
		test_charset_is_utf8,
		test_charset_utf8,
#ifdef HAVE_ICONV
		test_charset_iconv,
#endif
		NULL
	};

	return test_run(test_functions);
}
