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
	string_t *src, *str = t_str_new(256);
	enum charset_result result;
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		test_assert_idx(charset_to_utf8_str(input_charset, NULL,
						    tests[i].input, str, &result) == 0, i);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
		test_assert_idx(result == tests[i].result, i);
	}
	/* check that E2BIG handling works. We assume that iconv() is called
	   with 8192 byte buffer (tmpbuf[8192]) */
	src = str_new(default_pool, 16384);
	for (i = 0; i < 8190; i++)
		str_append_c(src, 'a' + i % ('z'-'a'+1));
	for (i = 0; i < 256; i++) {
		str_truncate(str, 0);
		str_append_c(src, 'A' + i % ('Z'-'A'+1));
		test_assert_idx(charset_to_utf8_str(input_charset, NULL,
						    str_c(src), str, &result) == 0, i);
	}
	str_free(&src);
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
static void test_charset_iconv_crashes(void)
{
	struct {
		const char *charset;
		const char *input;
	} tests[] = {
		{ "CP932", "\203\334" }
	};
	string_t *str = t_str_new(128);
	enum charset_result result;
	unsigned int i;

	test_begin("charset iconv crashes");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		/* we don't care about checking the result. we only want to
		   verify that there's no crash. */
		(void)charset_to_utf8_str(tests[i].charset, NULL,
					  tests[i].input, str, &result);
	}
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
		test_charset_iconv_crashes,
#endif
		NULL
	};

	return test_run(test_functions);
}
